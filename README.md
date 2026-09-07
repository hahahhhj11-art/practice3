# TrustGate

面向终端 AI Agent 的间接提示注入（IPI）防御网关 —— 基于任务-能力绑定与污点传播的可信工具调用引用监视器。

核心设计假设，也是与多数同类工作的区别：**Agent 进程本身被视为不可信组件。** 一旦外部内容进入 LLM 上下文，就必须假定 Agent 的行为可能已被攻击者部分控制。因此安全性不依赖提示加固或模型的自我约束，而由 Agent 之外、且 Agent 无法绕过的组件强制施加。

---

## 快速开始

无需 API Key（默认 MockLLM）：

```bash
python -m trustgate.sandbox build          # 建立隔离沙箱与基线哈希清单
python scripts/run_task.py                 # 跑一个端到端任务
python -m tests.test_defense               # 12 条防御回归测试
```

对比实验：

```bash
python attacks/generate.py --clean         # 生成 1152 条攻击样本
python -m eval.run_eval --limit 22 --benign 6      # 冒烟（每格 2 条，约 2 分钟）
python -m eval.run_eval --out logs/eval.json       # 全量
```

审计与取证：

```bash
python scripts/tamper_demo.py              # 对手 A2 的篡改检测演示（SC4 三态）
python scripts/run_task.py --anchor T1 --key-source ephemeral \
    --checkpoint-out logs/ckpt.json        # 产生可离机校验的日志
python scripts/verify_audit.py --audit logs/audit.jsonl \
    --key <hex> --checkpoint logs/ckpt.json
```

接真实模型（OpenAI 兼容接口，含录制回放）：

```bash
$env:TG_BASE_URL="https://api.deepseek.com/v1"; $env:TG_API_KEY="sk-..."
python scripts/run_task.py --llm openai --model deepseek-chat
python -m eval.run_eval --llm openai --model deepseek-chat --limit 22
```

---

## 架构

```
用户任务 → Agent 进程（不可信）
              ↓ IPC（唯一通道，JSON Lines over stdio）
           Tool Broker（PEP，唯一持有 FS/网络权限）
              ↓ evaluate()
           TrustedAnchor（TCB：PDP + 审计密钥 + 链头 + 溯源存储）
```

从 Agent 到文件系统没有任何直连边。三个组件之间的信任等级、以及每条边为什么必须存在，见 [`docs/02-系统架构.md`](docs/02-系统架构.md)。

### 五层策略引擎

按代价从低到高短路求值，任何一层给出 `deny` 立即返回——判定延迟低，且归因唯一（每个决策都带 `rule` 字段，可直接聚合成各层拦截贡献度）。

| 层 | 判定依据 | 主要抵抗 |
| --- | --- | --- |
| L1 静态权限 | 路径黑白名单、域名允许列表、长度上限 | 朴素越权 |
| L2 任务-能力绑定 | 调用是否落在**读取外部内容之前**冻结的能力清单内 | 计划外调用、越权读写 |
| L3 污点溯源 + 内容指纹 | 参数溯源为 trusted/unknown/untrusted；外发参数与已读敏感内容比对 | 注入驱动的不可逆操作、单次外泄 |
| L4 跨步骤时序策略 | 会话状态机、外泄链、会话外发预算 | 低带宽外泄、记忆投毒 |
| L5 风险计分 | 风险分累加 → 确认 / 拒绝 | 兜底 |

**任务-能力绑定为什么成立**：能力清单在规划期冻结，而此刻上下文里只有用户任务与工具 Schema，没有任何攻击者可控的字节。对手的能力全部作用于外部内容，完全在规划期的攻击面之外。

### 可信锚三档

| 档 | 部署形态 | 默认密钥来源 | 抵抗对手 A2 |
| --- | --- | --- | --- |
| T0 | 同进程 | `file` | 无（仅测功能与延迟下界） |
| T1 | 独立进程 + 单向 stdio | `ephemeral` | 除跨会话回滚外全部 |
| T2 | QEMU + OP-TEE TA | TEE 安全存储 | 全部（选做，接口已冻结） |

T1 与 T2 的能力差值就是 TEE 必要性的量化答案：T1 的单调序号活在进程内存里，重启归零，挡不住重放旧检查点。

---

## 实验结果

`python -m eval.run_eval --limit 24 --benign 8`，MockLLM（百分百服从注入，测的是防御强制力上界）：

| 组 | 防御配置 | ASR | UA | BTC | 良性 FPR | P95 延迟 |
| --- | --- | --- | --- | --- | --- | --- |
| C0 | 无防护基线 | 100% | 100% | 100% | 0% | 1.57ms |
| C1 | 提示层加固（Spotlighting） | 100% | 100% | 100% | 0% | 1.47ms |
| C2 | 静态规则 | 58.3% | 100% | 100% | 0% | 1.22ms |
| C3 | + 任务-能力绑定与污点传播 | 25.0% | 100% | 100% | 0% | 1.30ms |
| C4 | + 跨步骤时序策略 | **0%** | 91.7% | 100% | 0% | 1.75ms |
| C5 | 完整防御 + 可信锚 T1 | **0%** | 91.7% | 100% | 0% | 2.34ms |

**ASR 必须与 UA 一起读。** UA（utility under attack，口径同 AgentDojo §3.4）是注入存在时用户原任务的完成率。只看 ASR 会把「一律拒绝」评为满分防御：那种网关的 ASR 是 0%、BTC 也是 100%（BTC 只在无注入的良性样本上测），但 UA 会塌到 0——攻击没成功，用户的活也没干成。

四个结论：

1. **静态规则只覆盖一半攻击面。** 攻击者一旦把目标挪进策略允许的范围（例如密码泄漏进工作区笔记），静态规则的 ASR 从 0% 跳到 100%。
2. **低带宽外泄与合规内持久注入无法被任何单步规则拦住。** 它们在已含污点传播与内容指纹的 C3 下仍然 100% 成功，只有跨步骤时序策略能挡。
3. **提示层加固零收益。** C1 与 C0 的 ASR 完全相同。NDSS'26-f394 的实测更进一步：提示层防御的攻击成功率**高于**不设防（18.26% vs 16.89%）。
4. **完整防御的效用代价是 8.3%，且百分之百集中在一格。** `scripts/ua_breakdown.py` 显示损失全在 `persist/policy_aware`（该格 UA = 0%）：C4/C5 在那里把 ASR 压到 0，靠的是拒绝执行用户自己的摘要写入。这个代价是冗余付出的——文件溯源标签已经中和了再摄入，写入时那道硬拦截多余。修法（T5 判定改两阶段）见 [`docs/04-文献对齐与漏洞修复.md`](docs/04-文献对齐与漏洞修复.md) §3。

完整的按「攻击目标 × 规避层级」拆分的消融表、以及 ASR 语义的限定，见 [`docs/03-实验设计与效度.md`](docs/03-实验设计与效度.md)。以文献口径自检发现的两个可利用漏洞及其修复，见 [`docs/04-文献对齐与漏洞修复.md`](docs/04-文献对齐与漏洞修复.md)。

---

## 两条贯穿全局的方法论纪律

这两条在代码里是硬约束，破坏它们的改动会被回归测试拦下。

**一、canary 只属于评测侧。** canary（honeytoken）是判定攻击是否成功的 ground-truth 预言机。任何防御路径引用它，等于让被测系统提前知道答案，测出的 ASR 不可信。防御侧识别"什么是敏感数据"用策略声明的内容特征，识别"数据正在外流"用滑动窗口内容指纹（`trustgate/dlp.py`）——两者都不需要任何预置秘密。策略里保留 `dlp.oracle_canary_rule` 开关（默认关闭），仅用于测出"防御方知道秘密"这一理想情形下的 ASR 下界，作为指纹漏检率的参照。

**二、执行期配置只有一个来源。** Broker 虽然代码可信，但运行在对手 A2 可读写的文件系统上。它若自己去读 `policy.json`，A2 只需把 `mode` 改成 `observe`，整个网关就静默失效，而 `attest()` 依然汇报 `enforce`。因此 Broker 的全部配置向锚索取（`runtime_config()`），磁盘上的策略文件只有锚会读。由 `test_broker_does_not_reread_policy_from_disk` 锁死。

---

## 目录结构

```
trustgate/          核心实现
  types.py          信任格、能力声明、ToolCall/Result、Decision
  policy.py         PDP：L1–L5 五层策略引擎（无状态，可整体搬进 TEE）
  anchor.py         TrustedAnchor T0/T1 + 溯源存储 + 审计链权威
  broker.py         PEP + 工具执行体（独立进程）
  agent.py          编排循环 plan → freeze → act → observe
  taint.py          污点跟踪与参数溯源
  dlp.py            敏感内容指纹（不依赖 canary）
  audit.py          哈希链 + HMAC + 离机校验
  sanitize.py       HTML 抽取 + 去权化包装（Spotlighting 基线）
  sandbox.py        沙箱构建 / 重置 / canary 植入 / 完整性判定
attacks/generate.py 攻击样本生成器（目标 × 规避层级 × 载体 × 策略 × 强度）
eval/run_eval.py    C0–C5 对比实验与指标统计
scripts/            run_task / serve_corpus / verify_audit / tamper_demo
tests/              防御回归测试 + 数据集有效性检查
docs/               威胁模型、系统架构、实验设计与效度
policy.json         策略配置（参与 attestation）
```

---

## 文档

| 文档 | 内容 |
| --- | --- |
| [`docs/00-方案评审与优化.md`](docs/00-方案评审与优化.md) | 原始方案的硬伤与修正过程 |
| [`docs/01-威胁模型.md`](docs/01-威胁模型.md) | 系统模型、资产、对手 A1/A2、攻击分类、安全论断 SC1–SC6 及其边界 |
| [`docs/02-系统架构.md`](docs/02-系统架构.md) | 设计原则、组件契约、五层策略细节、可追溯性矩阵 |
| [`docs/03-实验设计与效度.md`](docs/03-实验设计与效度.md) | C0–C5 设计、主结果、以及为保证结论可信做的效度修正 |

---

## 声明

本项目是课程/研究用途的防御性安全研究。攻击样本全部在本机隔离沙箱内运行，敏感文件为合成数据，canary 为合成令牌，"外泄接收端"是绑定在 `127.0.0.1` 的本地进程。任何时候都不接触真实用户数据，也不向本机之外发送任何内容。
