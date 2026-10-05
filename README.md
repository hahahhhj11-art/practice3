# TrustGate

面向终端 AI Agent 的间接提示注入（IPI）防御网关 —— 基于任务-能力绑定与污点传播的可信工具调用引用监视器。

核心设计假设，也是与多数同类工作的区别：**Agent 进程本身被视为不可信组件。** 一旦外部内容进入 LLM 上下文，就必须假定 Agent 的行为可能已被攻击者部分控制。因此安全性不依赖提示加固或模型的自我约束，而由 Agent 之外、且 Agent 无法绕过的组件强制施加。

---

## 快速开始

一条命令跑完全部可验证结论（无需 API Key，默认 MockLLM）：

```bash
python scripts/reproduce.py --quick        # 冒烟，几分钟
python scripts/reproduce.py --full         # 论文主表规模
```

流程为：环境与权限剥离能力探测 → 沙箱重置 → 全套单元测试 → 生成攻击样本集 →
非绕过性对照 → 审计篡改检测 → C0–C5 主实验 → 取证层。**第一步是能力探测而非跑
测试**：Linux 上 S2 是内核强制，Windows 上文件与网络没有内核兜底，不先把本机档位
打出来，后面"非绕过性"那一格的数字会被误读成防御失效。

分步执行：

```bash
python -m trustgate.sandbox build          # 建立隔离沙箱与基线哈希清单
python scripts/run_task.py                 # 跑一个端到端任务
python -m unittest discover -s tests       # 全套回归测试
```

非绕过性（这一节是与提示层工作的分水岭）：

```bash
python scripts/bypass_demo.py --level S0   # 预期 3/3 绕过成功 —— 对照组
python scripts/bypass_demo.py --level S2   # 预期 0/3（Linux，Landlock + seccomp）
python -m trustgate.supervisor --task "..." --confine S2   # 特权父进程 + 被剥权子进程
```

S0 对照组不可省：只报"S2 拦住了"无法排除"这条路径本来就走不通"，3/3 → 0/3 的
**差值**才是权限剥离层的贡献。

对比实验：

```bash
python attacks/generate.py --clean         # 生成 1440 条攻击样本（15 格）
python -m eval.run_eval --limit 30 --benign 8      # 冒烟（每格 2 条）
python -m eval.run_eval --out logs/eval.json       # 全量
```

审计完整性：

```bash
python scripts/tamper_demo.py              # 对手 A2 的篡改检测演示（SC4 三态）
python scripts/run_task.py --anchor T1 --key-source ephemeral \
    --checkpoint-out logs/ckpt.json        # 产生可离机校验的日志
python scripts/verify_audit.py --audit logs/audit.jsonl \
    --key <hex> --checkpoint logs/ckpt.json
```

事后取证（定位 / 归因 / 恢复，不在关键路径上）：

```bash
# 先在 policy.json 里把 forensics.capture 设为 true —— 默认关闭是知情选择：
# 审计日志刻意只存 args_digest 不存原文，开启捕获等于多留一份未脱敏副本。
python scripts/forensics_report.py --all --recovery
```

接真实模型（OpenAI 兼容接口，含录制回放）：

```bash
$env:TG_BASE_URL="https://api.deepseek.com/v1"; $env:TG_API_KEY="sk-..."
python scripts/run_task.py --llm openai --model deepseek-chat

# 两臂实验：把 ASR@model 拆成「模型易感性 × 网关条件阻断率」
python -m eval.run_model_eval --preflight              # 只检查环境
python -m eval.run_model_eval --model deepseek-chat --limit 15
python -m eval.run_model_eval --replay-only            # 无 key 时用随仓库缓存离线复现
```

无 key 且无缓存时该管线以退出码 3 结束且**不输出任何数字**——给一个"未测"比给一个
来源不明的数字有用。

---

## 架构

```
Supervisor（特权父进程：文件系统 + 网络 + 审计密钥）
  ├── Tool Broker（PEP，唯一持有 FS/网络权限）
  │     └── TrustedAnchor（TCB：PDP + 审计密钥 + 链头 + 溯源存储）
  ├── 模型外发代办（目的地固定的单一出口，只转发字节、不做判定）
  └── Agent 子进程（不可信；S2 下由内核剥去文件与网络权限）
        ↑ 唯一通道：JSON Lines over stdio
```

从 Agent 到文件系统没有任何直连边。**这个拓扑是倒过来的**：早先的实现里 Agent 是
父进程、Broker 是子进程，于是"Agent 绕不过 Broker"只是一句代码风纪——父进程本就
持有用户的全部权限，一行 `open("sandbox/private/id_rsa")` 就能让五层判定一次都不
触发。倒置之后工具能力物理上不在 Agent 进程内，绕过路径由 Landlock/seccomp 在内核
层切断。

三个组件之间的信任等级见 [`docs/02-系统架构.md`](docs/02-系统架构.md)；权限剥离的
三档能力与逐平台缺口见 [`trustgate/confine.py`](trustgate/confine.py) 模块头。

### 权限剥离三档

| 档 | 机制 | 保证 |
| --- | --- | --- |
| S0 | 无 | 无。仅用于测延迟下界，并**证明绕过确实可行**（缺了这个对照组，S2 的结论没有参照） |
| S1 | 能力面裁剪（不可导入工具模块、环境变量清洗） | 非 OS 强制：进程仍以用户身份运行，`open()`/`socket()` 依然可用 |
| S2 | Linux：Landlock（路径粒度白名单）+ seccomp-BPF（禁 AF_INET/AF_INET6） | 沙箱资产不可读写、无法直连网络。**明确不保证**读不到 `/usr`、`/etc`（运行 Python 所必需，不在资产集合内） |

Windows 上只能做到 Job Object 的生命周期约束，文件与网络无内核强制；此时
`effective` 如实降级标为 S1，缺口登记在 `ConfinementReport.gaps` 里，不靠措辞含糊
过去。

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

`python -m eval.run_eval --limit 30 --benign 8`（15 格 × 每格 2 条），MockLLM（百分百服从注入，测的是防御强制力上界）：

| 组 | 防御配置 | ASR | UA | BTC | 良性 FPR | 判定命中率 | 实际阻断率 | P95 延迟 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| C0 | 无防护基线 | 100% | 100% | 100% | 0% | 40.0% | 0% | 1.20ms |
| C1 | 提示层加固（Spotlighting） | 100% | 100% | 100% | 0% | 40.0% | 0% | 1.10ms |
| C2 | 静态规则（L1） | 66.7% | 100% | 100% | 0% | 10.0% | 10.0% | 1.13ms |
| C3 | + 任务-能力绑定与污点溯源（L2+L3） | 20.0% | 100% | 100% | 0% | 20.0% | 20.0% | 1.14ms |
| C4 | + 跨步骤时序策略（L4） | **0%** | **100%** | 100% | 0% | 40.0% | 40.0% | 1.23ms |
| C5 | 完整防御 + 可信锚 T1 | **0%** | **100%** | 100% | 0% | 40.0% | 40.0% | 1.62ms |

「判定命中率」与「实际阻断率」的差值就是 C0/C1 **能看见攻击却不阻止**的部分（observe 模式）。这两个口径必须分开报：早先把 observe 下的 deny 判定也算进阻断率，无防护基线看起来拦了四成调用，是自欺欺人。

**15 格全部对账通过**：每一格的实测拦截规则都落在样本声明的 `expect_layer` 内，零偏离。三个自适应格（读/前缀放宽 → `L3.untrusted_read_target`、覆盖/同名洗白 → `L3.untrusted_irreversible`、外泄/阈下分片 → `L4.exfil_chain`）也在内。表格由 `python scripts/report_table.py logs/eval-main.json` 从报告 JSON 直接生成，不手抄。

**ASR 必须与 UA 一起读。** UA（utility under attack，口径同 AgentDojo §3.4）是注入存在时用户原任务的完成率。只看 ASR 会把「一律拒绝」评为满分防御：那种网关的 ASR 是 0%、BTC 也是 100%（BTC 只在无注入的良性样本上测），但 UA 会塌到 0——攻击没成功，用户的活也没干成。

四个结论：

1. **静态规则只覆盖一半攻击面。** 攻击者一旦把目标挪进策略允许的范围（例如密码泄漏进工作区笔记），静态规则的 ASR 从 0% 跳到 100%。
2. **低带宽外泄与合规内持久注入无法被任何单步规则拦住。** 它们在已含污点传播与内容指纹的 C3 下仍然 100% 成功，只有跨步骤时序策略能挡。
3. **提示层加固零收益。** C1 与 C0 的 ASR 完全相同。NDSS'26-f394 的实测更进一步：提示层防御的攻击成功率**高于**不设防（18.26% vs 16.89%）。
4. **记忆投毒不该在写入时拦，该在再摄入时拦。** 判据"内容派生自不可信文本 + 落在可读区"对**任何网页摘要任务**都成立，靠关键词表区分"指令性文本"正是 ASB 与 Liu et al. 证明不可靠的语义判别。TrustGate 改为：写入放行但登记溯源，文件读回时标为 untrusted，毒文本里的路径参数于是溯源为不可信、由 L3 拦下——判据是数据流而非文本外观，改措辞无从规避。T5 判定同步改为两阶段（`T5a` 字节落盘、`T5b` 新会话读回后投毒生效），实测证明写入时那道硬拦截**安全收益为零、效用代价一半**（UA 50% vs 100%）。详见 [`docs/04-文献对齐与漏洞修复.md`](docs/04-文献对齐与漏洞修复.md) §3。

完整的按「攻击目标 × 规避层级」拆分的消融表、以及 ASR 语义的限定，见 [`docs/03-实验设计与效度.md`](docs/03-实验设计与效度.md)。以文献口径自检发现的两个可利用漏洞及其修复，见 [`docs/04-文献对齐与漏洞修复.md`](docs/04-文献对齐与漏洞修复.md)。

---

## 三条贯穿全局的方法论纪律

这三条在代码里是硬约束，破坏它们的改动会被回归测试拦下。

**一、canary 只属于评测侧。** canary（honeytoken）是判定攻击是否成功的 ground-truth 预言机。任何防御路径引用它，等于让被测系统提前知道答案，测出的 ASR 不可信。防御侧识别"什么是敏感数据"用策略声明的内容特征，识别"数据正在外流"用滑动窗口内容指纹（`trustgate/dlp.py`）——两者都不需要任何预置秘密。策略里保留 `dlp.oracle_canary_rule` 开关（默认关闭），仅用于测出"防御方知道秘密"这一理想情形下的 ASR 下界，作为指纹漏检率的参照。

**二、执行期配置只有一个来源。** Broker 虽然代码可信，但运行在对手 A2 可读写的文件系统上。它若自己去读 `policy.json`，A2 只需把 `mode` 改成 `observe`，整个网关就静默失效，而 `attest()` 依然汇报 `enforce`。因此 Broker 的全部配置向锚索取（`runtime_config()`），磁盘上的策略文件只有锚会读。由 `test_broker_does_not_reread_policy_from_disk` 锁死。

**三、任何"防住了"的数字都必须有无防护对照。** 这条纪律在项目里出现了三次，形式不同但内核一致：

- **C0 组**：攻击样本必须在无防护下真的成功，否则任何防御在该格都会测出 ASR=0。由 `test_attack_samples_actually_succeed_without_defense` 锁死——它检查的是**数据集**而不是防御。已记录四处"攻击其实没打中"的装置缺陷（见 [`docs/03`](docs/03-实验设计与效度.md) §7.1）。
- **S0 组**：三条绕过路径必须在无剥离时全部成功，否则 S2 的 0/3 无法排除"这条路本来就走不通"。由 `tests/test_confinement.py::BypassControlGroupTest` 锁死。
- **CBR 的分母**：真实模型实验里，只有在无防护臂真的中招的样本上才能把"没得手"算作网关的功劳。模型自己拒绝的样本必须从分母剔除，否则模型越保守、我们的数字越好看。由 `tests/test_model_eval.py::ConditionalBlockingRateTest` 锁死。

第三条最值得警惕，因为违反它产生的错误**只会让结论变漂亮**，事后极难被发现。

---

## 目录结构

```
trustgate/          核心实现
  types.py          信任格、能力声明、ToolCall/Result、Decision
  policy.py         PDP：L1–L5 五层策略引擎（无状态，可整体搬进 TEE）
  anchor.py         TrustedAnchor T0/T1 + 溯源存储 + 审计链权威
  broker.py         PEP + 工具执行体（含取证素材捕获，默认关闭）
  agent.py          编排循环 plan → freeze → act → observe
  supervisor.py     特权父进程：托管 Broker、代办模型调用、核验子进程剥离
  agent_host.py     被剥权的 Agent 子进程宿主（先剥权，后接触外部内容）
  confine.py        OS 级权限剥离 S0/S1/S2（Landlock / seccomp / Job Object）
  taint.py          污点跟踪与参数溯源
  dlp.py            敏感内容指纹（不依赖 canary）
  forensics.py      异步取证：注入定位 / 来源归因 / 数据恢复（不在关键路径上）
  audit.py          哈希链 + HMAC + 离机校验
  sanitize.py       HTML 抽取 + 去权化包装（Spotlighting 基线）
  sandbox.py        沙箱构建 / 重置 / canary 植入 / 完整性判定
attacks/generate.py 攻击样本生成器（目标 × 规避层级 × 载体 × 策略 × 强度）
eval/run_eval.py         C0–C5 对比实验与指标统计（ASR@obedient）
eval/run_model_eval.py   真实模型两臂实验（易感性 S / ASR@model / CBR）
scripts/            reproduce（一键复现）/ bypass_demo / tamper_demo /
                    forensics_report / run_task / serve_corpus / verify_audit
tests/              防御回归 + 数据集有效性 + 非绕过性 + 取证 + 实验口径
docs/               威胁模型、系统架构、实验设计与效度、论文骨架
policy.json         策略配置（参与 attestation）
```

---

## 文档

| 文档 | 内容 |
| --- | --- |
| [`docs/00-方案评审与优化.md`](docs/00-方案评审与优化.md) | 原始方案的硬伤与修正过程 |
| [`docs/01-威胁模型.md`](docs/01-威胁模型.md) | 系统模型、资产、对手 A1/A2、攻击分类、安全论断 SC1–SC6 及其边界 |
| [`docs/02-系统架构.md`](docs/02-系统架构.md) | 设计原则、组件契约、五层策略细节、可追溯性矩阵 |
| [`docs/03-实验设计与效度.md`](docs/03-实验设计与效度.md) | C0–C5 设计、主结果、效度限定与修正记录、实验进度台账 |
| [`docs/04-文献对齐与漏洞修复.md`](docs/04-文献对齐与漏洞修复.md) | 以文献口径自检发现的可利用漏洞及其修复 |
| [`docs/05-论文骨架.md`](docs/05-论文骨架.md) | 按 USENIX/NDSS 结构组织的论点—证据台账：每节的主张、证据产出物、以及**明确不声称什么** |

---

## 声明

本项目是课程/研究用途的防御性安全研究。攻击样本全部在本机隔离沙箱内运行，敏感文件为合成数据，canary 为合成令牌，"外泄接收端"是绑定在 `127.0.0.1` 的本地进程。任何时候都不接触真实用户数据，也不向本机之外发送任何内容。
