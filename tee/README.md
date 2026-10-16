# TrustGate TEE 组件（T2 可信锚）

实现依据：`docs/06-T2可信锚实现方案.md`。三个产物：

| 产物 | 跑在哪 | 说明 |
| --- | --- | --- |
| `bridge/tg_bridge_soft` | 开发机（host gcc） | 软模拟桥：不链 libteec，状态落普通文件。**仅供开发与单元测试** |
| `bridge/tg_bridge` | QEMU guest / 开发板（aarch64） | 真桥：经 libteec 调 TA |
| `ta/<uuid>.ta` | OP-TEE 安全世界 | 真 TA：密钥 + 单调序号 + 链头，持久存储 |

## 诚实边界（先读这个）

软模拟桥让没有 OP-TEE 环境的机器也能开发、跑单元测试。但它**不产生任何
安全性质**，也**绝不允许出现在论文实验数据里**——凡是要写进论文的数字
（`scripts/replay_demo.py`、`scripts/latency_bench.py` 的 T2 档），必须在
真桥 + 真 TA 上采集。`latency_bench.py` 对软模拟桥默认拒绝，需显式
`--allow-soft` 才会放行（用于 plumbing 自检）。

## 开发机：软模拟

```bash
make -C tee soft          # 产出 bridge/tg_bridge_soft
export TG_TEE_BRIDGE=$PWD/tee/bridge/tg_bridge_soft
export TG_TEE_SOFT_STATE=/tmp/tg-soft-state.json   # 可选，默认 .trustgate/tee-soft-state.json
python -m unittest tests.test_tee_anchor -v
```

## 真机：环境搭建与采数据（一步一步）

前置：一台 Ubuntu 22.04（物理机或 VM 均可），磁盘 ≥50GB，内存 ≥8GB，顺畅的网络。

**1. 实测网络，决定源码路径**

```bash
time git ls-remote https://github.com/OP-TEE/manifest.git HEAD
# 顺畅 → 官方源；超时 → 用代理，或搜 "OP-TEE gitee 镜像" 替换下面所有 URL
```

**2. 装依赖与 repo 工具**

```bash
sudo apt update && sudo apt install -y \
  repo git build-essential python3 python3-pip mtools device-tree-compiler \
  u-boot-tools qemu-system-arm flex bison libssl-dev libgnutls28-dev
mkdir -p ~/.bin
curl -L https://storage.googleapis.com/git-repo-downloads/repo > ~/.bin/repo
chmod +x ~/.bin/repo && export PATH="$HOME/.bin:$PATH"
```

**3. 同步 OP-TEE 源码（qemu_v8）**

```bash
mkdir ~/optee && cd ~/optee
repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml -b 4.4.0
repo sync -j$(nproc)        # 约 20GB，网络决定快慢
```

**4. 编译（首次 1–2 小时，之后增量）**

```bash
cd ~/optee/build
make -j$(nproc) toolchains
make -j$(nproc) all
```

**5. 冒烟验证 + 打开 RPMB**

```bash
make run-only     # 正常世界登录 root 后：xtest 全过
# RPMB 使能方式随版本不同：在构建树内 grep -ri rpmb build/qemu_v8.mk，
# 确保 tee-supplicant 走 RPMB 后端、guest 内出现 /dev/mmcblk*rpmb。
# 不落在 RPMB 上的构建**不得**用于论文实验（docs/06 决策 D3）。
```

**6. 让 guest 能跑 TrustGate**

guest 的 buildroot 默认没有 Python，需要加：

```bash
cd ~/optee/buildroot && make menuconfig
# Target packages → Interpreter languages and scripting → python3 → 保存
cd ~/optee/build && make -j$(nproc) all   # 重打包 rootfs
```

把 TrustGate 仓库弄进 guest（任选其一：scp、共享目录，或拷进 rootfs overlay），
然后在 **guest 内**构建 T2 组件：

```bash
cd <trustgate>
make -C tee ta     TA_DEV_KIT_DIR=~/optee/optee_os/out/arm/export-ta_arm64
make -C tee bridge TEEC_DIR=~/optee/optee_client/install
cp tee/ta/*.ta /lib/optee_armtz/ && pkill tee-supplicant || true
```

**7. 采数据（全部在 guest 内、真桥下执行）**

```bash
export TG_TEE_BRIDGE=$PWD/tee/bridge/tg_bridge    # 名字含 soft 的会被 bench 拒绝
python3 scripts/replay_demo.py                     # E1：六格结果
python3 scripts/latency_bench.py --runs 50         # E2：三档延迟表
python3 -m eval.run_eval --groups C5T2 --limit 20  # 端到端攻击样本
```

把 `logs/replay-demo-result.json`、`logs/latency-bench.json`、`logs/eval-report.json` 取回主机。

**8. 验收 checklist**

- [ ] `xtest` 通过，`/dev/tee0` 存在
- [ ] `/lib/optee_armtz/7c1c3f20-*.ta` 已安装
- [ ] `replay_demo.py` 的 T2 攻击格 = "检测到重放/截断"
- [ ] 断电重启 guest 后，`checkpoint.seq` 延续（RPMB 生效的铁证）
- [ ] 所有产物的桥路径不含 "soft"

踩坑记录（RPMB 具体开关、rootfs 改动等）请追加到本文档，下次复现不再重缴学费。

## Windows 主机复测（去 CI 盲点）

WSL 里开发时想提前验证 Windows 行为，在 **Windows 侧**（Git Bash 或 cmd）执行：

```bash
gcc -O2 -Wall -Wextra -DSOFT_TA -o tee/bridge/tg_bridge_soft.exe tee/bridge/tg_bridge.c
set TG_TEE_BRIDGE=%CD%\tee\bridge\tg_bridge_soft.exe   # cmd；bash 用 export
python -m unittest tests.test_tee_anchor -v
```

MinGW gcc（Git for Windows / Strawberry Perl 均自带）产物是 `.exe`；
测试的 `_soft_bin()` 两种后缀都认。跨 WSL 边界的 `\wsl.localhost` UNC
路径不能让 ld 直接写输出，先编到 Windows 临时目录再拷回。

## 协议（锚进程 ⇄ 桥）

stdio 上 JSON Lines，与 `trustgate/anchor.py::TeeBridge` 对应：

- `{"op":"init"}` → `{"result":{"ok":true}}`
- `{"op":"seal","data_b64":...}` → `{"result":{"mac":"hex64"}}`
- `{"op":"chain_append","payload_b64":...}` → `{"result":{"seq":n,"prev_hash":"hex","hash":"hex","mac":"hex"}}`
- `{"op":"checkpoint"}` → `{"result":{"seq":n,"head":"hex","mac":"hex"}}`
- `{"op":"export_key"}` → `{"result":{"key":"hex64"}}`

`payload_b64` 是 `trustgate.audit.canonical_payload()` 输出的原文
（base64 编码只为避开 JSON 转义），TA 不解析 JSON，只做
`sha256(prev_hex || seq || payload)` 拼接——序列化规则全项目只有
Python 一个权威。
