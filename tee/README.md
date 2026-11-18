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
  repo git build-essential python3 python3-pip python3-pyelftools \
  mtools device-tree-compiler u-boot-tools flex bison \
  libssl-dev libgnutls28-dev zlib1g-dev libglib2.0-dev libpixman-1-dev \
  libslirp-dev ninja-build pkg-config rsync cpio wget unzip bc uuid-dev

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
# ccache 已装 → 必须带 CCACHE=；禁用 Rust → 带 BR2_PACKAGE_OPTEE_RUST_EXAMPLES_EXT=n
make CCACHE= BR2_PACKAGE_OPTEE_RUST_EXAMPLES_EXT=n BR2_PACKAGE_PYTHON3=y -j$(nproc)
```

**5. 冒烟验证 + 打开 RPMB**

```bash
cd ~/optee/build
make run-only QEMU_VIRTFS_AUTOMOUNT=y   # 正常世界登录 root 后：xtest 全过
# RPMB 使能方式随版本不同：在构建树内 grep -ri rpmb build/qemu_v8.mk，
# 确保 tee-supplicant 走 RPMB 后端、guest 内出现 /dev/mmcblk*rpmb。
# 不落在 RPMB 上的构建**不得**用于论文实验（docs/06 决策 D3）。
```

**6. 让 guest 能跑 TrustGate**

guest 的 buildroot 默认没有 Python，需要加：

```bash
# 一次性：编出 libteec 导出（供 CA 链接）
cd ~/optee/optee_client
make CROSS_COMPILE=$HOME/optee/toolchains/aarch64/bin/aarch64-linux-gnu- WITH_TEEACL=0
# 产物在 ~/optee/optee_client/out/export/usr/{include,lib}

# 编译 TA（CROSS_COMPILE 必须显式传！不传会用宿主 x86 gcc，报 -mstrict-align 错）
make -C ~/practice3/tee ta \
  TA_DEV_KIT_DIR=$HOME/optee/optee_os/out/arm/export-ta_arm64 \
  CROSS_COMPILE=$HOME/optee/toolchains/aarch64/bin/aarch64-linux-gnu-

# 编译 CA/bridge
make -C ~/practice3/tee bridge \
  TEEC_DIR=$HOME/optee/optee_client/out/export/usr \
  CROSS_COMPILE=$HOME/optee/toolchains/aarch64/bin/aarch64-linux-gnu-

# 两个产物都必须是 ARM aarch64
file ~/practice3/tee/ta/*.ta ~/practice3/tee/bridge/tg_bridge


# 宿主机：把工程软链进共享根（~/optee 就是默认共享目录）
ln -s ~/practice3 ~/optee/practice3

make run-only QEMU_VIRTFS_AUTOMOUNT=y
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

- [x] `xtest` 通过，`/dev/tee0` 存在（2026-11-18）
- [x] `/lib/optee_armtz/7c1c3f20-*.ta` 已安装（2026-11-18）
- [x] `replay_demo.py` 的 T2 攻击格 = "检测到重放/截断"（2026-11-18 实测：
      出示 C_A seq=660，锚当前 seq=665）
- [x] 断电重启 guest 后，`checkpoint.seq` 延续（2026-11-18：计数器已跨多次
      guest 运行延续至 665，当次日志基址 655——RPMB 持久的直接证据）
- [x] 所有产物的桥路径不含 "soft"（`logs/replay-demo-result.json` 的
      bridge 字段为真桥）

## 踩坑记录（真机联调实录，2026-11-18）

1. **`TEEC_InvokeCommand` 返回 `0xffff3024`（TARGET_DEAD），安全侧日志
   `TA panicked with code 0xffff0006`**：桥/TA 会话正常但 TA 被 libutee
   panic。panic 码就是原始错误码——libutee 对不少 API 实行"错误白名单"，
   白名单外的错误一律 `TEE_Panic` 上屏；host 侧看不到任何内核日志，
   **dmesg 不更新是预期**，别去 guest 的 dmesg 里找。本项目实例：MAC 系
   列 API 必须 `TEE_SetOperationKey` → `TEE_MACInit` → `TEE_MACComputeFinal`
   三步齐全，漏 `TEE_MACInit` 即 BAD_PARAMETERS → panic（软模拟桥不经
   libutee，开发期不可见）。定位：看 `make run-only` 终端里的 `D/TC:` 行。
2. **TA 序号跨运行延续，校验器不得假设 seq 从 0 开始**。真桥 RPMB 的
   计数器在多次运行间持续上涨（实测日志基址已到 655）；开发期对软模拟
   桥写的"绝对 seq"校验逻辑一到真机就整体误报。校验一律相对链基址
   （首条 seq），创世链才额外对 GENESIS 验证 prev_hash；检查点对账用
   "末条 seq+1 == 检查点 seq"。
3. **桥编译的三个坑**：TEEC 参数类型常量名是 `TEEC_MEMREF_TEMP_*`（不是
   `TEEC_PARAM_TYPE_MEMREF_*`）；`LINE_MAX` 与系统头冲突（已改
   `TG_LINE_MAX`）；交叉编译必须显式传
   `CROSS_COMPILE=$HOME/optee/toolchains/aarch64/bin/aarch64-linux-gnu-`，
   否则 TA 会被宿主 x86 gcc 编译并报 `-mstrict-align`。前两项已修进源码，
   第三项已写进步骤 6。

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
