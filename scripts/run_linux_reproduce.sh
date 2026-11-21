#!/usr/bin/env bash
# TrustGate Linux 完整一键复现脚本（纯 CPU，无需 GPU，无需 API Key）
#
# 用途：在带 Landlock + seccomp 的 Linux 机器上跑完论文主表规模的完整复现
# （包含内核级 S2 非绕过性验证，Windows 上 S2 会降级为 S1）。
#
# 用法：
#   bash scripts/run_linux_reproduce.sh              # 默认 --full
#   bash scripts/run_linux_reproduce.sh --fail-fast  # 遇错即停
#   bash scripts/run_linux_reproduce.sh --quick      # 仅冒烟规模
set -euo pipefail

if [ "$(uname -s)" != "Linux" ]; then
    echo "错误：本脚本仅用于 Linux（当前系统：$(uname -s)）。" >&2
    echo "Linux 上才能验证内核级 S2（Landlock + seccomp）非绕过性。" >&2
    exit 2
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "错误：未找到 $PYTHON_BIN，请先安装 Python >= 3.11。" >&2
    exit 2
fi

"$PYTHON_BIN" - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit(
        f"错误：需要 Python >= 3.11，当前为 {sys.version_info.major}.{sys.version_info.minor}"
    )
print(f"Python 版本检查通过：{sys.version.split()[0]}")
PY

MODE_FLAG="--full"
EXTRA_ARGS=()
for arg in "$@"; do
    case "$arg" in
        --quick|--full)
            MODE_FLAG="$arg"
            ;;
        *)
            EXTRA_ARGS+=("$arg")
            ;;
    esac
done

TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="$ROOT/logs/linux-reproduce-$TS"
mkdir -p "$OUT_DIR"

export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

echo "==> 环境信息" | tee "$OUT_DIR/run.log"
{
    echo "date:   $(date -Is)"
    echo "host:   $(hostname)"
    echo "kernel: $(uname -a)"
    echo "git:    $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    echo "mode:   $MODE_FLAG ${EXTRA_ARGS[*]:-}"
} | tee -a "$OUT_DIR/run.log"

echo "==> 探测内核权限剥离能力（预期 max_level=S2）" | tee -a "$OUT_DIR/run.log"
"$PYTHON_BIN" -c "import json; from trustgate.confine import probe; p=probe(); print(json.dumps(p, ensure_ascii=False, indent=2)); print('max_level=' + p['max_level'])" \
    | tee -a "$OUT_DIR/run.log"

echo "==> 开始运行 python3 scripts/reproduce.py $MODE_FLAG ${EXTRA_ARGS[*]:-}" | tee -a "$OUT_DIR/run.log"
set +e
"$PYTHON_BIN" -u scripts/reproduce.py "$MODE_FLAG" "${EXTRA_ARGS[@]}" 2>&1 | tee -a "$OUT_DIR/run.log"
STATUS=${PIPESTATUS[0]}
set -e

# 归档本次运行产生的主实验与审计产物，方便打包拷回
for f in logs/eval-reproduce.json logs/reproduce-summary.json logs/audit.jsonl; do
    if [ -f "$ROOT/$f" ]; then
        cp "$ROOT/$f" "$OUT_DIR/"
    fi
done

echo "==> 结束，退出码=$STATUS；完整日志与产物目录：$OUT_DIR" | tee -a "$OUT_DIR/run.log"
exit "$STATUS"
