#!/usr/bin/env bash
# 本地 LLM 环境一键搭建：llama.cpp (CPU) + Qwen2.5-7B-Instruct q3_k_m
#
# 用途：跑真实模型实验（eval/run_model_eval.py）的本地对照模型。
# 该模型对齐较弱、会被本仓库攻击语料骗到（S≈38%，见 docs/03 §6.3），
# 与 DeepSeek/kimi-k3 等对齐良好的模型（S=0）构成两极对照。
#
# 用法：
#   bash scripts/setup_local_llm.sh          # 下载 + 启动（幂等，已下载则跳过）
#   bash scripts/setup_local_llm.sh stop     # 停止服务
#
# 启动后配合评测：
#   TG_API_KEY=local TG_BASE_URL=http://127.0.0.1:8899/v1 \
#     python3 -m eval.run_model_eval --model qwen2.5-7b-instruct \
#       --limit 5 --runs 3 --temperature 1.0 --no-cache
#
# 注意：模型权重约 3.8GB，下载到 .local/（已被 .gitignore 排除，不进版本库）。
# 端口 8899 刻意避开测试端口（tests 用 8799 与 8811），与测试套件互不干扰。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUNTIME="$ROOT/.local/llama"
BUILD="b12318"
MODEL_FILE="qwen2.5-7b-instruct-q3_k_m.gguf"
MODEL_URL="https://hf-mirror.com/Qwen/Qwen2.5-7B-Instruct-GGUF/resolve/main/$MODEL_FILE"
BIN_URL="https://github.com/ggml-org/llama.cpp/releases/download/$BUILD/llama-$BUILD-bin-ubuntu-x64.tar.gz"

if [ "${1:-}" = "stop" ]; then
    pkill -f "llama-server.*--port 8899" && echo "已停止" || echo "服务未在运行"
    exit 0
fi

mkdir -p "$RUNTIME"
cd "$RUNTIME"

if [ ! -x "llama-$BUILD/llama-server" ]; then
    echo "==> 下载 llama.cpp $BUILD (ubuntu-x64 CPU)"
    curl -sL -o llama.tar.gz "$BIN_URL"
    tar xzf llama.tar.gz
fi

if [ ! -f "$MODEL_FILE" ]; then
    echo "==> 下载 Qwen2.5-7B-Instruct q3_k_m（约 3.8GB，耐心等待）"
    curl -sL -o "$MODEL_FILE" "$MODEL_URL"
fi

if curl -s -m 2 http://127.0.0.1:8899/v1/models > /dev/null 2>&1; then
    echo "==> 服务已在运行（:8899）"
else
    echo "==> 启动 llama-server（:8899，8 线程）"
    nohup ./"llama-$BUILD"/llama-server -m "$MODEL_FILE" \
        --alias qwen2.5-7b-instruct --port 8899 -t 8 -c 4096 --no-warmup \
        > server.log 2>&1 &
    for i in $(seq 1 60); do
        curl -s -m 2 http://127.0.0.1:8899/v1/models > /dev/null 2>&1 && break
        sleep 2
    done
fi

curl -s -m 10 http://127.0.0.1:8899/v1/models | head -c 200
echo
echo "==> 就绪。预检：TG_API_KEY=local TG_BASE_URL=http://127.0.0.1:8899/v1 python3 -m eval.run_model_eval --model qwen2.5-7b-instruct --preflight"
