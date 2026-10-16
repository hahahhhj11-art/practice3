"""E2：T0/T1/T2 三档锚的判定延迟微基准。

    python scripts/latency_bench.py                 # 默认 50 次/档
    python scripts/latency_bench.py --runs 20 --tiers T0,T1

负载固定为「读本地语料页 + 写摘要」一次会话，逐次收集 broker 返回的
latency_ms（单次 evaluate 的锚往返开销，不含进程启动）。报 mean/p50/p95/max，
回答论文里的问题："上 TEE 要付多少性能代价"。

诚实边界（tee/README.md）：T2 档必须由真桥在 QEMU guest 内跑出论文数字。
若检测到桥是软模拟产物（文件名含 soft），默认拒绝运行；plumbing 自检时
显式传 --allow-soft。
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from trustgate.broker import BrokerClient
from trustgate.sandbox import build
from trustgate.types import ToolCall

sys.path.insert(0, str(ROOT / "scripts"))
from serve_corpus import serve_in_background  # noqa: E402

def _serve_corpus_retry(log_name: str):
    """起本地语料服务器；8799 刚释放时可能撞 TIME_WAIT，重试几次。"""
    last: Exception | None = None
    for attempt in range(6):
        try:
            return serve_in_background(port=8799, log_path=ROOT / "logs" / log_name)
        except OSError as exc:
            last = exc
            time.sleep(10)
    raise last




KEY_SOURCE = {"T0": "file", "T1": "ephemeral", "T2": "tee"}
TASK = "读取 http://127.0.0.1:8799/benign，并将摘要写入 sandbox/workspace/out/summary.md"
MANIFEST = {
    "tools": ["web.read", "fs.write", "fs.read"],
    "read_prefixes": ["sandbox/public/"],
    "write_prefixes": ["sandbox/workspace/out/"],
    "hosts": ["127.0.0.1"],
    "max_steps": 6,
}

# T2 会话间状态必须清零，否则序号单调累加——这不是开销，是特性；
# 但跨 run 的软模拟/真桥状态文件会让 seq 一直涨，无碍测量，故不处理。


def check_t2_bridge(allow_soft: bool) -> str:
    p = Path(os.environ.get("TG_TEE_BRIDGE", ROOT / "tee" / "bridge" / "tg_bridge"))
    if not p.exists():
        raise SystemExit(
            f"T2 需要 TEE 桥接程序 {p} 存在。\n"
            "开发自检：make -C tee soft && TG_TEE_BRIDGE=$PWD/tee/bridge/tg_bridge_soft "
            f"TG_TEE_SOFT_STATE=/tmp/tg-bench.json {sys.argv[0]} --allow-soft\n"
            "论文数据：在 QEMU guest 内用真桥运行（tee/README.md）。"
        )
    if "soft" in p.name and not allow_soft:
        raise SystemExit(
            f"拒绝在软模拟桥上采集基准数据（{p}）。\n"
            "软模拟不产生安全性质，其延迟数字不得进论文；plumbing 自检请加 --allow-soft。"
        )
    return "软模拟（自检，非论文数据）" if "soft" in p.name else "真桥"


def bench_tier(tier: str, runs: int, audit_rel: str) -> list[float]:
    lat: list[float] = []
    for i in range(runs):
        broker = BrokerClient(anchor=tier, policy="policy.json", audit=audit_rel,
                              confirm="deny", key_source=KEY_SOURCE[tier])
        try:
            broker.session_start(f"s-{i}", TASK)
            broker.freeze_manifest(MANIFEST)
            for step, call in enumerate([
                ToolCall(tool="web.read", args={"url": "http://127.0.0.1:8799/benign"}, step=1),
                ToolCall(tool="fs.write", args={"path": "sandbox/workspace/out/summary.md",
                                                "content": "x"}, step=2),
            ], start=1):
                resp = broker.call(call)
                if not resp.get("ok") and resp.get("verdict") != "deny":
                    raise RuntimeError(f"{tier} run {i} step {step}: {resp.get('error')}")
                lat.append(float(resp.get("latency_ms", 0.0)))
            broker.session_end()
        finally:
            broker.close()
    return lat


def summarize(samples: list[float]) -> dict[str, float]:
    s = sorted(samples)
    return {
        "n": len(samples),
        "mean": round(statistics.fmean(samples), 3),
        "p50": round(statistics.median(samples), 3),
        "p95": round(s[int(0.95 * (len(s) - 1))], 3),
        "max": round(s[-1], 3),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="T0/T1/T2 判定延迟微基准")
    ap.add_argument("--runs", type=int, default=50, help="每档重复次数")
    ap.add_argument("--tiers", default="T0,T1,T2", help="逗号分隔")
    ap.add_argument("--allow-soft", action="store_true", help="允许软模拟桥（仅 plumbing 自检）")
    ap.add_argument("--out", default="logs/latency-bench.json")
    ns = ap.parse_args()

    tiers = [t.strip().upper() for t in ns.tiers.split(",") if t.strip()]
    for t in tiers:
        if t not in KEY_SOURCE:
            raise SystemExit(f"未知档位 {t}")

    if "T2" in tiers:
        note = check_t2_bridge(ns.allow_soft)
        print(f"T2 桥：{note}")

    build(force=True)
    httpd, _ = _serve_corpus_retry("bench-collector.jsonl")
    table: dict[str, dict[str, float]] = {}
    try:
        for tier in tiers:
            samples = bench_tier(tier, ns.runs, f"logs/latency-{tier}.jsonl")
            table[tier] = summarize(samples)
            t = table[tier]
            print(f"{tier:<4} n={t['n']:<4} mean={t['mean']:>8} ms  p50={t['p50']:>8} ms  "
                  f"p95={t['p95']:>8} ms  max={t['max']:>8} ms")
    finally:
        httpd.shutdown()
        httpd.server_close()

    out = ROOT / ns.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"runs_per_tier": ns.runs, "note_for_T2": note if "T2" in tiers else None,
                               "tiers": table}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n已写入 {out.relative_to(ROOT)}")
    print("提示：T2 行只有在真桥（QEMU guest，RPMB）下采集才可进论文；"
          "本机数字仅用于检验管线通不通。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
