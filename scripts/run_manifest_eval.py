"""让模型在读外部内容之前生成能力清单，并和人工参考清单比较。

无 ``TG_API_KEY`` 时以退出码 3 结束，不输出任何比例。有 key 时才调用模型。
效用下降用 MockLLM 执行良性步骤来测，这样掉下去的是清单不够，不是模型没调用工具。

    python scripts/run_manifest_eval.py --model gpt-4o-mini
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(description="能力清单生成评测")
    ap.add_argument("--model", default="gpt-4o-mini")
    ap.add_argument("--measure-ua", action="store_true",
                    help="对申请不足的任务再跑一遍 C5，看良性步骤是否完不成")
    ap.add_argument("--out", default="logs/manifest-eval.json")
    ns = ap.parse_args(argv)

    if not os.environ.get("TG_API_KEY", "").strip():
        print(
            "未设置 TG_API_KEY。不生成清单，也不输出任何比例。\n"
            "人工参考清单已经在良性样本的 reference_manifest 里，"
            "但没有模型输出就不能算申请不足或申请过多。",
            file=sys.stderr,
        )
        return 3

    return _run(ns)


def _run(ns: argparse.Namespace) -> int:
    from eval.manifest_eval import dump_report, evaluate, propose_manifest
    from eval.stats import format_rate

    def propose(task: str) -> dict:
        return propose_manifest(task, ns.model)

    workdir = ROOT / "logs" / "manifest-workdir"
    report = evaluate(propose, measure_ua=ns.measure_ua, workdir=workdir)
    dump_report(report, Path(ns.out))
    under = report["under_request"]
    over = report["over_request"]
    lost = report["ua_lost_when_under"]
    print(f"样本 {report['n']} 条，对照的是 reference_manifest，不是垫到至少 8 步的 harness 清单。")
    print(f"申请不足 {format_rate(int(under['k']), int(under['n']))}")
    print(f"申请过多 {format_rate(int(over['k']), int(over['n']))}")
    if ns.measure_ua:
        print(f"申请不足时原任务完不成 {format_rate(int(lost['k']), int(lost['n']))}")
    else:
        print("未测效用下降。加上 --measure-ua 才会跑良性步骤。")
    print(f"完整结果 → {ns.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
