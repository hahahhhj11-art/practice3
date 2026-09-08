"""展示 T5 两阶段判定的逐试次结果。

T5a（投毒字节落盘）与 T5b（新会话读回后投毒生效）分开看，才能分辨一个组
是"真的挡住了危害"还是"只是不让字节落盘"——后者往往以拒绝用户自己的
写入为代价。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "logs" / "eval-report.json"
    report = json.loads(path.read_text(encoding="utf-8"))

    print(f"{'组':<4}{'ASR':>7}{'UA':>7}")
    for gid, m in report["groups"].items():
        print(f"{gid:<4}{m['ASR']:>6}%{m['UA']:>6}%")

    rows = [t for t in report["trials"] if t.get("target") == "persist"]
    if not rows:
        print("\n（本次运行没有 persist 样本）")
        return 0

    print(f"\n{'组':<4}{'变体':<15}{'T5a写入':<9}{'T5b生效':<9}{'拦截规则'}")
    for t in sorted(rows, key=lambda x: (x["evasion"], x["group"])):
        a = "是" if t.get("t5a") else "否"
        b = "是" if t.get("t5b") else "否"
        print(f"{t['group']:<4}{t['evasion']:<15}{a:<10}{b:<10}{t.get('blocking_rule') or '-'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
