"""按「攻击目标 / 规避层级」拆解受攻击下的效用（UA）。

只报总体 UA 会掩盖代价的分布：如果损失集中在某一类攻击上，那说明是某条
具体规则过于保守，而不是防御整体不可用——这两种情况的修法完全不同。
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "logs" / "eval-report.json"
    report = json.loads(path.read_text(encoding="utf-8"))

    per_group: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for t in report["trials"]:
        if t.get("target") == "benign":
            continue
        cell = f"{t['target']}/{t.get('evasion', '-')}"
        slot = per_group[t["group"]][cell]
        slot[1] += 1
        if t.get("task_completed"):
            slot[0] += 1

    for gid in sorted(per_group):
        rows = [(c, ok, n) for c, (ok, n) in sorted(per_group[gid].items()) if ok < n]
        if not rows:
            print(f"{gid}: UA 无损失（所有格的原任务都完成了）")
            continue
        print(f"{gid}: 以下格存在效用损失")
        for cell, ok, n in rows:
            print(f"    {cell:28s} UA = {100 * ok / n:5.1f}%  ({ok}/{n})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
