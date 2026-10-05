"""把 eval 报告渲染成可直接粘进 README/docs 的 Markdown 表。

存在的理由很实际：主表与分格表要同时出现在 README、docs/03 和论文里，手抄三遍
必然抄错一处，而抄错的那个数字看不出来是抄错的。既然报告 JSON 是唯一事实来源，
表格就应该由它生成。

    python scripts/report_table.py logs/eval-main.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

GROUP_NAMES = {
    "C0": "无防护基线",
    "C1": "提示层加固（Spotlighting）",
    "C2": "静态规则（L1）",
    "C3": "+ 任务-能力绑定与污点溯源（L2+L3）",
    "C4": "+ 跨步骤时序策略（L4）",
    "C5": "完整防御 + 可信锚 T1",
}

CELL_NAMES = {
    "read": "读", "delete": "删", "overwrite": "覆盖", "exfil": "外泄", "persist": "注入",
}
EVASION_NAMES = {
    "naive": "朴素", "policy_aware": "合规内", "lowbw": "低带宽", "path_lowbw": "路径低带宽",
    "prefix_widen": "前缀放宽", "basename_launder": "同名洗白", "subthreshold": "阈下分片",
}


def cell_label(cell: str) -> str:
    tgt, _, ev = cell.partition("/")
    return f"{CELL_NAMES.get(tgt, tgt)}/{EVASION_NAMES.get(ev, ev)}"


def main() -> int:
    for s in (sys.stdout, sys.stderr):
        if hasattr(s, "reconfigure"):
            s.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser()
    ap.add_argument("report", nargs="?", default="logs/eval-main.json")
    ns = ap.parse_args()

    path = ROOT / ns.report
    report = json.loads(path.read_text(encoding="utf-8"))
    groups = report["groups"]
    trials = report["trials"]
    meta = report["meta"]

    print(f"来源 {ns.report} · 攻击样本 {meta['n_attack_samples']} 条 "
          f"· 良性任务 {meta['n_benign_samples']} 条 · {meta['llm']}\n")

    print("## 主表\n")
    print("| 组 | 防御配置 | ASR | UA | BTC | 良性 FPR | 判定命中率 | 实际阻断率 | P50 | P95 |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for gid, m in groups.items():
        print(
            f"| {gid} | {GROUP_NAMES.get(gid, gid)} | {m['ASR']}% | {m['UA']}% | {m['BTC']}% "
            f"| {m['FPR_benign_calls']}% | {m.get('flag_rate_calls', 0)}% | {m['BR_calls']}% "
            f"| {m['latency_p50_ms']}ms | {m['latency_p95_ms']}ms |"
        )

    cells = sorted({f"{t['target']}/{t['evasion']}" for t in trials if t["target"] != "benign"})
    print("\n## 分格 ASR（%）\n")
    print("| 组 | " + " | ".join(cell_label(c) for c in cells) + " |")
    print("| --- |" + " --- |" * len(cells))
    for gid in groups:
        row = []
        for c in cells:
            sub = [
                t for t in trials
                if t["group"] == gid and f"{t['target']}/{t['evasion']}" == c
            ]
            if not sub:
                row.append("-")
                continue
            asr = round(100 * sum(1 for t in sub if t["attack_success"]) / len(sub))
            row.append(f"**{asr}**" if asr else "0")
        print(f"| {gid} | " + " | ".join(row) + " |")

    print("\n## 各格预期拦截层 vs 实测（C5）\n")
    print("| 格 | 预期层 | 实测规则 |")
    print("| --- | --- | --- |")
    for c in cells:
        sub = [
            t for t in trials
            if t["group"] == "C5" and f"{t['target']}/{t['evasion']}" == c
        ]
        if not sub:
            continue
        expect = sub[0]["expect_layer"]
        rules = sorted({t["blocking_rule"] for t in sub if t["blocking_rule"]})
        ok = "✔" if all(r.startswith(expect) for r in rules) and rules else "✗"
        print(f"| {cell_label(c)} | {expect} | {', '.join(f'`{r}`' for r in rules) or '（无）'} {ok} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
