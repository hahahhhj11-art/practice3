"""把 eval 报告渲染成可直接粘进 README/docs 的 Markdown 表。

存在的理由很实际：主表与分格表要同时出现在 README、docs/03 和论文里，手抄三遍
必然抄错一处，而抄错的那个数字看不出来是抄错的。既然报告 JSON 是唯一事实来源，
表格就应该由它生成。文末的「可粘贴摘要」把同一批数字收成一段，文档只许从这里
抄，不许从记忆里补。

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
# 自适应格在分格表上标 †。名字集中在这里，是为了让 README 与 docs 用的是
# 同一份标记，而不是各写各的。
ADAPTIVE = {"prefix_widen", "basename_launder", "subthreshold"}
TARGET_ORDER = ("read", "delete", "overwrite", "exfil", "persist")
EVASION_ORDER = (
    "naive", "policy_aware", "prefix_widen", "lowbw", "path_lowbw",
    "basename_launder", "subthreshold",
)


def cell_label(cell: str, dagger: bool = True) -> str:
    tgt, _, ev = cell.partition("/")
    label = f"{CELL_NAMES.get(tgt, tgt)}/{EVASION_NAMES.get(ev, ev)}"
    if dagger and ev in ADAPTIVE:
        label += "†"
    return label


def _cell_key(cell: str) -> tuple[int, int, str]:
    tgt, _, ev = cell.partition("/")
    ti = TARGET_ORDER.index(tgt) if tgt in TARGET_ORDER else len(TARGET_ORDER)
    ei = EVASION_ORDER.index(ev) if ev in EVASION_ORDER else len(EVASION_ORDER)
    return (ti, ei, cell)


def corpus_blurb() -> str:
    """语料库规模只从 index.json 数，不写死。生成器增删变体时这里跟着变。"""
    index = ROOT / "attacks" / "samples" / "index.json"
    if not index.exists():
        return "未找到 attacks/samples/index.json（先运行 python attacks/generate.py --clean）。"
    records = json.loads(index.read_text(encoding="utf-8"))
    cells: dict[str, int] = {}
    for r in records:
        key = f"{r['target']}/{r['evasion']}"
        cells[key] = cells.get(key, 0) + 1
    per = sorted(set(cells.values()))
    per_s = str(per[0]) if len(per) == 1 else "、".join(str(n) for n in per)
    return f"语料库 {len(records)} 条、{len(cells)} 格（每格 {per_s} 条）。"


def render(report: dict, source: str) -> str:
    groups = report["groups"]
    trials = report["trials"]
    meta = report["meta"]
    cells = sorted(
        {f"{t['target']}/{t['evasion']}" for t in trials if t["target"] != "benign"},
        key=_cell_key,
    )
    lines = [
        f"来源 `{source}` · 本报告攻击样本 {meta['n_attack_samples']} 条 "
        f"· 良性任务 {meta['n_benign_samples']} 条 · {meta['llm']}",
        corpus_blurb(),
        "",
        "## 主表",
        "",
        "| 组 | 防御配置 | ASR | UA | BTC | 良性 FPR | 良性确认率 | 判定命中率 | 实际阻断率 | P50 | P95 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for gid, m in groups.items():
        lines.append(
            f"| {gid} | {GROUP_NAMES.get(gid, gid)} | {m['ASR']}% | {m['UA']}% | {m['BTC']}% "
            f"| {m['FPR_benign_calls']}% | {m.get('confirm_rate_benign', 0)}% "
            f"| {m.get('flag_rate_calls', 0)}% | {m['BR_calls']}% "
            f"| {m['latency_p50_ms']:.3f}ms | {m['latency_p95_ms']:.3f}ms |"
        )

    lines += [
        "",
        "## 分格 ASR（%）",
        "",
        "| 组 | " + " | ".join(cell_label(c) for c in cells) + " |",
        "| --- |" + " --- |" * len(cells),
    ]
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
        lines.append(f"| {gid} | " + " | ".join(row) + " |")

    lines += [
        "",
        "## 各格预期拦截层 vs 实测（C5）",
        "",
        "| 格 | 预期层 | 实测规则 |",
        "| --- | --- | --- |",
    ]
    n_ok = 0
    n_bad = 0
    for c in cells:
        sub = [
            t for t in trials
            if t["group"] == "C5" and f"{t['target']}/{t['evasion']}" == c
        ]
        if not sub:
            continue
        expect = sub[0]["expect_layer"]
        rules = sorted({t["blocking_rule"] for t in sub if t["blocking_rule"]})
        ok = bool(rules) and all(str(r).startswith(expect) for r in rules)
        if ok:
            n_ok += 1
        else:
            n_bad += 1
        mark = "✔" if ok else "✗"
        lines.append(
            f"| {cell_label(c)} | {expect} | "
            f"{', '.join(f'`{r}`' for r in rules) or '（无）'} {mark} |"
        )

    c0 = groups.get("C0", {})
    c5 = groups.get("C5", {})
    lines += [
        "",
        "## 可粘贴摘要",
        "",
        corpus_blurb() + (
            f"本报告抽样 {meta['n_attack_samples']} 条攻击 + "
            f"{meta['n_benign_samples']} 条良性，后端 {meta['llm']}。"
        ),
        (
            f"C0 ASR {c0.get('ASR', '—')}%、UA {c0.get('UA', '—')}%、"
            f"BTC {c0.get('BTC', '—')}%、良性 FPR {c0.get('FPR_benign_calls', '—')}%、"
            f"良性确认率 {c0.get('confirm_rate_benign', '—')}%、"
            f"判定命中率 {c0.get('flag_rate_calls', '—')}%、"
            f"实际阻断率 {c0.get('BR_calls', '—')}%、"
            f"P50 {c0.get('latency_p50_ms', 0):.3f}ms、P95 {c0.get('latency_p95_ms', 0):.3f}ms。"
        ),
        (
            f"C5 ASR {c5.get('ASR', '—')}%、UA {c5.get('UA', '—')}%、"
            f"BTC {c5.get('BTC', '—')}%、良性 FPR {c5.get('FPR_benign_calls', '—')}%、"
            f"良性确认率 {c5.get('confirm_rate_benign', '—')}%、"
            f"判定命中率 {c5.get('flag_rate_calls', '—')}%、"
            f"实际阻断率 {c5.get('BR_calls', '—')}%、"
            f"P50 {c5.get('latency_p50_ms', 0):.3f}ms、P95 {c5.get('latency_p95_ms', 0):.3f}ms。"
        ),
        f"C5 预期层对账：{n_ok} 格一致，{n_bad} 格偏离。",
        "以上数字全部来自本报告 JSON，不要手改。",
    ]
    return "\n".join(lines)


def main() -> int:
    for s in (sys.stdout, sys.stderr):
        if hasattr(s, "reconfigure"):
            s.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser()
    ap.add_argument("report", nargs="?", default="logs/eval-main.json")
    ns = ap.parse_args()

    path = Path(ns.report)
    if not path.is_absolute():
        path = ROOT / path
    report = json.loads(path.read_text(encoding="utf-8"))
    print(render(report, ns.report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
