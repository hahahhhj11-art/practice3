"""对一次会话做事后取证：注入定位 + 来源归因 + 数据恢复预览。

前提：策略里 forensics.capture 已打开（默认关闭，见 policy.json 的说明），
会话运行后 logs/forensics/<session>.jsonl 里会有 ingest / violation 两类记录。

    python scripts/forensics_report.py --session s-a1b2c3
    python scripts/forensics_report.py --all --sample-index attacks/samples/index.json

给了 --sample-index 时会顺带算定位准确率：样本元数据里的 payload 字段是注入
载荷原文，可作 ground truth。没有 ground truth 时只报"定位到了哪几段"，不编
准确率——这类数字一旦没有真值支撑就只是自说自话。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from trustgate.forensics import (  # noqa: E402
    IngestedDoc,
    localize,
    sanitize,
    span_prf,
    summarize,
    truth_span,
)


def load_session(path: Path) -> tuple[list[IngestedDoc], list[str], list[dict[str, Any]]]:
    """从捕获文件还原 (外部内容文档, 违规参数值, 违规记录)。"""
    docs: list[IngestedDoc] = []
    values: list[str] = []
    violations: list[dict[str, Any]] = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("kind") == "ingest":
            docs.append(
                IngestedDoc(
                    doc_id=f"{rec.get('call_id', i)}",
                    source=str(rec.get("source", "unknown")),
                    content=str(rec.get("content", "")),
                )
            )
        elif rec.get("kind") == "violation":
            violations.append(rec)
            for v in dict(rec.get("args", {})).values():
                if isinstance(v, str):
                    values.append(v)
    return docs, values, violations


def report_one(path: Path, payload_by_source: dict[str, str], show_recovery: bool) -> dict[str, Any]:
    docs, values, violations = load_session(path)
    session = path.stem
    if not docs:
        return {"session": session, "skipped": "没有捕获到任何不可信内容"}
    if not values:
        return {"session": session, "skipped": "本会话没有被拦下的调用，无痕迹可反查"}

    loc = localize(docs, values)
    out: dict[str, Any] = {
        "session": session,
        "violations": [
            {"step": v.get("step"), "tool": v.get("tool"), "rule": v.get("rule")}
            for v in violations
        ],
        **summarize(loc, docs),
    }

    # 定位准确率：只在拿到 ground truth 时才算
    scored: list[dict[str, Any]] = []
    for doc in docs:
        payload = payload_by_source.get(doc.source, "")
        if not payload:
            continue
        truth = truth_span(doc.content, payload)
        if not truth:
            # ground truth 抽取失败（载体把载荷转义得认不出来）。跳过而不是记 0：
            # 把"真值没拿到"算成"定位失败"会低估取证效果，那是另一种自欺。
            scored.append({"doc_id": doc.doc_id, "skipped": "ground truth 未能在原文中定位"})
            continue
        p, r, f1 = span_prf(loc.char_set(doc.doc_id), truth)
        scored.append({
            "doc_id": doc.doc_id, "truth_chars": len(truth),
            "precision": p, "recall": r, "f1": f1,
        })
    if scored:
        out["localization_accuracy"] = scored

    if show_recovery and docs:
        out["recovery_preview"] = sanitize(docs[0], loc)[:400]
    return out


def build_payload_index(index_path: Path) -> dict[str, str]:
    """source → 注入载荷原文。捕获记录里的 source 形如 web:<url>，与样本的 url 对齐。"""
    if not index_path.exists():
        return {}
    out: dict[str, str] = {}
    for rec in json.loads(index_path.read_text(encoding="utf-8")):
        payload = str(rec.get("payload", ""))
        if not payload:
            continue
        url = str(rec.get("url", ""))
        out[url] = payload
        out[f"web:{url}"] = payload
        out[f"web:{url}#untrusted"] = payload
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="TrustGate 异步取证报告")
    ap.add_argument("--session", help="只分析这一个会话（logs/forensics/<session>.jsonl）")
    ap.add_argument("--all", action="store_true", help="分析捕获目录下的全部会话")
    ap.add_argument("--dir", default="logs/forensics")
    ap.add_argument("--sample-index", default="attacks/samples/index.json",
                    help="样本索引，用于取 ground truth 算定位准确率")
    ap.add_argument("--recovery", action="store_true", help="附带展示摘除注入段后的正文预览")
    ap.add_argument("--json", action="store_true")
    ns = ap.parse_args()

    cap_dir = ROOT / ns.dir
    if not cap_dir.is_dir():
        print(
            f"捕获目录不存在：{cap_dir}\n"
            "取证捕获默认关闭。请在 policy.json 里把 forensics.capture 设为 true 后重跑会话。",
            file=sys.stderr,
        )
        return 2

    if ns.session:
        files = [cap_dir / f"{ns.session}.jsonl"]
    elif ns.all:
        files = sorted(cap_dir.glob("*.jsonl"))
    else:
        ap.error("请指定 --session 或 --all")

    files = [f for f in files if f.is_file()]
    if not files:
        print("没有找到任何捕获文件", file=sys.stderr)
        return 2

    payloads = build_payload_index(ROOT / ns.sample_index)
    reports = [report_one(f, payloads, ns.recovery) for f in files]

    if ns.json:
        print(json.dumps(reports, ensure_ascii=False, indent=2))
        return 0

    for rep in reports:
        print("=" * 72)
        print(f"会话 {rep['session']}")
        if rep.get("skipped"):
            print(f"  跳过：{rep['skipped']}")
            continue
        for v in rep["violations"]:
            print(f"  违规 #{v['step']} {v['tool']} ← {v['rule']}")
        print(f"  候选片段 {rep['span_count']} 段，命中 {rep['hit_count']} 段")
        print("  来源归因（分数越高越可能是注入入口）：")
        for src, score in rep["attribution"] or [("（无）", 0)]:
            print(f"    {score:>5}  {src}")
        print("  定位到的片段：")
        for s in rep["top_spans"]:
            if s["score"] <= 0:
                continue
            print(f"    [{s['start']}:{s['end']}] 分数 {s['score']}  {s['text'][:100]}")
            print(f"        由此派生的违规参数：{s['matched']}")
        for acc in rep.get("localization_accuracy", []):
            if acc.get("skipped"):
                print(f"  定位准确率（{acc['doc_id']}）：{acc['skipped']}")
            else:
                print(
                    f"  定位准确率（{acc['doc_id']}）：精度 {acc['precision']} "
                    f"召回 {acc['recall']} F1 {acc['f1']}（真值 {acc['truth_chars']} 字符）"
                )
        if rep.get("recovery_preview"):
            print("  摘除注入段后的正文预览：")
            print("    " + rep["recovery_preview"].replace("\n", "\n    ")[:400])
    print("=" * 72)
    print(f"共分析 {len(reports)} 个会话")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
