"""T1 → T2 能力差值实验（E1）：跨会话重放旧检查点检测。

    python scripts/replay_demo.py

攻击场景（docs/06-T2可信锚实现方案.md §5 E1）：

    会话 A 跑完，校验方留存检查点 C_A；会话 B 又产生了若干条记录，
    但 B 结束后的新检查点 C_B 因故未送达校验方（外发通道被 A2 掐断——
    观测 IPC 流量本就在 A2-C4 能力范围内）。A2 随后**截断日志到 C_A**
    并把 C_A 当最新检查点交差。

判定：

    链校验本身对截断后的前缀**一律通过**（剩下的前缀是一条完全合法的链，
    这正是哈希链的已知边界）。差别只在锚能不能反驳：

      · T2：TA 内的持久单调序号 > C_A.seq——"我签发过更多记录，这份
        检查点是旧的"，当场抓获；
      · T1-ephemeral：重启后密钥与序号全部消失，校验在构造上就无法进行；
      · T1-file：重启后锚一样记不得签过多少条——它无法区分"被截断"与
        "正常重启"，因此该信号永远没有权威（且密钥本就可被 A2 读走）。

结论行可直接写进论文 §9：T1 → T2 的差值 = "锚在重启后仍能反驳陈旧检查点"。

诚实边界：T2 档必须由真桥（tee/README.md）跑出论文数字；本脚本在开发机上
可指向软模拟桥用于 plumbing 自检，输出中会如实标注桥的类型。
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from trustgate.audit import verify_chain
from trustgate.broker import BrokerClient
from trustgate.sandbox import build

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




TASK = "读取 http://127.0.0.1:8799/benign，并将摘要写入 sandbox/workspace/out/summary.md"
MANIFEST = {
    "tools": ["web.read", "fs.write", "fs.read"],
    "read_prefixes": ["sandbox/public/"],
    "write_prefixes": ["sandbox/workspace/out/"],
    "hosts": ["127.0.0.1"],
    "max_steps": 6,
}

TIERS = [
    # (标签, anchor 档, 密钥来源)
    ("T1-ephemeral", "T1", "ephemeral"),
    ("T1-file", "T1", "file"),
    ("T2", "T2", "tee"),
]


def _sealer(key_hex: str) -> Callable[[bytes], str]:
    key = bytes.fromhex(key_hex)
    return lambda data: hmac.new(key, data, hashlib.sha256).hexdigest()


def _bridge_note() -> str:
    import os
    p = Path(os.environ.get("TG_TEE_BRIDGE", ROOT / "tee" / "bridge" / "tg_bridge"))
    kind = "软模拟（开发自检，非实验数据）" if "soft" in p.name else "真桥"
    return f"{p}（{kind}）"


def produce(tag: str, anchor: str, key_source: str,
            audit_rel: str) -> tuple[Path, dict[str, Any], dict[str, Any], str]:
    """两个会话 + 两次离机检查点，返回 (日志路径, C_A, C_B, 验证密钥)。"""
    from trustgate.types import ToolCall

    path = ROOT / audit_rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    broker = BrokerClient(anchor=anchor, policy="policy.json", audit=audit_rel,
                          confirm="deny", key_source=key_source, allow_key_export=True)
    try:
        key = broker.export_key()
        broker.session_start("s-A", TASK)
        broker.freeze_manifest(MANIFEST)
        r = broker.call(ToolCall(tool="web.read", args={"url": "http://127.0.0.1:8799/benign"}, step=1))
        assert r.get("ok"), r.get("error")
        r = broker.call(ToolCall(tool="fs.write", args={"path": "sandbox/workspace/out/summary.md",
                                                        "content": "A"}, step=2))
        assert r.get("ok"), r.get("error")
        c_a = dict(broker.session_end().get("checkpoint", {}))

        broker.session_start("s-B", TASK)
        broker.freeze_manifest(MANIFEST)
        r = broker.call(ToolCall(tool="fs.read", args={"path": "sandbox/public/about.txt"}, step=1))
        assert r.get("ok"), r.get("error")
        r = broker.call(ToolCall(tool="fs.write", args={"path": "sandbox/workspace/out/summary.md",
                                                        "content": "B"}, step=2))
        assert r.get("ok"), r.get("error")
        c_b = dict(broker.session_end().get("checkpoint", {}))
    finally:
        broker.close()
    return path, c_a, c_b, key


def anchor_now(anchor: str, key_source: str, tag: str) -> dict[str, Any]:
    """重启后的锚当前状态：只读探针，不追加任何审计记录。

    因此一致性判据就是简单的 now.seq == 出示检查点.seq：诚实场景下锚的
    持久状态与最新离机检查点对得上；A2 重放旧检查点时必然对不上。
    """
    broker = BrokerClient(anchor=anchor, policy="policy.json",
                          audit=f"logs/replay-verify-{tag}.jsonl",
                          confirm="deny", key_source=key_source, allow_key_export=True)
    try:
        return broker.probe_checkpoint()
    finally:
        broker.close()


def truncate_to(path: Path, checkpoint: dict[str, Any]) -> int:
    lines = path.read_text(encoding="utf-8").splitlines()
    keep = int(checkpoint.get("seq", len(lines)))
    path.write_text("\n".join(lines[:keep]) + "\n", encoding="utf-8")
    return keep


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    ap = argparse.ArgumentParser(description="T1→T2 差值实验：跨会话重放旧检查点检测")
    ap.add_argument("--out", default="logs/replay-demo-result.json")
    ns = ap.parse_args()

    build(force=True)
    httpd, _ = _serve_corpus_retry("replay-collector.jsonl")

    print("=" * 74)
    print("T1 → T2 能力差值实验 · 跨会话重放旧检查点")
    print(f"TEE 桥：{_bridge_note()}")
    print("=" * 74)

    results: list[dict[str, Any]] = []
    try:
        for label, anchor, ks in TIERS:
            tag = label.replace("-", "_").lower()
            log, c_a, c_b, key = produce(label, anchor, ks, f"logs/replay-{tag}.jsonl")
            pristine = log.with_name(log.stem + "-pristine.jsonl")
            shutil.copyfile(log, pristine)

            for scenario in ("control", "attack"):
                work = log if scenario == "control" else pristine.with_name(
                    pristine.stem + f"-{scenario}.jsonl")
                shutil.copyfile(pristine, work)
                presented = c_b if scenario == "control" else c_a
                if scenario == "attack":
                    truncate_to(work, c_a)

                rep = verify_chain(work, _sealer(key), presented)
                now = anchor_now(anchor, ks, f"{tag}-{scenario}")
                consistent = int(now.get("seq", -1)) == int(presented.get("seq", -2))

                if anchor == "T2":
                    if rep.ok and consistent:
                        verdict, icon = "通过（无篡改）", "✔"
                    elif rep.ok and not consistent:
                        verdict, icon = "检测到重放/截断", "✔"
                    else:
                        verdict, icon = f"链校验失败（{rep.problems[0] if rep.problems else '?'})", "✗"
                else:
                    # T1：重启后的锚无权威状态。ephemeral 连密钥都已消失。
                    if ks == "ephemeral" and not rep.ok:
                        verdict, icon = "校验无法进行（密钥已随进程消失）→ 未检测", "—"
                    else:
                        verdict, icon = "锚无持久状态可反驳 → 未检测", "—"

                results.append({"tier": label, "scenario": scenario, "verdict": verdict,
                                "chain_ok": rep.ok, "consistent": consistent,
                                "presented_seq": presented.get("seq"),
                                "anchor_now_seq": now.get("seq")})
                print(f"\n[{label} · {'无攻击对照' if scenario == 'control' else '截断+重放旧检查点'}]")
                print(f"   出示检查点 seq={presented.get('seq')}  链校验: "
                      f"{'通过' if rep.ok else '失败'}  锚当前 seq={now.get('seq')}")
                print(f"   结果：{icon} {verdict}")
                work.unlink(missing_ok=True)
    finally:
        httpd.shutdown()
        httpd.server_close()

    print("\n" + "=" * 74)
    print("汇总（论文 §9 素材）")
    print("=" * 74)
    for r in results:
        s = "无攻击" if r["scenario"] == "control" else "重放攻击"
        print(f"  {r['tier']:<14} {s:<6} → {r['verdict']}")

    print("""
结论（SC 表述）：
  截断后的前缀本身是一条完全合法的链，链校验**一律通过**——检出攻击靠的是
  锚的持久状态对陈旧检查点的反驳：
    · T2：TA 内单调序号重启不丢，seq 对不上即抓获；
    · T1：重启后密钥与序号归零（ephemeral）或失去权威（file），
      构造上就无法反驳任何旧检查点。
  这一格差值就是"TEE 到底必不必要"的量化回答。""")

    out = ROOT / ns.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"bridge": _bridge_note(), "results": results},
                              ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n明细已写入 {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
