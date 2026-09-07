"""对手 A2 的审计篡改检测演示（安全论断 SC4）。

    python scripts/tamper_demo.py

跑一个真实会话产生审计日志，然后依次施加对手 A2 的四种篡改，逐一给出
校验结果。**最后一格是本项目刻意呈现的一个「检测不出来」。**

## 为什么要专门做这个演示

"哈希链能防篡改"是一句会被追问的话。哈希链保证的是**前缀完整性**：
攻击者删掉尾部 K 条之后，剩下的前缀本身是一条完全合法的链——seq 连续、
prev_hash 首尾相接、每条 MAC 都正确。本地校验器无从发现少了东西。

要检测截断，校验方必须独立地知道"本应有多少条"，也就是锚签发、保存在
这台机器之外的检查点 {seq, head, mac}。这个演示把有检查点与没检查点的
两种结果并排放出来，让"哈希链防不防截断"这个问题有一个精确的答案，
而不是含糊过去。

## 密钥来源同样是论断的一部分

对手 A2 的能力 A2-C1 是"以相同 OS 用户权限读写任意用户态文件"。只要审计
密钥以任何形式落在文件系统上，A2 就能读走它并伪造任意自洽的日志。所以
本演示强制 key_source=ephemeral：密钥只在锚进程的内存里，校验方在会话
期间取走。演示末尾会额外呈现 key_source=file 时同一个攻击的结果——
校验通过，因为攻击者拿着真钥匙。
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from trustgate.agent import Agent
from trustgate.audit import verify_chain
from trustgate.broker import BrokerClient
from trustgate.llm import MockLLM
from trustgate.sandbox import build

sys.path.insert(0, str(ROOT / "scripts"))
from serve_corpus import serve_in_background  # noqa: E402

TASK = "读取 http://127.0.0.1:8799/benign，并将摘要写入 sandbox/workspace/out/summary.md"

# 演示的日志里必须**真的有一条 deny**：A2 要抹掉的正是这种痕迹。
# 若跑一个全程 allow 的良性任务，"把 deny 改成 allow"这个动作不会改动任何
# 字节，校验自然通过——那不是防篡改失效，是演示本身没造出可篡改的内容。
_BENIGN_SCRIPT = {
    "plan": "读网页并写摘要",
    "manifest": {
        "tools": ["web.read", "fs.write"],
        "write_prefixes": ["sandbox/workspace/out/"],
        "hosts": ["127.0.0.1"],
        "max_steps": 6,
    },
    "steps": [
        {"tool": "web.read", "args": {"url": "http://127.0.0.1:8799/benign"}},
        {"tool": "fs.write", "args": {"path": "sandbox/workspace/out/summary.md",
                                      "content": "@@LAST@@"}},
    ],
}
_INJECTED = [{"tool": "fs.read", "args": {"path": "sandbox/private/id_rsa"}}]


def _sealer(key_hex: str) -> Callable[[bytes], str]:
    key = bytes.fromhex(key_hex)
    return lambda data: hmac.new(key, data, hashlib.sha256).hexdigest()


def produce_log(audit_rel: str, key_source: str) -> tuple[Path, dict[str, Any], str]:
    """跑一个真实会话，返回 (日志路径, 离机检查点, 验证密钥)。"""
    path = ROOT / audit_rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)

    build(force=True)
    httpd, _ = serve_in_background(port=8799, log_path=ROOT / "logs" / "tamper-collector.jsonl")
    broker = BrokerClient(anchor="T1", policy="policy.json", audit=audit_rel,
                          confirm="deny", key_source=key_source)
    try:
        # 密钥必须在 Broker 还活着的时候取走：ephemeral 模式下进程一退出
        # 就再也拿不回来，事后无法校验这段日志。这正是 T1 相对 T2 的缺口。
        key = broker.export_key()
        llm = MockLLM(script=_BENIGN_SCRIPT, injected=_INJECTED)
        Agent(llm, broker, verbose=False).run(TASK)
        checkpoint = dict(broker.session_end().get("checkpoint", {})) or broker.checkpoint
    finally:
        broker.close()
        httpd.shutdown()
        httpd.server_close()
    return path, checkpoint, key


# ---------------------------------------------------------------- A2 的四种篡改

def attack_none(_path: Path, _key: str) -> str:
    return "不做任何改动（对照）"


def attack_modify(path: Path, _key: str) -> str:
    """A2-C1：改写记录内容，把一次被拒的敏感读取抹成正常放行。"""
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, ln in enumerate(lines):
        rec = json.loads(ln)
        if rec.get("event") == "tool_call" and rec.get("verdict") == "deny":
            rec["verdict"] = "allow"
            rec["verdict_effective"] = "allow"
            rec["rule"] = "L5.ok"
            rec["path"] = "sandbox/public/about.txt"
            lines[i] = json.dumps(rec, ensure_ascii=False)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return f"把第 {rec['seq']} 条的 deny({rec.get('args_digest', '')[:12]}…) 抹成 allow"
    raise RuntimeError("日志里没有 deny 记录，演示无法构造改写攻击")


def attack_truncate(path: Path, _key: str) -> str:
    """A2-C2：删掉尾部记录，隐藏攻击发生过的痕迹。"""
    lines = path.read_text(encoding="utf-8").splitlines()
    keep = max(len(lines) - 3, 1)
    path.write_text("\n".join(lines[:keep]) + "\n", encoding="utf-8")
    return f"删除尾部 {len(lines) - keep} 条记录（保留 {keep} 条）"


def attack_rebuild(path: Path, _key: str) -> str:
    """A2-C1 的完全形态：用自己的密钥把整条链重建成一份"干净"的历史。"""
    from trustgate.audit import GENESIS, chain_record

    forged_key = b"\x00" * 32

    def seal(data: str) -> str:
        return hmac.new(forged_key, data.encode(), hashlib.sha256).hexdigest()

    lines = path.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    prev = GENESIS
    for seq, ln in enumerate(lines):
        rec = json.loads(ln)
        payload = {k: v for k, v in rec.items() if k not in ("seq", "prev_hash", "hash", "mac")}
        if payload.get("event") == "tool_call":
            payload["verdict"] = "allow"
            payload["verdict_effective"] = "allow"
        h = chain_record(prev, seq, payload)
        out.append(json.dumps({"seq": seq, **payload, "prev_hash": prev, "hash": h, "mac": seal(h)},
                              ensure_ascii=False))
        prev = h
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    return "用攻击者自己的密钥重建整条链（每条记录自洽、seq 连续）"


ATTACKS = [
    ("完好日志", attack_none, True),
    ("改写记录内容", attack_modify, True),
    ("截断尾部记录", attack_truncate, True),
    ("整链重建（攻击者密钥）", attack_rebuild, True),
    # 同一个截断攻击，但校验方手里没有离机检查点。
    ("截断尾部记录（校验方无检查点）", attack_truncate, False),
]


def run_case(label: str, attack: Callable[[Path, str], str], use_checkpoint: bool,
             pristine: Path, checkpoint: dict[str, Any], key: str) -> bool:
    work = pristine.with_name(pristine.stem + "-case.jsonl")
    shutil.copyfile(pristine, work)
    what = attack(work, key)

    report = verify_chain(work, _sealer(key), checkpoint if use_checkpoint else None)
    detected = not report.ok

    print(f"\n── {label}")
    print(f"   A2 的动作：{what}")
    print(f"   校验方持有检查点：{'是' if use_checkpoint else '否'}")
    print(f"   结果：{'检测到篡改 ✔' if detected else '校验通过（未检测到）'}（{report.count} 条记录）")
    for p in report.problems[:3]:
        print(f"     ✗ {p}")
    work.unlink(missing_ok=True)
    return detected


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    ap = argparse.ArgumentParser(description="A2 审计篡改检测演示（SC4）")
    ap.add_argument("--audit", default="logs/tamper-demo.jsonl")
    ns = ap.parse_args()

    print("=" * 74)
    print("对手 A2 审计篡改检测演示 · 可信锚 T1 · 密钥来源 ephemeral（不落盘）")
    print("=" * 74)

    pristine, checkpoint, key = produce_log(ns.audit, "ephemeral")
    n = len(pristine.read_text(encoding="utf-8").splitlines())
    print(f"\n已产生 {n} 条审计记录：{pristine.relative_to(ROOT)}")
    print(f"锚签发的离机检查点：seq={checkpoint.get('seq')} head={str(checkpoint.get('head'))[:16]}…")

    results = [
        (label, run_case(label, atk, use_cp, pristine, checkpoint, key))
        for label, atk, use_cp in ATTACKS
    ]

    print("\n" + "=" * 74)
    print("汇总")
    print("=" * 74)
    for label, detected in results:
        expect_clean = label == "完好日志"
        ok = (not detected) if expect_clean else detected
        icon = "✔" if ok else ("—" if not detected else "✔")
        print(f"  {icon} {label:<34} {'检测到' if detected else '未检测到'}")

    print("""
结论（可直接写进论文的 SC4 表述）：

  · 记录改写、整链重建 —— 只要密钥不在 A2 手里，一律检测得到；
  · 尾部截断 —— **当且仅当**校验方持有锚签发的离机检查点时检测得到。
    没有检查点，剩下的前缀本身是一条完全合法的链，本地校验器无从发现。

因此 SC4 的正确措辞不是"任何修改或截断均可被检测"，而是：
「在 A2 下，对审计日志的改写可被检测；在校验方持有离机检查点时，
  截断与整链重建亦可被检测。」

密钥来源同样是论断的一部分：key_source=file 时密钥与日志同在 A2 可读写的
文件系统里，上面每一格都会变成"校验通过"——因为攻击者拿着真钥匙。
attest() 的 resists_a2_forgery 字段就是为了不让实验报告在这一点上含糊过去。

还有一处 T1 挡不住的缺口：锚的单调序号与链头活在进程内存里，进程重启即
归零，因此 A2 可以重放一份旧的检查点。要同时做到"A2 读不到"与"跨重启
持久"，只有 TEE 的安全存储能给——这正是 T2 存在的技术理由。""")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
