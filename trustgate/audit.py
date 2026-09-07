"""防篡改审计日志：哈希链 + HMAC。

对应威胁模型对手 A2：
  A2-C2 可截断日志  -> prev_hash 链 + 单调 seq，删尾可被检测
  A2-C1 可改写内容  -> HMAC，密钥由 TrustedAnchor 持有，不落盘
  A2-C3 可回滚策略  -> 每条记录内嵌 policy_hash
详见 docs/02-系统架构.md §5.3。

**链头权威在锚内，不在日志文件里。**
早先的实现从日志最后一行恢复 (seq, prev_hash) 再继续追加。这让截断攻击
完全免疫检测：A2 删掉日志尾部若干条，下次启动时 Broker 从被截断处接着
写，产出的链自洽、seq 连续、每条 MAC 都对——校验器看不出任何异常。
真正的修法是让计数器和链头待在 A2 够不着的地方，也就是可信锚。本模块
因此不再自行推导链状态，只负责把锚签发的记录落盘。
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

GENESIS = "0" * 64


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_args(args: dict[str, Any]) -> str:
    """审计日志只存参数摘要，避免日志本身成为敏感数据泄露点。"""
    payload = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return "sha256:" + sha256_hex(payload.encode())[:16]


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


@dataclass
class VerifyReport:
    ok: bool
    count: int
    problems: list[str]

    def describe(self) -> str:
        head = f"审计链校验：{'通过' if self.ok else '失败'}（{self.count} 条记录）"
        if self.problems:
            return head + "\n" + "\n".join("  ✗ " + p for p in self.problems)
        return head


class AuditLog:
    """追加式哈希链日志的**落盘端**。

    序号、链头与 MAC 全部由 TrustedAnchor 签发（chain_fn）；本类既不持有
    密钥，也不推导链状态，因此即便攻击者完全控制这个进程和这个文件，
    也无法让被篡改的日志通过校验。
    """

    def __init__(
        self,
        path: str | Path,
        chain_fn: Callable[[dict[str, Any]], dict[str, Any]],
        device: str = "dev-local",
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._chain = chain_fn
        self.device = device
        self._head = GENESIS

    @property
    def head(self) -> str:
        """当前链头。定期外发到手机/云端可防止 A2 重建整条链。"""
        return self._head

    def append(self, event: str, policy_hash: str, session: str = "", **fields: Any) -> dict[str, Any]:
        payload = {
            "ts": round(time.time(), 3),
            "device": self.device,
            "session": session,
            "event": event,
            "policy_hash": policy_hash,
            **fields,
        }
        sealed = self._chain(payload)
        record = {
            "seq": sealed["seq"],
            **payload,
            "prev_hash": sealed["prev_hash"],
            "hash": sealed["hash"],
            "mac": sealed["mac"],
        }

        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

        self._head = sealed["hash"]
        return record

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as fh:
            return [json.loads(ln) for ln in fh if ln.strip()]


def chain_record(prev_hash: str, seq: int, payload: dict[str, Any]) -> str:
    """链上单条记录的哈希。锚与校验器必须用同一个函数，否则校验恒失败。"""
    body = {"seq": seq, **payload}
    return sha256_hex(prev_hash.encode() + b"|" + _canonical(body))


def verify_chain(
    path: str | Path,
    seal_fn: Callable[[bytes], str],
    checkpoint: dict[str, Any] | None = None,
) -> VerifyReport:
    """离机校验：逐条重算哈希链与 MAC，并与外发保存的检查点对账。

    checkpoint 是锚在会话结束时签发的 {seq, head, mac}，应当保存在这台
    机器之外（手机、云端）。**没有它，尾部截断在原理上就无法检测**——
    删掉最后 K 条之后剩下的前缀本身是一条完全合法的链。这一点必须在
    论文里讲清楚，而不是含糊地说"哈希链能防截断"。
    """
    records = []
    p = Path(path)
    if p.exists():
        with p.open("r", encoding="utf-8") as fh:
            records = [json.loads(ln) for ln in fh if ln.strip()]

    problems: list[str] = []
    prev = GENESIS
    for i, rec in enumerate(records):
        if rec.get("seq") != i:
            problems.append(f"#{i} seq 不连续（得到 {rec.get('seq')}）——有记录被删除或插入")
        if rec.get("prev_hash") != prev:
            problems.append(f"#{i} prev_hash 断链——前序记录被修改或删除")

        payload = {k: v for k, v in rec.items() if k not in ("seq", "prev_hash", "hash", "mac")}
        recomputed = chain_record(str(rec.get("prev_hash", "")), int(rec.get("seq", -1)), payload)
        if recomputed != rec.get("hash"):
            problems.append(f"#{i} hash 不匹配——记录内容被篡改")
        elif seal_fn(recomputed.encode()) != rec.get("mac"):
            problems.append(f"#{i} MAC 不匹配——记录由无密钥方伪造")

        prev = str(rec.get("hash", ""))

    if checkpoint:
        exp_head = str(checkpoint.get("head", ""))
        exp_seq = int(checkpoint.get("seq", -1))
        if seal_fn(f"{exp_seq}|{exp_head}".encode()) != checkpoint.get("mac"):
            problems.append("检查点自身 MAC 无效——检查点被伪造")
        elif len(records) != exp_seq:
            problems.append(
                f"记录数 {len(records)} 与检查点声明的 {exp_seq} 不符——日志被截断或删改"
            )
        elif prev != exp_head:
            problems.append("链头与检查点不一致——日志被整体重建")

    return VerifyReport(ok=not problems, count=len(records), problems=problems)
