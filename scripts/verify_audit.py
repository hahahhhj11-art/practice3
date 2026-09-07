"""离机校验 TrustGate 审计日志的哈希链与 HMAC。

「离机」两个字是认真的：这个脚本代表的是保管在手机或云端的那个校验方，
它只应该拥有三样东西——日志副本、会话结束时取回的验证密钥、以及锚签发
的检查点。它**不应该**去读本机的 .trustgate/anchor.key，因为在对手 A2
的能力模型里那把密钥早就被读走了。

    --key 与 --checkpoint 都提供   → 能检测改写、截断、重建（完整 SC4）
    只提供 --key                   → 只能检测链内改写，测不出尾部截断
    两个都不提供（--local-key）    → 仅供 T0 功能自测，不构成任何安全论断
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from trustgate.anchor import InProcessAnchor
from trustgate.audit import verify_chain


def main() -> int:
    parser = argparse.ArgumentParser(description="校验 TrustGate 防篡改审计链")
    parser.add_argument("--audit", default="logs/audit.jsonl")
    parser.add_argument("--policy", default="policy.json")
    parser.add_argument("--key", help="会话期间取回的验证密钥（hex）")
    parser.add_argument("--checkpoint", help="锚签发的检查点 JSON 文件或内联 JSON")
    parser.add_argument(
        "--local-key",
        action="store_true",
        help="退化模式：从本机密钥文件取密钥，仅用于 T0 自测，不成立任何安全论断",
    )
    args = parser.parse_args()

    audit_path = (ROOT / args.audit).resolve()
    if not audit_path.is_file():
        print(f"审计日志不存在：{audit_path}", file=sys.stderr)
        return 2

    if args.key:
        key = bytes.fromhex(args.key)

        def seal(data: bytes) -> str:
            return hmac.new(key, data, hashlib.sha256).hexdigest()

        key_note = "使用离机保管的验证密钥"
    elif args.local_key:
        policy_path = (ROOT / args.policy).resolve()
        if not policy_path.is_file():
            print(f"策略文件不存在：{policy_path}", file=sys.stderr)
            return 2
        seal = InProcessAnchor(str(policy_path)).seal
        key_note = "⚠ 使用本机密钥文件——对手 A2 同样读得到它，本次校验不构成防篡改论断"
    else:
        print("必须提供 --key（离机密钥）或显式使用 --local-key", file=sys.stderr)
        return 2

    checkpoint = None
    if args.checkpoint:
        p = Path(args.checkpoint)
        checkpoint = json.loads(p.read_text(encoding="utf-8") if p.is_file() else args.checkpoint)

    report = verify_chain(audit_path, seal, checkpoint)
    print(report.describe())
    print(key_note)
    if checkpoint is None:
        print("提示：未提供 --checkpoint，只能检测链内篡改，无法检测尾部截断。")
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
