"""运行一个 TrustGate 端到端任务。

默认使用 MockLLM，因此无需 API Key 即可验证 Agent → Broker → PDP →
工具执行 → 审计的完整链路。真实模型可通过 OpenAI 兼容接口接入。
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from trustgate.agent import Agent
from trustgate.broker import BrokerClient
from trustgate.llm import MockLLM, OpenAICompatibleLLM
from trustgate.sandbox import build


DEFAULT_TASK = (
    "读取 sandbox/public/about.txt，并将内容写入 "
    "sandbox/workspace/out/summary.md"
)


def _policy_for_mode(policy_path: Path, mode: str | None) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    """按需创建仅修改 mode 的临时策略，避免改动项目策略文件。"""
    if mode is None:
        return policy_path, None

    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["mode"] = mode
    temp_dir = tempfile.TemporaryDirectory(prefix="trustgate-policy-")
    temp_path = Path(temp_dir.name) / "policy.json"
    temp_path.write_text(json.dumps(policy, ensure_ascii=False, indent=2), encoding="utf-8")
    return temp_path, temp_dir


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="运行 TrustGate 单任务演示")
    parser.add_argument("--task", default=DEFAULT_TASK, help="要交给 Agent 的自然语言任务")
    parser.add_argument("--anchor", choices=["T0", "T1"], default="T0")
    parser.add_argument("--mode", choices=["observe", "enforce"], help="临时覆盖策略模式")
    parser.add_argument("--policy", default="policy.json")
    parser.add_argument("--audit", default="logs/audit.jsonl")
    parser.add_argument("--confirm", choices=["tty", "deny", "allow"], default="deny")
    parser.add_argument(
        "--key-source",
        choices=["file", "ephemeral", "env"],
        default="file",
        help="审计密钥来源；file 便于演示但不抵抗对手 A2，ephemeral 才成立防篡改论断",
    )
    parser.add_argument("--checkpoint-out", help="把会话结束时的审计检查点写到此文件（供离机校验）")
    parser.add_argument("--llm", choices=["mock", "openai"], default="mock")
    parser.add_argument("--model", help="OpenAI 兼容模型名；--llm openai 时必填")
    parser.add_argument("--base-url", help="OpenAI 兼容 API 根地址")
    parser.add_argument("--api-key", help="API Key；也可使用 TG_API_KEY")
    parser.add_argument("--replay-only", action="store_true", help="只使用已有 LLM 录制缓存")
    parser.add_argument("--max-steps", type=int, default=8)
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--reset-sandbox", action="store_true", help="运行前强制重置沙箱")
    return parser.parse_args()


def main() -> int:
    # Windows 的旧代码页无法编码状态图标；替换不可表示字符，避免演示中断。
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    args = parse_args()
    policy_source = (ROOT / args.policy).resolve()
    if not policy_source.is_file():
        print(f"策略文件不存在：{policy_source}", file=sys.stderr)
        return 2
    if args.llm == "openai" and not args.model:
        print("--llm openai 必须同时指定 --model", file=sys.stderr)
        return 2

    build(force=args.reset_sandbox)
    policy_path, temp_dir = _policy_for_mode(policy_source, args.mode)
    broker: BrokerClient | None = None
    try:
        llm = (
            MockLLM()
            if args.llm == "mock"
            else OpenAICompatibleLLM(
                model=args.model,
                base_url=args.base_url,
                api_key=args.api_key,
                replay_only=args.replay_only,
            )
        )
        broker = BrokerClient(
            anchor=args.anchor,
            policy=str(policy_path),
            audit=args.audit,
            confirm=args.confirm,
            key_source=args.key_source,
        )
        # 密钥必须在 Broker 还活着的时候取走：ephemeral 模式下进程一退出，
        # 这把密钥就再也拿不回来了，事后就无法校验这段日志。
        verify_key = broker.export_key()
        result = Agent(
            llm=llm,
            broker=broker,
            max_steps=args.max_steps,
            verbose=not args.quiet,
        ).run(args.task)
        print("\n" + result.summary())

        if args.checkpoint_out:
            out = Path(args.checkpoint_out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(
                json.dumps({**broker.checkpoint, "verify_key": verify_key}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            print(f"审计检查点与验证密钥已导出 → {out}（请离机保管）")

        if result.error:
            print(f"\n错误：{result.error}", file=sys.stderr)
            return 1
        return 0
    finally:
        if broker is not None:
            broker.close()
        if temp_dir is not None:
            temp_dir.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
