"""用 AgentDojo 的套件跑 TrustGate 适配层。

无 ``TG_API_KEY`` 时以退出码 3 结束，不输出任何数字。有 key 时才构造
OpenAI 兼容客户端并跑套件。数字只来自那一次运行，本脚本不内置结果。

    python scripts/run_agentdojo.py --suite workspace --model gpt-4o-mini --defense trustgate
    python scripts/run_agentdojo.py --suite banking --model gpt-4o-mini --defense none
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SUITES = ("workspace", "banking", "slack", "travel")
DEFENSES = ("none", "trustgate")


class ThoughtSignatureClient:
    """把工具调用上的 ``extra_content`` 回填进下一轮请求。

    Gemini 3 的 OpenAI 兼容接口要求多轮工具调用带回上一轮的 thought_signature，
    缺了直接 400。AgentDojo 的 ``OpenAILLM`` 在消息往返时只保留 id / 函数名 /
    参数，会把它丢掉。不返回该字段的接口上这一层什么也不做。
    """

    def __init__(self, client: object, empty_retries: int = 2):
        from types import SimpleNamespace

        self._client = client
        self._extra: dict[str, object] = {}
        self._empty_retries = empty_retries
        # 重试后仍没有 message 的次数。按「模型无输出」计分，结果里必须报出来
        self.empty_replies = 0
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kw: object) -> object:
        kw["messages"] = [self._restore(m) for m in kw.get("messages") or []]
        for _ in range(self._empty_retries + 1):
            resp = self._client.chat.completions.create(**kw)  # type: ignore[attr-defined]
            choices = getattr(resp, "choices", None) or []
            if choices and all(getattr(c, "message", None) is not None for c in choices):
                break
        else:
            if not choices:
                raise RuntimeError("模型返回里没有 choices")
            from openai.types.chat import ChatCompletionMessage

            # AgentDojo 读 message.tool_calls 时遇到 None 会让整次评测崩掉
            for c in choices:
                if getattr(c, "message", None) is None:
                    c.message = ChatCompletionMessage(role="assistant", content="")
                    self.empty_replies += 1
        for choice in getattr(resp, "choices", None) or []:
            for tc in getattr(choice.message, "tool_calls", None) or []:
                extra = getattr(tc, "extra_content", None) or (getattr(tc, "model_extra", None) or {}).get("extra_content")
                if extra and tc.id:
                    self._extra[tc.id] = extra
        return resp

    def _restore(self, msg: object) -> object:
        if not isinstance(msg, dict) or msg.get("role") != "assistant" or not msg.get("tool_calls"):
            return msg
        calls = []
        for tc in msg["tool_calls"]:
            extra = self._extra.get(tc.get("id", ""))
            calls.append({**tc, "extra_content": extra} if extra and "extra_content" not in tc else tc)
        return {**msg, "tool_calls": calls}


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(description="在 AgentDojo 套件上挂 TrustGate")
    ap.add_argument("--suite", choices=SUITES, default="workspace")
    ap.add_argument("--model", default="gpt-4o-mini")
    ap.add_argument("--defense", choices=DEFENSES, default="trustgate")
    ap.add_argument("--version", default="v1.2.2", help="AgentDojo 套件版本")
    # direct 不要求流水线名字能映射到 AgentDojo 的模型表。
    # important_instructions 会在名字对不上时直接抛错，默认不用它。
    ap.add_argument("--attack", default="direct")
    ap.add_argument("--model-prose", default="",
                    help="攻击文本里对模型的称呼，模型不在 AgentDojo 的 MODEL_NAMES 表里时必须给，"
                         "例如 Gemini 系列在该表里统一是 \"AI model developed by Google\"")
    ap.add_argument("--user-task", action="append", default=[], help="只跑这些用户任务 id，可重复")
    ap.add_argument("--audit", default="logs/agentdojo-audit.jsonl")
    ap.add_argument("--logdir", default="logs/agentdojo-runs", help="AgentDojo 逐条轨迹的落盘目录")
    ns = ap.parse_args(argv)

    if not os.environ.get("TG_API_KEY", "").strip():
        print(
            "未设置 TG_API_KEY。不跑 AgentDojo，也不输出任何数字。\n"
            "这是刻意的降级：没有这次运行的产物，就不给攻击成功率。",
            file=sys.stderr,
        )
        return 3

    return _run(ns)


def _run(ns: argparse.Namespace) -> int:
    import openai

    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
    import agentdojo.attacks  # noqa: F401  注册攻击名，否则 load_attack 找不到
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import benchmark_suite_with_injections
    from agentdojo.logging import OutputLogger
    from agentdojo.task_suite.load_suites import get_suite

    from eval.agentdojo_adapter import AGENTDOJO_VERSION, TrustGateToolsExecutor

    client = openai.OpenAI(
        api_key=os.environ["TG_API_KEY"],
        base_url=(os.environ.get("TG_BASE_URL") or "https://api.openai.com/v1").rstrip("/"),
    )
    sig_client = ThoughtSignatureClient(client)
    llm = OpenAILLM(sig_client, ns.model)  # type: ignore[arg-type]
    system = SystemMessage(load_system_message(None))
    if ns.defense == "trustgate":
        tools = TrustGateToolsExecutor(audit_path=ns.audit)
        defense_name = "trustgate"
    else:
        tools = ToolsExecutor()
        defense_name = "none"
    pipeline = AgentPipeline([system, InitQuery(), llm, ToolsExecutionLoop([tools, llm])])
    pipeline.name = f"{ns.model}-{defense_name}"

    if ns.model_prose:
        from agentdojo.models import MODEL_NAMES

        MODEL_NAMES[ns.model] = ns.model_prose
    suite = get_suite(ns.version, ns.suite)
    attack = load_attack(ns.attack, suite, pipeline)
    user_tasks = ns.user_task or None
    logdir = ROOT / ns.logdir
    logdir.mkdir(parents=True, exist_ok=True)
    # TraceLogger 要从外层 OutputLogger 取 logdir；没有这一层会落到 NullLogger 上直接抛错
    with OutputLogger(str(logdir), live=None):
        results = benchmark_suite_with_injections(
            pipeline,
            suite,
            attack,
            logdir=logdir,
            force_rerun=True,
            user_tasks=user_tasks,
            benchmark_version=ns.version,
        )
    utility = results["utility_results"]
    security = results["security_results"]
    # AgentDojo 的 security() 为真表示注入目标达成，也就是攻击成功。
    # 这里同时给出「攻击没达成」的条数，避免把字段名读反。
    n = len(security)
    attacked = sum(1 for ok in security.values() if ok)
    print(f"agentdojo {AGENTDOJO_VERSION} · suite {ns.suite} · defense {defense_name} · model {ns.model}")
    print(f"任务对 {n} 条")
    print(f"用户任务完成 {sum(1 for ok in utility.values() if ok)} / {len(utility)}")
    print(f"注入目标达成 {attacked} / {n}")
    print(f"注入目标未达成 {n - attacked} / {n}")
    print(f"模型空回复（重试 {sig_client._empty_retries} 次后仍为空，按无输出计分）{sig_client.empty_replies} 次")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
