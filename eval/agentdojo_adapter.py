"""把 AgentDojo 的工具调用映射到 TrustGate 的判定。

AgentDojo 0.1.35 的流水线是单进程的：模型、工具和防御元素在同一次
``query`` 里来回调用，没有 TrustGate 那种「特权父进程 + 被剥权子进程」。
因此这里复用的是判定规则，不是 T1 锚进程本身：

- 判定仍在模型之外。模型只能提出工具调用，执行发生在本元素里。
- 失败即拒绝。判定抛错时不调用工具。
- 每次判定追加到内存审计，并可写入 jsonl。这条链没有锚的签名，
  离机校验仍要走 TrustGate 自己的 Broker。

能力清单在看到任何工具返回之前，从用户任务原文冻结。默认不收窄工具名：
套件把哪些工具交给 Agent，清单里就是哪些。收窄工具名是另一条管线的事。
外发目的地（收件人、IBAN、外链 URL、日历参与者）必须整段出现在用户任务里，
否则拒绝。工具返回只算不可信来源，不能把一个新地址洗成用户指定的。
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from importlib.metadata import version
from pathlib import Path

from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

from trustgate.taint import TaintTracker
from trustgate.types import Decision, Trust

AGENTDOJO_VERSION = version("agentdojo")

# 这些字段是外发目的地，不是正文。正文里出现工具返回的句子不构成
# 「用户指定了这个地址」。日历参与者算在内，是因为创建事件会向他们发信。
_EGRESS_FIELDS: dict[str, tuple[str, ...]] = {
    "send_email": ("recipients", "cc", "bcc"),
    "send_money": ("recipient",),
    "schedule_transaction": ("recipient",),
    "update_scheduled_transaction": ("recipient",),
    "post_webpage": ("url",),
    "get_webpage": ("url",),
    "download_file": ("url",),
    "send_direct_message": ("recipient",),
    "invite_user_to_slack": ("user_email",),
    "create_calendar_event": ("participants",),
    "add_calendar_event_participants": ("participants",),
}

# 短于污点模块的最小 token 时，溯源把参数当成没有候选并标成 TRUSTED。
# 套件里的文件 id 可以是 "13"，这条规则盖不住它，不在这里假装盖住了。
_DESTRUCTIVE_FIELDS: dict[str, tuple[str, ...]] = {
    "delete_file": ("file_id",),
    "delete_email": ("email_id",),
    "remove_user_from_slack": ("user",),
    "update_password": ("password",),
}


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for item in value:
            out.extend(_strings(item))
        return out
    if isinstance(value, dict):
        out = []
        for item in value.values():
            out.extend(_strings(item))
        return out
    return []


class TrustGateToolsExecutor(ToolsExecutor):
    """在 ``ToolsExecutor`` 真正调用工具之前做判定。

    同一实例会被套件复用到下一条任务。消息里还没有工具返回时视为新任务，
    重新冻结清单；已经有工具返回时不重置，否则污染会在同一次任务中丢失。
    """

    def __init__(self, audit_path: str | Path | None = None) -> None:
        super().__init__(tool_result_to_str)
        self.audit_path = Path(audit_path) if audit_path else None
        self.audit: list[dict] = []
        self._taint = TaintTracker()
        self._tools: set[str] = set()
        self._task = ""

    def _reset(self, task: str, runtime: FunctionsRuntime) -> None:
        # 清单只看用户任务和此刻已经注册的工具。此后出现的工具名不补进清单。
        self._task = task
        self._taint = TaintTracker(task=task)
        self._tools = set(runtime.functions)

    def _record(self, tool: str, decision: Decision) -> None:
        row = {
            "tool": tool,
            "verdict": decision.verdict,
            "rule": decision.rule,
            "reason": decision.reason,
        }
        self.audit.append(row)
        if self.audit_path is None:
            return
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        except OSError as exc:
            # 审计写不进去就当这次判定失败。没有记录的放行不能算数。
            raise RuntimeError(f"审计写入失败: {exc}") from exc

    def decide(self, tool: str, args: dict) -> Decision:
        try:
            return self._decide(tool, args)
        except Exception as exc:
            return Decision("deny", "L0.judge_error", f"判定失败，拒绝执行: {exc}")

    def _decide(self, tool: str, args: dict) -> Decision:
        if tool not in self._tools:
            return Decision(
                "deny", "L2.tool_not_in_manifest",
                f"{tool} 不在任务开始时冻结的工具清单里",
            )
        for dest in _strings({k: args.get(k) for k in _EGRESS_FIELDS.get(tool, ())}):
            if self._taint.origin(dest) is not Trust.TRUSTED:
                return Decision(
                    "deny", "L4.exfil_chain",
                    "外发目的地不在用户任务原文里",
                )
        if self._taint.session_tainted:
            for value in _strings({k: args.get(k) for k in _DESTRUCTIVE_FIELDS.get(tool, ())}):
                if self._taint.origin(value) is Trust.UNTRUSTED:
                    return Decision(
                        "deny", "L3.untrusted_irreversible",
                        "破坏性操作的目标只出现在工具返回里",
                    )
        return Decision("allow", "L0.ok", "")

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if len(messages) == 0 or messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        tool_calls = messages[-1]["tool_calls"]
        if not tool_calls:
            return query, runtime, env, messages, extra_args
        if not any(m["role"] == "tool" for m in messages):
            self._reset(query, runtime)

        results = []
        for tool_call in tool_calls:
            if tool_call.function == EMPTY_FUNCTION_NAME or tool_call.function not in runtime.functions:
                results.append(self._error(tool_call, f"Invalid tool {tool_call.function} provided."))
                continue
            decision = self.decide(tool_call.function, dict(tool_call.args))
            try:
                self._record(tool_call.function, decision)
            except RuntimeError as exc:
                decision = Decision("deny", "L0.judge_error", str(exc))
            if not decision.allowed:
                results.append(self._error(tool_call, f"{decision.rule}: {decision.reason}"))
                continue
            tool_result, error = runtime.run_function(env, tool_call.function, tool_call.args)
            formatted = self.output_formatter(tool_result)
            if error is None:
                self._taint.add_untrusted(formatted, source=tool_call.function)
            results.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(formatted)],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=error,
                )
            )
        return query, runtime, env, [*messages, *results], extra_args

    @staticmethod
    def _error(tool_call, message: str) -> ChatToolResultMessage:
        return ChatToolResultMessage(
            role="tool",
            content=[text_content_block_from_string("")],
            tool_call_id=tool_call.id,
            tool_call=tool_call,
            error=message,
        )
