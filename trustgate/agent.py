"""Agent 编排循环：plan → freeze → act → observe。

本进程被视为**不可信**：一旦外部内容进入上下文，它的行为就可能已被
攻击者部分控制（威胁模型 §1.3）。因此这里不做任何安全判定——
它甚至不导入 tools_fs / tools_web，没有能力自己碰磁盘和网络。
它上报的 arg_origin 也只是提示，PDP 会独立重算。
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from .broker import BrokerClient
from .llm import LLMBackend, Turn
from .sanitize import wrap_untrusted
from .taint import TaintTracker
from .types import Manifest, ToolCall, Trust


@dataclass
class StepTrace:
    step: int
    tool: str
    args: dict[str, Any]
    verdict: str
    verdict_effective: str
    rule: str
    reason: str
    risk: int
    ok: bool
    bypassed: bool
    latency_ms: float
    thought: str = ""


@dataclass
class RunResult:
    session: str
    task: str
    mode: str
    anchor: str
    plan: str = ""
    manifest_digest: str = ""
    manifest_ok: bool = False
    final: str = ""
    steps: list[StepTrace] = field(default_factory=list)
    wall_ms: float = 0.0
    audit_head: str = ""
    error: str = ""

    @property
    def blocked_count(self) -> int:
        return sum(1 for s in self.steps if s.verdict_effective != "allow")

    def summary(self) -> str:
        lines = [
            f"会话 {self.session} · 模式 {self.mode} · 可信锚 {self.anchor}",
            f"任务：{self.task}",
            f"计划：{self.plan}  [manifest {self.manifest_digest}]",
            "",
        ]
        for s in self.steps:
            icon = {"allow": "✅", "deny": "⛔", "confirm": "⚠️"}.get(s.verdict, "?")
            note = "（observe 模式未拦截）" if s.bypassed else ""
            lines.append(f"{icon} #{s.step} {s.tool} {_brief(s.args)}")
            lines.append(f"     判定={s.verdict} 规则={s.rule} 风险={s.risk} 延迟={s.latency_ms}ms {note}")
            if s.reason:
                lines.append(f"     原因：{s.reason}")
        lines.append("")
        lines.append(f"最终回复：{self.final or '(无)'}")
        lines.append(f"共 {len(self.steps)} 次调用，其中 {self.blocked_count} 次被判为不允许；耗时 {self.wall_ms:.0f} ms")
        lines.append(f"审计链头：{self.audit_head[:16]}…")
        return "\n".join(lines)


def _brief(args: dict[str, Any]) -> str:
    out = {}
    for k, v in args.items():
        out[k] = (v[:60] + "…") if isinstance(v, str) and len(v) > 60 else v
    return str(out)


class Agent:
    def __init__(self, llm: LLMBackend, broker: BrokerClient, max_steps: int = 8, verbose: bool = True):
        self.llm = llm
        self.broker = broker
        self.max_steps = max_steps
        self.verbose = verbose

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def run(self, task: str, session: str | None = None) -> RunResult:
        session = session or "s-" + uuid.uuid4().hex[:6]
        t0 = time.perf_counter()

        started = self.broker.session_start(session, task)
        run = RunResult(
            session=session,
            task=task,
            mode=str(started.get("mode", "?")),
            anchor=str(started.get("attest", {}).get("anchor", "?")),
        )
        taint = TaintTracker(task=task)
        history: list[Turn] = []

        # ---- 阶段一：规划期。上下文中只有任务与工具 Schema，尚未被污染 ----
        try:
            planned = self.llm.plan(task, self.broker.tools)
        except Exception as exc:
            run.error = f"规划失败: {exc}"
            return run
        run.plan = str(planned.get("plan", ""))
        taint.add_trusted(run.plan)
        self._log(f"[plan] {run.plan}")

        frozen = self.broker.freeze_manifest(dict(planned.get("manifest", {})))
        run.manifest_ok = bool(frozen.get("ok"))
        run.manifest_digest = str(frozen.get("digest", ""))
        if not run.manifest_ok:
            run.error = f"能力清单冻结失败: {frozen.get('reason', '')}"
            return run
        manifest = Manifest.from_wire(dict(frozen.get("manifest", {})))
        self._log(f"[freeze] 能力集={manifest.tools} 摘要={run.manifest_digest}")

        # ---- 阶段二：执行期。外部内容一旦进入，Agent 即降级为不可信 ----
        for step in range(1, self.max_steps + 1):
            try:
                act = self.llm.act(task, self.broker.tools, run.plan, history)
            except Exception as exc:
                run.error = f"决策失败: {exc}"
                break

            thought = str(act.get("thought", ""))
            if "final" in act or not act.get("tool"):
                run.final = str(act.get("final", ""))
                self._log(f"[final] {run.final}")
                break

            call = ToolCall(tool=str(act["tool"]), args=dict(act.get("args", {})), step=step)
            call.arg_origin = {k: v.value for k, v in taint.origins(call.args).items()}
            history.append(Turn("action", f'{{"tool": "{call.tool}", "args": {_brief(call.args)}}}'))
            self._log(f"[step {step}] {call.tool} {_brief(call.args)}  ← {thought}")

            resp = self.broker.call(call)
            run.steps.append(
                StepTrace(
                    step=step,
                    tool=call.tool,
                    args=call.args,
                    verdict=str(resp.get("verdict", "?")),
                    verdict_effective=str(resp.get("verdict_effective", "?")),
                    rule=str(resp.get("rule", "")),
                    reason=str(resp.get("reason", "")),
                    risk=int(resp.get("risk", 0)),
                    ok=bool(resp.get("ok")),
                    bypassed=bool(resp.get("bypassed")),
                    latency_ms=float(resp.get("latency_ms", 0.0)),
                    thought=thought,
                )
            )

            observation = self._observe(resp, taint)
            history.append(Turn("observation", observation))
            taint.observe_agent_output(thought)
            verdict_icon = {"allow": "✅", "deny": "⛔", "confirm": "⚠️"}.get(str(resp.get("verdict")), "?")
            self._log(f"          {verdict_icon} {resp.get('verdict')} / {resp.get('rule')} — {resp.get('reason', '')}")

        run.audit_head = str(self.broker.session_end().get("audit_head", ""))
        run.wall_ms = (time.perf_counter() - t0) * 1000
        return run

    def _observe(self, resp: dict[str, Any], taint: TaintTracker) -> str:
        """把工具结果转成观察文本，不可信来源强制去权化包装。"""
        if not resp.get("ok"):
            return f"[工具失败] {resp.get('error', '')}"

        content = str(resp.get("content", ""))
        sources = list(resp.get("sources", []))
        source = sources[0] if sources else "unknown"
        if str(resp.get("trust")) == Trust.UNTRUSTED.value:
            taint.add_untrusted(content, source)
            # 关掉 spotlight 后，不可信内容与可信内容在上下文里长得一模一样。
            # 这正是 C0 无防护基线要复现的情形：Agent 分不出哪段是数据、
            # 哪段是指令。污点跟踪不受影响——它在 Agent 之外独立维护。
            if self.broker.spotlight:
                return wrap_untrusted(content, source, str(resp.get("call_id", "d0")))
            return f"[来自 {source}]\n{content}"
        taint.add_trusted(content)
        return f"[来自 {source}]\n{content}"
