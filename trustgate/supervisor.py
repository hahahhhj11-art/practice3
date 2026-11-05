"""Supervisor：特权父进程，TCB 在进程边界上的那一侧。

进程拓扑（相对旧实现是倒过来的，这次倒置是整层剥离能成立的前提）：

    Supervisor（特权：文件系统 + 网络 + 可信锚 + 审计密钥）
      ├── Broker / PDP        在本进程内，Agent 无法触及其状态
      ├── 模型外发代办         目的地固定的单一出口，只转发字节、不做判定
      └── Agent 子进程（不可信，S2 下由内核剥去文件与网络权限）

旧实现里 Agent 是父进程、Broker 是子进程，于是「Agent 绕不过 Broker」只是
一句风纪要求：父进程本就持有用户全部权限。倒置之后，工具能力物理上不在
Agent 进程内，绕过路径由 Landlock/seccomp 在内核层切断。

两处顺手堵上的洞
--------------
1. **审计密钥不再经不可信通道导出。** 旧实现把 ``export_key`` 开在 Agent 的
   通道上——被注入的 Agent 拿到 HMAC 密钥就能把整条哈希链重签，SC4 防篡改
   形同虚设。现在密钥由特权侧直接向锚索取，子进程问了会被拒。
2. **剥离结果不采信子进程自报。** 子进程在不可信域内，它说自己是 S2 不算
   证据。父进程从 ``/proc/<pid>/status`` 读内核直接暴露的 Seccomp 状态做独立
   核验；Landlock 内核不提供 /proc 内省，这一项如实标为不可内省，改由
   scripts/bypass_demo.py 用「父进程亲自检查文件系统有没有被动过」来取证。
3. **会话控制消息不采信子进程。** 内核剥权只切断了「绕开管道」，管道本身
   仍是攻击面：``session_start`` 里的 task 是污点溯源的可信根，而会话状态
   （污染标记、外发预算、能力清单）都挂在 session 上。若子进程能自报 task、
   能中途重发 ``session_start``，被注入的 Agent 就能把外泄 URL 写进「用户
   任务」、清零污染状态、重新冻结清单，不碰任何系统调用就让 L1–L5 放行。
   因此 session 与 task 由本进程决定，会话控制消息每种只受理一次。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .audit import digest_args
from .broker import Broker
from .confine import probe
from .llm import LLMBackend, Turn
from .paths import project_root

# 子进程自报的剥离结果里，这些字段一旦声称为真就必须能被父进程核验，
# 否则实验报告不得引用。
_CLAIMED_KEYS = ("fs_read_denied", "fs_write_denied", "net_denied")


@dataclass
class SupervisedRun:
    task: str
    session: str = ""
    mode: str = ""
    anchor: str = ""
    confine_requested: str = "S2"
    # 子进程自报 vs 父进程独立核验，分开存放，绝不合并成一个"结论"
    confinement_claimed: dict[str, Any] = field(default_factory=dict)
    confinement_verified: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] = field(default_factory=dict)
    audit_head: str = ""
    checkpoint: dict[str, Any] = field(default_factory=dict)
    verify_key: str = ""
    llm_calls: int = 0
    wall_ms: float = 0.0
    error: str = ""
    child_pid: int = 0
    # 已受理过的一次性会话控制消息；重复出现即视为协议违规
    seen: set[str] = field(default_factory=set)
    protocol_violations: list[str] = field(default_factory=list)
    # 请求 S2 且本平台做得到、但核验没站住。非空则拒绝之后的工具调用与模型代办。
    confine_failed: str = ""

    @property
    def steps(self) -> list[dict[str, Any]]:
        return list(self.result.get("steps", []))

    def summary(self) -> str:
        r = self.result
        lines = [
            f"会话 {self.session} · 模式 {self.mode} · 可信锚 {self.anchor} · 剥离 {self.confine_requested}",
            f"任务：{self.task}",
            f"计划：{r.get('plan', '')}  [manifest {r.get('manifest_digest', '')}]",
            "",
        ]
        for s in self.steps:
            icon = {"allow": "允许", "deny": "阻断", "confirm": "待确认"}.get(s.get("verdict", ""), "?")
            note = "（observe 模式未拦截）" if s.get("bypassed") else ""
            lines.append(f"[{icon}] #{s.get('step')} {s.get('tool')} ")
            lines.append(
                f"     判定={s.get('verdict')} 规则={s.get('rule')} "
                f"风险={s.get('risk')} 延迟={s.get('latency_ms')}ms {note}"
            )
            if s.get("reason"):
                lines.append(f"     原因：{s['reason']}")
        blocked = sum(1 for s in self.steps if s.get("verdict_effective") != "allow")
        lines += [
            "",
            f"最终回复：{r.get('final') or '(无)'}",
            f"共 {len(self.steps)} 次调用，其中 {blocked} 次被判为不允许；耗时 {self.wall_ms:.0f} ms",
            f"审计链头：{self.audit_head[:16]}…",
            "",
            self.confinement_note(),
        ]
        if self.error:
            lines.append(f"错误：{self.error}")
        return "\n".join(lines)

    def confinement_note(self) -> str:
        c = self.confinement_claimed
        v = self.confinement_verified
        bits = [f"子进程自报 {c.get('effective', '?')}（机制 {', '.join(c.get('mechanisms', [])) or '无'}）"]
        if v.get("available"):
            bits.append(
                f"父进程核验 seccomp={v.get('seccomp_mode')} "
                f"过滤器数={v.get('seccomp_filters')} NoNewPrivs={v.get('nonewprivs')}"
            )
        else:
            bits.append(f"父进程核验不可用（{v.get('reason', '未知')}）")
        if c.get("gaps"):
            bits.append("未覆盖：" + "；".join(c["gaps"]))
        return "权限剥离：" + " | ".join(bits)


def _llm_request_digest(msg: dict[str, Any]) -> str:
    """代办请求的摘要。只覆盖真正送进模型的字段，日志里不留原文。"""
    return digest_args(
        {
            "op": str(msg.get("op", "")),
            "task": msg.get("task", ""),
            "tools": msg.get("tools", []),
            "plan": msg.get("plan", ""),
            "history": msg.get("history", []),
        }
    )


def verify_child_confinement(pid: int) -> dict[str, Any]:
    """父进程侧的独立核验，数据直接来自内核而非子进程自述。

    能核验的：seccomp 是否处于 filter 模式、装了几个过滤器、NoNewPrivs 是否置位。
    **不能**核验的：Landlock 域——当前内核不在 /proc/<pid>/status 里暴露它。
    这一项不含糊过去，标成 landlock_introspectable=False，另由行为取证补上。
    """
    status = Path(f"/proc/{pid}/status")
    if sys.platform != "linux" or not status.exists():
        return {
            "available": False,
            "reason": f"平台 {sys.platform} 无 /proc 内省",
            "landlock_introspectable": False,
        }
    fields: dict[str, str] = {}
    try:
        for line in status.read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                fields[k.strip()] = v.strip()
    except OSError as exc:
        return {"available": False, "reason": str(exc), "landlock_introspectable": False}

    return {
        "available": True,
        "seccomp_mode": int(fields.get("Seccomp", "0") or 0),
        "seccomp_filters": int(fields.get("Seccomp_filters", "0") or 0),
        "nonewprivs": int(fields.get("NoNewPrivs", "0") or 0),
        # seccomp 处于 filter 模式即证明网络剥离真的装上了内核过滤器
        "net_denial_verified": int(fields.get("Seccomp", "0") or 0) == 2,
        "landlock_introspectable": False,
    }


class Supervisor:
    def __init__(
        self,
        anchor: str = "T1",
        policy: str = "policy.json",
        audit: str = "logs/audit.jsonl",
        confirm: str = "deny",
        key_source: str = "ephemeral",
        confine: str = "S2",
        llm: LLMBackend | None = None,
        verbose: bool = True,
    ):
        self.confine = confine
        self.verbose = verbose
        self.llm = llm
        # expose_key 保持关闭：密钥只从本进程内的锚直接取，绝不上通道
        self.broker = Broker(anchor, policy, audit, confirm, key_source, expose_key=False)
        self._llm_calls = 0

    # ---- 消息分发：不认识的一律交给 Broker 走完整仲裁 ----

    _ONCE = ("child_hello", "session_start", "freeze_manifest", "session_end", "run_result", "run_failed")
    _PASSTHROUGH = ("tool_call", "attest", "checkpoint")

    def _reject(self, run: SupervisedRun, why: str) -> dict[str, Any]:
        run.protocol_violations.append(why)
        self.broker.audit.append("protocol_violation", self.broker.policy_hash,
                                 session=run.session, reason=why)
        return {"type": "error", "error": f"[TrustGate 协议] {why}"}

    def _s2_os_required(self) -> bool:
        """请求了 S2，且本平台的 probe 认为内核强制做得到。

        做不到时（Windows 的 max_level 是 S1）保持如实降级并继续，不在这里失败关闭。
        """
        return self.confine.upper() == "S2" and str(probe().get("max_level")) == "S2"

    def _mark_confine_failure(self, run: SupervisedRun, why: str) -> None:
        run.confine_failed = run.confine_failed or why
        run.error = run.error or run.confine_failed

    def _assess_confinement(self, run: SupervisedRun) -> None:
        if not self._s2_os_required():
            return
        # seen 在进入处理函数前已经写入。hello 晚于 session_start 到达时，洗不掉这个失败。
        if "session_start" in run.seen:
            self._mark_confine_failure(run, "child_hello 未在 session_start 之前到达")
            return
        claimed = run.confinement_claimed
        problems: list[str] = []
        if not claimed.get("fs_read_denied") or not claimed.get("net_denied"):
            problems.append("子进程自报 fs_read_denied/net_denied 不成立")
        try:
            mode = int(run.confinement_verified.get("seccomp_mode"))
        except (TypeError, ValueError):
            mode = -1
        if mode != 2:
            problems.append(f"父进程核验 seccomp_mode={mode}，要求 2")
        if problems:
            self._mark_confine_failure(run, "；".join(problems))

    def _confine_block(self, run: SupervisedRun) -> str:
        if not self._s2_os_required():
            return ""
        if run.confine_failed:
            return run.confine_failed
        if "child_hello" not in run.seen:
            return "请求 S2 且本平台可内核强制，但尚未收到 child_hello"
        return ""

    def _reject_closed(self, run: SupervisedRun, why: str) -> dict[str, Any]:
        self._mark_confine_failure(run, why)
        return self._reject(run, why)

    def _dispatch(self, msg: dict[str, Any], run: SupervisedRun) -> dict[str, Any]:
        kind = str(msg.get("type", ""))
        if kind in self._ONCE:
            if kind in run.seen:
                return self._reject(run, f"{kind} 只受理一次")
            if kind in ("run_result", "run_failed") and ({"run_result", "run_failed"} & run.seen):
                return self._reject(run, "运行结果已提交")
            run.seen.add(kind)

        if kind == "child_hello":
            run.confinement_claimed = dict(msg.get("confinement", {}))
            # pid 用本进程拉起时拿到的那个：子进程自报的 pid 可以指向任意别的进程
            run.confinement_verified = verify_child_confinement(run.child_pid)
            self._assess_confinement(run)
            return {"type": "hello_ack"}
        if kind == "llm_request":
            if why := self._confine_block(run):
                return self._reject_closed(run, why)
            return self._llm(msg, run)
        if kind == "run_result":
            run.result = dict(msg.get("result", {}))
            return {"type": "result_ack"}
        if kind == "run_failed":
            if not run.confine_failed:
                run.error = str(msg.get("error", ""))
            return {"type": "result_ack"}

        if kind == "session_start":
            if self._s2_os_required() and "child_hello" not in run.seen:
                self._mark_confine_failure(run, "child_hello 未在 session_start 之前到达")
            return self.broker.handle({"type": "session_start", "session": run.session, "task": run.task})
        if "session_start" not in run.seen:
            return self._reject(run, f"会话未开始，拒绝 {kind}")
        if "session_end" in run.seen and kind != "checkpoint":
            return self._reject(run, f"会话已结束，拒绝 {kind}")
        if kind in ("freeze_manifest", "session_end") or kind in self._PASSTHROUGH:
            if kind == "tool_call":
                if why := self._confine_block(run):
                    return self._reject_closed(run, why)
            return self.broker.handle(msg)
        return self._reject(run, f"未知消息类型 {kind}")

    def _llm(self, msg: dict[str, Any], run: SupervisedRun) -> dict[str, Any]:
        """代办模型推理。只转发，不解释内容——TCB 不因此承担语义职责。"""
        op = str(msg.get("op", ""))
        self.broker.audit.append(
            "llm_request",
            self.broker.policy_hash,
            session=run.session,
            op=op,
            args_digest=_llm_request_digest(msg),
        )
        if self.llm is None:
            return {"type": "error", "error": "父进程未配置模型后端"}
        self._llm_calls += 1
        try:
            if op == "plan":
                out = self.llm.plan(str(msg.get("task", "")), list(msg.get("tools", [])))
            elif op == "act":
                history = [Turn(str(t.get("role", "")), str(t.get("content", "")))
                           for t in msg.get("history", [])]
                out = self.llm.act(
                    str(msg.get("task", "")), list(msg.get("tools", [])),
                    str(msg.get("plan", "")), history,
                )
            else:
                return {"type": "error", "error": f"未知模型操作 {op}"}
            return {"type": "llm_response", "output": out}
        except Exception as exc:
            return {"type": "error", "error": f"{type(exc).__name__}: {exc}"}

    # ---- 运行一次受监管的会话 ----

    def run(
        self,
        task: str,
        session: str | None = None,
        max_steps: int = 8,
        mock_spec: dict[str, Any] | None = None,
    ) -> SupervisedRun:
        t0 = time.perf_counter()
        run = SupervisedRun(
            task=task, session=session or "s-" + uuid.uuid4().hex[:6], confine_requested=self.confine,
        )
        # 密钥必须趁锚还活着取走；ephemeral 下进程一退出就再也拿不回来
        run.verify_key = self.broker.anchor.export_key()

        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        # 字节码不落盘：剥离后子进程全盘不可写，写 __pycache__ 只会制造噪声
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        # 清洗掉子进程不该看见的凭据：模型调用由父进程代办，子进程不需要 key
        for leak in ("TG_API_KEY", "OPENAI_API_KEY", "TG_BASE_URL",
                     "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            env.pop(leak, None)

        argv = [
            sys.executable, "-m", "trustgate.agent_host",
            "--task", task,
            "--confine", self.confine,
            "--max-steps", str(max_steps),
            "--llm", "mock" if self.llm is None else "proxy",
            "--session", run.session,
        ]
        if mock_spec:
            argv += ["--mock-spec", json.dumps(mock_spec, ensure_ascii=False)]
        if not self.verbose:
            argv.append("--quiet")

        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,          # Agent 的执行轨迹直通用户终端
            cwd=str(project_root()),
            env=env,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        assert proc.stdin and proc.stdout
        run.child_pid = proc.pid
        try:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    resp = self._dispatch(json.loads(line), run)
                except Exception as exc:
                    resp = {"type": "error", "error": f"{type(exc).__name__}: {exc}"}
                proc.stdin.write(json.dumps(resp, ensure_ascii=False) + "\n")
                proc.stdin.flush()
        except BrokenPipeError:
            run.error = run.error or "子进程管道中断"
        finally:
            try:
                proc.stdin.close()
                proc.stdout.close()
                proc.wait(timeout=5)
            except Exception:
                proc.kill()

        run.mode = str(run.result.get("mode", ""))
        run.anchor = str(run.result.get("anchor", ""))
        run.audit_head = str(run.result.get("audit_head", "")) or self.broker.audit.head
        run.checkpoint = self.broker.anchor.chain_checkpoint()
        run.llm_calls = self._llm_calls
        run.wall_ms = (time.perf_counter() - t0) * 1000
        if run.confine_failed:
            run.error = run.confine_failed
        elif not run.result and not run.error:
            run.error = "子进程未返回运行结果"
        return run

    def close(self) -> None:
        self.broker.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="以特权父进程运行一次受监管的 Agent 会话")
    ap.add_argument("--task", required=True)
    ap.add_argument("--confine", default="S2", choices=["S0", "S1", "S2"])
    ap.add_argument("--anchor", default="T1", choices=["T0", "T1", "T2"])
    ap.add_argument("--policy", default="policy.json")
    ap.add_argument("--audit", default="logs/audit.jsonl")
    ap.add_argument("--confirm", default="deny", choices=["tty", "deny", "allow"])
    ap.add_argument("--key-source", default="ephemeral", choices=["file", "ephemeral", "env"])
    ap.add_argument("--max-steps", type=int, default=8)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--json", action="store_true")
    ns = ap.parse_args()

    sup = Supervisor(
        anchor=ns.anchor, policy=ns.policy, audit=ns.audit, confirm=ns.confirm,
        key_source=ns.key_source, confine=ns.confine, verbose=not ns.quiet,
    )
    try:
        run = sup.run(ns.task, max_steps=ns.max_steps)
    finally:
        sup.close()

    if ns.json:
        from dataclasses import asdict
        print(json.dumps(asdict(run), ensure_ascii=False, indent=2))
    else:
        print("\n" + run.summary())
    return 1 if run.error else 0


if __name__ == "__main__":
    raise SystemExit(main())
