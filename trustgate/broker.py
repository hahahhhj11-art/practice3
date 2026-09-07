"""Tool Broker：策略执行点 PEP + 工具执行体。

本进程是系统里唯一持有文件系统与网络权限的组件。Agent 进程只能通过
stdio 上的 JSON Lines 通道向这里提出请求，因此策略无法被旁路
（设计原则 P1 完全仲裁，见 docs/02-系统架构.md §2）。

两种运行形态：
  python -m trustgate.broker --serve   作为子进程被 Agent 拉起
  BrokerClient(...)                    Agent 侧的客户端封装

mode=observe 时，判定照常执行并写入审计日志，但不拦截——用于采集
C0 无防护基线，且日志格式与 enforce 模式完全一致，可直接对比。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, TextIO

from .anchor import make_anchor
from .audit import AuditLog, digest_args
from .paths import project_root
from .taint import find_canaries
from .tools_fs import fs_delete, fs_read, fs_write, target_exists
from .tools_web import web_read
from .types import PROTOCOL_VERSION, TOOL_SPECS, ToolCall, ToolResult, Trust


# ---------------------------------------------------------------- 用户确认通道

def _open_console() -> TextIO | None:
    """打开一条 Agent 无法伪造的带外确认通道。

    stdin/stdout 已被 IPC 占用，且都由不可信的 Agent 控制——若从那里读确认，
    被注入的 Agent 可以自己"代替用户点同意"。所以必须直连控制台。
    """
    for dev in ("CON", "/dev/tty"):
        try:
            return open(dev, "r", encoding="utf-8", errors="replace")
        except OSError:
            continue
    return None


class ConfirmChannel:
    def __init__(self, mode: str = "tty"):
        self.mode = mode
        self._console: TextIO | None = None

    def ask(self, tool: str, args: dict[str, Any], reason: str, risk: int) -> bool:
        if self.mode == "deny":
            return False
        if self.mode == "allow":
            return True
        if self._console is None:
            self._console = _open_console()
        if self._console is None:
            print("[broker] 无可用带外确认通道，按 fail-closed 拒绝", file=sys.stderr)
            return False
        shown = {k: (v[:120] + "…" if isinstance(v, str) and len(v) > 120 else v) for k, v in args.items()}
        print(
            f"\n[TrustGate 需要确认] 风险分 {risk}\n"
            f"  工具：{tool}\n"
            f"  参数：{json.dumps(shown, ensure_ascii=False)}\n"
            f"  原因：{reason}\n"
            f"  允许执行？(y/N) ",
            end="",
            file=sys.stderr,
            flush=True,
        )
        try:
            ans = self._console.readline().strip().lower()
        except Exception:
            return False
        return ans in ("y", "yes", "是")


# ---------------------------------------------------------------- Broker 服务端

class Broker:
    def __init__(
        self,
        anchor_kind: str = "T1",
        policy_path: str = "policy.json",
        audit_path: str = "logs/audit.jsonl",
        confirm: str = "tty",
        key_source: str | None = None,
    ):
        self.anchor = make_anchor(anchor_kind, policy_path, key_source)
        # 配置只从锚取，绝不自己去读 policy.json：Broker 与锚各读一遍磁盘，
        # 等于给对手 A2 留了一个只需改一个字段就能整体关停网关的开关。
        self.rt: dict[str, Any] = self.anchor.runtime_config()
        self.audit = AuditLog(project_root() / audit_path, chain_fn=self.anchor.chain_append)
        self.confirm = ConfirmChannel(confirm)
        self.session = ""

    @property
    def enforcing(self) -> bool:
        return self.rt.get("mode") == "enforce"

    @property
    def policy_hash(self) -> str:
        return str(self.rt.get("policy_hash", ""))

    # ---- 消息分发 ----

    def handle(self, msg: dict[str, Any]) -> dict[str, Any]:
        kind = msg.get("type", "")
        if kind == "session_start":
            return self._session_start(msg)
        if kind == "freeze_manifest":
            return self._freeze(msg)
        if kind == "tool_call":
            return self._tool_call(msg)
        if kind == "attest":
            return {"type": "attest", **asdict(self.anchor.attest())}
        if kind == "session_end":
            self.audit.append("session_end", self.policy_hash, session=self.session)
            # 检查点必须在这里签发并交给外部保管：只有把 (seq, head) 存到
            # 这台机器之外，事后才可能识别出"日志被删掉了最后几条"。
            return {
                "type": "bye",
                "audit_head": self.audit.head,
                "checkpoint": self.anchor.chain_checkpoint(),
            }
        if kind == "export_key":
            return {"type": "key", "key": self.anchor.export_key()}
        return {"type": "error", "error": f"未知消息类型 {kind}"}

    def _session_start(self, msg: dict[str, Any]) -> dict[str, Any]:
        self.session = str(msg.get("session", "s-0"))
        task = str(msg.get("task", ""))
        self.anchor.session_start(self.session, task)
        self.rt = self.anchor.runtime_config()   # 刷新跨会话溯源标记
        att = self.anchor.attest()
        self.audit.append(
            "session_start",
            self.policy_hash,
            session=self.session,
            task_digest=digest_args({"task": task}),
            anchor=att.anchor,
            mode=self.rt.get("mode"),
            key_source=att.key_source,
        )
        caps = dict(self.rt.get("capabilities", {}))
        return {
            "type": "session_started",
            "session": self.session,
            "mode": self.rt.get("mode"),
            "attest": asdict(att),
            "audit_head": self.audit.head,
            # 提示层去权化包装是否开启，由策略决定而非 Agent 自选：
            # C1 基线要能单独关掉它，否则 C0 与 C1 之间没有可比的差值。
            "spotlight": bool(dict(self.rt.get("layers", {})).get("spotlight", True)),
            "tools": [TOOL_SPECS[t].schema_line() for t in TOOL_SPECS if caps.get(t, True)],
        }

    def _freeze(self, msg: dict[str, Any]) -> dict[str, Any]:
        res = self.anchor.freeze_manifest(self.session, dict(msg.get("manifest", {})))
        self.audit.append(
            "freeze_manifest",
            self.policy_hash,
            session=self.session,
            ok=bool(res.get("ok")),
            manifest_digest=res.get("digest", ""),
            reason=res.get("reason", ""),
        )
        return {"type": "manifest_frozen", **res}

    # ---- 核心：一次工具调用的完整仲裁 ----

    def _tool_call(self, msg: dict[str, Any]) -> dict[str, Any]:
        t0 = time.perf_counter()
        call = ToolCall(
            tool=str(msg.get("tool", "")),
            args=dict(msg.get("args", {})),
            step=int(msg.get("step", 0)),
            call_id=str(msg.get("call_id", "")),
            arg_origin=dict(msg.get("arg_origin", {})),
        )
        fs_cfg = dict(self.rt.get("fs", {}))
        root = str(self.rt.get("sandbox_root", "sandbox"))

        # 判定前先收集 PDP 需要但不应自己去取的事实（PDP 不接触文件系统）
        meta: dict[str, Any] = {}
        if call.tool.startswith("fs.") and call.args.get("path"):
            meta["target_exists"] = target_exists(str(call.args["path"]), root)

        verdict_raw = self.anchor.evaluate(self.session, call.to_wire(), meta)
        decision_meta = dict(verdict_raw.get("meta", {}))
        verdict = str(verdict_raw.get("verdict", "deny"))
        rule = str(verdict_raw.get("rule", "unknown"))
        reason = str(verdict_raw.get("reason", ""))
        risk = int(verdict_raw.get("risk", 0))
        latency_ms = round((time.perf_counter() - t0) * 1000, 3)

        # 需要确认时走带外通道询问用户
        confirmed: bool | None = None
        if verdict == "confirm":
            confirmed = self.confirm.ask(call.tool, call.args, reason, risk)
            verdict_effective = "allow" if confirmed else "deny"
        else:
            verdict_effective = verdict

        # observe 模式：判定与日志照常，但一律放行，用于采集无防护基线
        execute = verdict_effective == "allow" or not self.enforcing
        bypassed = execute and verdict_effective != "allow"

        result = self._execute(call, fs_cfg, root, decision_meta) if execute else ToolResult(
            ok=False, error=f"[TrustGate 已阻断] {rule}: {reason}"
        )

        # 敏感性判定只看 source 上的标记，而标记来自策略声明的路径与内容特征。
        # canary 仅记录进审计日志供评测侧取证，不参与任何判定路径。
        sensitive = any("#sensitive" in s for s in result.sources)
        canaries = find_canaries(result.content)

        self.anchor.post_exec(
            self.session,
            {
                "tool": call.tool,
                "args": call.args,
                "rel": decision_meta.get("rel", ""),
                "verdict": verdict_effective,
                "executed": execute and result.ok,
                "rule": rule,
                "risk": risk,
                "content": result.content if result.ok else "",
                "written_content": str(call.args.get("content", "")) if call.tool == "fs.write" else "",
                "trust": result.trust.value,
                "source": result.sources[0] if result.sources else "",
                "sensitive": sensitive,
                "query_len": int(decision_meta.get("query_len", 0)),
            },
        )

        self.audit.append(
            "tool_call",
            self.policy_hash,
            session=self.session,
            step=call.step,
            call_id=call.call_id,
            tool=call.tool,
            args_digest=digest_args(call.args),
            path=decision_meta.get("rel", ""),
            verdict=verdict,
            verdict_effective=verdict_effective,
            enforced=self.enforcing,
            bypassed=bypassed,
            rule=rule,
            risk=risk,
            trust=decision_meta.get("trust", "trusted"),
            arg_origin_pdp=decision_meta.get("arg_origin_pdp", {}),
            taint_mismatch=bool(decision_meta.get("taint_mismatch")),
            confirmed=confirmed,
            executed=execute,
            result_ok=result.ok,
            canaries=canaries,
            latency_ms=latency_ms,
        )

        return {
            "v": PROTOCOL_VERSION,
            "type": "tool_result",
            "step": call.step,
            "call_id": call.call_id,
            "verdict": verdict,
            "verdict_effective": verdict_effective,
            "bypassed": bypassed,
            "rule": rule,
            "reason": reason,
            "risk": risk,
            "ok": result.ok,
            "content": result.content,
            "error": result.error,
            "trust": result.trust.value,
            "sources": result.sources,
            "truncated": result.truncated,
            "latency_ms": latency_ms,
        }

    def _execute(
        self, call: ToolCall, fs_cfg: dict[str, Any], root: str, decision_meta: dict[str, Any]
    ) -> ToolResult:
        try:
            if call.tool == "web.read":
                web = dict(self.rt.get("web", {}))
                return web_read(
                    str(call.args.get("url", "")),
                    max_bytes=int(web.get("max_bytes", 262144)),
                    timeout=float(web.get("timeout_s", 8)),
                )
            if call.tool == "fs.read":
                tainted = {str(decision_meta.get("rel", ""))} if decision_meta.get("path_tainted") else set()
                return fs_read(
                    str(call.args.get("path", "")),
                    root,
                    int(fs_cfg.get("max_read_bytes", 65536)),
                    list(fs_cfg.get("deny", [])),
                    list(fs_cfg.get("sensitive_content", [])),
                    tainted,
                )
            if call.tool == "fs.write":
                return fs_write(
                    str(call.args.get("path", "")),
                    str(call.args.get("content", "")),
                    root,
                    int(fs_cfg.get("max_write_bytes", 65536)),
                )
            if call.tool == "fs.delete":
                return fs_delete(str(call.args.get("path", "")), root)
        except Exception as exc:
            return ToolResult(ok=False, error=f"工具执行异常 {type(exc).__name__}: {exc}")
        return ToolResult(ok=False, error=f"未实现的工具 {call.tool}")

    def close(self) -> None:
        self.anchor.close()


def _serve(ns: argparse.Namespace) -> None:
    broker = Broker(ns.anchor, ns.policy, ns.audit, ns.confirm, ns.key_source)
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                out = broker.handle(json.loads(line))
            except Exception as exc:
                out = {"type": "error", "error": f"{type(exc).__name__}: {exc}"}
            sys.stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    finally:
        broker.close()


# ---------------------------------------------------------------- Agent 侧客户端

class BrokerClient:
    """Agent 进程中对 Broker 的封装。Agent 只能看见这个窄接口。"""

    def __init__(
        self,
        anchor: str = "T1",
        policy: str = "policy.json",
        audit: str = "logs/audit.jsonl",
        confirm: str = "tty",
        key_source: str = "file",
    ):
        child_env = os.environ.copy()
        child_env["PYTHONUTF8"] = "1"
        self.proc = subprocess.Popen(
            [
                sys.executable, "-m", "trustgate.broker", "--serve",
                "--anchor", anchor, "--policy", policy,
                "--audit", audit, "--confirm", confirm,
                "--key-source", key_source,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            cwd=str(project_root()),
            env=child_env,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self.tools: list[str] = []
        self.mode = "unknown"
        self.spotlight = True
        self.attest: dict[str, Any] = {}
        self.checkpoint: dict[str, Any] = {}

    def _send(self, msg: dict[str, Any]) -> dict[str, Any]:
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(json.dumps(msg, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("Broker 进程已退出")
        return json.loads(line)

    def session_start(self, session: str, task: str) -> dict[str, Any]:
        resp = self._send({"type": "session_start", "session": session, "task": task})
        self.tools = list(resp.get("tools", []))
        self.mode = str(resp.get("mode", "unknown"))
        self.spotlight = bool(resp.get("spotlight", True))
        self.attest = dict(resp.get("attest", {}))
        return resp

    def freeze_manifest(self, manifest: dict[str, Any]) -> dict[str, Any]:
        return self._send({"type": "freeze_manifest", "manifest": manifest})

    def call(self, call: ToolCall) -> dict[str, Any]:
        return self._send(call.to_wire())

    def session_end(self) -> dict[str, Any]:
        try:
            resp = self._send({"type": "session_end"})
            self.checkpoint = dict(resp.get("checkpoint", {}))
            return resp
        except Exception:
            return {}

    def export_key(self) -> str:
        """取回审计验证密钥。ephemeral 模式下 Broker 一退出这把密钥就消失，
        校验方必须在会话期间取走——这正是 T1 相对 T2 的能力缺口所在。"""
        try:
            return str(self._send({"type": "export_key"}).get("key", ""))
        except Exception:
            return ""

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="TrustGate Tool Broker（PEP + 工具执行体）")
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--anchor", default="T1", choices=["T0", "T1", "T2"])
    ap.add_argument("--policy", default="policy.json")
    ap.add_argument("--audit", default="logs/audit.jsonl")
    ap.add_argument("--confirm", default="tty", choices=["tty", "deny", "allow"])
    ap.add_argument("--key-source", default="file", choices=["file", "ephemeral", "env"])
    ns = ap.parse_args()
    if ns.serve:
        _serve(ns)
    else:
        ap.print_help()
