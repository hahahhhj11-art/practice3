"""Tool Broker：策略执行点 PEP + 工具执行体。

本进程持有文件系统与网络权限，Agent 只能通过 stdio 上的 JSON Lines 通道
向这里提出请求。但要注意：「Agent 绕不过来」这件事**不是本文件能保证的**，
它取决于两个进程谁是谁的父进程、以及 Agent 那一侧有没有被内核剥权：

  S0（BrokerClient）        Agent 是父进程、Broker 是子进程。Agent 持有用户
                            全部权限，一行 open() 就绕过了整条策略链。此档
                            **不满足**完全仲裁，只用作对照与延迟下界。
  S1/S2（Supervisor）       特权父进程持有 Broker，Agent 是被剥权的子进程。
                            S2 下由 Landlock + seccomp 在内核层切断绕过路径，
                            完全仲裁才真正成立。见 trustgate/confine.py 与
                            trustgate/supervisor.py。

设计原则 P1（完全仲裁）见 docs/02-系统架构.md §2。

两种运行形态：
  python -m trustgate.broker --serve   作为子进程被 Agent 拉起（S0）
  Broker(...).handle(msg)              由 Supervisor 在特权侧直接驱动（S1/S2）

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
        expose_key: bool = False,
    ):
        # 审计验证密钥绝不应该走 Agent 那条通道出去。Agent 是不可信的：它一旦
        # 拿到 HMAC 密钥，就能把整条哈希链重签一遍，SC4 防篡改直接失效。
        # 正确的取密钥方是特权侧（Supervisor 直接问锚），而不是被仲裁的一方。
        # 这里保留开关只为兼容 S0 对照组——那一档本来就不提供任何隔离保证。
        self.expose_key = expose_key
        self.anchor = make_anchor(anchor_kind, policy_path, key_source)
        # 配置只从锚取，绝不自己去读 policy.json：Broker 与锚各读一遍磁盘，
        # 等于给对手 A2 留了一个只需改一个字段就能整体关停网关的开关。
        self.rt: dict[str, Any] = self.anchor.runtime_config()
        self.audit = AuditLog(project_root() / audit_path, chain_fn=self.anchor.chain_append)
        self.confirm = ConfirmChannel(confirm)
        self.session = ""
        # 取证捕获默认关闭，且必须显式在策略里打开。
        #
        # 关掉是默认值而不是遗漏：审计日志刻意只存 args_digest 不存原文，正是
        # 为了不让审计本身变成敏感数据的第二个泄露点。取证要的恰恰是原文，
        # 所以它天生与那条设计相冲突——开了就等于在磁盘上多留一份未脱敏副本。
        # 因此它是一个知情选择，而不是顺手就有的功能。
        self._forensics = dict(self.rt.get("forensics", {}))

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
        if kind == "checkpoint":
            # 只读探针：不追加任何审计记录。校验方用它向（可能重启过的）锚
            # 询问当前链权威状态，以反驳陈旧检查点（scripts/replay_demo.py）。
            return {"type": "checkpoint", "checkpoint": self.anchor.chain_checkpoint()}
        if kind == "export_key":
            if not self.expose_key:
                return {"type": "error", "error": "本通道不提供审计密钥导出（仅特权侧可取）"}
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
                "egress_len": int(decision_meta.get("egress_len", 0)),
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

        self._capture_forensics(call, result, verdict_effective, rule, reason)

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

    def _capture_forensics(
        self, call: ToolCall, result: ToolResult, verdict: str, rule: str, reason: str
    ) -> None:
        """把取证层需要的原始素材另存一份。完全在判定之外，不影响任何裁决。

        只记两类记录：
          ingest     进入过上下文的不可信内容（定位的搜索空间）
          violation  被判为不允许的调用及其**参数原值**（定位的痕迹来源）
        审计日志里这两样都只有摘要，取证无法从摘要反查，所以必须另开一路。
        写失败一律吞掉：取证是事后分析设施，绝不能因为它落盘失败而影响一次
        正常的工具调用——安全设施把主流程搞挂，比缺少取证材料严重得多。
        """
        if not self._forensics.get("capture"):
            return
        records: list[dict[str, Any]] = []
        if result.ok and result.trust == Trust.UNTRUSTED and result.content:
            records.append({
                "kind": "ingest",
                "step": call.step,
                "call_id": call.call_id,
                "source": result.sources[0] if result.sources else "unknown",
                "content": result.content[: int(self._forensics.get("max_chars", 20000))],
            })
        if verdict != "allow":
            records.append({
                "kind": "violation",
                "step": call.step,
                "call_id": call.call_id,
                "tool": call.tool,
                "rule": rule,
                "reason": reason,
                # 参数原值是定位的输入：违规调用的路径 / URL / 待写内容正是
                # 攻击在数据流上留下的痕迹，摘要化之后就无从反查了。
                "args": {k: (v[:2000] if isinstance(v, str) else v) for k, v in call.args.items()},
            })
        if not records:
            return
        try:
            out = project_root() / str(self._forensics.get("dir", "logs/forensics"))
            out.mkdir(parents=True, exist_ok=True)
            with (out / f"{self.session or 'nosession'}.jsonl").open("a", encoding="utf-8") as fh:
                for rec in records:
                    fh.write(json.dumps({"session": self.session, **rec}, ensure_ascii=False) + "\n")
        except Exception:
            pass

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
    broker = Broker(
        ns.anchor, ns.policy, ns.audit, ns.confirm, ns.key_source,
        expose_key=bool(getattr(ns, "expose_key", False)),
    )
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

class BrokerChannel:
    """Agent 侧看到的窄接口。收发流由子类提供，上层协议完全共用。

    两种接法对应两种进程拓扑：
      · BrokerClient          Agent 是父进程，自己拉起 Broker 子进程。
        这是 S0 对照档——Agent 持有用户全部权限，随时可以不经 Broker 直接
        open()/socket()，「完全仲裁」在此档**不成立**，仅用于测延迟下界。
      · AttachedBrokerClient  Agent 是被剥权的子进程，管道由特权父进程建好。
        工具能力物理上不在本进程内，绕过路径由内核切断（见 confine.py）。
    """

    def __init__(self) -> None:
        self.tools: list[str] = []
        self.mode = "unknown"
        self.spotlight = True
        self.attest: dict[str, Any] = {}
        self.checkpoint: dict[str, Any] = {}

    # 子类必须提供 (读流, 写流)
    def _streams(self) -> tuple[TextIO, TextIO]:
        raise NotImplementedError

    def _send(self, msg: dict[str, Any]) -> dict[str, Any]:
        r, w = self._streams()
        w.write(json.dumps(msg, ensure_ascii=False) + "\n")
        w.flush()
        line = r.readline()
        if not line:
            raise RuntimeError("Broker 通道已关闭")
        return json.loads(line)

    def request(self, msg: dict[str, Any]) -> dict[str, Any]:
        """发一条通道消息并取回应答。供宿主层（报到、模型代办）复用同一条管道。"""
        return self._send(msg)

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

    def probe_checkpoint(self) -> dict[str, Any]:
        """只读探针：询问锚当前的链权威状态（不追加审计记录）。"""
        try:
            return dict(self._send({"type": "checkpoint"}).get("checkpoint", {}))
        except Exception:
            return {}

    def export_key(self) -> str:
        """取回审计验证密钥。

        注意这条路径在新拓扑下**会被 Broker 拒绝**，这是有意的：Agent 不可信，
        拿到 HMAC 密钥就能重签整条哈希链。特权侧（Supervisor）直接向锚索取，
        不经过这个通道。ephemeral 模式下 Broker 一退出密钥即消失，校验方必须
        在会话期间取走——这正是 T1 相对 T2 的能力缺口所在。
        """
        try:
            return str(self._send({"type": "export_key"}).get("key", ""))
        except Exception:
            return ""

    def close(self) -> None:
        pass


class BrokerClient(BrokerChannel):
    """S0 对照档：Agent 作为父进程自行拉起 Broker 子进程。

    保留它不是为了当主架构用，而是实验里必须有一个「没有任何隔离」的参照点：
    没有 S0 的数字，就无法证明 S2 拦下的绕过路径原本确实走得通。
    """

    def __init__(
        self,
        anchor: str = "T1",
        policy: str = "policy.json",
        audit: str = "logs/audit.jsonl",
        confirm: str = "tty",
        key_source: str = "file",
        allow_key_export: bool = False,
    ):
        super().__init__()
        child_env = os.environ.copy()
        child_env["PYTHONUTF8"] = "1"
        argv = [
            sys.executable, "-m", "trustgate.broker", "--serve",
            "--anchor", anchor, "--policy", policy,
            "--audit", audit, "--confirm", confirm,
            "--key-source", key_source,
        ]
        if allow_key_export:
            argv.append("--expose-key")
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            cwd=str(project_root()),
            env=child_env,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )

    def _streams(self) -> tuple[TextIO, TextIO]:
        assert self.proc.stdin and self.proc.stdout
        return self.proc.stdout, self.proc.stdin

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            if self.proc.stdout:
                self.proc.stdout.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


class AttachedBrokerClient(BrokerChannel):
    """S1/S2 档：Agent 是被剥权的子进程，管道由特权父进程建好后交下来。

    本进程内**没有**任何工具实现，也没有文件系统与网络权限；这个对象是
    Agent 唯一的对外出口。它不 spawn 任何东西，生命周期由父进程掌握。
    """

    def __init__(self, read_stream: TextIO, write_stream: TextIO):
        super().__init__()
        self._r = read_stream
        self._w = write_stream

    def _streams(self) -> tuple[TextIO, TextIO]:
        return self._r, self._w


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="TrustGate Tool Broker（PEP + 工具执行体）")
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--anchor", default="T1", choices=["T0", "T1", "T2"])
    ap.add_argument("--policy", default="policy.json")
    ap.add_argument("--audit", default="logs/audit.jsonl")
    ap.add_argument("--confirm", default="tty", choices=["tty", "deny", "allow"])
    ap.add_argument("--key-source", default="file", choices=["file", "ephemeral", "env", "tee"])
    ap.add_argument(
        "--expose-key",
        action="store_true",
        help="允许经本通道导出审计密钥；仅 S0 对照档使用，正式拓扑下不得开启",
    )
    ns = ap.parse_args()
    if ns.serve:
        _serve(ns)
    else:
        ap.print_help()
