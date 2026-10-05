"""可信锚 TrustedAnchor：策略判定与审计签名的可信计算基（TCB）。

三档实现共用同一接口，替换只需改配置（见 docs/02-系统架构.md §5.2）：

  T0 InProcessAnchor      同进程，仅用于测功能与延迟下界，不抵抗任何本地对手
  T1 IsolatedProcessAnchor 独立进程 + 单向 stdio 通道，密钥不出该进程
  T2 OpteeAnchor          QEMU + OP-TEE TA（选做，接口已预留）

TCB 最小化原则（P4）：锚内只有策略求值 + 会话状态 + HMAC 密钥。
不含 LLM、不含网络栈、不含文件系统工具——TCB 越小越可信。

会话状态刻意保存在锚内而非 Broker 内：这样对手 A2 即使能读写 Broker 的
内存以外的一切，也无法伪造"我从没读过敏感文件"的历史。
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Protocol

from .audit import GENESIS, chain_record
from .paths import project_root
from .policy import Policy, PolicyEngine, SessionState
from .taint import find_canaries
from .types import Attestation, Decision, Manifest, ToolCall, Trust

KEY_PATH = ".trustgate/anchor.key"
PROVENANCE_PATH = ".trustgate/provenance.json"


def _load_key(source: str) -> tuple[bytes, str]:
    """按来源取得审计密钥，并如实回报这把密钥能抵抗谁。

    这里有一处早期实现里的**安全声明造假**必须纠正：原本无论哪一档都把
    密钥写进 .trustgate/anchor.key。可对手 A2 的能力 A2-C1 恰恰是"以相同
    OS 用户权限读写任意用户态文件"——它直接读走密钥就能伪造任意 MAC。
    于是"T1 抵抗 A2-C1"这条论断在实现上是空的。

    诚实的做法是把选择权和代价都摆出来：
      file       密钥落盘，便于反复演示，**不抵抗 A2**，仅适用于 T0
      ephemeral  每次启动随机生成、只存内存，A2 无从伪造；代价是校验方
                 必须在会话期间取走密钥（export_key），进程一退出即失效
      env        由外部注入（例如从手机/HSM 送入），生产形态的近似
    T2 的意义正在于此：只有 TEE 的安全存储能同时给出"持久"与"A2 不可读"。
    """
    if source == "ephemeral":
        return os.urandom(32), "ephemeral"
    if source == "env":
        raw = os.environ.get("TG_ANCHOR_KEY", "")
        if not raw:
            raise RuntimeError("key_source=env 但环境变量 TG_ANCHOR_KEY 为空（fail-closed）")
        return hashlib.sha256(raw.encode()).digest(), "env"

    p = project_root() / KEY_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        return p.read_bytes(), "file"
    key = os.urandom(32)
    p.write_bytes(key)
    try:
        p.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return key, "file"


class TrustedAnchor(Protocol):
    def session_start(self, session_id: str, task: str) -> None: ...
    def observe(self, session_id: str, text: str, trust: str, source: str = "") -> None: ...
    def freeze_manifest(self, session_id: str, manifest: dict[str, Any]) -> dict[str, Any]: ...
    def evaluate(self, session_id: str, call: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]: ...
    def post_exec(self, session_id: str, payload: dict[str, Any]) -> None: ...
    def runtime_config(self) -> dict[str, Any]: ...
    def chain_append(self, payload: dict[str, Any]) -> dict[str, Any]: ...
    def chain_checkpoint(self) -> dict[str, Any]: ...
    def export_key(self) -> str: ...
    def seal(self, data: bytes) -> str: ...
    def attest(self) -> Attestation: ...
    def close(self) -> None: ...


class AnchorCore:
    """锚的全部业务逻辑。T0 直接调用它，T1 在子进程里跑它。"""

    def __init__(self, policy_path: str = "policy.json", key_source: str = "file"):
        self.policy = Policy.load(policy_path)
        self.engine = PolicyEngine(self.policy)
        self._key, self.key_source = _load_key(key_source)
        self.sessions: dict[str, SessionState] = {}
        # 审计链的权威状态。留在锚内，Broker 与日志文件都无权推进它。
        self._chain_seq = 0
        self._chain_head = GENESIS
        self._provenance: set[str] = self._load_provenance()

    # ---------- 跨会话溯源存储（持久化注入 T5） ----------

    @staticmethod
    def _prov_file() -> Path:
        return project_root() / PROVENANCE_PATH

    def _load_provenance(self) -> set[str]:
        p = self._prov_file()
        if not p.exists():
            return set()
        try:
            return set(json.loads(p.read_text(encoding="utf-8")).get("tainted_paths", []))
        except (OSError, ValueError):
            return set()

    def _save_provenance(self) -> None:
        p = self._prov_file()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps({"tainted_paths": sorted(self._provenance)}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def tainted_paths(self) -> list[str]:
        return sorted(self._provenance)

    def clear_provenance(self) -> None:
        """实验样本之间重置溯源存储，保证样本间零污染。"""
        self._provenance.clear()
        self._save_provenance()

    # ---------- 运行时配置的单一来源 ----------

    def runtime_config(self) -> dict[str, Any]:
        """Broker 执行工具时需要的全部配置，一律从锚取。

        Broker 原先自己 Policy.load(policy.json) 读一遍，这在对手 A2 面前是
        致命的：A2 只要把磁盘上的 mode 改成 observe，Broker 就不再拦截任何
        调用，而锚的 attest() 依然汇报 enforce——网关被整体关停，且看不出来。
        配置只能有一个来源，就是锚。
        """
        return {
            "mode": self.policy.mode,
            "sandbox_root": self.policy.raw.get("sandbox_root", "sandbox"),
            "fs": self.policy.sec("fs"),
            "web": self.policy.sec("web"),
            "capabilities": self.policy.sec("capabilities"),
            "layers": self.policy.raw.get("layers", {}),
            "policy_hash": self.policy.source_digest,
            "policy_version": self.policy.version,
            "tainted_paths": self.tainted_paths(),
            # 取证捕获开关。也必须从锚取而不是让 Broker 自己读盘——否则对手 A2
            # 改一个字段就能把取证材料悄悄关掉，而 attest() 毫无察觉。
            "forensics": self.policy.sec("forensics"),
        }

    # ---------- 会话生命周期 ----------

    def _state(self, session_id: str) -> SessionState:
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionState(session_id=session_id)
        return self.sessions[session_id]

    def session_start(self, session_id: str, task: str) -> None:
        st = SessionState(session_id=session_id)
        st.taint.add_trusted(task)
        st.taint.task = task
        self.sessions[session_id] = st

    def observe(self, session_id: str, text: str, trust: str, source: str = "") -> None:
        st = self._state(session_id)
        if trust == Trust.UNTRUSTED.value:
            st.taint.add_untrusted(text, source)
        else:
            st.taint.add_trusted(text)

    def freeze_manifest(self, session_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        """冻结能力清单。此刻上下文中不应有任何外部内容——若已污染则拒绝冻结。"""
        st = self._state(session_id)
        if st.taint.session_tainted:
            return {
                "ok": False,
                "reason": "会话已被不可信内容污染，不允许再冻结/扩展能力清单",
            }
        m = Manifest.from_wire(manifest)
        cap = int(self.policy.sec("manifest").get("max_steps_cap", 12))
        m.max_steps = min(m.max_steps, cap)
        m.tools = [t for t in m.tools if self.policy.sec("capabilities").get(t, True)]
        st.manifest = m
        return {"ok": True, "digest": m.digest(), "manifest": m.to_wire()}

    def evaluate(self, session_id: str, call: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
        st = self._state(session_id)
        tc = ToolCall(
            tool=str(call.get("tool", "")),
            args=dict(call.get("args", {})),
            step=int(call.get("step", 0)),
            call_id=str(call.get("call_id", "")),
            arg_origin=dict(call.get("arg_origin", {})),
        )
        work = dict(meta)
        decision = self.engine.evaluate(tc, st, work)
        # 顺带告诉 Broker 这个路径是否登记过污点，省掉一次额外的锚往返。
        if tc.tool == "fs.read" and work.get("rel") in self._provenance:
            work["path_tainted"] = True
        return {
            "verdict": decision.verdict,
            "rule": decision.rule,
            "reason": decision.reason,
            "risk": decision.risk,
            "meta": work,
        }

    def post_exec(self, session_id: str, payload: dict[str, Any]) -> None:
        """执行后回写会话状态：污点、敏感命中、外发预算、调用历史、溯源登记。"""
        st = self._state(session_id)
        content = str(payload.get("content", ""))
        source = str(payload.get("source", ""))

        # canary 只用于给评测侧留痕，不参与任何判定；判定走内容指纹。
        canaries = find_canaries(content)
        if canaries:
            st.canaries_seen.update(canaries)

        if payload.get("sensitive"):
            st.sensitive_seen = True
            if content:
                st.fingerprint.add(content, source)
        # 累加的是"攻击者可控的外发载荷"，不只是查询串长度。
        st.query_bytes_used += int(payload.get("egress_len", payload.get("query_len", 0)))

        trust = str(payload.get("trust", Trust.TRUSTED.value))
        if content:
            self.observe(session_id, content, trust, source)

        # 写入操作的溯源登记：内容源自不可信文本的写入，其目标路径此后
        # 一律带污点。这样下一次（甚至下一个会话）把它读回来时不会被当成
        # 可信数据，持久化注入的"写进去→读出来洗白"闭环就被切断了。
        #
        # 判据是"字节有没有真的落盘"，不是"判定是不是 allow"：observe 模式下
        # 被判 deny 的写入依然会执行，若按判定登记，C0 基线里的污染就会漏记，
        # 而 C0 恰恰是需要如实呈现攻击效果的那一组。
        if payload.get("tool") == "fs.write" and payload.get("executed"):
            rel = str(payload.get("rel", ""))
            written = str(payload.get("written_content", ""))
            if rel and written and st.taint.contains_untrusted(written[:400]):
                if rel not in self._provenance:
                    self._provenance.add(rel)
                    self._save_provenance()

        st.record(
            ToolCall(tool=str(payload.get("tool", "")), args=dict(payload.get("args", {}))),
            Decision(payload.get("verdict", "allow"), str(payload.get("rule", "")), risk=int(payload.get("risk", 0))),
            Trust(trust),
            bool(payload.get("sensitive")),
        )

    # ---------- 审计链：锚是唯一的序号与链头权威 ----------

    def chain_append(self, payload: dict[str, Any]) -> dict[str, Any]:
        seq = self._chain_seq
        prev = self._chain_head
        h = chain_record(prev, seq, payload)
        self._chain_seq = seq + 1
        self._chain_head = h
        return {"seq": seq, "prev_hash": prev, "hash": h, "mac": self.seal(h.encode())}

    def chain_checkpoint(self) -> dict[str, Any]:
        """签发可离机保存的检查点。校验方拿它才能识别尾部截断。"""
        return {
            "seq": self._chain_seq,
            "head": self._chain_head,
            "mac": self.seal(f"{self._chain_seq}|{self._chain_head}".encode()),
        }

    def export_key(self) -> str:
        """把验证密钥交给离机校验方。ephemeral 模式下这是唯一的取密钥时机。"""
        return self._key.hex()

    def seal(self, data: bytes) -> str:
        return hmac.new(self._key, data, hashlib.sha256).hexdigest()

    def attest(self) -> dict[str, Any]:
        a = self.policy.attestation(anchor="core")
        return {
            "anchor": a.anchor,
            "policy_hash": a.policy_hash,
            "policy_version": a.policy_version,
            "mode": a.mode,
            # 如实汇报密钥来源：file 模式下审计 MAC 对 A2 没有任何意义，
            # 校验报告必须能反映这一点，而不是让读者以为有保护。
            "key_source": self.key_source,
            "resists_a2_forgery": self.key_source != "file",
        }


class InProcessAnchor:
    """T0：同进程。基线档，用于测量策略判定的延迟下界。"""

    kind = "T0"

    def __init__(self, policy_path: str = "policy.json", key_source: str = "file"):
        self.core = AnchorCore(policy_path, key_source)

    def session_start(self, session_id: str, task: str) -> None:
        self.core.session_start(session_id, task)

    def observe(self, session_id: str, text: str, trust: str, source: str = "") -> None:
        self.core.observe(session_id, text, trust, source)

    def freeze_manifest(self, session_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        return self.core.freeze_manifest(session_id, manifest)

    def evaluate(self, session_id: str, call: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
        return self.core.evaluate(session_id, call, meta)

    def post_exec(self, session_id: str, payload: dict[str, Any]) -> None:
        self.core.post_exec(session_id, payload)

    def runtime_config(self) -> dict[str, Any]:
        return self.core.runtime_config()

    def chain_append(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.core.chain_append(payload)

    def chain_checkpoint(self) -> dict[str, Any]:
        return self.core.chain_checkpoint()

    def export_key(self) -> str:
        return self.core.export_key()

    def seal(self, data: bytes) -> str:
        return self.core.seal(data)

    def attest(self) -> Attestation:
        d = self.core.attest()
        return Attestation(
            self.kind, d["policy_hash"], d["policy_version"], d["mode"],
            d["key_source"], d["resists_a2_forgery"],
        )

    @property
    def policy(self) -> Policy:
        return self.core.policy

    def close(self) -> None:
        pass


class IsolatedProcessAnchor:
    """T1：独立进程 + 单向 stdio 通道。

    抵抗对手 A2 的 C1/C2/C3：策略、会话历史与 HMAC 密钥都在这个进程内，
    Broker 与 Agent 只能通过窄接口提问，无法读出密钥、无法改写历史。
    """

    kind = "T1"

    def __init__(self, policy_path: str = "policy.json", key_source: str = "ephemeral"):
        self._policy_path = policy_path
        child_env = os.environ.copy()
        child_env["PYTHONUTF8"] = "1"
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "trustgate.anchor", "--serve",
             "--policy", policy_path, "--key-source", key_source],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            cwd=str(project_root()),
            env=child_env,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )

    def _rpc(self, op: str, **kwargs: Any) -> Any:
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(json.dumps({"op": op, **kwargs}, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("可信锚进程已退出（fail-closed：调用方应拒绝本次操作）")
        resp = json.loads(line)
        if "error" in resp:
            raise RuntimeError(f"锚内错误: {resp['error']}")
        return resp.get("result")

    def session_start(self, session_id: str, task: str) -> None:
        self._rpc("session_start", session_id=session_id, task=task)

    def observe(self, session_id: str, text: str, trust: str, source: str = "") -> None:
        self._rpc("observe", session_id=session_id, text=text, trust=trust, source=source)

    def freeze_manifest(self, session_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        return self._rpc("freeze_manifest", session_id=session_id, manifest=manifest)

    def evaluate(self, session_id: str, call: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
        return self._rpc("evaluate", session_id=session_id, call=call, meta=meta)

    def post_exec(self, session_id: str, payload: dict[str, Any]) -> None:
        self._rpc("post_exec", session_id=session_id, payload=payload)

    def runtime_config(self) -> dict[str, Any]:
        return dict(self._rpc("runtime_config"))

    def chain_append(self, payload: dict[str, Any]) -> dict[str, Any]:
        return dict(self._rpc("chain_append", payload=payload))

    def chain_checkpoint(self) -> dict[str, Any]:
        return dict(self._rpc("chain_checkpoint"))

    def export_key(self) -> str:
        return str(self._rpc("export_key"))

    def seal(self, data: bytes) -> str:
        return str(self._rpc("seal", data=data.decode("utf-8", "surrogateescape")))

    def attest(self) -> Attestation:
        d = self._rpc("attest")
        return Attestation(
            self.kind, d["policy_hash"], d["policy_version"], d["mode"],
            d["key_source"], d["resists_a2_forgery"],
        )

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()


def make_anchor(kind: str = "T1", policy_path: str = "policy.json", key_source: str | None = None) -> Any:
    """按档位构造可信锚。

    默认密钥来源随档位而变，且是刻意的：T0 是功能与延迟基线档，不宣称
    抵抗任何本地对手，用落盘密钥换取演示便利；T1 一旦宣称抵抗 A2-C1，
    密钥就不能待在 A2 读得到的地方，只能是 ephemeral。
    """
    kind = kind.upper()
    if kind == "T0":
        return InProcessAnchor(policy_path, key_source or "file")
    if kind == "T1":
        return IsolatedProcessAnchor(policy_path, key_source or "ephemeral")
    if kind == "T2":
        raise NotImplementedError("T2 (QEMU + OP-TEE) 为第 12 周选做项，接口已在 §5.2 冻结")
    raise ValueError(f"未知的可信锚档位: {kind}")


# ---------- T1 的服务端（子进程入口） ----------

def _serve(policy_path: str, key_source: str) -> None:
    core = AnchorCore(policy_path, key_source)
    ops = {
        "session_start": lambda a: core.session_start(a["session_id"], a["task"]),
        "observe": lambda a: core.observe(a["session_id"], a["text"], a["trust"], a.get("source", "")),
        "freeze_manifest": lambda a: core.freeze_manifest(a["session_id"], a["manifest"]),
        "evaluate": lambda a: core.evaluate(a["session_id"], a["call"], a["meta"]),
        "post_exec": lambda a: core.post_exec(a["session_id"], a["payload"]),
        "runtime_config": lambda a: core.runtime_config(),
        "chain_append": lambda a: core.chain_append(a["payload"]),
        "chain_checkpoint": lambda a: core.chain_checkpoint(),
        "export_key": lambda a: core.export_key(),
        "clear_provenance": lambda a: core.clear_provenance(),
        "seal": lambda a: core.seal(a["data"].encode("utf-8", "surrogateescape")),
        "attest": lambda a: core.attest(),
    }
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            fn = ops.get(req.get("op", ""))
            if fn is None:
                out = {"error": f"未知操作 {req.get('op')}"}
            else:
                out = {"result": fn(req)}
        except Exception as exc:  # 锚内异常一律回报错误，由调用方 fail-closed
            out = {"error": f"{type(exc).__name__}: {exc}"}
        sys.stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="TrustGate 可信锚（T1 隔离进程模式）")
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--policy", default="policy.json")
    ap.add_argument("--key-source", default="file", choices=["file", "ephemeral", "env"])
    ns = ap.parse_args()
    if ns.serve:
        _serve(ns.policy, ns.key_source)
    else:
        core = AnchorCore(ns.policy, ns.key_source)
        print(json.dumps(core.attest(), ensure_ascii=False, indent=2))
