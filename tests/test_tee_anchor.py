"""T2 可信锚（TEE 桥）的单元测试。

全部跑在**软模拟桥**（tg_bridge_soft）上：它的价值是锁住"Python 锚 ⇄ C 桥
⇄ TA 语义"的逐字节一致性（哈希公式、HMAC、序号持久化、fail-closed），
以及 make_anchor("T2") 的端到端链路。**软模拟不产生任何安全性质**，
论文实验数据必须来自真桥（tee/README.md 的诚实边界）。

运行：python -m tests.test_tee_anchor
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from trustgate.anchor import TeeBridge, make_anchor  # noqa: E402
from trustgate.audit import GENESIS, chain_record  # noqa: E402

SOFT_BIN = ROOT / "tee" / "bridge" / "tg_bridge_soft"

_BRIDGE_ENV = "TG_TEE_BRIDGE"
_STATE_ENV = "TG_TEE_SOFT_STATE"

_old_env: dict[str, str | None] = {}
_tmpdir: Path | None = None
_state_file: Path | None = None


def _build_soft_bridge() -> None:
    if SOFT_BIN.exists():
        return
    if shutil.which("gcc") is None:
        raise unittest.SkipTest("无 gcc，无法编译软模拟桥")
    SOFT_BIN.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["gcc", "-O2", "-Wall", "-Wextra", "-DSOFT_TA", "-o", str(SOFT_BIN),
         str(ROOT / "tee" / "bridge" / "tg_bridge.c")],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise unittest.SkipTest(f"软模拟桥编译失败:\n{r.stderr}")


def setUpModule() -> None:
    global _tmpdir, _state_file
    _build_soft_bridge()
    _tmpdir = Path(tempfile.mkdtemp(prefix="tg-tee-test-"))
    _state_file = _tmpdir / "soft-state.json"
    for k in (_BRIDGE_ENV, _STATE_ENV):
        _old_env[k] = os.environ.get(k)
    os.environ[_BRIDGE_ENV] = str(SOFT_BIN)
    os.environ[_STATE_ENV] = str(_state_file)


def tearDownModule() -> None:
    for k, v in _old_env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    if _tmpdir is not None:
        resolved = _tmpdir.resolve()
        assert resolved.is_relative_to(Path(tempfile.gettempdir()).resolve())
        shutil.rmtree(resolved, ignore_errors=True)


class TeeChainTest(unittest.TestCase):
    def setUp(self) -> None:
        assert _state_file is not None
        _state_file.unlink(missing_ok=True)
        self.bridge = TeeBridge()
        self.addCleanup(self.bridge.close)

    def test_chain_record_matches_doc_formula(self) -> None:
        """audit.chain_record 与 docs/02 §5.3 公式逐字节一致（T2 依赖此公式）。"""
        payload = {"event": "tool_call", "risk": 30}
        cp = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                        separators=(",", ":")).encode()
        expect = hashlib.sha256(b"0" * 64 + b"|" + b"0" + b"|" + cp).hexdigest()
        self.assertEqual(chain_record(GENESIS, 0, payload), expect)

    def test_seal_matches_python_hmac(self) -> None:
        key_hex = self.bridge.rpc("export_key")["key"]
        key = bytes.fromhex(key_hex)
        for msg in (b"", b"abc", os.urandom(256)):
            got = self.bridge.rpc("seal", data_b64=__import__("base64").b64encode(msg).decode())
            expect = hmac_mod.new(key, msg, hashlib.sha256).hexdigest()
            self.assertEqual(got["mac"], expect)

    def test_chain_append_matches_audit_semantics(self) -> None:
        key_hex = self.bridge.rpc("export_key")["key"]
        key = bytes.fromhex(key_hex)
        prev = GENESIS
        for seq in range(3):
            payload = {"event": "tool_call", "seq_probe": seq}
            cp = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                            separators=(",", ":")).encode()
            import base64
            res = self.bridge.rpc("chain_append", payload_b64=base64.b64encode(cp).decode())
            expect_hash = chain_record(prev, seq, payload)
            self.assertEqual(res["seq"], seq)
            self.assertEqual(res["prev_hash"], prev)
            self.assertEqual(res["hash"], expect_hash)
            self.assertEqual(res["mac"], hmac_mod.new(key, expect_hash.encode(),
                                                      hashlib.sha256).hexdigest())
            prev = expect_hash

    def test_checkpoint_mac(self) -> None:
        import base64
        key_hex = self.bridge.rpc("export_key")["key"]
        key = bytes.fromhex(key_hex)
        self.bridge.rpc("chain_append", payload_b64=base64.b64encode(b"{}").decode())
        cp = self.bridge.rpc("checkpoint")
        msg = f"{cp['seq']}|{cp['head']}".encode()
        self.assertEqual(cp["mac"], hmac_mod.new(key, msg, hashlib.sha256).hexdigest())

    def test_persistence_across_bridge_restart(self) -> None:
        """软模拟镜像 TA 的持久性：桥重启后序号延续、密钥不变。"""
        import base64
        self.bridge.rpc("chain_append", payload_b64=base64.b64encode(b"{}").decode())
        self.bridge.rpc("chain_append", payload_b64=base64.b64encode(b"{}").decode())
        key1 = self.bridge.rpc("export_key")["key"]
        self.bridge.close()

        b2 = TeeBridge()
        self.addCleanup(b2.close)
        cp = b2.rpc("checkpoint")
        self.assertEqual(cp["seq"], 2)
        self.assertEqual(b2.rpc("export_key")["key"], key1)

    def test_fail_closed_when_bridge_dies(self) -> None:
        self.bridge.proc.kill()
        self.bridge.proc.wait()
        with self.assertRaises(RuntimeError):
            self.bridge.rpc("checkpoint")


class TeeAnchorFactoryTest(unittest.TestCase):
    def setUp(self) -> None:
        assert _state_file is not None
        _state_file.unlink(missing_ok=True)

    def test_factory_t2_end_to_end(self) -> None:
        """make_anchor("T2") 全链路：serve 侧 TeeAnchorCore + 桥 + 软 TA。"""
        anchor = make_anchor("T2", str(ROOT / "policy.json"))
        try:
            att = anchor.attest()
            self.assertEqual(att.key_source, "tee")
            self.assertTrue(att.resists_a2_forgery)
            self.assertEqual(att.anchor, "T2")

            anchor.session_start("s-tee", "测试任务")
            verdict = anchor.evaluate("s-tee", {"tool": "fs.read", "args": {}, "step": 1}, {})
            self.assertIn(verdict["verdict"], ("allow", "deny", "confirm"))

            rec = anchor.chain_append({"event": "tool_call", "probe": 1})
            self.assertEqual(rec["seq"], 0)
            self.assertEqual(rec["prev_hash"], GENESIS)

            key1 = anchor.export_key()
            self.assertEqual(len(key1), 64)
        finally:
            anchor.close()

    def test_t2_key_persists_across_anchor_restart(self) -> None:
        """T2 头条性质：锚整体重启后密钥不变（T1-ephemeral 在这里必然失败）。"""
        a1 = make_anchor("T2", str(ROOT / "policy.json"))
        try:
            k1 = a1.export_key()
            a1.chain_append({"event": "probe"})
        finally:
            a1.close()
        a2 = make_anchor("T2", str(ROOT / "policy.json"))
        try:
            self.assertEqual(a2.export_key(), k1)
            cp = a2.chain_checkpoint()
            self.assertEqual(cp["seq"], 1)
        finally:
            a2.close()


if __name__ == "__main__":
    unittest.main()
