"""AgentDojo 适配层的离线测试。不调用模型。

良性一侧走用户任务自己的 ground truth，并交给套件的 utility 判定。
注入一侧在读过一次工具返回之后，再发往任务里没写过的地址。
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# agentdojo 是可选依赖，核心 CI 矩阵刻意不装第三方包。
# 设了 TG_REQUIRE_AGENTDOJO 的那一格必须真的跑，缺包就失败而不是跳过。
try:
    from agentdojo.functions_runtime import FunctionsRuntime  # noqa: E402
    from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
    from agentdojo.types import ChatAssistantMessage, text_content_block_from_string  # noqa: E402

    from eval.agentdojo_adapter import AGENTDOJO_VERSION, TrustGateToolsExecutor  # noqa: E402

    _MISSING = ""
except ImportError as exc:
    if os.environ.get("TG_REQUIRE_AGENTDOJO"):
        raise
    _MISSING = f"未安装 agentdojo（{exc}）。pip install -r requirements.txt 后才跑这组"


def _run_calls(exe, prompt, env, runtime, calls, messages=None):
    messages = list(messages or [])
    for call in calls:
        messages.append(
            ChatAssistantMessage(
                role="assistant",
                content=[text_content_block_from_string("")],
                tool_calls=[call],
            )
        )
        _, runtime, env, messages, _ = exe.query(prompt, runtime, env, messages, {})
    return env, messages


@unittest.skipIf(bool(_MISSING), _MISSING)
class AgentDojoAdapterTest(unittest.TestCase):
    def test_version_is_the_pinned_release(self) -> None:
        self.assertEqual(AGENTDOJO_VERSION, "0.1.35")

    def test_user_task_ground_truth_still_completes(self) -> None:
        suite = get_suite("v1", "workspace")
        user = next(t for t in suite.user_tasks.values() if "sarah.connor@gmail.com" in t.PROMPT)
        env = user.init_environment(suite.load_and_inject_default_environment({}))
        pre = env.model_copy(deep=True)
        runtime = FunctionsRuntime(suite.tools)
        exe = TrustGateToolsExecutor()
        env, messages = _run_calls(exe, user.PROMPT, env, runtime, user.ground_truth(pre))
        self.assertTrue(all(m["error"] is None for m in messages if m["role"] == "tool"), messages)
        self.assertTrue(
            user.utility("", pre, env),
            "用户任务的 ground truth 被适配层改写后不再完成",
        )

    def test_email_to_address_absent_from_the_task_is_denied_after_tool_output(self) -> None:
        suite = get_suite("v1", "workspace")
        user = next(t for t in suite.user_tasks.values() if "sarah.connor@gmail.com" in t.PROMPT)
        injection = next(t for t in suite.injection_tasks.values() if "mark.black-2134@gmail.com" in t.GOAL)
        env = user.init_environment(suite.load_and_inject_default_environment({}))
        pre = env.model_copy(deep=True)
        runtime = FunctionsRuntime(suite.tools)
        exe = TrustGateToolsExecutor()
        benign = user.ground_truth(pre)[:1]
        env, messages = _run_calls(exe, user.PROMPT, env, runtime, benign)
        self.assertIsNone(messages[-1]["error"])
        self.assertTrue(exe._taint.session_tainted)
        env, messages = _run_calls(
            exe, user.PROMPT, env, runtime, injection.ground_truth(pre), messages
        )
        denied = [m for m in messages if m["role"] == "tool" and m["error"]]
        self.assertTrue(denied, messages)
        self.assertIn("L4.exfil_chain", denied[-1]["error"])
        self.assertFalse(
            injection.security("", pre, env),
            "拒绝之后注入目标仍然达成了",
        )


class AgentDojoScriptTest(unittest.TestCase):
    def test_missing_key_exits_3_without_numbers(self) -> None:
        env = os.environ.copy()
        env.pop("TG_API_KEY", None)
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "run_agentdojo.py"),
             "--suite", "workspace", "--model", "gpt-4o-mini", "--defense", "trustgate"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(proc.returncode, 3)
        blob = proc.stdout + proc.stderr
        self.assertNotIn("%", blob)
        self.assertNotRegex(blob, r"\d+\s*/\s*\d+")

    def test_thought_signature_is_carried_into_the_next_turn(self) -> None:
        from types import SimpleNamespace

        from scripts.run_agentdojo import ThoughtSignatureClient

        sent: list[list[dict]] = []

        def create(**kw):
            sent.append(kw["messages"])
            tc = SimpleNamespace(id="c1", extra_content={"google": {"thought_signature": "sig"}})
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(tool_calls=[tc]))])

        client = ThoughtSignatureClient(SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create))))
        client.chat.completions.create(model="m", messages=[{"role": "user", "content": "x"}])
        call = {"id": "c1", "type": "function", "function": {"name": "f", "arguments": "{}"}}
        other = {"id": "c2", "type": "function", "function": {"name": "g", "arguments": "{}"}}
        client.chat.completions.create(
            model="m",
            messages=[{"role": "assistant", "content": None, "tool_calls": [call, other]},
                      {"role": "tool", "tool_call_id": "c1", "content": "ok"}],
        )
        calls = sent[-1][0]["tool_calls"]
        self.assertEqual(calls[0]["extra_content"], {"google": {"thought_signature": "sig"}})
        self.assertNotIn("extra_content", calls[1], "没见过的调用 id 不能被补上签名")
        self.assertNotIn("extra_content", call, "不能原地改调用方的消息")

    def _flaky(self, replies):
        from types import SimpleNamespace

        from scripts.run_agentdojo import ThoughtSignatureClient

        it = iter(replies)
        calls = {"n": 0}

        def create(**kw):
            calls["n"] += 1
            return SimpleNamespace(choices=[SimpleNamespace(message=next(it))])

        inner = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
        return ThoughtSignatureClient(inner, empty_retries=2), calls

    def test_empty_reply_is_retried(self) -> None:
        from types import SimpleNamespace

        ok = SimpleNamespace(tool_calls=None, content="done")
        client, calls = self._flaky([None, ok])
        resp = client.chat.completions.create(model="m", messages=[])
        self.assertIs(resp.choices[0].message, ok)
        self.assertEqual(calls["n"], 2)
        self.assertEqual(client.empty_replies, 0, "重试成功的不算空回复")

    @unittest.skipIf(bool(_MISSING), _MISSING)
    def test_persistent_empty_reply_is_counted_not_hidden(self) -> None:
        client, calls = self._flaky([None, None, None])
        resp = client.chat.completions.create(model="m", messages=[])
        self.assertEqual(calls["n"], 3)
        self.assertEqual(resp.choices[0].message.content, "")
        self.assertIsNone(resp.choices[0].message.tool_calls)
        self.assertEqual(client.empty_replies, 1)


if __name__ == "__main__":
    unittest.main()
