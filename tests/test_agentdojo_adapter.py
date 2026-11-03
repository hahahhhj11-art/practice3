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

from agentdojo.functions_runtime import FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from agentdojo.types import ChatAssistantMessage, text_content_block_from_string  # noqa: E402

from eval.agentdojo_adapter import AGENTDOJO_VERSION, TrustGateToolsExecutor  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
