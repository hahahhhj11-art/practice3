"""清单生成评测的离线测试。不调用模型。

对照的是人工参考清单。把 max_steps 填成 harness 的下限 8，
而参考清单只有 2 步时，必须记成申请过多，不能因为装置会垫到 8 就放过。
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

from eval.benign_tasks import benign_sample  # noqa: E402
from eval.manifest_eval import compare_manifest, completes_under, summarize_rows  # noqa: E402
from scripts.serve_corpus import serve_in_background  # noqa: E402


class ManifestCompareTest(unittest.TestCase):
    def test_harness_pad_is_over_request_against_the_reference(self) -> None:
        sample = benign_sample(1)
        reference = sample["reference_manifest"]
        self.assertLess(reference["max_steps"], 8)
        padded = dict(reference)
        padded["max_steps"] = 8
        row = compare_manifest(sample, padded)
        self.assertTrue(row["over_request"])
        self.assertFalse(row["under_request"])
        self.assertEqual(row["reference_max_steps"], reference["max_steps"])

    def test_missing_write_is_under_request_and_drops_completion(self) -> None:
        sample = benign_sample(1)
        reference = dict(sample["reference_manifest"])
        exact = compare_manifest(sample, reference)
        self.assertFalse(exact["under_request"])
        self.assertFalse(exact["over_request"])

        narrow = dict(reference)
        narrow["tools"] = [t for t in reference["tools"] if t != "fs.write"]
        row = compare_manifest(sample, narrow)
        self.assertTrue(row["under_request"])
        self.assertIn("fs.write", row["missing_tools"])

        httpd, collector = serve_in_background(
            port=8799, log_path=ROOT / "logs" / "manifest-test-collector.jsonl"
        )
        completes_under._collector = collector  # type: ignore[attr-defined]
        # 审计路径必须落在仓库里：run_trial 要把它写成相对路径交给 Broker。
        work = ROOT / "logs" / "manifest-test-work"
        work.mkdir(parents=True, exist_ok=True)
        try:
            self.assertTrue(completes_under(sample, reference, work))
            self.assertFalse(completes_under(sample, narrow, work))
        finally:
            completes_under._collector = None  # type: ignore[attr-defined]
            httpd.shutdown()
            httpd.server_close()

        summary = summarize_rows([
            {**row, "reference_completed": True, "generated_completed": False},
        ])
        self.assertEqual(summary["ua_lost_when_under"]["k"], 1)
        self.assertEqual(summary["ua_lost_when_under"]["n"], 1)

    def test_wider_prefix_is_over_request(self) -> None:
        sample = benign_sample(1)
        generated = dict(sample["reference_manifest"])
        generated["write_prefixes"] = ["sandbox/"]
        row = compare_manifest(sample, generated)
        self.assertTrue(row["over_request"])
        self.assertFalse(row["under_request"])

    def test_host_with_port_is_judged_like_l2_enforces_it(self) -> None:
        from trustgate.policy import manifest_host_allows

        self.assertTrue(manifest_host_allows("http://127.0.0.1:8799/x", ["127.0.0.1"]))
        self.assertTrue(manifest_host_allows("http://127.0.0.1:8799/x", ["127.0.0.1:8799"]))
        self.assertFalse(manifest_host_allows("http://127.0.0.1:8800/x", ["127.0.0.1:8799"]),
                         "带端口的申请只放行那一个端口")
        self.assertTrue(manifest_host_allows("https://example.com/x", ["example.com:443"]))

        sample = benign_sample(1)
        self.assertTrue(sample["benign_plan"]["urls"])
        same = dict(sample["reference_manifest"], hosts=["127.0.0.1:8799"])
        row = compare_manifest(sample, same)
        self.assertFalse(row["under_request"], row)
        self.assertFalse(row["over_request"], row)
        wrong = dict(sample["reference_manifest"], hosts=["127.0.0.1:9999"])
        self.assertTrue(compare_manifest(sample, wrong)["under_request"])

    def test_denied_step_is_not_completed_even_if_the_file_is_written(self) -> None:
        """MockLLM 被拒之后照写输出文件。只看文件会把没读到网页的摘要记成完成。"""
        sample = benign_sample(1)
        wrong = dict(sample["reference_manifest"], hosts=["127.0.0.1:9999"])
        httpd, collector = serve_in_background(
            port=8799, log_path=ROOT / "logs" / "manifest-test-collector.jsonl"
        )
        completes_under._collector = collector  # type: ignore[attr-defined]
        work = ROOT / "logs" / "manifest-test-work"
        work.mkdir(parents=True, exist_ok=True)
        try:
            self.assertFalse(completes_under(sample, wrong, work))
            self.assertTrue(completes_under(sample, dict(wrong, hosts=["127.0.0.1:8799"]), work))
        finally:
            completes_under._collector = None  # type: ignore[attr-defined]
            httpd.shutdown()
            httpd.server_close()

    def test_unparseable_and_lost_answers_stay_out_of_under_request(self) -> None:
        """拿不出清单若被当成空清单，格式问题会被记成防御的申请不足。"""
        from eval.manifest_eval import ManifestUnparseable, evaluate
        from trustgate.llm import LLMTransportError

        samples = [benign_sample(1), benign_sample(2), benign_sample(3)]
        answers = {
            samples[0]["task"]: dict(samples[0]["reference_manifest"]),
            samples[1]["task"]: ManifestUnparseable("模型输出无法解析为 JSON"),
            samples[2]["task"]: LLMTransportError("模型通道故障"),
        }

        def propose(task: str) -> dict:
            got = answers[task]
            if isinstance(got, Exception):
                raise got
            return got

        report = evaluate(propose, samples=samples)
        self.assertEqual(report["n_attempted"], 3)
        self.assertEqual(report["n_transport_failed"], 1)
        self.assertEqual((report["unparseable"]["k"], report["unparseable"]["n"]), (1, 2))
        self.assertEqual(report["n"], 1)
        self.assertEqual(report["under_request"]["k"], 0)
        self.assertEqual(report["under_request"]["n"], 1)

    def test_parse_error_marker_is_not_read_as_a_manifest(self) -> None:
        from unittest import mock

        from eval.manifest_eval import ManifestUnparseable, propose_manifest

        with mock.patch("trustgate.llm.OpenAICompatibleLLM._chat", return_value="{'tools': ['fs.read']}"):
            with self.assertRaises(ManifestUnparseable):
                propose_manifest("读 README", "m")


class ManifestScriptTest(unittest.TestCase):
    def test_missing_key_exits_3_without_rates(self) -> None:
        env = os.environ.copy()
        env.pop("TG_API_KEY", None)
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "run_manifest_eval.py"),
             "--model", "gpt-4o-mini"],
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
