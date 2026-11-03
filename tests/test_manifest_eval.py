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
