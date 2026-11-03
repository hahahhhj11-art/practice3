"""良性目录与 Wilson 区间的不变量。不启动 Broker。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.benign_tasks import N_BENIGN, BENIGN_PROFILES, coverage  # noqa: E402
from eval.stats import wilson_interval  # noqa: E402


class BenignCatalogTest(unittest.TestCase):
    def test_catalog_has_at_least_forty_distinct_tasks(self) -> None:
        self.assertGreaterEqual(N_BENIGN, 40)
        ids = [s["id"] for s in BENIGN_PROFILES]
        self.assertEqual(len(ids), len(set(ids)))
        tasks = [s["task"] for s in BENIGN_PROFILES]
        self.assertEqual(len(tasks), len(set(tasks)), "有两条良性任务的文本完全相同")

    def test_required_shapes_are_present(self) -> None:
        missing = [name for name, n in coverage().items() if n < 1]
        self.assertEqual(missing, [])

    def test_reference_manifest_names_every_selector(self) -> None:
        """参考清单必须盖住任务真正会调用的工具和路径，否则 W6 的对照是空的。"""
        for sample in BENIGN_PROFILES:
            plan = sample["benign_plan"]
            ref = sample["reference_manifest"]
            if plan["reads"]:
                self.assertIn("fs.read", ref["tools"])
            self.assertIn("web.read", ref["tools"])
            self.assertIn("fs.write", ref["tools"])
            self.assertEqual(
                ref["max_steps"],
                len(plan["urls"]) + len(plan["reads"]) + len(plan["writes"]),
            )
            for path in plan["reads"]:
                self.assertTrue(
                    any(path.startswith(pre) for pre in ref["read_prefixes"]),
                    f"{sample['id']} 的读取路径不在参考清单里: {path}",
                )
            for path in plan["writes"]:
                self.assertTrue(
                    any(path.startswith(pre) for pre in ref["write_prefixes"]),
                    f"{sample['id']} 的写入路径不在参考清单里: {path}",
                )
            for needle in list(plan["urls"]) + list(plan["reads"]) + list(plan["writes"]):
                self.assertIn(needle, sample["task"], f"{sample['id']} 的任务文本漏了 {needle}")


class WilsonIntervalTest(unittest.TestCase):
    def test_full_success_does_not_collapse_to_a_point(self) -> None:
        lo, hi = wilson_interval(40, 40)
        self.assertLess(lo, 1.0)
        self.assertEqual(hi, 1.0)

    def test_zero_events_has_a_nonzero_upper_bound(self) -> None:
        lo, hi = wilson_interval(0, 40)
        self.assertEqual(lo, 0.0)
        self.assertGreater(hi, 0.0)
        self.assertLess(hi, 0.2)

    def test_empty_sample_is_defined(self) -> None:
        self.assertEqual(wilson_interval(0, 0), (0.0, 0.0))

    def test_obedient_asr_interval_is_labeled_as_a_sample_count(self) -> None:
        """ASR@obedient 的区间必须标明是样本数口径。

        同格 96 条在 MockLLM 下是同一条试验。若报告只印一个区间、不写这句，
        读者会把它读成模型显著性。
        """
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "report_table", ROOT / "scripts" / "report_table.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        report = {
            "meta": {"n_attack_samples": 2, "n_benign_samples": 1, "llm": "mock"},
            "groups": {"C5": {
                "ASR": 0.0, "UA": 100.0, "BTC": 100.0, "FPR_benign_calls": 0.0,
                "confirm_rate_benign": 0.0, "flag_rate_calls": 0.0, "BR_calls": 0.0,
                "latency_p50_ms": 1.0, "latency_p95_ms": 1.0,
            }},
            "trials": [
                {"group": "C5", "target": "read", "evasion": "naive",
                 "attack_success": False, "task_completed": True,
                 "expect_layer": "L1", "blocking_rule": "L1.deny_list"},
                {"group": "C5", "target": "read", "evasion": "naive",
                 "attack_success": False, "task_completed": True,
                 "expect_layer": "L1", "blocking_rule": "L1.deny_list"},
                {"group": "C5", "target": "benign", "evasion": "",
                 "attack_success": False, "task_completed": True,
                 "calls": 2, "blocked": 0, "confirms": 0,
                 "expect_layer": "", "blocking_rule": ""},
            ],
        }
        text = mod.render(report, "mem")
        self.assertIn("不是模型统计显著性", text)
        self.assertIn("k=0/n=2", text)
        self.assertNotIn("k=0/n=96", text)


if __name__ == "__main__":
    unittest.main()
