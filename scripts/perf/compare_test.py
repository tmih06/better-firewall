#!/usr/bin/env python3
"""
Unit and fixture tests for scripts/perf/compare.py.
Uses pure synthetic fixtures; requires no network, no root, and no external dependencies.
Tests edge cases, missing metrics, zero metrics, threshold boundaries, and explicit failure paths.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

# Ensure scripts/perf is in Python path for direct imports
PERF_DIR = os.path.dirname(os.path.abspath(__file__))
if PERF_DIR not in sys.path:
    sys.path.insert(0, PERF_DIR)

import compare


def make_valid_k6_dict(
    rate: float = 1250.5,
    count: int = 6250,
    p50: float = 1.25,
    p95: float = 3.50,
    p99: float = 7.80,
    avg: float = 1.45,
    error_rate: float = 0.0,
) -> dict:
    """Helper to produce a valid k6 machine summary dictionary."""
    return {
        "metrics": {
            "http_reqs": {
                "values": {
                    "rate": rate,
                    "count": count,
                }
            },
            "http_req_duration": {
                "values": {
                    "avg": avg,
                    "p(50)": p50,
                    "p(95)": p95,
                    "p(99)": p99,
                    "min": 0.5,
                    "max": 15.2,
                }
            },
            "http_req_failed": {
                "values": {
                    "rate": error_rate,
                    "passes": int(count * (1.0 - error_rate)),
                    "fails": int(count * error_rate),
                }
            },
        }
    }


class TestCompareEngine(unittest.TestCase):
    def test_parse_valid_k6_summary(self):
        """Test parsing valid k6 metrics dictionary."""
        fixture = make_valid_k6_dict()
        parsed = compare.parse_k6_summary(fixture)
        self.assertAlmostEqual(parsed["throughput_rps"], 1250.5)
        self.assertEqual(parsed["request_count"], 6250)
        self.assertAlmostEqual(parsed["latency_p50_ms"], 1.25)
        self.assertAlmostEqual(parsed["latency_p95_ms"], 3.50)
        self.assertAlmostEqual(parsed["latency_p99_ms"], 7.80)
        self.assertAlmostEqual(parsed["error_rate"], 0.0)

    def test_missing_metrics_root_explicit_fail(self):
        """Test missing 'metrics' key raises explicit ValueError."""
        with self.assertRaises(ValueError) as ctx:
            compare.parse_k6_summary({"other": {}})
        self.assertIn("missing 'metrics'", str(ctx.exception))

    def test_missing_http_reqs_metric_explicit_fail(self):
        """Test missing 'http_reqs' metric raises explicit ValueError."""
        fixture = make_valid_k6_dict()
        del fixture["metrics"]["http_reqs"]
        with self.assertRaises(ValueError) as ctx:
            compare.parse_k6_summary(fixture)
        self.assertIn("Missing required metric: 'http_reqs'", str(ctx.exception))

    def test_missing_duration_percentiles_explicit_fail(self):
        """Test missing p(95) or p(50) in http_req_duration raises explicit ValueError."""
        fixture = make_valid_k6_dict()
        del fixture["metrics"]["http_req_duration"]["values"]["p(95)"]
        with self.assertRaises(ValueError) as ctx:
            compare.parse_k6_summary(fixture)
        self.assertIn("Missing latency percentiles", str(ctx.exception))

    def test_k6_default_summary_shape_explicit_fail(self):
        """k6's default summaryTrendStats (avg,min,med,max,p(90),p(95)) omits
        p(50) and p(99). A summary in that shape must be rejected, which is
        why firewall.js pins summaryTrendStats explicitly."""
        fixture = make_valid_k6_dict()
        fixture["metrics"]["http_req_duration"]["values"] = {
            "avg": 1.45,
            "min": 0.5,
            "med": 1.2,
            "max": 15.2,
            "p(90)": 3.0,
            "p(95)": 3.5,
        }
        with self.assertRaises(ValueError) as ctx:
            compare.parse_k6_summary(fixture)
        self.assertIn("Missing latency percentiles", str(ctx.exception))

    def test_k6_full_trend_stats_shape_parses(self):
        """Summary with every key from firewall.js's summaryTrendStats must
        parse, and p(50) must not be conflated with the distinct 'med' stat."""
        fixture = make_valid_k6_dict(p50=1.25)
        fixture["metrics"]["http_req_duration"]["values"].update(
            {"med": 9.99, "p(90)": 3.0}
        )
        parsed = compare.parse_k6_summary(fixture)
        self.assertAlmostEqual(parsed["latency_p50_ms"], 1.25)
        self.assertAlmostEqual(parsed["latency_p95_ms"], 3.50)
        self.assertAlmostEqual(parsed["latency_p99_ms"], 7.80)
        self.assertAlmostEqual(parsed["latency_avg_ms"], 1.45)

    def test_missing_failed_metric_explicit_fail(self):
        """Test missing 'http_req_failed' raises explicit ValueError."""
        fixture = make_valid_k6_dict()
        del fixture["metrics"]["http_req_failed"]
        with self.assertRaises(ValueError) as ctx:
            compare.parse_k6_summary(fixture)
        self.assertIn("Missing required metric: 'http_req_failed'", str(ctx.exception))

    def test_zero_throughput_explicit_fail(self):
        """Test rate=0 or count=0 raises explicit ValueError."""
        fixture = make_valid_k6_dict(rate=0.0, count=0)
        with self.assertRaises(ValueError) as ctx:
            compare.parse_k6_summary(fixture)
        self.assertIn("Zero throughput or requests recorded", str(ctx.exception))

    def test_aggregate_repeats(self):
        """Test averaging metrics across repeats."""
        r1 = compare.parse_k6_summary(make_valid_k6_dict(rate=1000.0, p95=4.0, count=5000))
        r2 = compare.parse_k6_summary(make_valid_k6_dict(rate=1200.0, p95=6.0, count=6000))
        agg = compare.aggregate_repeats([r1, r2])
        self.assertAlmostEqual(agg["throughput_rps"], 1100.0)
        self.assertEqual(agg["request_count"], 11000)
        self.assertAlmostEqual(agg["latency_p95_ms"], 5.0)
        self.assertEqual(agg["repeats"], 2)

    def test_aggregate_empty_list_fail(self):
        """Test empty runs list raises ValueError."""
        with self.assertRaises(ValueError):
            compare.aggregate_repeats([])

    def test_division_by_zero_safety(self):
        """Test safe handling when metrics or apply times are zero or missing."""
        scenarios = {
            "baseline": {"throughput_rps": 0.0},
            "bfw_10": {
                "throughput_rps": 1000.0,
                "latency_p50_ms": 1.0,
                "latency_p95_ms": 2.0,
                "latency_p99_ms": 3.0,
                "error_rate": 0.0,
            },
            "ufw_10": {
                "throughput_rps": 0.0,  # zero throughput
                "latency_p50_ms": 0.0,
                "latency_p95_ms": 0.0,
                "latency_p99_ms": 0.0,
                "error_rate": 0.0,
            },
        }
        apply_times = {"bfw": {"10": 0.0}, "ufw": {"10": 0.5}}

        comparisons = compare.compute_comparisons(scenarios, apply_times)
        self.assertEqual(len(comparisons), 1)
        comp = comparisons[0]
        # Should safely yield None instead of crashing with ZeroDivisionError
        self.assertIsNone(comp["throughput_ratio_bfw_vs_ufw"])
        self.assertIsNone(comp["p95_latency_ratio_bfw_vs_ufw"])
        self.assertIsNone(comp["apply_time_speedup"])

    def test_threshold_evaluation_success(self):
        """Test evaluation when all constraints pass."""
        scenarios = {
            "baseline": {"error_rate": 0.0, "latency_p95_ms": 2.5},
            "bfw_10": {"error_rate": 0.001, "latency_p95_ms": 3.2},
            "ufw_10": {"error_rate": 0.002, "latency_p95_ms": 3.8},
        }
        controls = {"positive_permitted": True, "negative_denied": True}
        res = compare.evaluate_thresholds(
            scenarios, controls, max_error_rate=0.01, max_p95_latency_ms=500.0
        )
        self.assertTrue(res["passed"])
        self.assertEqual(len(res["violations"]), 0)

    def test_threshold_evaluation_error_rate_failure(self):
        """Test failure when scenario exceeds max error rate."""
        scenarios = {
            "bfw_10": {"error_rate": 0.05, "latency_p95_ms": 5.0},
        }
        controls = {"positive_permitted": True, "negative_denied": True}
        res = compare.evaluate_thresholds(
            scenarios, controls, max_error_rate=0.01, max_p95_latency_ms=500.0
        )
        self.assertFalse(res["passed"])
        self.assertTrue(any("error rate" in v for v in res["violations"]))

    def test_threshold_evaluation_latency_failure(self):
        """Test failure when scenario exceeds p95 latency threshold."""
        scenarios = {
            "bfw_10": {"error_rate": 0.0, "latency_p95_ms": 650.0},
        }
        controls = {"positive_permitted": True, "negative_denied": True}
        res = compare.evaluate_thresholds(
            scenarios, controls, max_error_rate=0.01, max_p95_latency_ms=500.0
        )
        self.assertFalse(res["passed"])
        self.assertTrue(any("latency" in v for v in res["violations"]))

    def test_threshold_evaluation_controls_failure(self):
        """Test failure when security controls fail."""
        scenarios = {"baseline": {"error_rate": 0.0, "latency_p95_ms": 1.0}}
        # Positive control failed (permitted traffic dropped)
        controls = {"positive_permitted": False, "negative_denied": True}
        res = compare.evaluate_thresholds(scenarios, controls, 0.01, 500.0)
        self.assertFalse(res["passed"])
        self.assertTrue(any("Positive permitted" in v for v in res["violations"]))

        # Negative control failed (denied traffic permitted)
        controls2 = {"positive_permitted": True, "negative_denied": False}
        res2 = compare.evaluate_thresholds(scenarios, controls2, 0.01, 500.0)
        self.assertFalse(res2["passed"])
        self.assertTrue(any("Negative denied" in v for v in res2["violations"]))


class TestCompareCLIAndReports(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.dir_path = self.test_dir.name
        self.results_dir = os.path.join(self.dir_path, "raw")
        os.makedirs(self.results_dir, exist_ok=True)

    def tearDown(self):
        self.test_dir.cleanup()

    def _write_json(self, path: str, data: dict) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def test_end_to_end_cli_pass(self):
        """Test complete CLI pipeline generating summary.json and summary.md."""
        # Create synthetic fixture runs
        self._write_json(os.path.join(self.results_dir, "baseline_r1.json"), make_valid_k6_dict(rate=3000.0, p95=2.0))
        self._write_json(os.path.join(self.results_dir, "baseline_r2.json"), make_valid_k6_dict(rate=3100.0, p95=1.9))

        for card in (10, 100, 500):
            self._write_json(
                os.path.join(self.results_dir, f"bfw_{card}_r1.json"),
                make_valid_k6_dict(rate=2800.0 - card * 0.5, p95=2.2),
            )
            self._write_json(
                os.path.join(self.results_dir, f"bfw_{card}_r2.json"),
                make_valid_k6_dict(rate=2820.0 - card * 0.5, p95=2.1),
            )
            self._write_json(
                os.path.join(self.results_dir, f"ufw_{card}_r1.json"),
                make_valid_k6_dict(rate=2500.0 - card * 1.2, p95=2.8),
            )
            self._write_json(
                os.path.join(self.results_dir, f"ufw_{card}_r2.json"),
                make_valid_k6_dict(rate=2520.0 - card * 1.2, p95=2.7),
            )

        apply_times = {
            "bfw": {"10": [0.01, 0.01], "100": [0.04, 0.04], "500": [0.15, 0.15]},
            "ufw": {"10": [0.15, 0.14], "100": [1.50, 1.45], "500": [8.20, 8.10]},
        }
        apply_path = os.path.join(self.results_dir, "apply_times.json")
        self._write_json(apply_path, apply_times)

        meta = {
            "metadata": {
                "kernel": "Linux 6.17",
                "arch": "x86_64",
                "bfw_version": "0.1.0",
                "ufw_version": "0.36.2",
                "k6_version": "2.3.0",
                "isolation": "Internal-only Docker network; separate k6 attacker and firewall server containers",
            },
            "controls": {"positive_permitted": True, "negative_denied": True},
        }
        meta_path = os.path.join(self.results_dir, "metadata.json")
        self._write_json(meta_path, meta)

        out_json = os.path.join(self.dir_path, "summary.json")
        out_md = os.path.join(self.dir_path, "summary.md")

        cmd = [
            sys.executable,
            os.path.join(PERF_DIR, "compare.py"),
            "--results-dir",
            self.results_dir,
            "--apply-times",
            apply_path,
            "--meta-file",
            meta_path,
            "--output-json",
            out_json,
            "--output-md",
            out_md,
            "--max-error-rate",
            "0.01",
            "--max-p95-latency-ms",
            "500.0",
        ]

        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc.returncode, 0, f"CLI failed unexpectedly: {proc.stderr}")

        self.assertTrue(os.path.isfile(out_json))
        self.assertTrue(os.path.isfile(out_md))

        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["status"], "PASSED")
        self.assertEqual(len(data["comparisons"]), 3)
        self.assertIn("baseline", data["scenarios"])
        self.assertIn("bfw_10", data["scenarios"])

        with open(out_md, "r", encoding="utf-8") as f:
            md_content = f.read()
        self.assertIn("# Firewall Performance Benchmark: `bfw` vs `ufw`", md_content)
        self.assertIn("OVERALL VERDICT", md_content.upper())
        self.assertIn("Traversed Traffic Performance", md_content)
        self.assertIn("Comparative Ratios", md_content)
        self.assertIn("CLI Rule Apply Timing", md_content)
        self.assertIn("Internal-only Docker network", md_content)
        self.assertIn("k6 Version | 2.3.0", md_content)

    def test_cli_fails_on_corrupt_k6_json(self):
        """Test CLI explicitly fails (exit code 1) on missing metrics in json."""
        bad_file = os.path.join(self.results_dir, "bfw_10_r1.json")
        self._write_json(bad_file, {"metrics": {}})  # missing http_reqs, http_req_duration, etc.

        cmd = [
            sys.executable,
            os.path.join(PERF_DIR, "compare.py"),
            "--results-dir",
            self.results_dir,
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Missing required metric", proc.stderr)


if __name__ == "__main__":
    unittest.main()
