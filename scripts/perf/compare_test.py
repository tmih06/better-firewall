#!/usr/bin/env python3
"""
Unit and fixture tests for scripts/perf/compare.py.
Uses pure synthetic fixtures; requires no network, no root, and no external dependencies.
Tests edge cases, missing metrics, zero metrics, threshold boundaries, profile
pairing, apply-time phase splits, and explicit failure paths.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

# Ensure scripts/perf is in Python path for direct imports
PERF_DIR = os.path.dirname(os.path.abspath(__file__))
if PERF_DIR not in sys.path:
    sys.path.insert(0, PERF_DIR)

import compare
import measure_resources


def make_valid_k6_dict(
    rate: float = 1250.5,
    count: int = 6250,
    p50: float = 1.25,
    p95: float = 3.50,
    p99: float = 7.80,
    avg: float = 1.45,
    error_rate: float = 0.0,
    check_rate: float = 1.0,
    vus_max: float = 10.0,
    received: int = 2_500_000,
    sent: int = 500_000,
    dropped_iterations: int = 0,
) -> dict:
    """Helper to produce a valid k6 machine summary dictionary."""
    fails = int(count * error_rate)
    check_fails = int(count * (1.0 - check_rate))
    return {
        "benchmark_resources": {
            "server": {
                "cpu_avg_pct": 12.5,
                "cpu_peak_pct": 25.0,
                "memory_avg_mib": 32.0,
                "memory_peak_mib": 40.0,
                "sample_count": 10,
            },
            "attacker": {
                "cpu_avg_pct": 5.0,
                "cpu_peak_pct": 10.0,
                "memory_avg_mib": 48.0,
                "memory_peak_mib": 50.0,
                "sample_count": 10,
            },
        },
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
                    "passes": fails,
                    "fails": count - fails,
                }
            },
            "checks": {
                "values": {
                    "rate": check_rate,
                    "passes": count - check_fails,
                    "fails": check_fails,
                }
            },
            "iterations": {"values": {"count": count, "rate": rate}},
            "vus": {"values": {"value": vus_max, "min": 1.0, "max": vus_max}},
            "vus_max": {"values": {"value": vus_max, "min": 1.0, "max": vus_max}},
            "data_received": {"values": {"count": received, "rate": received / 5.0}},
            "data_sent": {"values": {"count": sent, "rate": sent / 5.0}},
            "dropped_iterations": {"values": {"count": dropped_iterations}},
            "http_req_connecting": {"values": {"avg": 0.4, "min": 0.0, "max": 5.0}},
            "http_req_waiting": {"values": {"avg": 1.1, "min": 0.2, "max": 9.0}},
            "http_req_receiving": {"values": {"avg": 0.2, "min": 0.0, "max": 3.0}},
            "http_req_sending": {"values": {"avg": 0.05, "min": 0.0, "max": 1.0}},
        }
    }


def make_apply_times() -> dict:
    """New-style apply timings: per-phase lists of per-repeat samples."""
    data = {
        "bfw": {
            "10": {"rule_add_seconds": [0.01, 0.011, 0.0105], "enable_seconds": [0.002, 0.002, 0.002], "total_seconds": [0.012, 0.013, 0.0125]},
            "100": {"rule_add_seconds": [0.04, 0.042, 0.041], "enable_seconds": [0.003, 0.003, 0.003], "total_seconds": [0.043, 0.045, 0.044]},
            "500": {"rule_add_seconds": [0.15, 0.16, 0.155], "enable_seconds": [0.004, 0.004, 0.004], "total_seconds": [0.154, 0.164, 0.159]},
            "1000": {"rule_add_seconds": [0.30, 0.31, 0.305], "enable_seconds": [0.005, 0.005, 0.005], "total_seconds": [0.305, 0.315, 0.310]},
        },
        "ufw": {
            "10": {"rule_add_seconds": [0.14, 0.15, 0.145], "enable_seconds": [0.05, 0.05, 0.05], "total_seconds": [0.19, 0.20, 0.195]},
            "100": {"rule_add_seconds": [1.40, 1.50, 1.45], "enable_seconds": [0.08, 0.09, 0.085], "total_seconds": [1.48, 1.59, 1.535]},
            "500": {"rule_add_seconds": [8.0, 8.2, 8.1], "enable_seconds": [0.12, 0.13, 0.125], "total_seconds": [8.12, 8.33, 8.225]},
            "1000": {"rule_add_seconds": [16.0, 16.4, 16.2], "enable_seconds": [0.15, 0.15, 0.15], "total_seconds": [16.15, 16.55, 16.35]},
        },
    }
    for cards in data.values():
        for timing in cards.values():
            timing.update(
                {
                    "rule_add_cpu_seconds": [0.01, 0.02, 0.03],
                    "enable_cpu_seconds": [0.001, 0.002, 0.003],
                    "rule_add_peak_rss_kib": [4096, 8192, 6144],
                    "enable_peak_rss_kib": [6144, 8192, 7168],
                }
            )
    return data



class TestResourceSamples(unittest.TestCase):
    def test_parses_docker_cpu_and_memory_for_both_containers(self):
        containers = {"server": "aabbccddeeff0011", "attacker": "1122334455667788"}
        output = (
            "aabbccddeeff|25.0%|32MiB / 1GiB\n"
            "112233445566|5.5%|2.5MiB / 512MiB\n"
        )
        sample = measure_resources.parse_docker_stats(output, containers)
        self.assertEqual(sample["server"], {"cpu_pct": 25.0, "memory_mib": 32.0})
        self.assertEqual(sample["attacker"]["memory_mib"], 2.5)

    def test_aggregates_resource_samples_as_average_and_peak(self):
        samples = [
            {
                "server": {"cpu_pct": 10.0, "memory_mib": 32.0},
                "attacker": {"cpu_pct": 5.0, "memory_mib": 48.0},
            },
            {
                "server": {"cpu_pct": 30.0, "memory_mib": 64.0},
                "attacker": {"cpu_pct": 15.0, "memory_mib": 96.0},
            },
        ]
        summary = measure_resources.aggregate_samples(samples)
        self.assertEqual(summary["server"]["cpu_avg_pct"], 20.0)
        self.assertEqual(summary["server"]["cpu_peak_pct"], 30.0)
        self.assertEqual(summary["server"]["memory_avg_mib"], 48.0)
        self.assertEqual(summary["server"]["memory_peak_mib"], 64.0)
        self.assertEqual(summary["attacker"]["cpu_avg_pct"], 10.0)
        self.assertEqual(summary["attacker"]["memory_peak_mib"], 96.0)
        self.assertEqual(summary["server"]["sample_count"], 2)

    def test_rejects_missing_container_stats(self):
        containers = {"server": "aabbccddeeff0011", "attacker": "1122334455667788"}
        with self.assertRaisesRegex(ValueError, "omitted containers"):
            measure_resources.parse_docker_stats("aabbccddeeff|1.0%|1MiB / 1GiB\n", containers)

    def test_run_measured_adds_resources_to_k6_summary(self):
        containers = {"server": "aabbccddeeff0011", "attacker": "1122334455667788"}
        stats = subprocess.CompletedProcess(
            ["docker", "stats"],
            0,
            stdout="aabbccddeeff|10.0%|32MiB / 1GiB\n112233445566|5.0%|48MiB / 1GiB\n",
            stderr="",
        )
        process = mock.Mock()
        process.poll.side_effect = [None, 0]
        process.wait.return_value = 0

        with tempfile.TemporaryDirectory() as directory:
            summary_path = os.path.join(directory, "summary.json")
            with open(summary_path, "w", encoding="utf-8") as output:
                json.dump({"metrics": {"http_reqs": {"values": {"count": 1}}}}, output)

            with (
                mock.patch.object(measure_resources.subprocess, "Popen", return_value=process),
                mock.patch.object(measure_resources.subprocess, "run", return_value=stats) as stats_run,
                mock.patch.object(measure_resources.time, "sleep"),
            ):
                status = measure_resources.run_measured(["k6"], summary_path, containers, 0.01)

            with open(summary_path, "r", encoding="utf-8") as summary_file:
                summary = json.load(summary_file)

        self.assertEqual(status, 0)
        self.assertEqual(stats_run.call_count, 2)
        self.assertEqual(summary["metrics"]["http_reqs"]["values"]["count"], 1)
        self.assertEqual(summary["benchmark_resources"]["server"]["cpu_avg_pct"], 10.0)
        self.assertEqual(summary["benchmark_resources"]["attacker"]["memory_peak_mib"], 48.0)
        self.assertEqual(summary["benchmark_resources"]["server"]["sample_count"], 2)


class TestCompareEngine(unittest.TestCase):
    def test_parse_valid_k6_summary(self):
        """Test parsing valid k6 metrics dictionary including extended fields."""
        fixture = make_valid_k6_dict(
            error_rate=0.002, count=5000, check_rate=0.999, vus_max=50, dropped_iterations=5
        )
        parsed = compare.parse_k6_summary(fixture)
        self.assertAlmostEqual(parsed["throughput_rps"], 1250.5)
        self.assertEqual(parsed["request_count"], 5000)
        self.assertEqual(parsed["error_count"], 10)
        self.assertEqual(parsed["check_passes"], 4995)
        self.assertEqual(parsed["check_fails"], 5)
        self.assertAlmostEqual(parsed["latency_p50_ms"], 1.25)
        self.assertAlmostEqual(parsed["latency_p95_ms"], 3.50)
        self.assertAlmostEqual(parsed["latency_p99_ms"], 7.80)
        self.assertAlmostEqual(parsed["error_rate"], 0.002)
        self.assertAlmostEqual(parsed["check_rate"], 0.999)
        self.assertEqual(parsed["iterations"], 5000)
        self.assertEqual(parsed["vus_max"], 50)
        self.assertEqual(parsed["dropped_iterations"], 5)
        self.assertEqual(parsed["data_received_bytes"], 2_500_000)
        self.assertEqual(parsed["data_sent_bytes"], 500_000)
        self.assertAlmostEqual(parsed["connecting_avg_ms"], 0.4)
        self.assertAlmostEqual(parsed["waiting_avg_ms"], 1.1)
        self.assertEqual(parsed["resource_usage"]["server"]["cpu_avg_pct"], 12.5)

    def test_resource_usage_is_required(self):
        fixture = make_valid_k6_dict()
        del fixture["benchmark_resources"]
        with self.assertRaises(ValueError) as ctx:
            compare.parse_k6_summary(fixture)
        self.assertIn("Missing benchmark resource usage", str(ctx.exception))


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

    def test_missing_checks_metric_explicit_fail(self):
        """Test missing 'checks' metric raises explicit ValueError."""
        fixture = make_valid_k6_dict()
        del fixture["metrics"]["checks"]
        with self.assertRaises(ValueError) as ctx:
            compare.parse_k6_summary(fixture)
        self.assertIn("Missing required metric: 'checks'", str(ctx.exception))

    def test_missing_vus_or_bytes_metric_explicit_fail(self):
        """Test missing VU/data counters raises explicit ValueError."""
        for metric in ("vus", "vus_max", "data_received", "data_sent", "iterations"):
            fixture = make_valid_k6_dict()
            del fixture["metrics"][metric]
            with self.assertRaises(ValueError) as ctx:
                compare.parse_k6_summary(fixture)
            self.assertIn(f"Missing required metric: '{metric}'", str(ctx.exception))

    def test_zero_throughput_explicit_fail(self):
        """Test rate=0 or count=0 raises explicit ValueError."""
        fixture = make_valid_k6_dict(rate=0.0, count=0)
        with self.assertRaises(ValueError) as ctx:
            compare.parse_k6_summary(fixture)
        self.assertIn("Zero throughput or requests recorded", str(ctx.exception))

    def test_aggregate_repeats(self):
        """Test averaging rates and summing counters across repeats."""
        r1 = compare.parse_k6_summary(
            make_valid_k6_dict(
                rate=1000.0, p95=4.0, count=5000, error_rate=0.002, vus_max=20, dropped_iterations=3
            )
        )
        r2 = compare.parse_k6_summary(
            make_valid_k6_dict(
                rate=1200.0, p95=6.0, count=6000, error_rate=0.0, vus_max=50, dropped_iterations=7
            )
        )
        agg = compare.aggregate_repeats([r1, r2])
        self.assertAlmostEqual(agg["throughput_rps"], 1100.0)
        self.assertEqual(agg["request_count"], 11000)
        self.assertEqual(agg["error_count"], 10)
        self.assertAlmostEqual(agg["latency_p95_ms"], 5.0)
        self.assertEqual(agg["vus_max"], 50)
        self.assertEqual(agg["repeats"], 2)
        self.assertEqual(agg["dropped_iterations"], 10)

    def test_aggregate_empty_list_fail(self):
        """Test empty runs list raises ValueError."""
        with self.assertRaises(ValueError):
            compare.aggregate_repeats([])

    def test_scenario_filename_rejects_legacy_names(self):
        """Legacy 'bfw_10_r1.json' (no profile) must be rejected fail-closed."""
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "bfw_10_r1.json"), "w", encoding="utf-8") as f:
                json.dump(make_valid_k6_dict(), f)
            with self.assertRaises(ValueError) as ctx:
                compare.load_results_directory(d)
            self.assertIn("Unrecognized result filename", str(ctx.exception))

    def test_scenario_filename_rejects_arbitrary_json(self):
        """Stray JSON files must fail closed, not be silently skipped."""
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "baseline_0_keepalive_r1.json"), "w", encoding="utf-8") as f:
                json.dump(make_valid_k6_dict(), f)
            with open(os.path.join(d, "warmup.json"), "w", encoding="utf-8") as f:
                json.dump(make_valid_k6_dict(), f)
            with self.assertRaises(ValueError):
                compare.load_results_directory(d)

    def test_profile_pairing_isolated_per_profile(self):
        """A cardinality present only under one profile must not leak into
        another profile's comparison rows."""
        scenarios = {
            "baseline_0_keepalive": compare.aggregate_repeats(
                [compare.parse_k6_summary(make_valid_k6_dict(rate=3000.0))]
            ),
            "baseline_0_churn": compare.aggregate_repeats(
                [compare.parse_k6_summary(make_valid_k6_dict(rate=900.0))]
            ),
            "bfw_10_keepalive": compare.aggregate_repeats(
                [compare.parse_k6_summary(make_valid_k6_dict(rate=2800.0, p95=2.0, p50=1.0, p99=4.0))]
            ),
            "ufw_10_keepalive": compare.aggregate_repeats(
                [compare.parse_k6_summary(make_valid_k6_dict(rate=2500.0, p95=4.0, p50=2.0, p99=8.0))]
            ),
            # churn only has bfw data: the row must still appear, with no ratios.
            "bfw_10_churn": compare.aggregate_repeats(
                [compare.parse_k6_summary(make_valid_k6_dict(rate=850.0, p95=5.0))]
            ),
        }
        data = compare.compute_comparisons(scenarios)
        comps = {(c["profile"], c["cardinality"]): c for c in data["comparisons"]}
        self.assertIn(("keepalive", 10), comps)
        self.assertIn(("churn", 10), comps)

        keep = comps[("keepalive", 10)]
        self.assertAlmostEqual(keep["throughput_ratio_bfw_vs_ufw"], 2800.0 / 2500.0, places=3)
        self.assertAlmostEqual(keep["p95_latency_ratio_bfw_vs_ufw"], 2.0 / 4.0, places=3)
        # Overhead is measured against the keepalive baseline, not churn's.
        self.assertAlmostEqual(keep["bfw_overhead_pct"], round((3000.0 - 2800.0) / 3000.0 * 100, 2))
        self.assertAlmostEqual(keep["ufw_overhead_pct"], round((3000.0 - 2500.0) / 3000.0 * 100, 2))

        churn = comps[("churn", 10)]
        self.assertTrue(churn["bfw_available"])
        self.assertFalse(churn["ufw_available"])
        self.assertNotIn("throughput_ratio_bfw_vs_ufw", churn)
        # Churn overhead uses its own per-profile baseline of 900 req/s.
        self.assertAlmostEqual(churn["bfw_overhead_pct"], round((900.0 - 850.0) / 900.0 * 100, 2))

    def test_division_by_zero_safety(self):
        """Test safe handling when metrics or apply times are zero or missing."""
        scenarios = {
            "baseline_0_keepalive": {"throughput_rps": 0.0},
            "bfw_10_keepalive": {
                "throughput_rps": 1000.0,
                "latency_p50_ms": 1.0,
                "latency_p95_ms": 2.0,
                "latency_p99_ms": 3.0,
                "error_rate": 0.0,
                "request_count": 5000,
                "error_count": 0,
            },
            "ufw_10_keepalive": {
                "throughput_rps": 0.0,
                "latency_p50_ms": 0.0,
                "latency_p95_ms": 0.0,
                "latency_p99_ms": 0.0,
                "error_rate": 0.0,
                "request_count": 0,
                "error_count": 0,
            },
        }
        data = compare.compute_comparisons(scenarios)
        self.assertEqual(len(data["comparisons"]), 1)
        comp = data["comparisons"][0]
        # Should safely yield None instead of crashing with ZeroDivisionError
        self.assertIsNone(comp["throughput_ratio_bfw_vs_ufw"])
        self.assertIsNone(comp["p95_latency_ratio_bfw_vs_ufw"])
        self.assertIsNone(comp["bfw_overhead_pct"])

    def test_apply_times_phase_split(self):
        """Apply timings aggregate per phase and compute per-phase speedups."""
        apply_times = compare.load_apply_times_from_dict(make_apply_times())
        rows = compare.compute_timing_comparisons(apply_times)
        self.assertEqual(len(rows), 4)
        row10 = next(r for r in rows if r["cardinality"] == 10)
        # means: bfw add 0.0105, ufw add 0.145 -> speedup ~13.81
        self.assertAlmostEqual(row10["bfw_rule_add_s"], 0.0105, places=4)
        self.assertAlmostEqual(row10["ufw_rule_add_s"], 0.145, places=4)
        self.assertAlmostEqual(row10["rule_add_speedup"], round(0.145 / 0.0105, 2))
        self.assertAlmostEqual(row10["enable_speedup"], round(0.05 / 0.002, 2))
        self.assertEqual(row10["bfw_repeats"], 3)
        self.assertAlmostEqual(row10["bfw_rule_add_cpu_s"], 0.02)
        self.assertAlmostEqual(row10["bfw_enable_cpu_s"], 0.002)
        self.assertEqual(row10["bfw_rule_add_peak_rss_mib"], 8.0)
        self.assertEqual(row10["ufw_enable_peak_rss_mib"], 8.0)

    def test_apply_times_malformed_explicit_fail(self):
        """Malformed apply timing entries must raise ValueError."""
        for bad in (
            {"bfw": {"10": {"rule_add_seconds": [0.1]}}, "ufw": {}},  # missing phases
            {"bfw": {"10": []}, "ufw": {}},  # not an object
            {"iptables": {"10": {}}, "ufw": {}},  # unknown engine
        ):
            with self.assertRaises(ValueError):
                compare.load_apply_times_from_dict(bad)

    def test_threshold_evaluation_success(self):
        """Test evaluation when all constraints pass."""
        scenarios = {
            "baseline_0_keepalive": {"error_rate": 0.0, "check_rate": 1.0, "latency_p95_ms": 2.5},
            "bfw_10_keepalive": {"error_rate": 0.001, "check_rate": 1.0, "latency_p95_ms": 3.2},
            "ufw_10_keepalive": {"error_rate": 0.002, "check_rate": 0.999, "latency_p95_ms": 3.8},
        }
        controls = {"baseline_unfiltered": True, "positive_permitted": True, "negative_denied": True}
        res = compare.evaluate_thresholds(
            scenarios, controls, max_error_rate=0.01, max_p95_latency_ms=500.0
        )
        self.assertTrue(res["passed"])
        self.assertEqual(len(res["violations"]), 0)

    def test_threshold_evaluation_error_rate_failure(self):
        """Test failure when scenario exceeds max error rate."""
        scenarios = {
            "bfw_10_mixed": {"error_rate": 0.05, "check_rate": 1.0, "latency_p95_ms": 5.0},
        }
        controls = {"baseline_unfiltered": True, "positive_permitted": True, "negative_denied": True}
        res = compare.evaluate_thresholds(
            scenarios, controls, max_error_rate=0.01, max_p95_latency_ms=500.0
        )
        self.assertFalse(res["passed"])
        self.assertTrue(any("error rate" in v for v in res["violations"]))

    def test_threshold_evaluation_check_rate_failure(self):
        """Test failure when scenario check rate drops below the minimum."""
        scenarios = {
            "bfw_10_mixed": {"error_rate": 0.0, "check_rate": 0.95, "latency_p95_ms": 5.0},
        }
        controls = {"baseline_unfiltered": True, "positive_permitted": True, "negative_denied": True}
        res = compare.evaluate_thresholds(
            scenarios, controls, max_error_rate=0.01, max_p95_latency_ms=500.0, min_check_rate=0.99
        )
        self.assertFalse(res["passed"])
        self.assertTrue(any("check rate" in v for v in res["violations"]))

    def test_threshold_evaluation_latency_failure(self):
        """Test failure when scenario exceeds p95 latency threshold."""
        scenarios = {
            "bfw_10_keepalive": {"error_rate": 0.0, "check_rate": 1.0, "latency_p95_ms": 650.0},
        }
        controls = {"baseline_unfiltered": True, "positive_permitted": True, "negative_denied": True}
        res = compare.evaluate_thresholds(
            scenarios, controls, max_error_rate=0.01, max_p95_latency_ms=500.0
        )
        self.assertFalse(res["passed"])
        self.assertTrue(any("latency" in v for v in res["violations"]))

    def test_threshold_evaluation_dropped_iterations_failure(self):
        """A configured arrival rate must not silently lose iterations."""
        scenarios = {
            "bfw_10_churn": {
                "error_rate": 0.0,
                "check_rate": 1.0,
                "latency_p95_ms": 1.0,
                "dropped_iterations": 7,
            },
        }
        controls = {"baseline_unfiltered": True, "positive_permitted": True, "negative_denied": True}
        result = compare.evaluate_thresholds(scenarios, controls, max_error_rate=0.01, max_p95_latency_ms=500.0)
        self.assertFalse(result["passed"])
        self.assertTrue(any("dropped 7 iterations" in violation for violation in result["violations"]))

    def test_threshold_evaluation_controls_failure(self):
        """Test failure when security controls fail."""
        scenarios = {"baseline_0_keepalive": {"error_rate": 0.0, "check_rate": 1.0, "latency_p95_ms": 1.0}}
        # Positive control failed (permitted traffic dropped)
        controls = {"baseline_unfiltered": True, "positive_permitted": False, "negative_denied": True}
        res = compare.evaluate_thresholds(scenarios, controls, 0.01, 500.0)
        self.assertFalse(res["passed"])
        self.assertTrue(any("Positive permitted" in v for v in res["violations"]))

        # Negative control failed (denied traffic permitted)
        controls2 = {"baseline_unfiltered": True, "positive_permitted": True, "negative_denied": False}
        res2 = compare.evaluate_thresholds(scenarios, controls2, 0.01, 500.0)
        self.assertFalse(res2["passed"])
        self.assertTrue(any("Negative denied" in v for v in res2["violations"]))

        # Baseline unfiltered control failed
        controls3 = {"baseline_unfiltered": False, "positive_permitted": True, "negative_denied": True}
        res3 = compare.evaluate_thresholds(scenarios, controls3, 0.01, 500.0)
        self.assertFalse(res3["passed"])
        self.assertTrue(any("Baseline unfiltered" in v for v in res3["violations"]))


    def test_apply_rules_reports_child_cpu_and_peak_rss(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            bin_dir = os.path.join(temp_dir, "bin")
            os.makedirs(bin_dir)
            bfw_stub = os.path.join(bin_dir, "bfw")
            with open(bfw_stub, "w", encoding="utf-8") as stub:
                stub.write("#!/bin/sh\nexit 0\n")
            os.chmod(bfw_stub, 0o755)
            env = os.environ.copy()
            env["PATH"] = bin_dir + os.pathsep + env["PATH"]
            result = subprocess.run(
                [sys.executable, os.path.join(PERF_DIR, "apply_rules.py"), "bfw", "2", "8080"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        timing = json.loads(result.stdout)
        self.assertEqual(timing["engine"], "bfw")
        self.assertEqual(timing["rule_count"], 2)
        for phase in ("rule_add", "enable"):
            self.assertGreaterEqual(timing[f"{phase}_cpu_seconds"], 0.0)
            self.assertGreater(timing[f"{phase}_peak_rss_kib"], 0)

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

    def _write_scenario_set(self, profile: str, base_rate: float) -> None:
        """Write a full profile x cardinality x repeat fixture set."""
        for repeat in (1, 2, 3):
            self._write_json(
                os.path.join(self.results_dir, f"baseline_0_{profile}_r{repeat}.json"),
                make_valid_k6_dict(rate=base_rate, p95=2.0, count=12000),
            )
            for card in (10, 100, 500, 1000):
                self._write_json(
                    os.path.join(self.results_dir, f"bfw_{card}_{profile}_r{repeat}.json"),
                    make_valid_k6_dict(rate=base_rate - 200 - card * 0.1, p95=2.2, p50=1.2, p99=4.5, count=11000),
                )
                self._write_json(
                    os.path.join(self.results_dir, f"ufw_{card}_{profile}_r{repeat}.json"),
                    make_valid_k6_dict(rate=base_rate - 500 - card * 0.4, p95=2.8, p50=1.8, p99=5.5, count=10000),
                )

    def test_end_to_end_cli_pass(self):
        """Test complete CLI pipeline generating summary.json and summary.md."""
        for profile, rate in (("keepalive", 3000.0), ("churn", 1200.0), ("mixed", 1500.0)):
            self._write_scenario_set(profile, rate)


        apply_path = os.path.join(self.results_dir, "apply_times.json")
        self._write_json(apply_path, make_apply_times())

        meta = {
            "metadata": {
                "kernel": "Linux 6.17",
                "arch": "x86_64",
                "bfw_version": "0.1.0",
                "ufw_version": "0.36.2",
                "k6_version": "2.3.0",
                "vus": "10",
                "peak_vus": "50",
                "churn_rps": "200",
                "profiles": "keepalive churn mixed",
                "cardinalities": "10 100 500 1000",
                "repeats": "3",
                "isolation": "Internal-only Docker network; separate k6 attacker and firewall server containers",
                "bfw_binary_size_bytes": 1234567,
                "ufw_launcher_size_bytes": 512,
                "ufw_launcher_path": "/usr/sbin/ufw",
                "ufw_package_installed_kib": 2048,
                "resource_sample_interval_seconds": 1.0,
            },
            "controls": {
                "baseline_unfiltered": True,
                "positive_permitted": True,
                "negative_denied": True,
                "benchmark_rulesets_verified": 24,
            },
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
        self.assertEqual(proc.returncode, 0, f"CLI failed unexpectedly: {proc.stderr}\n{proc.stdout}")

        self.assertTrue(os.path.isfile(out_json))
        self.assertTrue(os.path.isfile(out_md))

        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["status"], "PASSED")
        # 3 profiles x 4 cardinalities = 12 comparison rows
        self.assertEqual(len(data["comparisons"]), 12)
        self.assertIn("baseline_0_keepalive", data["scenarios"])
        self.assertIn("bfw_10_mixed", data["scenarios"])
        self.assertIn("ufw_1000_churn", data["scenarios"])
        # 3 repeats aggregated per scenario
        self.assertEqual(data["scenarios"]["bfw_10_keepalive"]["repeats"], 3)
        self.assertEqual(data["scenarios"]["bfw_10_keepalive"]["request_count"], 33000)
        self.assertEqual(data["scenarios"]["bfw_10_keepalive"]["resource_usage"]["server"]["sample_count"], 30)
        self.assertEqual(data["scenarios"]["bfw_10_keepalive"]["resource_usage"]["server"]["cpu_avg_pct"], 12.5)
        self.assertEqual(data["scenarios"]["bfw_10_churn"]["dropped_iterations"], 0)
        # Per-profile rollups exist for both engines
        self.assertEqual(len(data["profiles"]), 6)
        keep_bfw = next(p for p in data["profiles"] if p["profile"] == "keepalive" and p["engine"] == "bfw")
        self.assertEqual(keep_bfw["cardinalities"], [10, 100, 500, 1000])
        self.assertEqual(keep_bfw["total_requests"], 132000)
        # Split-phase timing rows for all four cardinalities
        self.assertEqual(len(data["timing_comparisons"]), 4)
        t_row = next(r for r in data["timing_comparisons"] if r["cardinality"] == 1000)
        self.assertGreater(t_row["rule_add_speedup"], 1.0)
        self.assertIsNotNone(t_row["bfw_enable_s"])
        self.assertIsNotNone(t_row["ufw_enable_s"])
        self.assertAlmostEqual(t_row["bfw_rule_add_cpu_s"], 0.02)
        self.assertAlmostEqual(t_row["bfw_rule_add_peak_rss_mib"], 8.0)
        # Ratios are per-profile, using the matching baseline
        comp = next(c for c in data["comparisons"] if c["profile"] == "churn" and c["cardinality"] == 10)
        self.assertAlmostEqual(
            comp["throughput_ratio_bfw_vs_ufw"],
            round((1200.0 - 200 - 1.0) / (1200.0 - 500 - 4.0), 3),
        )

        with open(out_md, "r", encoding="utf-8") as f:
            md_content = f.read()
        self.assertIn("# Firewall Performance Benchmark: `bfw` vs `ufw`", md_content)
        self.assertIn("OVERALL VERDICT", md_content.upper())
        self.assertIn("Traversed Traffic Performance", md_content)
        self.assertIn("Dropped It.", md_content)
        self.assertIn("Comparative Ratios", md_content)
        self.assertIn("CLI Rule Timing", md_content)
        self.assertIn("Executable & Package Footprint", md_content)
        self.assertIn("Container Resource Usage", md_content)
        self.assertIn("CLI Process Resource Usage", md_content)
        self.assertIn("1234567 bytes", md_content)
        self.assertIn("/usr/sbin/ufw", md_content)
        self.assertIn("2048 KiB", md_content)
        self.assertIn(
            "| keepalive | **bfw** | 10 | Server / defender | 12.50 | 25.00 | 32.00 | 40.00 | 30 |",
            md_content,
        )
        self.assertIn("keepalive", md_content)
        self.assertIn("churn", md_content)
        self.assertIn("mixed", md_content)
        self.assertIn("Internal-only Docker network", md_content)
        self.assertIn("k6 Version | 2.3.0", md_content)
        self.assertIn("Mixed Peak Concurrency", md_content)
        self.assertIn("Fixed-VU Profile Duration", md_content)
        self.assertIn("Fresh-Connection Target Rate", md_content)

    def test_cli_fails_on_corrupt_k6_json(self):
        """Test CLI explicitly fails (exit code 1) on missing metrics in json."""
        bad_file = os.path.join(self.results_dir, "bfw_10_keepalive_r1.json")
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


    def test_cli_fails_when_scenario_repeat_is_missing(self):
        """A comparison cannot pass when one firewall has fewer repeats."""
        for repeat in (1, 2):
            self._write_json(
                os.path.join(self.results_dir, f"baseline_0_keepalive_r{repeat}.json"),
                make_valid_k6_dict(rate=3000.0),
            )
            self._write_json(
                os.path.join(self.results_dir, f"bfw_10_keepalive_r{repeat}.json"),
                make_valid_k6_dict(rate=2800.0),
            )
        self._write_json(
            os.path.join(self.results_dir, "ufw_10_keepalive_r1.json"),
            make_valid_k6_dict(rate=2500.0),
        )

        timings = {
            engine: {
                "10": {
                    "rule_add_seconds": [0.1, 0.1],
                    "enable_seconds": [0.01, 0.01],
                    "total_seconds": [0.11, 0.11],
                    "rule_add_cpu_seconds": [0.02, 0.02],
                    "enable_cpu_seconds": [0.002, 0.002],
                    "rule_add_peak_rss_kib": [8192, 8192],
                    "enable_peak_rss_kib": [8192, 8192],
                }
            }
            for engine in ("bfw", "ufw")
        }
        apply_path = os.path.join(self.results_dir, "apply_times.json")
        self._write_json(apply_path, timings)
        meta_path = os.path.join(self.results_dir, "metadata.json")
        self._write_json(
            meta_path,
            {
                "metadata": {"profiles": "keepalive", "cardinalities": "10", "repeats": "2"},
                "controls": {
                    "baseline_unfiltered": True,
                    "positive_permitted": True,
                    "negative_denied": True,
                    "benchmark_rulesets_verified": 4,
                },
            },
        )

        proc = subprocess.run(
            [
                sys.executable,
                os.path.join(PERF_DIR, "compare.py"),
                "--results-dir",
                self.results_dir,
                "--apply-times",
                apply_path,
                "--meta-file",
                meta_path,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Incomplete benchmark matrix", proc.stdout)
        self.assertIn("ufw_10_keepalive", proc.stdout)

    def test_cli_fails_on_malformed_apply_times(self):
        """CLI must exit non-zero when apply_times.json is malformed."""
        self._write_json(
            os.path.join(self.results_dir, "baseline_0_keepalive_r1.json"),
            make_valid_k6_dict(rate=3000.0),
        )
        apply_path = os.path.join(self.results_dir, "apply_times.json")
        self._write_json(apply_path, {"bfw": {"10": {"rule_add_seconds": [0.1]}}, "ufw": {}})

        cmd = [
            sys.executable,
            os.path.join(PERF_DIR, "compare.py"),
            "--results-dir",
            self.results_dir,
            "--apply-times",
            apply_path,
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Invalid apply times", proc.stderr)


if __name__ == "__main__":
    unittest.main()
