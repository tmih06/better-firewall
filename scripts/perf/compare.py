#!/usr/bin/env python3
"""
Performance comparison engine for bfw vs ufw.
Parses raw k6 machine summaries and CLI apply timings, verifies security controls,
calculates comparative performance ratios per traffic profile and rule
cardinality, and outputs Markdown + JSON reports.

Raw result filenames follow `{engine}_{rules}_{profile}_r{repeat}.json`
(e.g. `bfw_500_keepalive_r1.json`); baseline runs use `baseline_0_<profile>`.
Any other *.json file in the results directory is rejected (fail-closed).
"""

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

ENGINES = ("bfw", "ufw")
# Preferred report ordering for known profiles; unknown profiles sort last
# alphabetically so forward-compatible raw files still render.
PROFILE_ORDER = {"keepalive": 0, "churn": 1, "mixed": 2}

SCENARIO_FILENAME = re.compile(r"^(baseline|bfw|ufw)_(\d+)_([a-z0-9]+)_r(\d+)$")
IGNORED_FILES = {"apply_times.json", "metadata.json", "manifest.json"}


def _profile_sort_key(profile: str) -> Tuple[int, str]:
    return (PROFILE_ORDER.get(profile, len(PROFILE_ORDER)), profile)


def split_scenario_key(scenario: str) -> Tuple[str, str, str]:
    """Split '<engine>_<rules>_<profile>' into its three parts."""
    engine, card_text, profile = scenario.split("_", 2)
    return engine, card_text, profile


def _scenario_sort_key(scenario: str) -> Tuple[Tuple[int, str], int, int]:
    engine, card_text, profile = split_scenario_key(scenario)
    engine_order = {"baseline": 0, "bfw": 1, "ufw": 2}.get(engine, 3)
    return (_profile_sort_key(profile), engine_order, int(card_text))


def _values(metrics: Dict[str, Any], name: str) -> Dict[str, Any]:
    metric = metrics.get(name)
    if not isinstance(metric, dict) or not isinstance(metric.get("values"), dict):
        raise ValueError(f"Missing required metric: '{name}'")
    return metric["values"]


def _avg(values: Dict[str, Any]) -> Optional[float]:
    avg = values.get("avg")
    return float(avg) if avg is not None else None


def parse_k6_summary(data_or_path: Any) -> Dict[str, Any]:
    """
    Parse a k6 summary JSON object or file.
    Validates structure and raises explicit ValueError on missing or zero metrics.
    """
    if isinstance(data_or_path, (str, bytes, os.PathLike)):
        with open(data_or_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif isinstance(data_or_path, dict):
        data = data_or_path
    else:
        raise TypeError(f"Expected dict or file path, got {type(data_or_path)}")

    if not isinstance(data, dict):
        raise ValueError("Invalid k6 summary: root must be a JSON object")

    metrics = data.get("metrics")
    if not isinstance(metrics, dict):
        raise ValueError("Invalid k6 summary: missing 'metrics' object")

    # 1. http_reqs (throughput and request count)
    reqs_values = _values(metrics, "http_reqs")
    rate = reqs_values.get("rate")
    count = reqs_values.get("count")
    if rate is None or count is None:
        raise ValueError("Metric 'http_reqs' missing 'rate' or 'count'")
    if count <= 0 or rate <= 0:
        raise ValueError(f"Zero throughput or requests recorded (count={count}, rate={rate})")

    # 2. http_req_duration (latencies). firewall.js pins summaryTrendStats so
    #    p(50) and p(99) are present alongside p(95).
    dur_values = _values(metrics, "http_req_duration")
    p50 = dur_values.get("p(50)")
    p95 = dur_values.get("p(95)")
    p99 = dur_values.get("p(99)")
    if p50 is None or p95 is None or p99 is None:
        raise ValueError("Missing latency percentiles: 'p(50)', 'p(95)', or 'p(99)' in http_req_duration")

    # 3. http_req_failed (error rate; 'passes' counts the failed requests)
    failed_values = _values(metrics, "http_req_failed")
    error_rate = failed_values.get("rate")
    if error_rate is None:
        raise ValueError("Metric 'http_req_failed' missing 'rate'")
    error_count = failed_values.get("passes")
    if error_count is None:
        error_count = int(round(float(error_rate) * int(count)))

    # 4. checks (validation pass rate and counts)
    check_values = _values(metrics, "checks")
    check_rate = check_values.get("rate")
    if check_rate is None:
        raise ValueError("Metric 'checks' missing 'rate'")

    # 5. iterations, concurrency, and transferred bytes
    iteration_values = _values(metrics, "iterations")
    vus_values = _values(metrics, "vus")
    vus_max_values = _values(metrics, "vus_max")
    received_values = _values(metrics, "data_received")
    sent_values = _values(metrics, "data_sent")

    # Optional sub-timings and dropped iterations (not emitted on every run).
    def optional_avg(name: str) -> Optional[float]:
        metric = metrics.get(name)
        if not isinstance(metric, dict) or not isinstance(metric.get("values"), dict):
            return None
        return _avg(metric["values"])

    dropped = metrics.get("dropped_iterations")
    dropped_count = 0
    if isinstance(dropped, dict) and isinstance(dropped.get("values"), dict):
        dropped_count = int(dropped["values"].get("count") or 0)

    return {
        "throughput_rps": float(rate),
        "request_count": int(count),
        "error_rate": float(error_rate),
        "error_count": int(error_count),
        "check_rate": float(check_rate),
        "check_passes": int(check_values.get("passes") or 0),
        "check_fails": int(check_values.get("fails") or 0),
        "iterations": int(iteration_values.get("count") or 0),
        "dropped_iterations": dropped_count,
        "vus": float(vus_values.get("value") or 0.0),
        "vus_max": float(vus_max_values.get("value") or 0.0),
        "data_received_bytes": int(received_values.get("count") or 0),
        "data_sent_bytes": int(sent_values.get("count") or 0),
        "latency_avg_ms": float(dur_values.get("avg") or 0.0),
        "latency_p50_ms": float(p50),
        "latency_p95_ms": float(p95),
        "latency_p99_ms": float(p99),
        "connecting_avg_ms": optional_avg("http_req_connecting"),
        "blocked_avg_ms": optional_avg("http_req_blocked"),
        "waiting_avg_ms": optional_avg("http_req_waiting"),
        "receiving_avg_ms": optional_avg("http_req_receiving"),
        "sending_avg_ms": optional_avg("http_req_sending"),
    }


def _mean(runs: List[Dict[str, Any]], key: str, digits: int) -> Optional[float]:
    values = [r[key] for r in runs if r.get(key) is not None]
    if not values:
        return None
    return round(sum(values) / len(values), digits)


def _total(runs: List[Dict[str, Any]], key: str) -> int:
    return sum(int(r.get(key) or 0) for r in runs)


def aggregate_repeats(runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate multiple repeat runs for a single scenario.

    Rates and latencies are mean-averaged; counters are summed; concurrency
    peaks take the maximum observed value.
    """
    if not runs:
        raise ValueError("Cannot aggregate empty list of runs")

    n = len(runs)
    return {
        "throughput_rps": round(sum(r["throughput_rps"] for r in runs) / n, 2),
        "request_count": _total(runs, "request_count"),
        "error_rate": round(sum(r["error_rate"] for r in runs) / n, 5),
        "error_count": _total(runs, "error_count"),
        "check_rate": round(sum(r["check_rate"] for r in runs) / n, 5),
        "check_passes": _total(runs, "check_passes"),
        "check_fails": _total(runs, "check_fails"),
        "iterations": _total(runs, "iterations"),
        "dropped_iterations": _total(runs, "dropped_iterations"),
        "vus": _mean(runs, "vus", 1),
        "vus_max": max(r["vus_max"] for r in runs),
        "data_received_bytes": _total(runs, "data_received_bytes"),
        "data_sent_bytes": _total(runs, "data_sent_bytes"),
        "latency_avg_ms": _mean(runs, "latency_avg_ms", 3),
        "latency_p50_ms": _mean(runs, "latency_p50_ms", 3),
        "latency_p95_ms": _mean(runs, "latency_p95_ms", 3),
        "latency_p99_ms": _mean(runs, "latency_p99_ms", 3),
        "connecting_avg_ms": _mean(runs, "connecting_avg_ms", 3),
        "blocked_avg_ms": _mean(runs, "blocked_avg_ms", 3),
        "waiting_avg_ms": _mean(runs, "waiting_avg_ms", 3),
        "receiving_avg_ms": _mean(runs, "receiving_avg_ms", 3),
        "sending_avg_ms": _mean(runs, "sending_avg_ms", 3),
        "repeats": n,
    }


def load_results_directory(results_dir: str) -> Dict[str, Any]:
    """
    Scan results directory for k6 JSON outputs and aggregate scenarios.

    Every *.json file must match '{engine}_{rules}_{profile}_r{repeat}.json'
    (baseline uses rules=0). Unrecognized names are rejected outright so
    malformed or legacy artifacts fail closed instead of being silently
    folded into a report.
    """
    if not os.path.isdir(results_dir):
        raise FileNotFoundError(f"Results directory not found: {results_dir}")

    scenario_runs: Dict[str, Dict[int, Dict[str, Any]]] = {}

    for filename in sorted(os.listdir(results_dir)):
        if not filename.endswith(".json") or filename in IGNORED_FILES:
            continue

        stem = filename[: -len(".json")]
        m = SCENARIO_FILENAME.match(stem)
        if not m:
            raise ValueError(
                f"Unrecognized result filename '{filename}': expected "
                "{engine}_{rules}_{profile}_r{repeat}.json"
            )

        engine, card_text, profile, repeat_text = m.groups()
        scenario_key = f"{engine}_{int(card_text)}_{profile}"
        repeat_index = int(repeat_text)

        filepath = os.path.join(results_dir, filename)
        parsed = parse_k6_summary(filepath)

        repeats = scenario_runs.setdefault(scenario_key, {})
        if repeat_index in repeats:
            raise ValueError(f"Duplicate repeat r{repeat_index} for scenario '{scenario_key}'")
        repeats[repeat_index] = parsed

    if not scenario_runs:
        raise ValueError(f"No valid k6 summary files found in {results_dir}")

    aggregated: Dict[str, Any] = {}
    for scenario_key, repeats in scenario_runs.items():
        repeat_numbers = sorted(repeats)
        if repeat_numbers != list(range(1, len(repeat_numbers) + 1)):
            raise ValueError(f"Non-contiguous repeat numbers for scenario '{scenario_key}': {repeat_numbers}")
        runs = [repeats[repeat] for repeat in repeat_numbers]
        aggregated[scenario_key] = aggregate_repeats(runs)

    return aggregated


def load_apply_times_from_dict(data: Dict[str, Any]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """
    Validate CLI apply timings and attach per-phase means.

    Expected shape (one timing list per repeat):
      {"bfw": {"500": {"rule_add_seconds": [..], "enable_seconds": [..],
                       "total_seconds": [..]}}, "ufw": {...}}

    Returns {engine: {cardinality: {"rule_add_seconds": [...], ...,
             "rule_add_mean_s": float, "enable_mean_s": float,
             "total_mean_s": float, "repeats": int}}}.
    Malformed entries raise ValueError (fail-closed).
    """
    if not isinstance(data, dict):
        raise ValueError("Invalid apply times file: root must be a JSON object")

    result: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for engine, cards in data.items():
        if engine not in ENGINES:
            raise ValueError(f"Invalid apply times file: unknown engine '{engine}'")
        if not isinstance(cards, dict):
            raise ValueError(f"Invalid apply times file: '{engine}' must map to cardinalities")

        engine_entry: Dict[str, Dict[str, Any]] = {}
        for card_text, timing in cards.items():
            if not str(card_text).isdigit():
                raise ValueError(f"Invalid apply times file: '{engine}' key '{card_text}' is not a rule count")
            if not isinstance(timing, dict):
                raise ValueError(f"Invalid apply times for {engine}/{card_text}: expected object of lists")

            entry: Dict[str, Any] = {}
            for phase in ("rule_add_seconds", "enable_seconds", "total_seconds"):
                samples = timing.get(phase)
                if not isinstance(samples, list) or not samples:
                    raise ValueError(
                        f"Invalid apply times for {engine}/{card_text}: missing or empty '{phase}' list"
                    )
                try:
                    entry[phase] = [float(sample) for sample in samples]
                except (TypeError, ValueError) as exc:
                    raise ValueError(
                        f"Invalid apply times for {engine}/{card_text}: non-numeric '{phase}' sample"
                    ) from exc

            sample_counts = {len(entry[phase]) for phase in ("rule_add_seconds", "enable_seconds", "total_seconds")}
            if len(sample_counts) != 1:
                raise ValueError(f"Invalid apply times for {engine}/{card_text}: phase sample counts differ")

            repeats = len(entry["total_seconds"])
            entry["rule_add_mean_s"] = round(sum(entry["rule_add_seconds"]) / repeats, 4)
            entry["enable_mean_s"] = round(sum(entry["enable_seconds"]) / repeats, 4)
            entry["total_mean_s"] = round(sum(entry["total_seconds"]) / repeats, 4)
            entry["repeats"] = repeats
            engine_entry[str(int(card_text))] = entry

        result[engine] = engine_entry

    return result


def load_apply_times(apply_times_path: Optional[str]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """Load CLI apply timings JSON from disk. An omitted path means timings
    were not requested; a specified but missing file is malformed input."""
    if not apply_times_path:
        return {}
    if not os.path.isfile(apply_times_path):
        raise FileNotFoundError(f"Apply times file not found: {apply_times_path}")

    with open(apply_times_path, "r", encoding="utf-8") as f:
        return load_apply_times_from_dict(json.load(f))


def validate_complete_matrix(
    scenarios: Dict[str, Any],
    metadata: Dict[str, Any],
    controls: Dict[str, Any],
    apply_times: Dict[str, Dict[str, Dict[str, Any]]],
    require_apply_times: bool,
) -> List[str]:
    """Return violations for missing or inconsistent expected benchmark inputs."""
    violations: List[str] = []

    def tokens(name: str) -> List[str]:
        value = metadata.get(name)
        if isinstance(value, str):
            return value.split()
        if isinstance(value, list):
            return [str(item) for item in value]
        return []

    profiles = tokens("profiles")
    card_tokens = tokens("cardinalities")
    try:
        cardinalities = [int(value) for value in card_tokens]
        repeats = int(metadata.get("repeats", 0))
    except (TypeError, ValueError):
        cardinalities = []
        repeats = 0

    if (
        not profiles
        or any(re.fullmatch(r"[a-z0-9]+", profile) is None for profile in profiles)
        or len(set(profiles)) != len(profiles)
        or not cardinalities
        or any(card <= 0 for card in cardinalities)
        or len(set(cardinalities)) != len(cardinalities)
        or repeats <= 0
    ):
        return [
            "Incomplete benchmark matrix: metadata must list unique profiles, positive rule counts, and repeats"
        ]

    expected = {f"baseline_0_{profile}" for profile in profiles}
    for profile in profiles:
        for card in cardinalities:
            expected.update(f"{engine}_{card}_{profile}" for engine in ENGINES)

    for key in sorted(expected - scenarios.keys()):
        violations.append(f"Incomplete benchmark matrix: missing scenario '{key}'")
    for key in sorted(scenarios.keys() - expected):
        violations.append(f"Incomplete benchmark matrix: unexpected scenario '{key}'")
    for key in sorted(expected & scenarios.keys()):
        actual_repeats = scenarios[key].get("repeats")
        if actual_repeats != repeats:
            violations.append(
                f"Incomplete benchmark matrix: scenario '{key}' has {actual_repeats} repeats; expected {repeats}"
            )

    expected_rule_checks = len(cardinalities) * len(ENGINES) * repeats
    actual_rule_checks = controls.get("benchmark_rulesets_verified")
    if type(actual_rule_checks) is not int or actual_rule_checks != expected_rule_checks:
        violations.append(
            f"Incomplete benchmark matrix: verified {actual_rule_checks!r} rulesets; expected {expected_rule_checks}"
        )

    for name in ("baseline_unfiltered", "positive_permitted", "negative_denied"):
        if type(controls.get(name)) is not bool:
            violations.append(f"Incomplete benchmark controls: missing boolean '{name}' result")

    if require_apply_times:
        for engine in ENGINES:
            for card in cardinalities:
                entry = apply_times.get(engine, {}).get(str(card))
                if entry is None:
                    violations.append(f"Incomplete apply timings: missing {engine}/{card}")
                elif entry.get("repeats") != repeats:
                    violations.append(
                        f"Incomplete apply timings: {engine}/{card} has {entry.get('repeats')} repeats; expected {repeats}"
                    )

    return violations


def _ratio(numerator: Optional[float], denominator: Optional[float], digits: int = 3) -> Optional[float]:
    if numerator is None or denominator is None or denominator <= 0:
        return None
    return round(numerator / denominator, digits)


def _overhead_pct(throughput: Optional[float], baseline_rps: float) -> Optional[float]:
    if throughput is None or baseline_rps <= 0:
        return None
    return round(((baseline_rps - throughput) / baseline_rps) * 100, 2)


def _ordered_profiles(scenarios: Dict[str, Any]) -> List[str]:
    profiles = {split_scenario_key(key)[2] for key in scenarios}
    return sorted(profiles, key=_profile_sort_key)


def compute_comparisons(scenarios: Dict[str, Any]) -> Dict[str, Any]:
    """Compute bfw-vs-ufw ratios per traffic profile and rule cardinality.

    Returns {"comparisons": [...], "profiles": [...]} where each comparison
    row covers one (profile, cardinality) pair and each profile row carries
    pooled bfw/ufw totals plus their aggregate ratios.
    """
    comparisons: List[Dict[str, Any]] = []
    profile_rows: List[Dict[str, Any]] = []

    for profile in _ordered_profiles(scenarios):
        baseline_key = f"baseline_0_{profile}"
        baseline = scenarios.get(baseline_key)
        baseline_rps = baseline["throughput_rps"] if baseline else 0.0

        cardinalities = sorted(
            {
                int(split_scenario_key(key)[1])
                for key in scenarios
                if split_scenario_key(key)[0] in ENGINES and split_scenario_key(key)[2] == profile
            }
        )

        profile_pool: Dict[str, Dict[str, float]] = {engine: {"requests": 0, "errors": 0, "throughputs": []} for engine in ENGINES}

        for card in cardinalities:
            bfw = scenarios.get(f"bfw_{card}_{profile}")
            ufw = scenarios.get(f"ufw_{card}_{profile}")

            comp: Dict[str, Any] = {
                "profile": profile,
                "cardinality": card,
                "baseline_scenario": baseline_key if baseline else None,
                "bfw_available": bfw is not None,
                "ufw_available": ufw is not None,
            }

            for engine, agg in (("bfw", bfw), ("ufw", ufw)):
                if agg:
                    pool = profile_pool[engine]
                    pool["requests"] += agg["request_count"]
                    pool["errors"] += agg["error_count"]
                    pool["throughputs"].append(agg["throughput_rps"])

            if bfw and ufw:
                comp["throughput_ratio_bfw_vs_ufw"] = _ratio(bfw["throughput_rps"], ufw["throughput_rps"])
                comp["p50_latency_ratio_bfw_vs_ufw"] = _ratio(bfw["latency_p50_ms"], ufw["latency_p50_ms"])
                comp["p95_latency_ratio_bfw_vs_ufw"] = _ratio(bfw["latency_p95_ms"], ufw["latency_p95_ms"])
                comp["p99_latency_ratio_bfw_vs_ufw"] = _ratio(bfw["latency_p99_ms"], ufw["latency_p99_ms"])

            comp["bfw_overhead_pct"] = _overhead_pct(bfw["throughput_rps"] if bfw else None, baseline_rps)
            comp["ufw_overhead_pct"] = _overhead_pct(ufw["throughput_rps"] if ufw else None, baseline_rps)

            comparisons.append(comp)

        for engine in ENGINES:
            pool = profile_pool[engine]
            engine_scenarios = [
                scenarios[f"{engine}_{card}_{profile}"] for card in cardinalities if f"{engine}_{card}_{profile}" in scenarios
            ]
            profile_rows.append(
                {
                    "profile": profile,
                    "engine": engine,
                    "cardinalities": cardinalities if engine_scenarios else [],
                    "total_requests": pool["requests"],
                    "total_errors": pool["errors"],
                    "pooled_error_rate": round(pool["errors"] / pool["requests"], 5) if pool["requests"] else None,
                    "mean_throughput_rps": round(sum(pool["throughputs"]) / len(pool["throughputs"]), 2)
                    if pool["throughputs"]
                    else None,
                    "mean_latency_p95_ms": round(
                        sum(s["latency_p95_ms"] for s in engine_scenarios) / len(engine_scenarios), 3
                    )
                    if engine_scenarios
                    else None,
                }
            )

    return {"comparisons": comparisons, "profiles": profile_rows}


def compute_timing_comparisons(
    apply_times: Dict[str, Dict[str, Dict[str, Any]]]
) -> List[Dict[str, Any]]:
    """Pair bfw/ufw apply timings per cardinality with per-phase speedups."""
    rows: List[Dict[str, Any]] = []
    cardinalities = sorted(
        {int(card) for engine in ENGINES for card in apply_times.get(engine, {})}
    )

    for card in cardinalities:
        bfw_entry = apply_times.get("bfw", {}).get(str(card))
        ufw_entry = apply_times.get("ufw", {}).get(str(card))

        row: Dict[str, Any] = {"cardinality": card}
        for engine, entry in (("bfw", bfw_entry), ("ufw", ufw_entry)):
            row[f"{engine}_rule_add_s"] = entry["rule_add_mean_s"] if entry else None
            row[f"{engine}_enable_s"] = entry["enable_mean_s"] if entry else None
            row[f"{engine}_total_s"] = entry["total_mean_s"] if entry else None
            row[f"{engine}_repeats"] = entry["repeats"] if entry else 0

        row["rule_add_speedup"] = (
            _ratio(ufw_entry["rule_add_mean_s"], bfw_entry["rule_add_mean_s"], 2) if bfw_entry and ufw_entry else None
        )
        row["enable_speedup"] = (
            _ratio(ufw_entry["enable_mean_s"], bfw_entry["enable_mean_s"], 2) if bfw_entry and ufw_entry else None
        )
        row["total_speedup"] = (
            _ratio(ufw_entry["total_mean_s"], bfw_entry["total_mean_s"], 2) if bfw_entry and ufw_entry else None
        )
        rows.append(row)

    return rows


def evaluate_thresholds(
    scenarios: Dict[str, Any],
    controls: Dict[str, Any],
    max_error_rate: float,
    max_p95_latency_ms: float,
    min_check_rate: float = 0.99,
    input_violations: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Evaluate hard correctness and latency thresholds.
    Performance ratios are informational because hosted runner noise makes
    them unsuitable as quality gates.
    """
    violations: List[str] = list(input_violations or [])
    # 1. Security controls check
    if not controls.get("baseline_unfiltered", False):
        violations.append("Security Control Failure: Baseline unfiltered reachability test failed")
    if not controls.get("positive_permitted", False):
        violations.append("Security Control Failure: Positive permitted traffic test failed (traffic was blocked)")
    if not controls.get("negative_denied", False):
        violations.append("Security Control Failure: Negative denied traffic test failed (denied traffic leaked through)")

    # 2. Correctness and latency per scenario
    for scenario_name in sorted(scenarios, key=_scenario_sort_key):
        metrics = scenarios[scenario_name]
        dropped = metrics.get("dropped_iterations", 0)
        if dropped > 0:
            violations.append(
                f"Load Threshold: Scenario '{scenario_name}' dropped {dropped} iterations at the configured arrival rate"
            )
        err = metrics.get("error_rate", 0.0)
        if err > max_error_rate:
            violations.append(
                f"Correctness Threshold: Scenario '{scenario_name}' error rate {err:.4f} > {max_error_rate:.4f}"
            )

        check_rate = metrics.get("check_rate")
        if check_rate is not None and check_rate < min_check_rate:
            violations.append(
                f"Correctness Threshold: Scenario '{scenario_name}' check rate {check_rate:.4f} < {min_check_rate:.4f}"
            )

        p95 = metrics.get("latency_p95_ms", 0.0)
        if p95 > max_p95_latency_ms:
            violations.append(
                f"Latency Threshold: Scenario '{scenario_name}' p95 latency {p95:.2f}ms > {max_p95_latency_ms:.2f}ms"
            )

    return {
        "passed": len(violations) == 0,
        "max_error_rate": max_error_rate,
        "max_p95_latency_ms": max_p95_latency_ms,
        "min_check_rate": min_check_rate,
        "violations": violations,
    }


def _fmt(value: Optional[float], fmt: str, suffix: str = "") -> str:
    return f"{value:{fmt}}{suffix}" if value is not None else "N/A"


def _mib(byte_count: Optional[int]) -> str:
    if byte_count is None:
        return "N/A"
    return f"{byte_count / (1024 * 1024):.1f}"


def render_markdown(
    metadata: Dict[str, Any],
    controls: Dict[str, bool],
    scenarios: Dict[str, Any],
    comparison_data: Dict[str, Any],
    timing_rows: List[Dict[str, Any]],
    thresholds: Dict[str, Any],
) -> str:
    """Generate Markdown report."""
    md: List[str] = []
    verdict = "PASSED" if thresholds["passed"] else "FAILED"

    md.append("# Firewall Performance Benchmark: `bfw` vs `ufw`\n")
    md.append(f"**Overall Verdict:** `{verdict}`\n")

    # Metadata
    md.append("## Environment & Run Metadata\n")
    md.append("| Property | Value |")
    md.append("|---|---|")
    md.append(f"| Host Kernel | {metadata.get('kernel', 'Linux')} |")
    md.append(f"| Architecture | {metadata.get('arch', 'unknown')} |")
    md.append(f"| bfw Version | {metadata.get('bfw_version', 'local build')} |")
    md.append(f"| ufw Version | {metadata.get('ufw_version', 'unknown')} |")
    md.append(f"| k6 Version | {metadata.get('k6_version', 'unknown')} |")
    md.append(f"| Traffic Profiles | {metadata.get('profiles', 'keepalive churn mixed')} |")
    md.append(f"| Test Concurrency (VUs) | {metadata.get('vus', '10')} |")
    md.append(f"| Mixed Peak Concurrency (VUs) | {metadata.get('peak_vus', '50')} |")
    md.append(f"| Fresh-Connection Target Rate (req/s) | {metadata.get('churn_rps', '200')} |")
    md.append(f"| Mixed Ramp Stages | {metadata.get('mixed_stages', '4s:0,6s:50,10s:50,5s:0')} |")
    md.append(f"| Fixed-VU Profile Duration | {metadata.get('duration', '10s')} |")
    md.append(f"| Warmup Duration | {metadata.get('warmup_duration', '2s')} |")
    md.append(f"| Repeats | {metadata.get('repeats', '3')} |")
    md.append(f"| Rule Scales | {metadata.get('cardinalities', '10 100 500 1000')} |")
    md.append(f"| Isolation | {metadata.get('isolation', 'Not recorded')} |\n")

    # Controls
    md.append("## Security Controls Proof\n")
    md.append("Security controls verify that k6 traffic reaches the server on the benchmark network and that the firewall filters the tested ports:\n")
    md.append("| Control | Expected | Actual | Status |")
    md.append("|---|---|---|---|")
    base_stat = "PASS" if controls.get("baseline_unfiltered", True) else "FAIL"
    pos_stat = "PASS" if controls.get("positive_permitted") else "FAIL"
    neg_stat = "PASS" if controls.get("negative_denied") else "FAIL"
    md.append(f"| Baseline Control (No Firewall) | HTTP 200 OK on both ports | Traffic Allowed | `{base_stat}` |")
    md.append(f"| Positive Control (Permitted Port 8080) | HTTP 200 OK | Traffic Allowed | `{pos_stat}` |")
    md.append(f"| Negative Control (Denied Port 8081) | Packet Dropped / Timeout | Traffic Blocked | `{neg_stat}` |")
    verified = controls.get("benchmark_rulesets_verified")
    if verified:
        md.append(f"| Per-Ruleset Controls | Verified {verified} times | Allow 8080 + Block 8081 | `PASS` |")
    md.append("")

    comparisons = comparison_data["comparisons"]

    # Per-profile traffic performance tables
    md.append("## Traversed Traffic Performance (k6 Throughput & Latency)\n")
    md.append("| Profile | Scenario | Rules | Reqs | Dropped It. | Errors | Checks | Throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | Err % | RX (MiB) | TX (MiB) | VU max |")
    md.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")

    for scenario_name in sorted(scenarios, key=_scenario_sort_key):
        engine, card_text, profile = split_scenario_key(scenario_name)
        s = scenarios[scenario_name]
        label = {
            "baseline": "Baseline (No FW)",
            "bfw": "**bfw**",
            "ufw": "ufw",
        }.get(engine, engine)
        check_pct = f"{s['check_rate'] * 100:.2f}%" if s.get("check_rate") is not None else "N/A"
        md.append(
            f"| {profile} | {label} | {card_text} | {s['request_count']} | {s.get('dropped_iterations', 0)} | "
            f"{s['error_count']} | {check_pct} | {s['throughput_rps']:.1f} | {s['latency_p50_ms']:.2f} | "
            f"{s['latency_p95_ms']:.2f} | {s['latency_p99_ms']:.2f} | {s['error_rate'] * 100:.2f}% | "
            f"{_mib(s.get('data_received_bytes'))} | {_mib(s.get('data_sent_bytes'))} | {s['vus_max']:.0f} |"
        )
    md.append("")

    # Comparative ratios per profile (informational)
    md.append("## Comparative Ratios & Analysis (Informational)\n")
    md.append("> *Note: Hosted CI runner virtualization introduces transient CPU scheduling noise. "
              "Ratios are informational while error rate, check rate, and latency thresholds govern build status.*\n")
    md.append("| Profile | Rules | Throughput (`bfw`/`ufw`) | p50 (`bfw`/`ufw`) | p95 (`bfw`/`ufw`) | p99 (`bfw`/`ufw`) | `bfw` Overhead vs Baseline | `ufw` Overhead vs Baseline |")
    md.append("|---|---|---|---|---|---|---|---|")

    for comp in comparisons:
        t_ratio = _fmt(comp.get("throughput_ratio_bfw_vs_ufw"), ".3f", "x")
        p50_ratio = _fmt(comp.get("p50_latency_ratio_bfw_vs_ufw"), ".3f", "x")
        p95_ratio = _fmt(comp.get("p95_latency_ratio_bfw_vs_ufw"), ".3f", "x")
        p99_ratio = _fmt(comp.get("p99_latency_ratio_bfw_vs_ufw"), ".3f", "x")
        bfw_ovh = _fmt(comp.get("bfw_overhead_pct"), ".1f", "%")
        ufw_ovh = _fmt(comp.get("ufw_overhead_pct"), ".1f", "%")
        md.append(
            f"| {comp['profile']} | {comp['cardinality']} | **{t_ratio}** | {p50_ratio} | **{p95_ratio}** | "
            f"{p99_ratio} | {bfw_ovh} | {ufw_ovh} |"
        )
    md.append("")

    # CLI rule timing, split into rule-add and enable phases
    md.append("## CLI Rule Timing\n")
    md.append("Wall-clock seconds split into rule configuration (`allow` calls) and enable/apply (`--force enable`):\n")
    md.append("| Rules | `bfw` Add (s) | `bfw` Enable (s) | `bfw` Total (s) | `ufw` Add (s) | `ufw` Enable (s) | `ufw` Total (s) | Add Speedup | Enable Speedup | Total Speedup |")
    md.append("|---|---|---|---|---|---|---|---|---|---|")

    for row in timing_rows:
        b_add = _fmt(row.get("bfw_rule_add_s"), ".4f")
        b_en = _fmt(row.get("bfw_enable_s"), ".4f")
        b_tot = _fmt(row.get("bfw_total_s"), ".4f")
        u_add = _fmt(row.get("ufw_rule_add_s"), ".4f")
        u_en = _fmt(row.get("ufw_enable_s"), ".4f")
        u_tot = _fmt(row.get("ufw_total_s"), ".4f")
        add_sp = _fmt(row.get("rule_add_speedup"), ".2f", "x")
        en_sp = _fmt(row.get("enable_speedup"), ".2f", "x")
        tot_sp = _fmt(row.get("total_speedup"), ".2f", "x")
        md.append(
            f"| {row['cardinality']} | {b_add} | {b_en} | {b_tot} | {u_add} | {u_en} | {u_tot} | "
            f"**{add_sp}** | **{en_sp}** | **{tot_sp}** |"
        )
    md.append("")

    # Thresholds / Violations
    md.append("## Quality Gates & Threshold Verification\n")
    md.append(f"- Max Allowable Error Rate: `{thresholds['max_error_rate'] * 100:.1f}%`")
    md.append(f"- Min Allowable Check Rate: `{thresholds.get('min_check_rate', 0.99) * 100:.1f}%`")
    md.append(f"- Max Allowable Latency (p95): `{thresholds['max_p95_latency_ms']:.1f} ms`")
    md.append("- Maximum Dropped Iterations: `0`")

    if thresholds["violations"]:
        md.append("\n### Threshold Violations:")
        for v in thresholds["violations"]:
            md.append(f"- ❌ {v}")
    else:
        md.append("\n✅ All correctness thresholds, latency boundaries, and security controls satisfied.")

    md.append("\n---\n")
    return "\n".join(md)


def generate_json_report(
    metadata: Dict[str, Any],
    controls: Dict[str, bool],
    scenarios: Dict[str, Any],
    comparison_data: Dict[str, Any],
    apply_times: Dict[str, Dict[str, Dict[str, Any]]],
    timing_rows: List[Dict[str, Any]],
    thresholds: Dict[str, Any],
) -> Dict[str, Any]:
    """Generate structured JSON report dictionary."""
    return {
        "status": "PASSED" if thresholds["passed"] else "FAILED",
        "metadata": metadata,
        "controls": controls,
        "profiles": comparison_data["profiles"],
        "scenarios": scenarios,
        "comparisons": comparison_data["comparisons"],
        "timing_comparisons": timing_rows,
        "apply_times": apply_times,
        "thresholds": thresholds,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare bfw vs ufw performance metrics")
    parser.add_argument("--results-dir", required=True, help="Directory containing raw k6 summary JSONs")
    parser.add_argument("--apply-times", default="", help="Path to apply_times.json")
    parser.add_argument("--meta-file", default="", help="Path to metadata.json")
    parser.add_argument("--output-json", default="", help="Output path for summary.json")
    parser.add_argument("--output-md", default="", help="Output path for summary.md")
    parser.add_argument("--max-error-rate", type=float, default=0.01, help="Max error rate threshold (default: 0.01)")
    parser.add_argument(
        "--max-p95-latency-ms", type=float, default=500.0, help="Max p95 latency threshold in ms (default: 500.0)"
    )
    parser.add_argument(
        "--min-check-rate", type=float, default=0.99, help="Min k6 check pass rate threshold (default: 0.99)"
    )
    args = parser.parse_args()

    metadata: Dict[str, Any] = {}
    controls: Dict[str, Any] = {
        "baseline_unfiltered": False,
        "positive_permitted": False,
        "negative_denied": False,
        "benchmark_rulesets_verified": 0,
    }
    input_violations: List[str] = []
    if args.meta_file:
        if not os.path.isfile(args.meta_file):
            input_violations.append(f"Incomplete benchmark metadata: file not found: {args.meta_file}")
        else:
            try:
                with open(args.meta_file, "r", encoding="utf-8") as f:
                    meta_json = json.load(f)
                if not isinstance(meta_json, dict):
                    raise ValueError("root must be a JSON object")
                metadata_candidate = meta_json.get("metadata", meta_json)
                if not isinstance(metadata_candidate, dict):
                    raise ValueError("'metadata' must be a JSON object")
                metadata = metadata_candidate
                controls_candidate = meta_json.get("controls")
                if isinstance(controls_candidate, dict):
                    controls = controls_candidate
                else:
                    input_violations.append("Incomplete benchmark controls: missing controls object")
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                input_violations.append(f"Incomplete benchmark metadata: {exc}")

    try:
        scenarios = load_results_directory(args.results_dir)
        apply_times = load_apply_times(args.apply_times)
    except Exception as e:
        sys.stderr.write(f"ERROR: Failed to load benchmark input: {e}\n")
        return 1

    input_violations.extend(
        validate_complete_matrix(scenarios, metadata, controls, apply_times, bool(args.apply_times))
    )
    comparison_data = compute_comparisons(scenarios)
    timing_rows = compute_timing_comparisons(apply_times)
    thresholds = evaluate_thresholds(
        scenarios,
        controls,
        args.max_error_rate,
        args.max_p95_latency_ms,
        args.min_check_rate,
        input_violations,
    )

    json_report = generate_json_report(
        metadata, controls, scenarios, comparison_data, apply_times, timing_rows, thresholds
    )
    md_report = render_markdown(
        metadata, controls, scenarios, comparison_data, timing_rows, thresholds
    )

    if args.output_json:
        os.makedirs(os.path.dirname(os.path.abspath(args.output_json)), exist_ok=True)
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(json_report, f, indent=2)

    if args.output_md:
        os.makedirs(os.path.dirname(os.path.abspath(args.output_md)), exist_ok=True)
        with open(args.output_md, "w", encoding="utf-8") as f:
            f.write(md_report)

    # Print markdown summary to stdout
    sys.stdout.write(md_report)
    sys.stdout.flush()

    if not thresholds["passed"]:
        sys.stderr.write(f"Performance quality gate FAILED with {len(thresholds['violations'])} violations\n")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
