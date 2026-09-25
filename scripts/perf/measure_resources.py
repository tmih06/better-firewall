#!/usr/bin/env python3
"""Sample Docker container CPU and memory while a benchmark command runs."""

import argparse
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Mapping

_MEMORY_UNITS = {
    "B": 1,
    "kB": 1000,
    "MB": 1000**2,
    "GB": 1000**3,
    "TB": 1000**4,
    "KiB": 1024,
    "MiB": 1024**2,
    "GiB": 1024**3,
    "TiB": 1024**4,
}
_MEMORY_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)?)\s*(B|kB|MB|GB|TB|KiB|MiB|GiB|TiB)$")


def parse_memory_mib(memory_usage: str) -> float:
    """Parse the current-memory side of Docker's ``MemUsage`` field into MiB."""
    current = memory_usage.split("/", 1)[0].strip()
    match = _MEMORY_RE.fullmatch(current)
    if match is None:
        raise ValueError(f"invalid Docker memory usage: {memory_usage!r}")
    amount, unit = match.groups()
    return float(amount) * _MEMORY_UNITS[unit] / (1024**2)


def parse_docker_stats(output: str, container_ids: Mapping[str, str]) -> Dict[str, Dict[str, float]]:
    """Parse one ``docker stats --no-stream`` sample for each named container."""
    prefixes = {container_id[:12]: name for name, container_id in container_ids.items()}
    sample: Dict[str, Dict[str, float]] = {}

    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("|", 2)
        if len(parts) != 3:
            raise ValueError(f"malformed Docker stats row: {line!r}")
        short_id, cpu_text, memory_usage = (part.strip() for part in parts)
        name = prefixes.get(short_id[:12])
        if name is None:
            raise ValueError(f"unexpected Docker stats container ID: {short_id!r}")
        if name in sample:
            raise ValueError(f"duplicate Docker stats row for {name}")
        if not cpu_text.endswith("%"):
            raise ValueError(f"invalid Docker CPU usage: {cpu_text!r}")
        cpu_pct = float(cpu_text[:-1])
        memory_mib = parse_memory_mib(memory_usage)
        if not math.isfinite(cpu_pct) or cpu_pct < 0 or not math.isfinite(memory_mib) or memory_mib < 0:
            raise ValueError(f"non-finite or negative Docker stats for {name}")
        sample[name] = {"cpu_pct": cpu_pct, "memory_mib": memory_mib}

    missing = set(container_ids) - sample.keys()
    if missing:
        raise ValueError(f"Docker stats omitted containers: {', '.join(sorted(missing))}")
    return sample


def aggregate_samples(samples: List[Dict[str, Dict[str, float]]]) -> Dict[str, Dict[str, Any]]:
    """Summarize samples with mean/peak CPU and memory for each container."""
    if not samples:
        raise ValueError("cannot summarize an empty Docker stats sample set")

    names = set(samples[0])
    if any(set(sample) != names for sample in samples):
        raise ValueError("Docker stats sample container sets differ")

    summaries: Dict[str, Dict[str, Any]] = {}
    for name in sorted(names):
        cpu_values = [sample[name]["cpu_pct"] for sample in samples]
        memory_values = [sample[name]["memory_mib"] for sample in samples]
        summaries[name] = {
            "cpu_avg_pct": round(sum(cpu_values) / len(cpu_values), 2),
            "cpu_peak_pct": round(max(cpu_values), 2),
            "memory_avg_mib": round(sum(memory_values) / len(memory_values), 2),
            "memory_peak_mib": round(max(memory_values), 2),
            "sample_count": len(samples),
        }
    return summaries


def _write_resource_summary(summary_path: str, resource_usage: Dict[str, Dict[str, Any]]) -> None:
    with open(summary_path, "r", encoding="utf-8") as source:
        summary = json.load(source)
    if not isinstance(summary, dict) or not isinstance(summary.get("metrics"), dict):
        raise ValueError(f"invalid k6 summary at {summary_path}")
    summary["benchmark_resources"] = resource_usage

    directory = os.path.dirname(os.path.abspath(summary_path))
    descriptor, temporary_path = tempfile.mkstemp(prefix=".resource-summary-", suffix=".json", dir=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(summary, output, indent=2)
            output.write("\n")
        os.replace(temporary_path, summary_path)
    except BaseException:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        raise


def run_measured(command: List[str], summary_path: str, container_ids: Mapping[str, str], sample_interval: float) -> int:
    """Run a command, sampling containers until it exits, then annotate its k6 summary."""
    if not command:
        raise ValueError("missing benchmark command")
    if not container_ids:
        raise ValueError("at least one container is required")
    if sample_interval <= 0 or not math.isfinite(sample_interval):
        raise ValueError("sample interval must be a positive finite number")

    process = subprocess.Popen(command)
    samples: List[Dict[str, Dict[str, float]]] = []
    stats_command = [
        "docker",
        "stats",
        "--no-stream",
        "--format",
        "{{.ID}}|{{.CPUPerc}}|{{.MemUsage}}",
        *container_ids.values(),
    ]

    try:
        while True:
            result = subprocess.run(stats_command, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                raise RuntimeError(f"docker stats failed: {result.stderr.strip()}")
            samples.append(parse_docker_stats(result.stdout, container_ids))
            if process.poll() is not None:
                break
            time.sleep(sample_interval)
    except BaseException:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        raise

    return_code = process.wait()
    _write_resource_summary(summary_path, aggregate_samples(samples))
    return return_code


def _parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", required=True, help="host path to the k6 summary JSON")
    parser.add_argument("--container", action="append", nargs=2, metavar=("NAME", "ID"), required=True)
    parser.add_argument("--sample-interval", type=float, default=1.0)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    names = [name for name, _ in args.container]
    if len(set(names)) != len(names):
        parser.error("container names must be unique")
    args.container_ids = dict(args.container)
    return args


def main(argv: List[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        return run_measured(args.command, args.summary, args.container_ids, args.sample_interval)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"FATAL: resource measurement failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
