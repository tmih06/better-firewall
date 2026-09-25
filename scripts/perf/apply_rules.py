#!/usr/bin/env python3
"""Apply firewall rules and report wall-clock, CPU, and peak child RSS.

Prints one JSON object with separate rule-add and enable measurements. CPU time
and peak RSS cover the firewall CLI child processes; peak RSS is reported in
KiB using Linux ``getrusage`` units.
"""

import json
import resource
import subprocess
import sys
import time


def run(*command: str) -> None:
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip()
        raise RuntimeError(f"{command!r} failed with {result.returncode}: {detail}")


def measure_phase(phase: str, engine: str, count: int, http_port: str) -> dict:
    result = subprocess.run(
        [sys.executable, __file__, "--phase", phase, engine, str(count), http_port],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"{phase} measurement failed: {result.stderr.strip()}")
    try:
        timing = json.loads(result.stdout)
        return {
            "wall_seconds": float(timing["wall_seconds"]),
            "cpu_seconds": float(timing["cpu_seconds"]),
            "peak_rss_kib": int(timing["peak_rss_kib"]),
        }
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        raise RuntimeError(f"malformed {phase} measurement: {error}") from error


def run_phase_worker(phase: str, engine: str, count: int, http_port: str) -> int:
    started = time.perf_counter()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)

    if phase == "rule_add":
        for port in range(10001, 10001 + count):
            run(engine, "allow", f"{port}/tcp")
        run(engine, "allow", f"{http_port}/tcp")
    elif phase == "enable":
        run(engine, "--force", "enable")
    else:
        raise ValueError(f"unknown phase: {phase}")

    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    print(
        json.dumps(
            {
                "wall_seconds": round(time.perf_counter() - started, 4),
                "cpu_seconds": round(
                    (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime), 6
                ),
                "peak_rss_kib": int(after.ru_maxrss),
            }
        )
    )
    return 0


def main() -> int:
    if len(sys.argv) == 6 and sys.argv[1] == "--phase":
        _, _, phase, engine, count_text, http_port = sys.argv
        if engine not in ("bfw", "ufw"):
            print(f"unknown firewall: {engine}", file=sys.stderr)
            return 2
        return run_phase_worker(phase, engine, int(count_text), http_port)

    if len(sys.argv) != 4:
        print("usage: apply_rules.py bfw|ufw RULE_COUNT HTTP_PORT", file=sys.stderr)
        return 2

    engine, count_text, http_port = sys.argv[1:]
    if engine not in ("bfw", "ufw"):
        print(f"unknown firewall: {engine}", file=sys.stderr)
        return 2

    count = int(count_text)
    run(engine, "default", "deny", "incoming")
    rule_add = measure_phase("rule_add", engine, count, http_port)
    enable = measure_phase("enable", engine, count, http_port)

    print(
        json.dumps(
            {
                "engine": engine,
                "rule_count": count,
                "rule_add_seconds": rule_add["wall_seconds"],
                "enable_seconds": enable["wall_seconds"],
                "total_seconds": round(rule_add["wall_seconds"] + enable["wall_seconds"], 4),
                "rule_add_cpu_seconds": rule_add["cpu_seconds"],
                "enable_cpu_seconds": enable["cpu_seconds"],
                "rule_add_peak_rss_kib": rule_add["peak_rss_kib"],
                "enable_peak_rss_kib": enable["peak_rss_kib"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError) as error:
        print(f"FATAL: {error}", file=sys.stderr)
        raise SystemExit(1)
