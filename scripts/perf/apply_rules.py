#!/usr/bin/env python3
"""Apply one firewall ruleset and report in-container wall-clock timings.

Prints a single JSON object on stdout:
  {"engine": ..., "rule_count": N, "rule_add_seconds": A, "enable_seconds": E,
   "total_seconds": T}
`rule_add_seconds` covers the per-rule `allow` CLI calls (the configuration
phase); `enable_seconds` covers the final `--force enable` (the apply phase).
"""

import json
import subprocess
import sys
import time


def run(*command: str) -> None:
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip()
        raise RuntimeError(f"{command!r} failed with {result.returncode}: {detail}")


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: apply_rules.py bfw|ufw RULE_COUNT HTTP_PORT", file=sys.stderr)
        return 2

    engine, count_text, http_port = sys.argv[1:]
    if engine not in ("bfw", "ufw"):
        print(f"unknown firewall: {engine}", file=sys.stderr)
        return 2

    count = int(count_text)
    run(engine, "default", "deny", "incoming")

    add_started = time.perf_counter()
    for port in range(10001, 10001 + count):
        run(engine, "allow", f"{port}/tcp")
    run(engine, "allow", f"{http_port}/tcp")
    rule_add_seconds = time.perf_counter() - add_started

    enable_started = time.perf_counter()
    run(engine, "--force", "enable")
    enable_seconds = time.perf_counter() - enable_started

    print(
        json.dumps(
            {
                "engine": engine,
                "rule_count": count,
                "rule_add_seconds": round(rule_add_seconds, 4),
                "enable_seconds": round(enable_seconds, 4),
                "total_seconds": round(rule_add_seconds + enable_seconds, 4),
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
