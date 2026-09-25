#!/usr/bin/env python3
"""Apply one firewall ruleset and report its in-container wall time."""

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

    started = time.perf_counter()
    for port in range(10001, 10001 + count):
        run(engine, "allow", f"{port}/tcp")
    run(engine, "allow", f"{http_port}/tcp")
    run(engine, "--force", "enable")
    print(f"{time.perf_counter() - started:.4f}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError) as error:
        print(f"FATAL: {error}", file=sys.stderr)
        raise SystemExit(1)
