#!/usr/bin/env python3
"""Assert the committed charts and docs/benchmarks.md match their snapshot.

The README quotes setup times, traffic counters and attack-lab results in prose.
Those numbers used to be transcribed by hand and drifted away from the CI
artifacts they claimed to describe. The generator now parses every rendered value
out of the snapshot, so this test re-runs the generator and fails if a committed
file is stale, or if the README quotes a performance figure that the snapshot does
not support.

Usage: scripts/charts/test_charts.py
Exits non-zero and prints each mismatch. Safe: no network, no privileges.
"""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHART_SCRIPT = ROOT / "scripts" / "charts" / "charts.py"
SNAPSHOT = ROOT / "scripts" / "charts" / "testdata"
README = ROOT / "README.md"

GENERATED = [
    "docs/firewall-setup-time.svg",
    "docs/firewall-reliability.svg",
    "docs/firewall-resources.svg",
    "docs/attack-lab.svg",
    "docs/benchmarks.md",
]


def regenerate():
    """Render into a scratch copy of the repo so the committed files are untouched.

    charts.py resolves its output paths relative to its own location
    (parents[2] of scripts/charts/charts.py), so copying it into a scratch tree
    alongside a copy of the snapshot reproduces exactly what `make charts` writes.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        scratch = tmp / "scripts" / "charts"
        (scratch / "testdata").mkdir(parents=True)
        (tmp / "docs").mkdir()
        (scratch / "charts.py").write_bytes(CHART_SCRIPT.read_bytes())
        for name in ("summary.json", "attack-summary.json", "protection-benchmarks.txt"):
            src = SNAPSHOT / name
            if src.exists():
                (scratch / "testdata" / name).write_bytes(src.read_bytes())
        subprocess.run([sys.executable, str(scratch / "charts.py")], check=True, capture_output=True)
        return {p: (tmp / p).read_text() for p in GENERATED if (tmp / p).exists()}


def check_regenerated(failures):
    """Committed files must be byte-identical to a fresh render of the snapshot."""
    fresh = regenerate()
    for rel, content in fresh.items():
        committed = ROOT / rel
        if not committed.exists():
            failures.append(f"{rel}: missing; run `make charts`")
        elif committed.read_text() != content:
            failures.append(f"{rel}: stale; run `make charts`")


def check_readme_figures(failures):
    """Every performance figure the README states must come from the snapshot."""
    summary = json.load(open(SNAPSHOT / "summary.json"))
    attack = json.load(open(SNAPSHOT / "attack-summary.json"))
    # The README uses typographic dashes and thousands separators; normalise so a
    # figure is matched on its digits rather than on the glyph chosen for them.
    readme = README.read_text().replace("\u2212", "-").replace("\u2013", "-")
    scen = summary["scenarios"]

    def stated(claim, ok):
        if not ok:
            failures.append(f"README: {claim} not found or does not match the snapshot")

    for t in summary["timing_comparisons"]:
        stated(f"{t['cardinality']}-rule bfw time {t['bfw_total_s']:.2f} s", f"{t['bfw_total_s']:.2f} s" in readme)
        stated(f"{t['cardinality']}-rule UFW time {t['ufw_total_s']:.2f} s", f"{t['ufw_total_s']:.2f} s" in readme)
        stated(f"{t['cardinality']}-rule speed-up {t['total_speedup']:.1f}x", f"{t['total_speedup']:.1f}" in readme)

    stated("total request count", f"{sum(v['request_count'] for v in scen.values()):,}" in readme)
    stated("total response checks", f"{sum(v['check_passes'] for v in scen.values()):,}" in readme)
    stated("zero request errors", sum(v["error_count"] for v in scen.values()) == 0)
    stated("zero dropped iterations", sum(v["dropped_iterations"] for v in scen.values()) == 0)

    # The reliability chart plots p95 deviation from the no-firewall container,
    # so the README's worst-case and "faster than no firewall" claims are derived
    # from the same arithmetic the chart does.
    p95_dev = {}
    for profile in ("keepalive", "churn", "mixed"):
        for k in (10, 100, 500, 1000):
            base = scen[f"baseline_{k}_{profile}"]["latency_p95_ms"]
            for engine in ("bfw", "ufw"):
                v = scen[f"{engine}_{k}_{profile}"]["latency_p95_ms"]
                p95_dev[(profile, k, engine)] = (v - base) / base * 100
    worst = max(abs(v) for v in p95_dev.values())
    faster = sum(1 for (p, k, e), v in p95_dev.items() if e == "bfw" and v < 0)
    stated(f"worst p95 deviation {worst:.1f}%", f"{worst:.1f}%" in readme)
    stated(f"bfw faster than no firewall in {faster} of 12 cells",
           re.search(rf"{faster} of (?:the )?12 cells", readme) is not None)

    # The README explains why p99 is not charted; that claim is churn p99 swing.
    churn_p99 = []
    for k in (10, 100, 500, 1000):
        base = scen[f"baseline_{k}_churn"]["latency_p99_ms"]
        churn_p99.append((scen[f"bfw_{k}_churn"]["latency_p99_ms"] - base) / base * 100)
    stated(f"churn p99 low {min(churn_p99):.1f}%", f"{min(churn_p99):.1f}%" in readme)
    stated(f"churn p99 high {max(churn_p99):+.1f}%", f"{max(churn_p99):+.1f}%" in readme)

    # The README records the bfw/UFW ratio range that got the old charts dropped.
    ratios = ([c["throughput_ratio_bfw_vs_ufw"] for c in summary["comparisons"]]
              + [c["p95_latency_ratio_bfw_vs_ufw"] for c in summary["comparisons"]])
    stated(f"ratio range min {min(ratios):.3f}", f"{min(ratios):.3f}" in readme)
    stated(f"ratio range max {max(ratios):.3f}", f"{max(ratios):.3f}" in readme)

    # The resources panel plots mean memory and mean CPU-over-baseline per rule
    # count, so the README's memory table and CPU tie figures are derived the same way.
    profiles = ("keepalive", "churn", "mixed")

    def mem(engine, k):
        return sum(scen[f"{engine}_{k}_{p}"]["resource_usage"]["server"]["memory_avg_mib"]
                   for p in profiles) / len(profiles)

    def cpu_over(engine, k):
        return sum(scen[f"{engine}_{k}_{p}"]["resource_usage"]["server"]["cpu_avg_pct"]
                   - scen[f"baseline_{k}_{p}"]["resource_usage"]["server"]["cpu_avg_pct"]
                   for p in profiles) / len(profiles)

    for k in (10, 100, 500, 1000):
        b, u = mem("bfw", k), mem("ufw", k)
        stated(f"memory {k} rules bfw {b:.1f} MiB", f"{b:.1f} MiB" in readme)
        stated(f"memory {k} rules UFW {u:.1f} MiB", f"{u:.1f} MiB" in readme)
        # The table also carries a rounded per-row delta. Rows whose engines are
        # level within half a percent are written as "level" rather than a number.
        pct = 100 * (b - u) / u
        if abs(pct) >= 0.5:
            delta = f"{pct:+.0f}%".replace("+", "−")
            stated(f"memory delta at {k} rules {delta}", delta in readme)
        for engine in ("bfw", "ufw"):
            v = cpu_over(engine, k)
            stated(f"CPU overhead {engine} {k} rules {v:+.1f} pp", f"{v:+.1f}" in readme)

    # The 14% memory saving is quoted three ways: as a headline, and per profile.
    # Check all of them, and require each per-profile figure so a rewrite that
    # keeps the numbers in one sentence cannot satisfy the check for another.
    headline = abs(100 * (mem("bfw", 1000) - mem("ufw", 1000)) / mem("ufw", 1000))
    stated(f"headline memory saving {headline:.0f}%", f"{headline:.0f}%" in readme)
    for p in profiles:
        k = 1000
        b = scen[f"bfw_{k}_{p}"]["resource_usage"]["server"]["memory_avg_mib"]
        u = scen[f"ufw_{k}_{p}"]["resource_usage"]["server"]["memory_avg_mib"]
        pct = abs(100 * (b - u) / u)
        stated(f"memory saving at 1,000 rules in {p}: {pct:.1f}%", f"{pct:.1f}%" in readme)

    for engine in ("none", "bfw", "ufw"):
        nmap = attack["engines"][engine]["nmap"]
        stated(f"{engine} nmap seconds", f"{nmap['seconds']:.2f}" in readme)
        for key, attack_name in (("synflood_denied", "SYN denied"),
                                 ("synflood_allowed", "SYN allowed"),
                                 ("connectflood", "connect flood")):
            ok = attack["engines"][engine]["attacks"][key]["legit"]["ok"]
            stated(f"{engine} legit requests {attack_name} {ok:,}", f"{ok:,}" in readme)

    bfw = attack["engines"]["bfw"]
    stated("bfw SSH jail ban time", f"{bfw['jail']['jail_ban_s']:.1f}" in readme)
    stated("bfw LAPI ban time", f"{bfw['lapi']['lapi_ban_s']:.1f}" in readme)
    stated("bfw LAPI unban time", f"{bfw['lapi']['lapi_unban_s']:.1f}" in readme)


def check_no_orphan_charts(failures):
    """Every committed SVG must be referenced by the README, and every docs/ link must resolve.

    An unreferenced chart is a chart nobody reads; a README link to a path that
    does not exist is a broken reference, and is the failure mode that let the
    previous absolute-latency chart go unnoticed.
    """
    readme = README.read_text()
    for svg in sorted((ROOT / "docs").glob("*.svg")):
        rel = f"docs/{svg.name}"
        if rel not in readme:
            failures.append(f"{rel}: generated but not referenced by README.md")
    for ref in sorted(set(re.findall(r"docs/[\w.-]+\.(?:svg|md)", readme))):
        if not (ROOT / ref).exists():
            failures.append(f"README references {ref} but it does not exist")


def main():
    failures = []
    check_regenerated(failures)
    check_readme_figures(failures)
    check_no_orphan_charts(failures)
    if failures:
        print("chart/README consistency FAILED:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("chart/README consistency OK: charts are current and every quoted figure traces to the snapshot")
    return 0


if __name__ == "__main__":
    sys.exit(main())
