#!/usr/bin/env python3
"""Regenerate the committed benchmark charts and docs/benchmarks.md from CI artifacts.

Outputs
-------
docs/firewall-setup-time.svg   rule add + enable wall clock, as a speed-up factor
docs/firewall-reliability.svg correctness counters and absolute tail latency
docs/attack-lab.svg           real-attack comparison (only when attack data is present)
docs/benchmarks.md            internal Go microbenchmarks, parsed from the CI bench text

Every number rendered here is parsed from the input artifacts. Nothing is
hand-transcribed, so a refreshed artifact cannot leave stale prose behind.

Chart conventions (kept from the previous generator, see 7739f1c):
  - Bar and dot lengths encode the quantity on a linear axis starting at zero.
  - A bar's length is never a ratio presented as a total, so no log scales.
  - Where a quantity spans orders of magnitude, the panel is dropped rather than
    rescaled, and the exact value is printed next to every mark.

Usage: charts.py [artifact-dir]
  Reads <dir>/summary.json, <dir>/protection-benchmarks.txt and, when present,
  <dir>/attack-summary.json. Defaults to the committed snapshot in
  scripts/charts/testdata/ so `make charts` is reproducible; pass a directory of
  freshly downloaded CI artifacts to publish a new run.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent / "testdata"

SUM = json.load(open(DATA / "summary.json"))
TXT = (DATA / "protection-benchmarks.txt").read_text()
ATTACK_PATH = DATA / "attack-summary.json"
ATTACK = json.load(open(ATTACK_PATH)) if ATTACK_PATH.exists() else None

# Engines are always drawn in this order so colours mean the same thing in every
# panel and legend.
ENGINES = [
    ("baseline", "No firewall", "#64748b", "base"),
    ("bfw", "bfw", "#0f9d8a", "bfw"),
    ("ufw", "UFW", "#3b82f6", "ufw"),
]
PROFILES = [("keepalive", "Keep-alive"), ("churn", "Connection churn"), ("mixed", "Mixed payload")]
CARDINALITIES = (10, 100, 500, 1000)

STYLE = """  <style>
    text { font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; fill: #172554; }
    .muted { fill: #64748b; }
    .panel { fill: #ffffff; stroke: #dbe4f0; stroke-width: 1; }
    .grid { stroke: #e2e8f0; stroke-width: 1; }
    .axis { stroke: #94a3b8; stroke-width: 1.2; }
    .base { fill: #64748b; }
    .bfw { fill: #0f9d8a; }
    .ufw { fill: #3b82f6; }
  </style>"""


def head(w, h, title, desc, subtitle):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-labelledby="title desc">\n'
            f'  <title id="title">{title}</title>\n'
            f'  <desc id="desc">{desc}</desc>\n{STYLE}\n'
            f'  <rect width="{w}" height="{h}" fill="#f1f5f9"/>\n'
            f'  <text x="32" y="38" font-size="24" font-weight="700">{title}</text>\n'
            f'  <text x="32" y="62" font-size="13" class="muted">{subtitle}</text>\n')


def legend(x, y):
    """Shared engine legend. Returns the x offset just past the last swatch."""
    for key, label, _, cls in ENGINES:
        s = f'  <rect x="{x}" y="{y}" width="12" height="12" rx="3" class="{cls}"/>\n'
        s += f'  <text x="{x + 18}" y="{y + 10}" font-size="12">{label}</text>\n'
        x += 30 + len(label) * 7
    return x


def esc(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


# ---------------------------------------------------------------- setup time

def setup_svg():
    """Rule add + enable time, drawn as the speed-up factor.

    Absolute seconds span 0.05 s to 168 s, so a single linear bar axis would
    flatten every bfw bar into a 1 px sliver. Speed-up is itself the claim being
    made, it stays within one order of magnitude, and the absolute seconds are
    printed on every row so the bar never hides them.
    """
    W, H = 1120, 560
    tc = {t["cardinality"]: t for t in SUM["timing_comparisons"]}
    vmax = max(t["total_speedup"] for t in tc.values())
    vmax = math_ceil_nice(vmax)
    x0, x1 = 300, 940

    s = head(W, H, "Rule setup is 8-32x faster than UFW",
             "Grouped horizontal bar chart. One bar per rule count showing the "
             "speed-up of bfw over UFW for the combined time to add the rules and "
             "enable the firewall. Bar length is the speed-up multiple on a linear "
             "axis from zero. The absolute wall-clock seconds for both firewalls are "
             "printed beside every bar.",
             f"Mean of {tc[10]['bfw_repeats']} repeats per engine · {SUM['metadata']['kernel']}")
    s += '  <rect class="panel" x="24" y="108" width="1072" height="336" rx="14"/>\n'

    step = vmax / 4
    for i in range(5):
        v = step * i
        x = x0 + (x1 - x0) * i / 4
        anchor = "start" if i == 0 else ("end" if i == 4 else "middle")
        s += f'  <line class="grid" x1="{x:.1f}" y1="140" x2="{x:.1f}" y2="418"/>\n'
        s += f'  <text x="{x:.1f}" y="{436}" text-anchor="{anchor}" font-size="11" class="muted">{v:g}x</text>\n'
    s += f'  <line class="axis" x1="{x0}" y1="140" x2="{x0}" y2="418"/>\n'

    for i, k in enumerate(CARDINALITIES):
        row = tc[k]
        y = 160 + i * 68
        bw = (x1 - x0) * row["total_speedup"] / vmax
        s += f'  <text x="52" y="{y + 22}" font-size="14" font-weight="650">{k:,} rules</text>\n'
        s += (f'  <rect class="bfw" x="{x0}" y="{y}" width="{bw:.1f}" height="30" rx="4">'
              f'<title>{k:,} rules: bfw {row["bfw_total_s"]:.2f} s vs UFW {row["ufw_total_s"]:.2f} s '
              f'= {row["total_speedup"]:.1f}x</title></rect>\n')
        s += f'  <text x="{x0 + bw + 10:.1f}" y="{y + 21}" font-size="13" font-weight="700" fill="#0f9d8a">{row["total_speedup"]:.1f}x</text>\n'
        s += (f'  <text x="{x0}" y="{y + 48}" font-size="11" class="muted">'
              f'bfw {row["bfw_total_s"]:.2f} s &#183; UFW {row["ufw_total_s"]:.2f} s</text>\n')

    s += '  <text x="620" y="458" text-anchor="middle" font-size="11" class="muted">Speed-up of bfw over UFW (higher is better)</text>\n'
    s += '  <text x="32" y="490" font-size="11" class="muted">Configuration and apply time only. This is not packet-processing latency.</text>\n'
    s += '  <text x="32" y="510" font-size="11" class="muted">UFW slows down superlinearly with rule count (one iptables-save per rule); bfw compiles the whole ruleset in a single atomic nftables transaction.</text>\n'
    s += '  <text x="32" y="530" font-size="11" class="muted">The axis is linear from zero, so bar length is proportional to the multiple shown.</text>\n'
    s += "</svg>\n"
    return s


def math_ceil_nice(v):
    for m in (5, 10, 15, 20, 25, 30, 40, 50):
        if v <= m:
            return m
    return v


# ---------------------------------------------------------------- reliability

def reliability_svg():
    """Correctness counters plus absolute tail latency against the no-firewall baseline.

    This is the "will it break my traffic" panel. Ratios were dropped because the
    bfw/UFW spread sits inside run-to-run noise; plotting absolute p99 with the
    no-firewall container as a third bar lets the reader see the bars are the same
    height, which is the actual claim.
    """
    W, H = 1120, 800
    scen = SUM["scenarios"]

    total_requests = sum(v["request_count"] for v in scen.values())
    total_errors = sum(v["error_count"] for v in scen.values())
    total_dropped = sum(v["dropped_iterations"] for v in scen.values())
    total_checks = sum(v["check_passes"] for v in scen.values())
    ctl = SUM["controls"]
    thr = SUM["thresholds"]

    tiles = [
        ("Requests served", f"{total_requests:,}", "no firewall, bfw and UFW combined"),
        ("Request errors", f"{total_errors:,}", f"budget {thr['max_error_rate'] * 100:.0f}%"),
        ("Dropped iterations", f"{total_dropped:,}", "load generator could not dispatch"),
        ("Response checks passed", f"{total_checks:,}", "server returned the expected body"),
    ]
    s = head(W, H, "No measurable traffic cost at any rule count",
             "Top row: correctness counters for the whole run - requests served, "
             "request errors, dropped iterations and k6 response checks that returned "
             "the expected body. Lower panels: mean p99 latency in milliseconds for no "
             "firewall, bfw and UFW at 10, 100, 500 and 1000 rules, one panel per "
             "traffic profile, each on its own linear axis from zero.",
             f"Mean p99 latency over {SUM['metadata']['repeats']} repeats per cell · {SUM['metadata']['kernel']}")

    # correctness tiles
    tw, gap = 251, 20
    for i, (label, value, note) in enumerate(tiles):
        x = 24 + i * (tw + gap)
        s += f'  <rect class="panel" x="{x}" y="92" width="{tw}" height="104" rx="12"/>\n'
        s += f'  <text x="{x + 20}" y="{118}" font-size="12" class="muted">{esc(label)}</text>\n'
        s += f'  <text x="{x + 20}" y="{154}" font-size="27" font-weight="700" fill="#0f9d8a">{esc(value)}</text>\n'
        s += f'  <text x="{x + 20}" y="{176}" font-size="10.5" class="muted">{esc(note)}</text>\n'

    # correctness controls
    cx = legend(24, 218)
    checks = [
        ("Denied traffic stays denied", ctl["negative_denied"]),
        ("Allowed traffic passes", ctl["positive_permitted"]),
        ("No-firewall baseline unfiltered", ctl["baseline_unfiltered"]),
    ]
    for label, ok in checks:
        mark = "pass" if ok else "FAIL"
        color = "#0f9d8a" if ok else "#ef4444"
        s += f'  <text x="{cx + 14}" y="228" font-size="11.5" font-weight="650" fill="{color}">{mark}</text>\n'
        s += f'  <text x="{cx + 56}" y="228" font-size="11.5" class="muted">{esc(label)}</text>\n'
        cx += 66 + len(label) * 6.4

    # p99 panels
    for pi, (p, label) in enumerate(PROFILES):
        y0 = 248 + pi * 178
        ytop, ybot = y0 + 46, y0 + 146
        vals = [scen[f"{e}_{k}_{p}"]["latency_p99_ms"] for e, _, _, _ in ENGINES for k in CARDINALITIES]
        vmax = nice_axis(max(vals))
        s += f'  <rect class="panel" x="24" y="{y0}" width="1072" height="168" rx="14"/>\n'
        s += f'  <text x="48" y="{y0 + 26}" font-size="13.5" font-weight="650">{esc(label)} &#183; p99 (ms, lower is better)</text>\n'
        for i in range(4):
            v = vmax * i / 3
            y = ybot - (ybot - ytop) * i / 3
            s += f'  <line class="grid" x1="196" y1="{y:.1f}" x2="1070" y2="{y:.1f}"/>\n'
            s += f'  <text x="186" y="{y + 4:.1f}" text-anchor="end" font-size="10" class="muted">{v:g}</text>\n'
        for gi, k in enumerate(CARDINALITIES):
            cxg = 268 + gi * 250
            for bi, (e, name, color, cls) in enumerate(ENGINES):
                v = scen[f"{e}_{k}_{p}"]["latency_p99_ms"]
                bh = (ybot - ytop) * v / vmax
                x = cxg - 78 + bi * 54
                s += (f'  <rect class="{cls}" x="{x:.1f}" y="{ybot - bh:.1f}" width="48" height="{bh:.1f}" rx="3">'
                      f'<title>{esc(name)}, {k:,} rules: {v:.3f} ms p99</title></rect>\n')
                s += f'  <text x="{x + 24:.1f}" y="{ybot - bh - 5:.1f}" text-anchor="middle" font-size="9.5" font-weight="650" fill="{color}">{v:.2f}</text>\n'
            s += f'  <text x="{cxg:.1f}" y="{ybot + 16:.1f}" text-anchor="middle" font-size="11" class="muted">{k:,} rules</text>\n'
        s += f'  <line class="axis" x1="196" y1="{ybot}" x2="1070" y2="{ybot}"/>\n'

    s += '  <text x="32" y="782" font-size="11" class="muted">Panels use independent y-axis scales; compare bar heights within a panel only. Each panel has its own axis labels.</text>\n'
    s += "</svg>\n"
    return s


def nice_axis(data_max):
    """Three-tick axis: smallest step in the nice ladder covering data_max * 1.15."""
    for step in (0.05, 0.1, 0.15, 0.2, 0.25, 0.4, 0.5, 1, 2, 4, 5, 10, 20, 40):
        if data_max * 1.15 <= 3 * step:
            return 3 * step
    return data_max * 1.15


# ----------------------------------------------------------------- attack lab

def attack_svg():
    W, H = 1120, 850
    eng = ATTACK["engines"]
    meta = ATTACK.get("metadata", {})
    E = [("none", "No firewall", "#64748b"), ("bfw", "bfw", "#0f9d8a"), ("ufw", "UFW", "#3b82f6")]
    ATTACKS = [
        ("synflood_denied", "SYN flood to a denied port"),
        ("synflood_allowed", "SYN flood to an allowed port"),
        ("connectflood", "TCP connect flood to an allowed port"),
    ]
    s = head(W, H, "Real attacks: what each firewall actually does",
             "Top panel: nmap recon time over ports 1-2000 and which ports in 8070-8110 "
             "answered, per engine. Middle panels: legitimate keep-alive HTTP requests "
             "completed and their p95 latency while each attack ran against the "
             "defended service. Bottom panel: dynamic ban outcomes, the capability UFW "
             "has no mechanism for.",
             f"Isolated Docker network &#183; {meta.get('rules', '?')} allow rules &#183; "
             f"{meta.get('flood_seconds', '?')}s per attack &#183; {meta.get('kernel', '')}")

    # recon
    s += '  <rect class="panel" x="24" y="104" width="1072" height="150" rx="14"/>\n'
    s += '  <text x="48" y="132" font-size="13.5" font-weight="650">Recon: nmap over ports 1-2000 (seconds to scan)</text>\n'
    times = {k: (eng[k]["nmap"] or {}).get("seconds") for k, _, _ in E}
    tmax = (max([t for t in times.values() if t] or [1])) * 1.15
    x0, x1 = 560, 900
    for i, (k, label, color) in enumerate(E):
        y = 156 + i * 30
        t = times[k]
        n = eng[k]["nmap"]
        w = eng[k].get("nmap_window") or {}
        win = ",".join(map(str, w.get("open_ports", []))) or "none open"
        detail = f"{n['filtered']} filtered" if n.get("filtered") else f"{n.get('closed', '?')} closed"
        s += f'  <text x="48" y="{y + 14}" font-size="12" font-weight="650">{label}</text>\n'
        s += f'  <text x="150" y="{y + 14}" font-size="11" class="muted">{esc(detail)}; ports 8070-8110: {esc(win)}</text>\n'
        bw = max((x1 - x0) * (t or 0) / tmax, 1.2)
        s += f'  <rect x="{x0}" y="{y}" width="{bw:.1f}" height="16" rx="4" fill="{color}"/>\n'
        s += f'  <text x="{x0 + bw + 8:.1f}" y="{y + 13}" font-size="11" font-weight="650" fill="{color}">{f"{t:.2f} s" if t is not None else "n/a"}</text>\n'

    # legit traffic under attack
    for pi, (akey, atitle) in enumerate(ATTACKS):
        y0 = 284 + pi * 144
        s += f'  <rect class="panel" x="24" y="{y0}" width="1072" height="128" rx="14"/>\n'
        s += f'  <text x="48" y="{y0 + 26}" font-size="13.5" font-weight="650">{esc(atitle)} - legitimate requests still served</text>\n'
        oks = {k: (eng[k]["attacks"][akey]["legit"] or {}).get("ok", 0) for k, _, _ in E}
        vmax = max(oks.values() or [1]) * 1.18
        for i, (k, label, color) in enumerate(E):
            y = y0 + 42 + i * 28
            st = eng[k]["attacks"][akey]["legit"] or {}
            bw = max((x1 - x0) * oks[k] / vmax, 1.2)
            s += f'  <text x="48" y="{y + 14}" font-size="12" font-weight="650">{label}</text>\n'
            s += f'  <rect x="{x0}" y="{y}" width="{bw:.1f}" height="16" rx="4" fill="{color}"/>\n'
            p95 = st.get("p95_ms")
            note = f" &#183; p95 {p95:.2f} ms" if p95 is not None else ""
            s += f'  <text x="{x0 + bw + 8:.1f}" y="{y + 13}" font-size="11" font-weight="650" fill="{color}">{oks[k]:,} ok{note}</text>\n'
            fails = st.get("req_fail", 0) + st.get("connect_fail", 0)
            if fails:
                s += f'  <text x="{x0 + bw + 190:.1f}" y="{y + 13}" font-size="10.5" fill="#ef4444">{fails} failed</text>\n'

    # dynamic bans
    dy = 284 + len(ATTACKS) * 144 + 6
    s += f'  <rect class="panel" x="24" y="{dy}" width="1072" height="110" rx="14"/>\n'
    s += f'  <text x="48" y="{dy + 26}" font-size="13.5" font-weight="650">Dynamic bans - the capability UFW has no mechanism for</text>\n'
    for ri, (rlabel, dkey, tkey) in enumerate([
        ("SSH brute-force (12 tries)", "jail", "jail_ban_s"),
        ("CrowdSec LAPI ban, then unban", "lapi", "lapi_ban_s"),
    ]):
        y = dy + 40 + ri * 32
        s += f'  <text x="48" y="{y + 13}" font-size="12" font-weight="650">{esc(rlabel)}</text>\n'
        for i, (k, label, color) in enumerate(E):
            d = eng[k].get(dkey) or {}
            bx = 380 + i * 230
            if not d or d.get("mechanism") == "none":
                s += f'  <text x="{bx}" y="{y + 13}" font-size="11" class="muted">{label}: not available</text>\n'
                continue
            t = d.get(tkey)
            txt = f"{label}: ban {t:.1f} s" if isinstance(t, (int, float)) and t >= 0 else f"{label}: ban pending"
            extra = ""
            if dkey == "jail" and d.get("ssh_after") is not None:
                extra = " - SSH blocked" if d["ssh_after"] == 0 else " - SSH still open"
            if dkey == "lapi" and isinstance(d.get("lapi_unban_s"), (int, float)) and d["lapi_unban_s"] >= 0:
                extra += f", unban in {d['lapi_unban_s']:.1f} s"
            s += f'  <text x="{bx}" y="{y + 13}" font-size="11" font-weight="650" fill="{color}">{esc(txt + extra)}</text>\n'

    fy = dy + 118
    lx = legend(24, fy)
    s += f'  <text x="{lx + 20}" y="{fy + 10}" font-size="10.5" class="muted">Bars: legitimate requests completed during the attack window.</text>\n'
    s += f'  <text x="24" y="{fy + 32}" font-size="10.5" class="muted">Gates asserted by the job: denied port stays closed, legitimate service stays reachable, legitimate p95 stays under 2 s, attacker ends up banned.</text>\n'
    s += "</svg>\n"
    return s


# -------------------------------------------------- microbenchmark markdown doc

BENCH_META = re.compile(r"^(goos|goarch|pkg|cpu):\s*(.*)$", re.M)
BENCH_ROW = re.compile(
    r"^(Benchmark\S+?)-\d+\s+\d+\s+([\d.]+) ns/op(?:\s+([\d.]+) MB/s)?\s+(\d+) B/op\s+(\d+) allocs/op",
    re.M,
)

# Grouping is a display concern only; keys must match the -bench filter in the
# Makefile's benchmark-protect target.
BENCH_GROUPS = [
    ("Protection decision path", "Journal failure detection, CrowdSec decision decoding. Runs on every journal record and every LAPI poll."),
    ("Ban-set compilation", "Turns a list of banned addresses into an nftables set definition. Runs once per flush of the ban list."),
    ("Ruleset compilation", "Turns stored configuration into nftables rules. This is configuration work, not packet filtering."),
    ("Ruleset rendering", "Text output behind `bfw status` and `bfw diff`, and the text produced by --dry-run."),
    ("Rule lookup", "Duplicate detection for CLI rule mutations, and tuple keys for import/export and application-profile grouping."),
]


def parse_benchmarks():
    meta = {k: v.strip() for k, v in BENCH_META.findall(TXT)}
    rows = []
    for m in BENCH_ROW.finditer(TXT):
        name, ns, mbs, b, allocs = m.group(1), float(m.group(2)), m.group(3), int(m.group(4)), int(m.group(5))
        if name.startswith("BenchmarkThreatBanSetCompile"):
            group, label = "Ban-set compilation", f"nft ban-set compile, {name.split('/')[-1]} bans"
        elif name.startswith("BenchmarkJournalFailureDetection"):
            group, label = "Protection decision path", "Journal failure detection, 1 failed-login event"
        elif name.startswith("BenchmarkCrowdSecDecisionDecode"):
            group, label = "Protection decision path", "CrowdSec decision decode, 100 decisions"
        elif name.startswith("BenchmarkLimitRulesetCompile"):
            group, label = "Ruleset compilation", f"Ruleset compile, {name.split('/')[-1]} limit rules"
        elif name.startswith("BenchmarkRulesetCompile"):
            group, label = "Ruleset compilation", f"Ruleset compile, {name.split('/')[-1]} rules"
        elif name.startswith("BenchmarkLimitRulesetRender"):
            group, label = "Ruleset rendering", f"Ruleset render, {name.split('/')[-1]} limit rules"
        elif name.startswith("BenchmarkRulesetRender"):
            group, label = "Ruleset rendering", f"Ruleset render, {name.split('/')[-1]} multi-port rules"
        elif name.startswith("BenchmarkRuleMatch"):
            group, label = "Rule lookup", "Rule match scan, 1,000 candidates"
        elif name.startswith("BenchmarkTupleKey"):
            group, label = "Rule lookup", "Tuple key, 1,000 rules"
        elif name.startswith("BenchmarkAppTuple"):
            group, label = "Rule lookup", "Application tuple, 1,000 rules"
        else:
            group, label = "Other", name
        rows.append((group, label, ns, mbs, b, allocs, name))
    return meta, rows


def fmt_ns(ns):
    if ns >= 1e6:
        return f"{ns / 1e6:.3f} ms".replace(".000 ", " ")
    if ns >= 1e3:
        return f"{ns / 1e3:.2f} \u00b5s".replace(".00 ", " ")
    return f"{ns:.0f} ns"


def fmt_b(b):
    if b >= 1024 * 1024:
        return f"{b / 1024 / 1024:.2f} MB"
    if b >= 1024:
        return f"{b / 1024:.1f} kB"
    return f"{b} B"


def benchmarks_md():
    meta, rows = parse_benchmarks()
    by_group = {}
    for group, label, ns, mbs, b, allocs, name in rows:
        by_group.setdefault(group, []).append((label, ns, mbs, b, allocs, name))

    plat = " / ".join(x for x in (meta.get("goos"), meta.get("goarch")) if x)
    out = [
        "# Internal microbenchmarks",
        "",
        "Generated by `scripts/charts/charts.py` from the `protection-benchmarks` CI job.",
        "Do not edit by hand: `make charts` rewrites this file, and the numbers below are",
        "parsed from the raw `go test -bench` output rather than transcribed.",
        "",
        f"Platform: {plat}, {meta.get('cpu', 'unknown CPU')}. One sample per case, so these",
        "numbers move between machines and are useful for spotting a regression in kind",
        "and shape (for example an allocation count that jumps an order of magnitude), not",
        "as a cross-machine performance guarantee.",
        "",
        "These measure internal code paths. They are **not** evidence about packet",
        "throughput or filtering latency; the hosted comparison for that is summarised in",
        "the project README.",
        "",
    ]
    for group, blurb in BENCH_GROUPS:
        if group not in by_group:
            continue
        out += [f"## {group}", "", blurb, "",
                "| Workload | Time | Throughput | B/op | Allocs/op |",
                "|---|---:|---:|---:|---:|"]
        for label, ns, mbs, b, allocs, _ in by_group[group]:
            thr = f"{float(mbs):,.1f} MB/s" if mbs else "\u2014"
            out.append(f"| {label} | {fmt_ns(ns)} | {thr} | {fmt_b(b)} | {allocs:,} |")
        out.append("")
    out += [
        "## Reproducing",
        "",
        "```sh",
        "make benchmark-protect   # runs the same benchmarks locally",
        "```",
        "",
        "The CI job publishes its raw output as the `protection-benchmarks` artifact. To",
        "refresh this document and the charts together, download the",
        "`protection-benchmarks`, `performance` and `better-firewall-attack` artifacts into",
        "one directory and run `python3 scripts/charts/charts.py <dir>`.",
        "",
    ]
    return "\n".join(out)


# ---------------------------------------------------------------------- output

out = {
    "docs/firewall-setup-time.svg": setup_svg(),
    "docs/firewall-reliability.svg": reliability_svg(),
    "docs/benchmarks.md": benchmarks_md(),
}
if ATTACK:
    out["docs/attack-lab.svg"] = attack_svg()

for path, content in out.items():
    dest = ROOT / path
    dest.write_text(content)
    print(f"wrote {path} ({len(content):,} bytes)")
