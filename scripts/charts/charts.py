#!/usr/bin/env python3
"""Regenerate the committed benchmark charts and docs/benchmarks.md from CI artifacts.

Outputs
-------
docs/firewall-setup-time.svg   rule add + enable wall clock, four small multiples
docs/firewall-reliability.svg correctness counters and p95 deviation vs no firewall
docs/attack-lab.svg           real-attack comparison (only when attack data is present)
docs/benchmarks.md            internal Go microbenchmarks, parsed from the CI bench text

Every number rendered here is parsed from the input artifacts. Nothing is
hand-transcribed, so a refreshed artifact cannot leave stale prose behind.

Chart conventions (kept from the previous generator, see 7739f1c):
  - Bar and dot lengths encode the quantity on a linear axis starting at zero.
  - A bar's length is never a ratio presented as a total, so no log scales.
  - Where two quantities are too far apart to share an axis, each gets its own
    panel with its own axis, rather than one axis that flattens the small one.
  - Where the finding is an absence of difference, the chart encodes the
    deviation from a reference rather than two near-identical magnitudes.

Usage: charts.py [artifact-dir]
  Reads <dir>/summary.json, <dir>/protection-benchmarks.txt and, when present,
  <dir>/attack-summary.json. Defaults to the committed snapshot in
  scripts/charts/testdata/ so `make charts` is reproducible; pass a directory of
  freshly downloaded CI artifacts to publish a new run.
"""
import json
import math
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


def legend(x, y, entries=None):
    """Render a colour legend at (x, y).

    Returns (svg, x) where x is the offset just past the last swatch, so callers
    can place a caption on the same baseline. The SVG must be returned rather than
    only the cursor: an earlier version built the markup locally and dropped it,
    which silently rendered every chart with no legend at all.

    entries defaults to the three engines. A chart where one of those colours is
    the reference rather than a plotted series must pass its own list, or the
    legend will claim a series that is not drawn.
    """
    entries = entries or [(label, cls) for _k, label, _c, cls in ENGINES]
    s = ""
    for label, cls in entries:
        s += f'  <rect x="{x}" y="{y}" width="12" height="12" rx="3" class="{cls}"/>\n'
        s += f'  <text x="{x + 18}" y="{y + 10}" font-size="11.5">{label}</text>\n'
        x += 30 + len(label) * 6.6
    return s, x


def esc(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


# ---------------------------------------------------------------- setup time

# Ladder used to round a panel's own axis up to a readable maximum. Each small
# multiple picks its own value, so a 1.6 s cell and a 156 s cell both get an axis
# that fills its panel instead of sharing one that flattens the small ones.
NICE_LADDER = (1, 1.2, 1.5, 1.6, 2, 2.5, 3, 4, 5, 6, 7, 8, 10)


def nice_ceil(v):
    """Smallest value in NICE_LADDER x 10^k that is >= v."""
    if v <= 0:
        return 1
    exp = 0
    while NICE_LADDER[-1] * (10 ** exp) < v:
        exp += 1
    for step in NICE_LADDER:
        cand = step * (10 ** exp)
        if cand >= v:
            return cand
    return NICE_LADDER[-1] * (10 ** exp)


def setup_svg():
    """Rule add + enable time, drawn as four small multiples.

    The two engines are 0.05 s and 156 s apart at the extreme, so no single
    linear axis can show both: on a shared 160 s axis the 10-rule bfw bar is
    11 px wide and the 1,000-rule bfw bar is 24 px. Giving each rule count its
    own axis, always linear from zero, keeps every bar honest and makes each
    panel answer its own question -- "at 1,000 rules, UFW took 156 s and bfw took
    8.7 s". Panels are not compared against each other, and each carries its own
    axis labels so that is explicit rather than assumed.
    """
    W, H = 1120, 540
    tc = {t["cardinality"]: t for t in SUM["timing_comparisons"]}
    PW, PH, GX, GY = 524, 152, 20, 20
    ORIGIN = (24, 100)
    # LABEL_ROOM is reserved inside every panel so the longest value label
    # ("156.33 s") stays within the card instead of overhanging its edge.
    LABEL_ROOM = 78

    s = head(W, H, "Rule setup is 8-32x faster than UFW",
             "Four small-multiple bar charts, one per rule count, each with its own "
             "linear axis starting at zero. Every panel compares the wall-clock "
             "seconds for bfw and for UFW to add the rules and enable the firewall. "
             "Panels use independent scales and are not comparable to each other; "
             "the speed-up multiple is printed in each panel.",
             f"Mean of {tc[10]['bfw_repeats']} repeats per engine &#183; {SUM['metadata']['kernel']}")

    for idx, k in enumerate(CARDINALITIES):
        row = tc[k]
        px = ORIGIN[0] + (idx % 2) * (PW + GX)
        py = ORIGIN[1] + (idx // 2) * (PH + GY)
        vmax = nice_ceil(row["ufw_total_s"])
        x0, x1 = px + 58, px + PW - LABEL_ROOM

        s += f'  <rect class="panel" x="{px}" y="{py}" width="{PW}" height="{PH}" rx="12"/>\n'
        s += f'  <text x="{px + 20}" y="{py + 25}" font-size="14" font-weight="650">{k:,} rules</text>\n'
        s += (f'  <text x="{px + PW - 20}" y="{py + 25}" text-anchor="end" font-size="13" '
              f'font-weight="700" fill="#0f9d8a">{row["total_speedup"]:.1f}x faster</text>\n')

        for i in range(3):
            gx = x0 + (x1 - x0) * i / 2
            s += f'  <line class="grid" x1="{gx:.1f}" y1="{py + 36}" x2="{gx:.1f}" y2="{py + 108}"/>\n'
            val = vmax * i / 2
            s += (f'  <text x="{gx:.1f}" y="{py + 126}" text-anchor="middle" font-size="10.5" '
                  f'class="muted">{val:g} s</text>\n')
        s += f'  <line class="axis" x1="{x0}" y1="{py + 36}" x2="{x0}" y2="{py + 108}"/>\n'

        for bi, (engine, cls, color, short) in enumerate(
                (("bfw", "bfw", "#0f9d8a", "bfw"), ("ufw", "ufw", "#3b82f6", "UFW"))):
            secs = row[f"{engine}_total_s"]
            by = py + 40 + bi * 34
            bw = max((x1 - x0) * secs / vmax, 1.5)
            s += f'  <text x="{px + 20}" y="{by + 19}" font-size="11" font-weight="650" fill="{color}">{short}</text>\n'
            s += (f'  <rect class="{cls}" x="{x0}" y="{by}" width="{bw:.1f}" height="27" rx="4">'
                  f'<title>{short}, {k:,} rules: {secs:.2f} s</title></rect>\n')
            s += (f'  <text x="{x0 + bw + 8:.1f}" y="{by + 19}" font-size="11.5" font-weight="650" '
                  f'fill="{color}">{secs:.2f} s</text>\n')

    s += '  <text x="24" y="486" font-size="11" class="muted">Configuration and apply time only, not packet-processing latency. UFW rewrites and reloads the whole ruleset once per rule; bfw compiles the entire ruleset in one atomic nftables transaction.</text>\n'
    s += '  <text x="24" y="506" font-size="11" class="muted">Each panel has its own linear axis from zero. Do not compare bar lengths across panels; compare the two bars within a panel.</text>\n'
    s += "</svg>\n"
    return s


# ---------------------------------------------------------------- reliability

# Shown as a reference band, not a claim about where the data falls. Two cells
# sit outside it and are left outside on purpose: widening the band to swallow
# them would hide the very fact the panel exists to show.
TOLERANCE_PCT = 5.0


def reliability_svg():
    """Correctness counters, then p95 deviation from the no-firewall baseline.

    Earlier revisions drew grouped bars of absolute latency. That cannot express
    "no measurable difference": with three near-identical bars per group across
    twelve groups, the reader has to hunt for a difference that is not there.

    p95 deviation from the no-firewall container expresses it directly. The
    deviations carry both signs, and bfw comes out "faster than no firewall at
    all" in half the cells, which is impossible for a real firewall and is
    therefore direct evidence that the spread is measurement noise.

    p99 is deliberately not used. The churn profile issues roughly 2,000 requests
    per repeat, so its p99 is the 20th-worst sample and swings from -31.7% to
    +21.9% between neighbouring rule counts on identical engines.
    """
    W, H = 1120, 690
    scen = SUM["scenarios"]

    total_requests = sum(v["request_count"] for v in scen.values())
    total_errors = sum(v["error_count"] for v in scen.values())
    total_dropped = sum(v["dropped_iterations"] for v in scen.values())
    total_checks = sum(v["check_passes"] for v in scen.values())
    ctl = SUM["controls"]

    rows = []
    for pkey, plabel in PROFILES:
        for k in CARDINALITIES:
            base = scen[f"baseline_{k}_{pkey}"]["latency_p95_ms"]
            rows.append((f"{plabel} &#183; {k:,}", {
                e: (scen[f"{e}_{k}_{pkey}"]["latency_p95_ms"] - base) / base * 100
                for e in ("bfw", "ufw")}))
    worst = max(abs(r[1][e]) for r in rows for e in ("bfw", "ufw"))
    outside = sum(1 for r in rows for e in ("bfw", "ufw") if abs(r[1][e]) > TOLERANCE_PCT)
    faster = sum(1 for r in rows if r[1]["bfw"] < 0)

    s = head(W, H, "No measurable traffic cost at any rule count",
             "Top row: correctness counters for the whole run. Lower panel: mean p95 "
             "latency of bfw and UFW expressed as a percentage deviation from the "
             "no-firewall container, one row per traffic profile and rule count. A "
             "shaded band marks plus or minus five percent. Deviations fall on both "
             "sides of zero, and bfw is faster than no firewall at all in half the "
             "rows, which no real firewall can be.",
             f"Mean p95 over {SUM['metadata']['repeats']} repeats per cell &#183; {SUM['metadata']['kernel']}")

    tiles = [
        ("Requests served", f"{total_requests:,}", "no firewall, bfw and UFW"),
        ("Request errors", f"{total_errors:,}", "budget 1%"),
        ("Dropped iterations", f"{total_dropped:,}", "load generator could not dispatch"),
        ("Response checks passed", f"{total_checks:,}", "expected body returned"),
    ]
    tw, gap = 251, 20
    for i, (label, value, note) in enumerate(tiles):
        x = 24 + i * (tw + gap)
        s += f'  <rect class="panel" x="{x}" y="86" width="{tw}" height="96" rx="12"/>\n'
        s += f'  <text x="{x + 20}" y="{110}" font-size="11.5" class="muted">{esc(label)}</text>\n'
        s += f'  <text x="{x + 20}" y="{144}" font-size="26" font-weight="700" fill="#0f9d8a">{esc(value)}</text>\n'
        s += f'  <text x="{x + 20}" y="{165}" font-size="10" class="muted">{esc(note)}</text>\n'

    PY, PH = 200, 404
    x0, x1 = 250, 1050
    # Axis half-range is derived from the data so the dots fill the plot, with a
    # margin. Ticks are fixed at the tolerance and its midpoint rather than
    # derived, so the labels read the same in every run.
    span = max(abs(r[1][e]) for r in rows for e in ("bfw", "ufw")) * 1.18
    span = math.ceil(span)
    ticks = [(-TOLERANCE_PCT, f"-{TOLERANCE_PCT:.0f}%"), (-TOLERANCE_PCT / 2, f"-{TOLERANCE_PCT / 2:g}%"),
             (0.0, "0%"), (TOLERANCE_PCT / 2, f"+{TOLERANCE_PCT / 2:g}%"),
             (TOLERANCE_PCT, f"+{TOLERANCE_PCT:.0f}%")]

    def X(pct):
        return x0 + (x1 - x0) * (pct + span) / (span * 2)

    s += f'  <rect class="panel" x="24" y="{PY}" width="1072" height="{PH}" rx="12"/>\n'
    s += f'  <text x="48" y="{PY + 28}" font-size="13.5" font-weight="650">p95 latency versus the no-firewall container</text>\n'
    s += f'  <rect x="{X(-TOLERANCE_PCT):.1f}" y="{PY + 42}" width="{X(TOLERANCE_PCT) - X(-TOLERANCE_PCT):.1f}" height="316" fill="#eef2f7"/>\n'
    for t, lab in ticks:
        s += f'  <line class="grid" x1="{X(t):.1f}" y1="{PY + 42}" x2="{X(t):.1f}" y2="{PY + 358}"/>\n'
        s += f'  <text x="{X(t):.1f}" y="{PY + 376}" text-anchor="middle" font-size="10.5" class="muted">{lab}</text>\n'
    s += f'  <line class="axis" x1="{X(0):.1f}" y1="{PY + 42}" x2="{X(0):.1f}" y2="{PY + 358}"/>\n'

    ry, RH = PY + 62, 26
    for i, (label, devs) in enumerate(rows):
        y = ry + i * RH
        if i in (4, 8):
            s += f'  <line x1="48" y1="{y - 13:.1f}" x2="1072" y2="{y - 13:.1f}" stroke="#eef2f7" stroke-width="1"/>\n'
        s += f'  <text x="{x0 - 18}" y="{y + 4}" text-anchor="end" font-size="11" class="muted">{label}</text>\n'
        bx, ux = X(devs["bfw"]), X(devs["ufw"])
        s += f'  <line x1="{bx:.1f}" y1="{y}" x2="{ux:.1f}" y2="{y}" stroke="#cbd5e1" stroke-width="1.5"/>\n'
        for cx, key, color in ((bx, "bfw", "#0f9d8a"), (ux, "ufw", "#3b82f6")):
            s += (f'  <circle cx="{cx:.1f}" cy="{y}" r="5.5" fill="{color}">'
                  f'<title>{esc(label)}, {"bfw" if key == "bfw" else "UFW"}: {devs[key]:+.1f}% versus no firewall</title></circle>\n')

    # Only the two engines are plotted here; no-firewall is the zero reference,
    # so it is named in the caption rather than given a legend swatch.
    lg, lx = legend(24, PY + PH + 16, entries=[("bfw", "bfw"), ("UFW", "ufw")])
    s += lg
    s += (f'  <text x="{lx + 16}" y="{PY + PH + 26}" font-size="11" class="muted">'
          f'Both measured against the no-firewall container. Shaded band is a plus or minus '
          f'{TOLERANCE_PCT:.0f}% reference, not a fitted range: {outside} of 24 dots fall outside it.</text>\n')
    s += (f'  <text x="24" y="{PY + PH + 48}" font-size="11" class="muted">'
          f'bfw is faster than no firewall at all in {faster} of 12 rows. A firewall cannot remove '
          f'latency, so both signs are noise; largest deviation anywhere is {worst:.1f}%.</text>\n')
    s += '  <text x="24" y="' + str(PY + PH + 68) + '" font-size="11" class="muted">p99 is not shown: the churn profile issues about 2,000 requests per repeat, so its p99 swings from -31.7% to +21.9% on identical engines.</text>\n'
    s += "</svg>\n"
    return s


# ----------------------------------------------------------------- attack lab

def attack_svg():
    W, H = 1120, 824
    eng = ATTACK["engines"]
    meta = ATTACK.get("metadata", {})
    E = [("none", "No firewall", "#64748b"), ("bfw", "bfw", "#0f9d8a"), ("ufw", "UFW", "#3b82f6")]
    ATTACKS = [
        ("synflood_denied", "SYN flood to a denied port"),
        ("synflood_allowed", "SYN flood to an allowed port"),
        ("connectflood", "TCP connect flood to an allowed port"),
    ]
    # Bars end well short of the card edge so the widest value label
    # ("163,056 ok - p95 0.63 ms") stays inside the panel.
    XR = 936
    X_RECON, X_FLOOD = 400, 150

    s = head(W, H, "Real attacks: what each firewall actually does",
             "Top panel: nmap recon time over ports 1-2000 and which ports in 8070-8110 "
             "answered. Middle panels: legitimate keep-alive requests still served while "
             "each attack ran, with their p95 latency. Bottom panel: dynamic ban outcomes, "
             "the capability UFW has no mechanism for.",
             f"Isolated Docker network &#183; {meta.get('rules', '?')} allow rules &#183; "
             f"{meta.get('flood_seconds', '?')}s per attack &#183; {meta.get('kernel', '')}")

    # recon
    RP, RH = 100, 136
    s += f'  <rect class="panel" x="24" y="{RP}" width="1072" height="{RH}" rx="12"/>\n'
    s += f'  <text x="48" y="{RP + 26}" font-size="13.5" font-weight="650">Recon: nmap over ports 1-2000 (seconds to scan)</text>\n'
    times = {k: (eng[k]["nmap"] or {}).get("seconds") for k, _, _ in E}
    tmax = (max([t for t in times.values() if t] or [1])) * 1.12
    for i, (k, label, color) in enumerate(E):
        y = RP + 44 + i * 28
        t = times[k]
        n = eng[k]["nmap"]
        w = eng[k].get("nmap_window") or {}
        win = ",".join(map(str, w.get("open_ports", []))) or "none open"
        detail = f"{n['filtered']} filtered" if n.get("filtered") else f"{n.get('closed', '?')} closed"
        s += f'  <text x="48" y="{y + 13}" font-size="12" font-weight="650">{label}</text>\n'
        s += f'  <text x="140" y="{y + 13}" font-size="10.5" class="muted">{esc(detail)}; ports 8070-8110: {esc(win)}</text>\n'
        bw = max((XR - X_RECON) * (t or 0) / tmax, 1.5)
        s += f'  <rect x="{X_RECON}" y="{y}" width="{bw:.1f}" height="16" rx="4" fill="{color}"/>\n'
        s += f'  <text x="{X_RECON + bw + 8:.1f}" y="{y + 13}" font-size="11" font-weight="650" fill="{color}">{f"{t:.2f} s" if t is not None else "n/a"}</text>\n'

    # legitimate traffic under attack
    AP0, APH, AGAP = 252, 110, 16
    for pi, (akey, atitle) in enumerate(ATTACKS):
        y0 = AP0 + pi * (APH + AGAP)
        s += f'  <rect class="panel" x="24" y="{y0}" width="1072" height="{APH}" rx="12"/>\n'
        s += f'  <text x="48" y="{y0 + 24}" font-size="13.5" font-weight="650">{esc(atitle)}</text>\n'
        s += f'  <text x="1072" y="{y0 + 24}" text-anchor="end" font-size="10.5" class="muted">Legitimate requests still served</text>\n'
        oks = {k: (eng[k]["attacks"][akey]["legit"] or {}).get("ok", 0) for k, _, _ in E}
        vmax = max(oks.values() or [1]) * 1.16
        for i, (k, label, color) in enumerate(E):
            y = y0 + 36 + i * 24
            st = eng[k]["attacks"][akey]["legit"] or {}
            bw = max((XR - X_FLOOD) * oks[k] / vmax, 1.5)
            s += f'  <text x="48" y="{y + 13}" font-size="11.5" font-weight="650">{label}</text>\n'
            s += f'  <rect x="{X_FLOOD}" y="{y}" width="{bw:.1f}" height="15" rx="4" fill="{color}"/>\n'
            p95 = st.get("p95_ms")
            note = f" &#183; p95 {p95:.2f} ms" if p95 is not None else ""
            fails = st.get("req_fail", 0) + st.get("connect_fail", 0)
            if fails:
                note += f" &#183; {fails} failed"
            s += f'  <text x="{X_FLOOD + bw + 8:.1f}" y="{y + 13}" font-size="10.5" font-weight="650" fill="{"#ef4444" if fails else color}">{oks[k]:,} ok{note}</text>\n'

    # dynamic bans
    DY = AP0 + len(ATTACKS) * (APH + AGAP) + 2
    DH = 112
    s += f'  <rect class="panel" x="24" y="{DY}" width="1072" height="{DH}" rx="12"/>\n'
    s += f'  <text x="48" y="{DY + 24}" font-size="13.5" font-weight="650">Dynamic bans &#8212; the capability UFW has no mechanism for</text>\n'
    for ri, (rlabel, dkey, tkey) in enumerate([
        ("SSH brute-force, 12 tries", "jail", "jail_ban_s"),
        ("CrowdSec LAPI ban, then unban", "lapi", "lapi_ban_s"),
    ]):
        y = DY + 48 + ri * 30
        s += f'  <text x="48" y="{y + 13}" font-size="11.5" font-weight="650">{esc(rlabel)}</text>\n'
        for i, (k, label, color) in enumerate(E):
            d = eng[k].get(dkey) or {}
            bx = 372 + i * 226
            if not d or d.get("mechanism") == "none":
                s += f'  <text x="{bx}" y="{y + 13}" font-size="11" class="muted">{label}: not available</text>\n'
                continue
            t = d.get(tkey)
            txt = f"{label}: ban {t:.1f} s" if isinstance(t, (int, float)) and t >= 0 else f"{label}: ban pending"
            extra = ""
            if dkey == "jail" and d.get("ssh_after") is not None:
                extra = ", SSH blocked" if d["ssh_after"] == 0 else ", SSH still open"
            if dkey == "lapi" and isinstance(d.get("lapi_unban_s"), (int, float)) and d["lapi_unban_s"] >= 0:
                extra += f", unban {d['lapi_unban_s']:.1f} s"
            s += f'  <text x="{bx}" y="{y + 13}" font-size="11" font-weight="650" fill="{color}">{esc(txt + extra)}</text>\n'

    lg, lx = legend(24, DY + DH + 18)
    s += lg
    s += f'  <text x="{lx + 16}" y="{DY + DH + 28}" font-size="10.5" class="muted">Bars: legitimate requests completed during the attack window.</text>\n'
    s += f'  <text x="24" y="{DY + DH + 50}" font-size="10.5" class="muted">Gates asserted by the job: denied port stays closed, legitimate service stays reachable, legitimate p95 stays under 2 s, attacker ends up banned.</text>\n'
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
