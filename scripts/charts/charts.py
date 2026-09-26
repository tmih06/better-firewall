#!/usr/bin/env python3
"""Regenerate docs/*.svg benchmark charts from CI run artifacts.

Style replicates the committed charts (Inter/system font, #172554 text,
panel cards, dot plots with parity line, grouped horizontal/vertical bars).

Usage: charts.py [testdata-dir]
  Reads <testdata-dir>/summary.json (performance job artifact) and
  <testdata-dir>/protection-benchmarks.txt (bench output). Defaults to the
  committed snapshot in scripts/charts/testdata/ so `make charts` is
  reproducible; point it at freshly downloaded CI artifacts to publish a
  new run.
"""
import json, math, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent / "testdata"
SUM = json.load(open(DATA / "summary.json"))
TXT = (DATA / "protection-benchmarks.txt").read_text()
ATTACK = json.load(open(DATA / "attack-summary.json")) if (DATA / "attack-summary.json").exists() else None

STYLE = """  <style>
    text { font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; fill: #172554; }
    .muted { fill: #64748b; }
    .panel { fill: #ffffff; stroke: #dbe4f0; stroke-width: 1; }
    .grid { stroke: #e2e8f0; stroke-width: 1; }
    .axis { stroke: #94a3b8; stroke-width: 1.2; }
    .parity { stroke: #334155; stroke-width: 1.4; stroke-dasharray: 5 4; }
    .base { fill: #64748b; }
    .bfw { fill: #0f9d8a; }
    .ufw { fill: #3b82f6; }
    .peak { fill-opacity: 0.42; }
    .prev { fill: #cbd5e1; }
  </style>"""

def head(w, h, title, desc, subtitle):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-labelledby="title desc">\n'
            f'  <title id="title">{title}</title>\n'
            f'  <desc id="desc">{desc}</desc>\n{STYLE}\n'
            f'  <rect width="{w}" height="{h}" fill="#f1f5f9"/>\n'
            f'  <text x="32" y="38" font-size="24" font-weight="700">{title}</text>\n'
            f'  <text x="32" y="62" font-size="13" class="muted">{subtitle}</text>\n')

def fmt_k(n):
    return f"{n:,.0f}".replace(",", " ") if n >= 10000 else f"{n:,}"

def fmt_bytes(b):
    if b >= 1024*1024: return f"{b/1024/1024:.3g} MB".replace('.0 ', ' ')
    if b >= 1024: return f"{b/1024:.1f} kB"
    return f"{b:.0f} B"

def fmt_time(ns):
    if ns >= 1e6:
        s = f"{ns/1e6:.3f}".rstrip('0').rstrip('.')
        return f"{s} ms"
    if ns >= 1e3:
        s = f"{ns/1e3:.2f}".rstrip('0').rstrip('.')
        return f"{s} µs"
    return f"{ns:.0f} ns"

# ---------- parse protection-benchmarks.txt ----------
prot = {}
for m in re.finditer(r"BenchmarkThreatBanSetCompile/(\d+)-\d+\s+\d+\s+([\d.]+) ns/op\s+(\d+) B/op\s+(\d+) allocs/op", TXT):
    n = int(m.group(1))
    prot[f"ban{n}"] = (float(m.group(2)), int(m.group(3)), int(m.group(4)))

CASES = [
    ("Journal failure detector", "one failed-login event", "JournalFailureDetection", "#0f9d8a"),
    ("CrowdSec JSON decode", "100 decisions", "CrowdSecDecisionDecode", "#3b82f6"),
    ("nft ban-set compile", "100 bans", "ban100", "#8b5cf6"),
    ("nft ban-set compile", "1,000 bans", "ban1000", "#f59e0b"),
    ("nft ban-set compile", "10,000 bans", "ban10000", "#ef4444"),
]
# Previous CI run values (old committed chart, pre-optimization).
PREV = {
    "JournalFailureDetection": (0.905e3, 122, 2),
    "CrowdSecDecisionDecode": (56.86e3, 26085, 119),
    "ban100": (78.20e3, 204369, 2470),
    "ban1000": (0.347e6, 1138708, 6980),
    "ban10000": (8.039e6, 17119158, 52005),
}

prot = {}
for m in re.finditer(r"Benchmark(JournalFailureDetection|CrowdSecDecisionDecode)-\d+\s+\d+\s+([\d.]+) ns/op(?:\s+[\d.]+ MB/s)?\s+(\d+) B/op\s+(\d+) allocs/op", TXT):
    prot[m.group(1)] = (float(m.group(2)), int(m.group(3)), int(m.group(4)))
for m in re.finditer(r"BenchmarkThreatBanSetCompile/(\d+)-\d+\s+\d+\s+([\d.]+) ns/op\s+(\d+) B/op\s+(\d+) allocs/op", TXT):
    prot[f"ban{m.group(1)}"] = (float(m.group(2)), int(m.group(3)), int(m.group(4)))

def panel_grid(x0, x1, ytop, ybot, ticks):
    out = []
    for t, lab, anchor in ticks:
        x = x0 + (x1 - x0) * t
        out.append(f'  <line class="grid" x1="{x:.1f}" y1="{ytop}" x2="{x:.1f}" y2="{ybot}"/>')
        out.append(f'  <text x="{x:.1f}" y="{ybot+18}" text-anchor="{anchor}" font-size="10" class="muted">{lab}</text>')
    out.append(f'  <line class="axis" x1="{x0}" y1="{ytop}" x2="{x0}" y2="{ybot}"/>')
    return "\n".join(out)

def protection_svg():
    W, H = 1120, 900
    panels = [
        ("Time per operation", 104, 212, 9e6, fmt_time, [("0 ms","start"),("3 ms","middle"),("6 ms","middle"),("9 ms","end")]),
        ("Heap memory per operation", 330, 212, 18*1024*1024, fmt_bytes, [("0 MiB","start"),("6 MiB","middle"),("12 MiB","middle"),("18 MiB","end")]),
        ("Heap allocations per operation", 556, 212, 60000, lambda v: f"{v:,.0f}", [("0","start"),("20000","middle"),("40000","middle"),("60000","end")]),
    ]
    s = head(W, H, "Protection path cost per operation",
             "Three dot-plot panels, one per measure, on a linear axis running from zero. Time, heap bytes, and heap allocations per operation for journal failure detection, CrowdSec decision decoding, and nft ban-set compilation at 100, 1,000, and 10,000 bans. Colored dots are the latest CI run; grey ghost dots are the previous run before the compile-path optimization. Dots mark position only, because these measures span several orders of magnitude.",
             "Five benchmark cases · colored = latest CI run · grey = previous run · linear axis from zero · Linux x86_64, Go 1.27.x, AMD EPYC")
    rows = []
    for label, sub, key, color in CASES:
        rows.append((label, sub, prot[key], PREV[key], color))
    for pi, (ptitle, y0, ph, vmax, fmt, tlabs) in enumerate(panels):
        x0, x1 = 470, 1010
        ytop, ybot = y0 + 36, y0 + ph - 28
        s += f'  <rect class="panel" x="24" y="{y0}" width="1072" height="{ph}" rx="14"/>\n'
        s += f'  <text x="48" y="{y0+26}" font-size="14" font-weight="650">{ptitle}</text>\n'
        ticks = [(0.0, tlabs[0][0], tlabs[0][1]), (1/3, tlabs[1][0], tlabs[1][1]), (2/3, tlabs[2][0], tlabs[2][1]), (1.0, tlabs[3][0], tlabs[3][1])]
        s += panel_grid(x0, x1, ytop, ybot, ticks) + "\n"
        for i, (label, sub, new, old, color) in enumerate(rows):
            y = ytop + 23.2 + i * 30.4
            val, oval = new[pi], old[pi]
            s += f'  <text x="48" y="{y:.1f}" font-size="12.5" font-weight="650">{label}</text>\n'
            s += f'  <text x="48" y="{y+16:.1f}" font-size="10.5" class="muted">{sub}</text>\n'
            # ghost = previous run
            ox = x0 + (x1-x0) * min(oval/vmax, 1.0)
            s += f'  <line class="axis" x1="{x0}" y1="{y+1:.1f}" x2="{ox:.1f}" y2="{y+1:.1f}"/>\n'
            s += f'  <circle cx="{ox:.1f}" cy="{y+1:.1f}" r="5" class="prev"><title>previous run, {label}, {sub}: {fmt(oval)}</title></circle>\n'
            nx = x0 + (x1-x0) * min(val/vmax, 1.0)
            s += f'  <line class="axis" x1="{x0}" y1="{y+1:.1f}" x2="{nx:.1f}" y2="{y+1:.1f}"/>\n'
            s += f'  <circle cx="{nx:.1f}" cy="{y+1:.1f}" r="6" fill="{color}"><title>{label}, {sub}: {fmt(val)}</title></circle>\n'
            s += f'  <text x="{nx+12:.1f}" y="{y+5:.1f}" font-size="11" font-weight="650" fill="{color}">{fmt(val)}</text>\n'
    s += '  <rect x="24" y="800" width="12" height="12" rx="3" class="bfw"/>\n'
    s += '  <text x="42" y="810" font-size="12">Latest CI run</text>\n'
    s += '  <rect x="150" y="800" width="12" height="12" rx="3" class="prev"/>\n'
    s += '  <text x="168" y="810" font-size="12">Previous run</text>\n'
    s += '  <text x="280" y="810" font-size="11" class="muted">Every axis is linear and starts at zero; a dot twice as far from the axis is twice the value. Values are a single sample and vary by machine.</text>\n'
    s += "</svg>\n"
    return s

def ratio_svg(title, key, desc, dotnote):
    """3-panel dot plot of bfw/ufw ratio per profile."""
    W, H = 1120, 470
    profs = [("keepalive", "Keep-alive"), ("churn", "Connection churn"), ("mixed", "Mixed payload")]
    data = {}
    for c in SUM["comparisons"]:
        data.setdefault(c["profile"], {})[c["cardinality"]] = c[key]
    s = head(W, H, title, desc, f"{title.split(':')[0]} ratio by traffic profile · 3 repeats · 1.000× means parity")
    for i, (p, label) in enumerate(profs):
        px = 24 + i * 362
        vals = [data[p][k] for k in (10, 100, 500, 1000)]
        lo = math.floor((min(min(vals), 1.0) - 0.004) * 1000) / 1000
        hi = math.ceil((max(max(vals), 1.0) + 0.004) * 1000) / 1000
        x0, x1 = px + 78, px + 330
        span = hi - lo
        def X(v): return x0 + (x1 - x0) * (v - lo) / span
        s += f'  <rect class="panel" x="{px}.0" y="104" width="348.0" height="300" rx="14"/>\n'
        s += f'  <text x="{px+20}.0" y="132" font-size="14" font-weight="650">{label}</text>\n'
        s += f'  <line class="parity" x1="{X(1.0):.1f}" y1="144" x2="{X(1.0):.1f}" y2="378"/>\n'
        s += f'  <line class="axis" x1="{x0:.1f}" y1="378" x2="{x1:.1f}" y2="378"/>\n'
        s += f'  <text x="{x0:.1f}" y="392" text-anchor="start" font-size="10" class="muted">{lo:.3f}×</text>\n'
        s += f'  <text x="{x1:.1f}" y="392" text-anchor="end" font-size="10" class="muted">{hi:.3f}×</text>\n'
        s += f'  <text x="{X(1.0):.1f}" y="156" text-anchor="middle" font-size="10" font-weight="650">1.000×</text>\n'
        for j, k in enumerate((10, 100, 500, 1000)):
            v = data[p][k]
            y = 193 + j * 54
            cx = X(v)
            s += f'  <text x="{px+20}.0" y="{y+4}.0" font-size="11" class="muted">{k:,}</text>\n'
            s += f'  <line class="axis" x1="{x0:.1f}" y1="{y}" x2="{x1:.1f}" y2="{y}"/>\n'
            s += f'  <circle cx="{cx:.1f}" cy="{y}" r="5.5" fill="#0f9d8a"><title>{k:,} rules: {v:.4f}×</title></circle>\n'
            anchor = "end"; tx = cx - 11
            if cx + 60 > x1: anchor, tx = "end", cx - 11
            else: anchor, tx = ("end" if v <= 1.0 else "start"), (cx - 11 if v <= 1.0 else cx + 11)
            # put label on side with more room
            if cx - x0 > x1 - cx: anchor, tx = "end", cx - 11
            else: anchor, tx = "start", cx + 11
            s += f'  <text x="{tx:.1f}" y="{y+4}.0" text-anchor="{anchor}" font-size="10.5" font-weight="650" fill="#0f9d8a">{v:.4f}×</text>\n'
    s += f'  <text x="24" y="424" font-size="11" class="muted">{dotnote}</text>\n'
    s += '  <text x="24" y="442" font-size="11" class="muted">The horizontal axis is linear and zoomed to the measured range, so small gaps look larger than they are.</text>\n'
    s += "</svg>\n"
    return s

def setup_svg():
    W, H = 1120, 560
    tc = {t["cardinality"]: t for t in SUM["timing_comparisons"]}
    vmax = 180.0
    x0, x1 = 300, 980
    s = head(W, H, "Rule setup + firewall enable time",
             "Grouped horizontal bar chart of the mean wall-clock seconds to add the rules and enable the firewall, one bfw bar and one UFW bar per rule count at 10, 100, 500, and 1,000 rules. The axis is linear and starts at zero so bar length is proportional to time; the speed-up under each label carries the comparison bar lengths cannot show at this range.",
             "Mean wall-clock seconds per rule count · 3 repeats · linear axis from zero")
    s += '  <rect class="panel" x="24" y="108" width="1072" height="340" rx="14"/>\n'
    for t in (0, 60, 120, 180):
        x = x0 + (x1-x0)*t/vmax
        anchor = "start" if t == 0 else ("end" if t == vmax else "middle")
        s += f'  <line class="grid" x1="{x:.1f}" y1="142" x2="{x:.1f}" y2="422"/>\n'
        s += f'  <text x="{x:.1f}" y="440" text-anchor="{anchor}" font-size="11" class="muted">{t}</text>\n'
    s += f'  <line class="axis" x1="{x0}" y1="142" x2="{x0}" y2="422"/>\n'
    for i, k in enumerate((10, 100, 500, 1000)):
        y = 163 + i * 70
        bfw, ufw = tc[k]["bfw_total_s"], tc[k]["ufw_total_s"]
        s += f'  <text x="52" y="{y+24}.0" font-size="14" font-weight="650">{k:,} rules</text>\n'
        s += f'  <text x="52" y="{y+41}.0" font-size="11" class="muted">{tc[k]["total_speedup"]:.1f}× faster with bfw</text>\n'
        bw = max((x1-x0)*bfw/vmax, 1.2)
        s += f'  <rect class="bfw" x="{x0}" y="{y}" width="{bw:.1f}" height="18" rx="4"/>\n'
        s += f'  <text x="{x0+bw+6.7:.1f}" y="{y+14}.0" font-size="11" font-weight="650" fill="#0f9d8a">{bfw:.4f} s</text>\n'
        uw = (x1-x0)*ufw/vmax
        s += f'  <rect class="ufw" x="{x0}" y="{y+24}" width="{uw:.1f}" height="18" rx="4"/>\n'
        s += f'  <text x="{x0+uw+8:.1f}" y="{y+38}.0" font-size="11" font-weight="650" fill="#3b82f6">{ufw:.4f} s</text>\n'
    s += '  <text x="640" y="452" text-anchor="middle" font-size="11" class="muted">Mean seconds to add the rules and enable the firewall</text>\n'
    s += '  <text x="300" y="506" font-size="11" class="muted">Configuration and apply time only; this is not packet-processing latency.</text>\n'
    s += '  <text x="300" y="524" font-size="11" class="muted">Linear axis from zero: bfw\'s bars are short because bfw is fast, not because the scale flatters it.</text>\n'
    s += "</svg>\n"
    return s

def nice_vmax(v):
    for m in (0.5, 1, 2, 5, 10, 20, 50, 100):
        if v <= m: return m
    return math.ceil(v)

def nice_axis(data_max):
    """3-tick axis: smallest step in the nice ladder covering data_max*1.15."""
    for step in (0.05, 0.1, 0.15, 0.2, 0.25, 0.4, 0.5, 1, 2, 4, 5, 10, 20, 40):
        if data_max * 1.15 <= 3 * step:
            return 3 * step
    return math.ceil(data_max * 1.15)

def latency_abs_svg():
    W, H = 1120, 760
    scen = SUM["scenarios"]
    profs = [("keepalive", "Keep-alive"), ("churn", "Connection churn"), ("mixed", "Mixed payload")]
    groups = (10, 100, 500, 1000)
    def p95(eng, prof, k): return scen[f"{eng}_{k}_{prof}"]["latency_p95_ms"]
    s = head(W, H, "p95 latency in milliseconds",
             "Three panels of grouped vertical bars, one per traffic profile. Each group is a rule count with three bars for no firewall, bfw, and UFW, showing mean p95 latency in milliseconds. Each panel has its own linear axis starting at zero.",
             "Mean p95 latency by rule count · 3 repeats · lower is better · linear axis from zero")
    for pi, (p, label) in enumerate(profs):
        y0 = 100 + pi * 208
        ytop, ybot = y0 + 46, y0 + 166
        vals = [p95(e, p, k) for e in ("baseline", "bfw", "ufw") for k in groups]
        vmax = nice_axis(max(vals))
        s += f'  <rect class="panel" x="24" y="{y0}" width="1072" height="196" rx="14"/>\n'
        s += f'  <text x="48" y="{y0+28}" font-size="14" font-weight="650">{label} · p95 (ms)</text>\n'
        for i in range(4):
            v = vmax * i / 3
            y = ybot - (ybot - ytop) * i / 3
            s += f'  <line class="grid" x1="92" y1="{y:.1f}" x2="1070" y2="{y:.1f}"/>\n'
            s += f'  <text x="82" y="{y+4:.1f}" text-anchor="end" font-size="10" class="muted">{v:g}</text>\n'
        for gi, k in enumerate(groups):
            cx = 214.2 + gi * 244.6
            for bi, (e, cls, color, name) in enumerate((("baseline","base","#64748b","No firewall"), ("bfw","bfw","#0f9d8a","bfw"), ("ufw","ufw","#3b82f6","UFW"))):
                v = p95(e, p, k)
                bh = (ybot - ytop) * v / vmax
                x = cx - 75 + bi * 52
                s += f'  <rect class="{cls}" x="{x:.1f}" y="{ybot-bh:.1f}" width="46.0" height="{bh:.1f}" rx="3"><title>{name}, {k:,} rules: {v:.3f} ms</title></rect>\n'
                s += f'  <text x="{x+23:.1f}" y="{ybot-bh-5:.1f}" text-anchor="middle" font-size="9.5" font-weight="650" fill="{color}">{v:.3f}</text>\n'
            s += f'  <text x="{cx:.1f}" y="{ybot+16:.1f}" text-anchor="middle" font-size="11" class="muted">{k:,}</text>\n'
        s += f'  <line class="axis" x1="92" y1="{ybot}" x2="1070" y2="{ybot}"/>\n'
    s += '  <text x="581.0" y="714.0" text-anchor="middle" font-size="11" class="muted">Rule count</text>\n'
    s += '  <rect x="24" y="720" width="12" height="12" rx="3" class="base"/>\n'
    s += '  <text x="42" y="730" font-size="12">No firewall</text>\n'
    s += '  <rect x="135" y="720" width="12" height="12" rx="3" class="bfw"/>\n'
    s += '  <text x="153" y="730" font-size="12">bfw</text>\n'
    s += '  <rect x="187" y="720" width="12" height="12" rx="3" class="ufw"/>\n'
    s += '  <text x="205" y="730" font-size="12">UFW</text>\n'
    s += '  <text x="330" y="730" font-size="11" class="muted">Panels use different y-axis scales; compare bar heights inside a panel only.</text>\n'
    s += "</svg>\n"
    return s

def resources_svg():
    W, H = 1120, 520
    scen = SUM["scenarios"]
    def res(e): return scen[f"{e}_1000_mixed"]["resource_usage"]["server"]
    s = head(W, H, "Defender container resources",
             "Two panels of grouped horizontal bars. The CPU panel shows average and peak server CPU percent for no firewall, bfw, and UFW at 1,000 rules under the mixed profile. The memory panel shows average and peak server memory in mebibytes for the same scenarios.",
             "1,000-rule mixed profile · one-second samples · 24 samples per scenario")
    panels = [(24, "CPU (%)", 120.0, "cpu_avg_pct", "cpu_peak_pct"), (572, "Memory (MiB)", 48.0, "memory_avg_mib", "memory_peak_mib")]
    for px, ptitle, vmax, kavg, kpeak in panels:
        x0 = px + 132; x1 = px + 510
        s += f'  <rect class="panel" x="{px}" y="104" width="536" height="316" rx="14"/>\n'
        s += f'  <text x="{px+20}" y="132" font-size="14" font-weight="650">{ptitle}</text>\n'
        for i in range(4, -1, -1):
            v = vmax * i / 4
            x = x0 + (x1-x0) * i / 4
            s += f'  <line class="grid" x1="{x:.1f}" y1="144" x2="{x:.1f}" y2="396"/>\n'
            s += f'  <text x="{x:.1f}" y="412" text-anchor="middle" font-size="10" class="muted">{v:.1f}</text>\n'
        for si, (e, cls, color, name) in enumerate((("baseline","base","#64748b","No firewall"), ("bfw","bfw","#0f9d8a","bfw"), ("ufw","ufw","#3b82f6","UFW"))):
            y = 172.7 + si * 81.3
            avg, peak = res(e)[kavg], res(e)[kpeak]
            s += f'  <text x="{px+20}" y="{y+28:.1f}" font-size="12">{name}</text>\n'
            s += f'  <rect class="{cls}" x="{x0}" y="{y:.1f}" width="{(x1-x0)*avg/vmax:.1f}" height="17" rx="4"/>\n'
            s += f'  <text x="{x0+(x1-x0)*avg/vmax+7:.1f}" y="{y+13:.1f}" font-size="10.5" font-weight="650" fill="{color}">{avg:.1f}</text>\n'
            s += f'  <rect class="{cls} peak" x="{x0}" y="{y+22:.1f}" width="{(x1-x0)*peak/vmax:.1f}" height="17" rx="4"/>\n'
            s += f'  <text x="{x0+(x1-x0)*peak/vmax+7:.1f}" y="{y+35:.1f}" font-size="10.5" font-weight="650" fill="{color}">{peak:.1f}</text>\n'
    s += '  <rect x="24" y="476" width="12" height="12" rx="3" class="bfw"/>\n'
    s += '  <text x="42" y="486" font-size="12">Average</text>\n'
    s += '  <rect x="105" y="476" width="12" height="12" rx="3" class="peak"/>\n'
    s += '  <text x="123" y="486" font-size="12">Peak</text>\n'
    s += '  <text x="200" y="486" font-size="11" class="muted">One hosted run; peak CPU above 100% means multiple cores were used.</text>\n'
    s += '  <text x="24" y="504" font-size="11" class="muted">Scheduler noise makes small differences informational, not a general performance guarantee. Resources do not gate CI.</text>\n'
    s += "</svg>\n"
    return s

out = {
    "docs/protection-benchmark.svg": protection_svg(),
    "docs/firewall-throughput.svg": ratio_svg("Request throughput: bfw / UFW", "throughput_ratio_bfw_vs_ufw",
        "Three dot-plot panels, one per traffic profile, showing the ratio of bfw to UFW requests per second at 10, 100, 500, and 1,000 rules. A dashed line marks the 1.000× parity value.",
        "Each dot is the bfw-to-UFW ratio for that rule count; dots left of the dashed line favour bfw."),
    "docs/firewall-latency.svg": ratio_svg("p95 latency: bfw / UFW", "p95_latency_ratio_bfw_vs_ufw",
        "Three dot-plot panels, one per traffic profile, showing the ratio of bfw to UFW p95 latency at 10, 100, 500, and 1,000 rules. A dashed line marks the 1.000× parity value.",
        "Each dot is the bfw-to-UFW p95 ratio for that rule count; dots left of the dashed line favour bfw (lower p95)."),
    "docs/firewall-latency-absolute.svg": latency_abs_svg(),
    "docs/firewall-setup-time.svg": setup_svg(),
    "docs/firewall-resources.svg": resources_svg(),
}

def attack_svg():
    W, H = 1120, 850
    eng = ATTACK["engines"]
    meta = ATTACK.get("metadata", {})
    ENGINES = [("none", "No firewall", "#64748b"), ("bfw", "bfw", "#0f9d8a"), ("ufw", "UFW", "#3b82f6")]
    ATTACKS = [
        ("synflood_denied", "SYN flood → denied port"),
        ("synflood_allowed", "SYN flood → allowed port"),
        ("connectflood", "TCP connect flood → allowed port"),
    ]
    s = head(W, H, "Attack lab: bfw vs UFW",
             "Comparison board from the containerized attack-lab CI job. Top panel: nmap recon time over ports 1-2000 and which ports in 8070-8110 answered. Lower panels: legitimate keep-alive HTTP requests completed and their p95 latency while each attack ran against the defended service.",
             f"Isolated Docker network · {meta.get('rules','?')} allow rules · {meta.get('flood_seconds','?')}s per attack · {meta.get('kernel','')} · single CI run")
    # Panel 1: recon
    s += '  <rect class="panel" x="24" y="104" width="1072" height="150" rx="14"/>\n'
    s += '  <text x="48" y="132" font-size="14" font-weight="650">Recon: nmap scan of ports 1–2000 (lower = attacker sees more, faster)</text>\n'
    times = {k: (eng[k]["nmap"] or {}).get("seconds") for k, _, _ in ENGINES}
    tmax = max([t for t in times.values() if t] or [1]) * 1.15
    x0, x1 = 560, 900
    for i, (k, label, color) in enumerate(ENGINES):
        y = 156 + i * 30
        t = times[k] or 0
        n = eng[k]["nmap"]
        w = eng[k].get("nmap_window") or {}
        win = ",".join(map(str, w.get("open_ports", []))) or "none open"
        detail = (f"{n['filtered']} filtered" if n.get("filtered") else f"{n.get('closed','?')} closed")
        s += f'  <text x="48" y="{y+14}" font-size="12" font-weight="650">{label}</text>\n'
        s += f'  <text x="150" y="{y+14}" font-size="11" class="muted">{detail}; ports 8070–8110: {win}</text>\n'
        bw = max((x1 - x0) * t / tmax, 1.2)
        s += f'  <rect x="{x0}" y="{y}" width="{bw:.1f}" height="16" rx="4" fill="{color}"/>\n'
        tlab = f"{t:.2f} s" if times[k] is not None else "n/a"
        s += f'  <text x="{x0 + bw + 8:.1f}" y="{y+13}" font-size="11" font-weight="650" fill="{color}">{tlab}</text>\n'
    # Panels 2-4: legit traffic during each attack
    for pi, (akey, atitle) in enumerate(ATTACKS):
        y0 = 284 + pi * 144
        s += f'  <rect class="panel" x="24" y="{y0}" width="1072" height="128" rx="14"/>\n'
        s += f'  <text x="48" y="{y0+26}" font-size="14" font-weight="650">{atitle} — legit requests completed</text>\n'
        oks = {k: (eng[k]["attacks"][akey]["legit"] or {}).get("ok", 0) for k, _, _ in ENGINES}
        vmax = max(oks.values() or [1]) * 1.18
        for i, (k, label, color) in enumerate(ENGINES):
            y = y0 + 42 + i * 28
            st = eng[k]["attacks"][akey]["legit"] or {}
            bw = max((x1 - x0) * oks[k] / vmax, 1.2)
            s += f'  <text x="48" y="{y+14}" font-size="12" font-weight="650">{label}</text>\n'
            s += f'  <rect x="{x0}" y="{y}" width="{bw:.1f}" height="16" rx="4" fill="{color}"/>\n'
            p95 = st.get("p95_ms")
            note = f" · p95 {p95:.2f} ms" if p95 is not None else ""
            s += f'  <text x="{x0 + bw + 8:.1f}" y="{y+13}" font-size="11" font-weight="650" fill="{color}">{oks[k]:,} ok{note}</text>\n'
            fails = st.get("req_fail", 0) + st.get("connect_fail", 0)
            if fails:
                s += f'  <text x="{x0 + bw + 160:.1f}" y="{y+13}" font-size="10.5" fill="#ef4444">{fails} failed</text>\n'
    # Panel 5: dynamic smart banning (bfw protect). Rows show mechanism
    # outcome per engine; ban latency drawn when measured.
    dy = 284 + len(ATTACKS) * 144 + 6
    s += f'  <rect class="panel" x="24" y="{dy}" width="1072" height="110" rx="14"/>\n'
    s += f'  <text x="48" y="{dy+26}" font-size="14" font-weight="650">Dynamic bans — bfw protect (journal jail + CrowdSec LAPI)</text>\n'
    dyn_rows = [
        ("SSH brute-force → jail ban", "jail", "jail_ban_s"),
        ("CrowdSec LAPI ban → unban", "lapi", "lapi_ban_s"),
    ]
    for ri, (rlabel, dkey, tkey) in enumerate(dyn_rows):
        y = dy + 40 + ri * 32
        s += f'  <text x="48" y="{y+13}" font-size="12" font-weight="650">{rlabel}</text>\n'
        for i, (k, label, color) in enumerate(ENGINES):
            d = eng[k].get(dkey) or {}
            bx = 380 + i * 230
            if not d:
                s += f'  <text x="{bx}" y="{y+13}" font-size="11" class="muted">{label}: n/a</text>\n'
                continue
            if d.get("mechanism") == "none":
                s += f'  <text x="{bx}" y="{y+13}" font-size="11" fill="{color}">{label}: no mechanism — attacker unbanned</text>\n'
                continue
            t = d.get(tkey)
            txt = f"{label}: ban {t:.1f} s" if isinstance(t, (int, float)) and t >= 0 else f"{label}: ban pending"
            extra = ""
            if dkey == "jail" and d.get("ssh_after") is not None:
                extra = " (ssh blocked)" if d["ssh_after"] == 0 else " (ssh OPEN)"
            if dkey == "lapi" and d.get("lapi_unban_s") is not None and d.get("lapi_unban_s", -1) >= 0:
                extra = f", unban {d['lapi_unban_s']:.1f} s"
            s += f'  <text x="{bx}" y="{y+13}" font-size="11" font-weight="650" fill="{color}">{txt}{extra}</text>\n'
    fy = dy + 118
    s += f'  <rect x="24" y="{fy}" width="12" height="12" rx="3" class="base"/>\n'
    s += f'  <text x="42" y="{fy+10}" font-size="11">No firewall</text>\n'
    s += f'  <rect x="120" y="{fy}" width="12" height="12" rx="3" class="bfw"/>\n'
    s += f'  <text x="138" y="{fy+10}" font-size="11">bfw</text>\n'
    s += f'  <rect x="176" y="{fy}" width="12" height="12" rx="3" class="ufw"/>\n'
    s += f'  <text x="194" y="{fy+10}" font-size="11">UFW</text>\n'
    s += f'  <text x="240" y="{fy+10}" font-size="10.5" class="muted">Bars: requests completed during the attack window · gates: denied port closed, service reachable, legit p95 &lt; 2 s, attacker banned</text>\n'
    s += "</svg>\n"
    return s

if ATTACK:
    out["docs/attack-lab.svg"] = attack_svg()
for path, svg in out.items():
    dest = ROOT / path
    dest.write_text(svg)
    print("wrote", path, len(svg), "bytes")
