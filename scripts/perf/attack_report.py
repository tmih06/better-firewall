#!/usr/bin/env python3
"""Merge attack-lab raw artifacts into summary.json + summary.md and apply
result gates. Mirrors compare.py's role for the attack job.

File layout expected in --raw-dir:
  metadata.json
  setup_{engine}.json                    engine, rules, setup_s
  reach_{engine}.json                    open_8080, open_8081 (1/0)
  nmap_{engine}.txt                      raw nmap output
  legit_calm_{engine}.json               calm-baseline traffic stats
  attack_{name}.txt                      attacker stdout/stderr
  legit_during_{name}_{engine}.json      traffic stats during that attack
  cpu_{name}_{engine}.json               defender CPU% mid-attack

Gates (exit 1 on failure):
  * every engine must keep the service reachable and the denied port closed
  * every engine must complete >0 legit requests during each attack
  * bfw legit p95 during each attack must stay under --max-p95-ms
"""
import argparse
import json
import re
import sys
from pathlib import Path

ENGINES = ["none", "bfw", "ufw"]
ATTACKS = ["synflood_denied", "synflood_allowed", "connectflood"]
ATTACK_LABEL = {
    "synflood_denied": "SYN flood → denied port",
    "synflood_allowed": "SYN flood → allowed port",
    "connectflood": "TCP connect flood → allowed port",
}


def load(raw, name):
    p = raw / name
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return None

def nmap_stats(path):
    """Parse one nmap run: open port list, closed/filtered counts, scan time."""
    if not path or not path.exists():
        return {"open_ports": [], "open": None, "closed": None, "filtered": None, "seconds": None}
    text = path.read_text()
    open_ports = sorted({int(m.group(1)) for m in re.finditer(r"^(\d+)/tcp\s+open\b", text, re.M)})
    m = re.search(r"Not shown: (\d+) closed", text)
    closed = int(m.group(1)) if m else 0
    m = re.search(r"Not shown: (\d+) filtered", text)
    filtered = int(m.group(1)) if m else 0
    m = re.search(r"scanned in ([\d.]+) seconds", text)
    seconds = float(m.group(1)) if m else None
    return {"open_ports": open_ports, "open": len(open_ports),
            "closed": closed, "filtered": filtered, "seconds": seconds}


def fmt_ms(stats):
    if not stats or "p95_ms" not in stats:
        return "—"
    return f"{stats['p95_ms']:.1f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw-dir", required=True)
    ap.add_argument("--output-json", required=True)
    ap.add_argument("--output-md", required=True)
    ap.add_argument("--max-p95-ms", type=float, default=2000.0)
    args = ap.parse_args()

    raw = Path(args.raw_dir)
    meta = load(raw, "metadata.json") or {}
    engines = {}
    gates = []

    for e in ENGINES:
        entry = {
            "setup": load(raw, f"setup_{e}.json"),
            "reach": load(raw, f"reach_{e}.json"),
            "nmap": nmap_stats(raw / f"nmap_{e}.txt"),
            "nmap_window": nmap_stats(raw / f"nmap_window_{e}.txt"),
            "calm": load(raw, f"legit_calm_{e}.json"),
            "attacks": {},
            "lapi": load(raw, f"dynamic_lapi_{e}.json"),
            "jail": load(raw, f"dynamic_jail_{e}.json"),
        }
        for a in ATTACKS:
            entry["attacks"][a] = {
                "legit": load(raw, f"legit_during_{a}_{e}.json"),
                "cpu": load(raw, f"cpu_{a}_{e}.json"),
            }
        engines[e] = entry


        # Gate: service reachable, denied port closed.
        reach = entry["reach"] or {}
        if e != "none":
            if reach.get("open_8080") != 1:
                gates.append(f"{e}: service port 8080 was NOT reachable")
            if reach.get("open_8081") != 0:
                gates.append(f"{e}: denied port 8081 was reachable (firewall leak)")
        # Gate: with a protect mechanism, the attacker must actually get banned.
        if e == "bfw":
            jail = entry["jail"] or {}
            if jail.get("jail_ban_s", -1) is not None and jail.get("jail_ban_s", -1) < 0:
                gates.append("bfw: SSH brute-force did not produce a jail ban")
            if jail.get("ssh_after") != 0:
                gates.append("bfw: attacker still reached sshd after the jail ban")
            if jail.get("legit_after") != 1:
                gates.append("bfw: legit client was affected by the attacker ban")
            lapi = entry["lapi"] or {}
            if lapi.get("lapi_ban_s", -1) is not None and lapi.get("lapi_ban_s", -1) < 0:
                gates.append("bfw: LAPI ban decision was not applied")
            if lapi.get("lapi_unban_s", -1) is not None and lapi.get("lapi_unban_s", -1) < 0:
                gates.append("bfw: LAPI unban did not remove the threat set entry")
        # Gate: legit traffic must complete during every attack.
        for a in ATTACKS:
            st = entry["attacks"][a]["legit"] or {}
            if st.get("ok", 0) <= 0:
                gates.append(f"{e}: zero legit requests completed during {a}")

    # Gate: bfw must keep legit p95 under the bound during each attack.
    for a in ATTACKS:
        st = engines["bfw"]["attacks"][a]["legit"] or {}
        p95 = st.get("p95_ms")
        if p95 is not None and p95 > args.max_p95_ms:
            gates.append(f"bfw: legit p95 {p95:.0f} ms exceeded {args.max_p95_ms:.0f} ms during {a}")

    summary = {"metadata": meta, "engines": engines, "gates_failed": gates}
    Path(args.output_json).write_text(json.dumps(summary, indent=2) + "\n")

    # ---- markdown ----
    lines = [
        "## Attack-lab results",
        "",
        f"Isolated Docker network · {meta.get('rules', '?')} allow rules · "
        f"{meta.get('flood_seconds', '?')}s per attack · kernel `{meta.get('kernel', '?')}`",
        "",
        "| Control / attack | none | bfw | ufw |",
        "|---|---:|---:|---:|",
    ]

    def reach_cell(e):
        r = engines[e]["reach"] or {}
        if not r:
            return "—"
        return f"8080:{r.get('open_8080','?')} 8081:{r.get('open_8081','?')}"

    lines.append(f"| Reachability (open:1 closed:0) | {reach_cell('none')} | {reach_cell('bfw')} | {reach_cell('ufw')} |")

    def nmap_cell(e):
        n = engines[e]["nmap"]
        w = engines[e]["nmap_window"]
        if n["open"] is None:
            return "—"
        wide = (f"{n['filtered']} filtered/{n['closed']} closed in {n['seconds']:.0f}s"
                if n["seconds"] is not None else "?")
        win = ",".join(map(str, w["open_ports"])) if w["open_ports"] else "none"
        return f"1–2000: {wide}; open 8070–8110: {win}"

    lines.append(f"| nmap recon | {nmap_cell('none')} | {nmap_cell('bfw')} | {nmap_cell('ufw')} |")
    lines.append("")

    lines += [
        "| Attack | engine | legit ok | fail | conn fail | p50 ms | p95 ms | max ms | defender CPU% |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for a in ATTACKS:
        for e in ENGINES:
            cell = engines[e]["attacks"][a]
            st = cell["legit"] or {}
            cpu = (cell["cpu"] or {}).get("server_cpu")
            lines.append(
                f"| {ATTACK_LABEL[a]} | {e} | {st.get('ok','—')} | {st.get('req_fail','—')} | "
                f"{st.get('connect_fail','—')} | {st.get('p50_ms','—')} | {st.get('p95_ms','—')} | "
                f"{st.get('max_ms','—')} | {cpu if cpu is not None else '—'} |"
            )

    lines += ["", "### Setup", "", "| engine | rules | wall s |", "|---|---:|---:|"]
    for e in ENGINES:
        s = engines[e]["setup"] or {}
        lines.append(f"| {e} | {s.get('rules','—')} | {s.get('setup_s','—')} |")

    lines += ["", "### Dynamic protection (smart banning)", "",
              "| Measure | none | bfw | ufw |", "|---|---:|---:|---:|"]

    def dyn_cell(e, key):
        d = engines[e].get(key) or {}
        if not d:
            return "n/a"
        if d.get("mechanism") == "none":
            return "no mechanism — attacker stays unbanned"
        if key == "lapi":
            parts = []
            ban, unban = d.get("lapi_ban_s"), d.get("lapi_unban_s")
            if ban is not None and ban >= 0:
                parts.append(f"ban in {ban:.1f} s")
            if unban is not None and unban >= 0:
                parts.append(f"unban in {unban:.1f} s")
            parts.append("blocked" if d.get("attacker_after_ban") == 0 else "NOT blocked")
            parts.append("legit ok" if d.get("legit_after_ban") == 1 else "legit AFFECTED")
            return "; ".join(parts)
        parts = []
        ban = d.get("jail_ban_s")
        if ban is not None and ban >= 0:
            parts.append(f"jail ban in {ban:.1f} s")
        if "ssh_after" in d:
            parts.append("ssh blocked" if d["ssh_after"] == 0 else "ssh STILL OPEN")
        if "legit_after" in d:
            parts.append("legit ok" if d["legit_after"] == 1 else "legit AFFECTED")
        return "; ".join(parts)

    lines.append(f"| SSH brute-force → journal jail | {dyn_cell('none','jail')} | {dyn_cell('bfw','jail')} | {dyn_cell('ufw','jail')} |")
    lines.append(f"| CrowdSec-style LAPI ban/unban | {dyn_cell('none','lapi')} | {dyn_cell('bfw','lapi')} | {dyn_cell('ufw','lapi')} |")

    lines += ["", "### Calm baseline (no attack)", "",
              "| engine | ok | p50 ms | p95 ms |", "|---|---:|---:|---:|"]
    for e in ENGINES:
        st = engines[e]["calm"] or {}
        lines.append(f"| {e} | {st.get('ok','—')} | {fmt_ms(st)} ← p95 | — |" if False else
                     f"| {e} | {st.get('ok','—')} | {st.get('p50_ms','—')} | {st.get('p95_ms','—')} |")

    if gates:
        lines += ["", "**Gates FAILED:**"] + [f"- {g}" for g in gates]
    else:
        lines += ["", "All gates passed."]

    Path(args.output_md).write_text("\n".join(lines) + "\n")
    print("\n".join(lines))

    if gates:
        print("\nattack_report: gates failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
