# Adding firewalld to the hosted comparison

**Status: assessment only.** Nothing in `scripts/perf/` has been changed. This
note records what a fair third engine would require, because the current
harness cannot absorb one without a deliberate generalisation, and because the
only way to settle the open questions is the hosted `performance` job.

## 1. Semantic equivalence

`bfw default deny incoming` + `bfw allow 8080/tcp` and
`ufw default deny incoming` + `ufw allow 8080/tcp` both end as "drop every
inbound packet except TCP 8080", and the harness proves it with the positive
(`probe allowed 8080`) and negative (`probe blocked 8081`) controls in
`run.sh:137-156` plus `verify_benchmark_controls` at `run.sh:222-232`.

firewalld needs three extra steps to reach the same state:

1. A zone whose target is `DROP`. `--set-target=DROP` is the direct equivalent of
   `default deny incoming`.
2. An **empty** zone. The shipped `public` zone allows `ssh` and `mdns`, so
   using it would silently open ports 22 and 5353 that bfw and UFW leave closed
   and would make the comparison dishonest. Create a dedicated zone and set it
   as the default instead of adding ports to `public`.
3. Ports added through `firewall-offline-cmd --zone=<zone> --add-port=PORT/tcp`.

`firewall-offline-cmd` is the only supported way to write permanent config
without the daemon, and it is documented as safe to use *only while firewalld is
stopped* (<https://firewalld.org/documentation/man-pages/firewall-offline-cmd.html>).
That maps cleanly onto the harness's two phases: `rule_add` runs offline, and
`enable` starts the daemon so it loads the permanent ruleset. Note the semantic
difference this introduces and state it in the report: for bfw and UFW "enable"
is a ruleset write, while for firewalld it also starts a resident process.

Idempotency matters for `reset_firewalls`. The same manual documents that
`ALREADY_ENABLED` (11), `NOT_ENABLED` (12), and `ZONE_ALREADY_SET` (16) count as
success, so a reset can treat those exit codes as "already in the target state"
instead of failing.

## 2. Cost accounting

`apply_rules.py:23-69` measures `getrusage(RUSAGE_CHILDREN)` around the CLI
processes, which covers `bfw`, `ufw`, and `firewall-offline-cmd` but **not** a
daemon that stays running. A firewalld daemon keeps resident memory and can burn
CPU reloading rules; that cost is real and must not disappear from the report.

Two places would have to account for it:

* `measure_resources.py` already samples whole containers, so a resident daemon
  shows up in `resource_usage.server` automatically. That is the honest number
  and it should be the one quoted.
* The per-phase `*_peak_rss_kib` fields are CLI-child peaks. For firewalld they
  describe `firewall-offline-cmd` only. The report needs a separate
  "resident after enable" figure (for example `ss`-derived or `/proc/<pid>`
  `VmRSS` of the firewalld process) so the tables do not imply the daemon is
  free.

The engine table should also carry firewalld's package size the way it carries
`ufw_package_installed_kib`, because a daemon ships considerably more than a
launcher script. Reporting the launcher size alone would be a misleading
comparison.

## 3. Code changes the report layer needs

`compare.py` is shaped around exactly two engines, so this is a generalisation,
not an extra case:

| Location | Current shape | Needed |
|---|---|---|
| `compare.py:21` | `ENGINES = ("bfw", "ufw")` | add `"firewalld"`; the constant already drives `merge_shards.py:45,72,102` |
| `compare.py:42` | `engine_order = {"baseline": 0, "bfw": 1, "ufw": 2}` | order the third engine |
| `compare.py:519-545` | `bfw`/`ufw` locals, `*_bfw_vs_ufw` ratio keys | per-engine ratio keys (`throughput_ratio_bfw_vs_firewalld`, …) |
| `compare.py:585-600` | `bfw_entry`/`ufw_entry` pairs | loop over `ENGINES`; speedups become a mapping |
| `compare.py:784,804` | Markdown label maps | new labels and a wider table |
| `apply_rules.py:44-53,75,85` | `run(engine, "allow", port)` / `run(engine, "--force", "enable")` | a firewalld branch using `firewall-offline-cmd`, and a separate daemon start for `enable` |
| `run.sh:132-135` | resets bfw and ufw | stop the daemon and reset zone state between scenarios |
| `run.sh:112-116` | binary and package sizes | firewalld package size |
| `server.Dockerfile:7` | installs `iptables nftables ufw` | `firewalld` plus dbus |
| `compare_test.py` | ~44 KB of two-engine expectations | new coverage for the third engine |

`server.Dockerfile` and the compose file grant `cap_drop: ALL` plus
`cap_add: NET_ADMIN` and `no-new-privileges:true`. firewalld normally expects a
system D-Bus and a service manager, neither of which exists in the container, so
the daemon has to be launched directly and the D-Bus system bus started by hand.
Whether that works under those capability restrictions is the single largest
unknown, and it cannot be answered from this machine: `AGENTS.md` forbids
running `scripts/perf/run.sh` locally.

## 4. What a fair report must then say

* firewalld is compared with its daemon running, because that is how it is
  deployed; excluding the daemon would favour it unfairly.
* Rule counts mean the same thing: the same number of allowed TCP ports, same
  profiles, same k6 script, same positive/negative controls.
* "Enable" is not the same operation across engines (ruleset write versus daemon
  start), so setup numbers should be reported with that caveat, and it is
  arguably a different metric rather than a third value in one column.
* Throughput and p95 differences between bfw, UFW, and firewalld on the same
  host are small relative to CI noise. A third engine makes the
  "bfw is better in every aspect" framing even less supportable, not more.

## 5. Recommendation

Do it as its own change, in this order, with a hosted run between each step:

1. Extend `apply_rules.py` and `run.sh` for firewalld and confirm the controls
   pass in the hosted job. This is the risky part; do it before touching the
   report layer.
2. Generalise `compare.py` to iterate `ENGINES`, adding the per-engine tests
   alongside.
3. Only then regenerate charts and README claims from a successful run.

Until step 1 passes on a hosted runner, no firewalld number should appear in
`README.md`.
