# better-firewall

better-firewall is a Linux firewall frontend for **nftables**, written in Go.
Its `bfw` CLI implements the ufw 0.36.2 command grammar and can replace UFW
when invoked as `ufw`. It imports supported rules from UFW, firewalld,
iptables-persistent, and native nftables configurations; it does not emulate
those managers' command-line interfaces.

## Features

- **ufw-compatible grammar** — `allow`, `deny`, `reject`, `limit`, `delete`,
  `insert`, `prepend`, `route`, `status`, `default`, `logging`, `app`,
  `enable`, `disable`, `reload`, `reset`, `show` behave like ufw 0.36.2,
  including `status numbered`, `status verbose`, and prompts/output formats.
- **nftables backend** — the entire ruleset compiles to a single atomic
  netlink batch; no partial applies. `bfw --dry-run …` renders the exact
  ruleset that would be installed.
- **Dual-stack** — separate IPv4/IPv6 rule lists like ufw; one dual-family
  rule produces an entry in each.
- **Named IP sets** — reusable address lists referenced from rules
  (`from set NAME`), backed by nftables sets.
- **NAT** — masquerade and DNAT rules managed alongside filter rules.
- **Expiring rules** — `expires` clause plus a `sweep` command/systemd timer
  that removes expired rules.
- **Toggleable rules** — `rule enable|disable NUM` without deleting.
- **Drift & health checks** — `check` (ssh-lockout risk, shadowed/expired
  rules, foreign ufw chains, enabled-but-not-loaded) and `diff` (stored
  vs. live kernel ruleset, normalized against `nft -nn` output).
- **Panic mode** — one command drops all traffic; `panic off` restores.
- **App profiles** — INI profiles in `/etc/better-firewall/applications.d`,
  shipped defaults for OpenSSH, Nginx, mail, and misc services.
- **Migration** — `migrate` previews/imports supported UFW, firewalld,
  iptables-persistent, and native nftables rules. Optional `--takeover` stops
  and disables the source manager before enabling bfw.
- **Fragments & hooks** — ufw-style `before*.rules`/`after*.rules` nft
  fragments and `before.init`/`after.init` hooks.
- **systemd units** — boot-time load plus a sweep timer for expired rules.

## Requirements

- Linux with nftables (`nf_tables` kernel support)
- systemd for packaged boot persistence and `migrate --takeover`
- Go 1.22+ to build; the compiled `bfw` binary has no Python dependency
- `nft` is recommended for inspection and required for native nftables import
- Release installer: `curl` or `wget`, `tar`, and `sha256sum`
- Root privileges for mutating commands and for `status`/`check`

## Build & Install

```sh
make build          # produces ./bfw
sudo make install   # installs to /usr/sbin/bfw + systemd units
sudo make uninstall
```

Version-tagged linux/amd64 and linux/arm64 releases include a
checksum-verified systemd-oriented installer. It installs the binary and
units but does not stop or replace an existing firewall manager:

```sh
curl -fsSL \
  https://github.com/tmih06/bfirewall/releases/latest/download/install.sh \
  -o install-bfw.sh
sudo sh install-bfw.sh
```

Or with Go directly:

```sh
go build -o bfw ./cmd/bfw
```

Installation layout:

| Path | Purpose |
|---|---|
| `/usr/sbin/bfw` | the binary |
| `/etc/better-firewall/` | state dir: `rules.json`, `better-firewall.conf`, `sysctl.conf`, `applications.d/`, `before*.rules`/`after*.rules`, `*.init` hooks |
| `/etc/default/better-firewall` | tunables (`IPT_SYSCTL`, `IPT_MODULES`, `DEFAULT_APPLICATION_POLICY`, …) |
| `/etc/systemd/system/better-firewall.service` | loads rules at boot (`Before=network-pre.target`) |
| `/etc/systemd/system/better-firewall-sweep.{service,timer}` | periodic removal of expired rules |

Set `BFW_PREFIX` to relocate the state dir (used by tests; e.g.
`BFW_PREFIX=/tmp/fw`).

## Quick start

```sh
sudo bfw enable                      # compiles + atomically applies the ruleset
sudo bfw allow 22/tcp                # ufw-style rule
sudo bfw allow from 192.168.1.0/24 to any port 5432 proto tcp
sudo bfw status numbered
sudo bfw --dry-run reload            # print the rendered nft ruleset, touch nothing
sudo bfw status verbose
```

Drop-in mode: invoke the binary as `ufw` (symlink or rename) and behavior is
identical — only the program name in help text changes.

## Command reference

### Lifecycle

| Command | Description |
|---|---|
| `bfw enable` | Compile + apply ruleset; writes `ENABLED=yes` |
| `bfw disable` | Flush managed tables from the kernel |
| `bfw reload` | Re-apply stored state |
| `bfw reset [--force]` | Reset to install defaults (prompts unless `--force`) |
| `bfw boot-load` / `bfw boot-unload` | Used by the systemd unit |

### Rules (ufw grammar)

```sh
bfw allow|deny|reject|limit RULE
bfw delete RULE|NUM
bfw insert NUM RULE
bfw prepend RULE
bfw route RULE                 # forwarded/routed traffic
bfw rule enable|disable NUM    # better-firewall extension: toggle without deleting
```

RULE supports the full ufw shape — `in|out` on interfaces, `from`/`to`
addresses and CIDRs, `port`, `proto`, `comment`, service names — plus
better-firewall extensions:

```sh
bfw allow from set trusted to any port 22 proto tcp   # named set endpoint
bfw allow 8080/tcp expires 2h                         # auto-expiring (Ns|Nm|Nh|Nd)
bfw allow to any proto icmpv6 type 135                # exact ICMPv6 type
```

The bfw `type` extension applies only to `proto icmp` and `proto icmpv6`; TYPE
accepts a supported symbolic name or a numeric value from 0 through 255.

### Policy & logging

```sh
bfw default allow|deny|reject incoming|outgoing|routed
bfw logging off|low|medium|high|full
```

### Application profiles

```sh
bfw app list                     # profiles from /etc/better-firewall/applications.d
bfw app info PROFILE             # show profile details
bfw app update PROFILE|all       # refresh rules generated from a profile
bfw app default allow|deny|reject|skip
```

Profile format (INI):

```ini
[Nginx Full]
title=Web Server (HTTP,HTTPS)
description=Nginx Full
ports=80,443/tcp
```

### Authentication protection (optional)

`bfw protect` is a long-running, root-owned service. The embedded
`/etc/better-firewall/protect.json` default watches systemd journal records
from `sshd`, ignores `127.0.0.0/8` and `::1/128`, and bans a source IP for one
hour after five failed-password messages within ten minutes. Failure counters
live in memory; persisted bans survive service restarts. This is Fail2ban-like
behavior, not a Fail2ban compatibility layer; it does not read flat log files
or load Fail2ban filters and actions.

Jails select journal identifiers and regular expressions. Each pattern must
capture the source address in a named `ip` group:

```json
{
  "jails": [
    {
      "name": "ssh",
      "identifiers": ["sshd"],
      "patterns": [
        "(?i)Failed password for .* from (?P<ip>[a-f0-9:.]+) port [0-9]+"
      ],
      "max_retries": 5,
      "find_time": "10m",
      "ban_time": "1h",
      "ignore_ips": ["192.0.2.0/24"]
    }
  ]
}
```

`find_time` and `ban_time` use Go duration syntax; `ban_time` must be at least
one second. `ignore_ips` accepts addresses and CIDR prefixes. Add identifiers
and patterns for other journald-backed services. The service starts the
journal follower at the current end of the log; it does not replay historical
failures.

To enable the local jail:

```sh
sudo systemctl enable --now better-firewall-protect.service
sudo systemctl status better-firewall-protect.service
```

The unit is installed but not enabled automatically. Bans are persisted in
`rules.json`, compiled into IPv4/IPv6 interval sets, and checked before
established-flow acceptance on input and forwarded traffic. Expired bans are
removed by the minutely sweep timer; the firewall systemd unit starts that
timer. If running the firewall outside its systemd unit, enable
`better-firewall-sweep.timer` separately. A ban may therefore remain enforced
for up to one sweep interval after its configured expiry.

#### CrowdSec Local API bouncer

The same service can consume CrowdSec LAPI decisions. On the LAPI host, create a
bouncer with `sudo cscli bouncers add bfirewall`; the key is shown once. Store
it in a root-owned file readable only by root:

```sh
sudo install -o root -g root -m 0600 /dev/null /etc/better-firewall/crowdsec.key
sudoedit /etc/better-firewall/crowdsec.key
```

Add the `crowdsec` object to `protect.json`:

```json
{
  "crowdsec": {
    "url": "https://lapi.example:8080",
    "api_key_file": "/etc/better-firewall/crowdsec.key",
    "poll_interval": "30s"
  }
}
```

The URL must use HTTPS, except HTTP to loopback for a local LAPI. The bouncer
uses `X-Api-Key`, requests IP and range decision deltas, and reconciles a full
snapshot at startup. Only `ban` decisions with IP/range scopes are enforced;
the API key is not stored in `protect.json` or firewall state. Redirects are
rejected to prevent forwarding the key. TLS client-certificate authentication
is not currently supported. Protocol details and first-party references are in
[`docs/crowdsec-lapi-research.md`](docs/crowdsec-lapi-research.md).

Once the config and key file are in place, enable the same optional service
with the systemd commands above. The CrowdSec bouncer can also run with
`"jails": []` to consume only LAPI decisions.

### Status & reports

```sh
bfw status [numbered|verbose]
bfw show raw|builtins|before-rules|after-rules|user-rules|logging-rules|listening|added
```

### Named IP sets (extension)

```sh
bfw set create NAME
bfw set add NAME IP|CIDR [...]
bfw set del NAME IP|CIDR [...]
bfw set list [NAME]
bfw set destroy NAME            # also strips rules referencing it
```

### NAT (extension)

```sh
bfw nat add masquerade out on IFACE [from CIDR]
bfw nat add dnat proto tcp|udp [in on IFACE] to IP port N to-destination IP[:PORT]
bfw nat list
bfw nat delete NUM
```

### Health & safety (extensions)

```sh
bfw check      # ssh-lockout risk, shadowed/expired rules, enabled-but-not-loaded, foreign ufw chains
bfw diff       # unified diff of stored vs. live ruleset (normalized vs `nft -nn`)
bfw panic      # drop ALL traffic immediately (refuses over ssh without --force)
bfw panic off  # restore stored policies
bfw sweep      # remove expired rules
bfw logs       # follow firewall log lines (journalctl -kf -g BFW; falls back to kern.log/syslog filtered)
```

### Migration (extensions)

```sh
bfw export [FILE]              # JSON state → FILE or stdout
bfw import [--replace] FILE    # merge (or replace) state; "-" reads stdin
bfw import-ufw [--dir DIR]     # import UFW's saved rule files
bfw migrate [OPTIONS]          # import a system firewall; optional --takeover
```

`migrate` accepts `--from auto|ufw|firewalld|iptables|nftables`. `auto` requires
exactly one recognized active manager; otherwise choose the source explicitly.
`--dir DIR` selects UFW, firewalld, or iptables-persistent configuration files.
Native nftables import reads the live ruleset through `nft -j list ruleset`.
Firewalld imports permanent zone/service/ipset XML: `/etc/firewalld` overrides
package definitions in `/usr/lib/firewalld`; runtime-only changes are not
imported. The stock `allow-host-ipv6` policy shape and one family-scoped
`icmp-type` rich-rule match are supported; zone-level ICMP blocks and other
policy semantics abort import.
UFW import uses tuple-marked `user.rules`/`user6.rules` and policy settings;
raw iptables commands and `before*.rules`/`after*.rules` hooks are not
translated and are reported as a migration warning.
iptables-persistent reads `rules.v4`/`rules.v6` filter-table rules; non-filter
tables with rules or non-ACCEPT policies on those tables, reachable
user-chain jumps, unsupported match modules, negations, ICMP code qualifiers,
and targets bfw cannot express abort import.
Native nftables import supports simple filter base chains and exact matches;
NAT, sets/maps, jumps, negations, ICMP codes, and other unsupported
expressions abort import rather than being broadened or dropped.

Preview first, then migrate and hand off explicitly:

```sh
sudo bfw --dry-run migrate --from auto --replace
sudo bfw migrate --from auto --replace --takeover
```

Without `--replace`, imported rules merge into the existing bfw state.
`--takeover` prompts before stopping/disabling the source manager and enabling
bfw; `--force` skips that prompt. If applying bfw fails, the previous bfw
state is restored and the command attempts to re-enable the source manager.
Source configuration is not deleted. Stopping a manager does not guarantee
that every foreign or manually-installed kernel rule is removed; inspect the
live ruleset before and after handoff.
Identifiable unsupported enforcement semantics abort import. Unparsed UFW tuple
records, raw UFW rules/hooks, and non-enforcement metadata/accounting produce
warnings; inspect them and dry-run output before takeover.
This migrates supported rules; it does not emulate firewalld, iptables, or
nftables command-line interfaces.

The compiled `bfw` binary does not need Python. Reading saved UFW files also
does not run Python; `--takeover` invokes the installed `ufw` command to stop
UFW.

### Global flags

| Flag | Effect |
|---|---|
| `--dry-run` | Preview rules; do not apply them to the kernel |
| `--force`, `-f` | Skip interactive prompts, including `migrate --takeover` |
| `--json` | JSON output where supported |
| `--version` | Print version |

## Architecture

```
cmd/bfw            entrypoint — argv[0]=="ufw" enables drop-in mode
internal/cli       full ufw grammar parser + commands + output conventions
internal/rule      canonical rule model (Rules4/Rules6 dual lists)
internal/store     persistent state under /etc/better-firewall
internal/backend   backend interface (atomic apply, read-back, fragments)
internal/backend/nft   nftables compiler/renderer via google/nftables netlink
internal/protect  journal failure detector and CrowdSec LAPI bouncer
internal/appprof   INI application-profile parsing/expansion
internal/sysstate  sysctl writes, modprobe, ssh detection, mutating flock
internal/impexp    state export/import and firewall migration
internal/defaults  embedded protection config, profiles/sysctl; lazy materialization
internal/report    `show` reports
internal/services  service-name → port resolution
packaging          systemd units
tests              integration tests (build tag `integration`)
```

State lives in `/etc/better-firewall/rules.json` (atomic tmp+rename, mode 0600).
Mutating commands take an exclusive flock on `/run/better-firewall.lock`. `enable`
runs `before.init start` (abort on failure), applies the core ruleset in one
netlink transaction, applies `before*.rules`/`after*.rules` fragments in a
second transaction (rolling back core on failure), then applies
`sysctl.conf` and `IPT_MODULES`.

## Development

```sh
make build              # go build -o bfw ./cmd/bfw
make test               # go test ./...            (unit; no root needed)
make check              # gofmt, module tidy check, vet, staticcheck, actionlint, shellcheck, govulncheck
make package            # staged install + systemd verify + staged uninstall (no root/systemctl)
make test-integration   # privileged: real nftables inside disposable namespaces (see below)
make benchmark-protect  # unprivileged detector, CrowdSec decode, nft set microbenchmarks
```

Unit tests are dependency-injected (`hookGeteuid`, `hookUnderSSH`,
`hookLockFile`, `hookRunCmd`, replaceable backend constructor) so the command
surface is testable without root or a kernel.

### Privileged testing — read before running

Never run privileged integration tests or the k6 performance benchmark on this
workstation or any production host. Both use real kernel firewall state;
running them outside the isolated CI setup can disrupt networking or SSH.
`make benchmark-protect` is an unprivileged Go microbenchmark and is safe to run
locally.
The `integration` job runs only on a disposable GitHub-hosted runner through
`scripts/ci/isolate.sh`, which:

- **fails closed outside CI**; no local override is provided;
- requires **root**, then re-executes under
  `unshare --mount --net --pid --fork`;
- inside the namespaces, mounts tmpfs over `/etc/better-firewall`,
  `/etc/default/better-firewall`, `/etc/ufw`, `/run`, brings `lo` up with **no
  external networking**, shadows `modprobe`, makes host `/proc/sys` subtrees
  read-only, and exports `BFW_ISOLATED=1` + `BFW_ORIGINAL_NET_NS` so tests
  prove they are not using the host network namespace.

The `performance` job uses Docker Compose on that disposable runner. Its
internal-only network connects a server container (bfw/ufw, `NET_ADMIN`) to
a separate k6 attacker container (no `NET_ADMIN`). No ports are published to
the host; CI removes both containers and their network after the run.

`make test-integration` is CI-only. Never run `go test -tags=integration`
directly as root, and never spoof the CI guard to run it locally. The standard
`make test` and `make check` remain unprivileged.

### Performance comparison (k6)

`scripts/perf/run.sh` builds a server image containing the downloaded `bfw`
artifact and starts it beside a separate k6 attacker container on an
internal-only Docker network. It compares baseline, bfw, and ufw with 10, 100,
500, and 1,000 rules over three alternating repeats. Each ruleset uses three
profiles: keep-alive requests, bounded fresh-connection churn (200 new
connections/second by default), and a mixed 70/20/10 small/medium/large response
workload ramping up to 50 virtual users.

GitHub CI runs one cardinality per isolated runner in parallel, then merges all
raw shards into one validated report; all profiles and three repeats are kept.
Each cardinality's baseline is captured on its own runner before the firewall
pair, preserving same-host baseline comparisons.

The report includes per-profile throughput, latency percentiles, request,
drop, check and error counts, transferred bytes, active virtual users,
comparative ratios, and separate rule-configuration and firewall-enable
timings. Each measured k6 run also samples Docker CPU and memory for both
the server/defender and attacker containers once per second by default
(`PERF_RESOURCE_SAMPLE_INTERVAL` overrides the interval). Rule-add and
enable phases report child-process CPU time and peak RSS. The footprint section
measures the native `bfw` executable, the UFW launcher file, and dpkg's
installed size for the `ufw` package; launcher bytes exclude its Python runtime
and package dependencies, so those values are not like-for-like executable
sizes. Results are saved under `artifacts/performance/` (`summary.md`,
`summary.json`, `raw/*.json`) and uploaded as the
`better-firewall-performance` CI artifact.

Hosted-runner numbers remain noisy (shared CPU and Docker bridge overhead).
Treat ratios as indicative of relative overhead, not as absolute throughput
guarantees.

### CI

`.github/workflows/ci.yml` runs on **every push, every pull request, and
manual dispatch** (`Actions → CI → Run workflow`). Actions are pinned to
commit SHAs. Privileged work runs only on the disposable runner: integration
uses `scripts/ci/isolate.sh`, performance uses an internal-only Docker network.
Coverage intent (not a claim that every behavior is proven):

| Repo area | CI job(s) |
|---|---|
| Go source (all `internal/*`, `cmd/bfw`) | `lint` (gofmt, module tidiness, vet/staticcheck), `build` (Go 1.22.x min + 1.26.x + 1.27.x stable, linux/amd64 + linux/arm64), `unit-test` (race + coverage artifact), `vuln` (govulncheck), `security-codeql` |
| `internal/protect` | `unit-test` and `protection-benchmarks` (jail detector + CrowdSec client race tests; journal detection, decision decode, and ban-set cardinality benchmarks) |
| `etc/better-firewall/*`, `etc/default/*`, embedded defaults | `unit-test` (materialization, overrides, preservation) and `package` (staged configuration tree) |
| `tests/`, nft backend (`internal/backend/nft` integration tests) | `integration` — isolated namespaces, including kernel threat-ban set/rule installation |
| `packaging/*` systemd units, install layout | `package` — staged install + `systemd-analyze verify` + staged uninstall; systemctl stubbed |
| bfw vs ufw performance | `performance` — k6 keep-alive, connection-churn, and mixed-load profiles across 10–1,000 rules; uploads detailed comparison artifacts |
| `.github/workflows/*.yml`, `scripts/**/*.sh` | `lint` — actionlint + shellcheck |
| Secrets in git history | `secrets` — gitleaks, full history (`fetch-depth: 0`, `--all`) |

Local equivalents: `make check` = lint + vuln (tools pinned in the workflow;
install hints in `scripts/ci/check.sh`), `make package` = the `package` job.
The `integration` job requires root + namespaces through `isolate.sh`; the
`performance` job requires the GitHub-hosted Docker setup. Do not run either
privileged path outside its CI isolation.

## License

No license file yet — treat as all-rights-reserved until one is added.
