# bfirewall

A ufw-compatible firewall frontend for **nftables**, written in Go. The `bfw`
binary speaks the complete ufw command grammar — same syntax, same output
conventions, same exit codes — and can be symlinked/renamed to `ufw` as a
drop-in replacement. On top of the ufw grammar it adds extensions for named
IP sets, NAT, emergency panic mode, drift detection, and expiring rules.

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
- **App profiles** — INI profiles in `/etc/bfirewall/applications.d`,
  shipped defaults for OpenSSH, Nginx, mail, and misc services.
- **Migration** — `export`/`import` JSON state; `import-ufw` migrates a live
  ufw installation (`user.rules`, `user6.rules`, policies, `ufw.conf`).
- **Fragments & hooks** — ufw-style `before*.rules`/`after*.rules` nft
  fragments and `before.init`/`after.init` hooks.
- **systemd units** — boot-time load plus a sweep timer for expired rules.

## Requirements

- Linux with nftables (`nf_tables` kernel support)
- Go 1.22+ (build only)
- `nft` binary recommended for inspecting the live ruleset
- Root privileges for all mutating commands and for `status`/`check`

## Build & Install

```sh
make build          # produces ./bfw
sudo make install   # installs to /usr/sbin/bfw + systemd units
sudo make uninstall
```

Or with Go directly:

```sh
go build -o bfw ./cmd/bfw
```

Installation layout:

| Path | Purpose |
|---|---|
| `/usr/sbin/bfw` | the binary |
| `/etc/bfirewall/` | state dir: `rules.json`, `bfw.conf`, `sysctl.conf`, `applications.d/`, `before*.rules`/`after*.rules`, `*.init` hooks |
| `/etc/default/bfirewall` | tunables (`IPT_SYSCTL`, `IPT_MODULES`, `DEFAULT_APPLICATION_POLICY`, …) |
| `/etc/systemd/system/bfirewall.service` | loads rules at boot (`Before=network-pre.target`) |
| `/etc/systemd/system/bfirewall-sweep.{service,timer}` | periodic removal of expired rules |

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
bfw rule enable|disable NUM    # bfirewall extension: toggle without deleting
```

RULE supports the full ufw shape — `in|out` on interfaces, `from`/`to`
addresses and CIDRs, `port`, `proto`, `comment`, service names — plus
bfirewall extensions:

```sh
bfw allow from set trusted to any port 22 proto tcp   # named set endpoint
bfw allow 8080/tcp expires 2h                         # auto-expiring (Ns|Nm|Nh|Nd)
```

### Policy & logging

```sh
bfw default allow|deny|reject incoming|outgoing|routed
bfw logging off|low|medium|high|full
```

### Application profiles

```sh
bfw app list                     # profiles from /etc/bfirewall/applications.d
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
bfw import-ufw [--dir DIR]     # migrate ufw user.rules/user6.rules + policies + ufw.conf
```

### Global flags

| Flag | Effect |
|---|---|
| `--dry-run` | Render/validate without touching kernel or disk |
| `--force`, `-f` | Skip interactive prompts (e.g. `reset`, `panic` over ssh) |
| `--json` | JSON output where supported |
| `--version` | Print version |

## Architecture

```
cmd/bfw            entrypoint — argv[0]=="ufw" enables drop-in mode
internal/cli       full ufw grammar parser + commands + output conventions
internal/rule      canonical rule model (Rules4/Rules6 dual lists)
internal/store     persistent state under /etc/bfirewall
internal/backend   backend interface (atomic apply, read-back, fragments)
internal/backend/nft   nftables compiler/renderer via google/nftables netlink
internal/appprof   INI application-profile parsing/expansion
internal/sysstate  sysctl writes, modprobe, ssh detection, mutating flock
internal/impexp    export/import + ufw migration
internal/defaults  embedded default profiles/sysctl, lazily materialized
internal/report    `show` reports
internal/services  service-name → port resolution
packaging          systemd units
tests              integration tests (build tag `integration`)
```

State lives in `/etc/bfirewall/rules.json` (atomic tmp+rename, mode 0600).
Mutating commands take an exclusive flock on `/run/bfw.lock`. `enable`
runs `before.init start` (abort on failure), applies the core ruleset in one
netlink transaction, applies `before*.rules`/`after*.rules` fragments in a
second transaction (rolling back core on failure), then applies
`sysctl.conf` and `IPT_MODULES`.

## Development

```sh
make test               # go test ./...
make test-integration   # go test -tags=integration ./tests/...
go build ./...
```

CLI internals are dependency-injected (`hookGeteuid`, `hookUnderSSH`,
`hookLockFile`, `hookRunCmd`, replaceable backend constructor) so the command
surface is testable without root or a kernel.

## License

No license file yet — treat as all-rights-reserved until one is added.
