# Two-laptop firewall showcase

This showcase checks externally observable firewall behavior and a few operator workflows: permitted and default-denied inbound TCP, a source-restricted allow rule, rule logging, status/check/diff, and rule disable/enable. It does not cover every bfw feature: NAT, migration, CrowdSec, login protection, IPv6 routing, and destructive panic behavior need separate setups and are not safe to exercise in this walkthrough.

Use two Linux laptops on a private LAN that you control. On the firewall laptop, build bfw from the project checkout with `make build`; this creates `./bfw` locally and does not install it on PATH. The firewall laptop also needs nftables available. Keep physical/console access while changing firewall rules; do not run this over the only SSH session. These commands change the firewall laptop's active policy. Use a dedicated lab machine or restore its prior configuration afterward.

## 1. Start listeners on the firewall laptop

From the project checkout, start four HTTP listeners in one terminal:

```sh
scripts/perf/showcase-server.sh
```

The listeners serve ports 8080–8083 on all interfaces. Keep this process running. Find the firewall laptop's LAN address with `ip -br addr`.

## 2. Configure bfw on the firewall laptop

Find the client laptop's LAN address with `ip -br addr`. Replace the sample address `192.168.1.50` below with that actual address; do not type placeholder angle brackets into the shell. If managing the firewall remotely, add an allow rule for your management connection before changing the default policy; retain console access. Run these from the repository checkout on the firewall laptop after `make build`:

```sh
sudo ./bfw default deny incoming
sudo ./bfw allow 8080/tcp
sudo ./bfw allow from 192.168.1.50 to any port 8082 proto tcp
sudo ./bfw allow log 8083/tcp
sudo ./bfw logging medium
sudo ./bfw enable
sudo ./bfw status numbered
sudo ./bfw check
sudo ./bfw diff
```

Port 8081 has a running HTTP server but no allow rule, so the default incoming policy should block it. Port 8082 is allowed only from the configured client address. Port 8083 is allowed with per-rule logging.

## 3. Run the client suite

Install k6 on the client or add the project's local `.tools/bin` to your `PATH`. Replace the example server address `192.168.1.10` below with the firewall laptop's actual LAN address:

```sh
scripts/perf/test-target.sh 192.168.1.10
```

Expected: 8080 allowed, 8081 blocked, 8082 allowed from the configured source, and 8083 allowed. To use different ports, set `PERF_HTTP_PORT`, `PERF_DENIED_PORT`, `PERF_SOURCE_PORT`, and `PERF_LOGGED_PORT`; the same values must be set for the server listener script.

On the firewall laptop, watch rule log output in another terminal:

```sh
sudo ./bfw --stream-logs
```

The request to port 8083 should produce a BFW log entry. Log output depends on kernel/journal configuration and is not itself a pass/fail gate in the client script.

## 4. Demonstrate a rule transition

Get the number of the 8080 allow rule from `sudo ./bfw status numbered`. In the examples below, replace `1` with the actual number printed for that rule:

```sh
sudo ./bfw rule disable 1
```

From the client laptop, the whole suite should still pass with the primary 8080 probe expected to be blocked:

```sh
env PERF_HTTP_MODE=blocked scripts/perf/test-target.sh 192.168.1.10
```

Re-enable the rule and rerun the normal suite:

```sh
sudo ./bfw rule enable 1
scripts/perf/test-target.sh 192.168.1.10
```

## 5. Stop and restore

Stop the listeners with Ctrl-C. Remove only the showcase rules you added, using their rule numbers from `sudo ./bfw status numbered`; avoid `bfw reset` on a machine with existing policy. Restore the prior default policy and logging setting if you changed them, then verify with `sudo ./bfw status` and `sudo ./bfw check`.

The suite demonstrates network behavior plus basic operator interactions; it is not a complete integration test for every command or extension. CI's privileged integration and performance jobs remain restricted to disposable GitHub-hosted runners.
