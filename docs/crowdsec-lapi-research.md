# CrowdSec Local API — bouncer contract

Research for the native CrowdSec "local API" (LAPI) integration in bfirewall.
All facts below come from first-party CrowdSec documentation or CrowdSec-owned
source; each claim cites its source. Verified vs. unverified items are marked.
Sources were read on 2026-09-25 (docs version v1.8, code `master`).

## 1. Endpoints

Two endpoints are relevant to a firewall bouncer. Both live under the LAPI
(`basePath: /v1`; default `127.0.0.1:8080`) and are secured with the bouncer
API key (`APIKeyAuthorizer`, header `X-Api-Key`).

| Endpoint | Purpose | Response |
|---|---|---|
| `GET /v1/decisions` | Query mode: on-demand lookups (e.g. "is this IP banned?") | `200` JSON array of decisions, or JSON `null` when empty |
| `HEAD /v1/decisions` | Cheap auth/connectivity probe (returns `text/plain`, empty body) | `200` |
| `GET /v1/decisions/stream` | Stream mode: poll for decision deltas | `200` `{"new": [...], "deleted": [...]}` |
| `HEAD /v1/decisions/stream` | Probe; does NOT touch pull state | `200` |

- Swagger (generated spec): https://crowdsecurity.github.io/api_doc/lapi/
- Swagger source: https://github.com/crowdsecurity/crowdsec/blob/master/pkg/models/localapi_swagger.yaml
- Official usage doc ("For Remediation Components"): https://docs.crowdsec.net/docs/local_api/bouncers/
- Handler source: https://github.com/crowdsecurity/crowdsec/blob/master/pkg/apiserver/controllers/v1/decisions.go

`GET /v1/decisions` filter query params (swagger): `scope`, `value`, `type`,
`ip` (shorthand for `scope=ip&value=`), `range`, `contains` (bool; default true),
`origins`, `scenarios_containing`, `scenarios_not_containing`. `GET` on it only
returns *active* decisions (`Until >= now`).

`GET /v1/decisions/stream` filter query params (swagger): `startup` (bool),
`scopes`, `origins`, `scenarios_containing`, `scenarios_not_containing`.
Additional params accepted by the implementation but **not** in swagger:
`dedup` (default deduplicates overlapping decisions, keeping the longest-lived
one per scope+value; `dedup=false` disables) and `simulated` (decisions from
scenarios in simulation mode are excluded unless `simulated=true` is passed).
Source: https://github.com/crowdsecurity/crowdsec/blob/master/pkg/database/decisionfilter.go ,
https://github.com/crowdsecurity/crowdsec/blob/master/pkg/database/decisions.go

For a firewall, stream mode is the primary mechanism (the docs describe
streaming "polling" as the intended usage for bouncers maintaining a full
blocklist). If `scopes` is omitted on stream calls the implementation defaults
it to `ip,range` — i.e. only IP and range decisions — but pass it explicitly.
Source: `decisions.go` (`filters["scopes"] = []string{"ip,range"}`).

## 2. Authentication & key provisioning

- Auth is an API key sent as the `X-Api-Key` HTTP header. Docs example:
  `curl -H "X-Api-Key: <key>" localhost:8080/v1/decisions` → `HTTP/1.1 200 OK`.
  https://docs.crowdsec.net/docs/local_api/bouncers/
- The key is provisioned on the LAPI host with `sudo cscli bouncers add <name>`
  which prints `Api key for '<name>': <hex>` and warns the key is shown only
  once (only a hash is stored). A specific key can be set with `-k/--key`.
  Manage with `cscli bouncers list` / `cscli bouncers delete`.
  https://docs.crowdsec.net/docs/local_api/authentication/ ,
  https://docs.crowdsec.net/docs/cscli/cscli_bouncers_add/
- `cscli bouncers add` writes directly to the LAPI database, so run it on the
  LAPI host (or `docker exec` inside the CrowdSec container).
  https://docs.crowdsec.net/u/user_guides/lapi_mgmt/
- Alternative: TLS client-certificate auth. LAPI is configured with
  `api.server.tls` (`cert_file`, `key_file`, `ca_cert_path`,
  `bouncers_allowed_ou`); a bouncer cert whose OU matches is auto-provisioned
  (a `CN@IP` bouncer row is created on first use) — no API key needed.
  Revocation via CRL/OCSP is supported.
  https://docs.crowdsec.net/docs/local_api/tls_auth/
- Implementation details worth knowing (from middleware source
  https://github.com/crowdsecurity/crowdsec/blob/master/pkg/apiserver/middlewares/v1/api_key.go):
  - Keys are stored as SHA-512 hashes; bouncer identity is bound to the source
    IP — the first request from a new IP with a shared key creates a
    `name@ip` entry. Each pull state is tracked per bouncer row.
  - The middleware parses `User-Agent` as `<type>/<version>` and records it
    (`cscli bouncers list` TYPE/VERSION columns). Send a `User-Agent` like
    `bfirewall/<semver>`.

## 3. Response shape

`GET /v1/decisions` → `200` with a JSON array (or `null` if empty).
`GET /v1/decisions/stream` → `200` with:

```json
{"new": [ <Decision>, ... ] | null, "deleted": [ <Decision>, ... ] | null}
```

Both keys are always present; either list may be `null`/`[]`. Parse tolerantly.
Source: swagger `DecisionsStreamResponse`/`GetDecisionsResponse`; streamed as
chunked `application/json` by `streamDecisions` in `decisions.go`.

`Decision` object (swagger `definitions/Decision`; required: `origin`, `type`,
`scope`, `value`, `duration`, `scenario`):

| Field | Type | Meaning |
|---|---|---|
| `id` | int | decision id (read-only) |
| `uuid` | string | set for CAPI-synced decisions; `omitempty` |
| `origin` | string | e.g. `cscli`, `crowdsec`, `CAPI`, `lists`, `console`, `cscli-import`, `remediation_sync` (constants: https://github.com/crowdsecurity/crowdsec/blob/master/pkg/types/constants.go ) |
| `type` | string | action: `ban`, `captcha`, or custom (e.g. `enforce_mfa`) |
| `scope` | string | what `value` applies to: `Ip`, `Range`, `Country`, `AS`, `username`, ... |
| `value` | string | the IP (`192.168.1.1`), CIDR (`2.2.3.0/24`), or scope value |
| `duration` | string | remaining validity as a Go duration string, e.g. `3h59m57.64s`; **negative** on deleted/expired decisions (e.g. `-18897h25m52.8s`) |
| `until` | string | "the date until the decisions must be active" — defined in swagger but **not populated** by the current bouncer endpoints (`formatOneDecision` does not set it; `omitempty`). Do not rely on it. |
| `scenario` | string | e.g. `crowdsecurity/http-probing` or `manual 'ban' from '<machine>'` |
| `simulated` | bool | `omitempty`; not set on bouncer responses (simulated decisions are filtered out anyway) |

Go model: https://github.com/crowdsecurity/crowdsec/blob/master/pkg/models/decision.go
Formatting (duration = `until - now` rounded to seconds):
https://github.com/crowdsecurity/crowdsec/blob/master/pkg/apiserver/controllers/v1/decisions.go

**Scope casing is inconsistent in the wild**: docs examples show `"Ip"`,
`"Range"`, `"username"`, and CAPI-pushed decisions have been observed with
`"ip"` (docs example shows `"scope":"ip","value":"91.241.19.122/32"` — note
an `Ip`-scope value can itself carry a `/32` CIDR suffix). Server-side, the
`scopes=` filter lowercases `ip`/`range`/`country`/`as` and canonicalizes to
`Ip`/`Range`/`Country`/`AS` (constants in
https://github.com/crowdsecurity/crowdsec/blob/master/pkg/types/event.go ).
→ Compare `scope` case-insensitively and parse `value` as IP-or-CIDR.

## 4. Active vs. removed decision semantics (stream mode)

From https://docs.crowdsec.net/docs/local_api/bouncers/ (verified doc text)
plus `decisions.go` on master/v1.8:

- `startup=true`: returns the **full state** — all currently active decisions
  in `new`, plus *past deleted/expired* decisions in `deleted`. The docs
  explicitly say the initial response includes past deletions "to account for
  crashes/services restart" — a bouncer that restarts must be able to reconcile
  its local table from a full snapshot + deletions.
- `startup=false` (subsequent polls): returns only the **delta since this
  bouncer key's last pull** — newly added active decisions in `new`, decisions
  that expired (or were deleted, which is implemented as "expire now") since
  last pull in `deleted`.
- Pull state is tracked **per bouncer row on the server** (`last_pull` +
  decision-id cursor in v1.8/master; last_pull-only in older releases). The
  state is only advanced when the stream write succeeds, so a failed/truncated
  pull is retried next time.
- `deleted` entries carry the *remaining* (now negative) `duration`; the
  identifying fields are `scope`+`value` (and `id`, `type`). Apply deletions
  idempotently — the implementation deliberately uses a ~2 s overlap window
  for expirations, so the same deletion may be reported twice.
- A `new` decision already present locally should just refresh/overwrite
  (decision `id` and `scope`+`value` are the dedupe keys; `dedup` on by
  default already collapses overlapping decisions to the longest-lived).
- `null` lists are normal: after a `startup=true` pull, an immediate
  `startup=false` poll returns `{"deleted": null, "new": null}`.
- Deleting a decision (`cscli decisions delete`, console, expiry) is
  implemented by setting `until` to now (`ExpireDecisions*`), so "deleted" and
  "expired" decisions surface identically through the `deleted` array.
  Source: `expireDecisionBatch`/`ExpireDecisionsWithFilter` in
  https://github.com/crowdsecurity/crowdsec/blob/master/pkg/database/decisions.go
- HEAD requests never advance pull state (stream handler returns before any
  state update) — safe as a liveness probe.

## 5. IP/CIDR scopes for a firewall bouncer

- `scope=Ip`: `value` is a single IP **or** an IP with CIDR suffix
  (`91.241.19.122/32` observed in CAPI data). Treat as CIDR when parsing.
- `scope=Range`: `value` is a CIDR (`2.2.3.0/24`).
- Other scopes (`Country`, `AS`, `username`, ...) exist; a firewall should
  restrict to `ip,range` (send `?scopes=ip,range`; the server canonicalizes
  casing) or filter client-side.
- Decision `type`: `ban` maps to a firewall drop/reject. Non-block types
  (`captcha`, `enforce_mfa`, custom) are valid API output — filter to
  actionable types (`ban`; optionally treat unknown types as ban per local
  policy) rather than failing on them.
- `origin`: informational (`cscli`, `crowdsec`, `CAPI`, `lists`, ...); use for
  reporting/source labels, not enforcement decisions.
- Query-mode nicety: `GET /v1/decisions?ip=<ip>` returns the *containing*
  range decision too (e.g. querying `2.2.3.42` returns the `Range:2.2.3.0/24`
  ban) — good for a Fail2ban-style "is this source currently banned" check.

## 6. Errors & status codes

| Condition | Status | Body |
|---|---|---|
| Success | `200` | JSON (stream body may be chunked/streamed) |
| Missing/invalid `X-Api-Key`; TLS cert OU not allowed; revoked cert | `403` | `{"message":"access forbidden"}` |
| Bouncer identity resolvable but unusable (e.g. IP/User-Agent record update failure) | `403` | `{"message":"access forbidden"|"bad user agent"}` |
| Missing bouncer context inside handler (shouldn't happen through middleware) | `401` | `{"message":"not allowed"}` |
| Invalid params | swagger says `400` `{"message":...,"errors":...}` | **Caveat:** current source wraps filter errors (`invalid filter`, `invalid ip address / range`) into `QueryFail`, which `HandleDBErrors` maps to **`500`**. Treat any 4xx/5xx with a JSON `message` as an error surface; don't depend on the exact code. |
| DB failures mid-stream | `500` or a truncated JSON body | retry; pull state isn't advanced on failure so nothing is lost |

Sources: middleware (`api_key.go`) returns `http.StatusForbidden` with
`{"message": "access forbidden"}` (there's even a `XXX: StatusUnauthorized?`
comment noting it could arguably be 401); handlers (`decisions.go`) return 401
only if the bouncer context is absent; `HandleDBErrors`
(https://github.com/crowdsecurity/crowdsec/blob/master/pkg/apiserver/controllers/v1/errors.go)
maps `ItemNotFound`→404, `UserExists`→403, `HashError`→400, everything
else→500; swagger documents 400 `ErrorResponse{message, errors}` on the
decision endpoints.

TLS-auth failures likewise return `{"message":"access forbidden"}` per the
TLS doc examples (wrong OU, revoked cert).

## 7. Suggested client behavior for bfirewall

1. On start: `GET /v1/decisions/stream?startup=true&scopes=ip,range` → seed
   blocklist (apply `deleted` too, idempotently).
2. Poll `GET /v1/decisions/stream?scopes=ip,range` on a timer; apply `new` then
   `deleted`.
3. Compute a per-decision expiry from `duration` (Go duration string; parse
   `1h2m3.4s` / negative) so entries can age out even if a delta is missed.
4. HEAD `/v1/decisions` or `/v1/decisions/stream` for a health probe.
5. Send `User-Agent: bfirewall/<version>`; authenticate with `X-Api-Key`
   (or a client cert if TLS auth is configured).

## Gaps / unverified

- The `until` field: documented in swagger but never emitted by current code
  paths — treat `duration` as the only expiration signal.
- Exact status for invalid filter params (swagger `400` vs observed `500` path
  in `HandleDBErrors`) — noted above; handle both.
- Delta-cursor mechanics differ between releases (v1.8/master use an id cursor
  + `last_pull`; older releases used `last_pull` only). The wire contract
  (`startup` + `new`/`deleted`) is stable across versions.
- `limit`/`offset`/`id_gt`/`dedup`/`simulated` params exist in code but are
  undocumented; `dedup=false`/`simulated=true` are the only ones plausibly
  useful to us.
- First-party Go client for reference: https://github.com/crowdsecurity/go-cs-bouncer
  (streaming bouncer helper used by official remediation components) — not yet
  audited for extra behaviors.
