# certsight-fleet-manager — design plan

Status: proposal, 2026-09-15. Nothing here is implemented.

## Problem

CertSight has fleet-wide *observability* (Grafana, the three fleet explorers,
the MCP server) but no fleet-wide *control*. Turning a Tetragon policy off on
a node today means SSH + `tetra tracingpolicy disable` (and remembering that
it comes back on the next Tetragon restart), or a Helm upgrade on k8s. There
is no place to see "which policies are enabled where" as a single table, and
no way to act on it.

## Goals

- **v1:** a web console that lists every analyzer node, shows the
  enabled/disabled state of every Tetragon policy per node, and lets an
  operator toggle a policy on one node or on all nodes — durably. The three
  fleet explorers (blast radius, chain, FIPS rollout) are surfaced in the
  same UI so it becomes the one "fleet" entry point.
- **v2:** per-node cert-analyzer config editing, and start/stop/restart of
  cert-analyzer and Tetragon.

Non-goals (all versions): adding/deleting policies (the policy *set* stays
owned by the RPM / Helm chart), editing policy YAML, managing Prometheus or
Grafana, replacing the test console.

## Architecture

Two pieces. One is new; the other is a small extension of cert-analyzer.

```
 browser ──HTTPS──▶ certsight-fleet-manager (new, one per fleet)
                       │            │
            reads      │            │ writes (authenticated)
                       ▼            ▼
                  Prometheus     cert-analyzer :8086  (per node, existing
                  (existing)     HealthServer + new /control/* routes)
                                        │
                                        ▼ gRPC ConfigureTracingPolicy
                                     Tetragon (per node, existing socket)
```

### Why extend cert-analyzer rather than ship a separate node agent

- It already has the Tetragon gRPC channel, the socket permission
  (`tetragon-override.conf` chgrps the socket to `cert-analyzer`), the
  reconnect loop, and a policy-listing call. `ConfigureTracingPolicy` is one
  more RPC on the same stub.
- It already runs an HTTP server on every node (`agent/health.py`). Adding
  routes is cheaper than a new process, RPM, user, and firewall port.
- One fewer thing to install, version, and keep in step per node. The RPM
  `Requires` chain and the k8s DaemonSet don't change shape.
- The privilege boundary stays where it is for v1: policy toggles need no
  root. (v2 is where this gets revisited — see below.)

### Why reads go through Prometheus, not the nodes

Fleet manager never has to fan out N requests to build a page.
`tetragon_policy_info`, `cert_analyzer_build_info`, `tetragon_connected`,
`cert_analyzer_healthy`, `cert_analyzer_last_event_timestamp` etc. all carry
`node_name` and are already scraped. Node inventory is
`/api/v1/targets` + `cert_analyzer_build_info`. This also means the console
degrades to read-only, not dead, when a node's control port is unreachable —
and it's the same data source the explorers and the MCP server already use.

The write path is the only thing that talks to nodes directly.

## v1 — policy control

### Node side (cert-analyzer)

New config section:

```ini
[control]
enabled = false                 # off by default; HealthServer stays as today
token = <fleet shared secret>   # required when enabled; 32+ random bytes
state_path = /var/lib/cert-analyzer/policy-state.json
```

New routes on the existing HealthServer (same port, 8086):

| Route | Method | Purpose |
|---|---|---|
| `/control/policies` | GET | Live `ListTracingPolicies` result plus desired state from `state_path` — so the caller sees drift |
| `/control/policies/{name}` | PUT `{"enabled": bool}` | Persist desired state to `state_path`, then `ConfigureTracingPolicy(enable=…)`. Returns observed state after the call |
| `/control/info` | GET | version, node_name, platform (host/k8s), capabilities list (`["policies"]` in v1, `["policies","config","lifecycle"]` later) so the UI knows what it may offer per node |

Auth: `Authorization: Bearer <token>`, constant-time compare, every
`/control/*` request. Unauthenticated requests get 401 with no body.
`/healthz` and `/readyz` stay unauthenticated. Bind address stays as today
(the health server already listens on all interfaces for the k8s probes).

**Reconciliation — the part that makes disables stick.** After every
Tetragon (re)connect, right where `check_tetragon_policies(stub)` is called
today (`agent/analyzer.py:918`), read `state_path` and re-apply any policy
whose desired state differs from what Tetragon reports. This is what
survives a Tetragon restart on bare metal (where `tetragon.tp.d` reloads
everything enabled) and a DaemonSet pod restart on k8s (where the CR does).
Log each re-application at INFO; count them in a new
`cert_analyzer_policy_reconciliations_total{policy,node_name}` so the
dashboard can show a node that keeps fighting its Tetragon.

Only policies that are *present* in Tetragon are ever touched. If desired
state names a policy Tetragon no longer has, it's reported as `stale` in
`/control/policies` and left alone.

Audit: every PUT is logged at WARNING with the remote address and the
policy/state — it's the first thing in cert-analyzer that changes system
behaviour on request, so it should be loud in the journal.

Metrics/tests: unit tests around the new handler and the reconcile step
with a fake stub (the pattern `test_cert_analyzer.py` already uses for
`check_tetragon_policies`).

### Fleet-manager side (new, `extras/fleet-manager/`)

Python stdlib HTTP server + static UI, same stack as the test-server and MCP
server. No framework, no build step, no npm.

```
extras/fleet-manager/
  server.py              routes, Prometheus + node client, auth
  fleet_state.py         node inventory + policy matrix from Prometheus
  node_client.py         thin client for /control/* with timeouts
  static/{index.html,app.js,app.css}
  fleet-manager.conf     systemd EnvironmentFile
  certsight-fleet-manager.service
  certsight-fleet-manager.spec
  build-rpm.sh
  FLEET-MANAGER-README.md
```

Config (`/etc/certsight-fleet-manager/fleet-manager.conf`):

```
FLEET_MANAGER_BIND=127.0.0.1          # put nginx in front for anything else
FLEET_MANAGER_PORT=8094
FLEET_MANAGER_PROMETHEUS_URL=http://127.0.0.1:9090
FLEET_MANAGER_NODE_TOKEN=...          # same value as every node's [control] token
FLEET_MANAGER_CONTROL_PORT=8086       # default; per-node override below
FLEET_MANAGER_NODE_OVERRIDES=/etc/certsight-fleet-manager/nodes.json  # optional
FLEET_MANAGER_ADMIN_PASSWORD_HASH=... # UI login, see Security
FLEET_MANAGER_AUDIT_LOG=/var/lib/certsight-fleet-manager/audit.jsonl
```

Node discovery: `GET /api/v1/targets` → for each `up` cert-analyzer target
take `instance` host + `node_name` label. Control URL =
`http://<host>:<control_port>`. `nodes.json` lets an operator override the
control URL per `node_name` for the cases where the scrape address isn't the
control address (k8s pod IP vs hostPort, NAT, a Prometheus that scrapes via
a proxy). Nodes without a reachable control endpoint still render — as
read-only rows with a "control unreachable" badge.

Pages / routes:

| UI | Backing route | Source |
|---|---|---|
| Nodes | `GET /api/nodes` | Prometheus: version, healthy, tetragon_connected, last event age, policy counts, control reachability |
| Policies (matrix: nodes × policies) | `GET /api/policies` | Prometheus `tetragon_policy_info` for observed state; node `/control/policies` for desired state + drift, fetched lazily per row |
| Toggle one cell | `PUT /api/nodes/{node}/policies/{name}` | node client |
| Toggle a column (all nodes) | `POST /api/policies/{name}` `{"enabled":bool}` | fan-out with per-node results; UI shows partial success honestly |
| Explorers | `/fleet-blast-radius`, `/fleet-chain-explorer`, `/fleet-fips-rollout` | `generate(prometheus_url)` from the test-server modules, exactly as the test-server and MCP server mount them |
| Audit | `GET /api/audit` | tail of `audit.jsonl` |

Explorer reuse: `sys.path.insert(0, CERTSIGHT_TEST_SERVER_DIR)` and
`Requires: certsight-test-server` — the pattern `extras/mcp-server/server.py`
and `certsight-mcp.spec` already use. It's a hand-synced-copy smell
(`blast_radius.py` is already a copy of `extras/cert_blast_radius.py`), but
a shared `certsight-fleet-common` package is a separate refactor and
shouldn't gate this. Note it in the README; do it when the third consumer
(this one) hurts enough.

UI behaviour that matters:

- The matrix cell shows *observed* state (Prometheus) and flags drift
  against *desired* state (node). A cell that's been toggled but hasn't
  reported back yet shows a pending spinner, then reads back from the node —
  never assumes success.
- Bulk toggles confirm with the node count before firing and stream results
  per node. Partial failure is normal (a node mid-upgrade) and is shown, not
  collapsed into a red banner.
- Each node row says `host` or `k8s`, because on k8s a per-node disable is a
  *node-local* override of a cluster-wide CR, and the operator should know
  that's what they're doing.
- Explorers open in the same shell (nav bar + page), not as bare pages.

### Security posture (v1 is the first CertSight component that writes)

The test console's "no auth, lab only" stance is fine for something that
only fires demo traffic. The fleet manager can switch off detection across a
fleet, so:

- UI login required from day one: single admin account, password hash in
  config (`hashlib.scrypt`), session cookie, `Secure`/`HttpOnly`/`SameSite=Strict`.
  No self-registration, no "default admin/admin" (see the 2026-07-13 Grafana
  incident).
- Node writes authenticated by the shared token; nodes with `[control]`
  disabled simply don't expose the routes.
- Fleet manager binds to loopback by default; the AWS demo puts it behind
  the existing nginx with TLS, same as the MCP endpoint. HTTP Basic at nginx
  is *additional*, not a substitute for the app login.
- Audit log is append-only JSONL: timestamp, user, action, node, policy,
  result. Also mirrored to the journal.
- CSRF: state-changing routes require a header the static UI sets
  (`X-Requested-With`) and reject cross-origin `Origin`.
- v2 (mTLS between fleet manager and nodes) is listed below; a bearer token
  is deliberately the v1 floor so the node side stays a few dozen lines.

### Deployment

- RPM `certsight-fleet-manager` (user `certsight-fleet-manager`, same shape
  as `certsight-mcp.spec`), plus a container image for the k8s-hosted case.
- AWS demo: install on the analyzer node, nginx location `/fleet/` with TLS
  and the demo's rate-limit block; enable `[control]` on both demo nodes.
  The k8s node needs its health port exposed as a hostPort (it's currently
  only reachable in-cluster) and a firewalld opening — the same class of gap
  found for Kafka and Prometheus when that node was added.
- cert-analyzer RPM/Helm: new `[control]` section shipped disabled; Helm
  gets `control.enabled` / `control.tokenSecretRef`.

### v1 exit criteria

- On the AWS demo (2 nodes: host + k8s), disabling `openssl3-cert-load` on
  the k8s node from the UI stops that node's `SSL_CTX_use_certificate*`
  events in the Event Sources dashboard row, the bare-metal node is
  unaffected, and the policy stays disabled across a `systemctl restart
  tetragon` / Tetragon pod restart.
- Bulk-disable then bulk-enable across both nodes shows correct per-node
  results, and the audit page shows four entries.
- Explorers render inside the fleet manager with the same output as the
  test console.
- A node with control disabled appears in the matrix as read-only.

## v2 — config and lifecycle

Both v2 features cross the privilege boundary cert-analyzer currently sits
behind, so they're a design decision, not just more routes.

### Per-node config

Don't write `/etc/cert-analyzer/cert-analyzer.conf` (root-owned, RPM-owned).
Instead layer an override file the analyzer's own user can write:

```
/etc/cert-analyzer/cert-analyzer.conf            base (RPM, root)
/var/lib/cert-analyzer/fleet-override.conf       fleet-managed (cert-analyzer user)
```

`agent/config.py` reads both, override wins. The fleet manager edits the
override through `PUT /control/config` (validated against a declared schema
of the fields that are safe to change remotely — e.g. `[port_probe]` rates,
`[scanning]` paths, `[certificates]` thresholds, **not** `[tetragon]` socket
or `[control]` itself). No privilege needed. This also gives a clean
"reset to package defaults" = delete the override.

Applying a change needs a restart today: `agent/config.py` handles SIGTERM
only, there is no SIGHUP reload. Two options, in order of preference:

1. Add a SIGHUP reload for the fields the override schema allows (rate
   limits, thresholds, scan paths). Anything not hot-reloadable is marked
   `restart_required` in the schema and the UI says so.
2. Fall through to the lifecycle restart below.

### Start / stop / restart

cert-analyzer can't restart itself or Tetragon unprivileged. Options:

| Option | How | Trade-off |
|---|---|---|
| **polkit rule** (recommended) | `/etc/polkit-1/rules.d/50-cert-analyzer.rules` allowing user `cert-analyzer` `org.freedesktop.systemd1.manage-units` for exactly `tetragon.service` and `cert-analyzer.service`; call systemd over D-Bus | No new process, no sudo, scoped to two units. Ships in the cert-analyzer RPM. Not applicable on k8s |
| sudoers + `systemctl` | `NOPASSWD` entry for the two commands | Simpler to read, but sudo-in-a-daemon is the pattern the deployer-caps work moved away from |
| separate privileged `certsight-node-agent` | tiny root service with its own socket | Cleanest boundary, but a third RPM per node and a second thing to keep in step. Only worth it if v3 wants more root actions |

On k8s, "restart" = delete the DaemonSet pod (kubelet recreates it). That's
a fleet-manager-side action using a service account with `pods/delete` on
the one namespace, not a node-side one. Tetragon restart on k8s is the same.

Semantics: a `restart cert-analyzer` request is acked *before* the process
dies; the fleet manager treats a dropped connection after the ack as
expected and polls `/readyz` until it's back, with a timeout. `stop` needs
an explicit second confirmation in the UI because it stops detection on
that node until someone starts it again.

### v2 security additions

- mTLS between fleet manager and node control endpoints (CertSight can
  issue and rotate the pair itself; and it'd be odd for a cert tool to
  leave this on a shared token forever).
- Per-action authorisation: `viewer` / `operator` (policies) / `admin`
  (config, lifecycle). Still a local user table; no OIDC until someone
  asks.

## MCP server

Stays read-only. If write tools are ever wanted (`disable_policy`), they go
through the fleet manager's authenticated API, not straight to nodes — one
audit log, one auth boundary.

## Sequencing

1. cert-analyzer `[control]` + `/control/*` + reconciliation + tests
   (one PR, no UI, verifiable with `curl`).
2. Fleet manager skeleton: nodes page + policy matrix + login + audit
   (second PR). Explorers mounted here too — it's a few lines given the
   MCP precedent.
3. RPM + AWS demo rollout + exit criteria check (third PR; includes the k8s
   hostPort/firewalld work).
4. Release tag; README + DASHBOARDS/FIELDS updates for the new metric.
5. v2 items as separate branches, config first (no privilege needed),
   lifecycle second (polkit rule decision made then).

## Open questions

- Should a disable also be *reported* as a distinct state in Grafana's Node
  Health row (`tetragon_policy_info{state="disabled"}` already exists —
  probably just a panel change)?
- Fleet manager on k8s as a Deployment with the Helm chart, or host-only
  for now? Host-only for v1 unless the demo needs otherwise.
- Token distribution: manual in v1. Worth a `certsight-fleet-manager
  gen-token` helper that prints the two config lines.
