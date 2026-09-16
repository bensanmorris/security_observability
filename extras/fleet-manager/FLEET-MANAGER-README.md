# certsight-fleet-manager

The fleet control console: one page for every cert-analyzer node, a
nodes × policies matrix of Tetragon tracing-policy state, and the ability
to switch a policy on or off on one node or fleet-wide — durably. The
three fleet explorers (blast radius, chain explorer, FIPS rollout) are
served here as well, so this is the single fleet entry point.

Design and roadmap: [`extras/FLEET-MANAGER-PLAN.md`](../FLEET-MANAGER-PLAN.md).

## How it works

```
 browser ──▶ certsight-fleet-manager ──reads──▶ Prometheus
                      │
                      └──writes (token / mTLS)──▶ cert-analyzer :8087 [control] listener  (per node)
                                                        └── gRPC ──▶ Tetragon
```

- **Reads never touch the nodes.** Node inventory, health, and the policy
  matrix come from series cert-analyzer already exports
  (`cert_analyzer_build_info`, `cert_analyzer_healthy`,
  `tetragon_connected`, `tetragon_policy_info`, …). A node whose control
  port this host can't reach still renders, read-only.
- **Writes go to the node.** `PUT /control/policies/<name>` on the node's
  dedicated `[control]` listener (port 8087, loopback by default),
  authenticated by a shared token and/or mutual TLS. The node records the
  decision and re-applies it after every Tetragon restart, so a disable
  made here sticks — see the `[control]` section of the main README.
- The only per-node reads are a short, parallel, cached fan-out to
  `/control/info` + `/control/policies` so the UI can show which nodes
  are controllable and whether any recorded decision has drifted.

## Prerequisites

- Prometheus scraping every cert-analyzer node.
- `[control] enabled = true` with a token and/or `tls_client_ca` on each
  node you want to control (`/etc/cert-analyzer/cert-analyzer.conf`).
  Nodes without it still appear, read-only, and the Control column says
  which case it is: **control off** (`[control]` disabled in config),
  **no control (not installed)** (the node has the base `cert-analyzer`
  only, not `cert-analyzer-control` — there is nothing to enable),
  **unreachable** (the node says its listener is
  on but this host can't reach it), **unauthorized** / **refused** (the
  node answered 401 / 403), or **read-only client** (the node accepts
  this console's certificate for reads only). The node reports the first
  two through `cert_analyzer_config_info{fleet_control=...}`, so they are
  known even when nothing is listening.
- A path from this host to each node's `[control]` listener. It binds
  loopback by default, so either: keep it there and reach it through an
  SSH tunnel (map the node to `http://127.0.0.1:<local port>` in the
  overrides file), or set `listen` to a management interface on the node,
  restrict it with `allowed_sources` + the node firewall to this host, and
  put TLS on it (below). k8s nodes run `hostNetwork`, so the listener is
  on the node IP at whatever `control.listen` the chart sets.
- Python 3.9+. No third-party packages — stdlib only.
- For the explorer pages, `extras/test-server/` alongside (source
  checkout) or the `certsight-test-server` RPM (`CERTSIGHT_TEST_SERVER_DIR`).

## Installation

The fleet manager runs on **one** host per fleet — the natural place is the
Prometheus/Grafana host, since every read goes to Prometheus. It is a
noarch RPM (pure Python, stdlib only) that pulls in `certsight-test-server`
for the explorer pages. Nothing else on that host changes.

### 1. Decide which cert-analyzer package your nodes run

Fleet control is a separate, opt-in package on each node. The base
`cert-analyzer` RPM and the default container image contain **no
fleet-control code at all** — nothing to enable, `[control] enabled = true`
is a logged error — so upgrading an existing node adds no control surface.

| Package / image | What it adds |
|---|---|
| `cert-analyzer-<ver>-1.el9.x86_64.rpm`, `…:<tag>-ubi9` | The monitor. No `[control]` code |
| `cert-analyzer-control-<ver>-1.el9.x86_64.rpm` (`Requires: cert-analyzer = <ver>`), `…:<tag>-ubi9-control` | The two `[control]` modules: the listener, **off by default**, loopback by default, until `[control] enabled = true` |

The fleet manager works with either. Against nodes without the control
package it is a read-only fleet console (nodes, matrix, explorers, audit)
and says so per node — *no control (not installed)* — which is the right
first deployment where a security review has not yet accepted a control
surface on nodes. Adding control to a host later is
`dnf install ./cert-analyzer-control-<ver>-1.el9.x86_64.rpm` (cert-analyzer
restarts and picks the modules up); `dnf remove cert-analyzer-control`
withdraws it again. On Kubernetes, switch `image.tag` to the `-control`
variant (see the chart README).

### 2. Install the console

```bash
sudo dnf install ./certsight-fleet-manager-<ver>-1.el9.noarch.rpm   # pulls in certsight-test-server
```

This creates the `certsight-fleet-manager` system user, installs to
`/opt/certsight-fleet-manager`, the unit `certsight-fleet-manager.service`,
and the config `/etc/certsight-fleet-manager/fleet-manager.conf`
(`root:certsight-fleet-manager 0640` — it will hold two secrets). The
service is not started yet.

### 3. Configure

Generate the admin password hash (prompts twice; prints one line):

```bash
certsight-fleet-manager --hash-password
```

Then edit `/etc/certsight-fleet-manager/fleet-manager.conf`. The minimum:

```bash
FLEET_MANAGER_ADMIN_PASSWORD_HASH=scrypt$...        # from --hash-password
FLEET_MANAGER_PROMETHEUS_URL=http://127.0.0.1:9090  # the Prometheus scraping every node
FLEET_MANAGER_AUDIT_LOG=/var/lib/certsight-fleet-manager/audit.jsonl
```

Node credentials — add these once you have done step 5, or now if you
already know the values:

```bash
FLEET_MANAGER_NODE_TOKEN=<the nodes' [control] token>    # token auth
# and/or mutual TLS (step 5c):
#FLEET_MANAGER_NODE_TLS_CA=/etc/certsight-fleet-manager/pki/ca.crt
#FLEET_MANAGER_NODE_CLIENT_CERT=/etc/certsight-fleet-manager/pki/fleet-manager.crt
#FLEET_MANAGER_NODE_CLIENT_KEY=/etc/certsight-fleet-manager/pki/fleet-manager.key
```

Without either the console still starts, but every node shows
*unauthorized* and a warning banner tells the admin so. For a read-only
console (a fleet without `cert-analyzer-control`, or a viewer-only deployment) simply leave
them unset.

The file is annotated; the remaining settings (bind/port, viewer access,
node overrides, timeouts) are all documented in place.

### 4. Start it

```bash
sudo systemctl enable --now certsight-fleet-manager
sudo journalctl -u certsight-fleet-manager -n 5      # "serving on http://127.0.0.1:8094 (... accounts: admin (admin))"
```

Open `http://127.0.0.1:8094` (an SSH tunnel from your workstation is the
simplest way while it is on loopback). Sign in as `admin`. The **Nodes**
page should list every node Prometheus is scraping, with the Control
column saying *control off* or *no control (not installed)* — expected,
nothing is enabled on the nodes yet.

The console binds loopback by default. To expose it further, put nginx
with TLS in front — `extras/aws-demo/user-data.sh` has a complete
`server` block (rate-limited `/api/login`, `X-Forwarded-For` and
`X-Forwarded-Proto` passed through so audit entries carry the real client
and the session cookie is marked `Secure`). Don't just change
`FLEET_MANAGER_BIND`: this console can switch detection off fleet-wide.

### 5. Enable `[control]` on the nodes you want to control

Skip this for a read-only console. Otherwise, on each node
(`/etc/cert-analyzer/cert-analyzer.conf`, then `systemctl restart
cert-analyzer`), pick the pattern that fits how the console reaches the
node. Generate one token for the fleet first:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
```

**(a) Loopback listener + SSH tunnel** — nothing new listens on the network.

```ini
[control]
enabled = true
token = <fleet token>
# listen stays at its default 127.0.0.1:8087
```

On the console host, keep a tunnel per node
(`ssh -N -L 18087:127.0.0.1:8087 node-a`, e.g. as a systemd unit) and map
each node in `FLEET_MANAGER_NODE_OVERRIDES`:

```json
{ "node-a": "http://127.0.0.1:18087", "node-b": "http://127.0.0.1:18088" }
```

**(b) Management interface + source allowlist + TLS** — the console dials
the node directly.

```ini
[control]
enabled = true
listen = 10.0.1.7:8087                 # a management address, never 0.0.0.0 on a public host
allowed_sources = 10.0.1.5/32          # the console's address; checked before auth
token = <fleet token>
tls_cert = /etc/cert-analyzer/control/server.crt
tls_key = /etc/cert-analyzer/control/server.key
```

Open 8087 from the console's address in the node firewall
(`firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=10.0.1.5/32 port port=8087 protocol=tcp accept'`).
Set `FLEET_MANAGER_NODE_TLS_CA` on the console so node URLs become `https`
and the node certificate is verified. Without `tls_cert`/`tls_key` the
token crosses the network in clear and cert-analyzer warns at startup.

**(c) Mutual TLS** — (b) plus a client certificate, so the node authorises
the console by certificate CN and can hand a second console read-only
access:

```bash
# on the console host
./gen-control-certs.sh --out /etc/certsight-fleet-manager/pki --auditor node-a:10.0.1.7 node-b:10.0.1.8
```

Copy `node-<name>.crt/.key` + `ca.crt` to each node's
`/etc/cert-analyzer/control/` and add:

```ini
tls_client_ca = /etc/cert-analyzer/control/ca.crt
authorized_clients = fleet-manager     # may change policies
readonly_clients = fleet-auditor       # may only read (optional)
```

and on the console `FLEET_MANAGER_NODE_TLS_CA` / `_NODE_CLIENT_CERT` /
`_NODE_CLIENT_KEY`. A token may be kept as well; then both are required.

**(d) Kubernetes (Helm chart)** — the DaemonSet runs `hostNetwork`, so the
listener is on the node IP:

```bash
helm upgrade cert-analyzer extras/helm/cert-analyzer \
  --set control.enabled=true \
  --set control.token=<fleet token> \
  --set control.allowedSources=10.0.1.5/32
  # mutual TLS: --set control.tls.existingSecret=<Secret with tls.crt/tls.key/ca.crt>
```

Open 8087 from the console on the k8s nodes' firewall/security group. A
per-node disable on k8s is a node-local override of the cluster-wide
TracingPolicy object; the matrix column says `k8s` to remind you. See the
chart README's *Fleet control* section for `control.state.hostPath`
(keeps recorded decisions across pod replacement).

Whichever pattern: cert-analyzer logs
`Fleet control listening on http(s)://…` at startup, or an error and
`Fleet control stays OFF` if anything is inconsistent (short token, half a
TLS pair, …) — detection is never lost over a control-plane typo.

### 6. Check

Refresh the **Nodes** page. Each controlled node's Control column should
now read `host` / `k8s` / `container` in green, with its control URL
beneath. Anything else names the problem:

| Badge | Meaning | Fix |
|---|---|---|
| *control off* | node reports `[control] enabled = false` | step 5 on that node |
| *no control (not installed)* | node has `cert-analyzer` only | `dnf install cert-analyzer-control` (or the `-control` image), or accept read-only |
| *unreachable* | node says its listener is on, console can't connect | firewall, `allowed_sources`, tunnel/override URL, wrong port |
| *unauthorized* | node answered 401 | `FLEET_MANAGER_NODE_TOKEN` ≠ the node's `token` |
| *refused* | node answered 403 | console address not in `allowed_sources`, or client CN in neither list |
| *read-only client* | node accepts this console's certificate for reads only | its CN is in `readonly_clients`, not `authorized_clients` |
| *not a control port* | something answered without `/control` routes | the URL points at the health port (8086) or another service |

On the **Policies** page, disable one policy on one node, then `systemctl
restart tetragon` on that node: within seconds the cell should return to
*disabled* (the node re-applied its recorded decision; the reconciliation
is counted in `cert_analyzer_policy_reconciliations_total`). The **Audit**
page shows the change with your username and address.

### 7. Optional: read-only access for others

Two ways to let people look without being able to change anything; both
are enforced server-side (every write route answers `403 read_only`):

- **A viewer account** — for an on-call rota or an auditor:

  ```bash
  certsight-fleet-manager --hash-password        # a different password
  # add to fleet-manager.conf:
  FLEET_MANAGER_VIEWER_PASSWORD_HASH=scrypt$...
  sudo systemctl restart certsight-fleet-manager
  ```

  The landing page gains a *Read-only viewer access →* link under the
  administrator form; it asks for that password as a single access code.

- **Anonymous viewers (demo / wallboard)** — no credentials, one click:

  ```bash
  # add to fleet-manager.conf:
  FLEET_MANAGER_ANONYMOUS_VIEWER=1
  FLEET_MANAGER_READ_ONLY_NOTE=Public demo: anyone may look; changing a policy needs the admin login.
  sudo systemctl restart certsight-fleet-manager
  ```

  The landing page gains *Continue as read-only viewer →* with that note.
  Nobody gets a session just for arriving; entering the read-only view is
  an explicit step, and *Leave read-only view* returns to the landing
  page. A *Sign in* button in the header leads back to the administrator
  form. If both are configured, the landing page offers the anonymous
  link; the account still works through `POST /api/login`.

  With anonymous viewers and **no** `FLEET_MANAGER_ADMIN_PASSWORD_HASH` at
  all, the console is provably read-only — the process holds no
  credential that can produce a write — and its banner and startup log
  say so. That, on a fleet without `cert-analyzer-control`, is the
  least-privilege deployment.

This is how the AWS demo is set up (`extras/aws-demo/user-data.sh`):
anonymous viewers behind nginx on port 8094, admin password generated at
install and kept root-only on the instance.

## Run from a source checkout

```bash
cd extras/test-server && python3 -m venv .venv && . .venv/bin/activate   # explorers' deps
cd ../fleet-manager
export FLEET_MANAGER_ADMIN_PASSWORD_HASH="$(python3 server.py --hash-password)"
export FLEET_MANAGER_NODE_TOKEN='<same value as every node's [control] token>'
python3 server.py --prometheus-url http://127.0.0.1:9090
# → http://127.0.0.1:8094  (user: admin)
```

## Configuration

Every flag has a `FLEET_MANAGER_*` environment variable; the systemd unit
reads them from `/etc/certsight-fleet-manager/fleet-manager.conf`. See
that file for the full annotated list. The ones that matter:

| Variable | Purpose |
|---|---|
| `FLEET_MANAGER_ADMIN_PASSWORD_HASH` | scrypt hash from `--hash-password` for the `admin` account (the only role that may change a policy). Required unless the deployment is read-only by design (see roles below). There is no unauthenticated mode and no default password. |
| `FLEET_MANAGER_VIEWER_PASSWORD_HASH` | Optional read-only `viewer` account (`FLEET_MANAGER_VIEWER_USER` renames it). |
| `FLEET_MANAGER_ANONYMOUS_VIEWER=1` | Offer visitors a one-click read-only entry from the landing page, no credentials; `FLEET_MANAGER_READ_ONLY_NOTE` is shown beside it and in the read-only banner. |
| `FLEET_MANAGER_NODE_TOKEN` | The nodes' shared `[control] token`. Required unless a client certificate is set; if the nodes require both, both must be set. |
| `FLEET_MANAGER_NODE_TLS_CA` | CA that signed the nodes' `[control] tls_cert`. Setting it switches derived node URLs to `https` and verifies each node's certificate and SAN. |
| `FLEET_MANAGER_NODE_CLIENT_CERT` / `_KEY` | This console's client certificate for nodes with `[control] tls_client_ca` (mutual TLS). Its CN must appear in the nodes' `authorized_clients` to write; in `readonly_clients` it can only read, and the console shows that node as *read-only client*. |

### Roles

Two roles, enforced on the server — the UI only reflects them:

| Role | Who | May |
|---|---|---|
| `admin` | `FLEET_MANAGER_ADMIN_PASSWORD_HASH` | Everything: read every page, toggle policies per node and fleet-wide. Every change is audited with the username and address. |
| `viewer` | `FLEET_MANAGER_VIEWER_PASSWORD_HASH`, or every visitor when `FLEET_MANAGER_ANONYMOUS_VIEWER=1` | Read every page, including the audit log and the explorers. Every write route answers `403 {"error":"read_only"}`. Toggle buttons are rendered disabled so the matrix still reads the same, with the reason in the tooltip. |

The landing page is the **administrator sign-in** (username + password).
Read-only access is never a role picker in that form; it is a separate
link beneath it, present only when the deployment has one:

- with a viewer account — *Read-only viewer access →*, which swaps the
  form for a single **viewer access code** field (the username is implied);
- with `FLEET_MANAGER_ANONYMOUS_VIEWER=1` — *Continue as read-only
  viewer →*, no credentials, one click (`POST /api/viewer`; shares the
  login rate limit). A visitor enters the read-only view knowingly rather
  than being dropped into it, and *Leave read-only view* returns to the
  landing page. `FLEET_MANAGER_READ_ONLY_NOTE` is shown next to the link
  and in the read-only banner.

A deployment with a viewer (or anonymous viewers) and **no** admin hash
is provably read-only: the process holds no credential that can produce
a write, which is the configuration to reach for when a security review
wants a fleet *view* long before it will allow fleet *control*. The
console says so in its banner, and warns at startup.

The console is equally plain about what it can do on each node. The
Nodes page's Control column and the matrix header carry one of:
`host`/`k8s`/`container` (reachable, writable), `read-only client`, `no
control (not installed)`, `control off`, `unreachable`, `unauthorized`,
`refused`, `not a control port` — each with the cause in its tooltip. An
admin on a console with neither a node token nor a client certificate
gets a warning banner up front rather than a refusal per click, and the
row's *Enable all* / *Disable all* buttons carry the number of nodes they
will actually touch (and are disabled when that is zero).

### Mutual TLS between the console and the nodes

`gen-control-certs.sh` creates a private CA, one server certificate per
node (SAN = the address this console dials) and a `fleet-manager` client
certificate (plus an optional read-only `fleet-auditor`):

```bash
./gen-control-certs.sh --out /etc/certsight-fleet-manager/pki --auditor web-01:10.0.1.7 k8s-a:10.0.1.9
```

Copy `node-<name>.crt/.key` + `ca.crt` to each node's
`/etc/cert-analyzer/control/` and set `[control] tls_cert / tls_key /
tls_client_ca / authorized_clients = fleet-manager`; point
`FLEET_MANAGER_NODE_TLS_CA` and `FLEET_MANAGER_NODE_CLIENT_CERT/_KEY` at
`ca.crt` and `fleet-manager.crt/.key` here. An organisation with its own
PKI can issue from that instead — the listener only needs standard X.509
with `serverAuth` / `clientAuth`.

### Node overrides

By default a node's control URL is `<scheme>://<Prometheus scrape host>:<control port>`.
When that's wrong (a loopback listener reached through an SSH tunnel, a
k8s pod IP scraped through a Service/Route, NAT), point
`FLEET_MANAGER_NODE_OVERRIDES` at a JSON file:

```json
{ "web-01": "http://127.0.0.1:18087", "ip-10-0-1-7.ec2.internal": "https://10.0.1.7:8087" }
```

## Security posture

This is the first CertSight component that can change what a node
detects, so it does not inherit the test console's "lab only, no auth"
stance:

- Local accounts only (`admin`, optional read-only `viewer`, or
  anonymous viewers); passwords stored only as scrypt hashes; login
  rate-limited per client address (10/min). Role checks are server-side
  on every write route.
- Opaque random session cookie, `HttpOnly; SameSite=Strict`, `Secure`
  when behind TLS (auto-detected from `X-Forwarded-Proto`, or forced with
  `FLEET_MANAGER_COOKIE_SECURE=1`). Sessions live in memory: a restart
  logs everyone out. Idle timeout 12h, absolute 24h.
- State-changing calls require the `X-Requested-With: fetch` header the
  UI sets and reject a mismatched `Origin` — a cross-site form can't
  trigger a toggle.
- Every login and every policy change is appended to
  `FLEET_MANAGER_AUDIT_LOG` (JSONL: time, user, address, node, policy,
  change, result) and mirrored to the journal at WARNING. Bulk actions
  write one line per node.
- Binds to loopback by default. For anything wider, put nginx with TLS in
  front (the AWS demo's `user-data.sh` shows the pattern used for the test
  console and MCP server). HTTP Basic at nginx is additional, not a
  substitute for the app login.
- Node side: the control listener is separate from the probe port, off by
  default, loopback by default, gated by a source allowlist, a bearer
  token and/or mutual TLS with CN-based read/write authorisation — and a
  node without the `cert-analyzer-control` package has no listener at all,
  because the code isn't there. See the `[control]` section of the main
  README.

## HTTP API

All routes except `/`, the static assets and `POST /api/login` need a
session. State-changing routes also need `X-Requested-With: fetch`.

| Route | Purpose |
|---|---|
| `GET /api/login-options` | Unauthenticated. Which entries the landing page may offer: `admin`, `viewer_account` (+ `viewer_user`), `anonymous_viewer`, `read_only_note` — shapes only, never credentials |
| `POST /api/login` `{"username","password"}` | Sets the session cookie. 401 on bad credentials, 429 when rate-limited |
| `POST /api/viewer` | Anonymous-viewer deployments only (404 otherwise): mints a read-only session without credentials. Same rate limit as login |
| `POST /api/logout` | Revokes the session |
| `GET /api/me` | Current `user`, `role`, whether the session is `anonymous`, whether an admin login exists, which node credentials this console holds (`node_auth`), and which explorer pages are available |
| `GET /api/nodes` | Inventory with health, versions, policy counts and a `control` block: `reachable`, `writable`, `role` (what the node grants this console), `error` (`unauthorized`/`forbidden`/`unreachable`/…), `configured` (the node's own `enabled`/`disabled`/`unavailable`) |
| `GET /api/policies` | The matrix: `nodes[]` (same control fields) and `policies[]` with per-node `cells` (`state`, `desired`, `drift`, `controllable`) |
| `PUT /api/nodes/<node>/policies/<name>[?namespace=]` `{"enabled": bool}` | Toggle on one node. Returns the node's observed state after the call. `403 read_only` for a viewer session |
| `POST /api/policies/<name>[?namespace=]` `{"enabled": bool}` | Toggle on every node that has the policy and will accept a write from this console. Returns per-node results with `applied`/`failed`/`skipped` counts; skipped entries say why (`unreachable`, `unauthorized`, `read_only_client`, `policy_not_present`). `403 read_only` for a viewer session |
| `GET /api/audit?limit=N` | Newest-first audit entries |
| `GET /fleet-blast-radius`, `/fleet-chain-explorer`, `/fleet-fips-rollout` | The explorer pages (session required) |

## Tests

```bash
cd extras/fleet-manager && python3 -m pytest test_fleet_manager.py
```

The tests stand up a fake Prometheus and fake node control endpoints on
loopback and drive the real server through HTTP; nothing external is
contacted.
