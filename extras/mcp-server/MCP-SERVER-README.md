# CertSight MCP server (read-only)

Exposes fleet certificate, FIPS-rollout, and chain-of-trust queries as MCP
tools, so any MCP-capable assistant (Claude Desktop, Claude Code, etc.) can
answer questions like "which nodes haven't finished the FIPS migration?" or
"what's the blast radius if this key is compromised?" directly against a
running CertSight fleet.

It is a thin wrapper: every tool calls straight into the query functions
already used by the [detection test console](../test-server/TEST-SERVER-README.md)'s
fleet views (`fleet_blast_radius.py`, `chain_explorer.py`,
`fleet_fips_rollout.py`) and returns JSON instead of an HTML page. No new
PromQL, no new inventory to keep in sync.

## Read-only, by construction

Every tool here only ever calls Prometheus's `/api/v1/query` endpoint.
There is no remote-write call anywhere in `server.py`, no Kafka producer,
and no code path back into cert-analyzer or any discovered host — so this
server cannot mutate fleet state even in principle, not merely by policy.
The one open-ended tool, `query_prometheus`, is still just PromQL against a
read-only query API.

## Setup

Two ways to get this running, depending on whether the target host has
pip/internet access.

### Option A: virtualenv (target host has pip/internet access)

Requires Python 3.10+ (the `mcp` SDK's minimum):

```bash
cd extras/mcp-server
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Only `mcp` itself needs installing here -- `server.py` imports its query
functions (`blast_radius.py`, `fleet_blast_radius.py`, `chain_explorer.py`,
`fleet_fips_rollout.py`) straight from the sibling
[`extras/test-server/`](../test-server/TEST-SERVER-README.md) directory, so
this only works run from inside a full repo checkout, not copied out on its
own.

### Option B: RPM (target host has no pip/internet access)

CI builds this RPM already, for both el8 and el9, with the `mcp` SDK bundled
into a relocatable virtualenv at `/opt/certsight-mcp/venv` -- no need to
build it yourself. Grab `certsight-mcp-*.el8*.rpm` / `*.el9*.rpm` from a
tagged [Release](../../releases) page, or -- for an untagged branch/PR --
from the `build-mcp-server-rpm` job's artifacts on its
[Actions run](../../actions/workflows/build.yml) (also triggerable on-demand
via `workflow_dispatch`). Copy it to the target host and install it there
with zero pip/internet access required:

```bash
sudo dnf install ./certsight-mcp-<version>-<release>.el9.*.rpm
```

This also pulls in `certsight-test-server` (a declared `Requires` -- see the
Option A note above on why) if it isn't already installed. Unlike a source
checkout, the RPM install has no sibling directory relationship between the
two packages, so `certsight-mcp.service` sets
`CERTSIGHT_TEST_SERVER_DIR=/opt/certsight-test-server` explicitly; running
the bare `certsight-mcp` binary outside systemd needs the same variable set
by hand.

Only build it locally (`./build-rpm.sh --version 0.1.0 --release 1`) if you
need a change that hasn't been through CI yet. Run that on any machine with
normal pip/PyPI access (it doesn't need to be the target host), and it
produces the same RPM under
`~/rpmbuild/RPMS/$(uname -m)/certsight-mcp-<version>-<release>.*.rpm`,
following the same pattern as `certsight-test-server.spec` (see there for
why the debuginfo/build-id suppression macros at the top of the spec are
needed).

This installs a `certsight-mcp` wrapper onto `$PATH` that runs `server.py`
with the bundled venv's interpreter, plus a `certsight-mcp.service` systemd
unit and a dedicated `certsight-mcp` system user -- see "Running over the
network" below.

### Prometheus URL

Point it at your Prometheus (defaults to `http://127.0.0.1:9090` if unset —
note the dev-box convention elsewhere in this repo puts Prometheus on
`9091`, since `9090` is cert-analyzer's own `/metrics` port):

```bash
export CERTSIGHT_PROMETHEUS_URL=http://127.0.0.1:9091
```

## Claude Desktop / Claude Code config

Add to `claude_desktop_config.json` (Desktop) or your MCP config (Code):

```json
{
  "mcpServers": {
    "certsight": {
      "command": "/absolute/path/to/extras/mcp-server/.venv/bin/python3",
      "args": ["/absolute/path/to/extras/mcp-server/server.py"],
      "env": {
        "CERTSIGHT_PROMETHEUS_URL": "http://127.0.0.1:9091"
      }
    }
  }
}
```

Restart Claude Desktop (or reload the MCP config in Code) and the tools
below become available.

## Running over the network (streamable-http)

By default the server speaks stdio, for a locally-launched MCP client. To
run it as a standalone service reachable over the network instead:

```bash
export CERTSIGHT_MCP_TRANSPORT=streamable-http
export CERTSIGHT_MCP_HOST=0.0.0.0   # or 127.0.0.1 to keep it local-only
export CERTSIGHT_MCP_PORT=8092  # 8091 is already the test-console's internal port
python3 server.py
```

RPM install (Option B above) instead configures `/etc/certsight-mcp/mcp.conf`
and lets systemd manage it:

```bash
sudo $EDITOR /etc/certsight-mcp/mcp.conf   # uncomment/set the CERTSIGHT_MCP_* vars above
sudo systemctl enable --now certsight-mcp
```

**No auth of any kind** — same open-by-design posture as the Grafana
dashboard and test console elsewhere in this demo. Anyone who can reach the
port can query it. `server.py` itself does no rate limiting either, so
don't expose `CERTSIGHT_MCP_HOST=0.0.0.0` directly on a shared or public
box without a rate-limiting reverse proxy in front of it — see
`extras/aws-demo/user-data.sh`'s nginx config for the pattern this repo
uses on the live AWS demo (per-IP request-rate and connection limits, the
server itself only ever bound to `127.0.0.1`).

`server.py` itself has no HTTPS support, deliberately — TLS is terminated
at the reverse proxy instead, same division of labor as rate limiting
above. On the AWS demo, `extras/aws-demo/enable-mcp-https.sh` gets a real
Let's Encrypt certificate and adds a `listen 8092 ssl` block to nginx's
config; note it's a separate script from `user-data.sh` rather than part
of first-boot provisioning, since it needs DNS already pointed at the
instance before Let's Encrypt's HTTP-01 challenge can succeed. Once run,
point clients at `https://` instead of `http://`.

Point an MCP client at it with:

```bash
claude mcp add --transport http certsight http://<host>:8092/mcp
```

`query_prometheus` (raw PromQL) is left out of the tool list entirely
unless `CERTSIGHT_ENABLE_RAW_QUERY=1` is also set — it's the one unbounded
query surface in this file, worth enabling only where the operator, not the
public, controls who can reach the endpoint.

## Tools

| Tool | Answers |
|---|---|
| `list_fleet_certs(node?, namespace?)` | Every discovered cert + what's using it, optionally filtered |
| `get_expiring_certs(max_days=30)` | What's expiring soon, soonest first |
| `get_blast_radius(query)` | "What's exposed if this cert/key is compromised?" — groups by shared SPKI/checksum across the fleet |
| `get_fips_rollout_status(node?)` | Per-node FIPS compliance + "cipher drift" (live non-approved cipher despite a compliant cert) |
| `get_negotiated_sessions(node?, drift_only=false)` | Per-session negotiated protocol/cipher + the process/pod that negotiated it; `drift_only=true` for just the non-approved ones |
| `explain_chain(query)` | Chain length, role of each cert, and any missing/cross-file-resolved issuer |
| `query_prometheus(promql)` | Raw PromQL escape hatch |

## Debugging

Run the server directly with the [MCP inspector](https://github.com/modelcontextprotocol/inspector)
before wiring it into Claude Desktop:

```bash
npx @modelcontextprotocol/inspector python3 server.py
```

A `RuntimeError` mentioning "is cert-analyzer running and scraped?" from
any tool means `CERTSIGHT_PROMETHEUS_URL` is wrong or unreachable, not a
bug in the tool itself — the same check `fleet_blast_radius.generate()`
does for the test console.
