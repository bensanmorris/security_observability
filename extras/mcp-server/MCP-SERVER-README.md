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

```bash
cd extras/mcp-server
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

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

Restart Claude Desktop (or reload the MCP config in Code) and the six tools
below become available.

## Tools

| Tool | Answers |
|---|---|
| `list_fleet_certs(node?, namespace?)` | Every discovered cert + what's using it, optionally filtered |
| `get_expiring_certs(max_days=30)` | What's expiring soon, soonest first |
| `get_blast_radius(query)` | "What's exposed if this cert/key is compromised?" — groups by shared SPKI/checksum across the fleet |
| `get_fips_rollout_status(node?)` | Per-node FIPS compliance + "cipher drift" (live non-approved cipher despite a compliant cert) |
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
