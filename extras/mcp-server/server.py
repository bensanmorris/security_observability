#!/usr/bin/env python3
"""
CertSight read-only MCP server -- exposes fleet certificate/FIPS/chain
queries as MCP tools by calling straight into extras/test-server's existing
Prometheus-query functions (fleet_blast_radius.py, chain_explorer.py,
fleet_fips_rollout.py) rather than re-implementing PromQL from scratch.
Those modules already reuse each other's private helpers this same way
(see fleet_fips_rollout.py's own docstring) -- this server just adds one
more caller, returning JSON instead of an HTML page.

Read-only by construction, not just by convention: every tool below only
ever calls Prometheus's /api/v1/query endpoint (there is no remote-write
path anywhere in this file), and nothing here authenticates or executes
against cert-analyzer, Kafka, or any discovered host -- it can only see
what cert-analyzer has already published to Prometheus.

Run (stdio transport, for a local Claude Desktop/Code config):
    CERTSIGHT_PROMETHEUS_URL=http://127.0.0.1:9091 python3 server.py

Run (streamable-http transport, for a network-reachable deployment):
    CERTSIGHT_MCP_TRANSPORT=streamable-http \
        CERTSIGHT_MCP_HOST=0.0.0.0 CERTSIGHT_MCP_PORT=8092 python3 server.py

No auth of any kind gates the streamable-http transport -- same
open-by-design posture as the Grafana dashboard and test console elsewhere
in this demo. Put a rate-limiting reverse proxy in front of it before
exposing it publicly (see extras/aws-demo/user-data.sh's nginx config for
the pattern this repo uses); nothing in this file throttles clients itself.

See MCP-SERVER-README.md for the Claude Desktop config snippet and setup.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "test-server"))

import blast_radius        # noqa: E402
import fleet_blast_radius  # noqa: E402
import chain_explorer      # noqa: E402
import fleet_fips_rollout  # noqa: E402

from mcp.server.mcpserver import MCPServer  # noqa: E402

PROMETHEUS_URL = os.environ.get("CERTSIGHT_PROMETHEUS_URL", "http://127.0.0.1:9090")

TRANSPORT = os.environ.get("CERTSIGHT_MCP_TRANSPORT", "stdio")
MCP_HOST = os.environ.get("CERTSIGHT_MCP_HOST", "127.0.0.1")
MCP_PORT = int(os.environ.get("CERTSIGHT_MCP_PORT", "8092"))

# The one PromQL escape-hatch tool (below) is the only unbounded-query surface
# in this file -- everything else replays fixed queries the test-console's
# fleet views already run publicly. Left off by default; only worth enabling
# on a deployment nobody but the operator can reach.
ENABLE_RAW_QUERY = os.environ.get("CERTSIGHT_ENABLE_RAW_QUERY") == "1"

mcp = MCPServer("certsight")


def _load_fleet_certs():
    """Cert inventory + process/pod/namespace attribution, keyed as in
    fleet_blast_radius._fetch_fleet_certs. Queried fresh on every call --
    this fronts a live monitoring fleet, not a snapshot worth caching."""
    certs = fleet_blast_radius._fetch_fleet_certs(PROMETHEUS_URL)
    fleet_blast_radius._fetch_fleet_process_pairings(PROMETHEUS_URL, certs)
    return certs


def _cert_public(cert):
    """The subset of a cert dict worth crossing the MCP boundary."""
    return {
        "common_name": cert["common_name"],
        "node_name": cert["node_name"],
        "serial": cert["serial"],
        "cert_path": cert["cert_path"],
        "days_left": round(cert["days_left"], 1),
        "checksum": cert["checksum"],
        "spki_hash": cert["spki_hash"],
        "leaves": cert["leaves"],
    }


@mcp.tool()
def list_fleet_certs(node: str = "", namespace: str = "") -> str:
    """List every certificate cert-analyzer has discovered fleet-wide, with
    the processes/pods/namespaces observed loading each one. Optionally
    filter by node name or namespace (substring match, case-insensitive)."""
    certs = _load_fleet_certs()
    node_l, ns_l = node.lower(), namespace.lower()
    out = []
    for cert in certs.values():
        if node_l and node_l not in cert["node_name"].lower():
            continue
        if ns_l and not any(ns_l in leaf["namespace"].lower() for leaf in cert["leaves"]):
            continue
        out.append(_cert_public(cert))
    return json.dumps(out, indent=2)


@mcp.tool()
def get_expiring_certs(max_days: float = 30) -> str:
    """List certificates expiring within max_days (default 30), soonest
    first. A negative days_left means the certificate has already expired."""
    certs = _load_fleet_certs()
    out = [_cert_public(c) for c in certs.values() if c["days_left"] <= max_days]
    out.sort(key=lambda c: c["days_left"])
    return json.dumps(out, indent=2)


@mcp.tool()
def get_blast_radius(query: str) -> str:
    """Given a certificate common name, serial, checksum, or SPKI hash
    (substring match), find every certificate sharing the same underlying
    key material fleet-wide -- grouped by SPKI hash where available, else
    raw checksum -- and return every process/pod/namespace/node exposed to
    it, i.e. what would be affected if that key were compromised."""
    certs = _load_fleet_certs()
    q = query.lower()
    matched_keys = {
        k for k, c in certs.items()
        if q in c["common_name"].lower() or q in c["serial"].lower()
        or q in c["checksum"].lower() or q in c["spki_hash"].lower()
    }
    if not matched_keys:
        return json.dumps({"error": f"No certificate matching {query!r}"}, indent=2)

    dimension = "spki_hash" if any(certs[k]["spki_hash"] for k in matched_keys) else "checksum"
    groups, _excluded = fleet_blast_radius._group_by(certs, dimension)

    results, seen_values = [], set()
    for k in matched_keys:
        value = certs[k][dimension]
        if not value or value in seen_values:
            continue
        seen_values.add(value)
        group = groups.get(value)
        if group is None:
            continue
        results.append({
            dimension: value,
            "distinct_checksums": group["distinct_checksums"],
            "members": [_cert_public(m) for m in group["members"]],
            "exposed_to": group["leaves"],
        })
    return json.dumps(results, indent=2)


@mcp.tool()
def get_fips_rollout_status(node: str = "") -> str:
    """Fleet-wide FIPS 140-2/140-3 rollout status per node: how many certs
    are FIPS-compliant vs not vs unchecked, plus 'cipher drift' -- a live
    TLS session negotiating a non-approved cipher even when its own
    certificate is FIPS-compliant. Optionally filter to one node (substring
    match, case-insensitive)."""
    certs = _load_fleet_certs()
    for cert in certs.values():
        cert["fips_compliant"] = None
        cert["negotiations"] = []
    fleet_fips_rollout._fetch_fleet_fips(PROMETHEUS_URL, certs)
    fleet_fips_rollout._fetch_fleet_negotiated(PROMETHEUS_URL, certs)
    nodes = fleet_fips_rollout._build_node_stats(certs)

    node_l = node.lower()
    out = {}
    for name, stats in nodes.items():
        if node_l and node_l not in name.lower():
            continue
        out[name] = {
            "status": fleet_fips_rollout._node_status(stats),
            "compliant": stats["compliant"],
            "non_compliant": stats["non_compliant"],
            "unknown": stats["unknown"],
            "negotiations_total": stats["negotiations_total"],
            "negotiations_drift": stats["negotiations_drift"],
        }
    return json.dumps(out, indent=2)


@mcp.tool()
def explain_chain(query: str) -> str:
    """Explain the certificate chain for a given cert_path or common-name
    (substring match): chain length, each cert's role (root / intermediate
    ca / leaf), and any gap where an issuer cert is missing fleet-wide or
    only resolvable from a different file elsewhere on the fleet."""
    bundles = chain_explorer._fetch_bundles(PROMETHEUS_URL)
    q = query.lower()
    matched_paths = [
        path for path, by_index in bundles.items()
        if q in path.lower() or any(q in e["common_name"].lower() for e in by_index.values())
    ]
    if not matched_paths:
        return json.dumps({"error": f"No certificate bundle matching {query!r}"}, indent=2)

    subject_index = {}
    for path, by_index in bundles.items():
        for entry in by_index.values():
            if entry["subject"]:
                subject_index.setdefault(entry["subject"], set()).add(path)

    out = []
    for path in matched_paths:
        by_index = bundles[path]
        gaps = chain_explorer._find_chain_gaps(path, by_index, subject_index)
        missing = [{"index": idx, "common_name": entry["common_name"], "missing_issuer": issuer}
                   for idx, entry, issuer, other in gaps if other is None]
        resolved = [{"index": idx, "common_name": entry["common_name"], "issuer": issuer, "found_in": other}
                    for idx, entry, issuer, other in gaps if other is not None]
        out.append({
            "path": path,
            "chain": [
                {"index": idx, "common_name": e["common_name"], "role": chain_explorer._role(e)}
                for idx, e in sorted(by_index.items())
            ],
            "missing_issuers": missing,
            "resolved_cross_file": resolved,
        })
    return json.dumps(out, indent=2)


if ENABLE_RAW_QUERY:
    @mcp.tool()
    def query_prometheus(promql: str) -> str:
        """Escape hatch: run an arbitrary PromQL instant query against
        cert-analyzer's Prometheus and return the raw result. Prometheus's
        query API is inherently read-only -- there is no write path to reach
        through it."""
        result = blast_radius._prom_query(PROMETHEUS_URL, promql)
        return json.dumps(result, indent=2)


if __name__ == "__main__":
    if TRANSPORT == "stdio":
        mcp.run()
    elif TRANSPORT == "streamable-http":
        mcp.run(transport="streamable-http", host=MCP_HOST, port=MCP_PORT)
    else:
        raise ValueError(f"Unknown CERTSIGHT_MCP_TRANSPORT: {TRANSPORT!r}")
