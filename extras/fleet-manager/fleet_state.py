"""
fleet_state.py -- what the fleet manager knows about its nodes, and how.

Inventory comes from Prometheus: cert-analyzer already exports
node_name-labelled health, version, and tetragon_policy_info series for
every node, so discovering the fleet is a handful of instant queries
against one endpoint regardless of fleet size, and a node whose control
port is unreachable still renders (as a read-only row, with Prometheus's
last-scraped policy states) instead of taking the page down.

The nodes are contacted directly for two things: the small
/control/info + /control/policies pair -- fanned out in parallel with a
short timeout and cached briefly -- which says whether control is
reachable, what the node's *recorded* (desired) state is, and its live
policy states (fresher than Prometheus by up to a monitor interval plus
a scrape, which matters right after a toggle); and the actual PUTs that
toggle a policy.

Node addressing: Prometheus's `instance` label on cert_analyzer_build_info
is the host the metrics were scraped from, so by default the control URL
is that host on the control port. An overrides file (JSON,
{"node_name": "http://host:port", ...}) covers the cases where that's
wrong -- a k8s pod scraped through a Service/Route, NAT, a Prometheus
that scrapes through a proxy.
"""
import json
import logging
import os
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

from node_client import NodeClient, NodeTls

logger = logging.getLogger("fleet-manager")

CONTROL_CACHE_SECONDS = 15.0
FANOUT_WORKERS = 16


def prom_query(base_url: str, promql: str, timeout: float = 10.0) -> list:
    url = f"{base_url.rstrip('/')}/api/v1/query?{urllib.parse.urlencode({'query': promql})}"
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        payload = json.load(resp)
    if payload.get("status") != "success":
        raise RuntimeError(f"Prometheus query failed: {payload}")
    return payload["data"]["result"]


def _instance_host(instance: str) -> str:
    """'10.0.1.5:9090' -> '10.0.1.5'; '[::1]:9090' -> '[::1]'."""
    if instance.startswith("["):
        return instance.split("]")[0] + "]"
    return instance.rsplit(":", 1)[0] if ":" in instance else instance


def load_node_overrides(path: Optional[str]) -> Dict[str, str]:
    if not path:
        return {}
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        logger.error("could not read node overrides %s: %s -- ignoring", path, e)
        return {}
    if not isinstance(data, dict) or not all(isinstance(v, str) for v in data.values()):
        logger.error("node overrides %s must be a JSON object of node_name -> URL -- ignoring", path)
        return {}
    return data


def policy_key(name: str, namespace: str = "") -> str:
    return f"{namespace}/{name}" if namespace else name


class FleetState:
    def __init__(self, prometheus_url: str, node_token: str, control_port: int,
                 node_overrides: Optional[Dict[str, str]] = None,
                 node_timeout: float = 5.0, cache_seconds: float = CONTROL_CACHE_SECONDS,
                 clock=time.time, control_scheme: str = "http", tls: Optional[NodeTls] = None):
        self.prometheus_url = prometheus_url
        self._token = node_token
        self._control_port = control_port
        self._control_scheme = control_scheme
        self._tls = tls
        self._overrides = dict(node_overrides or {})
        self._node_timeout = node_timeout
        self._cache_seconds = cache_seconds
        self._clock = clock
        self._cache_lock = threading.Lock()
        self._control_cache: Dict[str, dict] = {}
        self._control_cache_at = 0.0

    # ── Prometheus-side inventory ─────────────────────────────────────────

    def control_url(self, node_name: str, instance: str) -> str:
        if node_name in self._overrides:
            return self._overrides[node_name].rstrip("/")
        return f"{self._control_scheme}://{_instance_host(instance)}:{self._control_port}"

    def _client(self, node: dict) -> NodeClient:
        return NodeClient(node["control_url"], self._token, timeout=self._node_timeout, tls=self._tls)

    def discover_nodes(self) -> List[dict]:
        """
        One entry per node_name seen in cert_analyzer_build_info, with the
        per-node health series folded in. A node that has stopped being
        scraped drops out once Prometheus marks its series stale (5m), which
        is the same rule Grafana's node picker follows.
        """
        now = self._clock()
        nodes: Dict[str, dict] = {}
        for r in prom_query(self.prometheus_url, "cert_analyzer_build_info"):
            m = r["metric"]
            name = m.get("node_name", "")
            if not name:
                continue
            instance = m.get("instance", "")
            nodes[name] = {
                "node_name": name,
                "instance": instance,
                "version": m.get("version", ""),
                "tetragon_version": m.get("tetragon_build_version", ""),
                "healthy": None,
                "tetragon_connected": None,
                "last_event_age_seconds": None,
                "policies_enabled": 0,
                "policies_total": 0,
                "policies_broken": 0,
                "control_url": self.control_url(name, instance),
                # From cert_analyzer_config_info{fleet_control}: 'enabled',
                # 'disabled' (config) or 'unavailable' (built --without
                # control). None for a node too old to report it.
                "control_configured": None,
            }

        def fold(promql, key, convert):
            for r in prom_query(self.prometheus_url, promql):
                node = nodes.get(r["metric"].get("node_name", ""))
                if node is not None:
                    node[key] = convert(r)

        fold("cert_analyzer_config_info", "control_configured",
             lambda r: r["metric"].get("fleet_control") or None)
        fold("cert_analyzer_healthy", "healthy", lambda r: float(r["value"][1]) == 1.0)
        fold("tetragon_connected", "tetragon_connected", lambda r: float(r["value"][1]) == 1.0)
        fold("cert_analyzer_last_event_timestamp", "last_event_age_seconds",
             lambda r: max(0, int(now - float(r["value"][1]))) if float(r["value"][1]) > 0 else None)

        for r in prom_query(self.prometheus_url, "tetragon_policies_total"):
            node = nodes.get(r["metric"].get("node_name", ""))
            if node is None:
                continue
            state = r["metric"].get("state", "")
            count = int(float(r["value"][1]))
            node["policies_total"] += count
            if state == "enabled":
                node["policies_enabled"] += count
            elif state in ("load_error", "error"):
                node["policies_broken"] += count

        return [nodes[k] for k in sorted(nodes)]

    def observed_policies(self) -> Dict[str, Dict[str, str]]:
        """{policy_key: {node_name: state}} from tetragon_policy_info."""
        out: Dict[str, Dict[str, str]] = {}
        for r in prom_query(self.prometheus_url, "tetragon_policy_info"):
            m = r["metric"]
            name = m.get("name", "")
            if not name:
                continue
            key = policy_key(name, m.get("namespace", ""))
            out.setdefault(key, {})[m.get("node_name", "")] = m.get("state", "unknown")
        return out

    # ── Node-side control fan-out (cached) ────────────────────────────────

    def _fetch_node_control(self, node: dict) -> dict:
        client = self._client(node)
        info = client.info()
        if not info.get("ok"):
            return {"reachable": False, "error": info.get("error"), "detail": info.get("detail", ""),
                    "capabilities": [], "platform": None, "role": None, "policies": {}}
        policies = client.policies()
        desired = {}
        if policies.get("ok"):
            for p in policies.get("policies", []):
                desired[policy_key(p.get("name", ""), p.get("namespace", ""))] = p
        return {
            "reachable": True,
            "error": None,
            "capabilities": info.get("capabilities", []),
            "platform": info.get("platform"),
            "version": info.get("version"),
            # What the node lets *this console* do: 'operator' or 'viewer'
            # (our client-certificate CN is in its readonly_clients). The
            # node is still "reachable" -- we can read it -- but nothing
            # here may be toggled, and the UI must say so up front.
            "role": info.get("role", "operator"),
            "policies": desired,
        }

    @staticmethod
    def _writable(control: dict) -> bool:
        return bool(control.get("reachable")) and control.get("role", "operator") == "operator"

    def node_control(self, nodes: List[dict], force: bool = False) -> Dict[str, dict]:
        """
        {node_name: control summary} for every node, in parallel, cached for
        cache_seconds so the nodes and policies pages within one screen
        refresh share a single fan-out. force=True after a write so the
        next read reflects it.
        """
        now = self._clock()
        with self._cache_lock:
            fresh = (now - self._control_cache_at) < self._cache_seconds
            if fresh and not force and set(self._control_cache) == {n["node_name"] for n in nodes}:
                return dict(self._control_cache)
        if not nodes:
            result: Dict[str, dict] = {}
        else:
            with ThreadPoolExecutor(max_workers=min(FANOUT_WORKERS, len(nodes))) as pool:
                summaries = list(pool.map(self._fetch_node_control, nodes))
            result = {n["node_name"]: s for n, s in zip(nodes, summaries)}
        with self._cache_lock:
            self._control_cache = result
            self._control_cache_at = self._clock()
        return dict(result)

    def invalidate(self) -> None:
        with self._cache_lock:
            self._control_cache_at = 0.0

    # ── Composite views ───────────────────────────────────────────────────

    def nodes_view(self) -> List[dict]:
        nodes = self.discover_nodes()
        control = self.node_control(nodes)
        out = []
        for n in nodes:
            c = control.get(n["node_name"], {})
            row = dict(n)
            row["control"] = {
                "reachable": c.get("reachable", False),
                "error": c.get("error"),
                "detail": c.get("detail", ""),
                "capabilities": c.get("capabilities", []),
                "platform": c.get("platform"),
                "role": c.get("role"),
                "writable": self._writable(c),
                "configured": n["control_configured"],
            }
            out.append(row)
        return out

    def policies_view(self) -> dict:
        """
        Rows are policies, columns are nodes. Each cell: the state, the
        node's recorded (desired) flag and drift, and whether the cell can
        be toggled from here.

        For a reachable node the state comes from its own /control/policies
        answer, which is a live ListTracingPolicies; Prometheus's
        tetragon_policy_info lags it by up to the node's policy-monitor
        interval plus a scrape interval, so right after a toggle it would
        show the old state next to a new desired flag and no drift -- a
        contradiction the operator can't act on. Prometheus is the
        fallback for nodes this host can't reach.
        """
        nodes = self.discover_nodes()
        observed = self.observed_policies()
        control = self.node_control(nodes)
        node_names = [n["node_name"] for n in nodes]

        keys = set(observed)
        for c in control.values():
            keys.update(c.get("policies", {}))
        rows = []
        for key in sorted(keys):
            namespace, _, name = key.rpartition("/")
            cells = {}
            for node_name in node_names:
                c = control.get(node_name, {})
                recorded = c.get("policies", {}).get(key)
                state = recorded.get("state") if recorded else None
                if state is None:
                    state = observed.get(key, {}).get(node_name)
                cells[node_name] = {
                    "state": state or "absent",
                    "desired": recorded.get("desired") if recorded else None,
                    "drift": bool(recorded.get("drift")) if recorded else False,
                    "stale": bool(recorded.get("stale")) if recorded else False,
                    "controllable": self._writable(c) and state not in (None, "absent"),
                }
            rows.append({"name": name, "namespace": namespace, "key": key, "cells": cells})
        return {
            "nodes": [
                {"node_name": n["node_name"],
                 "platform": control.get(n["node_name"], {}).get("platform"),
                 "reachable": control.get(n["node_name"], {}).get("reachable", False),
                 "writable": self._writable(control.get(n["node_name"], {})),
                 "role": control.get(n["node_name"], {}).get("role"),
                 "error": control.get(n["node_name"], {}).get("error"),
                 "configured": n["control_configured"]}
                for n in nodes
            ],
            "policies": rows,
        }

    # ── Writes ────────────────────────────────────────────────────────────

    def find_node(self, node_name: str) -> Optional[dict]:
        for n in self.discover_nodes():
            if n["node_name"] == node_name:
                return n
        return None

    def set_policy(self, node: dict, name: str, namespace: str, enabled: bool) -> dict:
        result = self._client(node).set_policy(name, namespace, enabled)
        self.invalidate()
        return result

    def set_policy_everywhere(self, name: str, namespace: str, enabled: bool) -> List[dict]:
        """
        Toggle one policy on every node that currently lists it and will
        accept a write from us. Returns one result per node -- including
        the ones that were skipped and why -- so a partial outcome is
        visible as such.
        """
        nodes = self.discover_nodes()
        observed = self.observed_policies().get(policy_key(name, namespace), {})
        control = self.node_control(nodes)
        targets, results = [], []
        for n in nodes:
            c = control.get(n["node_name"], {})
            if n["node_name"] not in observed and policy_key(name, namespace) not in c.get("policies", {}):
                results.append({"node_name": n["node_name"], "ok": False, "skipped": True, "error": "policy_not_present"})
            elif not c.get("reachable"):
                results.append({"node_name": n["node_name"], "ok": False, "skipped": True, "error": c.get("error") or "unreachable"})
            elif not self._writable(c):
                # Don't even ask: the node told us we're a read-only client.
                results.append({"node_name": n["node_name"], "ok": False, "skipped": True, "error": "read_only_client"})
            else:
                targets.append(n)

        def one(node):
            r = self._client(node).set_policy(name, namespace, enabled)
            r["node_name"] = node["node_name"]
            r["skipped"] = False
            return r

        if targets:
            with ThreadPoolExecutor(max_workers=min(FANOUT_WORKERS, len(targets))) as pool:
                results.extend(pool.map(one, targets))
        self.invalidate()
        results.sort(key=lambda r: r["node_name"])
        return results
