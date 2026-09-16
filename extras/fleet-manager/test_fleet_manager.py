"""
Tests for certsight-fleet-manager.

Stands up a fake Prometheus and fake cert-analyzer control endpoints on
loopback, then drives the real server over HTTP. Nothing external is
contacted. Run from extras/fleet-manager/: python3 -m pytest test_fleet_manager.py
"""
import http.client
import json
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import auth  # noqa: E402
import fleet_state  # noqa: E402
import server as fm  # noqa: E402
from audit import AuditLog  # noqa: E402
from node_client import NodeClient  # noqa: E402

NODE_TOKEN = "node-token-0123456789abcdef"
PASSWORD = "correct horse battery staple"


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ── fakes ────────────────────────────────────────────────────────────────────

class FakePrometheus:
    """Answers /api/v1/query from a dict of metric name -> list of samples."""

    def __init__(self):
        self.series = {}          # metric -> [{"metric": {...}, "value": v}]
        self.down = False
        self.port = _free_port()
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if fake.down:
                    self.send_response(503)
                    self.end_headers()
                    return
                parts = urlsplit(self.path)
                q = (parse_qs(parts.query).get("query") or [""])[0]
                results = [
                    {"metric": dict(s["metric"], __name__=q), "value": [time.time(), str(s["value"])]}
                    for s in fake.series.get(q, [])
                ]
                body = json.dumps({"status": "success", "data": {"resultType": "vector", "result": results}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._srv = ThreadingHTTPServer(("127.0.0.1", self.port), H)
        self._srv.daemon_threads = True
        threading.Thread(target=self._srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def add_node(self, node_name, port, version="1.0.0", healthy=1, connected=1, last_event=None, control="enabled"):
        """control: the node's cert_analyzer_config_info{fleet_control} -- 'enabled' |
        'disabled' | 'unavailable' (cert-analyzer-control not installed) | None (too old to report it)."""
        inst = f"127.0.0.1:{port}"
        self.series.setdefault("cert_analyzer_build_info", []).append(
            {"metric": {"node_name": node_name, "instance": inst, "job": "cert-analyzer",
                        "version": version, "tetragon_build_version": "v1.7.0"}, "value": 1})
        cfg = {"node_name": node_name, "checksum_enabled": "true"}
        if control is not None:
            cfg["fleet_control"] = control
        self.series.setdefault("cert_analyzer_config_info", []).append({"metric": cfg, "value": 1})
        self.series.setdefault("cert_analyzer_healthy", []).append({"metric": {"node_name": node_name}, "value": healthy})
        self.series.setdefault("tetragon_connected", []).append({"metric": {"node_name": node_name}, "value": connected})
        self.series.setdefault("cert_analyzer_last_event_timestamp", []).append(
            {"metric": {"node_name": node_name}, "value": last_event if last_event is not None else time.time() - 30})

    def set_policies(self, node_name, states):
        """states: {policy_name: state_str}; rewrites this node's policy series."""
        info = [s for s in self.series.get("tetragon_policy_info", []) if s["metric"]["node_name"] != node_name]
        totals = [s for s in self.series.get("tetragon_policies_total", []) if s["metric"]["node_name"] != node_name]
        counts = {}
        for name, state in states.items():
            info.append({"metric": {"name": name, "namespace": "", "state": state, "node_name": node_name}, "value": 1})
            counts[state] = counts.get(state, 0) + 1
        for state in ("enabled", "disabled", "load_error", "error", "loading", "unloading", "unknown"):
            totals.append({"metric": {"state": state, "node_name": node_name}, "value": counts.get(state, 0)})
        self.series["tetragon_policy_info"] = info
        self.series["tetragon_policies_total"] = totals

    def close(self):
        self._srv.shutdown()


class FakeNode:
    """
    A cert-analyzer [control] listener: bearer auth, in-memory policy
    states, and the same response shapes as agent/control_server.py. mode:
    'ok' | 'disabled' (no listener at all -- [control] off or control package absent,
    exactly what the real thing looks like: connection refused) |
    'forbidden' (bodiless 403 to everything: allowed_sources / unknown CN) |
    'rpc_fail' (PUT answers 502). role is what the node tells the caller it
    is: 'operator' or 'viewer' (readonly_clients -> PUT is a bodiless 403).
    """

    def __init__(self, node_name, policies, prom=None, token=NODE_TOKEN, mode="ok", platform="host",
                 role="operator"):
        self.node_name = node_name
        self.policies = dict(policies)      # name -> 'enabled'|'disabled'|'load_error'
        self.desired = {}                   # name -> bool
        self.mode = mode
        self.token = token
        self.platform = platform
        self.role = role
        self.prom = prom
        self.port = _free_port()
        self.puts = []
        node = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, status, obj):
                body = (json.dumps(obj) + "\n").encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _empty(self, status):
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _authed(self):
                # Like agent/control_server.py: no configured token means
                # the transport (mTLS) carries authentication.
                if not node.token:
                    return True
                return self.headers.get("Authorization") == f"Bearer {node.token}"

            def _listing(self):
                out = []
                for name, state in node.policies.items():
                    desired = node.desired.get(name)
                    drift = desired is not None and state in ("enabled", "disabled") and (state == "enabled") != desired
                    out.append({"name": name, "namespace": "", "state": state,
                                "desired": desired, "drift": drift, "stale": False})
                return {"policies": out}

            def do_GET(self):
                path = urlsplit(self.path).path
                if not path.startswith("/control/"):
                    self._empty(404)
                    return
                if node.mode == "forbidden":
                    self._empty(403)
                    return
                if not self._authed():
                    self._empty(401)
                    return
                if path == "/control/info":
                    self._json(200, {"node_name": node.node_name, "version": "1.0.0", "platform": node.platform,
                                     "capabilities": ["policies"], "role": node.role, "tetragon_connected": True})
                elif path == "/control/policies":
                    self._json(200, self._listing())
                else:
                    self._empty(404)

            def do_PUT(self):
                parts = urlsplit(self.path)
                if node.mode == "forbidden":
                    self._empty(403)
                    return
                if not self._authed():
                    self._empty(401)
                    return
                if node.role != "operator":
                    node.puts.append(("refused", parts.path))
                    self._empty(403)
                    return
                name = parts.path[len("/control/policies/"):]
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
                enabled = body.get("enabled")
                node.puts.append((name, enabled))
                if name not in node.policies:
                    self._json(404, {"error": "unknown_policy", "name": name, "namespace": ""})
                    return
                node.desired[name] = enabled
                if node.mode == "rpc_fail":
                    self._json(502, {"error": "tetragon_rpc_failed", "detail": "UNAVAILABLE",
                                     "name": name, "namespace": "", "desired": enabled})
                    return
                node.policies[name] = "enabled" if enabled else "disabled"
                if node.prom is not None:
                    node.prom.set_policies(node.node_name, node.policies)
                self._json(200, {"name": name, "namespace": "", "desired": enabled, "state": node.policies[name]})

        self._srv = None
        if mode != "disabled":
            self._srv = ThreadingHTTPServer(("127.0.0.1", self.port), H)
            self._srv.daemon_threads = True
            threading.Thread(target=self._srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self):
        if self._srv is not None:
            self._srv.shutdown()


class Client:
    """Minimal cookie-aware HTTP client for driving the fleet manager."""

    def __init__(self, port):
        self.port = port
        self.cookie = None

    def request(self, method, path, body=None, headers=None, fetch=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        hdrs = dict(headers or {})
        if fetch and method in ("POST", "PUT"):
            hdrs.setdefault("X-Requested-With", "fetch")
        if self.cookie:
            hdrs["Cookie"] = self.cookie
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read()
        set_cookie = resp.getheader("Set-Cookie")
        if set_cookie:
            first = set_cookie.split(";")[0]
            self.cookie = None if first.endswith("=") else first
        try:
            payload = json.loads(raw) if raw else None
        except ValueError:
            payload = raw
        conn.close()
        return resp.status, payload, resp.getheaders()

    def login(self, user="admin", password=PASSWORD):
        return self.request("POST", "/api/login", {"username": user, "password": password})


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def prom():
    p = FakePrometheus()
    yield p
    p.close()


@pytest.fixture
def fleet(prom, tmp_path):
    """
    Three nodes: alpha (controllable), beta (control disabled), gamma
    (wrong token -> unauthorized). alpha and beta share two policies;
    gamma has one extra of its own.
    """
    alpha = FakeNode("alpha", {"cert-access": "enabled", "tcp-connect": "enabled"}, prom=prom)
    beta = FakeNode("beta", {"cert-access": "enabled", "tcp-connect": "disabled"}, prom=prom, mode="disabled")
    gamma = FakeNode("gamma", {"cert-access": "enabled", "java-cert": "load_error"}, prom=prom, token="other", platform="k8s")
    for n in (alpha, beta, gamma):
        prom.add_node(n.node_name, n.port, control="disabled" if n is beta else "enabled")
        prom.set_policies(n.node_name, n.policies)

    config = fm.Config(
        bind="127.0.0.1", port=_free_port(), prometheus_url=prom.url, node_token=NODE_TOKEN,
        control_port=0, node_overrides_path=None, admin_user="admin",
        admin_password_hash=auth.hash_password(PASSWORD), audit_log=str(tmp_path / "audit.jsonl"),
        node_timeout=3.0, cache_seconds=0.0, cookie_secure=False,
    )
    # control_port=0 would be wrong for every node; the overrides map each
    # node to its fake control server, the same mechanism a k8s node uses.
    overrides = {n.node_name: f"http://127.0.0.1:{n.port}" for n in (alpha, beta, gamma)}
    state = fleet_state.FleetState(prom.url, NODE_TOKEN, 0, node_overrides=overrides,
                                   node_timeout=3.0, cache_seconds=0.0)
    app = fm.App(config, fleet=state)
    srv = ThreadingHTTPServer((config.bind, config.port), fm.make_handler(app))
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    yield {"app": app, "config": config, "prom": prom, "nodes": {"alpha": alpha, "beta": beta, "gamma": gamma},
           "client": Client(config.port), "audit_path": tmp_path / "audit.jsonl"}
    srv.shutdown()
    for n in (alpha, beta, gamma):
        n.close()


# ── auth primitives ──────────────────────────────────────────────────────────

class TestAuthPrimitives:
    def test_hash_verify_roundtrip(self):
        h = auth.hash_password("s3cret")
        assert h.startswith("scrypt$")
        assert auth.verify_password("s3cret", h)
        assert not auth.verify_password("s3cret ", h)
        assert not auth.verify_password("", h)

    def test_fresh_salt_each_time(self):
        assert auth.hash_password("x") != auth.hash_password("x")

    def test_malformed_hash_never_verifies(self):
        for bad in ("", "plain", "scrypt$abc", "md5$a$b", "scrypt$!!$!!"):
            assert not auth.verify_password("x", bad)

    def test_empty_password_refused(self):
        with pytest.raises(ValueError):
            auth.hash_password("")

    def test_session_idle_and_absolute_expiry(self):
        now = [1000.0]
        store = auth.SessionStore(idle_seconds=100, max_seconds=1000, clock=lambda: now[0])
        t = store.create("admin")
        assert store.get(t)["user"] == "admin"
        now[0] += 90
        assert store.get(t)                      # touched, still within idle
        now[0] += 101
        assert store.get(t) is None              # idle expiry
        t2 = store.create("admin")
        for _ in range(12):
            now[0] += 90
            store.get(t2)
        assert store.get(t2) is None             # absolute expiry despite activity

    def test_session_unknown_and_revoke(self):
        store = auth.SessionStore()
        assert store.get(None) is None
        assert store.get("nope") is None
        t = store.create("admin")
        store.revoke(t)
        assert store.get(t) is None

    def test_login_limiter_window(self):
        now = [0.0]
        lim = auth.LoginLimiter(max_attempts=3, window_seconds=60, clock=lambda: now[0])
        assert all(lim.allow("1.2.3.4") for _ in range(3))
        assert not lim.allow("1.2.3.4")
        assert lim.allow("5.6.7.8")             # per-address
        now[0] += 61
        assert lim.allow("1.2.3.4")
        lim.reset("1.2.3.4")
        assert all(lim.allow("1.2.3.4") for _ in range(3))


# ── login / session / CSRF over HTTP ─────────────────────────────────────────

class TestLoginFlow:
    def test_api_requires_login(self, fleet):
        c = fleet["client"]
        for path in ("/api/me", "/api/nodes", "/api/policies", "/api/audit"):
            status, body, _ = c.request("GET", path)
            assert status == 401 and body["error"] == "login_required"
        status, _, _ = c.request("PUT", "/api/nodes/alpha/policies/cert-access", {"enabled": False})
        assert status == 401
        status, _, _ = c.request("POST", "/api/policies/cert-access", {"enabled": False})
        assert status == 401

    def test_shell_and_assets_served_without_login(self, fleet):
        c = fleet["client"]
        for path in ("/", "/app.js", "/app.css"):
            status, body, _ = c.request("GET", path)
            assert status == 200 and body

    def test_wrong_credentials(self, fleet):
        c = fleet["client"]
        status, body, _ = c.login(password="wrong")
        assert status == 401 and body["error"] == "invalid_credentials"
        status, body, _ = c.login(user="root")
        assert status == 401
        assert c.cookie is None

    def test_login_sets_hardened_cookie_and_me_works(self, fleet):
        c = fleet["client"]
        status, body, headers = c.login()
        assert status == 200 and body["user"] == "admin"
        set_cookie = dict(headers)["Set-Cookie"]
        assert "HttpOnly" in set_cookie and "SameSite=Strict" in set_cookie and "Path=/" in set_cookie
        assert "Secure" not in set_cookie               # plain http, no proxy header
        status, body, _ = c.request("GET", "/api/me")
        assert status == 200 and body["user"] == "admin"
        assert "/fleet-blast-radius" in body["explorers"]

    def test_cookie_secure_behind_tls_proxy(self, fleet):
        c = fleet["client"]
        _, _, headers = c.request("POST", "/api/login", {"username": "admin", "password": PASSWORD},
                                  headers={"X-Forwarded-Proto": "https"})
        assert "Secure" in dict(headers)["Set-Cookie"]

    def test_logout_revokes(self, fleet):
        c = fleet["client"]
        c.login()
        status, _, _ = c.request("POST", "/api/logout")
        assert status == 200
        status, _, _ = c.request("GET", "/api/me")
        assert status == 401

    def test_login_rate_limited(self, fleet):
        c = fleet["client"]
        statuses = [c.login(password="wrong")[0] for _ in range(auth.LOGIN_MAX_ATTEMPTS + 1)]
        assert statuses[:-1] == [401] * auth.LOGIN_MAX_ATTEMPTS
        assert statuses[-1] == 429
        # Even the right password is refused inside the window
        assert c.login()[0] == 429

    def test_bad_login_body(self, fleet):
        c = fleet["client"]
        status, body, _ = c.request("POST", "/api/login", {"username": 1, "password": []})
        assert status == 400

    def test_csrf_header_required_for_writes(self, fleet):
        c = fleet["client"]
        c.login()
        status, body, _ = c.request("PUT", "/api/nodes/alpha/policies/cert-access", {"enabled": False}, fetch=False)
        assert status == 403 and body["error"] == "cross_origin"
        status, _, _ = c.request("POST", "/api/logout", fetch=False)
        assert status == 403
        assert fleet["nodes"]["alpha"].puts == []

    def test_csrf_mismatched_origin_refused(self, fleet):
        c = fleet["client"]
        c.login()
        status, body, _ = c.request("PUT", "/api/nodes/alpha/policies/cert-access", {"enabled": False},
                                    headers={"Origin": "http://evil.example"})
        assert status == 403
        status, _, _ = c.request("PUT", "/api/nodes/alpha/policies/cert-access", {"enabled": False},
                                 headers={"Origin": f"http://127.0.0.1:{fleet['config'].port}"})
        assert status == 200

    def test_audit_records_login(self, fleet):
        c = fleet["client"]
        c.login()
        status, body, _ = c.request("GET", "/api/audit")
        assert status == 200
        assert body["entries"][0]["action"] == "login"
        assert body["entries"][0]["user"] == "admin"

    def test_explorer_page_requires_login(self, fleet):
        c = fleet["client"]
        status, _, headers = c.request("GET", "/fleet-blast-radius")
        assert status == 302 and dict(headers)["Location"] == "/"
        c.login()
        status, _, _ = c.request("GET", "/fleet-blast-radius")
        # Fake Prometheus has no cert series, so the explorer either renders
        # an empty page or reports it can't -- either way it's not a redirect.
        assert status in (200, 502)


# ── read views ───────────────────────────────────────────────────────────────

class TestNodesView:
    def test_inventory_and_control_reachability(self, fleet):
        c = fleet["client"]
        c.login()
        status, body, _ = c.request("GET", "/api/nodes")
        assert status == 200
        by = {n["node_name"]: n for n in body["nodes"]}
        assert list(by) == ["alpha", "beta", "gamma"]
        a = by["alpha"]
        assert a["version"] == "1.0.0" and a["tetragon_version"] == "v1.7.0"
        assert a["healthy"] is True and a["tetragon_connected"] is True
        assert 0 <= a["last_event_age_seconds"] <= 60
        assert a["policies_enabled"] == 2 and a["policies_total"] == 2
        assert a["control"] == {"reachable": True, "error": None, "detail": "", "capabilities": ["policies"],
                                "platform": "host", "role": "operator", "writable": True, "configured": "enabled"}
        # beta: nothing listening, and Prometheus says why (its [control] is off)
        b = by["beta"]["control"]
        assert b["reachable"] is False and b["error"] == "unreachable" and b["configured"] == "disabled"
        assert b["writable"] is False and ("refused" in b["detail"].lower() or "connect" in b["detail"].lower())
        assert by["beta"]["policies_enabled"] == 1
        assert by["gamma"]["control"]["error"] == "unauthorized" and by["gamma"]["control"]["configured"] == "enabled"
        assert by["gamma"]["policies_broken"] == 1

    def test_prometheus_down_is_502_not_hang(self, fleet):
        c = fleet["client"]
        c.login()
        fleet["prom"].down = True
        status, body, _ = c.request("GET", "/api/nodes")
        assert status == 502 and body["error"] == "upstream_failed"
        status, body, _ = c.request("GET", "/api/policies")
        assert status == 502


class TestPoliciesView:
    def test_matrix_shape(self, fleet):
        c = fleet["client"]
        c.login()
        status, body, _ = c.request("GET", "/api/policies")
        assert status == 200
        assert [n["node_name"] for n in body["nodes"]] == ["alpha", "beta", "gamma"]
        assert body["nodes"][2]["platform"] == "k8s" or body["nodes"][2]["reachable"] is False
        rows = {p["name"]: p for p in body["policies"]}
        assert set(rows) == {"cert-access", "tcp-connect", "java-cert"}
        ca = rows["cert-access"]["cells"]
        assert ca["alpha"] == {"state": "enabled", "desired": None, "drift": False, "stale": False, "controllable": True}
        assert ca["beta"]["controllable"] is False           # control off: no listener
        assert ca["gamma"]["controllable"] is False          # unauthorized
        by_node = {n["node_name"]: n for n in body["nodes"]}
        assert by_node["alpha"]["writable"] is True and by_node["alpha"]["role"] == "operator"
        assert by_node["beta"] == {"node_name": "beta", "platform": None, "reachable": False, "writable": False,
                                   "role": None, "error": "unreachable", "configured": "disabled"}
        assert rows["java-cert"]["cells"]["alpha"]["state"] == "absent"
        assert rows["java-cert"]["cells"]["gamma"]["state"] == "load_error"
        assert rows["tcp-connect"]["cells"]["beta"]["state"] == "disabled"

    def test_reachable_node_state_beats_stale_prometheus(self, fleet):
        """
        After a toggle, Prometheus lags by a policy-monitor interval plus a
        scrape; the node's live answer must win or the cell contradicts
        its own desired flag.
        """
        alpha = fleet["nodes"]["alpha"]
        alpha.prom = None                              # fake node stops "being scraped"
        alpha.policies["cert-access"] = "disabled"
        alpha.desired["cert-access"] = False
        c = fleet["client"]
        c.login()
        _, body, _ = c.request("GET", "/api/policies")
        cell = {p["name"]: p for p in body["policies"]}["cert-access"]["cells"]["alpha"]
        assert cell["state"] == "disabled" and cell["desired"] is False and cell["drift"] is False
        # Prometheus still says enabled -- and is what an unreachable node would show
        assert fleet["prom"].series["tetragon_policy_info"][0]["metric"]["state"] == "enabled"

    def test_drift_reported_from_node(self, fleet):
        alpha = fleet["nodes"]["alpha"]
        alpha.desired["cert-access"] = False          # recorded disabled, Tetragon says enabled
        c = fleet["client"]
        c.login()
        _, body, _ = c.request("GET", "/api/policies")
        cell = {p["name"]: p for p in body["policies"]}["cert-access"]["cells"]["alpha"]
        assert cell["desired"] is False and cell["drift"] is True


# ── writes ───────────────────────────────────────────────────────────────────

class TestNodeToggle:
    def test_disable_then_enable_one_node(self, fleet):
        c = fleet["client"]
        alpha = fleet["nodes"]["alpha"]
        c.login()
        status, body, _ = c.request("PUT", "/api/nodes/alpha/policies/cert-access", {"enabled": False})
        assert status == 200
        assert body["node_name"] == "alpha" and body["state"] == "disabled" and body["desired"] is False
        assert alpha.puts == [("cert-access", False)]
        assert alpha.policies["cert-access"] == "disabled"
        # The matrix now reflects it (fake node pushed the new state to fake Prometheus)
        _, view, _ = c.request("GET", "/api/policies")
        assert {p["name"]: p for p in view["policies"]}["cert-access"]["cells"]["alpha"]["state"] == "disabled"
        status, body, _ = c.request("PUT", "/api/nodes/alpha/policies/cert-access", {"enabled": True})
        assert status == 200 and body["state"] == "enabled"

    def test_audit_line_per_toggle(self, fleet):
        c = fleet["client"]
        c.login()
        c.request("PUT", "/api/nodes/alpha/policies/tcp-connect", {"enabled": False})
        lines = [json.loads(l) for l in fleet["audit_path"].read_text().splitlines()]
        last = lines[-1]
        assert last["action"] == "set_policy" and last["node"] == "alpha"
        assert last["policy"] == "tcp-connect" and last["enabled"] is False and last["ok"] is True
        assert last["user"] == "admin" and last["address"] == "127.0.0.1"

    def test_unknown_node_404(self, fleet):
        c = fleet["client"]
        c.login()
        status, body, _ = c.request("PUT", "/api/nodes/nope/policies/cert-access", {"enabled": False})
        assert status == 404 and body["error"] == "unknown_node"

    def test_unknown_policy_on_node_is_502_with_node_error(self, fleet):
        c = fleet["client"]
        c.login()
        status, body, _ = c.request("PUT", "/api/nodes/alpha/policies/java-cert", {"enabled": False})
        assert status == 502 and body["error"] == "unknown_policy"

    @pytest.mark.parametrize("path,body", [
        ("/api/nodes/alpha/policies/cert-access", {"enabled": "false"}),
        ("/api/nodes/alpha/policies/cert-access", {}),
        ("/api/nodes/alpha/policies/-bad", {"enabled": False}),
        ("/api/nodes/alpha/policies/cert-access?namespace=bad%20ns", {"enabled": False}),
    ])
    def test_bad_request_400(self, fleet, path, body):
        c = fleet["client"]
        c.login()
        status, resp, _ = c.request("PUT", path, body)
        assert status == 400 and resp["error"] == "bad_request"
        assert fleet["nodes"]["alpha"].puts == []

    def test_control_disabled_node_502(self, fleet):
        c = fleet["client"]
        c.login()
        status, body, _ = c.request("PUT", "/api/nodes/beta/policies/cert-access", {"enabled": False})
        assert status == 502 and body["error"] == "unreachable"

    def test_unauthorized_node_502(self, fleet):
        c = fleet["client"]
        c.login()
        status, body, _ = c.request("PUT", "/api/nodes/gamma/policies/cert-access", {"enabled": False})
        assert status == 502 and body["error"] == "unauthorized"

    def test_tetragon_rpc_failure_surfaced_and_audited_as_failed(self, fleet):
        alpha = fleet["nodes"]["alpha"]
        alpha.mode = "rpc_fail"
        c = fleet["client"]
        c.login()
        status, body, _ = c.request("PUT", "/api/nodes/alpha/policies/cert-access", {"enabled": False})
        assert status == 502 and body["error"] == "tetragon_rpc_failed"
        last = json.loads(fleet["audit_path"].read_text().splitlines()[-1])
        assert last["ok"] is False and last["detail"] == "tetragon_rpc_failed"


class TestBulkToggle:
    def test_applies_to_reachable_nodes_only(self, fleet):
        c = fleet["client"]
        c.login()
        status, body, _ = c.request("POST", "/api/policies/cert-access", {"enabled": False})
        assert status == 200
        assert body["applied"] == 1 and body["failed"] == 0 and body["skipped"] == 2
        by = {r["node_name"]: r for r in body["results"]}
        assert by["alpha"]["ok"] is True and by["alpha"]["state"] == "disabled"
        assert by["beta"]["skipped"] is True and by["beta"]["error"] == "unreachable"
        assert by["gamma"]["skipped"] is True and by["gamma"]["error"] == "unauthorized"
        assert fleet["nodes"]["alpha"].policies["cert-access"] == "disabled"
        assert fleet["nodes"]["beta"].puts == [] and fleet["nodes"]["gamma"].puts == []

    def test_policy_absent_on_a_node_is_skipped(self, fleet):
        c = fleet["client"]
        c.login()
        _, body, _ = c.request("POST", "/api/policies/java-cert", {"enabled": False})
        by = {r["node_name"]: r for r in body["results"]}
        assert by["alpha"]["error"] == "policy_not_present" and by["alpha"]["skipped"] is True
        assert body["applied"] == 0

    def test_audit_one_line_per_applied_node(self, fleet):
        c = fleet["client"]
        c.login()
        c.request("POST", "/api/policies/tcp-connect", {"enabled": False})
        lines = [json.loads(l) for l in fleet["audit_path"].read_text().splitlines()]
        toggles = [l for l in lines if l["action"] == "set_policy"]
        assert [t["node"] for t in toggles] == ["alpha"]        # skipped nodes write no line

    def test_partial_failure_is_reported_not_hidden(self, fleet):
        fleet["nodes"]["alpha"].mode = "rpc_fail"
        c = fleet["client"]
        c.login()
        status, body, _ = c.request("POST", "/api/policies/cert-access", {"enabled": False})
        assert status == 200                       # the request itself worked; the results say what happened
        assert body["failed"] == 1 and body["applied"] == 0
        assert {r["node_name"]: r for r in body["results"]}["alpha"]["error"] == "tetragon_rpc_failed"


# ── audit log ────────────────────────────────────────────────────────────────

class TestAuditLog:
    def test_tail_newest_first_with_limit(self, tmp_path):
        log = AuditLog(str(tmp_path / "a.jsonl"))
        for i in range(5):
            log.record("admin", "127.0.0.1", "set_policy", node=f"n{i}", ok=True)
        entries = log.tail(3)
        assert [e["node"] for e in entries] == ["n4", "n3", "n2"]

    def test_unparseable_lines_skipped(self, tmp_path):
        p = tmp_path / "a.jsonl"
        log = AuditLog(str(p))
        log.record("admin", "x", "login")
        with open(p, "a") as f:
            f.write("garbage\n")
        log.record("admin", "x", "logout")
        assert [e["action"] for e in log.tail()] == ["logout", "login"]

    def test_journal_only_when_no_path(self):
        log = AuditLog(None)
        entry = log.record("admin", "x", "login")
        assert entry["action"] == "login"
        assert log.tail() == []


# ── node addressing / config ─────────────────────────────────────────────────

class TestNodeAddressing:
    def test_instance_host(self):
        assert fleet_state._instance_host("10.0.1.5:9090") == "10.0.1.5"
        assert fleet_state._instance_host("host.example:9090") == "host.example"
        assert fleet_state._instance_host("[::1]:9090") == "[::1]"
        assert fleet_state._instance_host("bare") == "bare"

    def test_control_url_default_and_override(self):
        st = fleet_state.FleetState("http://p", "t", 8086, node_overrides={"k8s-node": "http://10.0.0.9:30086/"})
        assert st.control_url("n1", "10.0.1.5:9090") == "http://10.0.1.5:8086"
        assert st.control_url("k8s-node", "svc.cluster:80") == "http://10.0.0.9:30086"

    def test_load_overrides_tolerates_missing_and_bad(self, tmp_path):
        assert fleet_state.load_node_overrides(None) == {}
        assert fleet_state.load_node_overrides(str(tmp_path / "missing.json")) == {}
        bad = tmp_path / "bad.json"
        bad.write_text('{"n": 1}')
        assert fleet_state.load_node_overrides(str(bad)) == {}
        good = tmp_path / "good.json"
        good.write_text('{"n": "http://h:1"}')
        assert fleet_state.load_node_overrides(str(good)) == {"n": "http://h:1"}

    def test_node_client_error_codes(self):
        # Nothing listening: unreachable, never an exception
        r = NodeClient(f"http://127.0.0.1:{_free_port()}", "t", timeout=1).info()
        assert r["ok"] is False and r["error"] == "unreachable"


class TestHashPasswordCli:
    def test_piped_stdin(self):
        import io
        pw = fm.read_password_for_hashing(io.StringIO("s3cret\n"))
        assert pw == "s3cret"
        assert auth.verify_password("s3cret", auth.hash_password(pw))

    def test_piped_empty_refused(self):
        import io
        with pytest.raises(SystemExit):
            fm.read_password_for_hashing(io.StringIO("\n"))


class TestBuildConfig:
    def test_missing_hash_refuses_to_start(self, monkeypatch):
        monkeypatch.delenv("FLEET_MANAGER_ADMIN_PASSWORD_HASH", raising=False)
        with pytest.raises(SystemExit, match="ADMIN_PASSWORD_HASH"):
            fm.build_config(fm.parse_args([]))

    def test_malformed_hash_refuses_to_start(self, monkeypatch):
        monkeypatch.setenv("FLEET_MANAGER_ADMIN_PASSWORD_HASH", "hunter2")
        with pytest.raises(SystemExit, match="scrypt"):
            fm.build_config(fm.parse_args([]))

    def test_env_and_flags(self, monkeypatch):
        monkeypatch.setenv("FLEET_MANAGER_ADMIN_PASSWORD_HASH", auth.hash_password("x"))
        monkeypatch.setenv("FLEET_MANAGER_NODE_TOKEN", "tok")
        monkeypatch.setenv("FLEET_MANAGER_PORT", "9999")
        cfg = fm.build_config(fm.parse_args(["--prometheus-url", "http://p:1"]))
        assert cfg.port == 9999 and cfg.prometheus_url == "http://p:1" and cfg.node_token == "tok"
        assert cfg.bind == "127.0.0.1" and cfg.control_port == 8087


# ── node TLS / mutual TLS ────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """A throwaway PKI from gen-control-certs.sh: CA, node cert for 127.0.0.1, two clients."""
    import shutil, subprocess
    if shutil.which("openssl") is None:
        pytest.skip("openssl CLI not available")
    out = tmp_path_factory.mktemp("pki")
    script = Path(__file__).resolve().parent / "gen-control-certs.sh"
    subprocess.run([str(script), "--out", str(out), "--auditor", "node:127.0.0.1"], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {k: str(out / v) for k, v in {
        "ca": "ca.crt", "node_cert": "node-node.crt", "node_key": "node-node.key",
        "client_cert": "fleet-manager.crt", "client_key": "fleet-manager.key",
        "auditor_cert": "fleet-auditor.crt", "auditor_key": "fleet-auditor.key",
    }.items()}


class TlsFakeNode(FakeNode):
    """FakeNode behind TLS, optionally demanding a client cert signed by `client_ca`."""

    def __init__(self, node_name, policies, pki, client_ca=True, **kw):
        import ssl as _ssl
        super().__init__(node_name, policies, **kw)
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(pki["node_cert"], pki["node_key"])
        if client_ca:
            ctx.verify_mode = _ssl.CERT_REQUIRED
            ctx.load_verify_locations(cafile=pki["ca"])
        self._srv.socket = ctx.wrap_socket(self._srv.socket, server_side=True)


class TestNodeTls:
    def test_gen_script_output_verifies(self, pki):
        import subprocess
        r = subprocess.run(["openssl", "verify", "-CAfile", pki["ca"], pki["node_cert"], pki["client_cert"]],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr

    def test_mtls_roundtrip(self, pki):
        from node_client import NodeClient, NodeTls
        node = TlsFakeNode("node", {"cert-access": "enabled"}, pki, token="")
        try:
            tls = NodeTls(ca=pki["ca"], client_cert=pki["client_cert"], client_key=pki["client_key"])
            c = NodeClient(f"https://127.0.0.1:{node.port}", "", tls=tls)
            r = c.info()
            assert r["ok"] is True and r["node_name"] == "node"
            r = c.set_policy("cert-access", "", False)
            assert r["ok"] is True and r["state"] == "disabled"
        finally:
            node.close()

    def test_missing_client_cert_is_unreachable_with_tls_detail(self, pki):
        from node_client import NodeClient, NodeTls
        node = TlsFakeNode("node", {"cert-access": "enabled"}, pki, token="")
        try:
            c = NodeClient(f"https://127.0.0.1:{node.port}", "", tls=NodeTls(ca=pki["ca"]))
            r = c.info()
            # TLS 1.3 servers report a missing client cert as a post-handshake
            # alert, which the client sees as a reset rather than an SSLError
            # -- either way it is "unreachable" to the operator, never a 401.
            assert r["ok"] is False and r["error"] == "unreachable"
        finally:
            node.close()

    def test_untrusted_ca_refused(self, pki):
        from node_client import NodeClient, NodeTls
        node = TlsFakeNode("node", {"cert-access": "enabled"}, pki, client_ca=False, token="")
        try:
            c = NodeClient(f"https://127.0.0.1:{node.port}", "", tls=NodeTls())   # system CAs only
            r = c.info()
            assert r["ok"] is False and r["error"] == "unreachable"
        finally:
            node.close()

    def test_scheme_derived_from_tls_config(self, monkeypatch, pki):
        monkeypatch.setenv("FLEET_MANAGER_ADMIN_PASSWORD_HASH", auth.hash_password("x"))
        monkeypatch.setenv("FLEET_MANAGER_NODE_TLS_CA", pki["ca"])
        cfg = fm.build_config(fm.parse_args([]))
        assert cfg.control_scheme == "https" and cfg.control_port == 8087
        monkeypatch.delenv("FLEET_MANAGER_NODE_TLS_CA")
        cfg = fm.build_config(fm.parse_args([]))
        assert cfg.control_scheme == "http"

    def test_client_cert_without_key_refused(self, monkeypatch, pki):
        monkeypatch.setenv("FLEET_MANAGER_ADMIN_PASSWORD_HASH", auth.hash_password("x"))
        monkeypatch.setenv("FLEET_MANAGER_NODE_CLIENT_CERT", pki["client_cert"])
        with pytest.raises(SystemExit, match="together"):
            fm.build_config(fm.parse_args([]))

    def test_missing_tls_file_refused(self, monkeypatch, tmp_path):
        monkeypatch.setenv("FLEET_MANAGER_ADMIN_PASSWORD_HASH", auth.hash_password("x"))
        monkeypatch.setenv("FLEET_MANAGER_NODE_TLS_CA", str(tmp_path / "nope.crt"))
        with pytest.raises(SystemExit, match="not found"):
            fm.build_config(fm.parse_args([]))

    def test_full_stack_over_mtls(self, prom, tmp_path, pki):
        """The fleet manager driving a real mTLS node end-to-end through its own API."""
        node = TlsFakeNode("alpha", {"cert-access": "enabled"}, pki, prom=prom, token="")
        prom.add_node("alpha", node.port)
        prom.set_policies("alpha", node.policies)
        tls = fleet_state.NodeTls(ca=pki["ca"], client_cert=pki["client_cert"], client_key=pki["client_key"])
        state = fleet_state.FleetState(prom.url, "", 0, node_overrides={"alpha": f"https://127.0.0.1:{node.port}"},
                                       node_timeout=3.0, cache_seconds=0.0, tls=tls)
        config = fm.Config(bind="127.0.0.1", port=_free_port(), prometheus_url=prom.url, node_token="",
                           control_port=0, node_overrides_path=None, admin_user="admin",
                           admin_password_hash=auth.hash_password(PASSWORD), audit_log=None,
                           node_timeout=3.0, cache_seconds=0.0, cookie_secure=False)
        app = fm.App(config, fleet=state)
        srv = ThreadingHTTPServer((config.bind, config.port), fm.make_handler(app))
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        try:
            c = Client(config.port)
            c.login()
            _, body, _ = c.request("GET", "/api/nodes")
            assert body["nodes"][0]["control"]["reachable"] is True
            status, body, _ = c.request("PUT", "/api/nodes/alpha/policies/cert-access", {"enabled": False})
            assert status == 200 and body["state"] == "disabled"
        finally:
            srv.shutdown()
            node.close()


# ── viewer role / anonymous mode ─────────────────────────────────────────────

def _manager(prom, nodes, tmp_path, **cfg_overrides):
    """Start a fleet manager over the given fake nodes; returns (client, app, srv)."""
    overrides = {n.node_name: f"http://127.0.0.1:{n.port}" for n in nodes}
    state = fleet_state.FleetState(prom.url, NODE_TOKEN, 0, node_overrides=overrides,
                                   node_timeout=3.0, cache_seconds=0.0)
    cfg = dict(bind="127.0.0.1", port=_free_port(), prometheus_url=prom.url, node_token=NODE_TOKEN,
               control_port=0, node_overrides_path=None, admin_user="admin",
               admin_password_hash=auth.hash_password(PASSWORD), audit_log=str(tmp_path / "audit.jsonl"),
               node_timeout=3.0, cache_seconds=0.0, cookie_secure=False)
    cfg.update(cfg_overrides)
    config = fm.Config(**cfg)
    app = fm.App(config, fleet=state)
    srv = ThreadingHTTPServer((config.bind, config.port), fm.make_handler(app))
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    return Client(config.port), app, srv


VIEWER_PASSWORD = "look but do not touch"


class TestViewerRole:
    def test_viewer_account_can_read_but_not_write(self, prom, tmp_path):
        node = FakeNode("alpha", {"cert-access": "enabled"}, prom=prom)
        prom.add_node("alpha", node.port); prom.set_policies("alpha", node.policies)
        c, app, srv = _manager(prom, [node], tmp_path, viewer_password_hash=auth.hash_password(VIEWER_PASSWORD))
        try:
            status, body, _ = c.login(user="viewer", password=VIEWER_PASSWORD)
            assert status == 200 and body["role"] == "viewer"
            status, body, _ = c.request("GET", "/api/me")
            assert body["role"] == "viewer" and body["anonymous"] is False and body["admin_login_available"] is True
            for path in ("/api/nodes", "/api/policies", "/api/audit"):
                assert c.request("GET", path)[0] == 200
            status, body, _ = c.request("PUT", "/api/nodes/alpha/policies/cert-access", {"enabled": False})
            assert status == 403 and body["error"] == "read_only"
            status, body, _ = c.request("POST", "/api/policies/cert-access", {"enabled": False})
            assert status == 403 and body["error"] == "read_only"
            assert node.puts == []                       # never reached the node
            # audit: the viewer login is recorded with its role, no set_policy lines
            entries = c.request("GET", "/api/audit")[1]["entries"]
            assert entries[0]["action"] == "login" and entries[0]["detail"] == "viewer"
            assert not any(e["action"] == "set_policy" for e in entries)
        finally:
            srv.shutdown(); node.close()

    def test_viewer_password_does_not_open_admin(self, prom, tmp_path):
        c, app, srv = _manager(prom, [], tmp_path, viewer_password_hash=auth.hash_password(VIEWER_PASSWORD))
        try:
            assert c.login(user="admin", password=VIEWER_PASSWORD)[0] == 401
            assert c.login(user="viewer", password=PASSWORD)[0] == 401
        finally:
            srv.shutdown()

    def test_login_options_describe_the_landing_page(self, prom, tmp_path):
        """Unauthenticated: the landing page learns which read-only entry to offer, nothing more."""
        cases = [
            (dict(), {"admin": True, "viewer_account": False, "viewer_user": None, "anonymous_viewer": False}),
            (dict(viewer_password_hash=auth.hash_password(VIEWER_PASSWORD), viewer_user="lookout"),
             {"admin": True, "viewer_account": True, "viewer_user": "lookout", "anonymous_viewer": False}),
            (dict(anonymous_viewer=True, admin_password_hash="", read_only_note="Demo."),
             {"admin": False, "viewer_account": False, "viewer_user": None, "anonymous_viewer": True}),
        ]
        for overrides, expected in cases:
            c, app, srv = _manager(prom, [], tmp_path, **overrides)
            try:
                status, body, _ = c.request("GET", "/api/login-options")
                assert status == 200 and {k: body[k] for k in expected} == expected
                assert body["read_only_note"] == overrides.get("read_only_note", "")
                assert not any("hash" in k for k in body)
            finally:
                srv.shutdown()

    def test_anonymous_viewer_enters_explicitly_not_on_first_contact(self, prom, tmp_path):
        node = FakeNode("alpha", {"cert-access": "enabled"}, prom=prom)
        prom.add_node("alpha", node.port); prom.set_policies("alpha", node.policies)
        c, app, srv = _manager(prom, [node], tmp_path, anonymous_viewer=True,
                               read_only_note="Demo deployment.")
        try:
            # First contact is the landing page: no session is minted for merely arriving
            status, body, headers = c.request("GET", "/api/me")
            assert status == 401 and "Set-Cookie" not in dict(headers) and c.cookie is None
            assert c.request("GET", "/api/policies")[0] == 401
            # The "continue as read-only viewer" link
            status, body, headers = c.request("POST", "/api/viewer")
            assert status == 200 and body == {"user": "anonymous", "role": "viewer"}
            assert "fm_session=" in dict(headers)["Set-Cookie"] and c.cookie
            status, body, _ = c.request("GET", "/api/me")
            assert status == 200
            assert body["user"] == "anonymous" and body["role"] == "viewer" and body["anonymous"] is True
            assert body["read_only_note"] == "Demo deployment."
            assert c.request("GET", "/api/policies")[0] == 200
            status, body, _ = c.request("PUT", "/api/nodes/alpha/policies/cert-access", {"enabled": False})
            assert status == 403 and body["error"] == "read_only"
            assert node.puts == []
            # anonymous sessions are not audited
            assert c.request("GET", "/api/audit")[1]["entries"] == []
            # explorer pages don't bounce to a login either
            status, _, _ = c.request("GET", "/fleet-fips-rollout")
            assert status in (200, 502)
            # leaving: the session is gone, the next visit is the landing page again
            c.request("POST", "/api/logout")
            assert c.request("GET", "/api/me")[0] == 401
        finally:
            srv.shutdown(); node.close()

    def test_viewer_entry_is_404_off_anonymous_mode_and_rate_limited_on(self, prom, tmp_path):
        c, app, srv = _manager(prom, [], tmp_path)
        try:
            assert c.request("POST", "/api/viewer")[0] == 404
            assert c.request("POST", "/api/viewer", fetch=False)[0] == 403     # CSRF guard applies
        finally:
            srv.shutdown()
        c, app, srv = _manager(prom, [], tmp_path, anonymous_viewer=True)
        try:
            for _ in range(auth.LOGIN_MAX_ATTEMPTS):
                assert c.request("POST", "/api/viewer")[0] == 200
            assert c.request("POST", "/api/viewer")[0] == 429
        finally:
            srv.shutdown()

    def test_anonymous_can_upgrade_to_admin_and_back(self, prom, tmp_path):
        node = FakeNode("alpha", {"cert-access": "enabled"}, prom=prom)
        prom.add_node("alpha", node.port); prom.set_policies("alpha", node.policies)
        c, app, srv = _manager(prom, [node], tmp_path, anonymous_viewer=True)
        try:
            c.request("POST", "/api/viewer")
            anon_cookie = c.cookie
            status, body, _ = c.login()
            assert status == 200 and body["role"] == "admin" and c.cookie != anon_cookie
            assert c.request("GET", "/api/me")[1]["anonymous"] is False
            status, body, _ = c.request("PUT", "/api/nodes/alpha/policies/cert-access", {"enabled": False})
            assert status == 200
            # the old anonymous session was revoked on login
            old = Client(c.port); old.cookie = anon_cookie
            assert old.request("GET", "/api/me")[0] == 401
            # logout returns to the landing page; the viewer link works again
            c.request("POST", "/api/logout")
            assert c.request("GET", "/api/me")[0] == 401
            c.request("POST", "/api/viewer")
            assert c.request("GET", "/api/me")[1]["role"] == "viewer"
        finally:
            srv.shutdown(); node.close()

    def test_anonymous_without_admin_hash_is_provably_read_only(self, prom, tmp_path):
        node = FakeNode("alpha", {"cert-access": "enabled"}, prom=prom)
        prom.add_node("alpha", node.port); prom.set_policies("alpha", node.policies)
        c, app, srv = _manager(prom, [node], tmp_path, anonymous_viewer=True, admin_password_hash="")
        try:
            c.request("POST", "/api/viewer")
            body = c.request("GET", "/api/me")[1]
            assert body["admin_login_available"] is False
            assert c.login()[0] == 401                                  # no admin account exists at all
            assert c.request("PUT", "/api/nodes/alpha/policies/cert-access", {"enabled": False})[0] == 403
            assert node.puts == []
        finally:
            srv.shutdown(); node.close()

    def test_build_config_accepts_anonymous_without_admin(self, monkeypatch):
        monkeypatch.delenv("FLEET_MANAGER_ADMIN_PASSWORD_HASH", raising=False)
        monkeypatch.setenv("FLEET_MANAGER_ANONYMOUS_VIEWER", "1")
        cfg = fm.build_config(fm.parse_args([]))
        assert cfg.anonymous_viewer is True and cfg.admin_password_hash is None
        monkeypatch.delenv("FLEET_MANAGER_ANONYMOUS_VIEWER")
        with pytest.raises(SystemExit, match="ANONYMOUS_VIEWER"):
            fm.build_config(fm.parse_args([]))
        monkeypatch.setenv("FLEET_MANAGER_VIEWER_PASSWORD_HASH", "nothash")
        with pytest.raises(SystemExit, match="VIEWER_PASSWORD_HASH"):
            fm.build_config(fm.parse_args([]))

    def test_no_control_node_is_reported_not_faulted(self, prom, tmp_path):
        """A node without cert-analyzer-control has no listener: the console shows it unreachable
        *and* says why (configured = unavailable), every cell read-only, never an error."""
        node = FakeNode("alpha", {"cert-access": "enabled"}, prom=prom, mode="disabled")
        prom.add_node("alpha", node.port, control="unavailable"); prom.set_policies("alpha", node.policies)
        c, app, srv = _manager(prom, [node], tmp_path, anonymous_viewer=True)
        try:
            c.request("POST", "/api/viewer")
            ctl = c.request("GET", "/api/nodes")[1]["nodes"][0]["control"]
            assert ctl["reachable"] is False and ctl["error"] == "unreachable" and ctl["configured"] == "unavailable"
            assert ctl["writable"] is False and ctl["role"] is None
            cell = c.request("GET", "/api/policies")[1]["policies"][0]["cells"]["alpha"]
            assert cell["state"] == "enabled" and cell["controllable"] is False
        finally:
            srv.shutdown(); node.close()


class TestNodeHonesty:
    """What the console tells the UI about each node must match what a write would meet."""

    def test_read_only_client_node_is_reachable_but_not_writable(self, prom, tmp_path):
        """Our client cert is in the node's readonly_clients: reads work, so the node is
        reachable and its live state is shown, but no cell is controllable and a bulk
        toggle skips it as read_only_client without sending the PUT."""
        ro = FakeNode("ro", {"cert-access": "enabled"}, prom=prom, role="viewer")
        rw = FakeNode("rw", {"cert-access": "enabled"}, prom=prom)
        for n in (ro, rw):
            prom.add_node(n.node_name, n.port); prom.set_policies(n.node_name, n.policies)
        c, app, srv = _manager(prom, [ro, rw], tmp_path)
        try:
            c.login()
            by = {n["node_name"]: n["control"] for n in c.request("GET", "/api/nodes")[1]["nodes"]}
            assert by["ro"]["reachable"] is True and by["ro"]["role"] == "viewer" and by["ro"]["writable"] is False
            assert by["rw"]["writable"] is True
            matrix = c.request("GET", "/api/policies")[1]
            cells = matrix["policies"][0]["cells"]
            assert cells["ro"]["state"] == "enabled" and cells["ro"]["controllable"] is False
            assert cells["rw"]["controllable"] is True
            assert {n["node_name"]: n["writable"] for n in matrix["nodes"]} == {"ro": False, "rw": True}
            status, body, _ = c.request("POST", "/api/policies/cert-access", {"enabled": False})
            assert status == 200 and body["applied"] == 1 and body["skipped"] == 1 and body["failed"] == 0
            res = {r["node_name"]: r for r in body["results"]}
            assert res["ro"] == {"node_name": "ro", "ok": False, "skipped": True, "error": "read_only_client"}
            assert ro.puts == []                          # never even asked
            # a direct single-node toggle still goes to the node, which is the authority
            status, body, _ = c.request("PUT", "/api/nodes/ro/policies/cert-access", {"enabled": False})
            assert status == 502 and body["error"] == "forbidden"
            assert ro.puts == [("refused", "/control/policies/cert-access")]
        finally:
            srv.shutdown(); ro.close(); rw.close()

    def test_403_from_node_is_forbidden_not_unreachable(self, prom, tmp_path):
        node = FakeNode("alpha", {"cert-access": "enabled"}, prom=prom, mode="forbidden")
        prom.add_node("alpha", node.port); prom.set_policies("alpha", node.policies)
        c, app, srv = _manager(prom, [node], tmp_path)
        try:
            c.login()
            ctl = c.request("GET", "/api/nodes")[1]["nodes"][0]["control"]
            assert ctl == {"reachable": False, "error": "forbidden", "detail": "", "capabilities": [],
                           "platform": None, "role": None, "writable": False, "configured": "enabled"}
        finally:
            srv.shutdown(); node.close()

    def test_old_node_without_fleet_control_field(self, prom, tmp_path):
        """A node whose config_info predates fleet_control: configured is None, not a guess."""
        node = FakeNode("alpha", {"cert-access": "enabled"}, prom=prom, mode="disabled")
        prom.add_node("alpha", node.port, control=None); prom.set_policies("alpha", node.policies)
        c, app, srv = _manager(prom, [node], tmp_path)
        try:
            c.login()
            ctl = c.request("GET", "/api/nodes")[1]["nodes"][0]["control"]
            assert ctl["error"] == "unreachable" and ctl["configured"] is None
        finally:
            srv.shutdown(); node.close()

    def test_me_reports_node_credentials(self, prom, tmp_path):
        """An admin on a console with no token and no client cert is told so up front."""
        c, app, srv = _manager(prom, [], tmp_path)
        try:
            c.login()
            assert c.request("GET", "/api/me")[1]["node_auth"] == ["token"]
        finally:
            srv.shutdown()
        c, app, srv = _manager(prom, [], tmp_path, node_token="")
        try:
            c.login()
            assert c.request("GET", "/api/me")[1]["node_auth"] == []
        finally:
            srv.shutdown()
