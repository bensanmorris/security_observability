#!/usr/bin/env python3
"""
certsight-fleet-manager -- the fleet control console.

One place to see every cert-analyzer node, which Tetragon tracing policies
are enabled where, and to switch a policy on or off on one node or across
the fleet -- durably, since each node records the decision and re-applies
it after a Tetragon restart (agent/control.py in the main tree). The three
fleet explorers (blast radius, chain, FIPS rollout) are served here too, so
this is the single fleet entry point.

Reads come from Prometheus; writes go to each node's authenticated
/control/* routes. See extras/FLEET-MANAGER-PLAN.md for the design and
FLEET-MANAGER-README.md for deployment.

Unlike the test console there is no unauthenticated mode: a local login
(scrypt hashes in config) gates every page and API, every state-changing
call is refused for anything but the admin role server-side and appended
to an audit log. The sign-in form is the administrators'; beside it the
landing page offers a read-only entry when the deployment has one -- a
`viewer` account (an access code, no username) or, with
FLEET_MANAGER_ANONYMOUS_VIEWER=1, a plain "continue as read-only viewer"
link. A public, provably read-only console needs no admin account at all. Bind
stays on loopback by default -- put nginx with TLS in front for anything
else.

Usage:
    FLEET_MANAGER_ADMIN_PASSWORD_HASH="$(python3 server.py --hash-password)" \\
    FLEET_MANAGER_NODE_TOKEN=... python3 server.py --prometheus-url http://127.0.0.1:9090
"""
import argparse
import getpass
import json
import logging
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit import AuditLog  # noqa: E402
from auth import (  # noqa: E402
    ANONYMOUS_USER, ROLE_ADMIN, ROLE_VIEWER, LoginLimiter, SessionStore, hash_password, verify_password,
)
from fleet_state import FleetState, load_node_overrides  # noqa: E402
from node_client import NodeTls  # noqa: E402

# The fleet explorers live in extras/test-server/ and are imported from
# there rather than copied -- the same arrangement extras/mcp-server uses.
# The RPM sets CERTSIGHT_TEST_SERVER_DIR to certsight-test-server's install
# dir; a source checkout finds the sibling directory. If neither is present
# the explorer routes answer 503 and everything else still works.
sys.path.insert(0, os.environ.get(
    "CERTSIGHT_TEST_SERVER_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "test-server"),
))
try:
    import fleet_blast_radius   # noqa: E402
    import fleet_chain_explorer  # noqa: E402
    import fleet_fips_rollout    # noqa: E402
    EXPLORERS = {
        "/fleet-blast-radius": (fleet_blast_radius, "fleet blast radius"),
        "/fleet-chain-explorer": (fleet_chain_explorer, "fleet chain explorer"),
        "/fleet-fips-rollout": (fleet_fips_rollout, "fleet FIPS rollout"),
    }
except ImportError as _explorer_import_error:  # pragma: no cover - environment-dependent
    EXPLORERS = {}
    _EXPLORER_IMPORT_ERROR = str(_explorer_import_error)
else:
    _EXPLORER_IMPORT_ERROR = ""

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("fleet-manager")

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript"),
    "/app.css": ("app.css", "text/css"),
}
SESSION_COOKIE = "fm_session"
MAX_BODY_BYTES = 4096


class Config:
    def __init__(self, *, bind, port, prometheus_url, node_token, control_port,
                 node_overrides_path, admin_user, admin_password_hash, audit_log,
                 node_timeout, cache_seconds, cookie_secure, control_scheme="http",
                 node_tls_ca="", node_client_cert="", node_client_key="", node_tls_verify_hostname=True,
                 viewer_user="viewer", viewer_password_hash="", anonymous_viewer=False, read_only_note=""):
        self.viewer_user = viewer_user
        self.viewer_password_hash = viewer_password_hash or None
        self.anonymous_viewer = anonymous_viewer
        # Free text shown in the viewer banner, e.g. why this deployment is read-only.
        self.read_only_note = read_only_note
        self.bind = bind
        self.port = port
        self.prometheus_url = prometheus_url
        self.node_token = node_token
        self.control_port = control_port
        self.control_scheme = control_scheme
        self.node_tls_ca = node_tls_ca or None
        self.node_client_cert = node_client_cert or None
        self.node_client_key = node_client_key or None
        self.node_tls_verify_hostname = node_tls_verify_hostname
        self.node_overrides_path = node_overrides_path
        self.admin_user = admin_user
        self.admin_password_hash = admin_password_hash or None
        self.audit_log = audit_log
        self.node_timeout = node_timeout
        self.cache_seconds = cache_seconds
        self.cookie_secure = cookie_secure


class App:
    """Everything the request handler needs, built once per process."""

    def __init__(self, config: Config, fleet: Optional[FleetState] = None,
                 sessions: Optional[SessionStore] = None, limiter: Optional[LoginLimiter] = None,
                 audit: Optional[AuditLog] = None):
        self.config = config
        tls = None
        if config.node_tls_ca or config.node_client_cert:
            tls = NodeTls(ca=config.node_tls_ca, client_cert=config.node_client_cert,
                          client_key=config.node_client_key, verify_hostname=config.node_tls_verify_hostname)
        self.fleet = fleet or FleetState(
            config.prometheus_url, config.node_token, config.control_port,
            node_overrides=load_node_overrides(config.node_overrides_path),
            node_timeout=config.node_timeout, cache_seconds=config.cache_seconds,
            control_scheme=config.control_scheme, tls=tls,
        )
        self.sessions = sessions or SessionStore()
        self.limiter = limiter or LoginLimiter()
        self.audit = audit or AuditLog(config.audit_log)


# Mirrors agent/control.py's POLICY_NAME_RE so a bad name is refused here
# with a 400 rather than fanned out to every node.
_POLICY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")


def _valid_policy_name(name: str) -> bool:
    return bool(_POLICY_NAME_RE.match(name))


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = "certsight-fleet-manager"

        # ── plumbing ────────────────────────────────────────────────────

        def log_message(self, fmt, *args):
            logger.info("%s - %s", self.address_string(), fmt % args)

        def _send(self, status: int, body: bytes, content_type: str, extra_headers=()):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.send_header("Referrer-Policy", "same-origin")
            for k, v in extra_headers:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload, extra_headers=()):
            self._send(status, (json.dumps(payload) + "\n").encode("utf-8"),
                       "application/json", extra_headers)

        def _read_json(self) -> Optional[dict]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return None
            if length < 0 or length > MAX_BODY_BYTES:
                return None
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw or b"{}")
            except ValueError:
                return None
            return body if isinstance(body, dict) else None

        def _cookie(self, name: str) -> Optional[str]:
            header = self.headers.get("Cookie", "")
            for part in header.split(";"):
                k, _, v = part.strip().partition("=")
                if k == name:
                    return v
            return None

        def _client_ip(self) -> str:
            # Trust X-Forwarded-For only from loopback, i.e. the nginx in
            # front of a public deployment; anything else could set it.
            if self.client_address[0] in ("127.0.0.1", "::1"):
                xff = self.headers.get("X-Forwarded-For", "")
                if xff:
                    return xff.split(",")[0].strip()
            return self.client_address[0]

        def _cookie_secure(self) -> bool:
            if app.config.cookie_secure:
                return True
            return self.headers.get("X-Forwarded-Proto", "").lower() == "https"

        def _session(self) -> Optional[dict]:
            return app.sessions.get(self._cookie(SESSION_COOKIE))

        def _require_session(self, api: bool = True) -> Optional[dict]:
            session = self._session()
            if session is None:
                if api:
                    self._json(401, {"error": "login_required"})
                else:
                    # Explorer pages: bounce to the console, which shows the login
                    self._send(302, b"", "text/plain", [("Location", "/")])
            return session

        def _require_operator(self) -> Optional[dict]:
            """Session gate for write routes: viewers are refused server-side."""
            session = self._require_session()
            if session and session.get("role") != ROLE_ADMIN:
                self._json(403, {"error": "read_only", "role": session.get("role")})
                return None
            return session

        def _same_origin(self) -> bool:
            """
            CSRF guard for state-changing calls: the SPA always sets
            X-Requested-With, which a cross-site form post cannot, and a
            browser-supplied Origin (when present) must match our Host.
            SameSite=Strict on the cookie is the primary defence; this is
            the belt to its braces.
            """
            if self.headers.get("X-Requested-With", "") != "fetch":
                return False
            origin = self.headers.get("Origin")
            if origin:
                host = self.headers.get("Host", "")
                origin_host = urlsplit(origin).netloc
                if not host or origin_host != host:
                    return False
            return True

        # ── routing ─────────────────────────────────────────────────────

        def do_GET(self):
            parts = urlsplit(self.path)
            path = parts.path
            if path in STATIC_FILES:
                self._serve_static(path)
            elif path == "/api/login-options":
                # Unauthenticated by design: the landing page is the
                # administrator sign-in, and it needs to know whether to
                # offer a read-only entry beside it and of which kind.
                # Reveals account *shapes*, never credentials.
                self._json(200, {"admin": app.config.admin_password_hash is not None,
                                 "viewer_account": app.config.viewer_password_hash is not None,
                                 "viewer_user": app.config.viewer_user if app.config.viewer_password_hash else None,
                                 "anonymous_viewer": app.config.anonymous_viewer,
                                 "read_only_note": app.config.read_only_note})
            elif path == "/api/me":
                session = self._require_session()
                if session:
                    self._json(200, {"user": session["user"],
                                     "role": session.get("role", ROLE_ADMIN),
                                     "anonymous": session["user"] == ANONYMOUS_USER,
                                     "admin_login_available": app.config.admin_password_hash is not None,
                                     "read_only_note": app.config.read_only_note,
                                     # What this console can present to nodes. Empty means
                                     # every node will refuse it, so the UI can say that
                                     # instead of letting an admin discover it per click.
                                     "node_auth": [m for m, on in (("token", bool(app.config.node_token)),
                                                                   ("mtls", bool(app.config.node_client_cert))) if on],
                                     "explorers": sorted(EXPLORERS),
                                     "prometheus_url": app.config.prometheus_url})
            elif path == "/api/nodes":
                if self._require_session():
                    self._guarded(lambda: self._json(200, {"nodes": app.fleet.nodes_view()}))
            elif path == "/api/policies":
                if self._require_session():
                    self._guarded(lambda: self._json(200, app.fleet.policies_view()))
            elif path == "/api/audit":
                if self._require_session():
                    limit = (parse_qs(parts.query).get("limit") or ["200"])[0]
                    try:
                        limit = max(1, min(int(limit), 1000))
                    except ValueError:
                        limit = 200
                    self._json(200, {"entries": app.audit.tail(limit)})
            elif path in EXPLORERS:
                if self._require_session(api=False):
                    self._serve_explorer(path)
            elif path.startswith("/fleet-") and not EXPLORERS:
                self._send(503, f"fleet explorers unavailable: {_EXPLORER_IMPORT_ERROR}".encode(),
                           "text/plain; charset=utf-8")
            else:
                self._send(404, b"not found\n", "text/plain")

        def do_POST(self):
            parts = urlsplit(self.path)
            path = parts.path
            if path == "/api/login":
                self._login()
                return
            if not self._same_origin():
                self._json(403, {"error": "cross_origin"})
                return
            if path == "/api/viewer":
                self._enter_as_viewer()
                return
            if path == "/api/logout":
                # Any session (viewer included) may end itself. Revoke rather
                # than look the session up, so an anonymous deployment doesn't
                # mint a fresh one on the way out; the UI re-bootstraps.
                app.sessions.revoke(self._cookie(SESSION_COOKIE))
                self._json(200, {"ok": True}, [("Set-Cookie", self._clear_cookie())])
                return
            session = self._require_operator()
            if not session:
                return
            if path.startswith("/api/policies/"):
                self._bulk_toggle(session, path[len("/api/policies/"):], parts.query)
            else:
                self._json(404, {"error": "not_found"})

        def do_PUT(self):
            parts = urlsplit(self.path)
            path = parts.path
            session = self._require_operator()
            if not session:
                return
            if not self._same_origin():
                self._json(403, {"error": "cross_origin"})
                return
            prefix = "/api/nodes/"
            if path.startswith(prefix) and "/policies/" in path:
                node_name, _, policy = path[len(prefix):].partition("/policies/")
                self._node_toggle(session, node_name, policy, parts.query)
            else:
                self._json(404, {"error": "not_found"})

        def _guarded(self, fn):
            """Prometheus down must be a readable 502, not a hung request."""
            try:
                fn()
            except Exception as e:
                logger.exception("request failed")
                self._json(502, {"error": "upstream_failed", "detail": str(e)})

        # ── handlers ────────────────────────────────────────────────────

        def _serve_static(self, path):
            filename, content_type = STATIC_FILES[path]
            self._send(200, (STATIC_DIR / filename).read_bytes(), content_type)

        def _serve_explorer(self, path):
            module, label = EXPLORERS[path]
            try:
                html = module.generate(app.config.prometheus_url)
            except Exception as e:
                logger.exception("%s generation failed", label)
                self._send(502, f"Failed to generate {label} view: {e}".encode("utf-8"),
                           "text/plain; charset=utf-8")
                return
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")

        def _set_cookie(self, token: str) -> str:
            attrs = [f"{SESSION_COOKIE}={token}", "Path=/", "HttpOnly", "SameSite=Strict"]
            if self._cookie_secure():
                attrs.append("Secure")
            return "; ".join(attrs)

        def _clear_cookie(self) -> str:
            return f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"

        def _login(self):
            ip = self._client_ip()
            if not app.limiter.allow(ip):
                logger.warning("login rate-limited for %s", ip)
                self._json(429, {"error": "too_many_attempts"})
                return
            body = self._read_json()
            user = (body or {}).get("username")
            password = (body or {}).get("password")
            if not isinstance(user, str) or not isinstance(password, str):
                self._json(400, {"error": "bad_request"})
                return
            role = None
            if (app.config.admin_password_hash and user == app.config.admin_user
                    and verify_password(password, app.config.admin_password_hash)):
                role = ROLE_ADMIN
            elif (app.config.viewer_password_hash and user == app.config.viewer_user
                    and verify_password(password, app.config.viewer_password_hash)):
                role = ROLE_VIEWER
            if role is None:
                logger.warning("failed login for user %r from %s", user, ip)
                self._json(401, {"error": "invalid_credentials"})
                return
            app.limiter.reset(ip)
            # Replace any anonymous viewer session with the real one
            app.sessions.revoke(self._cookie(SESSION_COOKIE))
            token = app.sessions.create(user, role)
            app.audit.record(user, ip, "login", detail=role)
            self._json(200, {"user": user, "role": role}, [("Set-Cookie", self._set_cookie(token))])

        def _enter_as_viewer(self):
            """
            Anonymous deployments only: the landing page's "read-only
            viewer" link. An explicit step rather than minting a session on
            first contact, so the sign-in form stays the administrators'
            and a visitor knowingly enters the read-only view. Not
            audited -- it's not a login. Shares the login limiter so a bot
            can't fill memory with sessions.
            """
            if not app.config.anonymous_viewer:
                self._json(404, {"error": "not_found"})
                return
            ip = self._client_ip()
            if not app.limiter.allow(ip):
                self._json(429, {"error": "too_many_attempts"})
                return
            app.sessions.revoke(self._cookie(SESSION_COOKIE))
            token = app.sessions.create(ANONYMOUS_USER, ROLE_VIEWER)
            self._json(200, {"user": ANONYMOUS_USER, "role": ROLE_VIEWER}, [("Set-Cookie", self._set_cookie(token))])

        def _parse_toggle(self, policy: str, query: str):
            """Shared validation for both toggle routes; returns (name, ns, enabled) or None."""
            namespace = (parse_qs(query).get("namespace") or [""])[0]
            body = self._read_json()
            enabled = (body or {}).get("enabled")
            if (not _valid_policy_name(policy)
                    or (namespace and not _valid_policy_name(namespace))
                    or not isinstance(enabled, bool)):
                self._json(400, {"error": "bad_request"})
                return None
            return policy, namespace, enabled

        def _node_toggle(self, session, node_name, policy, query):
            parsed = self._parse_toggle(policy, query)
            if not parsed:
                return
            name, namespace, enabled = parsed
            try:
                node = app.fleet.find_node(node_name)
            except Exception as e:
                self._json(502, {"error": "upstream_failed", "detail": str(e)})
                return
            if node is None:
                self._json(404, {"error": "unknown_node"})
                return
            result = app.fleet.set_policy(node, name, namespace, enabled)
            app.audit.record(
                session["user"], self._client_ip(), "set_policy", node=node_name,
                policy=name, namespace=namespace, enabled=enabled,
                ok=bool(result.get("ok")),
                detail=result.get("error", "") if not result.get("ok") else result.get("state", ""),
            )
            status = 200 if result.get("ok") else 502
            self._json(status, {"node_name": node_name, **result})

        def _bulk_toggle(self, session, policy, query):
            parsed = self._parse_toggle(policy, query)
            if not parsed:
                return
            name, namespace, enabled = parsed
            try:
                results = app.fleet.set_policy_everywhere(name, namespace, enabled)
            except Exception as e:
                self._json(502, {"error": "upstream_failed", "detail": str(e)})
                return
            for r in results:
                if r.get("skipped"):
                    continue
                app.audit.record(
                    session["user"], self._client_ip(), "set_policy", node=r["node_name"],
                    policy=name, namespace=namespace, enabled=enabled,
                    ok=bool(r.get("ok")),
                    detail=r.get("error", "") if not r.get("ok") else r.get("state", ""),
                )
            applied = sum(1 for r in results if r.get("ok"))
            failed = sum(1 for r in results if not r.get("ok") and not r.get("skipped"))
            skipped = sum(1 for r in results if r.get("skipped"))
            self._json(200, {"policy": name, "namespace": namespace, "enabled": enabled,
                             "applied": applied, "failed": failed, "skipped": skipped,
                             "results": results})

    return Handler


def _env(name: str, default: str = "") -> str:
    return os.environ.get(f"FLEET_MANAGER_{name}", default)


def parse_args(argv=None) -> argparse.Namespace:
    # Every flag falls back to a FLEET_MANAGER_* environment variable so the
    # systemd unit configures this via EnvironmentFile= (same convention as
    # the test-server and MCP server). Secrets are env/file only.
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--hash-password", action="store_true",
                   help="print a password's FLEET_MANAGER_ADMIN_PASSWORD_HASH value and exit -- prompts on a "
                        "terminal, otherwise reads one line from stdin (for provisioning scripts)")
    p.add_argument("--bind", default=_env("BIND", "127.0.0.1"),
                   help="listen address (default 127.0.0.1; put nginx+TLS in front for anything wider)")
    p.add_argument("--port", type=int, default=int(_env("PORT", "8094")))
    p.add_argument("--prometheus-url", default=_env("PROMETHEUS_URL", "http://127.0.0.1:9090"),
                   help="Prometheus base URL (IPv4 literal on purpose -- see test-server.conf)")
    p.add_argument("--control-port", type=int, default=int(_env("CONTROL_PORT", "8087")),
                   help="cert-analyzer [control] listen port on every node, unless overridden per node")
    p.add_argument("--control-scheme", choices=("http", "https"),
                   default=_env("CONTROL_SCHEME", "") or None,
                   help="scheme for derived node control URLs (default: https when a node CA or client cert is configured, else http)")
    p.add_argument("--node-tls-ca", default=_env("NODE_TLS_CA", ""),
                   help="CA bundle that signed the nodes' [control] tls_cert (enables https)")
    p.add_argument("--node-client-cert", default=_env("NODE_CLIENT_CERT", ""),
                   help="this fleet manager's client certificate for nodes with [control] tls_client_ca (mutual TLS)")
    p.add_argument("--node-client-key", default=_env("NODE_CLIENT_KEY", ""))
    p.add_argument("--node-tls-no-verify-hostname", action="store_true",
                   default=_env("NODE_TLS_VERIFY_HOSTNAME", "1") == "0",
                   help="skip SAN/hostname verification of node certificates (CA verification still applies)")
    p.add_argument("--node-overrides", default=_env("NODE_OVERRIDES", ""),
                   help="JSON file of node_name -> control URL for nodes whose scrape address isn't their control address")
    p.add_argument("--admin-user", default=_env("ADMIN_USER", "admin"))
    p.add_argument("--viewer-user", default=_env("VIEWER_USER", "viewer"),
                   help="username of the optional read-only account (FLEET_MANAGER_VIEWER_PASSWORD_HASH)")
    p.add_argument("--anonymous-viewer", action="store_true", default=_env("ANONYMOUS_VIEWER", "") == "1",
                   help="offer every visitor a read-only viewer session from the landing page, no credentials "
                        "(the admin account then becomes optional)")
    p.add_argument("--read-only-note", default=_env("READ_ONLY_NOTE", ""),
                   help="text shown to viewers explaining why this deployment is read-only")
    p.add_argument("--audit-log", default=_env("AUDIT_LOG", ""),
                   help="append-only JSONL audit file (default: journal only)")
    p.add_argument("--node-timeout", type=float, default=float(_env("NODE_TIMEOUT", "5")))
    p.add_argument("--cache-seconds", type=float, default=float(_env("CACHE_SECONDS", "15")))
    p.add_argument("--cookie-secure", action="store_true", default=_env("COOKIE_SECURE", "") == "1",
                   help="always mark the session cookie Secure (auto when X-Forwarded-Proto: https)")
    return p.parse_args(argv)


def build_config(args) -> Config:
    token = _env("NODE_TOKEN").strip()
    password_hash = _env("ADMIN_PASSWORD_HASH").strip()
    viewer_hash = _env("VIEWER_PASSWORD_HASH").strip()
    if not password_hash and not viewer_hash and not args.anonymous_viewer:
        raise SystemExit(
            "FLEET_MANAGER_ADMIN_PASSWORD_HASH is not set -- there is no unauthenticated mode "
            "(FLEET_MANAGER_ANONYMOUS_VIEWER=1 gives visitors a read-only session instead). "
            "Generate one with: python3 server.py --hash-password"
        )
    for label, h in (("ADMIN", password_hash), ("VIEWER", viewer_hash)):
        if h and (not h.startswith("scrypt$") or h.count("$") != 2):
            raise SystemExit(f"FLEET_MANAGER_{label}_PASSWORD_HASH is not in scrypt$salt$hash form")
    if not password_hash:
        logger.warning("no admin account configured (FLEET_MANAGER_ADMIN_PASSWORD_HASH unset): "
                       "this console is read-only -- no session can change a policy")
    if bool(args.node_client_cert) != bool(args.node_client_key):
        raise SystemExit("FLEET_MANAGER_NODE_CLIENT_CERT and FLEET_MANAGER_NODE_CLIENT_KEY must be set together")
    for label, path in (("NODE_TLS_CA", args.node_tls_ca), ("NODE_CLIENT_CERT", args.node_client_cert),
                        ("NODE_CLIENT_KEY", args.node_client_key)):
        if path and not os.path.isfile(path):
            raise SystemExit(f"FLEET_MANAGER_{label}={path}: file not found")
    tls_configured = bool(args.node_tls_ca or args.node_client_cert)
    scheme = args.control_scheme or ("https" if tls_configured else "http")
    if not token and not args.node_client_cert:
        logger.warning("neither FLEET_MANAGER_NODE_TOKEN nor a client certificate is set -- every node will "
                       "show as unauthorized; the console is read-only until one matches the nodes' [control] config")
    if scheme == "http" and token:
        logger.warning("node control over plain http: the node token crosses the network in clear unless "
                       "every node's [control] listener is on loopback (SSH tunnel) -- set FLEET_MANAGER_NODE_TLS_CA")
    return Config(
        bind=args.bind, port=args.port, prometheus_url=args.prometheus_url,
        node_token=token, control_port=args.control_port,
        node_overrides_path=args.node_overrides or None,
        admin_user=args.admin_user, admin_password_hash=password_hash,
        audit_log=args.audit_log or None, node_timeout=args.node_timeout,
        cache_seconds=args.cache_seconds, cookie_secure=args.cookie_secure,
        control_scheme=scheme, node_tls_ca=args.node_tls_ca, node_client_cert=args.node_client_cert,
        node_client_key=args.node_client_key, node_tls_verify_hostname=not args.node_tls_no_verify_hostname,
        viewer_user=args.viewer_user, viewer_password_hash=viewer_hash,
        anonymous_viewer=args.anonymous_viewer, read_only_note=args.read_only_note,
    )


def read_password_for_hashing(stdin=None) -> str:
    """
    Interactive: prompt twice via getpass. Piped (a provisioning script,
    e.g. the AWS demo's user-data.sh): one line from stdin, so the
    password never appears on a command line or in a process listing.
    """
    stdin = stdin or sys.stdin
    if stdin.isatty():
        pw = getpass.getpass("Password: ")
        if pw != getpass.getpass("Again: "):
            raise SystemExit("passwords do not match")
    else:
        pw = stdin.readline().rstrip("\r\n")
    if not pw:
        raise SystemExit("password must not be empty")
    return pw


def main(argv=None) -> None:
    args = parse_args(argv)
    if args.hash_password:
        print(hash_password(read_password_for_hashing()))
        return
    config = build_config(args)
    app = App(config)
    server = ThreadingHTTPServer((config.bind, config.port), make_handler(app))
    server.daemon_threads = True
    logger.info("serving on http://%s:%d (Prometheus: %s, node control %s://<node>:%d%s, explorers: %s, audit: %s, "
                "accounts: %s%s)",
                config.bind, config.port, config.prometheus_url, config.control_scheme, config.control_port,
                " with client cert" if config.node_client_cert else "",
                "available" if EXPLORERS else "unavailable", config.audit_log or "journal only",
                ", ".join(n for n, h in ((config.admin_user + " (admin)", config.admin_password_hash),
                                         (config.viewer_user + " (viewer)", config.viewer_password_hash)) if h) or "none",
                "; anonymous viewer" if config.anonymous_viewer else "")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
