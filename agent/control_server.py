"""
The fleet-control listener: a small HTTP(S) server, separate from the
health/probe port, that lets certsight-fleet-manager read and change this
node's Tetragon tracing-policy state.

Why a separate listener rather than routes on the health port: the health
port has to be reachable by kubelet (and so binds every interface) and has
to stay unauthenticated. Control should be the opposite -- off by default,
bound to loopback by default, and gated. Keeping it on its own socket
means an operator can reason about it as one thing: "port 8087, loopback,
mTLS, these two client CNs", and a package built --without control has no
listener at all (see agent/control.py's module docstring and
cert-analyzer.spec's %bcond).

Gates, in the order a request meets them:

  1. allowed_sources   -- client address must be inside one of the CIDRs
                          (empty = no restriction; the listen address is
                          the real default restriction).
  2. TLS               -- tls_cert/tls_key make it HTTPS; tls_client_ca
                          additionally requires a client certificate signed
                          by that CA (mutual TLS). Enforced by the socket:
                          a client without a valid cert never reaches a
                          handler.
  3. authentication    -- bearer token (constant-time compare) if `token`
                          is set. Mandatory unless mTLS is on; if both are
                          configured, both are required.
  4. authorisation     -- with mTLS, the client cert's CN decides:
                          authorized_clients may PUT, readonly_clients may
                          only GET. Without mTLS every authenticated caller
                          is an operator (there is nothing else to key on).

Every PUT -- accepted or refused -- is logged at WARNING with the caller's
address and identity, since this is the one thing in cert-analyzer that
changes what the node detects on request.
"""
import hmac
import ipaddress
import json
import logging
import os
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, List, Optional
from urllib.parse import parse_qs, urlsplit

from .constants import CERT_ANALYZER_VERSION
from .control import POLICY_NAME_RE

if TYPE_CHECKING:
    from .analyzer import CertificateAnalyzer

logger = logging.getLogger(__name__)

# Largest request body accepted. A policy toggle is ~20 bytes.
_MAX_BODY_BYTES = 4096

CAPABILITIES = ['policies']


def parse_listen(value: str, default_port: int = 8087) -> tuple:
    """'127.0.0.1:8087' / '[::1]:8087' / '0.0.0.0' -> (host, port)."""
    value = value.strip()
    if value.startswith('['):
        host, _, rest = value[1:].partition(']')
        port = rest.lstrip(':') or str(default_port)
    elif value.count(':') == 1:
        host, _, port = value.partition(':')
    else:
        host, port = value, str(default_port)
    return host or '127.0.0.1', int(port)


def parse_cidrs(value: str) -> List[ipaddress._BaseNetwork]:
    """Comma-separated CIDRs/addresses -> networks. Raises ValueError on junk."""
    out = []
    for item in value.split(','):
        item = item.strip()
        if item:
            out.append(ipaddress.ip_network(item, strict=False))
    return out


def _split_names(value: str) -> List[str]:
    return [n.strip() for n in value.split(',') if n.strip()]


class ControlSettings:
    """Validated [control] configuration. See agent/config.py for parsing."""

    def __init__(self, *, listen: str = '127.0.0.1:8087', token: str = '',
                 allowed_sources: str = '', tls_cert: str = '', tls_key: str = '',
                 tls_client_ca: str = '', authorized_clients: str = '',
                 readonly_clients: str = ''):
        self.host, self.port = parse_listen(listen)
        self.token = token.strip() or None
        self.allowed_sources = parse_cidrs(allowed_sources)
        self.tls_cert = tls_cert.strip() or None
        self.tls_key = tls_key.strip() or None
        self.tls_client_ca = tls_client_ca.strip() or None
        self.authorized_clients = _split_names(authorized_clients)
        self.readonly_clients = _split_names(readonly_clients)

    @property
    def tls(self) -> bool:
        return bool(self.tls_cert and self.tls_key)

    @property
    def mtls(self) -> bool:
        return self.tls and bool(self.tls_client_ca)

    @property
    def loopback_only(self) -> bool:
        try:
            return ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            return self.host in ('localhost',)

    def auth_modes(self) -> List[str]:
        modes = []
        if self.token:
            modes.append('token')
        if self.mtls:
            modes.append('mtls')
        return modes


class ControlServer:
    def __init__(self, analyzer: 'CertificateAnalyzer', settings: ControlSettings):
        self.analyzer = analyzer
        self.settings = settings
        self._server: Optional[ThreadingHTTPServer] = None

    # ── gates ─────────────────────────────────────────────────────────────

    def source_allowed(self, address: str) -> bool:
        if not self.settings.allowed_sources:
            return True
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        return any(ip in net for net in self.settings.allowed_sources)

    def token_ok(self, header: str) -> bool:
        token = self.settings.token
        if token is None:
            return True                      # not configured: mTLS carries auth
        scheme, _, presented = header.partition(' ')
        if scheme.lower() != 'bearer' or not presented:
            return False
        return hmac.compare_digest(presented.strip().encode(), token.encode())

    def client_role(self, peer_cn: Optional[str]) -> Optional[str]:
        """
        'operator' (may write), 'viewer' (read only) or None (refused).
        Without mTLS every caller that passed the token is an operator.
        With mTLS and no lists configured, any CA-signed client is an
        operator (warned about at startup).
        """
        s = self.settings
        if not s.mtls:
            return 'operator'
        if peer_cn is None:
            return None
        if not s.authorized_clients and not s.readonly_clients:
            return 'operator'
        if peer_cn in s.authorized_clients:
            return 'operator'
        if peer_cn in s.readonly_clients:
            return 'viewer'
        return None

    def info(self, role: str = 'operator') -> dict:
        analyzer = self.analyzer
        if os.getenv('KUBERNETES_SERVICE_HOST'):
            platform = 'k8s'
        elif getattr(analyzer, 'host_prefix', ''):
            platform = 'container'
        else:
            platform = 'host'
        return {
            'node_name': analyzer.metrics._node_name,
            'version': CERT_ANALYZER_VERSION,
            'platform': platform,
            'capabilities': CAPABILITIES,
            'auth': self.settings.auth_modes(),
            # The caller's own role, so a read-only client (readonly_clients
            # CN) learns it up front and can say so instead of offering
            # controls that every PUT would refuse.
            'role': role,
            'tetragon_connected': getattr(analyzer, '_tetragon_stub', None) is not None,
        }

    # ── handler ───────────────────────────────────────────────────────────

    def _make_handler(self):
        control = self

        class _Handler(BaseHTTPRequestHandler):
            server_version = 'cert-analyzer-control'

            def _send_json(self, status: int, body: dict) -> None:
                body_bytes = (json.dumps(body) + '\n').encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body_bytes)))
                self.end_headers()
                self.wfile.write(body_bytes)

            def _send_empty(self, status: int) -> None:
                self.send_response(status)
                self.send_header('Content-Length', '0')
                self.end_headers()

            def _peer_cn(self) -> Optional[str]:
                getpeercert = getattr(self.connection, 'getpeercert', None)
                if getpeercert is None:
                    return None
                cert = getpeercert() or {}
                for rdn in cert.get('subject', ()):
                    for key, value in rdn:
                        if key == 'commonName':
                            return value
                return None

            def _identity(self) -> str:
                cn = self._peer_cn()
                return f"{self.client_address[0]}" + (f" (CN={cn})" if cn else '')

            def _gate(self, write: bool) -> Optional[str]:
                """Source allowlist -> token -> role. Returns the caller's role, or None once a refusal was sent."""
                if not control.source_allowed(self.client_address[0]):
                    logger.warning(f"Fleet control: refused {self.client_address[0]}: not in allowed_sources")
                    self._send_empty(403)
                    return None
                if not control.token_ok(self.headers.get('Authorization', '')):
                    self._send_empty(401)
                    return None
                role = control.client_role(self._peer_cn())
                if role is None:
                    logger.warning(f"Fleet control: refused {self._identity()}: client certificate not authorised")
                    self._send_empty(403)
                    return None
                if write and role != 'operator':
                    logger.warning(f"Fleet control: refused write from {self._identity()}: read-only client")
                    self._send_empty(403)
                    return None
                return role

            def _read_body(self) -> Optional[dict]:
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                except ValueError:
                    return None
                if length < 0 or length > _MAX_BODY_BYTES:
                    return None
                raw = self.rfile.read(length) if length else b''
                try:
                    body = json.loads(raw or b'{}')
                except ValueError:
                    return None
                return body if isinstance(body, dict) else None

            def do_GET(self):
                path = urlsplit(self.path).path
                if path not in ('/control/info', '/control/policies'):
                    self._send_empty(404)
                    return
                role = self._gate(write=False)
                if role is None:
                    return
                if path == '/control/info':
                    self._send_json(200, control.info(role))
                else:
                    self._send_json(200, control.analyzer.list_policies_for_control())

            def do_PUT(self):
                parts = urlsplit(self.path)
                prefix = '/control/policies/'
                if not parts.path.startswith(prefix):
                    self._send_empty(404)
                    return
                if self._gate(write=True) is None:
                    return
                name = parts.path[len(prefix):]
                namespace = (parse_qs(parts.query).get('namespace') or [''])[0]
                body = self._read_body()
                enabled = body.get('enabled') if body else None
                if (not POLICY_NAME_RE.match(name)
                        or (namespace and not POLICY_NAME_RE.match(namespace))
                        or not isinstance(enabled, bool)):
                    self._send_json(400, {'error': 'bad_request'})
                    return
                status, result = control.analyzer.set_policy_enabled_for_control(name, namespace, enabled)
                logger.warning(
                    f"Fleet control: {self._identity()} requested policy "
                    f"{name!r}{' in ' + namespace if namespace else ''} -> "
                    f"{'enabled' if enabled else 'disabled'}: HTTP {status}"
                    + (f" ({result.get('error')})" if status != 200 else '')
                )
                self._send_json(status, result)

            def log_message(self, fmt, *args):
                logger.debug(f"Fleet control: {fmt % args}")

        return _Handler

    # ── lifecycle ─────────────────────────────────────────────────────────

    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        s = self.settings
        if not s.tls:
            return None
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(s.tls_cert, s.tls_key)
        if s.tls_client_ca:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(cafile=s.tls_client_ca)
        return ctx

    def start(self) -> None:
        s = self.settings
        try:
            ctx = self._ssl_context()
        except (OSError, ssl.SSLError) as e:
            logger.critical(f"Cannot load [control] TLS material: {e}. Fleet control stays OFF.")
            return
        try:
            self._server = ThreadingHTTPServer((s.host, s.port), self._make_handler())
        except OSError as e:
            logger.critical(
                f"Cannot bind fleet-control listener to {s.host}:{s.port}: {e}. "
                f"Change [control] listen in cert-analyzer.conf or set CONTROL_LISTEN."
            )
            sys.exit(1)
        self._server.daemon_threads = True
        if ctx is not None:
            self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)
        thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        thread.name = 'control-server'
        thread.start()
        if s.mtls and not s.authorized_clients and not s.readonly_clients:
            logger.warning(
                "[control] tls_client_ca is set but authorized_clients/readonly_clients are not: "
                "any client certificate signed by that CA is treated as an operator"
            )
        if not s.tls and not s.loopback_only:
            logger.warning(
                f"[control] listener on {s.host}:{s.port} has no TLS: the bearer token crosses "
                f"the network in clear. Set tls_cert/tls_key (and tls_client_ca) or keep listen on loopback."
            )
        logger.info(
            f"Fleet control listening on {'https' if s.tls else 'http'}://{s.host}:{s.port} "
            f"(auth: {', '.join(s.auth_modes()) or 'none'}"
            f"{', sources: ' + ','.join(str(n) for n in s.allowed_sources) if s.allowed_sources else ''})"
        )

    @property
    def port(self) -> int:
        return self._server.server_address[1] if self._server else self.settings.port

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
