import grpc
import hmac
import json
import logging
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Optional
from urllib.parse import parse_qs, urlsplit

from .constants import CERT_ANALYZER_VERSION
from .control import POLICY_NAME_RE

if TYPE_CHECKING:
    from .analyzer import CertificateAnalyzer

logger = logging.getLogger(__name__)

# Largest request body /control/* will read. A policy toggle is ~20 bytes;
# anything approaching this is not a fleet manager.
_MAX_CONTROL_BODY_BYTES = 4096

# grpc.Channel (grpc 1.60.1's concrete implementation, grpc._channel.Channel)
# has no public synchronous "give me the current state" method -- get_state()
# doesn't exist on it, and the only public API for connectivity is the async
# subscribe(callback)/unsubscribe() pair, which doesn't fit a synchronous HTTP
# health-check handler. The private channel._channel.check_connectivity_state()
# is the pragmatic way to poll it synchronously, but it returns a bare int (the
# underlying cygrpc state code), and grpc.ChannelConnectivity(<int>) cannot
# construct a member from that directly -- the enum's actual values are
# (int, name) tuples, e.g. ChannelConnectivity.READY.value == (2, 'ready'), so
# grpc.ChannelConnectivity(2) always raises ValueError. This lookup table maps
# the raw int back to the correct member instead.
_CONNECTIVITY_STATE_BY_INT = {member.value[0]: member for member in grpc.ChannelConnectivity}


class HealthServer:
    """
    Lightweight HTTP server exposing liveness and readiness probes for
    OpenShift / Kubernetes.

    Endpoints
    ---------
    GET /healthz  — liveness probe.
        Returns 200 if the analyzer process is alive and the gRPC channel
        is not in a terminal failure state.  Returns 503 only if the channel
        has been explicitly shut down.  Temporary Tetragon unavailability
        (e.g. during an upgrade) never causes a liveness failure — the
        reconnection loop handles that transparently.

    GET /readyz   — readiness probe.
        Returns 200 while the startup grace period has not expired.  After
        the grace period, returns 200 only if at least one event has been
        processed within the staleness window.  Returns 503 if events were
        expected but the last event timestamp is too old, indicating the
        analyzer has fallen behind or lost its event stream without recovery.

    Fleet control (only when constructed with a control_token; otherwise
    these paths are 404 exactly as before). Every request needs
    `Authorization: Bearer <token>`; a wrong or missing token is a bodiless
    401. See agent/control.py for why the desired state is persisted.

    GET /control/info                — node_name, version, platform, and
                                       which control capabilities this
                                       build offers
    GET /control/policies            — observed + desired state of every
                                       Tetragon tracing policy on this node
    PUT /control/policies/{name}     — body {"enabled": true|false};
        [?namespace=ns]                records the decision, applies it to
                                       Tetragon, returns the observed state

    Configuration (env vars)
    ------------------------
    HEALTH_PORT                    — port for this server (default: 8086)
    READINESS_GRACE_PERIOD_SECONDS — seconds after startup before readiness
                                     checking begins (default: 60)
    READINESS_STALENESS_SECONDS    — max age of last event before unready
                                     (default: 300 — 5 minutes)
    """

    def __init__(
        self,
        analyzer: 'CertificateAnalyzer',
        port: int = 8086,
        grace_period_seconds: int = 60,
        staleness_seconds: int = 300,
        control_token: Optional[str] = None,
    ):
        self.analyzer            = analyzer
        self.port                = port
        self.grace_period        = grace_period_seconds
        self.staleness_seconds   = staleness_seconds
        self.control_token       = control_token or None
        self._start_time         = time.time()
        self._channel            = None   # set by CertificateAnalyzer.start()
        self._server: Optional[ThreadingHTTPServer] = None

    def set_channel(self, channel) -> None:
        """Called by CertificateAnalyzer.start() once the gRPC channel exists."""
        self._channel = channel

    # ── Probe logic ───────────────────────────────────────────────────────────

    def is_live(self) -> tuple:
        """
        Returns (True, reason) if alive, (False, reason) if not.

        Liveness fails only if the gRPC channel has been explicitly shut down
        (SHUTDOWN state).  All other states — including IDLE and TRANSIENT_FAILURE
        — are treated as live because the reconnection loop is handling them.
        """
        if self._channel is None:
            # Channel not yet created — process is still starting up, consider live
            return True, "starting"

        try:
            # See _CONNECTIVITY_STATE_BY_INT's module-level comment: this used
            # to construct grpc.ChannelConnectivity(state) directly from the
            # raw int, which always raised ValueError and was silently
            # swallowed below -- meaning this check always fell through to
            # "unknown"/True and never actually detected a SHUTDOWN channel.
            raw_state = self._channel._channel.check_connectivity_state(False)
            connectivity = _CONNECTIVITY_STATE_BY_INT.get(raw_state)
            if connectivity is None:
                logger.debug(f"Health check saw unrecognised connectivity state: {raw_state}")
                return True, "unknown"
            if connectivity == grpc.ChannelConnectivity.SHUTDOWN:
                return False, "channel_shutdown"
            return True, connectivity.name.lower()
        except Exception as e:
            # If we can't check the state at all the process is still running
            logger.debug(f"Health check channel state error: {e}")
            return True, "unknown"

    def is_ready(self) -> tuple:
        """
        Returns (True, reason) if ready, (False, reason) if not.

        During the grace period always returns ready.  After the grace period,
        checks that last_event_timestamp is within the staleness window.
        """
        uptime = time.time() - self._start_time

        if uptime < self.grace_period:
            return True, f"grace_period ({int(self.grace_period - uptime)}s remaining)"

        last_event = self.analyzer.last_event_time

        if last_event == 0:
            # No events ever seen — if we're past the grace period but the node
            # has had no cert activity, that is a valid state, not a failure
            return True, "no_events_seen"

        age = time.time() - last_event
        if age > self.staleness_seconds:
            return False, f"last_event_stale ({int(age)}s ago, limit {self.staleness_seconds}s)"

        return True, f"last_event {int(age)}s ago"

    # ── Fleet control ─────────────────────────────────────────────────────────

    def control_info(self) -> dict:
        """Body for GET /control/info."""
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
            # Grows as later releases add config/lifecycle control; the
            # fleet manager reads this to decide what to offer per node.
            'capabilities': ['policies'],
            'tetragon_connected': getattr(analyzer, '_tetragon_stub', None) is not None,
        }

    # ── HTTP server ───────────────────────────────────────────────────────────

    def _make_handler(self):
        """Return a request handler class closed over this HealthServer instance."""
        health_server = self

        class _Handler(BaseHTTPRequestHandler):
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

            def _control_authorized(self) -> bool:
                """
                Bearer-token check for /control/*. Constant-time compare so
                the response time can't leak how much of a guessed token
                matched. Deliberately no body on failure -- nothing for a
                scanner to fingerprint.
                """
                token = health_server.control_token
                if token is None:
                    return False
                header = self.headers.get('Authorization', '')
                scheme, _, presented = header.partition(' ')
                if scheme.lower() != 'bearer' or not presented:
                    return False
                return hmac.compare_digest(presented.strip().encode(), token.encode())

            def _read_control_body(self) -> Optional[dict]:
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                except ValueError:
                    return None
                if length < 0 or length > _MAX_CONTROL_BODY_BYTES:
                    return None
                raw = self.rfile.read(length) if length else b''
                try:
                    body = json.loads(raw or b'{}')
                except ValueError:
                    return None
                return body if isinstance(body, dict) else None

            def do_GET(self):
                path = urlsplit(self.path).path
                if path == '/healthz':
                    ok, reason = health_server.is_live()
                elif path == '/readyz':
                    ok, reason = health_server.is_ready()
                elif path.startswith('/control/'):
                    self._do_control_get(path)
                    return
                else:
                    self._send_empty(404)
                    return

                status = 200 if ok else 503
                self._send_json(status, {'status': 'ok' if ok else 'fail', 'reason': reason})

            def _do_control_get(self, path: str) -> None:
                if health_server.control_token is None:
                    self._send_empty(404)
                    return
                if not self._control_authorized():
                    self._send_empty(401)
                    return
                if path == '/control/info':
                    self._send_json(200, health_server.control_info())
                elif path == '/control/policies':
                    self._send_json(200, health_server.analyzer.list_policies_for_control())
                else:
                    self._send_empty(404)

            def do_PUT(self):
                parts = urlsplit(self.path)
                path = parts.path
                if health_server.control_token is None or not path.startswith('/control/'):
                    self._send_empty(404)
                    return
                if not self._control_authorized():
                    self._send_empty(401)
                    return
                prefix = '/control/policies/'
                if not path.startswith(prefix):
                    self._send_empty(404)
                    return
                name = path[len(prefix):]
                namespace = (parse_qs(parts.query).get('namespace') or [''])[0]
                body = self._read_control_body()
                enabled = body.get('enabled') if body else None
                if (not POLICY_NAME_RE.match(name)
                        or (namespace and not POLICY_NAME_RE.match(namespace))
                        or not isinstance(enabled, bool)):
                    self._send_json(400, {'error': 'bad_request'})
                    return
                status, result = health_server.analyzer.set_policy_enabled_for_control(
                    name, namespace, enabled,
                )
                # Deliberately loud: this is the one thing in cert-analyzer
                # that changes what the node detects on request, so every
                # attempt -- refused or not -- lands in the journal with the
                # caller's address.
                logger.warning(
                    f"Fleet control: {self.client_address[0]} requested policy "
                    f"{name!r}{' in ' + namespace if namespace else ''} -> "
                    f"{'enabled' if enabled else 'disabled'}: HTTP {status}"
                    + (f" ({result.get('error')})" if status != 200 else '')
                )
                self._send_json(status, result)

            def log_message(self, fmt, *args):
                # Suppress per-request access logs to avoid filling stdout
                # with probe traffic — errors are still logged
                if args and str(args[1]) not in ('200', '503'):
                    logger.debug(f"Health probe: {fmt % args}")

        return _Handler

    def start(self) -> None:
        """Start the health server in a background daemon thread."""
        try:
            # Threaded so a /control/* call waiting on a Tetragon RPC (up to
            # its 10s timeout) can't stall a concurrent kubelet probe.
            self._server = ThreadingHTTPServer(('', self.port), self._make_handler())
            self._server.daemon_threads = True
        except OSError as e:
            logger.critical(
                f"Cannot bind health server to port {self.port}: {e}. "
                f"Change [health] port in cert-analyzer.conf or set HEALTH_PORT."
            )
            sys.exit(1)

        thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        thread.name = 'health-server'
        thread.start()
        logger.info(
            f"Health server started on port {self.port} "
            f"(grace={self.grace_period}s, staleness={self.staleness_seconds}s)"
        )

    def stop(self) -> None:
        """Shut down the health server cleanly."""
        if self._server:
            self._server.shutdown()
