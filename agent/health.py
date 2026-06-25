import grpc
import logging
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

logger = logging.getLogger(__name__)


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
    ):
        self.analyzer            = analyzer
        self.port                = port
        self.grace_period        = grace_period_seconds
        self.staleness_seconds   = staleness_seconds
        self._start_time         = time.time()
        self._channel            = None   # set by CertificateAnalyzer.start()
        self._server: Optional[HTTPServer] = None

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
            state = self._channel._channel.check_connectivity_state(False)
            # grpc.ChannelConnectivity values: IDLE=0, CONNECTING=1,
            # READY=2, TRANSIENT_FAILURE=3, SHUTDOWN=4
            if state == grpc.ChannelConnectivity.SHUTDOWN:
                return False, "channel_shutdown"
            return True, grpc.ChannelConnectivity(state).name.lower()
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

        last_event = self.analyzer.metrics.last_event_timestamp.labels(
            node_name=self.analyzer.metrics._node_name
        )._value.get()

        if last_event == 0:
            # No events ever seen — if we're past the grace period but the node
            # has had no cert activity, that is a valid state, not a failure
            return True, "no_events_seen"

        age = time.time() - last_event
        if age > self.staleness_seconds:
            return False, f"last_event_stale ({int(age)}s ago, limit {self.staleness_seconds}s)"

        return True, f"last_event {int(age)}s ago"

    # ── HTTP server ───────────────────────────────────────────────────────────

    def _make_handler(self):
        """Return a request handler class closed over this HealthServer instance."""
        health_server = self

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/healthz':
                    ok, reason = health_server.is_live()
                elif self.path == '/readyz':
                    ok, reason = health_server.is_ready()
                else:
                    self.send_response(404)
                    self.end_headers()
                    return

                status = 200 if ok else 503
                body   = f'{{"status": "{"ok" if ok else "fail"}", "reason": "{reason}"}}\n'
                body_bytes = body.encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body_bytes)))
                self.end_headers()
                self.wfile.write(body_bytes)

            def log_message(self, fmt, *args):
                # Suppress per-request access logs to avoid filling stdout
                # with probe traffic — errors are still logged
                if args and str(args[1]) not in ('200', '503'):
                    logger.debug(f"Health probe: {fmt % args}")

        return _Handler

    def start(self) -> None:
        """Start the health server in a background daemon thread."""
        try:
            self._server = HTTPServer(('', self.port), self._make_handler())
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
