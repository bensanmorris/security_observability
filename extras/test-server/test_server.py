"""
Tests for server.py's --mode full/explorer split (see AWS Marketplace plan:
the Dashboard AMI runs this in 'explorer' mode -- no Kafka, no /api/run/*
action endpoints, only the read-only fleet explorer pages).

Run from extras/test-server/: python3 -m pytest test_server.py
"""
import http.client
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import server as ts  # noqa: E402


# ── parse_args() mode/kafka-requirement resolution ──────────────────────────

class TestParseArgsMode:
    def test_default_mode_is_full(self, monkeypatch):
        """Backward compatibility: every existing deployment (aws-demo,
        OpenShift, CRC) never sets TEST_SERVER_MODE and already supplies
        Kafka args -- the default must stay 'full' so they're unaffected."""
        monkeypatch.delenv('TEST_SERVER_MODE', raising=False)
        monkeypatch.setattr(sys, 'argv', [
            'server.py', '--kafka-host', 'localhost', '--kafka-port', '9092',
        ])
        args = ts.parse_args()
        assert args.mode == 'full'

    def test_full_mode_without_kafka_args_errors(self, monkeypatch):
        monkeypatch.delenv('TEST_SERVER_MODE', raising=False)
        monkeypatch.delenv('TEST_SERVER_KAFKA_HOST', raising=False)
        monkeypatch.delenv('TEST_SERVER_KAFKA_PORT', raising=False)
        monkeypatch.setattr(sys, 'argv', ['server.py'])
        with pytest.raises(SystemExit):
            ts.parse_args()

    def test_explorer_mode_without_kafka_args_succeeds(self, monkeypatch):
        monkeypatch.delenv('TEST_SERVER_KAFKA_HOST', raising=False)
        monkeypatch.delenv('TEST_SERVER_KAFKA_PORT', raising=False)
        monkeypatch.setattr(sys, 'argv', ['server.py', '--mode', 'explorer'])
        args = ts.parse_args()
        assert args.mode == 'explorer'
        assert args.kafka_host is None
        assert args.kafka_port is None

    def test_explorer_mode_via_env_var(self, monkeypatch):
        monkeypatch.setenv('TEST_SERVER_MODE', 'explorer')
        monkeypatch.delenv('TEST_SERVER_KAFKA_HOST', raising=False)
        monkeypatch.delenv('TEST_SERVER_KAFKA_PORT', raising=False)
        monkeypatch.setattr(sys, 'argv', ['server.py'])
        args = ts.parse_args()
        assert args.mode == 'explorer'

    def test_invalid_mode_value_errors(self, monkeypatch):
        """argparse's choices= doesn't validate an env-sourced default on its
        own -- parse_args()'s explicit check is what actually catches this."""
        monkeypatch.setenv('TEST_SERVER_MODE', 'bogus')
        monkeypatch.setattr(sys, 'argv', ['server.py'])
        with pytest.raises(SystemExit):
            ts.parse_args()


# ── make_handler() routing in each mode ─────────────────────────────────────

class _RunningServer:
    """Starts make_handler(...) on an ephemeral localhost port for the
    duration of a `with` block, on its own daemon thread."""

    def __init__(self, broadcaster, prometheus_url, mode):
        self._httpd = ThreadingHTTPServer(
            ('127.0.0.1', 0), ts.make_handler(broadcaster, prometheus_url, mode)
        )
        self.port = self._httpd.server_address[1]

    def __enter__(self):
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._httpd.shutdown()
        self._thread.join(timeout=2.0)

    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=2)
        try:
            conn.request(method, path, body=body)
            return conn.getresponse().status
        finally:
            conn.close()


# A closed localhost port refuses the connection almost instantly (unlike an
# unroutable address, which just hangs until _prom_query's own 10s timeout),
# which is what proves _serve_generated_page's request actually failed --
# i.e. that routing reached it -- within this test's own client timeout.
_UNREACHABLE_PROMETHEUS_URL = 'http://127.0.0.1:1'


class TestExplorerModeRouting:
    def test_action_and_event_endpoints_404(self):
        with _RunningServer(None, _UNREACHABLE_PROMETHEUS_URL, 'explorer') as s:
            assert s.request('POST', '/api/run/cat-cert-bundle') == 404
            assert s.request('GET', '/api/events') == 404

    def test_use_cases_metadata_and_static_still_served(self):
        with _RunningServer(None, _UNREACHABLE_PROMETHEUS_URL, 'explorer') as s:
            assert s.request('GET', '/') == 200
            assert s.request('GET', '/api/use-cases') == 200

    def test_explorer_pages_are_routed_not_404(self):
        """Routing reaches _serve_generated_page (502 on a bad Prometheus
        URL) rather than falling through to the catch-all 404."""
        with _RunningServer(None, _UNREACHABLE_PROMETHEUS_URL, 'explorer') as s:
            for path in (
                '/blast-radius', '/fleet-blast-radius',
                '/chain-explorer', '/fleet-chain-explorer',
                '/fleet-fips-rollout',
            ):
                assert s.request('GET', path) == 502, path


class TestFullModeRoutingUnchanged:
    """Confirms explorer-mode gating doesn't alter --mode full's existing
    behavior for any deployment that hasn't opted in."""

    def test_events_endpoint_not_gated(self):
        broadcaster = ts.EventBroadcaster()
        with _RunningServer(broadcaster, _UNREACHABLE_PROMETHEUS_URL, 'full') as s:
            conn = http.client.HTTPConnection('127.0.0.1', s.port, timeout=2)
            conn.request('GET', '/api/events')
            resp = conn.getresponse()
            assert resp.status == 200
            conn.close()

    def test_run_use_case_endpoint_reaches_handler(self):
        """404 here comes from _run_use_case's own 'unknown use case' branch,
        not the routing catch-all -- confirmed by the response body."""
        broadcaster = ts.EventBroadcaster()
        with _RunningServer(broadcaster, _UNREACHABLE_PROMETHEUS_URL, 'full') as s:
            conn = http.client.HTTPConnection('127.0.0.1', s.port, timeout=2)
            conn.request('POST', '/api/run/does-not-exist')
            resp = conn.getresponse()
            body = resp.read()
            assert resp.status == 404
            assert b'unknown use case' in body
            conn.close()
