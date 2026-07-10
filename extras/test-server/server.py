#!/usr/bin/env python3
"""
Test HTTP server for exercising CertSight's certificate detections.

Serves a two-pane page: the left pane lists test use cases (e.g. "cat the
system certificate bundle"); clicking one runs the underlying action on
this host (a real file read, real TLS connection, etc.) so that a locally
running Tetragon + cert-analyzer pick it up exactly as they would in
production. The right pane streams cert-analyzer's resulting Kafka events
live via Server-Sent Events.

Requires:
  - Tetragon + cert-analyzer already running on this host with the
    relevant policy applied (see tetragon-policies/certificate-file-access.yaml)
  - cert-analyzer configured with [kafka] enabled = true, pointed at the
    same broker given to --kafka-host/--kafka-port here
  - kafka-python (pip install kafka-python)

cert-analyzer only publishes to Kafka on *first-time* discovery of a given
certificate (see extras/kafka/KAFKA-README.md) -- re-running a use case
against a certificate cert-analyzer has already seen since its last
restart will not produce a new event. Restart cert-analyzer to clear its
known-certs cache between test runs if you want every click to publish.

Usage:
    python3 extras/test-server/server.py --kafka-host localhost --kafka-port 9092
"""
import argparse
import json
import logging
import os
import queue
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

try:
    from kafka import KafkaConsumer
    from kafka.errors import KafkaError
except ImportError:
    print("ERROR: kafka-python is not installed. Install it with:", file=sys.stderr)
    print("       pip install kafka-python", file=sys.stderr)
    sys.exit(1)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from use_cases import USE_CASES, USE_CASES_BY_ID, UseCaseResult  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("test-server")

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript"),
    "/app.css": ("app.css", "text/css"),
}

# Raw source files servable via /source/<name>, linked from a use case's
# "How this works" pipeline text so the reader can see the full script
# behind an inlined snippet. Explicit allowlist rather than a generic
# ?file= path, since this endpoint may be reachable with no authentication
# (see TEST-SERVER-README.md) -- an unbounded version would let any caller
# read arbitrary files this process can access. Served from disk (not a
# GitHub link) so it keeps working on an RPM install with zero internet
# access, which is a supported deployment mode for this tool.
SOURCE_FILES = {"tls_probe_helper.py", "use_cases.py"}


class EventBroadcaster:
    """Fans out each Kafka message to every currently-connected SSE client."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: "set[queue.Queue]" = set()

    def subscribe(self) -> "queue.Queue":
        q: "queue.Queue" = queue.Queue()
        with self._lock:
            self._subscribers.add(q)
        return q

    def unsubscribe(self, q: "queue.Queue") -> None:
        with self._lock:
            self._subscribers.discard(q)

    def publish(self, message: str) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
        for q in subscribers:
            q.put(message)


def _consume_kafka(broadcaster: EventBroadcaster, host: str, port: int, topic: str) -> None:
    bootstrap = f"{host}:{port}"
    while True:
        try:
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=bootstrap,
                auto_offset_reset="latest",
                enable_auto_commit=False,
            )
            logger.info("connected to Kafka %s, topic '%s'", bootstrap, topic)
            for message in consumer:
                broadcaster.publish(message.value.decode("utf-8", errors="replace"))
        except KafkaError as e:
            logger.warning("Kafka consumer error (%s), retrying in 5s", e)
            time.sleep(5)
        except Exception:
            logger.exception("unexpected error in Kafka consumer loop, retrying in 5s")
            time.sleep(5)


def make_handler(broadcaster: EventBroadcaster):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            logger.info("%s - %s", self.address_string(), fmt % args)

        def do_GET(self):
            path = urlparse(self.path).path
            if path in STATIC_FILES:
                self._serve_static(path)
            elif path.startswith("/source/"):
                self._serve_source(path[len("/source/"):])
            elif path == "/api/use-cases":
                self._serve_use_cases()
            elif path == "/api/events":
                self._serve_events()
            else:
                self.send_error(404)

        def do_POST(self):
            path = urlparse(self.path).path
            if path.startswith("/api/run/"):
                self._run_use_case(path[len("/api/run/"):])
            else:
                self.send_error(404)

        def _serve_static(self, path):
            filename, content_type = STATIC_FILES[path]
            data = (STATIC_DIR / filename).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _serve_source(self, filename):
            if filename not in SOURCE_FILES:
                self.send_error(404, f"no such source file '{filename}'")
                return
            data = (APP_DIR / filename).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _serve_use_cases(self):
            payload = [
                {
                    "id": uc.id,
                    "label": uc.label,
                    "description": uc.description,
                    "pipeline": uc.pipeline or [],
                    "params": [
                        {"name": p.name, "label": p.label, "options": p.options, "default": p.default}
                        for p in (uc.params or [])
                    ],
                }
                for uc in USE_CASES
            ]
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _run_use_case(self, use_case_id):
            use_case = USE_CASES_BY_ID.get(use_case_id)
            if use_case is None:
                self.send_error(404, f"unknown use case '{use_case_id}'")
                return

            params = {}
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length:
                # Small cap on an unauthenticated, network-reachable endpoint --
                # the body is only ever a handful of short param values.
                if content_length > 4096:
                    self.send_error(413, "request body too large")
                    return
                raw = self.rfile.read(content_length)
                try:
                    params = json.loads(raw)
                    if not isinstance(params, dict):
                        raise ValueError("params body must be a JSON object")
                except (json.JSONDecodeError, ValueError) as e:
                    self.send_error(400, f"invalid JSON body: {e}")
                    return

            logger.info("running use case '%s' with params=%r", use_case_id, params)
            try:
                result = use_case.run(params)
            except Exception:
                # An uncaught exception here would otherwise propagate out of
                # do_POST with no response ever sent, which socketserver logs
                # but the client just sees as a raw connection failure (e.g.
                # browsers report a bare "NetworkError") instead of a readable
                # error -- always return a clean 500 with the exception text.
                logger.exception("use case '%s' raised", use_case_id)
                result = UseCaseResult(ok=False, detail=f"use case raised an unhandled exception: {sys.exc_info()[1]}")
            body = json.dumps({"ok": result.ok, "detail": result.detail}).encode("utf-8")
            self.send_response(200 if result.ok else 500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _serve_events(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            q = broadcaster.subscribe()
            try:
                while True:
                    try:
                        message = q.get(timeout=15)
                        self.wfile.write(f"data: {message}\n\n".encode("utf-8"))
                    except queue.Empty:
                        self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                broadcaster.unsubscribe(q)

    return Handler


def parse_args() -> argparse.Namespace:
    # Every flag also falls back to a TEST_SERVER_* environment variable, so
    # the systemd unit can configure this via EnvironmentFile= without
    # relying on shell-style $VAR substitution in ExecStart= (unsupported on
    # older systemd). CLI flags still win when both are given.
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("TEST_SERVER_PORT", 8090)),
        help="port for this test server (default: 8090, env: TEST_SERVER_PORT)",
    )
    parser.add_argument(
        "--bind",
        default=os.environ.get("TEST_SERVER_BIND", "127.0.0.1"),
        help=(
            "address to bind to (default: 127.0.0.1, env: TEST_SERVER_BIND) -- this "
            "server executes real file/network actions on request, so do not expose "
            "it beyond localhost or a trusted lab network"
        ),
    )
    parser.add_argument(
        "--kafka-host",
        default=os.environ.get("TEST_SERVER_KAFKA_HOST"),
        help="Kafka broker hostname/IP cert-analyzer is publishing to (env: TEST_SERVER_KAFKA_HOST)",
    )
    parser.add_argument(
        "--kafka-port",
        type=int,
        default=os.environ.get("TEST_SERVER_KAFKA_PORT"),
        help="Kafka broker port (env: TEST_SERVER_KAFKA_PORT)",
    )
    parser.add_argument(
        "--topic",
        default=os.environ.get("TEST_SERVER_TOPIC", "cert-analyzer-events"),
        help="Kafka topic to watch (default: cert-analyzer-events, env: TEST_SERVER_TOPIC)",
    )
    args = parser.parse_args()
    if args.kafka_host is None or args.kafka_port is None:
        parser.error(
            "--kafka-host/--kafka-port are required "
            "(pass as flags, or set TEST_SERVER_KAFKA_HOST/TEST_SERVER_KAFKA_PORT)"
        )
    return args


def main() -> None:
    args = parse_args()

    broadcaster = EventBroadcaster()
    consumer_thread = threading.Thread(
        target=_consume_kafka,
        args=(broadcaster, args.kafka_host, args.kafka_port, args.topic),
        daemon=True,
    )
    consumer_thread.start()

    server = ThreadingHTTPServer((args.bind, args.port), make_handler(broadcaster))
    server.daemon_threads = True
    logger.info(
        "serving on http://%s:%d (Kafka: %s:%d, topic '%s')",
        args.bind, args.port, args.kafka_host, args.kafka_port, args.topic,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
