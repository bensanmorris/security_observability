#!/usr/bin/env python3
"""
TLS Certificate Expiry Monitor for RHEL9/Podman
Consumes Tetragon events and analyzes certificate expiry dates
EXTENDED: Now supports multiple certificates per file
EXTENDED: Kubernetes pod enrichment via k8s_enricher
"""

import os
import sys
import logging
import grpc
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Set, Tuple, List, OrderedDict as OrderedDictType
from collections import OrderedDict
from dataclasses import dataclass, field
from concurrent import futures
import time
import re
import threading
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from prometheus_client import Gauge, Counter, Info, start_http_server

# Import generated Tetragon protos
try:
    from tetragon import tetragon_pb2, events_pb2, sensors_pb2_grpc
except ImportError:
    print("ERROR: Tetragon protobuf files not found. Run generate_tetragon_protos.sh first")
    sys.exit(1)

# Import Kubernetes enricher - optional, degrades gracefully if unavailable
try:
    from k8s_enricher import KubernetesEnricher
    K8S_ENRICHER_AVAILABLE = True
except ImportError:
    K8S_ENRICHER_AVAILABLE = False

# Import JKS parser - optional, degrades gracefully if unavailable
# Install with: pip install pyjks
try:
    import jks
    JKS_AVAILABLE = True
except ImportError:
    JKS_AVAILABLE = False

# The Tetragon version this build was compiled against.
# Must be kept in lockstep with the version used in the Containerfile build arg.
# Set by the CI build process via the TETRAGON_BUILD_VERSION environment variable
# which is injected at image build time; falls back to 'unknown' if not set.
TETRAGON_BUILD_VERSION: str = os.getenv('TETRAGON_BUILD_VERSION', 'unknown')

# The cert-analyzer version — set at image build time from the git tag or
# commit SHA via the VERSION build arg in the Containerfile.
# Falls back to 'dev' when running outside of a built container.
CERT_ANALYZER_VERSION: str = os.getenv('CERT_ANALYZER_VERSION', 'dev')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class CertificateInfo:
    """Information extracted from an X.509 certificate"""
    path: str
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    process: str
    pid: int
    namespace: str = ""
    common_name: str = ""
    san_dns_names: list = field(default_factory=list)
    cert_index: int = 0
    # Workload context sourced directly from Tetragon event (always populated when available)
    pod_name: str = ""
    workload_kind: str = ""
    workload_name: str = ""
    pod_labels: dict = None
    # Additional context from Kubernetes API enricher (supplements Tetragon data)
    app_label: str = ""
    container_name: str = ""
    container_image: str = ""
    # SHA-256 of the DER-encoded certificate bytes. Empty string when
    # CERT_CHECKSUM_ENABLED=false (the default).
    checksum: str = ""

    @property
    def days_until_expiry(self) -> float:
        """Calculate days until certificate expires"""
        delta = self.not_after - datetime.utcnow()
        return delta.total_seconds() / 86400

    @property
    def is_expired(self) -> bool:
        """Check if certificate has expired"""
        return datetime.utcnow() > self.not_after

    def expires_soon(self, days: int = 30) -> bool:
        """Check if certificate expires within specified days"""
        return 0 < self.days_until_expiry < days

    @property
    def unique_key(self) -> str:
        """Unique identifier for this certificate"""
        return f"{self.path}:{self.cert_index}:{self.serial_number}"

    @property
    def workload(self) -> str:
        """Human-readable workload reference e.g. DaemonSet/cert-analyzer"""
        if self.workload_kind and self.workload_name:
            return f"{self.workload_kind}/{self.workload_name}"
        return ""


class PrometheusMetrics:
    """Prometheus metrics for certificate monitoring"""

    def __init__(self):
        # Certificate expiry metrics - includes k8s workload labels
        self.cert_expiry_days = Gauge(
            'tls_certificate_expiry_days',
            'Days until TLS certificate expiry',
            ['cert_path', 'subject', 'issuer', 'serial', 'process', 'common_name',
             'cert_index', 'pod_name', 'namespace', 'workload_kind', 'workload_name',
             'app_label', 'container_name']
        )

        self.cert_expiry_timestamp = Gauge(
            'tls_certificate_expiry_timestamp',
            'Unix timestamp of certificate expiry',
            ['cert_path', 'subject', 'issuer', 'serial', 'process', 'common_name',
             'cert_index', 'pod_name', 'namespace', 'workload_kind', 'workload_name',
             'app_label', 'container_name']
        )

        self.cert_valid_from = Gauge(
            'tls_certificate_valid_from_timestamp',
            'Unix timestamp of certificate valid from date',
            ['cert_path', 'subject', 'issuer', 'serial', 'process', 'common_name',
             'cert_index', 'pod_name', 'namespace', 'workload_kind', 'workload_name',
             'app_label', 'container_name']
        )

        # Event counters
        self.cert_events_total = Counter(
            'tls_certificate_events_total',
            'Total number of certificate events detected',
            ['event_type', 'status']
        )

        self.cert_analysis_errors = Counter(
            'tls_certificate_analysis_errors_total',
            'Total number of certificate analysis errors',
            ['error_type']
        )

        # Certificate status
        self.cert_expired = Gauge(
            'tls_certificate_expired',
            'Whether certificate is expired (1=expired, 0=valid)',
            ['cert_path', 'process', 'cert_index', 'pod_name', 'namespace',
             'workload_kind', 'workload_name']
        )

        self.cert_expiring_soon = Gauge(
            'tls_certificate_expiring_soon',
            'Whether certificate expires within threshold (1=yes, 0=no)',
            ['cert_path', 'process', 'threshold_days', 'cert_index', 'pod_name',
             'namespace', 'workload_kind', 'workload_name']
        )

        # System health
        self.analyzer_healthy = Gauge(
            'cert_analyzer_healthy',
            'Health status of the analyzer (1=healthy, 0=unhealthy)'
        )
        self.analyzer_healthy.set(1)

        self.last_event_timestamp = Gauge(
            'cert_analyzer_last_event_timestamp',
            'Timestamp of last processed event'
        )

        # Tetragon version tracking — detects build/runtime version mismatch
        self.tetragon_version_info = Info(
            'cert_analyzer_tetragon_version',
            'Tetragon version information for build and runtime',
        )

        self.tetragon_version_match = Gauge(
            'cert_analyzer_tetragon_version_match',
            'Whether the build and runtime Tetragon versions match (1=match, 0=mismatch)',
        )

        # Build info — single source of truth for version diagnostics.
        # Combines cert-analyzer version and Tetragon build version so a single
        # Prometheus query shows exactly what was built together.
        self.build_info = Info(
            'cert_analyzer_build',
            'Build information for the cert-analyzer',
        )
        self.build_info.info({
            'version':                CERT_ANALYZER_VERSION,
            'tetragon_build_version': TETRAGON_BUILD_VERSION,
        })

        # Cache size metrics — track LRU cache occupancy for capacity planning
        # and to alert before caches approach their cap
        self.cache_known_certs_size = Gauge(
            'cert_analyzer_cache_known_certs_size',
            'Number of entries in the known_certs LRU cache',
        )
        self.cache_processed_paths_size = Gauge(
            'cert_analyzer_cache_processed_paths_size',
            'Number of entries in the processed_paths LRU cache',
        )
        self.cache_password_failed_size = Gauge(
            'cert_analyzer_cache_password_failed_size',
            'Number of entries in the password_failed_paths LRU cache',
        )
        self.cache_max_size = Gauge(
            'cert_analyzer_cache_max_size',
            'Configured maximum size for all LRU caches',
        )
        self.cache_max_size.set(CACHE_MAX_SIZE)

    def update_certificate_metrics(self, info: CertificateInfo):
        """Update Prometheus metrics for a certificate"""
        labels = {
            'cert_path':      info.path,
            'subject':        info.subject[:100],
            'issuer':         info.issuer[:100],
            'serial':         info.serial_number,
            'process':        info.process,
            'common_name':    info.common_name,
            'cert_index':     str(info.cert_index),
            'pod_name':       info.pod_name,
            'namespace':      info.namespace,
            'workload_kind':  info.workload_kind,
            'workload_name':  info.workload_name,
            'app_label':      info.app_label,
            'container_name': info.container_name,
        }

        self.cert_expiry_days.labels(**labels).set(info.days_until_expiry)
        self.cert_expiry_timestamp.labels(**labels).set(info.not_after.timestamp())
        self.cert_valid_from.labels(**labels).set(info.not_before.timestamp())

        self.cert_expired.labels(
            cert_path=info.path,
            process=info.process,
            cert_index=str(info.cert_index),
            pod_name=info.pod_name,
            namespace=info.namespace,
            workload_kind=info.workload_kind,
            workload_name=info.workload_name,
        ).set(1 if info.is_expired else 0)

        for threshold in [7, 30, 90]:
            self.cert_expiring_soon.labels(
                cert_path=info.path,
                process=info.process,
                threshold_days=str(threshold),
                cert_index=str(info.cert_index),
                pod_name=info.pod_name,
                namespace=info.namespace,
                workload_kind=info.workload_kind,
                workload_name=info.workload_name,
            ).set(1 if 0 < info.days_until_expiry < threshold else 0)


CACHE_MIN_SIZE: int = 10_000
CACHE_MAX_SIZE: int = max(CACHE_MIN_SIZE, int(os.getenv('CACHE_MAX_SIZE', str(CACHE_MIN_SIZE))))

# SHA-256 checksum computation on parsed certificates is disabled by default.
# Enable via CERT_CHECKSUM_ENABLED=true. When enabled, the DER-encoded bytes
# of each certificate are hashed and stored in CertificateInfo.checksum.
# Useful for detecting silent cert rotation (same path, different cert) and
# correlating the same cert appearing at multiple paths.
CERT_CHECKSUM_ENABLED: bool = os.getenv('CERT_CHECKSUM_ENABLED', 'false').lower() == 'true'


class LRUCache:
    """
    A dict-like LRU cache backed by OrderedDict.

    On every get/set the accessed key is moved to the end (most-recently-used).
    When the cap is reached the front entry (least-recently-used) is evicted.

    Used for all three caches in CertificateAnalyzer:
      - known_certs         (path:index:serial → CertificateInfo)
      - processed_paths     (path → True)
      - password_failed_paths (path → True)

    Evicting from known_certs / processed_paths gives evicted certs a chance
    to be re-analysed if they become active again.  Evicting from
    password_failed_paths gives previously-failed keystores a second chance,
    which is desirable if the operator has since set JKS_PASSWORD.
    """

    def __init__(self, maxsize: int = CACHE_MAX_SIZE):
        if maxsize < CACHE_MIN_SIZE:
            logger.warning(
                f"CACHE_MAX_SIZE {maxsize} is below minimum {CACHE_MIN_SIZE}; "
                f"using {CACHE_MIN_SIZE}."
            )
            maxsize = CACHE_MIN_SIZE
        self.maxsize = maxsize
        self._store: OrderedDict = OrderedDict()

    # ── dict-like interface ───────────────────────────────────────────────────

    def __contains__(self, key) -> bool:
        return key in self._store

    def __getitem__(self, key):
        self._store.move_to_end(key)
        return self._store[key]

    def __setitem__(self, key, value) -> None:
        if key in self._store:
            self._store.move_to_end(key)
            self._store[key] = value
        else:
            if len(self._store) >= self.maxsize:
                evicted_key, _ = self._store.popitem(last=False)
                logger.debug(f"LRU eviction: {evicted_key}")
            self._store[key] = value

    def __delitem__(self, key) -> None:
        del self._store[key]

    def __len__(self) -> int:
        return len(self._store)

    def __iter__(self):
        return iter(self._store)

    def get(self, key, default=None):
        if key in self._store:
            return self[key]
        return default

    def items(self):
        return self._store.items()

    def keys(self):
        return self._store.keys()

    def values(self):
        return self._store.values()

    def add(self, key) -> None:
        """Set-like interface for password_failed_paths."""
        self[key] = True

    def discard(self, key) -> None:
        """Set-like discard — no error if key absent."""
        if key in self._store:
            del self._store[key]

    def clear(self) -> None:
        self._store.clear()


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

        last_event = self.analyzer.metrics.last_event_timestamp._value.get()

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
        self._server = HTTPServer(('', self.port), self._make_handler())

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


class CertificateAnalyzer:
    """Main analyzer that processes Tetragon events and extracts certificate info"""

    CERT_EXTENSIONS  = {'.crt', '.pem', '.cert', '.cer', '.key'}
    JKS_EXTENSIONS   = {'.jks', '.keystore', '.truststore'}
    PKCS12_EXTENSIONS = {'.p12', '.pfx'}

    def __init__(self, tetragon_address: str, alert_threshold_days: int = 30,
                 filter_self_events: bool = True,
                 health_server: Optional['HealthServer'] = None):
        self.tetragon_address = tetragon_address
        self.alert_threshold_days = alert_threshold_days
        self.filter_self_events = filter_self_events
        self.metrics = PrometheusMetrics()
        self.known_certs: LRUCache = LRUCache()
        self.processed_paths: LRUCache = LRUCache()
        # Paths that failed password attempts — cached to avoid repeating expensive
        # crypto operations on every subsequent Tetragon event for the same file.
        # LRU eviction gives previously-failed paths a second chance after enough
        # other activity, which is desirable if JKS_PASSWORD has since been set.
        self.password_failed_paths: LRUCache = LRUCache()
        self.health_server = health_server

        # Kubernetes enricher - enabled when running in-cluster or locally with kubeconfig
        if K8S_ENRICHER_AVAILABLE:
            self.enricher = KubernetesEnricher()
            if self.enricher.available:
                logger.info("Kubernetes pod enrichment enabled")
            else:
                logger.info("Kubernetes pod enrichment disabled - API unavailable")
        else:
            self.enricher = None
            logger.info("Kubernetes pod enrichment disabled - k8s_enricher not found")

    def _update_cache_metrics(self) -> None:
        """Update Prometheus gauges reflecting current LRU cache occupancy."""
        self.metrics.cache_known_certs_size.set(len(self.known_certs))
        self.metrics.cache_processed_paths_size.set(len(self.processed_paths))
        self.metrics.cache_password_failed_size.set(len(self.password_failed_paths))

    def is_cert_path(self, path: str) -> bool:
        """Check if a path looks like a certificate or keystore file"""
        if not path:
            return False
        suffix = Path(path).suffix.lower()
        return (suffix in self.CERT_EXTENSIONS
                or suffix in self.JKS_EXTENSIONS
                or suffix in self.PKCS12_EXTENSIONS)

    def parse_jks_certificates(self, cert_path: str) -> List[x509.Certificate]:
        """
        Parse X.509 certificates from a JKS (Java KeyStore) file.

        JKS keystores are used by Java applications (Spring Boot, Tomcat, etc.)
        and contain trusted certificate entries and/or private key entries with
        certificate chains. This method extracts both.

        Requires the 'pyjks' package. Falls back gracefully if not installed.
        Set the JKS_PASSWORD env var if the keystore uses a non-default password.

        Password strategy: tries JKS_PASSWORD env var (if set), then 'changeit'
        (Java ecosystem default), then empty string (unprotected truststores).
        Files that fail all attempts are cached in password_failed_paths so
        subsequent Tetragon events for the same file skip the expensive crypto
        operations rather than retrying on every access.
        """
        if not JKS_AVAILABLE:
            logger.warning(
                f"Skipping JKS file {cert_path}: pyjks not installed. "
                "Add 'pyjks' to requirements.txt to enable JKS support."
            )
            self.metrics.cert_analysis_errors.labels(error_type='jks_unavailable').inc()
            return []

        # Skip files that have already failed — avoids repeating crypto work on
        # every subsequent Tetragon event for the same keystore
        if cert_path in self.password_failed_paths:
            logger.debug(
                f"Skipping previously password-failed JKS: {cert_path} "
                f"(set JKS_PASSWORD env var to enable monitoring of this file)"
            )
            return []

        configured = os.getenv('JKS_PASSWORD', '')
        # Option B: env var → changeit → empty string only
        # 'changeit' is retained as it is the Java ecosystem default and present
        # in many managed environments on legacy or CA bundle keystores.
        passwords_to_try = list(dict.fromkeys([configured, 'changeit', '']))

        ks = None
        for password in passwords_to_try:
            try:
                ks = jks.KeyStore.load(cert_path, password)
                logger.debug(
                    f"Opened JKS {cert_path} "
                    f"(password={'<empty>' if not password else '<set>'})"
                )
                break
            except jks.util.BadKeystoreFormatException:
                logger.debug(f"Not a valid JKS keystore: {cert_path}")
                return []
            except Exception:
                continue

        if ks is None:
            logger.warning(
                f"Could not open JKS {cert_path}: all passwords failed. "
                "Set JKS_PASSWORD env var if the keystore uses a custom password."
            )
            self.metrics.cert_analysis_errors.labels(error_type='jks_password_failed').inc()
            self.password_failed_paths.add(cert_path)
            self._update_cache_metrics()
            return []

        certificates = []

        # Trusted certificate entries (truststore / cacerts style)
        for alias, entry in ks.certs.items():
            try:
                cert = x509.load_der_x509_certificate(entry.cert, default_backend())
                certificates.append(cert)
                logger.debug(f"JKS trusted cert: alias='{alias}' path={cert_path}")
            except Exception as e:
                logger.debug(f"JKS: failed to parse trusted cert alias='{alias}': {e}")

        # Private key entries — extract the certificate chain
        for alias, entry in ks.private_keys.items():
            for _, cert_der in entry.cert_chain:
                try:
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    certificates.append(cert)
                    logger.debug(f"JKS chain cert: alias='{alias}' path={cert_path}")
                except Exception as e:
                    logger.debug(f"JKS: failed to parse chain cert alias='{alias}': {e}")

        logger.debug(f"JKS: loaded {len(certificates)} certificate(s) from {cert_path}")
        return certificates

    def parse_pkcs12_certificates(self, cert_path: str) -> List[x509.Certificate]:
        """
        Parse X.509 certificates from a PKCS12 keystore (.p12 / .pfx).

        PKCS12 is the modern industry-standard keystore format (replacing JKS)
        and is used by Java apps, .NET, OpenSSL, and browsers. A PKCS12 file
        contains a leaf certificate, its private key, and optionally a chain of
        intermediate/root CA certificates.

        No additional dependencies are required — the 'cryptography' library
        already provides PKCS12 support via load_pkcs12().

        Set the PKCS12_PASSWORD env var if the file uses a non-default password.
        """
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12

        configured = os.getenv('PKCS12_PASSWORD', '')
        # Option B: env var → changeit → empty string only
        passwords_to_try = list(dict.fromkeys([configured, 'changeit', '']))

        # Skip files that have already failed password attempts
        if cert_path in self.password_failed_paths:
            logger.debug(
                f"Skipping previously password-failed PKCS12: {cert_path} "
                f"(set PKCS12_PASSWORD env var to enable monitoring of this file)"
            )
            return []

        try:
            with open(cert_path, 'rb') as f:
                p12_data = f.read()
        except FileNotFoundError:
            logger.debug(f"PKCS12 file not found: {cert_path}")
            self.metrics.cert_analysis_errors.labels(error_type='file_not_found').inc()
            return []
        except PermissionError:
            logger.debug(f"Permission denied reading PKCS12: {cert_path}")
            self.metrics.cert_analysis_errors.labels(error_type='permission_denied').inc()
            return []

        p12 = None
        for password in passwords_to_try:
            try:
                pw_bytes = password.encode() if password else b''
                p12 = load_pkcs12(p12_data, pw_bytes)
                logger.debug(
                    f"Opened PKCS12 {cert_path} "
                    f"(password={'<empty>' if not password else '<set>'})"
                )
                break
            except Exception:
                continue

        if p12 is None:
            logger.warning(
                f"Could not open PKCS12 {cert_path}: all passwords failed. "
                "Set PKCS12_PASSWORD env var if the file uses a custom password."
            )
            self.metrics.cert_analysis_errors.labels(error_type='pkcs12_password_failed').inc()
            self.password_failed_paths.add(cert_path)
            self._update_cache_metrics()
            return []

        certificates = []

        # Leaf certificate (the primary end-entity cert)
        if p12.cert and p12.cert.certificate:
            certificates.append(p12.cert.certificate)
            logger.debug(f"PKCS12 leaf cert: path={cert_path}")

        # Additional certificates — intermediate and root CAs in the chain
        if p12.additional_certs:
            for additional in p12.additional_certs:
                if additional.certificate:
                    certificates.append(additional.certificate)
                    logger.debug(f"PKCS12 chain cert: path={cert_path}")

        logger.debug(f"PKCS12: loaded {len(certificates)} certificate(s) from {cert_path}")
        return certificates

    def parse_certificates(self, cert_path: str) -> List[x509.Certificate]:
        """Parse ALL X.509 certificates from a file (supports PEM, DER, JKS, and PKCS12)"""
        suffix = Path(cert_path).suffix.lower()

        if suffix in self.JKS_EXTENSIONS:
            return self.parse_jks_certificates(cert_path)

        if suffix in self.PKCS12_EXTENSIONS:
            return self.parse_pkcs12_certificates(cert_path)

        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()

            certificates = []

            # Try PEM format first (can contain multiple certs)
            try:
                pem_pattern = re.compile(
                    b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
                    re.DOTALL
                )
                pem_certs = pem_pattern.findall(cert_data)

                if pem_certs:
                    for pem_cert in pem_certs:
                        try:
                            cert = x509.load_pem_x509_certificate(pem_cert, default_backend())
                            certificates.append(cert)
                        except Exception as e:
                            logger.debug(f"Failed to parse PEM cert in {cert_path}: {e}")

                    if certificates:
                        logger.debug(f"Loaded {len(certificates)} certificate(s) from {cert_path}")
                        return certificates

            except Exception as e:
                logger.debug(f"PEM parsing failed for {cert_path}: {e}")

            # Try DER format (single certificate)
            try:
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
                return [cert]
            except Exception:
                pass

            return []

        except FileNotFoundError:
            logger.debug(f"Certificate file not found: {cert_path}")
            self.metrics.cert_analysis_errors.labels(error_type='file_not_found').inc()
            return []
        except PermissionError:
            logger.debug(f"Permission denied reading certificate: {cert_path}")
            self.metrics.cert_analysis_errors.labels(error_type='permission_denied').inc()
            return []
        except Exception as e:
            logger.debug(f"Error reading certificate {cert_path}: {e}")
            self.metrics.cert_analysis_errors.labels(error_type='read_error').inc()
            return []

    def extract_certificate_info(
        self,
        cert: x509.Certificate,
        cert_path: str,
        process: str,
        pid: int,
        namespace: str = "",
        cert_index: int = 0
    ) -> Optional[CertificateInfo]:
        """
        Extract relevant information from an X.509 certificate.

        Returns None if any mandatory field cannot be extracted, rather than
        raising — the caller in analyze_certificate() handles None gracefully.
        This covers malformed certs, encrypted fields, and future cryptography
        library API changes.
        """
        try:
            subject = cert.subject.rfc4514_string()
        except Exception as e:
            logger.warning(f"Could not extract subject from cert {cert_index} in {cert_path}: {e}")
            self.metrics.cert_analysis_errors.labels(error_type='extraction_error').inc()
            return None

        try:
            issuer = cert.issuer.rfc4514_string()
        except Exception as e:
            logger.warning(f"Could not extract issuer from cert {cert_index} in {cert_path}: {e}")
            self.metrics.cert_analysis_errors.labels(error_type='extraction_error').inc()
            return None

        try:
            serial_number = str(cert.serial_number)
        except Exception as e:
            logger.warning(f"Could not extract serial number from cert {cert_index} in {cert_path}: {e}")
            self.metrics.cert_analysis_errors.labels(error_type='extraction_error').inc()
            return None

        # Use the UTC-aware property where available, fall back to the naive
        # deprecated property for older cryptography library versions
        try:
            not_before = getattr(cert, 'not_valid_before_utc', None) or cert.not_valid_before
            not_after  = getattr(cert, 'not_valid_after_utc',  None) or cert.not_valid_after
            # Strip timezone info to keep datetime arithmetic consistent with
            # the rest of the codebase which uses datetime.utcnow()
            if not_before and not_before.tzinfo is not None:
                not_before = not_before.replace(tzinfo=None)
            if not_after and not_after.tzinfo is not None:
                not_after = not_after.replace(tzinfo=None)
        except Exception as e:
            logger.warning(f"Could not extract validity dates from cert {cert_index} in {cert_path}: {e}")
            self.metrics.cert_analysis_errors.labels(error_type='extraction_error').inc()
            return None

        try:
            common_name_attrs = cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )
            common_name = common_name_attrs[0].value if common_name_attrs else ""
        except Exception:
            common_name = ""

        san_dns_names = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            logger.debug(f"Error extracting SAN: {e}")

        # Compute SHA-256 of DER-encoded certificate when enabled.
        # Uses public_bytes() which is always available for a parsed cert object.
        checksum = ""
        if CERT_CHECKSUM_ENABLED:
            try:
                from cryptography.hazmat.primitives.serialization import Encoding
                der_bytes = cert.public_bytes(Encoding.DER)
                checksum = hashlib.sha256(der_bytes).hexdigest()
            except Exception as e:
                logger.debug(f"Could not compute checksum for cert {cert_index} in {cert_path}: {e}")

        return CertificateInfo(
            path=cert_path,
            subject=subject,
            issuer=issuer,
            serial_number=serial_number,
            not_before=not_before,
            not_after=not_after,
            process=process,
            pid=pid,
            namespace=namespace,
            common_name=common_name,
            san_dns_names=san_dns_names,
            cert_index=cert_index,
            checksum=checksum,
        )

    def analyze_certificate(
        self,
        cert_path: str,
        process: str,
        pid: int,
        namespace: str = ""
    ) -> List[CertificateInfo]:
        """Analyze a certificate file and return list of CertificateInfo (supports multi-cert files)"""

        try:
            certs = self.parse_certificates(cert_path)
        except Exception as e:
            logger.error(f"Unexpected error parsing certificates from {cert_path}: {e}",
                         exc_info=True)
            self.metrics.cert_analysis_errors.labels(error_type='parse_error').inc()
            return []

        if not certs:
            return []

        cert_infos = []
        for idx, cert in enumerate(certs):
            try:
                cert_info = self.extract_certificate_info(
                    cert, cert_path, process, pid, namespace, cert_index=idx
                )
                if cert_info is None:
                    # extract_certificate_info already logged and incremented
                    # the error metric — skip this cert and continue with others
                    continue
                cert_infos.append(cert_info)
                self.metrics.cert_events_total.labels(event_type='analysis', status='success').inc()
            except Exception as e:
                logger.error(f"Error extracting certificate info from {cert_path} (cert {idx}): {e}")
                self.metrics.cert_events_total.labels(event_type='analysis', status='failed').inc()
                self.metrics.cert_analysis_errors.labels(error_type='extraction_error').inc()

        self.processed_paths.add(cert_path)
        self._update_cache_metrics()
        return cert_infos

    def _apply_pod_context(self, cert_info: CertificateInfo, tetragon_pod):
        """
        Apply workload context to a CertificateInfo instance.

        Primary source: Tetragon event pod proto - provides pod name, namespace,
        workload kind/name, and pod labels with zero additional API calls.

        Secondary source: Kubernetes API enricher - supplements with fields
        Tetragon does not provide, specifically container name and container image.
        """
        # --- Primary: read directly from the Tetragon event proto ---
        if tetragon_pod is not None:
            cert_info.pod_name      = tetragon_pod.name
            cert_info.namespace     = tetragon_pod.namespace
            cert_info.workload_kind = tetragon_pod.workload_kind
            cert_info.workload_name = tetragon_pod.workload
            cert_info.pod_labels    = dict(tetragon_pod.pod_labels) if tetragon_pod.pod_labels else {}
            # Derive app_label from pod labels using common conventions
            for key in ["app.kubernetes.io/name", "app", "name"]:
                if key in cert_info.pod_labels:
                    cert_info.app_label = cert_info.pod_labels[key]
                    break
            logger.debug(
                f"Tetragon pod context: pod={cert_info.pod_name} "
                f"namespace={cert_info.namespace} "
                f"workload={cert_info.workload_kind}/{cert_info.workload_name} "
                f"labels={cert_info.pod_labels}"
            )

        # --- Secondary: Kubernetes API for fields Tetragon doesn't provide ---
        # Currently used for: container_name, container_image
        if self.enricher and self.enricher.available and cert_info.pod_name and cert_info.namespace:
            pod_ctx = self.enricher.enrich(cert_info.pod_name, cert_info.namespace)
            if pod_ctx:
                cert_info.container_name  = pod_ctx.container_name
                cert_info.container_image = pod_ctx.container_image
                logger.debug(
                    f"K8s enricher added: container={cert_info.container_name} "
                    f"image={cert_info.container_image}"
                )

    def log_certificate_status(self, info: CertificateInfo):
        """Log certificate status with appropriate severity"""
        days_left = info.days_until_expiry

        display_path = info.path
        if info.cert_index > 0:
            display_path = f"{info.path} [cert #{info.cert_index + 1}]"

        # Build workload context suffix for log lines
        k8s_ctx = ""
        if info.pod_name:
            k8s_ctx = (
                f" | pod={info.pod_name} namespace={info.namespace}"
                + (f" workload={info.workload}" if info.workload else "")
                + (f" container={info.container_name}" if info.container_name else "")
            )

        if info.is_expired:
            logger.error(
                f"🔴 EXPIRED: {display_path} "
                f"(process={info.process} CN={info.common_name}) "
                f"expired {abs(days_left):.1f} days ago"
                f"{k8s_ctx}"
            )
        elif days_left < 7:
            logger.critical(
                f"🔴 CRITICAL: {display_path} "
                f"(process={info.process} CN={info.common_name}) "
                f"expires in {days_left:.1f} days"
                f"{k8s_ctx}"
            )
        elif days_left < self.alert_threshold_days:
            logger.warning(
                f"⚠️  WARNING: {display_path} "
                f"(process={info.process} CN={info.common_name}) "
                f"expires in {days_left:.1f} days"
                f"{k8s_ctx}"
            )
        else:
            logger.info(
                f"✅ OK: {display_path} "
                f"(process={info.process} CN={info.common_name}) "
                f"valid for {days_left:.1f} more days"
                f"{k8s_ctx}"
            )

        logger.debug(f"   Subject: {info.subject}")
        logger.debug(f"   Issuer: {info.issuer}")
        logger.debug(f"   Serial: {info.serial_number}")
        if info.checksum:
            logger.debug(f"   SHA-256: {info.checksum}")
        logger.debug(
            f"   Valid: {info.not_before.strftime('%Y-%m-%d')} -> "
            f"{info.not_after.strftime('%Y-%m-%d')}"
        )
        if info.san_dns_names:
            logger.debug(f"   SAN DNS: {', '.join(info.san_dns_names[:5])}")
        if info.pod_name:
            logger.debug(f"   Pod: {info.namespace}/{info.pod_name}")
            logger.debug(f"   Workload: {info.workload}")
            logger.debug(f"   Container: {info.container_name} ({info.container_image})")

    def extract_cert_path_from_event(self, event) -> Tuple[Optional[str], str, int, str, object]:
        """
        Extract certificate path, process name, PID, namespace, and the raw
        Tetragon pod proto from a Tetragon event.

        Returns the pod proto object directly rather than individual string fields
        so that _apply_pod_context can read all available pod metadata (name,
        namespace, workload, labels) in one place without multiple return values.
        """
        cert_path    = None
        process_name = ""
        pid          = 0
        namespace    = ""
        tetragon_pod = None

        # Handle kprobe events
        if event.HasField('process_kprobe'):
            kprobe = event.process_kprobe
            process_name = kprobe.process.binary
            pid = kprobe.process.pid.value if kprobe.process.HasField('pid') else 0

            if kprobe.process.HasField('pod'):
                tetragon_pod = kprobe.process.pod
                namespace    = tetragon_pod.namespace

            for arg in kprobe.args:
                if arg.HasField('file_arg'):
                    path = arg.file_arg.path
                    if self.is_cert_path(path):
                        cert_path = path
                        logger.debug(f"Found cert path in file_arg: {cert_path}")
                        break
                elif arg.HasField('string_arg'):
                    path = arg.string_arg
                    if self.is_cert_path(path):
                        cert_path = path
                        logger.debug(f"Found cert path in string_arg: {cert_path}")
                        break

        # Handle uprobe events
        elif event.HasField('process_uprobe'):
            uprobe = event.process_uprobe
            process_name = uprobe.process.binary
            pid = uprobe.process.pid.value if uprobe.process.HasField('pid') else 0

            if uprobe.process.HasField('pod'):
                tetragon_pod = uprobe.process.pod
                namespace    = tetragon_pod.namespace

            for arg in uprobe.args:
                if arg.HasField('string_arg'):
                    path = arg.string_arg
                    if self.is_cert_path(path):
                        cert_path = path
                        logger.debug(f"Found cert path in uprobe string_arg: {cert_path}")
                        break

        # Translate host paths to container paths
        if cert_path and not cert_path.startswith("/host"):
            cert_path = "/host" + cert_path

        return cert_path, process_name, pid, namespace, tetragon_pod

    def process_event(self, event):
        """Process a single Tetragon event"""
        logger.debug("Processing event...")
        cert_path, process_name, pid, namespace, tetragon_pod = \
            self.extract_cert_path_from_event(event)
        pod_name = tetragon_pod.name if tetragon_pod is not None else ""
        logger.debug(f"Extracted: cert_path={cert_path}, process={process_name}, pid={pid}, pod={pod_name}")

        if not cert_path:
            return

        # Optionally skip events from the analyzer itself to avoid a feedback loop.
        # Set FILTER_SELF_EVENTS=false to disable this - useful for demos where the
        # cert-analyzer pod is itself the workload being observed.
        if self.filter_self_events:
            if process_name == "/app" or "cert-analyzer" in process_name or "cert_analyzer" in process_name:
                logger.debug(f"Skipping self-generated event from {process_name}")
                return

        logger.info(f"🔍 Detected certificate access: {cert_path} by {process_name} (PID: {pid})")

        # Update the event timestamp now — we have confirmed a cert-file access event
        # regardless of whether we can parse it. This keeps the readiness probe alive
        # even when all active keystores are password-protected and being skipped.
        self.metrics.last_event_timestamp.set(time.time())

        # Check if we've already analyzed this file
        if any(key.startswith(cert_path + ":") for key in self.known_certs.keys()):
            logger.info(f"Re-detected known certificate file: {cert_path}")
            matching_keys = [k for k in self.known_certs.keys()
                             if k.startswith(cert_path + ":")]
            for key in matching_keys:
                cert_info = self.known_certs[key]  # touches entry — moves to MRU end
                if tetragon_pod is not None and not cert_info.pod_name:
                    logger.debug(f"Applying pod context to cached entry for {cert_path}")
                    self._apply_pod_context(cert_info, tetragon_pod)
                self.log_certificate_status(cert_info)
                self.metrics.update_certificate_metrics(cert_info)
            return

        # Analyze new certificate file (may contain multiple certs)
        cert_infos = self.analyze_certificate(cert_path, process_name, pid, namespace)
        if not cert_infos:
            return

        logger.info(f"Found {len(cert_infos)} certificate(s) in {cert_path}")

        for cert_info in cert_infos:
            # Apply pod context: Tetragon event first, k8s API for extras
            self._apply_pod_context(cert_info, tetragon_pod)

            self.metrics.update_certificate_metrics(cert_info)
            self.log_certificate_status(cert_info)
            self.known_certs[cert_info.unique_key] = cert_info

        self._update_cache_metrics()

    def get_runtime_tetragon_version(self, stub) -> str:
        """
        Query the running Tetragon daemon for its version via GetVersion RPC.

        Returns the version string (e.g. 'v1.1.0') on success, or 'unknown'
        if the call fails or the version field is absent. Failures are logged
        as warnings and never propagate — a version mismatch should alert but
        must never prevent the analyzer from starting.
        """
        try:
            response = stub.GetVersion(
                tetragon_pb2.GetVersionRequest(),
                timeout=5.0,
            )
            version = getattr(response, 'version', '').strip()
            return version if version else 'unknown'
        except Exception as e:
            logger.warning(f"Could not retrieve runtime Tetragon version: {e}")
            return 'unknown'

    def check_tetragon_version(self, stub) -> None:
        """
        Compare the build-time and runtime Tetragon versions, update Prometheus
        metrics, and log a clear warning if they differ.

        Called once at startup after the gRPC channel is established.
        """
        runtime_version = self.get_runtime_tetragon_version(stub)
        build_version   = TETRAGON_BUILD_VERSION

        self.metrics.tetragon_version_info.info({
            'build_version':   build_version,
            'runtime_version': runtime_version,
        })

        versions_match = (
            build_version   != 'unknown'
            and runtime_version != 'unknown'
            and build_version   == runtime_version
        )
        self.metrics.tetragon_version_match.set(1 if versions_match else 0)

        if build_version == 'unknown' or runtime_version == 'unknown':
            logger.warning(
                f"Tetragon version check incomplete — "
                f"build: {build_version}, runtime: {runtime_version}"
            )
        elif versions_match:
            logger.info(
                f"Tetragon version OK — build and runtime both at {build_version}"
            )
        else:
            logger.warning(
                f"⚠️  Tetragon version MISMATCH — "
                f"built against {build_version}, runtime is {runtime_version}. "
                f"Proto incompatibilities may cause silent failures. "
                f"Rebuild the cert-analyzer image against {runtime_version}."
            )

    def _start_version_monitor(self, stub) -> None:
        """
        Start a background daemon thread that periodically re-checks the
        runtime Tetragon version and updates Prometheus metrics.

        This detects Tetragon upgrades or downgrades that occur while the
        analyzer is running without requiring an analyzer restart.

        Interval is configurable via TETRAGON_VERSION_CHECK_INTERVAL env var
        (default: 300 seconds / 5 minutes).
        """
        interval = int(os.getenv('TETRAGON_VERSION_CHECK_INTERVAL', '300'))

        def _monitor():
            while True:
                time.sleep(interval)
                try:
                    self.check_tetragon_version(stub)
                except Exception as e:
                    logger.warning(f"Version monitor error: {e}")

        thread = threading.Thread(target=_monitor, daemon=True)
        thread.name = 'tetragon-version-monitor'
        thread.start()
        logger.info(f"Started Tetragon version monitor (interval: {interval}s)")

    def start(self):
        """
        Start listening to Tetragon events with automatic reconnection.

        Establishes the gRPC channel once and re-issues GetEvents after any
        stream failure, using exponential backoff. This handles Tetragon
        restarts and upgrades transparently.

        The version monitor thread is started once and reuses the same channel —
        gRPC handles transport reconnection automatically so the stub remains
        valid across Tetragon restarts.
        """
        logger.info(f"Connecting to Tetragon at {self.tetragon_address}")

        if self.tetragon_address.startswith('unix://'):
            socket_path = self.tetragon_address[7:]
            channel = grpc.insecure_channel(f'unix:{socket_path}')
        else:
            channel = grpc.insecure_channel(self.tetragon_address)

        stub = sensors_pb2_grpc.FineGuidanceSensorsStub(channel)

        # Give the health server a reference to the channel so liveness
        # checks can inspect its connectivity state
        if self.health_server:
            self.health_server.set_channel(channel)

        # Version check on startup, then periodically in background
        self.check_tetragon_version(stub)
        self._start_version_monitor(stub)

        request = events_pb2.GetEventsRequest(
            allow_list=[
                events_pb2.Filter(
                    event_set=[
                        events_pb2.PROCESS_KPROBE,
                        events_pb2.PROCESS_UPROBE,
                    ]
                )
            ]
        )

        retry_delay = 5
        max_delay   = 60

        try:
            while True:
                try:
                    logger.info("Listening for Tetragon certificate events...")
                    self.metrics.analyzer_healthy.set(1)

                    for response in stub.GetEvents(request):
                        try:
                            self.process_event(response)
                        except Exception as e:
                            logger.error(f"Error processing event: {e}", exc_info=True)
                            self.metrics.cert_events_total.labels(
                                event_type='processing', status='error'
                            ).inc()

                    # Stream ended without error — Tetragon closed it cleanly
                    logger.warning("Tetragon event stream ended, reconnecting...")
                    retry_delay = 5

                except grpc.RpcError as e:
                    self.metrics.analyzer_healthy.set(0)
                    logger.warning(
                        f"Tetragon connection lost ({e.code().name}), "
                        f"retrying in {retry_delay}s..."
                    )
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, max_delay)

                except Exception as e:
                    self.metrics.analyzer_healthy.set(0)
                    logger.error(
                        f"Unexpected error in event stream: {e} — "
                        f"retrying in {retry_delay}s",
                        exc_info=True,
                    )
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, max_delay)

        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.metrics.analyzer_healthy.set(0)
        finally:
            channel.close()

    def periodic_scan(self, paths: list):
        """Periodically scan certificate directories for proactive monitoring"""
        logger.info(f"Starting periodic scan of {len(paths)} paths")

        for base_path in paths:
            try:
                path_obj = Path(base_path)
                if not path_obj.exists():
                    logger.debug(f"Path does not exist: {base_path}")
                    continue

                cert_count = 0
                for cert_file in path_obj.rglob('*'):
                    if cert_file.is_file() and self.is_cert_path(str(cert_file)):
                        cert_infos = self.analyze_certificate(
                            str(cert_file),
                            "periodic_scan",
                            0
                        )
                        for cert_info in cert_infos:
                            self.metrics.update_certificate_metrics(cert_info)
                            self.log_certificate_status(cert_info)
                            self.known_certs[cert_info.unique_key] = cert_info
                            cert_count += 1

                logger.info(f"Scanned {cert_count} certificates in {base_path}")

            except Exception as e:
                logger.error(f"Error scanning {base_path}: {e}")


def main():
    """Main entry point"""
    tetragon_addr    = os.getenv('TETRAGON_ADDR', 'localhost:54321')
    metrics_port     = int(os.getenv('METRICS_PORT', '9090'))
    health_port      = int(os.getenv('HEALTH_PORT', '8086'))
    alert_threshold  = int(os.getenv('ALERT_THRESHOLD_DAYS', '30'))
    log_level        = os.getenv('LOG_LEVEL', 'INFO')
    scan_paths_str   = os.getenv('CERT_SCAN_PATHS', '/etc/ssl,/etc/pki')
    scan_paths       = [p.strip() for p in scan_paths_str.split(',') if p.strip()]
    scan_interval    = int(os.getenv('SCAN_INTERVAL_SECONDS', '3600'))
    grace_period     = int(os.getenv('READINESS_GRACE_PERIOD_SECONDS', '60'))
    staleness        = int(os.getenv('READINESS_STALENESS_SECONDS', '300'))
    # Set to 'false' to allow the cert-analyzer to observe its own certificate
    # accesses - useful for demos showing self-pod enrichment
    filter_self      = os.getenv('FILTER_SELF_EVENTS', 'true').lower() != 'false'

    logging.getLogger().setLevel(getattr(logging, log_level.upper()))

    logger.info("="*60)
    logger.info("TLS Certificate Expiry Monitor (Multi-Cert + K8s Enrichment)")
    logger.info("="*60)
    logger.info(f"Version:           {CERT_ANALYZER_VERSION}")
    logger.info(f"Tetragon address:  {tetragon_addr}")
    logger.info(f"Tetragon build:    {TETRAGON_BUILD_VERSION}")
    logger.info(f"Cache max size:    {CACHE_MAX_SIZE}")
    logger.info(f"Cert checksums:    {'enabled' if CERT_CHECKSUM_ENABLED else 'disabled'}")
    logger.info(f"Metrics port:      {metrics_port}")
    logger.info(f"Health port:       {health_port}")
    logger.info(f"Alert threshold:   {alert_threshold} days")
    logger.info(f"Scan paths:        {scan_paths}")
    logger.info(f"Scan interval:     {scan_interval} seconds")
    logger.info(f"Filter self events: {filter_self}")
    logger.info("="*60)

    logger.info(f"Starting Prometheus metrics server on port {metrics_port}")
    start_http_server(metrics_port)

    # HealthServer.is_ready() reads analyzer.metrics.last_event_timestamp, so
    # it needs the analyzer reference. CertificateAnalyzer.start() calls
    # health_server.set_channel() once the gRPC channel is established.
    # Break the circular dependency by constructing the analyzer first, then
    # passing it to HealthServer, then wiring the health server back in.
    analyzer = CertificateAnalyzer(tetragon_addr, alert_threshold,
                                   filter_self_events=filter_self)

    health = HealthServer(
        analyzer=analyzer,
        port=health_port,
        grace_period_seconds=grace_period,
        staleness_seconds=staleness,
    )
    health.start()

    analyzer.health_server = health

    if scan_paths and scan_paths[0]:
        def periodic_scanner():
            while True:
                try:
                    analyzer.periodic_scan(scan_paths)
                except Exception as e:
                    logger.error(f"Error in periodic scan: {e}")
                time.sleep(scan_interval)

        scanner_thread = threading.Thread(target=periodic_scanner, daemon=True)
        scanner_thread.start()
        logger.info(f"Started periodic scanner (interval: {scan_interval}s)")

    try:
        analyzer.start()
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down...")
        health.stop()
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        health.stop()
        sys.exit(1)


if __name__ == '__main__':
    main()