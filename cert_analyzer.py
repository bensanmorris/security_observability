#!/usr/bin/env python3
"""
TLS Certificate Expiry Monitor for RHEL9/Podman
Consumes Tetragon events and analyzes certificate expiry dates
EXTENDED: Now supports multiple certificates per file
"""

import os
import sys
import json
import logging
import grpc
import socket
import ssl
import struct
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
import configparser
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from prometheus_client import Gauge, Counter, Info, start_http_server
from fips_compliance_checker import check_certificate as _fips_check, FipsComplianceResult

# Import generated Tetragon protos
try:
    from tetragon import tetragon_pb2, events_pb2, sensors_pb2, sensors_pb2_grpc
except ImportError:
    print("ERROR: Tetragon protobuf files not found. Run generate_tetragon_protos.sh first")
    sys.exit(1)

# Import JKS parser - optional, degrades gracefully if unavailable
# Install with: pip install pyjks
try:
    import jks
    JKS_AVAILABLE = True
except ImportError:
    JKS_AVAILABLE = False

# Import Kafka producer - optional, degrades gracefully if unavailable.
# When disabled (default) the analyzer publishes to Prometheus only.
# Enable via [kafka] enabled = true in cert-analyzer.conf or KAFKA_ENABLED=true.
# Install with: pip install kafka-python
KafkaProducer = None  # always defined so patch('cert_analyzer.KafkaProducer') works
KafkaError = None     # regardless of whether kafka-python is installed
try:
    from kafka import KafkaProducer
    from kafka.errors import KafkaError
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

# The Tetragon version this build was compiled against.
# Must be kept in lockstep with the version used in the Containerfile build arg.
# Set by the CI build process via the TETRAGON_BUILD_VERSION environment variable
# which is injected at image build time; falls back to 'unknown' if not set.
TETRAGON_BUILD_VERSION: str = os.getenv('TETRAGON_BUILD_VERSION', 'unknown')

# The cert-analyzer version — set at image build time from the git tag or
# commit SHA via the VERSION build arg in the Containerfile.
# Falls back to 'dev' when running outside of a built container.
CERT_ANALYZER_VERSION: str = os.getenv('CERT_ANALYZER_VERSION', 'dev')

# Map TracingPolicyState enum integers to clean label strings.
# Prefix TP_STATE_ is stripped and the remainder lowercased (e.g. TP_STATE_LOAD_ERROR → load_error).
_POLICY_STATE_NAMES: Dict[int, str] = {
    0: 'unknown',
    1: 'enabled',
    2: 'disabled',
    3: 'load_error',
    4: 'error',
    5: 'loading',
    6: 'unloading',
}

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Friendly names for the most common Extended Key Usage OIDs (RFC 5280 §4.2.1.12).
# Unknown OIDs fall back to their dotted-string representation.
_EKU_NAMES = {
    '1.3.6.1.5.5.7.3.1': 'server_auth',
    '1.3.6.1.5.5.7.3.2': 'client_auth',
    '1.3.6.1.5.5.7.3.3': 'code_signing',
    '1.3.6.1.5.5.7.3.4': 'email_protection',
    '1.3.6.1.5.5.7.3.8': 'time_stamping',
    '1.3.6.1.5.5.7.3.9': 'ocsp_signing',
}


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
    san_ip_addresses: list = field(default_factory=list)
    cert_index: int = 0
    # Kubernetes context sourced directly from the Tetragon event Pod proto
    pod_name: str = ""
    pod_uid: str = ""
    pod_labels: dict = None
    pod_annotations: dict = None
    workload_kind: str = ""
    workload_name: str = ""
    node_name: str = ""
    app_label: str = ""                      # derived from pod_labels
    container_id: str = ""
    container_name: str = ""
    container_image: str = ""
    container_image_id: str = ""
    container_privileged: bool = False
    container_pid: Optional[int] = None
    container_start_time: Optional[datetime] = None
    container_maybe_exec_probe: bool = False
    # Spawning process — binary path and PID of the process that launched
    # the cert loader. Empty when Tetragon's process cache didn't have the
    # parent at event time (common at startup).
    parent_process: str = ""
    parent_pid: int = 0
    # SHA-256 of the DER-encoded certificate bytes. Empty string when
    # CERT_CHECKSUM_ENABLED=false (the default).
    checksum: str = ""
    # FIPS 140-2/140-3 compliance fields — populated by extract_certificate_info()
    key_algorithm: str = ""    # RSA, EC, DSA, Ed25519, Ed448, unknown
    key_size: int = 0          # bits; 0 for EdDSA
    signature_hash: str = ""   # sha256, sha1, md5, etc.
    curve_name: str = ""       # secp256r1 etc. (EC only)
    fips_compliant: bool = False
    fips_violations: list = field(default_factory=list)
    # RFC 5280 extension fields — None means the extension is absent from the certificate
    key_usage: Optional[list] = None
    extended_key_usage: Optional[list] = None
    is_ca: Optional[bool] = None
    basic_constraints_path_length: Optional[int] = None
    # True when the certificate is self-signed (subject == issuer and signature
    # verifies against its own public key). Root CA certificates are legitimately
    # self-signed; self-signed leaf certificates are typically a configuration risk.
    is_self_signed: bool = False

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
             'san_dns_names', 'san_ip_addresses',
             'cert_index', 'pod_name', 'namespace', 'workload_kind', 'workload_name',
             'node_name', 'app_label', 'container_name', 'checksum', 'parent_process']
        )

        self.cert_expiry_timestamp = Gauge(
            'tls_certificate_expiry_timestamp',
            'Unix timestamp of certificate expiry',
            ['cert_path', 'subject', 'issuer', 'serial', 'process', 'common_name',
             'san_dns_names', 'san_ip_addresses',
             'cert_index', 'pod_name', 'namespace', 'workload_kind', 'workload_name',
             'node_name', 'app_label', 'container_name', 'checksum', 'parent_process']
        )

        self.cert_valid_from = Gauge(
            'tls_certificate_valid_from_timestamp',
            'Unix timestamp of certificate valid from date',
            ['cert_path', 'subject', 'issuer', 'serial', 'process', 'common_name',
             'san_dns_names', 'san_ip_addresses',
             'cert_index', 'pod_name', 'namespace', 'workload_kind', 'workload_name',
             'node_name', 'app_label', 'container_name', 'checksum', 'parent_process']
        )

        self.cert_last_accessed = Gauge(
            'tls_certificate_last_accessed_timestamp',
            'Unix timestamp of the most recent certificate access event',
            ['cert_path', 'subject', 'issuer', 'serial', 'process', 'common_name',
             'san_dns_names', 'san_ip_addresses',
             'cert_index', 'pod_name', 'namespace', 'workload_kind', 'workload_name',
             'node_name', 'app_label', 'container_name', 'checksum', 'parent_process']
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
             'workload_kind', 'workload_name', 'node_name']
        )

        self.cert_expiring_soon = Gauge(
            'tls_certificate_expiring_soon',
            'Whether certificate expires within threshold (1=yes, 0=no)',
            ['cert_path', 'process', 'threshold_days', 'cert_index', 'pod_name',
             'namespace', 'workload_kind', 'workload_name', 'node_name']
        )

        self.cert_fips_compliant = Gauge(
            'tls_certificate_fips_compliant',
            'Whether certificate uses FIPS-approved algorithms (1=compliant, 0=non-compliant)',
            ['cert_path', 'process', 'cert_index', 'pod_name', 'namespace',
             'workload_kind', 'workload_name', 'node_name', 'key_algorithm', 'signature_hash']
        )

        self.cert_self_signed = Gauge(
            'tls_certificate_self_signed',
            'Whether the certificate is self-signed (1=self-signed, 0=CA-signed)',
            ['cert_path', 'process', 'cert_index', 'pod_name', 'namespace',
             'workload_kind', 'workload_name', 'node_name', 'is_ca']
        )

        # System health
        self.analyzer_healthy = Gauge(
            'cert_analyzer_healthy',
            'Health status of the analyzer (1=healthy, 0=unhealthy)'
        )
        self.analyzer_healthy.set(1)

        self.tetragon_connected = Gauge(
            'tetragon_connected',
            'Whether the analyzer has an active gRPC event stream to Tetragon (1=connected, 0=disconnected)',
        )
        self.tetragon_connected.set(0)

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

        self.tls_port_probes_total = Counter(
            'tls_port_probes_total',
            'Total number of TLS port probe attempts triggered by bind events',
            ['status'],  # success, failed, skipped
        )

        # Tetragon policy tracking
        self.tetragon_policy_info = Gauge(
            'tetragon_policy_info',
            'Tetragon tracing policies and their current state (1=present)',
            ['name', 'namespace', 'state'],
        )
        self.tetragon_policies_total = Gauge(
            'tetragon_policies_total',
            'Number of Tetragon tracing policies by state',
            ['state'],
        )

    def update_certificate_metrics(self, info: CertificateInfo):
        """Update Prometheus metrics for a certificate"""
        labels = {
            'cert_path':        info.path,
            'subject':          info.subject[:100],
            'issuer':           info.issuer[:100],
            'serial':           info.serial_number,
            'process':          info.process,
            'common_name':      info.common_name,
            'san_dns_names':    ','.join(info.san_dns_names),
            'san_ip_addresses': ','.join(info.san_ip_addresses),
            'cert_index':       str(info.cert_index),
            'pod_name':         info.pod_name,
            'namespace':        info.namespace,
            'workload_kind':    info.workload_kind,
            'workload_name':    info.workload_name,
            'node_name':        info.node_name,
            'app_label':        info.app_label,
            'container_name':   info.container_name,
            # Empty string when CERT_CHECKSUM_ENABLED=false — Prometheus
            # handles empty label values cleanly and the label is simply
            # omitted from query results when filtering
            'checksum':         info.checksum,
            # Empty string when Tetragon's process cache didn't have the
            # parent at event time
            'parent_process':   info.parent_process,
        }

        self.cert_expiry_days.labels(**labels).set(info.days_until_expiry)
        self.cert_expiry_timestamp.labels(**labels).set(info.not_after.timestamp())
        self.cert_valid_from.labels(**labels).set(info.not_before.timestamp())
        self.cert_last_accessed.labels(**labels).set(datetime.utcnow().timestamp())

        self.cert_expired.labels(
            cert_path=info.path,
            process=info.process,
            cert_index=str(info.cert_index),
            pod_name=info.pod_name,
            namespace=info.namespace,
            workload_kind=info.workload_kind,
            workload_name=info.workload_name,
            node_name=info.node_name,
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
                node_name=info.node_name,
            ).set(1 if 0 < info.days_until_expiry < threshold else 0)

        if info.key_algorithm:
            self.cert_fips_compliant.labels(
                cert_path=info.path,
                process=info.process,
                cert_index=str(info.cert_index),
                pod_name=info.pod_name,
                namespace=info.namespace,
                workload_kind=info.workload_kind,
                workload_name=info.workload_name,
                node_name=info.node_name,
                key_algorithm=info.key_algorithm,
                signature_hash=info.signature_hash,
            ).set(1 if info.fips_compliant else 0)

        self.cert_self_signed.labels(
            cert_path=info.path,
            process=info.process,
            cert_index=str(info.cert_index),
            pod_name=info.pod_name,
            namespace=info.namespace,
            workload_kind=info.workload_kind,
            workload_name=info.workload_name,
            node_name=info.node_name,
            is_ca='true' if info.is_ca else ('false' if info.is_ca is False else 'unknown'),
        ).set(1 if info.is_self_signed else 0)




_kafka_delivery_errors = Counter(
    'kafka_delivery_errors_total',
    'Total number of Kafka message delivery failures (async, broker-side)',
)


class KafkaPublisher:
    """
    Optional Kafka publisher for new certificate discovery events.

    Publishes a JSON message to a configurable topic each time a certificate
    is seen for the first time. Re-detected known certificates are not
    published — Prometheus handles ongoing state; Kafka handles the event
    stream of new discoveries.

    The publisher is a no-op when Kafka is disabled or unavailable. All
    errors are logged as warnings and never propagate — a broker outage must
    never prevent the analyzer from continuing to work with Prometheus only.

    Message schema (all fields present, empty string when not applicable):
    {
        "event_type":       "certificate_discovered",
        "detected_at":      "2026-03-31T10:00:00.000000",   # ISO 8601 UTC
        "path":             "/etc/pki/tls/certs/ca-bundle.crt",
        "cert_index":       0,
        "subject":          "CN=...",
        "issuer":           "CN=...",
        "serial_number":    "abc123",
        "common_name":      "example.com",
        "san_dns_names":    ["example.com", "www.example.com"],
        "san_ip_addresses": ["10.96.0.1", "192.168.1.1"],
        "not_before":       "2024-01-01T00:00:00",
        "not_after":        "2025-01-01T00:00:00",
        "days_until_expiry": 44.9,
        "is_expired":       false,
        "process":          "/usr/bin/curl",
        "pid":              12345,
        "namespace":        "default",
        "pod_name":         "my-pod-abc",
        "workload_kind":    "Deployment",
        "workload_name":    "my-app",
        "app_label":        "my-app",
        "container_name":   "main",
        "container_image":  "my-app:1.0",
        "checksum":         "",
        "key_algorithm":    "RSA",
        "key_size":         2048,
        "signature_hash":   "sha256",
        "curve_name":       "",
        "fips_compliant":   true,
        "fips_violations":  [],
        "key_usage":                     ["digital_signature", "key_encipherment"],
        "extended_key_usage":            ["server_auth", "client_auth"],
        "is_ca":                         false,
        "basic_constraints_path_length": null,
        "is_self_signed":                false
    }
    """

    def __init__(
        self,
        bootstrap_servers: str,
        topic: str,
        security_protocol: str = 'PLAINTEXT',
        sasl_mechanism: str = '',
        sasl_username: str = '',
        sasl_password: str = '',
    ):
        self._topic = topic
        self._producer: Optional['KafkaProducer'] = None
        self._producer_kwargs: dict = {}
        self._last_connect_attempt: float = 0.0
        self._reconnect_cooldown: float = 30.0  # seconds between reconnect attempts

        if not KAFKA_AVAILABLE:
            logger.warning(
                "kafka-python is not installed — Kafka publishing disabled. "
                "Install with: pip install kafka-python"
            )
            return

        self._producer_kwargs = {
            'bootstrap_servers': [s.strip() for s in bootstrap_servers.split(',')],
            'value_serializer':  lambda v: json.dumps(v).encode('utf-8'),
            'key_serializer':    lambda k: k.encode('utf-8') if k else None,
            'acks':              'all',
            'retries':           3,
            'retry_backoff_ms':  200,
        }

        if security_protocol and security_protocol != 'PLAINTEXT':
            self._producer_kwargs['security_protocol'] = security_protocol

        if sasl_mechanism:
            self._producer_kwargs['sasl_mechanism']         = sasl_mechanism
            self._producer_kwargs['sasl_plain_username']    = sasl_username
            self._producer_kwargs['sasl_plain_password']    = sasl_password

        self._connect(bootstrap_servers, topic)

    def _connect(self, bootstrap_servers: str = '', topic: str = '') -> bool:
        """
        Attempt to create a KafkaProducer. Returns True on success.
        Respects a cooldown period to avoid hammering a down broker.
        """
        now = time.time()
        if now - self._last_connect_attempt < self._reconnect_cooldown:
            return False
        self._last_connect_attempt = now

        # Close any existing broken producer before reconnecting
        if self._producer is not None:
            try:
                self._producer.close(timeout=2)
            except Exception:
                pass
            self._producer = None

        try:
            self._producer = KafkaProducer(**self._producer_kwargs)
            label = bootstrap_servers or str(self._producer_kwargs.get('bootstrap_servers', ''))
            label_topic = topic or self._topic
            logger.info(
                f"Kafka producer connected — "
                f"brokers: {label}, topic: {label_topic}"
            )
            return True
        except Exception as e:
            logger.warning(
                f"Kafka producer connection failed (will retry in "
                f"{int(self._reconnect_cooldown)}s): {e}"
            )
            return False

    def publish(self, cert_info: 'CertificateInfo') -> None:
        """
        Publish a new certificate discovery event.

        Delivery is asynchronous — the producer's internal send queue handles
        batching and retries. If the producer is unavailable (e.g. broker
        restarted) a reconnect is attempted subject to a cooldown period.
        Errors are always logged as warnings and never raised.
        """
        if not KAFKA_AVAILABLE:
            return

        # Attempt reconnection if producer is absent
        if self._producer is None:
            if not self._connect():
                return

        message = {
            'event_type':        'certificate_discovered',
            'detected_at':       datetime.utcnow().isoformat(),
            'path':              cert_info.path,
            'cert_index':        cert_info.cert_index,
            'subject':           cert_info.subject,
            'issuer':            cert_info.issuer,
            'serial_number':     cert_info.serial_number,
            'common_name':       cert_info.common_name,
            'san_dns_names':     cert_info.san_dns_names,
            'san_ip_addresses':  cert_info.san_ip_addresses,
            'not_before':        cert_info.not_before.isoformat(),
            'not_after':         cert_info.not_after.isoformat(),
            'days_until_expiry': round(cert_info.days_until_expiry, 2),
            'is_expired':        cert_info.is_expired,
            'process':           cert_info.process,
            'pid':               cert_info.pid,
            'parent_process':    cert_info.parent_process,
            'parent_pid':        cert_info.parent_pid,
            'namespace':                  cert_info.namespace,
            'pod_name':                   cert_info.pod_name,
            'pod_uid':                    cert_info.pod_uid,
            'node_name':                  cert_info.node_name,
            'pod_annotations':            cert_info.pod_annotations,
            'workload_kind':              cert_info.workload_kind,
            'workload_name':              cert_info.workload_name,
            'app_label':                  cert_info.app_label,
            'container_id':               cert_info.container_id,
            'container_name':             cert_info.container_name,
            'container_image':            cert_info.container_image,
            'container_image_id':         cert_info.container_image_id,
            'container_privileged':       cert_info.container_privileged,
            'container_pid':              cert_info.container_pid,
            'container_start_time':       cert_info.container_start_time.isoformat() if cert_info.container_start_time else None,
            'container_maybe_exec_probe': cert_info.container_maybe_exec_probe,
            'checksum':          cert_info.checksum,
            'key_algorithm':     cert_info.key_algorithm,
            'key_size':          cert_info.key_size,
            'signature_hash':    cert_info.signature_hash,
            'curve_name':        cert_info.curve_name,
            'fips_compliant':    cert_info.fips_compliant,
            'fips_violations':   cert_info.fips_violations,
            'key_usage':                     cert_info.key_usage,
            'extended_key_usage':            cert_info.extended_key_usage,
            'is_ca':                         cert_info.is_ca,
            'basic_constraints_path_length': cert_info.basic_constraints_path_length,
            'is_self_signed':                cert_info.is_self_signed,
        }

        # Use unique_key (path:cert_index:serial) as the partition key.
        # This matches the internal cache key used by known_certs and gives
        # consumers a stable, cryptographically-scoped identifier that survives
        # cert rotation at the same path. All events for the same certificate
        # (same path, index, and serial) land on the same partition for ordered
        # consumption, while a rotated cert at the same path gets a new key.
        key = cert_info.unique_key

        try:
            self._producer.send(
                self._topic,
                key=key,
                value=message,
            ).add_errback(self._on_error)
        except Exception as e:
            logger.warning(f"Kafka publish failed for {cert_info.path}: {e}")
            # Nullify the producer so the next publish attempt triggers reconnect
            self._producer = None

    def _on_error(self, exc: Exception) -> None:
        logger.warning(f"Kafka delivery error: {exc}")
        _kafka_delivery_errors.inc()
        # Nullify the producer so the next publish attempt triggers reconnect.
        # Without this, a broker that drops messages in-flight (broker down,
        # auth failure, topic deleted) would leave the producer in a state where
        # send() appears to succeed but nothing is ever delivered.
        self._producer = None

    def close(self) -> None:
        """Flush pending messages and close the producer cleanly."""
        if self._producer is not None:
            try:
                self._producer.flush(timeout=5)
                self._producer.close()
            except Exception as e:
                logger.warning(f"Error closing Kafka producer: {e}")


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


class CertificateAnalyzer:
    """Main analyzer that processes Tetragon events and extracts certificate info"""

    CERT_EXTENSIONS  = {'.crt', '.pem', '.cert', '.cer', '.key'}
    JKS_EXTENSIONS   = {'.jks', '.keystore', '.truststore'}
    PKCS12_EXTENSIONS = {'.p12', '.pfx'}
    # Destination ports considered TLS for outbound connect probing.
    # These are checked in _handle_tls_connect_event as a Python-side guard
    # complementing the DPort filter in the tcp-connect-tls Tetragon policy.
    # Built-in default TLS port list — used when tls_outbound_ports is not
    # configured. Must be kept in sync with the DPort filter in
    # tetragon-policies/tcp-connect-tls.yaml (Tetragon filters first; this is
    # a Python-side guard for events that pass the kernel filter).
    TLS_OUTBOUND_PORTS = frozenset({
        443,   # HTTPS
        636,   # LDAPS
        5671,  # AMQP/TLS
        5672,  # AMQP (often TLS)
        6380,  # Redis TLS
        8443,  # HTTPS alternate
        8883,  # MQTT/TLS
        9093,  # Kafka TLS
        9094,  # Kafka TLS alternate
    })

    def __init__(self, tetragon_address: str, alert_threshold_days: int = 30,
                 filter_self_events: bool = True,
                 health_server: Optional['HealthServer'] = None,
                 host_prefix: str = '',
                 kafka_publisher: Optional['KafkaPublisher'] = None,
                 checksum_enabled: bool = False,
                 demo_mode: bool = False,
                 fips_compliance_enabled: bool = True,
                 bind_probe_enabled: bool = False,
                 connect_probe_enabled: bool = False,
                 port_probe_timeout: float = 5.0,
                 port_probe_connect_delay: float = 2.0,
                 tls_outbound_ports: Optional[frozenset] = None):
        self.tetragon_address = tetragon_address
        self.alert_threshold_days = alert_threshold_days
        self.filter_self_events = filter_self_events
        self.host_prefix = host_prefix
        self.kafka_publisher = kafka_publisher
        self.checksum_enabled = checksum_enabled
        self.demo_mode = demo_mode
        self.fips_compliance_enabled = fips_compliance_enabled
        self._bind_probe_enabled = bind_probe_enabled
        self._connect_probe_enabled = connect_probe_enabled
        self._port_probe_timeout = port_probe_timeout
        self._port_probe_connect_delay = port_probe_connect_delay
        self._tls_outbound_ports = tls_outbound_ports if tls_outbound_ports is not None else self.TLS_OUTBOUND_PORTS
        self.metrics = PrometheusMetrics()
        self.known_certs: LRUCache = LRUCache()
        self.processed_paths: LRUCache = LRUCache()
        # Paths that failed password attempts — cached to avoid repeating expensive
        # crypto operations on every subsequent Tetragon event for the same file.
        # LRU eviction gives previously-failed paths a second chance after enough
        # other activity, which is desirable if JKS_PASSWORD has since been set.
        self.password_failed_paths: LRUCache = LRUCache()
        self.health_server = health_server
        self._known_policy_labels: Set[Tuple[str, str, str]] = set()
        # Per-endpoint deduplication for TLS port probes.
        # _probed_endpoints: "host:port" strings already probed — O(1) pre-check
        #   prevents thread creation for endpoints whose cert is already known.
        # _probe_in_flight: "host:port" strings currently being probed — prevents
        #   duplicate concurrent probes when several events for a new endpoint
        #   arrive before the first probe completes (e.g. connection pooling).
        # CPython set operations (in / add / discard) are GIL-atomic; no lock needed.
        self._probed_endpoints: Set[str] = set()
        self._probe_in_flight: Set[str] = set()

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
        san_ip_addresses = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_dns_names = san_ext.value.get_values_for_type(x509.DNSName)
            san_ip_addresses = [
                str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)
            ]
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            logger.debug(f"Error extracting SAN: {e}")

        key_usage = None
        try:
            ku_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.KEY_USAGE
            )
            ku = ku_ext.value
            flags = [
                'digital_signature', 'content_commitment', 'key_encipherment',
                'data_encipherment', 'key_agreement', 'key_cert_sign', 'crl_sign',
            ]
            key_usage = [f for f in flags if getattr(ku, f)]
            if ku.key_agreement:
                if ku.encipher_only:
                    key_usage.append('encipher_only')
                if ku.decipher_only:
                    key_usage.append('decipher_only')
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            logger.debug(f"Error extracting Key Usage: {e}")

        extended_key_usage = None
        try:
            eku_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
            )
            extended_key_usage = [
                _EKU_NAMES.get(oid.dotted_string, oid.dotted_string)
                for oid in eku_ext.value
            ]
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            logger.debug(f"Error extracting Extended Key Usage: {e}")

        is_ca = None
        basic_constraints_path_length = None
        try:
            bc_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            )
            is_ca = bc_ext.value.ca
            basic_constraints_path_length = bc_ext.value.path_length
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            logger.debug(f"Error extracting Basic Constraints: {e}")

        # A certificate is self-signed when its subject name matches its issuer
        # and the signature verifies against its own public key.
        # verify_directly_issued_by() (cryptography ≥40) performs both checks atomically;
        # on older versions (e.g. RHEL8 ships 3.2.1) fall back to name-match heuristic.
        is_self_signed = False
        try:
            cert.verify_directly_issued_by(cert)
            is_self_signed = True
        except AttributeError:
            # cryptography < 40: Name.__eq__ does proper attribute-set comparison.
            is_self_signed = cert.subject == cert.issuer
        except Exception:
            pass

        # Compute SHA-256 of DER-encoded certificate when enabled.
        # Uses public_bytes() which is always available for a parsed cert object.
        checksum = ""
        if self.checksum_enabled:
            try:
                from cryptography.hazmat.primitives.serialization import Encoding
                der_bytes = cert.public_bytes(Encoding.DER)
                checksum = hashlib.sha256(der_bytes).hexdigest()
            except Exception as e:
                logger.debug(f"Could not compute checksum for cert {cert_index} in {cert_path}: {e}")

        fips_result = None
        if self.fips_compliance_enabled:
            try:
                pub_key = cert.public_key()
            except Exception:
                pub_key = None
            try:
                fips_result = _fips_check(cert, pub_key=pub_key)
            except Exception as e:
                logger.debug(f"FIPS check failed for cert {cert_index} in {cert_path}: {e}")
                fips_result = FipsComplianceResult(
                    compliant=False, key_algorithm='unknown', key_size=0,
                    curve_name='', signature_hash='unknown',
                    violations=['FIPS check error'],
                )

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
            san_ip_addresses=san_ip_addresses,
            cert_index=cert_index,
            checksum=checksum,
            key_algorithm=fips_result.key_algorithm if fips_result is not None else '',
            key_size=fips_result.key_size if fips_result is not None else 0,
            signature_hash=fips_result.signature_hash if fips_result is not None else '',
            curve_name=fips_result.curve_name if fips_result is not None else '',
            fips_compliant=fips_result.compliant if fips_result is not None else False,
            fips_violations=fips_result.violations if fips_result is not None else [],
            key_usage=key_usage,
            extended_key_usage=extended_key_usage,
            is_ca=is_ca,
            basic_constraints_path_length=basic_constraints_path_length,
            is_self_signed=is_self_signed,
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
        """Populate all Tetragon Pod proto fields onto cert_info."""
        if tetragon_pod is None:
            return

        cert_info.pod_name        = tetragon_pod.name
        cert_info.namespace       = tetragon_pod.namespace
        cert_info.workload_kind   = tetragon_pod.workload_kind
        cert_info.workload_name   = tetragon_pod.workload
        cert_info.pod_labels      = dict(tetragon_pod.pod_labels) if tetragon_pod.pod_labels else {}
        # pod.uid available from Tetragon v1.6.0; empty string on older servers
        if tetragon_pod.uid:
            cert_info.pod_uid = tetragon_pod.uid
        # pod.pod_annotations available from Tetragon v1.5.0; empty map on older servers
        cert_info.pod_annotations = dict(tetragon_pod.pod_annotations) if tetragon_pod.pod_annotations else {}

        for key in ["app.kubernetes.io/name", "app", "name"]:
            if key in cert_info.pod_labels:
                cert_info.app_label = cert_info.pod_labels[key]
                break

        c = tetragon_pod.container
        cert_info.container_id               = c.id
        cert_info.container_name             = c.name
        cert_info.container_image            = c.image.name
        cert_info.container_image_id         = c.image.id
        cert_info.container_maybe_exec_probe = c.maybe_exec_probe
        # container.security_context available from Tetragon v1.5.0; unset on older servers
        if c.HasField('security_context'):
            cert_info.container_privileged = c.security_context.privileged
        if c.HasField('pid'):
            cert_info.container_pid = c.pid.value
        if c.HasField('start_time'):
            cert_info.container_start_time = c.start_time.ToDatetime()

        logger.debug(
            f"Tetragon pod context: pod={cert_info.pod_name} uid={cert_info.pod_uid} "
            f"namespace={cert_info.namespace} "
            f"workload={cert_info.workload_kind}/{cert_info.workload_name} "
            f"container={cert_info.container_name} image={cert_info.container_image} "
            f"privileged={cert_info.container_privileged} labels={cert_info.pod_labels}"
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
                + (f" node={info.node_name}" if info.node_name else "")
                + (f" workload={info.workload}" if info.workload else "")
                + (f" container={info.container_name}" if info.container_name else "")
            )
        elif info.node_name:
            k8s_ctx = f" | node={info.node_name}"

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

        detail_log = logger.info if self.demo_mode else logger.debug
        detail_log(f"   Subject: {info.subject}")
        detail_log(f"   Issuer: {info.issuer}")
        detail_log(f"   Serial: {info.serial_number}")
        if info.checksum:
            detail_log(f"   SHA-256: {info.checksum}")
        detail_log(
            f"   Valid: {info.not_before.strftime('%Y-%m-%d')} -> "
            f"{info.not_after.strftime('%Y-%m-%d')}"
        )
        if info.san_dns_names:
            detail_log(f"   SAN DNS: {', '.join(info.san_dns_names[:5])}")
        if info.san_ip_addresses:
            detail_log(f"   SAN IP:  {', '.join(info.san_ip_addresses[:5])}")
        if info.key_usage is not None or info.extended_key_usage is not None:
            ku  = ', '.join(info.key_usage)         if info.key_usage         else '—'
            eku = ', '.join(info.extended_key_usage) if info.extended_key_usage else '—'
            detail_log(f"   Key Usage: {ku} | EKU: {eku}")
        if info.is_ca is not None:
            bc = "CA" if info.is_ca else "end-entity"
            if info.is_ca and info.basic_constraints_path_length is not None:
                bc += f" (path length {info.basic_constraints_path_length})"
            detail_log(f"   Basic Constraints: {bc}")
        if info.fips_compliant:
            alg = info.key_algorithm
            if info.key_size:
                alg += f" {info.key_size}-bit"
            if info.curve_name:
                alg += f"/{info.curve_name}"
            if info.signature_hash:
                alg += f"/{info.signature_hash}"
            detail_log(f"   FIPS: compliant ({alg})")
        elif info.fips_violations:
            logger.warning(
                f"⚠️  FIPS NON-COMPLIANT: {display_path} — "
                + " | ".join(info.fips_violations)
            )
        if info.is_self_signed:
            logger.warning(
                f"⚠️  SELF-SIGNED: {display_path} "
                f"(process={info.process} CN={info.common_name})"
                f"{k8s_ctx}"
            )
        if info.pod_name:
            detail_log(f"   Pod: {info.namespace}/{info.pod_name}")
            detail_log(f"   Workload: {info.workload}")
            detail_log(f"   Container: {info.container_name} ({info.container_image})")

    def _resolve_process_binary(self, process_name: str, pid: int) -> str:
        """Resolve the full binary path when Tetragon truncates it to a parent directory.

        Always probes /proc/{pid}/exe so that ProtectHome (which makes os.path.isdir()
        unreliable for /home paths inside the service namespace) does not prevent
        resolution while the process is still alive.
        """
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
            prefix = process_name.rstrip("/")
            if exe == prefix or exe.startswith(prefix + "/"):
                if exe != process_name:
                    logger.debug(f"Resolved truncated binary path for PID {pid}: {process_name!r} -> {exe!r}")
                return exe
        except OSError as e:
            logger.debug(f"Could not resolve binary path for PID {pid}: {e}")
        return process_name

    def extract_cert_path_from_event(self, event) -> Tuple[Optional[str], str, int, str, object]:
        """
        Extract certificate path, process name, PID, namespace, and the raw
        Tetragon pod proto from a Tetragon event.

        Returns the pod proto object directly rather than individual string fields
        so that _apply_pod_context can read all available pod metadata (name,
        namespace, workload, labels) in one place without multiple return values.
        """
        cert_path      = None
        process_name   = ""
        pid            = 0
        namespace      = ""
        tetragon_pod   = None
        parent_process = ""
        parent_pid     = 0

        # Handle kprobe events
        if event.HasField('process_kprobe'):
            kprobe = event.process_kprobe
            pid = kprobe.process.pid.value if kprobe.process.HasField('pid') else 0
            process_name = self._resolve_process_binary(kprobe.process.binary, pid)

            if kprobe.process.HasField('pod'):
                tetragon_pod = kprobe.process.pod
                namespace    = tetragon_pod.namespace

            if kprobe.HasField('parent'):
                parent_process = kprobe.parent.binary
                parent_pid = kprobe.parent.pid.value if kprobe.parent.HasField('pid') else 0

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
            pid = uprobe.process.pid.value if uprobe.process.HasField('pid') else 0
            process_name = self._resolve_process_binary(uprobe.process.binary, pid)

            if uprobe.process.HasField('pod'):
                tetragon_pod = uprobe.process.pod
                namespace    = tetragon_pod.namespace

            if uprobe.HasField('parent'):
                parent_process = uprobe.parent.binary
                parent_pid = uprobe.parent.pid.value if uprobe.parent.HasField('pid') else 0

            for arg in uprobe.args:
                if arg.HasField('string_arg'):
                    path = arg.string_arg
                    if self.is_cert_path(path):
                        cert_path = path
                        logger.debug(f"Found cert path in uprobe string_arg: {cert_path}")
                        break

        # Translate host paths — in Kubernetes the cert-analyzer runs in a
        # container where /host is a bind mount of the node root filesystem.
        # In standalone mode this prefix is empty so paths are used as-is.
        #
        # Tetragon may report either the prefixed path (e.g. /host/etc/pki/...)
        # when a container process accesses the file via the bind mount, or the
        # bare host path (e.g. /etc/pki/...) when a host process opens it.
        # Normalise to the prefixed form so the cert file is always resolvable
        # inside the container, but avoid double-prefixing paths already prefixed.
        if cert_path and self.host_prefix:
            if not cert_path.startswith(self.host_prefix):
                cert_path = self.host_prefix + cert_path

        return cert_path, process_name, pid, namespace, tetragon_pod, parent_process, parent_pid

    # ------------------------------------------------------------------
    # PKCS11 / NSS helpers (Java FIPS mode)
    # ------------------------------------------------------------------

    @staticmethod
    def _read_process_memory(pid: int, address: int, size: int) -> Optional[bytes]:
        """Read bytes from a process's virtual address space via /proc/<pid>/mem.

        Requires CAP_SYS_PTRACE (or the same UID as the target process when
        YAMA ptrace restrictions are relaxed).  cert_analyzer typically runs as
        root in the Tetragon security-monitoring context, so this works.
        """
        if address == 0 or size == 0:
            return None
        try:
            with open(f"/proc/{pid}/mem", "rb") as f:
                f.seek(address)
                return f.read(size)
        except (IOError, OSError, OverflowError) as exc:
            logger.debug(f"Cannot read /proc/{pid}/mem at 0x{address:x} ({size}B): {exc}")
            return None

    def _handle_nsc_create_object(self, event) -> bool:
        """Handle a NSC_CreateObject uprobe event from libsoftokn3.so.

        NSC_CreateObject(session, pTemplate, ulCount, phObject) is called when
        the NSS PKCS11 token creates any object — keys, digest sessions, and
        certificates (CKA_CLASS = CKO_CERTIFICATE = 0x01).

        When Java runs under FIPS mode, KeyStore.setCertificateEntry() calls this
        function to import a certificate DER blob into the NSS FIPS token.  The
        cert bytes live inside the CK_ATTRIBUTE pTemplate array:

            struct CK_ATTRIBUTE {          // 24 bytes on LP64
                uint64 type;               // e.g. 0x01 = CKA_CLASS, 0x11 = CKA_VALUE
                void  *pValue;             // pointer to the attribute's value
                uint64 ulValueLen;         // byte length of *pValue
            };

        Tetragon captures pTemplate and ulCount as uint64 args (args[1] and args[2]).
        This method reads the template from /proc/<pid>/mem, locates CKA_CLASS and
        CKA_VALUE, verifies the object is a certificate, then follows the CKA_VALUE
        pValue pointer to extract the raw DER bytes.
        """
        if not event.HasField('process_uprobe'):
            return False

        uprobe = event.process_uprobe
        pid = uprobe.process.pid.value if uprobe.process.HasField('pid') else 0
        process_name = self._resolve_process_binary(uprobe.process.binary, pid)
        tetragon_pod = uprobe.process.pod if uprobe.process.HasField('pod') else None
        namespace = tetragon_pod.namespace if tetragon_pod else ""
        parent_process = uprobe.parent.binary if uprobe.HasField('parent') else ""
        parent_pid = uprobe.parent.pid.value if uprobe.HasField('parent') and uprobe.parent.HasField('pid') else 0

        if self.filter_self_events:
            if "cert-analyzer" in process_name or "cert_analyzer" in process_name:
                return False
            if pid == os.getpid():
                return False

        # Extract the three uint64 args: session, pTemplate, ulCount
        uint64_args = [arg.size_arg for arg in uprobe.args if arg.HasField('size_arg')]
        if len(uint64_args) < 3:
            logger.debug("NSC_CreateObject: fewer than 3 uint64 args, skipping")
            return False

        template_addr = uint64_args[1]
        count = uint64_args[2]

        if count == 0 or count > 64:
            logger.debug(f"NSC_CreateObject: implausible attribute count {count}, skipping")
            return False

        # Read the flat CK_ATTRIBUTE array (each entry is 24 bytes)
        template_bytes = self._read_process_memory(pid, template_addr, count * 24)
        if not template_bytes or len(template_bytes) < count * 24:
            logger.debug(f"NSC_CreateObject: could not read template from PID {pid}")
            return False

        CKA_CLASS = 0x00000001
        CKO_CERTIFICATE = 0x00000001
        CKA_VALUE = 0x00000011
        ATTR_SIZE = 24  # sizeof(CK_ATTRIBUTE) on LP64

        ck_class: Optional[int] = None
        der_addr: Optional[int] = None
        der_len: int = 0

        for i in range(count):
            off = i * ATTR_SIZE
            attr_type = int.from_bytes(template_bytes[off:off+8], 'little')
            p_value   = int.from_bytes(template_bytes[off+8:off+16], 'little')
            val_len   = int.from_bytes(template_bytes[off+16:off+24], 'little')

            if attr_type == CKA_CLASS and val_len in (4, 8):
                class_bytes = self._read_process_memory(pid, p_value, val_len)
                if class_bytes:
                    ck_class = int.from_bytes(class_bytes[:val_len], 'little')
            elif attr_type == CKA_VALUE and val_len > 0:
                der_addr = p_value
                der_len  = val_len

        if ck_class != CKO_CERTIFICATE:
            logger.debug(f"NSC_CreateObject from {process_name}: CKA_CLASS={ck_class:#x}, not a cert")
            return False

        if not der_addr or not (64 < der_len < 65536):
            logger.debug(f"NSC_CreateObject from {process_name}: no CKA_VALUE or implausible len {der_len}")
            return False

        der_bytes = self._read_process_memory(pid, der_addr, der_len)
        if not der_bytes:
            logger.debug(f"NSC_CreateObject: could not read DER bytes from PID {pid}")
            return False

        try:
            cert = x509.load_der_x509_certificate(der_bytes, default_backend())
        except Exception as exc:
            logger.debug(f"NSC_CreateObject: DER parse failed: {exc}")
            return False

        serial = str(cert.serial_number)
        synthetic_path = f"uprobe://NSC_CreateObject/{pid}/{serial}"

        self.metrics.last_event_timestamp.set(time.time())
        logger.info(
            f"🔍 Detected Java FIPS in-memory certificate: {synthetic_path} "
            f"by {process_name} (PID: {pid})"
        )

        if any(k.startswith(synthetic_path + ":") for k in self.known_certs):
            logger.info(f"Re-detected known Java FIPS certificate: {synthetic_path}")
            return True

        cert_info = self.extract_certificate_info(cert, synthetic_path, process_name, pid, namespace)
        if cert_info is None:
            return False

        self._apply_pod_context(cert_info, tetragon_pod)
        cert_info.node_name      = event.node_name
        cert_info.parent_process = parent_process
        cert_info.parent_pid     = parent_pid
        self.metrics.update_certificate_metrics(cert_info)
        self.log_certificate_status(cert_info)
        self.known_certs[cert_info.unique_key] = cert_info

        if self.kafka_publisher is not None:
            self.kafka_publisher.publish(cert_info)

        self._update_cache_metrics()
        return True

    def _handle_nsc_find_objects_init(self, event) -> bool:
        """Handle a NSC_FindObjectsInit uprobe event from libsoftokn3.so.

        This fires when Java enumerates objects in the NSS PKCS11 token, which
        happens during KeyStore.load() in FIPS mode.  The template may contain
        a CKO_CERTIFICATE class filter, indicating a cert-read operation.

        We cannot extract cert bytes here (they are returned by subsequent
        NSC_FindObjects + NSC_GetAttributeValue calls), but we log the event
        to show that Java FIPS cert enumeration was detected.
        """
        if not event.HasField('process_uprobe'):
            return False

        uprobe = event.process_uprobe
        pid = uprobe.process.pid.value if uprobe.process.HasField('pid') else 0
        process_name = self._resolve_process_binary(uprobe.process.binary, pid)

        if self.filter_self_events and pid == os.getpid():
            return False

        uint64_args = [arg.size_arg for arg in uprobe.args if arg.HasField('size_arg')]
        if len(uint64_args) < 3:
            return False

        template_addr = uint64_args[1]
        count = uint64_args[2]

        if count == 0 or count > 32:
            return False

        template_bytes = self._read_process_memory(pid, template_addr, count * 24)
        if not template_bytes:
            return False

        CKA_CLASS = 0x00000001
        CKO_CERTIFICATE = 0x00000001
        ATTR_SIZE = 24

        for i in range(count):
            off = i * ATTR_SIZE
            attr_type = int.from_bytes(template_bytes[off:off+8], 'little')
            p_value   = int.from_bytes(template_bytes[off+8:off+16], 'little')
            val_len   = int.from_bytes(template_bytes[off+16:off+24], 'little')

            if attr_type == CKA_CLASS and val_len in (4, 8):
                class_bytes = self._read_process_memory(pid, p_value, val_len)
                if class_bytes:
                    ck_class = int.from_bytes(class_bytes[:val_len], 'little')
                    if ck_class == CKO_CERTIFICATE:
                        logger.info(
                            f"🔍 Java FIPS cert enumeration: NSC_FindObjectsInit "
                            f"from {process_name} (PID: {pid}) — "
                            f"cert bytes in subsequent NSC_GetAttributeValue"
                        )
                        return True
        return False

    def _handle_uprobe_in_memory_cert(self, event) -> bool:
        """
        Handle a process_uprobe event where the cert arrives as raw DER bytes
        (e.g. SSL_CTX_use_certificate_ASN1). Returns True if a cert was
        successfully extracted and processed, False otherwise (no bytes_arg,
        unparseable bytes, etc.).
        """
        if not event.HasField('process_uprobe'):
            return False

        uprobe = event.process_uprobe
        pid = uprobe.process.pid.value if uprobe.process.HasField('pid') else 0
        process_name = self._resolve_process_binary(uprobe.process.binary, pid)
        tetragon_pod = uprobe.process.pod if uprobe.process.HasField('pod') else None
        namespace = tetragon_pod.namespace if tetragon_pod else ""
        parent_process = uprobe.parent.binary if uprobe.HasField('parent') else ""
        parent_pid = uprobe.parent.pid.value if uprobe.HasField('parent') and uprobe.parent.HasField('pid') else 0

        if self.filter_self_events:
            if process_name == "/app" or "cert-analyzer" in process_name or "cert_analyzer" in process_name:
                logger.debug(f"Skipping self-generated uprobe bytes event from {process_name}")
                return False
            if pid == os.getpid():
                logger.debug(f"Skipping self-generated uprobe bytes event from PID {pid}")
                return False

        raw_bytes = None
        for arg in uprobe.args:
            if arg.HasField('bytes_arg'):
                raw_bytes = bytes(arg.bytes_arg)
                break

        if not raw_bytes:
            return False

        try:
            cert = x509.load_der_x509_certificate(raw_bytes, default_backend())
        except Exception as e:
            logger.debug(f"Could not parse uprobe bytes_arg as DER certificate: {e}")
            return False

        serial = str(cert.serial_number)
        symbol = uprobe.symbol if uprobe.symbol else "undetermined_symbol_name"
        synthetic_path = f"uprobe://{symbol}/{pid}/{serial}"

        self.metrics.last_event_timestamp.set(time.time())
        logger.info(f"🔍 Detected in-memory certificate: {synthetic_path} by {process_name} (PID: {pid})")

        if any(k.startswith(synthetic_path + ":") for k in self.known_certs):
            logger.info(f"Re-detected known in-memory certificate: {synthetic_path}")
            return True

        cert_info = self.extract_certificate_info(cert, synthetic_path, process_name, pid, namespace)
        if cert_info is None:
            return False

        self._apply_pod_context(cert_info, tetragon_pod)
        cert_info.node_name      = event.node_name
        cert_info.parent_process = parent_process
        cert_info.parent_pid     = parent_pid
        self.metrics.update_certificate_metrics(cert_info)
        self.log_certificate_status(cert_info)
        self.known_certs[cert_info.unique_key] = cert_info

        if self.kafka_publisher is not None:
            self.kafka_publisher.publish(cert_info)

        self._update_cache_metrics()
        return True

    # ------------------------------------------------------------------
    # Port-probe helpers — port-scanner-like cert discovery
    # ------------------------------------------------------------------

    def _read_primary_ip_from_fib_trie(self, pid: int) -> Optional[str]:
        """Read the primary non-loopback IPv4 from /proc/<pid>/net/fib_trie.

        Follows the process's network namespace so this returns the container's
        own IP, not the host IP. Used to probe containerised services that bind
        to 0.0.0.0 inside their own network namespace.
        """
        try:
            with open(f'/proc/{pid}/net/fib_trie', 'r') as f:
                lines = f.readlines()
        except OSError:
            return None

        ip_pat = re.compile(r'(\d+\.\d+\.\d+\.\d+)/32')
        for i, line in enumerate(lines):
            if 'LOCAL' in line and '/32 host' in line:
                for j in range(i - 1, max(-1, i - 5), -1):
                    m = ip_pat.search(lines[j])
                    if m:
                        ip = m.group(1)
                        if not ip.startswith('127.') and ip != '0.0.0.0':
                            return ip
        return None

    def _resolve_pid_ip(self, pid: int, bind_addr: str) -> str:
        """Resolve the IP address to probe for a given bind event.

        If the service bound to a specific address, use it directly. For
        wildcard binds (0.0.0.0 / ::) on K8s, read the container's primary
        IP from its network namespace via /proc/<pid>/net/fib_trie. Falls
        back to 127.0.0.1 for bare-metal deployments where the process
        is in the host network namespace.
        """
        if bind_addr and bind_addr not in ('0.0.0.0', '::', ''):
            return bind_addr
        ip = None
        try:
            ip = self._read_primary_ip_from_fib_trie(pid)
        except Exception as e:
            logger.debug(f"fib_trie lookup failed for PID {pid}: {e}")
        return ip or '127.0.0.1'

    def _probe_tls_endpoint(
        self,
        host: str,
        port: int,
        process_name: str,
        pid: int,
        node_name: str,
        tetragon_pod,
    ) -> None:
        """Connect to host:port, complete a TLS handshake, and ingest the leaf cert.

        Uses no-verify mode intentionally — the goal is certificate inventory,
        not validation. A short delay before calling (port_probe_connect_delay)
        gives the service time to finish TLS initialisation after binding.
        """
        synthetic_path = f'tls-probe://{host}:{port}'

        if f'{host}:{port}' in self._probed_endpoints:
            logger.debug(f"TLS probe: already probed {synthetic_path}")
            self.metrics.tls_port_probes_total.labels(status='skipped').inc()
            return

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            raw_sock = socket.create_connection((host, port), timeout=self._port_probe_timeout)
            with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                der_bytes = ssock.getpeercert(binary_form=True)
        except Exception as e:
            logger.debug(f"TLS probe failed {host}:{port}: {e}")
            self.metrics.tls_port_probes_total.labels(status='failed').inc()
            return

        if not der_bytes:
            self.metrics.tls_port_probes_total.labels(status='failed').inc()
            return

        try:
            cert = x509.load_der_x509_certificate(der_bytes, default_backend())
        except Exception as e:
            logger.debug(f"TLS probe: DER parse failed for {host}:{port}: {e}")
            self.metrics.tls_port_probes_total.labels(status='failed').inc()
            return

        cert_info = self.extract_certificate_info(cert, synthetic_path, process_name, pid)
        if cert_info is None:
            self.metrics.tls_port_probes_total.labels(status='failed').inc()
            return

        if tetragon_pod is not None:
            self._apply_pod_context(cert_info, tetragon_pod)
        cert_info.node_name = node_name

        self.metrics.update_certificate_metrics(cert_info)
        self.log_certificate_status(cert_info)
        self.known_certs[cert_info.unique_key] = cert_info
        self._probed_endpoints.add(f'{host}:{port}')
        self._update_cache_metrics()

        if self.kafka_publisher is not None:
            self.kafka_publisher.publish(cert_info)

        self.metrics.tls_port_probes_total.labels(status='success').inc()
        logger.info(
            f"TLS probe: discovered cert at {host}:{port} "
            f"CN={cert_info.common_name} process={process_name}"
        )

    def _handle_tls_bind_event(self, event) -> None:
        """Extract the bound address/port from a security_socket_bind or sys_bind
        kprobe event, resolve the probe target IP, and schedule a TLS probe.

        Handles two policy variants:
          - security_socket_bind (experimental policy): sockaddr decoded by Tetragon
            into sockaddr_arg — port in arg[1].sockaddr_arg.port
          - sys_bind (fixed policy): raw sockaddr bytes in arg[1].bytes_arg
        """
        kprobe = event.process_kprobe
        fn = kprobe.function_name
        pid = kprobe.process.pid.value if kprobe.process.HasField('pid') else 0
        process_name = self._resolve_process_binary(kprobe.process.binary, pid)
        tetragon_pod = kprobe.process.pod if kprobe.process.HasField('pod') else None
        node_name = event.node_name

        port = 0
        bind_addr = '0.0.0.0'

        if fn == 'security_socket_bind':
            # arg[0]=sock (socket struct), arg[1]=sockaddr_arg (address being bound)
            for arg in kprobe.args:
                if arg.HasField('sockaddr_arg') and arg.sockaddr_arg.port:
                    port = arg.sockaddr_arg.port
                    bind_addr = arg.sockaddr_arg.addr or '0.0.0.0'
                    break

        elif fn == 'sys_bind':
            # arg[0]=int (fd), arg[1]=char_buf (raw sockaddr struct)
            if len(kprobe.args) >= 2 and kprobe.args[1].HasField('bytes_arg'):
                data = bytes(kprobe.args[1].bytes_arg)
                if len(data) >= 8:
                    family = struct.unpack_from('<H', data, 0)[0]
                    port = struct.unpack_from('>H', data, 2)[0]
                    if family == 2:  # AF_INET
                        bind_addr = '.'.join(str(b) for b in data[4:8])

        if not port:
            logger.debug(f"TLS bind event: could not extract port from {fn} event")
            return

        host = self._resolve_pid_ip(pid, bind_addr)
        delay = self._port_probe_connect_delay

        endpoint_key = f'{host}:{port}'
        if endpoint_key in self._probed_endpoints or endpoint_key in self._probe_in_flight:
            logger.debug(f"TLS bind probe: {endpoint_key} already probed or in flight, skipping")
            return
        self._probe_in_flight.add(endpoint_key)

        def _probe():
            if delay:
                time.sleep(delay)
            try:
                self._probe_tls_endpoint(host, port, process_name, pid, node_name, tetragon_pod)
            except Exception as e:
                logger.debug(f"TLS probe thread error {host}:{port}: {e}")
            finally:
                self._probe_in_flight.discard(endpoint_key)

        t = threading.Thread(target=_probe, daemon=True, name=f'tls-probe-{host}-{port}')
        t.start()
        logger.debug(f"Scheduled TLS probe {host}:{port} delay={delay}s pid={pid} process={process_name}")

    def _handle_tls_connect_event(self, event) -> None:
        """Extract destination address/port from a tcp_connect kprobe event and schedule a TLS probe.

        tcp_connect fires when a process initiates an outbound TCP connection.
        The sock_arg carries the destination address and port. We probe that
        remote endpoint immediately — no startup delay is needed because the
        remote server is already running when our process connects to it.
        """
        kprobe = event.process_kprobe
        pid = kprobe.process.pid.value if kprobe.process.HasField('pid') else 0
        process_name = self._resolve_process_binary(kprobe.process.binary, pid)
        tetragon_pod = kprobe.process.pod if kprobe.process.HasField('pod') else None
        node_name = event.node_name

        daddr = ''
        dport = 0
        for arg in kprobe.args:
            if arg.HasField('sock_arg'):
                daddr = arg.sock_arg.daddr
                dport = arg.sock_arg.dport
                break

        if not dport or not daddr:
            logger.debug("tcp_connect event: could not extract destination address/port")
            return

        if dport not in self._tls_outbound_ports:
            logger.debug(f"tcp_connect: skipping non-TLS port {dport} from {process_name}")
            return

        endpoint_key = f'{daddr}:{dport}'
        if endpoint_key in self._probed_endpoints or endpoint_key in self._probe_in_flight:
            logger.debug(f"TLS connect probe: {endpoint_key} already probed or in flight, skipping")
            return
        self._probe_in_flight.add(endpoint_key)

        def _probe():
            try:
                self._probe_tls_endpoint(daddr, dport, process_name, pid, node_name, tetragon_pod)
            except Exception as e:
                logger.debug(f"TLS outbound probe thread error {daddr}:{dport}: {e}")
            finally:
                self._probe_in_flight.discard(endpoint_key)

        t = threading.Thread(target=_probe, daemon=True, name=f'tls-probe-out-{daddr}-{dport}')
        t.start()
        logger.debug(
            f"Scheduled TLS outbound probe {daddr}:{dport} pid={pid} process={process_name}"
        )

    def process_event(self, event):
        """Process a single Tetragon event"""
        logger.debug("Processing event...")

        # Bind and outbound-connect events carry no cert paths — route them to
        # port-probe handlers and return. Other kprobe/uprobe events fall through
        # to the normal cert extraction path below.
        if event.HasField('process_kprobe'):
            fn = getattr(event.process_kprobe, 'function_name', '')
            if fn in ('security_socket_bind', 'sys_bind'):
                if self._bind_probe_enabled:
                    self._handle_tls_bind_event(event)
                return
            if fn == 'tcp_connect':
                if self._connect_probe_enabled:
                    self._handle_tls_connect_event(event)
                return

        cert_path, process_name, pid, namespace, tetragon_pod, parent_process, parent_pid = \
            self.extract_cert_path_from_event(event)
        pod_name = tetragon_pod.name if tetragon_pod is not None else ""
        logger.debug(f"Extracted: cert_path={cert_path}, process={process_name}, pid={pid}, pod={pod_name}")

        if not cert_path:
            # Route PKCS11/NSS events (Java FIPS) to dedicated handlers first.
            if event.HasField('process_uprobe'):
                symbol = event.process_uprobe.symbol
                if symbol == "NSC_CreateObject":
                    self._handle_nsc_create_object(event)
                    return
                if symbol == "NSC_FindObjectsInit":
                    self._handle_nsc_find_objects_init(event)
                    return
            self._handle_uprobe_in_memory_cert(event)
            return

        # Optionally skip events from the analyzer itself to avoid a feedback loop.
        # Set FILTER_SELF_EVENTS=false to disable this - useful for demos where the
        # cert-analyzer pod is itself the workload being observed.
        if self.filter_self_events:
            if process_name == "/app" or "cert-analyzer" in process_name or "cert_analyzer" in process_name:
                logger.debug(f"Skipping self-generated event from {process_name}")
                return
            # Also filter by PID — Tetragon may report the process binary as '/'
            # on some systems, so name-based filtering alone is insufficient
            if pid == os.getpid():
                logger.debug(f"Skipping self-generated event from PID {pid}")
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
                if event.node_name:
                    cert_info.node_name = event.node_name
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
            cert_info.node_name     = event.node_name
            cert_info.parent_process = parent_process
            cert_info.parent_pid     = parent_pid

            self.metrics.update_certificate_metrics(cert_info)
            self.log_certificate_status(cert_info)
            self.known_certs[cert_info.unique_key] = cert_info

            # Publish new certificate discovery to Kafka if enabled
            if self.kafka_publisher is not None:
                self.kafka_publisher.publish(cert_info)

        self._update_cache_metrics()

    def get_runtime_tetragon_version(self, stub) -> str:
        """
        Query the running Tetragon daemon for its version via GetVersion RPC.

        Returns the version string (e.g. 'v1.1.0') on success, or 'unknown'
        if the call fails or the version field is absent. Failures are logged
        as warnings and never propagate — a version mismatch should alert but
        must never prevent the analyzer from starting.
        """
        if not hasattr(tetragon_pb2, 'GetVersionRequest'):
            logger.warning(
                "GetVersionRequest is not available in this version of the "
                "Tetragon protobuf bindings (requires > v1.1.0); skipping version check"
            )
            return 'unknown'
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

    def check_tetragon_policies(self, stub) -> None:
        """
        Query Tetragon for all tracing policies and update Prometheus metrics.

        Exposes two metrics:
          - tetragon_policy_info{name, namespace, state}=1  (presence per policy)
          - tetragon_policies_total{state}=N                (count per state)

        Stale series are removed when a policy is deleted or changes state,
        so the metrics always reflect the live policy table. Failures are
        logged as warnings and never propagate.
        """
        if not hasattr(sensors_pb2, 'ListTracingPoliciesRequest'):
            logger.warning(
                "ListTracingPoliciesRequest not available in Tetragon protobuf "
                "bindings; skipping policy check"
            )
            return
        try:
            response = stub.ListTracingPolicies(
                sensors_pb2.ListTracingPoliciesRequest(),
                timeout=5.0,
            )
        except Exception as e:
            logger.warning(f"Could not list Tetragon tracing policies: {e}")
            return

        new_labels: Set[Tuple[str, str, str]] = set()
        state_counts: Dict[str, int] = {}

        for policy in response.policies:
            state_str = _POLICY_STATE_NAMES.get(policy.state, 'unknown')
            ns = policy.namespace or ''
            key = (policy.name, ns, state_str)
            new_labels.add(key)
            state_counts[state_str] = state_counts.get(state_str, 0) + 1

        # Remove series for policies that were deleted or changed state
        for name, ns, state_str in self._known_policy_labels - new_labels:
            self.metrics.tetragon_policy_info.remove(name, ns, state_str)

        for name, ns, state_str in new_labels:
            self.metrics.tetragon_policy_info.labels(
                name=name, namespace=ns, state=state_str
            ).set(1)

        # Always emit a count for every known state so queries don't return no-data
        for state_str in _POLICY_STATE_NAMES.values():
            self.metrics.tetragon_policies_total.labels(state=state_str).set(
                state_counts.get(state_str, 0)
            )

        self._known_policy_labels = new_labels
        logger.debug(f"Tetragon policy states: {state_counts}")

    def _start_policy_monitor(self, stub) -> None:
        """
        Start a background daemon thread that periodically re-queries tracing
        policy state and updates Prometheus metrics.

        Interval is configurable via TETRAGON_POLICY_CHECK_INTERVAL env var
        (default: 60 seconds).
        """
        interval = int(os.getenv('TETRAGON_POLICY_CHECK_INTERVAL', '60'))

        def _monitor():
            while True:
                time.sleep(interval)
                try:
                    self.check_tetragon_policies(stub)
                except Exception as e:
                    logger.warning(f"Policy monitor error: {e}")

        thread = threading.Thread(target=_monitor, daemon=True)
        thread.name = 'tetragon-policy-monitor'
        thread.start()
        logger.info(f"Started Tetragon policy monitor (interval: {interval}s)")

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

        # Version and policy checks on startup, then periodically in background
        self.check_tetragon_version(stub)
        self._start_version_monitor(stub)
        self.check_tetragon_policies(stub)
        self._start_policy_monitor(stub)

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
                    self.metrics.tetragon_connected.set(1)

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
                    self.metrics.tetragon_connected.set(0)
                    logger.warning(
                        f"Tetragon connection lost ({e.code().name}), "
                        f"retrying in {retry_delay}s..."
                    )
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, max_delay)

                except Exception as e:
                    self.metrics.analyzer_healthy.set(0)
                    self.metrics.tetragon_connected.set(0)
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
            self.metrics.tetragon_connected.set(0)
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


CONFIG_FILE_PATH = '/etc/cert-analyzer/cert-analyzer.conf'


def load_config(path: str = CONFIG_FILE_PATH) -> configparser.ConfigParser:
    """
    Load the INI configuration file if it exists.

    Returns an empty ConfigParser (all lookups fall through to env var
    defaults) if the file is absent — this keeps the Kubernetes deployment
    path working without any config file present.

    The config file path can be overridden via the CERT_ANALYZER_CONFIG
    env var, which is useful for testing or non-standard deployments.
    """
    config_path = os.getenv('CERT_ANALYZER_CONFIG', path)
    cp = configparser.ConfigParser()

    if os.path.exists(config_path):
        try:
            cp.read(config_path)
            logger.info(f"Loaded configuration from {config_path}")
        except configparser.Error as e:
            logger.warning(
                f"Could not parse config file {config_path}: {e} — "
                f"falling back to environment variables and defaults"
            )
    else:
        logger.debug(
            f"Config file not found at {config_path} — "
            f"using environment variables and defaults"
        )

    return cp


def cfg(
    cp: configparser.ConfigParser,
    section: str,
    key: str,
    env_var: str,
    default: str,
) -> str:
    """
    Resolve a configuration value using the precedence chain:
      config file → env var → hardcoded default

    The config file takes precedence so that operators editing
    /etc/cert-analyzer/cert-analyzer.conf always see their changes
    reflected without needing to unset env vars.

    Returns a string — callers are responsible for casting to int/bool.
    """
    # Config file takes highest precedence
    if cp.has_option(section, key):
        return cp.get(section, key)
    # Env var is the fallback
    return os.getenv(env_var, default)


def main():
    """Main entry point"""
    cp = load_config()

    tetragon_addr   = cfg(cp, 'tetragon',  'addr',                        'TETRAGON_ADDR',                   'localhost:54321')
    metrics_port    = int(cfg(cp, 'metrics',  'port',                     'METRICS_PORT',                    '9090'))
    health_port     = int(cfg(cp, 'health',   'port',                     'HEALTH_PORT',                     '8086'))
    alert_threshold = int(cfg(cp, 'alerting', 'threshold_days',           'ALERT_THRESHOLD_DAYS',            '30'))
    log_level       = cfg(cp, 'logging',   'level',                       'LOG_LEVEL',                       'INFO')
    scan_paths_str  = cfg(cp, 'scanning',  'paths',                       'CERT_SCAN_PATHS',                 '/etc/ssl,/etc/pki')
    scan_paths      = [p.strip() for p in scan_paths_str.split(',') if p.strip()]
    scan_interval   = int(cfg(cp, 'scanning',  'interval_seconds',        'SCAN_INTERVAL_SECONDS',           '3600'))
    grace_period    = int(cfg(cp, 'health',    'readiness_grace_period_seconds', 'READINESS_GRACE_PERIOD_SECONDS', '60'))
    staleness       = int(cfg(cp, 'health',    'readiness_staleness_seconds',    'READINESS_STALENESS_SECONDS',    '300'))
    # Set to 'false' to allow the cert-analyzer to observe its own certificate
    # accesses - useful for demos showing self-pod enrichment
    filter_self     = cfg(cp, 'certificates', 'filter_self_events',       'FILTER_SELF_EVENTS',              'true').lower() != 'false'
    # Empty by default for standalone RPM deployment — set to /host for
    # Kubernetes where the node root filesystem is bind-mounted at /host
    host_prefix     = cfg(cp, 'certificates', 'host_prefix',              'HOST_PREFIX',                     '')
    checksum_enabled        = cfg(cp, 'certificates', 'checksum_enabled',        'CERT_CHECKSUM_ENABLED',        'false').lower() == 'true'
    demo_mode               = cfg(cp, 'certificates', 'demo_mode',               'DEMO_MODE',                    'false').lower() == 'true'
    fips_compliance_enabled = cfg(cp, 'certificates', 'fips_compliance_enabled', 'FIPS_COMPLIANCE_ENABLED',      'true').lower() != 'false'

    # ── Port probe (optional) ─────────────────────────────────────────────────
    bind_probe_enabled    = cfg(cp, 'port_probe', 'bind_probe_enabled',    'BIND_PROBE_ENABLED',    'false').lower() == 'true'
    connect_probe_enabled = cfg(cp, 'port_probe', 'connect_probe_enabled', 'CONNECT_PROBE_ENABLED', 'false').lower() == 'true'
    port_probe_timeout       = float(cfg(cp, 'port_probe', 'timeout_seconds',        'PORT_PROBE_TIMEOUT',       '5'))
    port_probe_connect_delay = float(cfg(cp, 'port_probe', 'connect_delay_seconds',  'PORT_PROBE_CONNECT_DELAY', '2'))
    _tls_ports_raw = cfg(cp, 'port_probe', 'tls_outbound_ports', 'TLS_OUTBOUND_PORTS', '')
    if _tls_ports_raw.strip():
        try:
            tls_outbound_ports: Optional[frozenset] = frozenset(
                int(p.strip()) for p in _tls_ports_raw.split(',') if p.strip()
            )
        except ValueError as e:
            logger.error(f"Invalid tls_outbound_ports value '{_tls_ports_raw}': {e} — using built-in defaults")
            tls_outbound_ports = None
    else:
        tls_outbound_ports = None

    # ── Kafka (optional) ──────────────────────────────────────────────────────
    kafka_enabled          = cfg(cp, 'kafka', 'enabled',           'KAFKA_ENABLED',           'false').lower() == 'true'
    kafka_bootstrap        = cfg(cp, 'kafka', 'bootstrap_servers', 'KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092')
    kafka_topic            = cfg(cp, 'kafka', 'topic',             'KAFKA_TOPIC',             'cert-analyzer-events')
    kafka_security         = cfg(cp, 'kafka', 'security_protocol', 'KAFKA_SECURITY_PROTOCOL', 'PLAINTEXT')
    kafka_sasl_mechanism   = cfg(cp, 'kafka', 'sasl_mechanism',    'KAFKA_SASL_MECHANISM',    '')
    kafka_sasl_username    = cfg(cp, 'kafka', 'sasl_username',     'KAFKA_SASL_USERNAME',     '')
    kafka_sasl_password    = cfg(cp, 'kafka', 'sasl_password',     'KAFKA_SASL_PASSWORD',     '')

    logging.getLogger().setLevel(getattr(logging, log_level.upper()))

    logger.info("="*60)
    logger.info("TLS Certificate Expiry Monitor (Multi-Cert + K8s Enrichment)")
    logger.info("="*60)
    logger.info(f"Version:           {CERT_ANALYZER_VERSION}")
    logger.info(f"Config file:       {os.getenv('CERT_ANALYZER_CONFIG', CONFIG_FILE_PATH)}")
    logger.info(f"Tetragon address:  {tetragon_addr}")
    logger.info(f"Tetragon build:    {TETRAGON_BUILD_VERSION}")
    logger.info(f"Cache max size:    {CACHE_MAX_SIZE}")
    logger.info(f"Cert checksums:    {'enabled' if checksum_enabled else 'disabled'}")
    logger.info(f"FIPS checking:     {'enabled' if fips_compliance_enabled else 'disabled'}")
    logger.info(f"Metrics port:      {metrics_port}")
    logger.info(f"Health port:       {health_port}")
    logger.info(f"Alert threshold:   {alert_threshold} days")
    logger.info(f"Scan paths:        {scan_paths}")
    logger.info(f"Scan interval:     {scan_interval} seconds")
    logger.info(f"Filter self events: {filter_self}")
    logger.info(f"Host prefix:       '{host_prefix}' (empty = standalone mode)")
    logger.info(f"Kafka enabled:     {kafka_enabled}")
    if kafka_enabled:
        logger.info(f"Kafka brokers:     {kafka_bootstrap}")
        logger.info(f"Kafka topic:       {kafka_topic}")
        logger.info(f"Kafka security:    {kafka_security}")
    logger.info(f"Bind probe:        {'enabled' if bind_probe_enabled else 'disabled'}")
    logger.info(f"Connect probe:     {'enabled' if connect_probe_enabled else 'disabled'}")
    if bind_probe_enabled or connect_probe_enabled:
        logger.info(f"Port probe timeout:        {port_probe_timeout}s")
    if bind_probe_enabled:
        logger.info(f"Port probe connect delay:  {port_probe_connect_delay}s")
    if connect_probe_enabled:
        _effective_ports = tls_outbound_ports if tls_outbound_ports is not None else CertificateAnalyzer.TLS_OUTBOUND_PORTS
        logger.info(f"TLS outbound ports:        {sorted(_effective_ports)}")
    logger.info("="*60)

    logger.info(f"Starting Prometheus metrics server on port {metrics_port}")
    try:
        start_http_server(metrics_port)
    except OSError as e:
        logger.critical(
            f"Cannot bind Prometheus metrics server to port {metrics_port}: {e}. "
            f"Change [metrics] port in cert-analyzer.conf or set METRICS_PORT."
        )
        sys.exit(1)

    # Initialise optional Kafka publisher before the analyzer so it can be
    # passed in at construction time
    kafka_publisher = None
    if kafka_enabled:
        kafka_publisher = KafkaPublisher(
            bootstrap_servers=kafka_bootstrap,
            topic=kafka_topic,
            security_protocol=kafka_security,
            sasl_mechanism=kafka_sasl_mechanism,
            sasl_username=kafka_sasl_username,
            sasl_password=kafka_sasl_password,
        )

    # HealthServer.is_ready() reads analyzer.metrics.last_event_timestamp, so
    # it needs the analyzer reference. CertificateAnalyzer.start() calls
    # health_server.set_channel() once the gRPC channel is established.
    # Break the circular dependency by constructing the analyzer first, then
    # passing it to HealthServer, then wiring the health server back in.
    analyzer = CertificateAnalyzer(tetragon_addr, alert_threshold,
                                   filter_self_events=filter_self,
                                   host_prefix=host_prefix,
                                   kafka_publisher=kafka_publisher,
                                   checksum_enabled=checksum_enabled,
                                   demo_mode=demo_mode,
                                   fips_compliance_enabled=fips_compliance_enabled,
                                   bind_probe_enabled=bind_probe_enabled,
                                   connect_probe_enabled=connect_probe_enabled,
                                   port_probe_timeout=port_probe_timeout,
                                   port_probe_connect_delay=port_probe_connect_delay,
                                   tls_outbound_ports=tls_outbound_ports)

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
        if kafka_publisher is not None:
            kafka_publisher.close()
        health.stop()
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        if kafka_publisher is not None:
            kafka_publisher.close()
        health.stop()
        sys.exit(1)


if __name__ == '__main__':
    main()
