import json
import logging
import threading
import time
from datetime import datetime
from typing import Optional

from prometheus_client import Counter

from .constants import _NODE_NAME
from .models import CertificateInfo

logger = logging.getLogger(__name__)

# Import Kafka producer - optional, degrades gracefully if unavailable.
# When disabled (default) the analyzer publishes to Prometheus only.
# Enable via [kafka] enabled = true in cert-analyzer.conf or KAFKA_ENABLED=true.
# Install with: pip install kafka-python
KafkaProducer = None  # always defined so patch('agent.kafka.KafkaProducer') works
KafkaError = None     # regardless of whether kafka-python is installed
try:
    from kafka import KafkaProducer
    from kafka.errors import KafkaError
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

_kafka_delivery_errors = Counter(
    'kafka_delivery_errors_total',
    'Total number of Kafka message delivery failures (async, broker-side)',
    ['node_name'],
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

    Thread-safety: publish() may be called concurrently from the main Tetragon
    event-consumer thread, the periodic_scan thread, and any number of
    large-file background parsing threads. An RLock guards every read/write of
    self._producer and self._last_connect_attempt (including the async
    _on_error errback, which kafka-python invokes from its own I/O thread) so
    reconnects can't race and a producer can't be closed out from under a
    concurrent send().

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
        self._lock = threading.RLock()

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

        with self._lock:
            self._connect(bootstrap_servers, topic)

    def _connect(self, bootstrap_servers: str = '', topic: str = '') -> bool:
        """
        Attempt to create a KafkaProducer. Returns True on success.
        Respects a cooldown period to avoid hammering a down broker.

        Caller must hold self._lock — this reads and writes self._producer
        and self._last_connect_attempt without its own locking.
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

    def publish(self, cert_info: CertificateInfo) -> None:
        """
        Publish a new certificate discovery event.

        Delivery is asynchronous — the producer's internal send queue handles
        batching and retries. If the producer is unavailable (e.g. broker
        restarted) a reconnect is attempted subject to a cooldown period.
        Errors are always logged as warnings and never raised.
        """
        if not KAFKA_AVAILABLE:
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
        key = cert_info.unique_key

        with self._lock:
            # Attempt reconnection if producer is absent
            if self._producer is None:
                if not self._connect():
                    return

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
        # kafka-python invokes errbacks from its own internal I/O thread, so
        # this can run concurrently with publish()/close() on other threads.
        logger.warning(f"Kafka delivery error: {exc}")
        _kafka_delivery_errors.labels(node_name=_NODE_NAME).inc()
        # Nullify the producer so the next publish attempt triggers reconnect.
        # Without this, a broker that drops messages in-flight (broker down,
        # auth failure, topic deleted) would leave the producer in a state where
        # send() appears to succeed but nothing is ever delivered.
        with self._lock:
            self._producer = None

    def close(self) -> None:
        """Flush pending messages and close the producer cleanly."""
        with self._lock:
            if self._producer is not None:
                try:
                    self._producer.flush(timeout=5)
                    self._producer.close()
                except Exception as e:
                    logger.warning(f"Error closing Kafka producer: {e}")
                self._producer = None
