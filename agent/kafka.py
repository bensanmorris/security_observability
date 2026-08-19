import json
import logging
import threading
import time
from datetime import datetime
from typing import Optional

from prometheus_client import Counter, Gauge

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

_kafka_connected_at_timestamp = Gauge(
    'kafka_connected_at_timestamp_seconds',
    'Unix timestamp of the last successful Kafka producer connection',
    ['node_name'],
)

_kafka_last_published_timestamp = Gauge(
    'kafka_last_published_timestamp_seconds',
    'Unix timestamp of the last message successfully acked by the broker',
    ['node_name'],
)

# Bumped only when the message schema itself breaks compatibility (a field is
# renamed, removed, or changes type) -- not on every release. Deliberately
# separate from CERT_ANALYZER_VERSION, which bumps on every release whether
# or not the payload shape changed; consumers should gate on this instead.
KAFKA_SCHEMA_VERSION = 1

# Static field -> (Kafka Connect JSON Schema type, optional) map for the
# certificate_discovered message, used to build the Connect envelope
# ({"schema": ..., "payload": ...}) published to [kafka] connect_topic when
# connect_enabled=true. Deliberately hand-maintained and built once (not
# inferred per-message from a live dict): several fields below are legitimately
# None on some messages (container_pid, container_start_time, key_usage,
# extended_key_usage, is_ca, basic_constraints_path_length), and a None value
# carries no type information to infer from. Kafka Connect's JSON converter
# also expects every record's "schema" to be structurally identical on a
# topic, so a schema built fresh per message would be actively wrong, not
# just wasteful. 'array_string' is a local sentinel expanded by
# _build_connect_schema() into a Connect "array" of "string" -- not a real
# Connect type name. Keep in sync with the message dict built in publish().
#
# A breaking change to this field set (rename/remove/retype) must ship as a
# new [kafka] connect_topic value (e.g. cert-analyzer-events-connect-v2), not
# an in-place change -- Kafka Connect sink connectors don't tolerate schema
# drift on a topic the way KAFKA_SCHEMA_VERSION lets plain-JSON consumers
# tolerate new fields. See extras/kafka/CONSUMER-README.md.
_CONNECT_SCHEMA_FIELDS = [
    ('schema_version',    'int32',  False),
    ('event_type',        'string', False),
    ('detected_at',       'string', False),
    ('path',               'string', False),
    ('cert_index',         'int32',  False),
    ('subject',             'string', False),
    ('issuer',              'string', False),
    ('serial_number',       'string', False),
    ('common_name',         'string', False),
    ('san_dns_names',       'array_string', False),
    ('san_ip_addresses',    'array_string', False),
    ('not_before',          'string', False),
    ('not_after',           'string', False),
    ('days_until_expiry',   'float64', False),
    ('is_expired',          'boolean', False),
    ('process',             'string', False),
    ('pid',                 'int32',  False),
    ('parent_process',      'string', False),
    ('parent_pid',          'int32',  False),
    ('namespace',                  'string', False),
    ('pod_name',                   'string', False),
    ('pod_uid',                    'string', False),
    ('node_name',                  'string', False),
    # JSON-encoded string in the Connect envelope -- Connect's JSON schema has
    # no map type a stock JDBC sink can flatten into columns without a custom
    # SMT. Decode client-side. See extras/kafka/CONSUMER-README.md.
    ('pod_annotations',            'string', False),
    ('workload_kind',              'string', False),
    ('workload_name',              'string', False),
    ('app_label',                  'string', False),
    ('container_id',               'string', False),
    ('container_name',             'string', False),
    ('container_image',            'string', False),
    ('container_image_id',         'string', False),
    ('container_privileged',       'boolean', False),
    ('container_pid',              'int32',  True),
    ('container_start_time',       'string', True),
    ('container_maybe_exec_probe', 'boolean', False),
    ('checksum',          'string', False),
    ('spki_hash',         'string', False),
    ('key_algorithm',     'string', False),
    ('key_size',          'int32',  False),
    ('signature_hash',    'string', False),
    ('curve_name',        'string', False),
    ('fips_compliant',    'boolean', False),
    ('fips_violations',   'array_string', False),
    ('spki_algorithm_oid',      'string', False),
    ('signature_algorithm_oid', 'string', False),
    ('key_usage',                     'array_string', True),
    ('extended_key_usage',            'array_string', True),
    ('is_ca',                         'boolean', True),
    ('basic_constraints_path_length', 'int32',  True),
    ('is_self_signed',                'boolean', False),
]


def _build_connect_schema() -> dict:
    """
    Build the Kafka Connect JSON Schema "schema" struct for the
    certificate_discovered Connect envelope, from _CONNECT_SCHEMA_FIELDS.
    Called once per KafkaPublisher instance (when connect_enabled) and
    cached -- never rebuilt per message.
    """
    fields = []
    for name, connect_type, optional in _CONNECT_SCHEMA_FIELDS:
        if connect_type == 'array_string':
            fields.append({
                'field': name,
                'type': 'array',
                'items': {'type': 'string', 'optional': False},
                'optional': optional,
            })
        else:
            fields.append({
                'field': name,
                'type': connect_type,
                'optional': optional,
            })
    return {
        'type': 'struct',
        'name': 'io.certanalyzer.CertificateDiscovered',
        'optional': False,
        'fields': fields,
    }


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
    concurrent send(). _on_error also carries the specific producer instance
    its send() was issued from, so a delayed errback for a producer that's
    since been superseded by a reconnect can't nullify the new one.

    The lock is only ever held for pointer reads/writes, never across a
    blocking producer call (send(), close(), or the KafkaProducer constructor).
    kafka-python's Sender thread invokes success/error callbacks synchronously
    from inside its own send/complete path, so holding self._lock across a
    blocking call here would risk that Sender thread stalling on self._lock
    inside _on_error while the thread holding the lock is itself blocked
    waiting on that same Sender thread to make progress (e.g. to free
    accumulator buffer memory or complete a join() during close()).

    Message schema (all fields present, empty string when not applicable):
    {
        "schema_version":   1,
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
        "spki_hash":        "",
        "key_algorithm":    "RSA",
        "key_size":         2048,
        "signature_hash":   "sha256",
        "curve_name":       "",
        "fips_compliant":   true,
        "fips_violations":  [],
        "spki_algorithm_oid":      "1.2.840.113549.1.1.1",
        "signature_algorithm_oid": "1.2.840.113549.1.1.11",
        "key_usage":                     ["digital_signature", "key_encipherment"],
        "extended_key_usage":            ["server_auth", "client_auth"],
        "is_ca":                         false,
        "basic_constraints_path_length": null,
        "is_self_signed":                false
    }

    Optionally, when connect_enabled=true, every certificate_discovered event
    above is additionally published to connect_topic wrapped in a Kafka
    Connect JSON envelope ({"schema": {...}, "payload": {...}}, the shape
    org.apache.kafka.connect.json.JsonConverter with schemas.enable=true
    expects) so a stock Kafka Connect JDBC Sink connector can consume it with
    no custom code. Off by default; purely additive -- the plain-JSON message
    above and its topic are unaffected either way. See _CONNECT_SCHEMA_FIELDS
    and extras/kafka/CONSUMER-README.md for the envelope's field types and
    the Kafka-message-key convention (node_name:path:cert_index, chosen for
    upsert correctness -- see extras/kafka/INTEGRATION-BRIEF.md).
    """

    def __init__(
        self,
        bootstrap_servers: str,
        topic: str,
        access_topic: str = '',
        connect_topic: str = '',
        security_protocol: str = 'PLAINTEXT',
        sasl_mechanism: str = '',
        sasl_username: str = '',
        sasl_password: str = '',  # nosec B107 - empty-string "not set" placeholder, not a credential
    ):
        self.bootstrap_servers = bootstrap_servers
        self._topic = topic
        # Empty string means certificate_accessed publishing is disabled --
        # see access_enabled below. One producer serves both topics; there's
        # no need for a second KafkaProducer/TCP connection per topic.
        self._access_topic = access_topic
        self.access_enabled = bool(access_topic)
        # Same empty-string-means-disabled convention as access_topic above.
        # Schema is built once here (not per message) since it's static --
        # see _build_connect_schema().
        self._connect_topic = connect_topic
        self.connect_enabled = bool(connect_topic)
        self._connect_schema = _build_connect_schema() if self.connect_enabled else None
        self._producer: Optional['KafkaProducer'] = None
        self._producer_kwargs: dict = {}
        self._last_connect_attempt: float = 0.0
        self._reconnect_cooldown: float = 30.0  # seconds between reconnect attempts
        # Guards reads/writes of self._producer and self._last_connect_attempt
        # only. Held only for quick pointer swaps, NEVER across a blocking
        # producer call (send()/close()/KafkaProducer()) — kafka-python's
        # Sender thread invokes _on_error synchronously off its own I/O thread,
        # and _on_error needs this lock, so a blocking call made while holding
        # it could deadlock against that Sender thread (see class docstring).
        # No code path currently re-enters this lock from the same thread, but
        # it's an RLock rather than a plain Lock as a defensive margin: if some
        # future change did accidentally nest an acquisition, a plain Lock
        # would hang silently, whereas RLock just works.
        #
        # Lock ordering: wherever both locks are held, self._connect_lock is
        # always acquired first and self._lock nested inside it (see
        # _connect() and publish()) — never the reverse — so the two locks
        # can't deadlock against each other.
        self._lock = threading.RLock()
        # Serializes _connect() attempts so concurrent publish() callers don't
        # race into constructing multiple producers. Deliberately a separate
        # lock from self._lock (which _on_error also needs): _connect() holds
        # this one across the slow, blocking close()/KafkaProducer() calls,
        # and self._lock must stay free-able by _on_error the whole time.
        # RLock because publish() holds it across its own re-check-then-connect
        # sequence and, within that, calls self._connect() — which acquires it
        # again on the same thread.
        self._connect_lock = threading.RLock()

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

        Manages its own locking — callers must NOT hold self._lock across
        this call. Closing the old producer and constructing the new one can
        block on network I/O, and doing that while holding self._lock would
        risk deadlocking against another producer's Sender thread trying to
        invoke _on_error (see class docstring). self._connect_lock (held for
        the full duration, unlike self._lock) serializes concurrent callers
        so only one reconnect attempt is ever in flight.
        """
        with self._connect_lock:
            with self._lock:
                now = time.time()
                if now - self._last_connect_attempt < self._reconnect_cooldown:
                    return False
                self._last_connect_attempt = now
                old_producer = self._producer
                self._producer = None

            # Close any existing broken producer before reconnecting
            if old_producer is not None:
                try:
                    old_producer.close(timeout=2)
                except Exception:
                    pass  # nosec B110 - best-effort close of an already-broken producer being replaced; a failure here changes nothing

            try:
                producer = KafkaProducer(**self._producer_kwargs)
            except Exception as e:
                logger.warning(
                    f"Kafka producer connection failed (will retry in "
                    f"{int(self._reconnect_cooldown)}s): {e}"
                )
                return False

            label = bootstrap_servers or str(self._producer_kwargs.get('bootstrap_servers', ''))
            label_topic = topic or self._topic
            if self._access_topic:
                label_topic = f"{label_topic}, {self._access_topic}"
            if self._connect_topic:
                label_topic = f"{label_topic}, {self._connect_topic}"
            logger.info(
                f"Kafka producer connected — "
                f"brokers: {label}, topics: {label_topic}"
            )
            _kafka_connected_at_timestamp.labels(node_name=_NODE_NAME).set(time.time())
            with self._lock:
                self._producer = producer
            return True

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
            'schema_version':    KAFKA_SCHEMA_VERSION,
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
            'spki_hash':         cert_info.spki_hash,
            'key_algorithm':     cert_info.key_algorithm,
            'key_size':          cert_info.key_size,
            'signature_hash':    cert_info.signature_hash,
            'curve_name':        cert_info.curve_name,
            'fips_compliant':    cert_info.fips_compliant,
            'fips_violations':   cert_info.fips_violations,
            'spki_algorithm_oid':      cert_info.spki_algorithm_oid,
            'signature_algorithm_oid': cert_info.signature_algorithm_oid,
            'key_usage':                     cert_info.key_usage,
            'extended_key_usage':            cert_info.extended_key_usage,
            'is_ca':                         cert_info.is_ca,
            'basic_constraints_path_length': cert_info.basic_constraints_path_length,
            'is_self_signed':                cert_info.is_self_signed,
        }

        # Use unique_key (path:cert_index:serial) as the partition key.
        self._send(self._topic, cert_info.unique_key, message, cert_info.path)

        if self.connect_enabled:
            envelope = self._to_connect_envelope(message)
            # node_name:path:cert_index, NOT unique_key -- this key drives an
            # upsert on the consumer side (typically a JDBC sink's
            # pk.mode=record_key), so it must uniquely identify "one row",
            # not just group related events. unique_key includes serial_number,
            # which would make every renewal a new row instead of updating the
            # existing one -- the opposite of what an expiry table wants. And
            # path:cert_index alone (the brief's own recommended *grouping*
            # key for this use case) would collide across every node running
            # an identical cert at the same path, silently collapsing a
            # fleet's worth of rows down to whichever node's event landed
            # last. See extras/kafka/INTEGRATION-BRIEF.md.
            connect_key = f"{cert_info.node_name}:{cert_info.path}:{cert_info.cert_index}"
            self._send(self._connect_topic, connect_key, envelope, cert_info.path)

    def publish_access(
        self,
        cert_info: CertificateInfo,
        process: str,
        pid: int,
        parent_process: str,
        parent_pid: int,
        namespace: str = '',
        pod_name: str = '',
        pod_uid: str = '',
        node_name: str = '',
        app_label: str = '',
        container_name: str = '',
        container_id: str = '',
        container_image: str = '',
    ) -> None:
        """
        Publish a certificate_accessed event for a distinct process/pod
        re-accessing an already-known certificate.

        No-op unless access_topic was configured (access_enabled is False by
        default — see [kafka] access_enabled in cert-analyzer.conf). Callers
        are expected to have already deduplicated per (process, parent_process,
        pod_name, namespace, app_label, container_name) — see
        CertificateAnalyzer._record_cert_process_access — so this fires once
        per distinct accessor per cert, not once per raw file-access event.

        Deliberately excludes cert metadata (subject, SANs, key info, FIPS
        flags, ...) already carried by the certificate_discovered event on
        the main topic; consumers join on cert_unique_key.

        Message schema:
        {
            "schema_version":  1,
            "event_type":      "certificate_accessed",
            "accessed_at":     "2026-03-31T10:00:00.000000",   # ISO 8601 UTC
            "cert_unique_key": "...",
            "path":            "/etc/pki/tls/certs/ca-bundle.crt",
            "cert_index":      0,
            "serial_number":   "abc123",
            "process":         "/usr/bin/curl",
            "pid":             12345,
            "parent_process":  "/usr/bin/bash",
            "parent_pid":      12300,
            "namespace":       "default",
            "pod_name":        "my-pod-abc",
            "pod_uid":         "...",
            "node_name":       "...",
            "app_label":       "my-app",
            "container_name":  "main",
            "container_id":    "...",
            "container_image": "my-app:1.0"
        }
        """
        if not KAFKA_AVAILABLE or not self.access_enabled:
            return

        message = {
            'schema_version':   KAFKA_SCHEMA_VERSION,
            'event_type':       'certificate_accessed',
            'accessed_at':      datetime.utcnow().isoformat(),
            'cert_unique_key':  cert_info.unique_key,
            'path':             cert_info.path,
            'cert_index':       cert_info.cert_index,
            'serial_number':    cert_info.serial_number,
            'process':          process,
            'pid':              pid,
            'parent_process':   parent_process,
            'parent_pid':       parent_pid,
            'namespace':        namespace,
            'pod_name':         pod_name,
            'pod_uid':          pod_uid,
            'node_name':        node_name,
            'app_label':        app_label,
            'container_name':   container_name,
            'container_id':     container_id,
            'container_image':  container_image,
        }

        self._send(self._access_topic, cert_info.unique_key, message, cert_info.path)

    def _to_connect_envelope(self, message: dict) -> dict:
        """
        Wrap a certificate_discovered message dict in the Kafka Connect JSON
        envelope ({"schema": self._connect_schema, "payload": ...}). Returns
        a new dict -- never mutates `message`, which the caller also sends
        unwrapped to the plain-JSON topic.
        """
        payload = dict(message)
        payload['pod_annotations'] = json.dumps(payload.get('pod_annotations') or {})
        return {'schema': self._connect_schema, 'payload': payload}

    def _send(self, topic: str, key: str, message: dict, log_label: str) -> None:
        """
        Shared connect-check-then-send path for publish() and publish_access().
        log_label is only used for the warning logged on a send failure.
        """
        with self._lock:
            producer = self._producer
            needs_connect = producer is None

        if needs_connect:
            # Attempt reconnection if producer is absent. _connect_lock
            # serializes this whole check-then-connect sequence across
            # concurrent publish() callers: whichever thread gets here first
            # does the actual connect; by the time the rest acquire the lock,
            # self._producer is already set and they just reuse it instead of
            # each constructing their own producer. Deliberately not
            # self._lock (see class docstring) — this can block for as long
            # as the KafkaProducer constructor takes.
            with self._connect_lock:
                with self._lock:
                    producer = self._producer
                    needs_connect = producer is None
                if needs_connect:
                    if not self._connect():
                        return
                    with self._lock:
                        producer = self._producer
                        if producer is None:
                            return

        # send() is issued outside self._lock: it can block (e.g. waiting for
        # accumulator buffer space) on progress from the producer's Sender
        # thread, and that same Sender thread invokes _on_error synchronously
        # when completing/failing a batch. Holding self._lock here would risk
        # that Sender thread stalling on self._lock inside _on_error while
        # this thread is blocked waiting on the Sender thread — see class
        # docstring.
        try:
            future = producer.send(
                topic,
                key=key,
                value=message,
            )
            future.add_callback(self._on_success)
            future.add_errback(lambda exc, _producer=producer: self._on_error(_producer, exc))
        except Exception as e:
            logger.warning(f"Kafka publish failed for {log_label}: {e}")
            # Nullify the producer so the next publish attempt triggers reconnect
            with self._lock:
                if self._producer is producer:
                    self._producer = None

    def _on_success(self, _record_metadata) -> None:
        # kafka-python invokes this from its own I/O thread, same as _on_error --
        # it only ever sets a Gauge, which is thread-safe on its own, so no
        # locking is needed here.
        _kafka_last_published_timestamp.labels(node_name=_NODE_NAME).set(time.time())

    def _on_error(self, producer, exc: Exception) -> None:
        # kafka-python invokes errbacks from its own internal I/O thread, so this
        # can run concurrently with publish()/close() on other threads, and can
        # fire long after the send() call that registered it -- kafka-python
        # retries internally before giving up, so the callback for an old send()
        # can land well after a later reconnect has already installed a new,
        # healthy producer. `producer` is the specific instance this failure
        # came from (captured at send() time); only nullify self._producer if
        # it's still that same instance, so a stale error from an
        # already-superseded producer can't tear down a newer one.
        logger.warning(f"Kafka delivery error: {exc}")
        _kafka_delivery_errors.labels(node_name=_NODE_NAME).inc()
        # Nullify the producer so the next publish attempt triggers reconnect.
        # Without this, a broker that drops messages in-flight (broker down,
        # auth failure, topic deleted) would leave the producer in a state where
        # send() appears to succeed but nothing is ever delivered.
        with self._lock:
            if self._producer is producer:
                self._producer = None

    def close(self) -> None:
        """Flush pending messages and close the producer cleanly."""
        with self._lock:
            producer = self._producer
            self._producer = None
        # flush()/close() can block for the full timeout — do this outside
        # self._lock so a concurrent publish()/_on_error() only has to wait
        # for the quick pointer swap above, not the whole drain.
        if producer is not None:
            try:
                producer.flush(timeout=5)
                producer.close()
            except Exception as e:
                logger.warning(f"Error closing Kafka producer: {e}")
