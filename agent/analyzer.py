import grpc
import logging
import random
import threading
import time
from collections import deque
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Optional, Set, Tuple

if TYPE_CHECKING:
    from .health import HealthServer

# _fips_check/_get_algorithm_oids are no longer called directly in this file
# (their callers moved to agent/cert_parsing.py) but stay imported here too --
# test_cert_analyzer.py monkeypatches them via agent.analyzer._fips_check /
# agent.analyzer._get_algorithm_oids, and agent/cert_parsing.py reads them
# back off this module's namespace at call time for exactly that reason (see
# its own comment on the deferred `from . import analyzer` there).
from .fips_compliance_checker import (
    check_certificate as _fips_check,
    get_algorithm_oids as _get_algorithm_oids,
)

# Import generated Tetragon protos. sensors_pb2 itself is no longer used
# directly in this file (its callers moved to agent/tetragon_monitor.py) but
# stays imported here too -- test_cert_analyzer.py monkeypatches it via
# agent.analyzer.sensors_pb2 (e.g. monkeypatch.delattr), which needs the name
# bound in this module's namespace even though the module object itself is
# the same singleton tetragon_monitor.py imports and actually reads from.
try:
    from tetragon import tetragon_pb2, events_pb2, sensors_pb2, sensors_pb2_grpc
except ImportError as _tetragon_err:
    raise ImportError(
        "Tetragon protobuf files not found. Run extras/generate_tetragon_protos.sh first."
    ) from _tetragon_err

# Import JKS parser - optional, degrades gracefully if unavailable
# Install with: pip install pyjks
try:
    import jks
    JKS_AVAILABLE = True
except ImportError:
    JKS_AVAILABLE = False

from .constants import _NODE_NAME, TETRAGON_BUILD_VERSION
from .models import CertificateInfo
from .metrics import PrometheusMetrics
from .cache import LRUCache
from .kafka import KafkaPublisher
from .java_fips import _JavaFipsMixin
from .tls_probe import _TlsProbeMixin
from .tetragon_monitor import _TetragonMonitorMixin
from .event_context import _EventContextMixin
from .cert_parsing import _CertParsingMixin
from .retry_queue import _TokenBucket, _RateLimitRetryQueueMixin

logger = logging.getLogger(__name__)


class CertificateAnalyzer(
    _JavaFipsMixin, _TlsProbeMixin, _TetragonMonitorMixin, _EventContextMixin,
    _CertParsingMixin, _RateLimitRetryQueueMixin,
):
    """
    Main analyzer that processes Tetragon events and extracts certificate info.

    Composed from mixins split out of this file, each in its own module and
    each documenting which methods it contributes and what shared instance
    state it expects from __init__ below: _JavaFipsMixin (agent/java_fips.py,
    PKCS11/NSS + in-memory-cert uprobe handlers), _TlsProbeMixin
    (agent/tls_probe.py, port-scanner-like TLS cert discovery),
    _TetragonMonitorMixin (agent/tetragon_monitor.py, version/policy checks +
    their monitor threads), _EventContextMixin (agent/event_context.py,
    Tetragon event/pod-context extraction + cert-status logging),
    _CertParsingMixin (agent/cert_parsing.py, PEM/DER/JKS/PKCS12 parsing +
    info extraction), _RateLimitRetryQueueMixin (agent/retry_queue.py,
    new-cert rate limiter + retry queue). This file itself keeps __init__,
    cache bookkeeping, concurrency helpers shared across mixins, the
    process_event dispatcher, and the main start()/periodic_scan() loops.
    """

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
        2376,  # Docker daemon TLS
        4443,  # HTTPS alternate
        5671,  # AMQP/TLS
        5672,  # AMQP (often TLS)
        5986,  # WinRM HTTPS
        6380,  # Redis TLS
        6443,  # Kubernetes API server
        8140,  # Puppet
        8443,  # HTTPS alternate
        8883,  # MQTT/TLS
        9093,  # Kafka TLS
        9094,  # Kafka TLS alternate
        9443,  # HTTPS alternate
    })

    # Bounds how long connect-probe's background thread will poll for a
    # same-PID SSL_ctrl capture before giving up and falling back to the raw
    # IP as SNI. The tcp_connect kprobe event (which schedules the probe) and
    # the SSL_ctrl uprobe event (which populates _recent_client_sni) are
    # emitted microseconds apart by the same process, but arrive over
    # Tetragon's gRPC stream and are handled by process_event independently
    # -- a single point-in-time cache check right after the probe thread
    # starts can run before the SSL_ctrl event has even been processed,
    # silently defeating the capture even though it's about to land. Polling
    # briefly instead closes that window; this runs on the probe's own
    # background thread, never the single-threaded process_event dispatch
    # loop, so it can't delay any other event's processing.
    _SNI_CAPTURE_POLL_INTERVAL_SECONDS = 0.02
    _SNI_CAPTURE_POLL_MAX_SECONDS = 0.25

    def __init__(self, tetragon_address: str, alert_threshold_days: int = 30,
                 filter_self_events: bool = True,
                 health_server: Optional['HealthServer'] = None,
                 host_prefix: str = '',
                 kafka_publisher: Optional[KafkaPublisher] = None,
                 checksum_enabled: bool = False,
                 spki_hash_enabled: bool = True,
                 demo_mode: bool = False,
                 fips_compliance_enabled: bool = True,
                 event_rate_metrics_enabled: bool = False,
                 bind_probe_enabled: bool = False,
                 connect_probe_enabled: bool = False,
                 port_probe_timeout: float = 5.0,
                 port_probe_connect_delay: float = 2.0,
                 tls_outbound_ports: Optional[frozenset] = None,
                 sni_capture_enabled: bool = False,
                 sni_capture_window_seconds: float = 2.0,
                 large_file_cert_threshold: int = 20,
                 large_file_metrics_cap: int = 300,
                 large_file_byte_cap: int = 2 * 1024 * 1024,
                 max_concurrent_background_threads: int = 20,
                 max_processes_per_cert: int = 20,
                 new_cert_events_per_second: float = 50.0,
                 uprobe_cert_events_per_second: float = 50.0,
                 retry_queue_max_size: int = 2000,
                 scan_paths: Optional[list] = None,
                 scan_interval_seconds: int = 3600,
                 metrics_port: int = 9090):
        self.tetragon_address = tetragon_address
        self.alert_threshold_days = alert_threshold_days
        self.filter_self_events = filter_self_events
        self.host_prefix = host_prefix
        self.kafka_publisher = kafka_publisher
        self.checksum_enabled = checksum_enabled
        self.spki_hash_enabled = spki_hash_enabled
        self.demo_mode = demo_mode
        self.fips_compliance_enabled = fips_compliance_enabled
        self._event_rate_metrics_enabled = event_rate_metrics_enabled
        self._bind_probe_enabled = bind_probe_enabled
        self._connect_probe_enabled = connect_probe_enabled
        self._port_probe_timeout = port_probe_timeout
        self._port_probe_connect_delay = port_probe_connect_delay
        self._tls_outbound_ports = tls_outbound_ports if tls_outbound_ports is not None else self.TLS_OUTBOUND_PORTS
        self._sni_capture_enabled = sni_capture_enabled
        self._sni_capture_window_seconds = sni_capture_window_seconds
        self._large_file_cert_threshold = large_file_cert_threshold
        self._large_file_metrics_cap = large_file_metrics_cap
        self._large_file_byte_cap = large_file_byte_cap
        # Bounds how many TLS-probe / large-file-parse threads can run at once.
        # Without this, a burst of events (e.g. every pod on a node reconnecting
        # to its dependencies after a restart, each opening a distinct host:port
        # tls_outbound_port) spawns one raw OS thread per event with no limit.
        # A plain (non-bounded) Semaphore is fine here: every acquire() this
        # class makes is matched by exactly one release() in the worker's
        # finally block, so it can never over-release.
        self._max_concurrent_background_threads = max_concurrent_background_threads
        self._background_thread_semaphore = threading.Semaphore(max_concurrent_background_threads)
        # Bounds the number of distinct (process, parent_process) pairs
        # tracked in tls_certificate_process_info per cert. Without this, a
        # file opened by many unrelated binaries over the life of the process
        # (e.g. the system CA trust bundle touched by curl, dnf, git, python,
        # docker, ...) accumulates one permanent series per distinct process,
        # forever — unbounded regardless of known_certs cache size, since the
        # cert entry itself may never be evicted. See _record_cert_process_access.
        self._max_processes_per_cert = max_processes_per_cert
        # Caps how many never-before-seen certificate files can be fully
        # parsed/extracted/cached per second, regardless of source (real-time
        # Tetragon events, periodic_scan, or the large-file background-thread
        # path -- all four trigger points, including the retry queue below,
        # funnel through _analyze_and_finish_new_certificate_file() /
        # _try_process_new_certificate_file(), the single choke point this
        # gates). Re-accesses of already-known paths are cheap and NOT gated
        # here; this only bounds the cost of onboarding new certs, which is
        # the part an attacker can drive purely by generating distinct
        # certificate content/paths, with no config access.
        self._new_cert_rate_limiter = _TokenBucket(new_cert_events_per_second)
        self._rate_limit_log_lock = threading.Lock()
        self._rate_limit_last_log_time = 0.0
        self._rate_limit_dropped_since_log = 0
        # Separate token bucket for the PKCS11/NSS and in-memory-DER uprobe
        # discovery paths (agent/java_fips.py): those bypass
        # _new_cert_rate_limiter entirely (see the comment on
        # _handle_nsc_create_object) and are deduped only on a synthetic
        # pid+serial path, trivially defeated by a compromised/malicious
        # process on the node varying the injected certificate's serial
        # number on every call -- with no limiter of its own, that path had
        # no ceiling on how much extract_certificate_info/logging/Kafka-
        # publish work it could force per second. Kept as its own bucket
        # rather than sharing _new_cert_rate_limiter's so a flood of forged
        # uprobe captures can't also starve real file-based cert discovery
        # of its budget.
        self._uprobe_cert_rate_limiter = _TokenBucket(uprobe_cert_events_per_second)
        self._uprobe_rate_limit_log_lock = threading.Lock()
        self._uprobe_rate_limit_last_log_time = 0.0
        self._uprobe_rate_limit_dropped_since_log = 0
        # A rate-limited file isn't dropped -- it's queued here and replayed
        # by the retry-queue drainer thread once capacity frees up, with its
        # *original* triggering process/pod context intact (unlike
        # periodic_scan's rediscovery path, which only knows the path, not
        # who touched it). This is what makes "throttled but not lost" true
        # regardless of whether the path happens to fall under scan_paths --
        # relying on periodic_scan alone left files outside scan_paths with
        # no recovery path at all. Bounded FIFO: at capacity, the oldest
        # queued entry is dropped to make room, so this can't become a
        # second unbounded memory sink for the same abuse the rate limiter
        # itself defends against.
        self._retry_queue_max_size = retry_queue_max_size
        self._retry_queue: deque = deque()
        self._retry_queue_paths: Set[str] = set()
        self._retry_queue_lock = threading.Lock()
        self._scan_paths = list(scan_paths) if scan_paths else []
        self._scan_interval_seconds = scan_interval_seconds
        self.metrics = PrometheusMetrics(node_name=_NODE_NAME)
        self.metrics.config_info.labels(node_name=_NODE_NAME).info({
            'checksum_enabled':                  str(checksum_enabled).lower(),
            'spki_hash_enabled':                 str(spki_hash_enabled).lower(),
            'demo_mode':                         str(demo_mode).lower(),
            'fips_compliance_enabled':            str(fips_compliance_enabled).lower(),
            'filter_self_events':                str(filter_self_events).lower(),
            'event_rate_metrics_enabled':         str(event_rate_metrics_enabled).lower(),
            'bind_probe_enabled':                 str(bind_probe_enabled).lower(),
            'connect_probe_enabled':              str(connect_probe_enabled).lower(),
            'port_probe_timeout':                 str(port_probe_timeout),
            'port_probe_connect_delay':            str(port_probe_connect_delay),
            'tls_outbound_ports':                  ','.join(str(p) for p in sorted(self._tls_outbound_ports)),
            'sni_capture_enabled':                 str(sni_capture_enabled).lower(),
            'sni_capture_window_seconds':          str(sni_capture_window_seconds),
            'large_file_cert_threshold':           str(large_file_cert_threshold),
            'large_file_metrics_cap':              str(large_file_metrics_cap),
            'large_file_byte_cap':                 str(large_file_byte_cap),
            'max_concurrent_background_threads':   str(max_concurrent_background_threads),
            'new_cert_events_per_second':          str(new_cert_events_per_second),
            'uprobe_cert_events_per_second':       str(uprobe_cert_events_per_second),
            'retry_queue_max_size':                str(retry_queue_max_size),
            'max_processes_per_cert':              str(max_processes_per_cert),
            'alert_threshold_days':                str(alert_threshold_days),
            'scan_paths':                          ','.join(self._scan_paths),
            'kafka_enabled':                       str(kafka_publisher is not None).lower(),
            'kafka_bootstrap_servers':              kafka_publisher.bootstrap_servers if kafka_publisher is not None else '',
            'kafka_plain_enabled':                  str(kafka_publisher.plain_enabled).lower() if kafka_publisher is not None else 'false',
            'kafka_connect_enabled':                str(kafka_publisher.connect_enabled).lower() if kafka_publisher is not None else 'false',
            'prometheus_port':                     str(metrics_port),
        })
        self.metrics.scan_interval_seconds.labels(node_name=_NODE_NAME).set(scan_interval_seconds)
        # cert_path -> set of known_certs keys for that path. Lets process_event's
        # "already known" check do an O(1) dict lookup instead of scanning every
        # entry in known_certs (which used to cost real, sustained CPU once the
        # cache grew past a few hundred entries — see _index_known_cert below).
        # Not GIL-atomic like the sets below: building it is a setdefault()+add()
        # pair, not a single op, so it needs its own lock.
        self._known_paths: Dict[str, Set[str]] = {}
        self._known_paths_lock = threading.Lock()
        # known_certs[unique_key] = cert_info is written from several threads
        # (the event-consumer thread, probe threads, the retry-queue drainer,
        # and large-file background workers) with no lock at any call site --
        # safe only because LRUCache guards every public method (including
        # __setitem__) with its own internal RLock. Don't add a second lock
        # around these call sites; it would just be redundant. (Reading a
        # cert_info's fields back out after it's cached is a separate concern
        # -- see the comment on the known-file re-access mutation in
        # process_event.)
        self.known_certs: LRUCache = LRUCache(
            on_set=self._index_known_cert, on_evict=self._deindex_known_cert
        )
        self.processed_paths: LRUCache = LRUCache()
        # Paths that failed password attempts — cached to avoid repeating expensive
        # crypto operations on every subsequent Tetragon event for the same file.
        # LRU eviction gives previously-failed paths a second chance after enough
        # other activity, which is desirable if JKS_PASSWORD has since been set.
        # Caveat: in a small deployment with few distinct keystores, other
        # cache activity may never push a failed entry out before the operator
        # notices and fixes the password. There's no active eviction/TTL here,
        # so today the only ways to force a retry after fixing
        # JKS_PASSWORD/PKCS12_PASSWORD are restarting the analyzer or waiting
        # for enough unrelated cache churn to evict the entry naturally.
        self.password_failed_paths: LRUCache = LRUCache()
        self.health_server = health_server
        self._known_policy_labels: Set[Tuple[str, str, str, str]] = set()
        # Per-endpoint deduplication for TLS port probes.
        # _probed_endpoints: "host:port" strings already probed — O(1) pre-check
        #   prevents thread creation for endpoints whose cert is already known.
        # _probe_in_flight: "host:port" strings currently being probed — prevents
        #   duplicate concurrent probes when several events for a new endpoint
        #   arrive before the first probe completes (e.g. connection pooling).
        # Individual set ops (in/add/discard) are GIL-atomic, but the check-then-add
        # at each call site is a *pair* of ops, and its discard() runs on a different
        # thread (the probe worker) than its check+add (the event-consumer thread) —
        # the GIL can switch between the check and the add, racing against a same-key
        # discard() completing in between, letting two probes get spawned for one
        # endpoint. Needs its own lock.
        self._probed_endpoints: LRUCache = LRUCache()
        self._probe_in_flight: Set[str] = set()
        self._probe_in_flight_lock = threading.Lock()
        # pid -> (hostname, captured_at) from the SSL_ctrl(cmd==55) uprobe --
        # the real SNI hostname a client process is about to send, captured
        # just before its own TLS handshake. Consulted (not actively expired;
        # staleness is checked against sni_capture_window_seconds at lookup
        # time in _probe_and_ingest_tls_cert) by connect-probe so it can dial
        # with the real hostname instead of the raw destination IP. See
        # _handle_ssl_ctrl_sni_capture. No extra lock needed -- LRUCache
        # already guards each individual get/set internally, and this is
        # only ever read/written as single atomic ops, never a compound
        # check-then-act sequence.
        self._recent_client_sni: LRUCache = LRUCache()
        # Paths whose large multi-cert file (see _count_pem_certs) is currently
        # being parsed on a background thread — de-dupes repeat Tetragon events
        # for the same path that arrive before the worker populates known_certs.
        self._large_file_in_flight: Set[str] = set()
        # Paths below _large_file_cert_threshold (so parsed synchronously rather
        # than via _process_certificate_file_async) that are currently being
        # analyzed for the first time. process_event() runs on a single thread
        # so it can't race against itself, but periodic_scan() runs on its own
        # thread and re-walks scan_paths independently — without this guard, a
        # file first seen at almost the same moment by both a Tetragon event and
        # a periodic scan tick (most likely right after agent startup) would get
        # parsed and _finish_new_certificate_file'd twice, double-publishing it
        # to Kafka as two separate "new discovery" events.
        self._new_file_in_flight: Set[str] = set()
        # Both sets above share this one lock rather than a lock each. A brand
        # new path's _count_pem_certs verdict (sync vs background-thread
        # routing) is only stable for a static file — if the file is actively
        # growing, two near-simultaneous events for the same never-before-seen
        # path can get different verdicts and race into *different* in-flight
        # sets, so neither set alone would catch the duplicate. Every
        # check-then-claim below checks both sets before adding to either,
        # which only works if that check-and-add is atomic across both sets —
        # hence one shared lock instead of two independent ones. Without this,
        # both mechanisms would independently analyze_certificate() the same
        # path and both write known_certs[key] = <their own CertificateInfo
        # instance> for the same resulting key(s); LRUCache.__setitem__ only
        # invokes on_evict for its own LRU-pop eviction, never for a same-key
        # overwrite, so whichever write lands second would silently replace
        # the first with no Prometheus series cleanup for the value it
        # replaced.
        self._new_path_lock = threading.Lock()
        self.last_event_time: float = 0.0

    def _index_known_cert(self, key: str, value) -> None:
        """
        known_certs on_set callback: record `key` under its cert's path in
        _known_paths. `value` is the CertificateInfo being stored (or, in tests
        that seed known_certs directly, sometimes None/a bare object) — anything
        without a `.path` just isn't indexed, which only degrades that entry back
        to "not found by process_event's known-file check", not a crash.
        """
        path = getattr(value, 'path', None)
        if path is None:
            return
        with self._known_paths_lock:
            self._known_paths.setdefault(path, set()).add(key)

    def _deindex_known_cert(self, key: str, value) -> None:
        """
        known_certs on_evict callback — the inverse of _index_known_cert, plus
        removing the evicted cert's Prometheus series so metric memory tracks
        cache occupancy instead of growing for the life of the process (see
        PrometheusMetrics.remove_certificate_metrics).
        """
        path = getattr(value, 'path', None)
        if path is None:
            return
        with self._known_paths_lock:
            keys_for_path = self._known_paths.get(path)
            if keys_for_path is not None:
                keys_for_path.discard(key)
                if not keys_for_path:
                    del self._known_paths[path]
        try:
            self.metrics.remove_certificate_metrics(value)
        except Exception as e:
            # value may be a bare/partial object in tests that seed known_certs
            # directly — degrade to a leaked series rather than crashing the
            # thread that's mutating the cache (event consumer, periodic scan,
            # or a background parse worker).
            logger.debug(f"Could not remove Prometheus metrics for evicted cert {key}: {e}")

    def _path_has_live_known_cert(self, cert_path: str) -> bool:
        """
        True if cert_path has at least one entry that's *actually* still
        present in known_certs right now -- not just listed in the
        _known_paths secondary index.

        _known_paths is populated/depopulated by known_certs's on_set/
        on_evict callbacks (_index_known_cert/_deindex_known_cert), which
        LRUCache invokes *after* releasing its own internal lock (see
        agent/cache.py's __setitem__) so it can't hold that lock across an
        arbitrary caller-supplied callback. That means _known_paths can be
        transiently stale relative to known_certs's real contents: a reader
        checking _known_paths_lock alone can catch a path as "known" a
        moment before it's actually inserted, or a moment after its last
        entry was actually evicted -- two independently-locked pieces of
        state that don't move together atomically.

        process_event's own known-file loop already tolerates this per-key
        (each iteration does its own known_certs.get() and skips a None
        gracefully); this is the same defensive check for callers --
        periodic_scan and the retry-queue drainer -- that only want a single
        yes/no answer and, critically, treat "yes" as a reason to skip work
        entirely. A false positive there would silently and *permanently*
        drop legitimate work rather than just delay it, so it's worth the
        extra known_certs lookups given neither caller is a per-event hot
        path.
        """
        with self._known_paths_lock:
            keys = list(self._known_paths.get(cert_path, ()))
        return any(self.known_certs.get(k) is not None for k in keys)

    def _update_cache_metrics(self) -> None:
        """Update Prometheus gauges reflecting current LRU cache occupancy."""
        self.metrics.cache_known_certs_size.labels(node_name=self.metrics._node_name).set(len(self.known_certs))
        self.metrics.cache_processed_paths_size.labels(node_name=self.metrics._node_name).set(len(self.processed_paths))
        self.metrics.cache_password_failed_size.labels(node_name=self.metrics._node_name).set(len(self.password_failed_paths))
        self.metrics.update_process_metrics()

    def _record_cert_process_access(self, cert_info: CertificateInfo, process: str, parent_process: str,
                                     pod_name: str = "", namespace: str = "",
                                     app_label: str = "", container_name: str = "") -> bool:
        """
        Record that `process` has accessed an already-known cert, capped at
        max_processes_per_cert distinct (process, parent_process, pod_name,
        namespace, app_label, container_name) tuples per cert.

        Returns True the first time this exact tuple is seen for this cert
        (the caller uses this to gate a one-time certificate_accessed Kafka
        event), False for a repeat access or one dropped by the cap.

        pod_name/namespace/app_label/container_name describe *this specific
        access* (the caller's current event), not cert_info's own pod fields —
        those are set once by whichever access first discovered the cert (see
        _apply_pod_context) and stay sticky to that discoverer even when a
        different pod later accesses the same cert, so they'd misattribute
        every subsequent access to the wrong pod if used here instead.

        Without this cap, a file opened by many unrelated binaries over the
        life of the process (e.g. the system CA trust bundle touched by curl,
        dnf, git, python, docker, ...) accumulates one permanent
        tls_certificate_process_info series per distinct process, forever —
        unlike the cert's own expiry/FIPS/self-signed metrics, this fan-out
        isn't bounded by known_certs' LRU size, since the cert entry itself
        may never get evicted while still being actively re-accessed.

        Only ever called from process_event, which runs on the single
        gRPC event-consumer thread, so cert_info._seen_processes needs no
        lock — nothing else mutates it after the initial seed in
        PrometheusMetrics.update_certificate_metrics.
        """
        key = (process, parent_process, pod_name, namespace, app_label, container_name)
        is_new = key not in cert_info._seen_processes
        if is_new:
            if len(cert_info._seen_processes) >= self._max_processes_per_cert:
                logger.debug(
                    "cert_process_info fan-out cap (%s) reached for %s — "
                    "not tracking additional process %r",
                    self._max_processes_per_cert, cert_info.path, process,
                )
                self.metrics.cert_analysis_errors.labels(error_type='process_fanout_cap_reached', node_name=self.metrics._node_name).inc()
                return False
            cert_info._seen_processes.add(key)
        self.metrics.record_cert_process_access(
            cert_info, process, parent_process, pod_name, namespace, app_label, container_name,
        )
        return is_new

    def _start_background_thread(self, target, name: str) -> bool:
        """
        Start a daemon thread for probe/large-file work, bounded by
        _background_thread_semaphore so a burst of events (many simultaneous
        TLS binds/connects, or several large CA bundles at once) can't spawn
        unbounded concurrent OS threads.

        Returns False without starting a thread if the concurrency cap is
        already reached. Callers already de-dupe via their own in-flight
        tracking before calling this, so a dropped attempt just means the
        same work is retried on a later event rather than queuing here.
        """
        if not self._background_thread_semaphore.acquire(blocking=False):
            logger.warning(
                f"Background thread cap ({self._max_concurrent_background_threads}) "
                f"reached, skipping {name}"
            )
            return False

        def _run():
            try:
                target()
            finally:
                self._background_thread_semaphore.release()

        threading.Thread(target=_run, daemon=True, name=name).start()
        return True

    def _process_certificate_file_async(
        self,
        cert_path: str,
        process_name: str,
        pid: int,
        namespace: str,
        tetragon_pod,
        parent_process: str,
        parent_pid: int,
        node_name: str,
    ) -> None:
        """
        Parse and extract a large multi-cert file on a background thread.

        Keeps the Tetragon event-consumer thread free to keep draining the
        gRPC stream while hundreds of certs (e.g. a system CA bundle) get
        parsed, instead of blocking it for the whole burst. _large_file_in_flight
        de-dupes repeat Tetragon events for the same path that arrive before the
        worker finishes and populates known_certs. Also checks _new_file_in_flight
        (the synchronous-path equivalent) — see the comment on _new_path_lock in
        __init__ for why a brand-new path can otherwise race into both.
        """
        with self._new_path_lock:
            if cert_path in self._large_file_in_flight or cert_path in self._new_file_in_flight:
                logger.debug(
                    f"Large certificate file {cert_path} already being processed "
                    f"(background or synchronous path) — skipping duplicate event"
                )
                return
            self._large_file_in_flight.add(cert_path)

        def _worker():
            try:
                try:
                    self._analyze_and_finish_new_certificate_file(
                        cert_path, process_name, pid, namespace,
                        tetragon_pod, parent_process, parent_pid, node_name,
                    )
                except Exception as e:
                    # Mirror the error handling start()'s event loop gives every
                    # synchronous event — this runs on its own thread, so nothing
                    # else will catch, log, or count an exception raised here.
                    logger.error(f"Error processing large certificate file {cert_path}: {e}",
                                 exc_info=True)
                    self.metrics.cert_events_total.labels(
                        event_type='processing', status='error', node_name=self.metrics._node_name
                    ).inc()
            finally:
                with self._new_path_lock:
                    self._large_file_in_flight.discard(cert_path)

        started = self._start_background_thread(_worker, name=f'cert-parse-{Path(cert_path).name}')
        if not started:
            # _worker's finally never ran, so undo the in-flight marker here —
            # the file will be retried on its next qualifying event.
            with self._new_path_lock:
                self._large_file_in_flight.discard(cert_path)
            self.metrics.cert_analysis_errors.labels(error_type='background_thread_cap_reached', node_name=self.metrics._node_name).inc()

    def process_event(self, event):
        """Process a single Tetragon event"""
        logger.debug("Processing event...")

        # Bind and outbound-connect events carry no cert paths — route them to
        # port-probe handlers and return. Other kprobe/uprobe events fall through
        # to the normal cert extraction path below.
        if event.HasField('process_kprobe'):
            fn = getattr(event.process_kprobe, 'function_name', '')
            if fn in ('security_socket_bind', 'sys_bind'):
                if self._event_rate_metrics_enabled:
                    process = event.process_kprobe.process.binary or 'unknown'
                    self.metrics.tls_socket_bind_events_total.labels(
                        process=process, node_name=self.metrics._node_name).inc()
                if self._bind_probe_enabled:
                    self._handle_tls_bind_event(event)
                return
            elif fn == 'tcp_connect':
                if self._event_rate_metrics_enabled:
                    process = event.process_kprobe.process.binary or 'unknown'
                    self.metrics.tls_tcp_connect_events_total.labels(
                        process=process, node_name=self.metrics._node_name).inc()
                if self._connect_probe_enabled:
                    self._handle_tls_connect_event(event)
                return

        cert_path, process_name, pid, namespace, tetragon_pod, parent_process, parent_pid = \
            self.extract_cert_path_from_event(event)
        pod_name = tetragon_pod.name if tetragon_pod is not None else ""
        logger.debug(
            "Extracted: cert_path=%s, process=%s, pid=%s, pod=%s",
            cert_path, process_name, pid, pod_name,
        )

        if not cert_path:
            # Route PKCS11/NSS events (Java FIPS) to dedicated handlers first.
            if event.HasField('process_uprobe'):
                symbol = event.process_uprobe.symbol
                if symbol == "SSL_ctrl":
                    if self._sni_capture_enabled:
                        self._handle_ssl_ctrl_sni_capture(event)
                    return
                if symbol == "NSC_CreateObject":
                    self._handle_nsc_create_object(event)
                    return
                if symbol == "NSC_FindObjectsInit":
                    self._handle_nsc_find_objects_init(event)
                    return
                # Fallback: any other uprobe symbol may still be delivering the
                # cert as raw DER bytes (e.g. SSL_CTX_use_certificate_ASN1).
                # Kept inside this HasField('process_uprobe') guard so kprobe
                # events with no file_arg match don't reach a handler that
                # only ever does anything for uprobes.
                self._handle_uprobe_in_memory_cert(event)
            return

        # Optionally skip events from the analyzer itself to avoid a feedback loop.
        # Set FILTER_SELF_EVENTS=false to disable this - useful for demos where the
        # cert-analyzer pod is itself the workload being observed.
        if self.filter_self_events and self._is_self_event(process_name, pid):
            logger.debug("Skipping self-generated event from %s (PID %s)", process_name, pid)
            return

        logger.debug("🔍 Detected certificate access: %s by %s (PID: %s)", cert_path, process_name, pid)

        # Update the event timestamp now — we have confirmed a cert-file access event
        # regardless of whether we can parse it. This keeps the readiness probe alive
        # even when all active keystores are password-protected and being skipped.
        self.last_event_time = time.time()
        self.metrics.last_event_timestamp.labels(node_name=self.metrics._node_name).set(self.last_event_time)

        # Check if we've already analyzed this file. _known_paths gives an O(1)
        # lookup keyed on the exact path rather than scanning every entry in
        # known_certs with a startswith() prefix match — at cache sizes in the
        # thousands (a busy node, or a large CA bundle's certs all cached) that
        # scan was real, sustained CPU on every single qualifying event.
        with self._known_paths_lock:
            matching_keys = list(self._known_paths.get(cert_path, ()))
        if matching_keys:
            logger.debug("Re-detected known certificate file: %s", cert_path)
            # A bundle file re-accessed by many distinct processes (e.g. the
            # system CA bundle opened by dozens of unrelated binaries) would
            # otherwise mint a cert_process_info series per (cached cert,
            # process) pair on every single event -- N processes re-accessing
            # an M-cert bundle is O(N*M) series, which is what actually drove
            # the 2026-07-03 incident (more so than the initial-parse fan-out
            # capped in _finish_new_certificate_file). Cap per-event tracking
            # to large_file_metrics_cap certs, same cap as the initial-parse cap.
            metrics_cap = self._large_file_metrics_cap
            is_bundle = len(matching_keys) > metrics_cap
            # Derived once per event, not per cached cert below -- this is the
            # *accessing* pod/container for this specific event, independent of
            # each cert_info's own (sticky, discoverer-attributed) pod fields.
            app_label, container_name = self._derive_app_label_and_container_name(tetragon_pod)
            publish_access = self.kafka_publisher is not None and (
                self.kafka_publisher.access_enabled or self.kafka_publisher.access_connect_enabled
            )
            if publish_access:
                pod_uid = tetragon_pod.uid if tetragon_pod is not None else ""
                container_id = tetragon_pod.container.id if tetragon_pod is not None else ""
                container_image = tetragon_pod.container.image.name if tetragon_pod is not None else ""
            # Tracks whether any candidate key actually resolved -- _known_paths
            # (this loop's source of matching_keys) can be transiently stale
            # relative to known_certs's real contents (see
            # _path_has_live_known_cert's docstring), so it's possible for
            # every single key here to have already been evicted. Without this,
            # that edge case would still hit the unconditional `return` below,
            # silently and permanently treating a now-untracked path as
            # "already known, nothing to do" instead of falling through to
            # rediscover it as new.
            any_live = False
            for i, key in enumerate(matching_keys):
                cert_info = self.known_certs.get(key)
                if cert_info is None:  # evicted between snapshot and access
                    continue
                any_live = True
                # cert_info is already published/cached and may be read
                # concurrently by probe threads, the retry drainer, or another
                # event-consumer iteration -- pod_name/namespace/node_name/etc.
                # are not updated atomically as a group here. Tolerated: every
                # writer of these fields (this call site, _apply_pod_context's
                # other call sites, _probe_tls_endpoint, the retry drainer)
                # uses the same set-once-if-empty (or same-value-every-time,
                # for node_name) semantics, so a reader can at worst see an
                # earlier-but-still-self-consistent snapshot, never a
                # torn/mixed one from two different pods.
                if tetragon_pod is not None and not cert_info.pod_name:
                    logger.debug("Applying pod context to cached entry for %s", cert_path)
                    self._apply_pod_context(cert_info, tetragon_pod)
                if event.node_name:
                    cert_info.node_name = event.node_name
                if is_bundle and i >= metrics_cap:
                    continue
                # The cert's own properties (expiry, FIPS status, etc.) haven't
                # changed since the last full update — only the access recency
                # and the (possibly new) accessing process need refreshing here,
                # not all 8 Gauges and the full detail log for every cached cert
                # in this file.
                self.log_certificate_status(cert_info, summary_only=True)
                self.metrics.update_last_accessed(cert_info)
                is_new_access = self._record_cert_process_access(
                    cert_info, process_name, parent_process,
                    pod_name, namespace, app_label, container_name,
                )
                if is_new_access and publish_access:
                    self.kafka_publisher.publish_access(
                        cert_info, process_name, pid, parent_process, parent_pid,
                        namespace=namespace, pod_name=pod_name, pod_uid=pod_uid,
                        node_name=cert_info.node_name, app_label=app_label,
                        container_name=container_name, container_id=container_id,
                        container_image=container_image,
                    )

            if is_bundle and any_live:
                logger.info(
                    f"{cert_path}: re-access by {process_name} covers "
                    f"{len(matching_keys)} cached certs — tracked process-access "
                    f"for the first {metrics_cap}; {len(matching_keys) - metrics_cap} "
                    f"more skipped to bound cert_process_info cardinality"
                )
            if any_live:
                return
            # Every candidate key from _known_paths turned out to be already
            # evicted from known_certs -- this path isn't actually known
            # anymore (the secondary index was just stale), so fall through
            # to the large-file/new-file handling below to rediscover it
            # instead of silently dropping it here.
            logger.debug(
                "%s: _known_paths listed %d stale key(s) with no live known_certs "
                "entry -- treating as a new file", cert_path, len(matching_keys),
            )

        # Large multi-cert files (e.g. system CA bundles with hundreds of
        # certs, or an oversized JKS/PKCS12 keystore) are parsed on a
        # background thread so one file doesn't block this thread from
        # consuming the rest of the Tetragon event stream.
        if self._is_large_certificate_file(cert_path):
            self._process_certificate_file_async(
                cert_path, process_name, pid, namespace,
                tetragon_pod, parent_process, parent_pid, event.node_name,
            )
            return

        # Analyze new certificate file (may contain multiple certs). Guarded by
        # _new_file_in_flight so a periodic_scan tick (or the background-thread
        # path above) landing on this same never-before-seen path at the same
        # moment doesn't double-parse and double-publish it — see the comment
        # on _new_path_lock in __init__.
        with self._new_path_lock:
            if cert_path in self._new_file_in_flight or cert_path in self._large_file_in_flight:
                logger.debug("New-file parse for %s already in flight, skipping duplicate", cert_path)
                return
            self._new_file_in_flight.add(cert_path)
        try:
            self._analyze_and_finish_new_certificate_file(
                cert_path, process_name, pid, namespace,
                tetragon_pod, parent_process, parent_pid, event.node_name,
            )
        finally:
            with self._new_path_lock:
                self._new_file_in_flight.discard(cert_path)

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
        self._start_process_metrics_monitor()
        self._start_retry_queue_drainer()

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
                    self.metrics.analyzer_healthy.labels(node_name=self.metrics._node_name).set(1)
                    self.metrics.tetragon_connected.labels(node_name=self.metrics._node_name).set(1)

                    for response in stub.GetEvents(request):
                        try:
                            self.process_event(response)
                        except Exception as e:
                            logger.error(f"Error processing event: {e}", exc_info=True)
                            self.metrics.cert_events_total.labels(
                                event_type='processing', status='error', node_name=self.metrics._node_name
                            ).inc()

                    # Stream ended without error — Tetragon closed it cleanly
                    logger.warning("Tetragon event stream ended, reconnecting...")
                    retry_delay = 5

                except grpc.RpcError as e:
                    self.metrics.analyzer_healthy.labels(node_name=self.metrics._node_name).set(0)
                    self.metrics.tetragon_connected.labels(node_name=self.metrics._node_name).set(0)
                    # Jittered (50-100% of retry_delay) so that many analyzer
                    # instances losing their Tetragon connection at the same
                    # moment (e.g. a Tetragon rollout) don't all reconnect in
                    # lockstep and thunder-herd it right back down.
                    sleep_for = retry_delay * (0.5 + random.random() * 0.5)  # nosec B311 - jitter for backoff timing, not a security/crypto use
                    logger.warning(
                        f"Tetragon connection lost ({e.code().name}), "
                        f"retrying in {sleep_for:.1f}s..."
                    )
                    time.sleep(sleep_for)
                    retry_delay = min(retry_delay * 2, max_delay)

                except Exception as e:
                    self.metrics.analyzer_healthy.labels(node_name=self.metrics._node_name).set(0)
                    self.metrics.tetragon_connected.labels(node_name=self.metrics._node_name).set(0)
                    sleep_for = retry_delay * (0.5 + random.random() * 0.5)  # nosec B311 - jitter for backoff timing, not a security/crypto use
                    logger.error(
                        f"Unexpected error in event stream: {e} — "
                        f"retrying in {sleep_for:.1f}s",
                        exc_info=True,
                    )
                    time.sleep(sleep_for)
                    retry_delay = min(retry_delay * 2, max_delay)

        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.metrics.analyzer_healthy.labels(node_name=self.metrics._node_name).set(0)
            self.metrics.tetragon_connected.labels(node_name=self.metrics._node_name).set(0)
            # Re-raise so callers (agent.config.main()) get a chance to run their
            # own shutdown handling -- flushing/closing the Kafka producer and
            # stopping the health server. Swallowing it here previously made
            # main()'s except KeyboardInterrupt block dead code: this method
            # returned normally, so main() fell off the end of its try block
            # without ever closing the Kafka producer, risking loss of
            # unflushed in-flight messages on a graceful shutdown signal.
            raise
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
                    # Skip symlinks and directory-hash/ -- update-ca-trust's
                    # extracted/pem/directory-hash/ re-exposes the same certs
                    # under extra paths purely for OpenSSL CApath subject-hash
                    # lookups: some entries are symlinks (bundle aliases,
                    # per-CA hash-named lookups) but others are genuine
                    # duplicate regular files (one per CA, alongside the
                    # symlinked hash lookup for it) -- either way it's the same
                    # cert content already covered by the parent bundle file,
                    # so skip the whole directory rather than just symlinks.
                    if (cert_file.is_symlink() or 'directory-hash' in cert_file.parts
                            or not cert_file.is_file() or not self.is_cert_path(str(cert_file))):
                        continue

                    cert_path = str(cert_file)
                    # Skip files already parsed via a Tetragon event (or an earlier
                    # scan) — re-parsing every known file on every scan_interval
                    # is wasted crypto work, and re-running _finish_new_certificate_file
                    # would re-publish "new discovery" Kafka messages for certs that
                    # aren't new. Genuinely new files fall through to the same
                    # threshold-routed / metrics-capped path Tetragon events use.
                    # _path_has_live_known_cert (not a bare _known_paths check)
                    # confirms against known_certs itself -- see its own
                    # docstring for why a bare membership check here could
                    # wrongly and permanently skip a file whose _known_paths
                    # entry is transiently stale.
                    if self._path_has_live_known_cert(cert_path):
                        continue

                    if self._is_large_certificate_file(cert_path):
                        self._process_certificate_file_async(
                            cert_path, "periodic_scan", 0, "",
                            None, "", 0, _NODE_NAME,
                        )
                        continue

                    # Guarded by _new_file_in_flight so a Tetragon event (either
                    # routing) landing on this same never-before-seen path at the
                    # same moment doesn't double-parse and double-publish it —
                    # see the comment on _new_path_lock in __init__.
                    with self._new_path_lock:
                        if cert_path in self._new_file_in_flight or cert_path in self._large_file_in_flight:
                            continue
                        self._new_file_in_flight.add(cert_path)
                    try:
                        cert_infos = self._analyze_and_finish_new_certificate_file(
                            cert_path, "periodic_scan", 0, "",
                            None, "", 0, _NODE_NAME,
                        )
                        cert_count += len(cert_infos)
                    finally:
                        with self._new_path_lock:
                            self._new_file_in_flight.discard(cert_path)

                logger.info(f"Scanned {cert_count} new certificate(s) in {base_path}")

            except Exception as e:
                logger.error(f"Error scanning {base_path}: {e}")
