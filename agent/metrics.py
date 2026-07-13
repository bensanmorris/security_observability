import logging
import socket
import threading
import time
import psutil
from datetime import datetime, timezone
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIServer, WSGIRequestHandler, make_server

from prometheus_client import Gauge, Counter, Info, REGISTRY, make_wsgi_app
from prometheus_client.core import GaugeMetricFamily

from .constants import CERT_ANALYZER_VERSION, TETRAGON_BUILD_VERSION, CACHE_MAX_SIZE
from .models import CertificateInfo

logger = logging.getLogger(__name__)


class _ScrapeIntervalCollector:
    """
    Reports the observed wall-clock gap between successive /metrics scrapes.

    collect() only runs when something actually pulls /metrics, so timing it
    (rather than reading Prometheus's own configured scrape_interval, which
    this process has no access to) gives the real interval including any
    scheduler drift -- the number that actually matters for judging scrape
    overhead. Nothing is yielded on the first-ever scrape since there's no
    prior timestamp to diff against.
    """

    def __init__(self, node_name: str):
        self._node_name = node_name
        self._last_scrape = None

    def describe(self):
        # Opts out of the registry's default behaviour of calling collect()
        # once at register() time to check for name collisions -- collect()
        # here has the side effect of priming _last_scrape, which would make
        # the very first real scrape measure from registration time instead
        # of reporting nothing as intended.
        return []

    def collect(self):
        now = time.monotonic()
        if self._last_scrape is not None:
            metric = GaugeMetricFamily(
                'cert_analyzer_scrape_interval_seconds',
                'Observed wall-clock interval since the previous /metrics scrape',
                labels=['node_name'],
            )
            metric.add_metric([self._node_name], now - self._last_scrape)
            yield metric
        self._last_scrape = now


class _ScrapeThrottleMiddleware:
    """
    WSGI middleware enforcing a minimum interval between real /metrics scrapes.

    Prometheus's scrape_interval lives entirely on the server side -- a
    misconfigured or malicious scraper can hit /metrics as often as it
    likes, forcing a fresh registry collect() every time. This replays the
    last real response verbatim for any request arriving less than
    min_interval_seconds after the previous one actually served, so an
    over-frequent scraper gets a cheap cached reply instead.

    Only GET requests for the metrics payload are throttled; OPTIONS,
    non-GET, and /favicon.ico pass straight through since prometheus_client
    handles those cheaply itself. The cache is keyed on the Accept /
    Accept-Encoding request headers so a too-soon request negotiating a
    different content type or encoding than what's cached falls through to
    a real collect() rather than replaying a mismatched response.
    """

    def __init__(self, app, min_interval_seconds: float):
        self._app = app
        self._min_interval = min_interval_seconds
        self._lock = threading.Lock()
        self._last_served = None
        self._cached = None  # (status, headers, body, accept, accept_encoding)

    def __call__(self, environ, start_response):
        if environ['REQUEST_METHOD'] != 'GET' or environ['PATH_INFO'] == '/favicon.ico':
            return self._app(environ, start_response)

        accept = environ.get('HTTP_ACCEPT')
        accept_encoding = environ.get('HTTP_ACCEPT_ENCODING')
        now = time.monotonic()

        with self._lock:
            cached = self._cached
            if (cached is not None
                    and now - self._last_served < self._min_interval
                    and cached[3] == accept
                    and cached[4] == accept_encoding):
                status, headers, body, _, _ = cached
                start_response(status, headers)
                return [body]

        captured = {}

        def _capture_start_response(status, headers, exc_info=None):
            captured['status'] = status
            captured['headers'] = headers
            return start_response(status, headers, exc_info)

        body = b''.join(self._app(environ, _capture_start_response))

        with self._lock:
            self._last_served = now
            self._cached = (captured['status'], captured['headers'], body, accept, accept_encoding)

        return [body]


class _ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """Thread-per-request HTTP server -- mirrors prometheus_client's own server."""
    daemon_threads = True


class _SilentWSGIRequestHandler(WSGIRequestHandler):
    """WSGI handler that does not log requests -- mirrors prometheus_client's own handler."""

    def log_message(self, format, *args):
        pass


def _get_best_family(address, port):
    """Automatically select address family depending on address."""
    infos = socket.getaddrinfo(address, port, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE)
    family, _, _, _, sockaddr = next(iter(infos))
    return family, sockaddr[0]


def start_metrics_server(port: int, min_scrape_interval_seconds: float,
                          addr: str = '0.0.0.0', registry=REGISTRY):  # nosec B104 - Prometheus scrape endpoint must be reachable off-pod; no sensitive data served
    """
    Starts the Prometheus /metrics WSGI server as a daemon thread.

    Behaves like prometheus_client.start_http_server(), except the app is
    wrapped in _ScrapeThrottleMiddleware so a scraper polling faster than
    min_scrape_interval_seconds gets a cached reply rather than triggering
    a fresh collect() on every request. Pass min_scrape_interval_seconds<=0
    to disable throttling and serve every request fresh.
    """
    app = make_wsgi_app(registry)
    if min_scrape_interval_seconds > 0:
        app = _ScrapeThrottleMiddleware(app, min_scrape_interval_seconds)

    class _Server(_ThreadingWSGIServer):
        """Copy of _ThreadingWSGIServer to update address_family locally."""

    _Server.address_family, addr = _get_best_family(addr, port)
    httpd = make_server(addr, port, app, _Server, handler_class=_SilentWSGIRequestHandler)
    t = threading.Thread(target=httpd.serve_forever)
    t.daemon = True
    t.start()
    return httpd


class PrometheusMetrics:
    """Prometheus metrics for certificate monitoring"""

    def __init__(self, node_name: str = ""):
        self._node_name = node_name
        # Certificate expiry metrics - includes k8s workload labels.
        # process/parent_process are intentionally absent: these are cert properties,
        # not per-accessor properties.  Use tls_certificate_process_info to map certs
        # to the processes that have loaded them.
        #
        # key_usage/extended_key_usage are comma-joined (same pattern as
        # san_dns_names/san_ip_addresses below) so key-usage-abuse queries
        # (e.g. a serverAuth-only cert observed somewhere clientAuth is
        # expected) are filterable/alertable from Prometheus instead of only
        # visible in the detail log or the optional Kafka event stream. Real
        # KU/EKU combinations cluster into a handful of common patterns, so
        # this doesn't add meaningful cardinality risk.
        self.cert_expiry_days = Gauge(
            'tls_certificate_expiry_days',
            'Days until TLS certificate expiry',
            ['cert_path', 'subject', 'issuer', 'serial', 'common_name',
             'san_dns_names', 'san_ip_addresses',
             'cert_index', 'pod_name', 'namespace', 'workload_kind', 'workload_name',
             'node_name', 'app_label', 'container_name', 'checksum',
             'key_usage', 'extended_key_usage']
        )

        self.cert_expiry_timestamp = Gauge(
            'tls_certificate_expiry_timestamp',
            'Unix timestamp of certificate expiry',
            ['cert_path', 'subject', 'issuer', 'serial', 'common_name',
             'san_dns_names', 'san_ip_addresses',
             'cert_index', 'pod_name', 'namespace', 'workload_kind', 'workload_name',
             'node_name', 'app_label', 'container_name', 'checksum',
             'key_usage', 'extended_key_usage']
        )

        self.cert_valid_from = Gauge(
            'tls_certificate_valid_from_timestamp',
            'Unix timestamp of certificate valid from date',
            ['cert_path', 'subject', 'issuer', 'serial', 'common_name',
             'san_dns_names', 'san_ip_addresses',
             'cert_index', 'pod_name', 'namespace', 'workload_kind', 'workload_name',
             'node_name', 'app_label', 'container_name', 'checksum',
             'key_usage', 'extended_key_usage']
        )

        self.cert_last_accessed = Gauge(
            'tls_certificate_last_accessed_timestamp',
            'Unix timestamp of the most recent certificate access event',
            ['cert_path', 'subject', 'issuer', 'serial', 'common_name',
             'san_dns_names', 'san_ip_addresses',
             'cert_index', 'pod_name', 'namespace', 'workload_kind', 'workload_name',
             'node_name', 'app_label', 'container_name', 'checksum',
             'key_usage', 'extended_key_usage']
        )

        # pod_name/namespace/app_label/container_name reflect the *accessing*
        # process's own pod/container at the time it was recorded (see
        # CertificateAnalyzer._record_cert_process_access), which is why they
        # live here as part of the fan-out key rather than being backfilled
        # from the cert's own (sticky, discoverer-attributed) pod fields --
        # a bundle re-accessed by processes in several different pods should
        # show each pod distinctly, not all attributed to whichever pod
        # happened to discover the cert first.
        self.cert_process_info = Gauge(
            'tls_certificate_process_info',
            'Processes observed loading this certificate (1=observed)',
            ['cert_path', 'cert_index', 'serial', 'process', 'parent_process', 'node_name',
             'pod_name', 'namespace', 'app_label', 'container_name', 'checksum'],
        )

        # TLS protocol version and cipher suite negotiated during a TLS port
        # probe (_probe_tls_endpoint). This is connection metadata, not a
        # certificate property -- file-discovered certificates have no live
        # connection, so this only ever has samples for TLS-probed endpoints.
        # protocol/cipher are both drawn from small, bounded vocabularies
        # (a handful of TLS versions and cipher suite names), and the
        # cert-identity labels are already bounded by the number of probed
        # endpoints (_probed_endpoints dedupes per host:port), so this
        # doesn't add meaningful cardinality risk.
        self.tls_negotiated_protocol = Gauge(
            'tls_certificate_negotiated_protocol',
            'TLS protocol version and cipher suite negotiated during a TLS port probe (1=observed)',
            ['cert_path', 'cert_index', 'serial', 'node_name', 'protocol', 'cipher', 'process'],
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
        #
        # issuer/serial are included on all four so a dashboard can group by
        # them to get a true distinct-certificate count (e.g. the same cert
        # served on several TLS-probed network endpoints, or present at
        # several file paths) instead of counting one row per observation.
        # This adds attributes to already one-series-per-cert Gauges rather
        # than a new fan-out axis, so it doesn't add cardinality risk.
        #
        # checksum is also included: issuer+serial is only a unique identity
        # if the issuing CA never reuses a serial number. Grouping by checksum
        # too means two certs that claim the same issuer+serial but actually
        # differ in content (serial collision/reuse, or tampering) stay as two
        # distinct groups instead of silently merging into one -- turning the
        # distinct count itself into a tamper signal. checksum is "" for every
        # series when checksum_enabled=false (the default), and grouping by a
        # label with the same value on every series is a no-op, so this is
        # free when the feature is off.
        self.cert_expired = Gauge(
            'tls_certificate_expired',
            'Whether certificate is expired (1=expired, 0=valid)',
            ['cert_path', 'cert_index', 'pod_name', 'namespace',
             'workload_kind', 'workload_name', 'node_name', 'app_label', 'container_name',
             'issuer', 'serial', 'checksum']
        )

        self.cert_expiring_soon = Gauge(
            'tls_certificate_expiring_soon',
            'Whether certificate expires within threshold (1=yes, 0=no)',
            ['cert_path', 'threshold_days', 'cert_index', 'pod_name',
             'namespace', 'workload_kind', 'workload_name', 'node_name',
             'app_label', 'container_name', 'issuer', 'serial', 'checksum']
        )

        self.cert_fips_compliant = Gauge(
            'tls_certificate_fips_compliant',
            'Whether certificate uses FIPS-approved algorithms (1=compliant, 0=non-compliant)',
            ['cert_path', 'cert_index', 'pod_name', 'namespace',
             'workload_kind', 'workload_name', 'node_name', 'app_label', 'container_name',
             'key_algorithm', 'signature_hash', 'key_size', 'curve_name', 'issuer', 'serial',
             'checksum']
        )

        self.cert_self_signed = Gauge(
            'tls_certificate_self_signed',
            'Whether the certificate is self-signed (1=self-signed, 0=CA-signed)',
            ['cert_path', 'cert_index', 'pod_name', 'namespace',
             'workload_kind', 'workload_name', 'node_name', 'app_label', 'container_name',
             'is_ca', 'issuer', 'serial', 'checksum']
        )

        # System health
        self.analyzer_healthy = Gauge(
            'cert_analyzer_healthy',
            'Health status of the analyzer (1=healthy, 0=unhealthy)',
            ['node_name']
        )
        self.analyzer_healthy.labels(node_name=self._node_name).set(1)

        self.tetragon_connected = Gauge(
            'tetragon_connected',
            'Whether the analyzer has an active gRPC event stream to Tetragon (1=connected, 0=disconnected)',
            ['node_name']
        )
        self.tetragon_connected.labels(node_name=self._node_name).set(0)

        self.last_event_timestamp = Gauge(
            'cert_analyzer_last_event_timestamp',
            'Timestamp of last processed event',
            ['node_name']
        )

        # Tetragon version tracking — detects build/runtime version mismatch
        self.tetragon_version_info = Info(
            'cert_analyzer_tetragon_version',
            'Tetragon version information for build and runtime',
            ['node_name'],
        )

        self.tetragon_version_match = Gauge(
            'cert_analyzer_tetragon_version_match',
            'Whether the build and runtime Tetragon versions match (1=match, 0=mismatch)',
            ['node_name']
        )

        # Build info — single source of truth for version diagnostics.
        # node_name-labeled (like tetragon_version_info/tetragon_version_match
        # above) so a fleet-wide dashboard can show which analyzer version is
        # actually running on each node -- e.g. to verify a rollout landed
        # everywhere, rather than only being able to compare Tetragon's own
        # build/runtime versions per node.
        self.build_info = Info(
            'cert_analyzer_build',
            'Build information for the cert-analyzer',
            ['node_name'],
        )
        self.build_info.labels(node_name=self._node_name).info({
            'version':                CERT_ANALYZER_VERSION,
            'tetragon_build_version': TETRAGON_BUILD_VERSION,
        })

        # Static analyzer config — populated by CertificateAnalyzer.__init__
        # once it knows its own resolved options, not here, since this class
        # is constructed before config parsing happens.
        self.config_info = Info(
            'cert_analyzer_config',
            'Static, performance-relevant analyzer configuration options',
            ['node_name'],
        )

        # Separate Gauge rather than another config_info label: it's a real
        # number (seconds), so it's directly graphable/alertable on its own,
        # unlike the string-valued fields folded into the info metric above.
        # Also populated by CertificateAnalyzer.__init__, same reason as above.
        self.scan_interval_seconds = Gauge(
            'cert_analyzer_scan_interval_seconds',
            'Configured periodic filesystem scan interval, in seconds',
            ['node_name'],
        )

        # Registered directly with the registry rather than stored as a Gauge
        # attribute: its value is computed at scrape time (see collect()
        # above), not set imperatively like the other metrics here.
        REGISTRY.register(_ScrapeIntervalCollector(self._node_name))

        # Cache size metrics — track LRU cache occupancy for capacity planning
        self.cache_known_certs_size = Gauge(
            'cert_analyzer_cache_known_certs_size',
            'Number of entries in the known_certs LRU cache',
            ['node_name'],
        )
        self.cache_processed_paths_size = Gauge(
            'cert_analyzer_cache_processed_paths_size',
            'Number of entries in the processed_paths LRU cache',
            ['node_name'],
        )
        self.cache_password_failed_size = Gauge(
            'cert_analyzer_cache_password_failed_size',
            'Number of entries in the password_failed_paths LRU cache',
            ['node_name'],
        )
        self.cache_max_size = Gauge(
            'cert_analyzer_cache_max_size',
            'Configured maximum size for all LRU caches',
            ['node_name'],
        )
        self.cache_max_size.labels(node_name=self._node_name).set(CACHE_MAX_SIZE)

        self._process = psutil.Process()
        # Primes psutil's internal cpu_percent() sample point. The first call
        # to cpu_percent(interval=None) after a Process is constructed always
        # returns 0.0 (nothing to compare against yet) -- priming here means
        # the first real reading, taken PROCESS_METRICS_INTERVAL later by the
        # periodic process-metrics monitor, reflects that interval rather
        # than a meaningless 0. See sample_cpu_percent() below.
        self._process.cpu_percent(interval=None)
        self.process_rss_bytes = Gauge(
            'cert_analyzer_process_rss_bytes',
            'Resident set size of the cert-analyzer process in bytes',
            ['node_name'],
        )
        self.process_cpu_seconds = Gauge(
            'cert_analyzer_process_cpu_seconds_total',
            'Cumulative user+system CPU seconds consumed by the cert-analyzer process',
            ['node_name'],
        )
        # Percentage of one CPU core used since the *previous* sample (see
        # sample_cpu_percent) -- e.g. what `top`/`ps %CPU`/`systemd-cgtop` show,
        # not a lifetime average. cert_analyzer_process_cpu_seconds_total
        # above is cumulative since process start: dividing that by uptime (or
        # graphing it with too wide a rate() window) is dominated by whatever
        # the heaviest historical burst was, understating current load for a
        # long-running process and overstating it for a recently-restarted
        # one. This gauge answers "how busy is it right now" directly.
        self.process_cpu_percent = Gauge(
            'cert_analyzer_process_cpu_percent',
            'Percentage of one CPU core used by the cert-analyzer process, '
            'sampled over the interval since the previous sample -- not a '
            'lifetime average',
            ['node_name'],
        )

        self.tls_port_probes_total = Counter(
            'tls_port_probes_total',
            'Total number of TLS port probe attempts triggered by bind or outbound connect events',
            ['status'],  # success, failed, skipped
        )

        self.tls_tcp_connect_events_total = Counter(
            'tls_tcp_connect_events_total',
            'Total tcp_connect kprobe events seen per process (TLS-port only); '
            'useful for diagnosing which application is driving probe load',
            ['process', 'node_name'],
        )
        self.tls_socket_bind_events_total = Counter(
            'tls_socket_bind_events_total',
            'Total socket-bind kprobe events seen per process; '
            'useful for diagnosing which application is driving probe load',
            ['process', 'node_name'],
        )

        # Tetragon policy tracking
        self.tetragon_policy_info = Gauge(
            'tetragon_policy_info',
            'Tetragon tracing policies and their current state (1=present)',
            ['name', 'namespace', 'state', 'node_name'],
        )
        self.tetragon_policies_total = Gauge(
            'tetragon_policies_total',
            'Number of Tetragon tracing policies by state',
            ['state', 'node_name'],
        )

    def update_certificate_metrics(self, info: CertificateInfo):
        """Update Prometheus metrics for a certificate"""
        # Computed once and reused below instead of re-evaluating the
        # days_until_expiry property (each call does its own datetime.utcnow())
        # once per Gauge that needs it -- cheap for a single cert, but this runs
        # per-cert across a whole bundle (up to large_file_metrics_cap certs).
        # Timezone-aware (not the naive datetime.utcnow() used elsewhere for
        # arithmetic against other naive UTC values) because this one feeds
        # .timestamp() directly below -- .timestamp() on a naive datetime
        # assumes the *local* timezone, silently shifting the Gauge value by
        # the local UTC offset.
        now = datetime.now(timezone.utc)
        days_left = info.days_until_expiry
        labels = {
            'cert_path':        info.path,
            'subject':          info.subject[:100],
            'issuer':           info.issuer[:100],
            'serial':           info.serial_number,
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
            'checksum':         info.checksum,
            'key_usage':          ','.join(info.key_usage) if info.key_usage else '',
            'extended_key_usage': ','.join(info.extended_key_usage) if info.extended_key_usage else '',
        }

        self.cert_process_info.labels(
            cert_path=info.path,
            cert_index=str(info.cert_index),
            serial=info.serial_number,
            process=info.process,
            parent_process=info.parent_process,
            node_name=info.node_name,
            pod_name=info.pod_name,
            namespace=info.namespace,
            app_label=info.app_label,
            container_name=info.container_name,
            checksum=info.checksum,
        ).set(1)
        # The discovering process is always allowed (an empty seen-set can
        # never already be at the fan-out cap) — seed it here so a later
        # cache-hit re-access by this same process isn't mistaken for a new
        # distinct process by CertificateAnalyzer._record_cert_process_access.
        # info.pod_name/namespace/app_label/container_name are correct here
        # (not stale) since this is the discovery event itself -- they were
        # just set by _apply_pod_context moments before this call.
        info._seen_processes.add((
            info.process, info.parent_process,
            info.pod_name, info.namespace, info.app_label, info.container_name,
        ))

        self.cert_expiry_days.labels(**labels).set(days_left)
        # not_after/not_before are naive datetimes that represent UTC wall-clock
        # time (see agent/analyzer.py's extraction code) -- attach UTC tzinfo
        # before .timestamp() so it isn't misinterpreted as local time.
        self.cert_expiry_timestamp.labels(**labels).set(info.not_after.replace(tzinfo=timezone.utc).timestamp())
        self.cert_valid_from.labels(**labels).set(info.not_before.replace(tzinfo=timezone.utc).timestamp())
        self.cert_last_accessed.labels(**labels).set(now.timestamp())

        self.cert_expired.labels(
            cert_path=info.path,
            cert_index=str(info.cert_index),
            pod_name=info.pod_name,
            namespace=info.namespace,
            workload_kind=info.workload_kind,
            workload_name=info.workload_name,
            node_name=info.node_name,
            app_label=info.app_label,
            container_name=info.container_name,
            issuer=info.issuer[:100],
            serial=info.serial_number,
            checksum=info.checksum,
        ).set(1 if info.is_expired else 0)

        for threshold in [7, 30, 90]:
            self.cert_expiring_soon.labels(
                cert_path=info.path,
                threshold_days=str(threshold),
                cert_index=str(info.cert_index),
                pod_name=info.pod_name,
                namespace=info.namespace,
                workload_kind=info.workload_kind,
                workload_name=info.workload_name,
                node_name=info.node_name,
                app_label=info.app_label,
                container_name=info.container_name,
                issuer=info.issuer[:100],
                serial=info.serial_number,
                checksum=info.checksum,
            ).set(1 if 0 < days_left < threshold else 0)

        if info.key_algorithm:
            self.cert_fips_compliant.labels(
                cert_path=info.path,
                cert_index=str(info.cert_index),
                pod_name=info.pod_name,
                namespace=info.namespace,
                workload_kind=info.workload_kind,
                workload_name=info.workload_name,
                node_name=info.node_name,
                app_label=info.app_label,
                container_name=info.container_name,
                key_algorithm=info.key_algorithm,
                signature_hash=info.signature_hash,
                key_size=str(info.key_size),
                curve_name=info.curve_name,
                issuer=info.issuer[:100],
                serial=info.serial_number,
                checksum=info.checksum,
            ).set(1 if info.fips_compliant else 0)

        self.cert_self_signed.labels(
            cert_path=info.path,
            cert_index=str(info.cert_index),
            pod_name=info.pod_name,
            namespace=info.namespace,
            workload_kind=info.workload_kind,
            workload_name=info.workload_name,
            node_name=info.node_name,
            app_label=info.app_label,
            container_name=info.container_name,
            is_ca='true' if info.is_ca else ('false' if info.is_ca is False else 'unknown'),
            issuer=info.issuer[:100],
            serial=info.serial_number,
            checksum=info.checksum,
        ).set(1 if info.is_self_signed else 0)

    @staticmethod
    def _safe_remove(metric, labelvalues: tuple) -> None:
        """Remove a label-set if present; a missing series (never set, or
        already removed) is not an error here."""
        try:
            metric.remove(*labelvalues)
        except KeyError:
            pass

    def remove_certificate_metrics(self, info: CertificateInfo) -> None:
        """
        Remove the per-cert Gauge series written by update_certificate_metrics.

        Called from LRUCache's on_evict callback when a cert falls out of
        known_certs, so Prometheus's own memory tracks cache occupancy instead
        of growing for the entire life of the process — update_certificate_metrics
        creates ~10 new label-sets per newly-discovered cert and nothing
        previously removed them on eviction, so every certificate ever seen
        stayed resident in the registry forever.

        cert_process_info fans out to one series per distinct (process,
        parent_process, pod_name, namespace, app_label, container_name)
        tuple that has accessed this cert, capped at max_processes_per_cert --
        every tuple that was ever actually given a series is tracked in
        info._seen_processes, so all of them are removed here, not just the
        most recent. tls_negotiated_protocol (TLS-probe discoveries only)
        still isn't cleaned up: protocol/cipher aren't persisted on
        CertificateInfo after the probe completes, so there's nothing to
        reconstruct that label tuple from.
        """
        shared_labels = (
            info.path, info.subject[:100], info.issuer[:100], info.serial_number,
            info.common_name, ','.join(info.san_dns_names), ','.join(info.san_ip_addresses),
            str(info.cert_index), info.pod_name, info.namespace, info.workload_kind,
            info.workload_name, info.node_name, info.app_label, info.container_name,
            info.checksum,
            ','.join(info.key_usage) if info.key_usage else '',
            ','.join(info.extended_key_usage) if info.extended_key_usage else '',
        )
        for gauge in (self.cert_expiry_days, self.cert_expiry_timestamp,
                      self.cert_valid_from, self.cert_last_accessed):
            self._safe_remove(gauge, shared_labels)

        seen_processes = getattr(info, '_seen_processes', None) or {(
            info.process, info.parent_process,
            info.pod_name, info.namespace, info.app_label, info.container_name,
        )}
        for process, parent_process, pod_name, namespace, app_label, container_name in seen_processes:
            self._safe_remove(self.cert_process_info, (
                info.path, str(info.cert_index), info.serial_number,
                process, parent_process, info.node_name,
                pod_name, namespace, app_label, container_name,
                info.checksum,
            ))

        self._safe_remove(self.cert_expired, (
            info.path, str(info.cert_index), info.pod_name, info.namespace,
            info.workload_kind, info.workload_name, info.node_name,
            info.app_label, info.container_name,
            info.issuer[:100], info.serial_number, info.checksum,
        ))

        for threshold in (7, 30, 90):
            self._safe_remove(self.cert_expiring_soon, (
                info.path, str(threshold), str(info.cert_index), info.pod_name,
                info.namespace, info.workload_kind, info.workload_name,
                info.node_name, info.app_label, info.container_name,
                info.issuer[:100], info.serial_number, info.checksum,
            ))

        if info.key_algorithm:
            self._safe_remove(self.cert_fips_compliant, (
                info.path, str(info.cert_index), info.pod_name, info.namespace,
                info.workload_kind, info.workload_name, info.node_name,
                info.app_label, info.container_name,
                info.key_algorithm, info.signature_hash, str(info.key_size),
                info.curve_name, info.issuer[:100], info.serial_number, info.checksum,
            ))

        is_ca_label = 'true' if info.is_ca else ('false' if info.is_ca is False else 'unknown')
        self._safe_remove(self.cert_self_signed, (
            info.path, str(info.cert_index), info.pod_name, info.namespace,
            info.workload_kind, info.workload_name, info.node_name,
            info.app_label, info.container_name,
            is_ca_label, info.issuer[:100], info.serial_number, info.checksum,
        ))

    def update_last_accessed(self, info: CertificateInfo) -> None:
        """
        Refresh only the last-accessed timestamp for an already-known certificate.

        Used on cache-hit re-detections, where the cert's own properties (expiry,
        FIPS status, etc.) haven't changed since the last full update_certificate_metrics()
        call and don't need re-setting for every cached cert on every re-detection.
        """
        self.cert_last_accessed.labels(
            cert_path=info.path,
            subject=info.subject[:100],
            issuer=info.issuer[:100],
            serial=info.serial_number,
            common_name=info.common_name,
            san_dns_names=','.join(info.san_dns_names),
            san_ip_addresses=','.join(info.san_ip_addresses),
            cert_index=str(info.cert_index),
            pod_name=info.pod_name,
            namespace=info.namespace,
            workload_kind=info.workload_kind,
            workload_name=info.workload_name,
            node_name=info.node_name,
            app_label=info.app_label,
            container_name=info.container_name,
            checksum=info.checksum,
            key_usage=','.join(info.key_usage) if info.key_usage else '',
            extended_key_usage=','.join(info.extended_key_usage) if info.extended_key_usage else '',
        # datetime.now(timezone.utc), not datetime.utcnow() -- .timestamp() on
        # a naive datetime assumes the local timezone, silently shifting this
        # by the local UTC offset (see update_certificate_metrics above).
        ).set(datetime.now(timezone.utc).timestamp())

    def record_cert_process_access(self, info: CertificateInfo, process: str, parent_process: str,
                                    pod_name: str = "", namespace: str = "",
                                    app_label: str = "", container_name: str = "") -> None:
        """
        Record that `process` has loaded an already-known certificate.

        A distinct (process, parent_process, pod_name, namespace, app_label,
        container_name) label tuple is its own Prometheus series, so repeated
        calls for different processes -- or the same process in a different
        pod -- accumulate into a multi-process, multi-pod view of who has
        loaded this cert, rather than overwriting the original discoverer.

        pod_name/namespace/app_label/container_name default to "" (rather than
        falling back to info's own fields) since they describe the *current*
        accessing event, which the caller (CertificateAnalyzer.
        _record_cert_process_access) is responsible for supplying -- info's
        own pod fields belong to whichever access first discovered the cert
        and may well be a different pod than this one.

        This method always writes the series unconditionally — capping the
        number of distinct processes tracked per cert (max_processes_per_cert)
        is the caller's job: see CertificateAnalyzer._record_cert_process_access,
        which decides whether to call this at all.
        """
        self.cert_process_info.labels(
            cert_path=info.path,
            cert_index=str(info.cert_index),
            serial=info.serial_number,
            process=process,
            parent_process=parent_process,
            node_name=info.node_name,
            pod_name=pod_name,
            namespace=namespace,
            app_label=app_label,
            container_name=container_name,
            checksum=info.checksum,
        ).set(1)

    def record_tls_negotiation(self, info: CertificateInfo, protocol: str, cipher: str) -> None:
        """
        Record the TLS protocol version and cipher suite negotiated for a
        certificate discovered via a TLS port probe.

        Reflects what cert-analyzer's own probe negotiated with
        ssl.create_default_context() -- the server's ceiling with a modern
        client, not necessarily what every real client gets.
        """
        self.tls_negotiated_protocol.labels(
            cert_path=info.path,
            cert_index=str(info.cert_index),
            serial=info.serial_number,
            node_name=info.node_name,
            protocol=protocol,
            cipher=cipher,
            process=info.process,
        ).set(1)

    def update_process_metrics(self) -> None:
        mem = self._process.memory_info()
        cpu = self._process.cpu_times()
        self.process_rss_bytes.labels(node_name=self._node_name).set(mem.rss)
        self.process_cpu_seconds.labels(node_name=self._node_name).set(cpu.user + cpu.system)

    def sample_cpu_percent(self) -> None:
        """
        Refresh cert_analyzer_process_cpu_percent -- the percentage of one
        CPU core used since the *previous* call to this method, computed the
        same way `top`/`ps %CPU`/`systemd-cgtop` do: compare cumulative CPU
        time now against cumulative CPU time at the last sample, divided by
        the wall-clock time between the two samples.

        Deliberately not folded into update_process_metrics() above, which is
        also called from the per-event cache-metrics path: RSS and cumulative
        CPU-seconds are harmless to refresh on every event, but
        cpu_percent(interval=None) is stateful and its accuracy depends on a
        stable sampling interval -- calling it many times per second during a
        burst would shrink the window between samples toward zero and produce
        noisy, spiky readings instead of a stable current-utilization figure.
        Only the periodic process-metrics monitor (fixed ~PROCESS_METRICS_INTERVAL
        cadence) calls this.
        """
        self.process_cpu_percent.labels(node_name=self._node_name).set(
            self._process.cpu_percent(interval=None)
        )
