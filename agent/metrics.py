import logging
import psutil
from datetime import datetime
from prometheus_client import Gauge, Counter, Info

from .constants import CERT_ANALYZER_VERSION, TETRAGON_BUILD_VERSION, CACHE_MAX_SIZE
from .models import CertificateInfo

logger = logging.getLogger(__name__)


class PrometheusMetrics:
    """Prometheus metrics for certificate monitoring"""

    def __init__(self, node_name: str = ""):
        self._node_name = node_name
        # Certificate expiry metrics - includes k8s workload labels.
        # process/parent_process are intentionally absent: these are cert properties,
        # not per-accessor properties.  Use tls_certificate_process_info to map certs
        # to the processes that have loaded them.
        self.cert_expiry_days = Gauge(
            'tls_certificate_expiry_days',
            'Days until TLS certificate expiry',
            ['cert_path', 'subject', 'issuer', 'serial', 'common_name',
             'san_dns_names', 'san_ip_addresses',
             'cert_index', 'pod_name', 'namespace', 'workload_kind', 'workload_name',
             'node_name', 'app_label', 'container_name', 'checksum']
        )

        self.cert_expiry_timestamp = Gauge(
            'tls_certificate_expiry_timestamp',
            'Unix timestamp of certificate expiry',
            ['cert_path', 'subject', 'issuer', 'serial', 'common_name',
             'san_dns_names', 'san_ip_addresses',
             'cert_index', 'pod_name', 'namespace', 'workload_kind', 'workload_name',
             'node_name', 'app_label', 'container_name', 'checksum']
        )

        self.cert_valid_from = Gauge(
            'tls_certificate_valid_from_timestamp',
            'Unix timestamp of certificate valid from date',
            ['cert_path', 'subject', 'issuer', 'serial', 'common_name',
             'san_dns_names', 'san_ip_addresses',
             'cert_index', 'pod_name', 'namespace', 'workload_kind', 'workload_name',
             'node_name', 'app_label', 'container_name', 'checksum']
        )

        self.cert_last_accessed = Gauge(
            'tls_certificate_last_accessed_timestamp',
            'Unix timestamp of the most recent certificate access event',
            ['cert_path', 'subject', 'issuer', 'serial', 'common_name',
             'san_dns_names', 'san_ip_addresses',
             'cert_index', 'pod_name', 'namespace', 'workload_kind', 'workload_name',
             'node_name', 'app_label', 'container_name', 'checksum']
        )

        self.cert_process_info = Gauge(
            'tls_certificate_process_info',
            'Processes observed loading this certificate (1=observed)',
            ['cert_path', 'cert_index', 'serial', 'process', 'parent_process', 'node_name',
             'checksum'],
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
            ['cert_path', 'cert_index', 'pod_name', 'namespace',
             'workload_kind', 'workload_name', 'node_name']
        )

        self.cert_expiring_soon = Gauge(
            'tls_certificate_expiring_soon',
            'Whether certificate expires within threshold (1=yes, 0=no)',
            ['cert_path', 'threshold_days', 'cert_index', 'pod_name',
             'namespace', 'workload_kind', 'workload_name', 'node_name']
        )

        self.cert_fips_compliant = Gauge(
            'tls_certificate_fips_compliant',
            'Whether certificate uses FIPS-approved algorithms (1=compliant, 0=non-compliant)',
            ['cert_path', 'cert_index', 'pod_name', 'namespace',
             'workload_kind', 'workload_name', 'node_name', 'key_algorithm', 'signature_hash',
             'key_size', 'curve_name']
        )

        self.cert_self_signed = Gauge(
            'tls_certificate_self_signed',
            'Whether the certificate is self-signed (1=self-signed, 0=CA-signed)',
            ['cert_path', 'cert_index', 'pod_name', 'namespace',
             'workload_kind', 'workload_name', 'node_name', 'is_ca']
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
        self.build_info = Info(
            'cert_analyzer_build',
            'Build information for the cert-analyzer',
        )
        self.build_info.info({
            'version':                CERT_ANALYZER_VERSION,
            'tetragon_build_version': TETRAGON_BUILD_VERSION,
        })

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

        self.tls_port_probes_total = Counter(
            'tls_port_probes_total',
            'Total number of TLS port probe attempts triggered by bind events',
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
        }

        self.cert_process_info.labels(
            cert_path=info.path,
            cert_index=str(info.cert_index),
            serial=info.serial_number,
            process=info.process,
            parent_process=info.parent_process,
            node_name=info.node_name,
            checksum=info.checksum,
        ).set(1)

        self.cert_expiry_days.labels(**labels).set(info.days_until_expiry)
        self.cert_expiry_timestamp.labels(**labels).set(info.not_after.timestamp())
        self.cert_valid_from.labels(**labels).set(info.not_before.timestamp())
        self.cert_last_accessed.labels(**labels).set(datetime.utcnow().timestamp())

        self.cert_expired.labels(
            cert_path=info.path,
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
                cert_index=str(info.cert_index),
                pod_name=info.pod_name,
                namespace=info.namespace,
                workload_kind=info.workload_kind,
                workload_name=info.workload_name,
                node_name=info.node_name,
                key_algorithm=info.key_algorithm,
                signature_hash=info.signature_hash,
                key_size=str(info.key_size),
                curve_name=info.curve_name,
            ).set(1 if info.fips_compliant else 0)

        self.cert_self_signed.labels(
            cert_path=info.path,
            cert_index=str(info.cert_index),
            pod_name=info.pod_name,
            namespace=info.namespace,
            workload_kind=info.workload_kind,
            workload_name=info.workload_name,
            node_name=info.node_name,
            is_ca='true' if info.is_ca else ('false' if info.is_ca is False else 'unknown'),
        ).set(1 if info.is_self_signed else 0)

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
        ).set(datetime.utcnow().timestamp())

    def record_cert_process_access(self, info: CertificateInfo, process: str, parent_process: str) -> None:
        """
        Record that `process` has loaded an already-known certificate.

        A distinct (process, parent_process) label pair is its own Prometheus series,
        so repeated calls for different processes accumulate into a multi-process view
        of who has loaded this cert, rather than overwriting the original discoverer.
        """
        self.cert_process_info.labels(
            cert_path=info.path,
            cert_index=str(info.cert_index),
            serial=info.serial_number,
            process=process,
            parent_process=parent_process,
            node_name=info.node_name,
            checksum=info.checksum,
        ).set(1)

    def update_process_metrics(self) -> None:
        mem = self._process.memory_info()
        cpu = self._process.cpu_times()
        self.process_rss_bytes.labels(node_name=self._node_name).set(mem.rss)
        self.process_cpu_seconds.labels(node_name=self._node_name).set(cpu.user + cpu.system)
