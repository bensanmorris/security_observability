import logging
from datetime import datetime
from prometheus_client import Gauge, Counter, Info

from .constants import CERT_ANALYZER_VERSION, TETRAGON_BUILD_VERSION, CACHE_MAX_SIZE
from .models import CertificateInfo

logger = logging.getLogger(__name__)


class PrometheusMetrics:
    """Prometheus metrics for certificate monitoring"""

    def __init__(self, node_name: str = ""):
        self._node_name = node_name
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

        self.tls_port_probes_total = Counter(
            'tls_port_probes_total',
            'Total number of TLS port probe attempts triggered by bind events',
            ['status'],  # success, failed, skipped
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
