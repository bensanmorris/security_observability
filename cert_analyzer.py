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
from typing import Dict, Optional, Set, Tuple, List
from dataclasses import dataclass, field
from concurrent import futures
import time
import re

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from prometheus_client import Gauge, Counter, start_http_server

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


class CertificateAnalyzer:
    """Main analyzer that processes Tetragon events and extracts certificate info"""

    CERT_EXTENSIONS = {'.crt', '.pem', '.cert', '.cer', '.key'}
    JKS_EXTENSIONS  = {'.jks', '.keystore', '.truststore'}

    def __init__(self, tetragon_address: str, alert_threshold_days: int = 30,
                 filter_self_events: bool = True):
        self.tetragon_address = tetragon_address
        self.alert_threshold_days = alert_threshold_days
        self.filter_self_events = filter_self_events
        self.metrics = PrometheusMetrics()
        self.known_certs: Dict[str, CertificateInfo] = {}
        self.processed_paths: Set[str] = set()

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

    def is_cert_path(self, path: str) -> bool:
        """Check if a path looks like a certificate or keystore file"""
        if not path:
            return False
        suffix = Path(path).suffix.lower()
        return suffix in self.CERT_EXTENSIONS or suffix in self.JKS_EXTENSIONS

    def parse_jks_certificates(self, cert_path: str) -> List[x509.Certificate]:
        """
        Parse X.509 certificates from a JKS (Java KeyStore) file.

        JKS keystores are used by Java applications (Spring Boot, Tomcat, etc.)
        and contain trusted certificate entries and/or private key entries with
        certificate chains. This method extracts both.

        Requires the 'pyjks' package. Falls back gracefully if not installed.
        Set the JKS_PASSWORD env var if the keystore uses a non-default password.
        """
        if not JKS_AVAILABLE:
            logger.warning(
                f"Skipping JKS file {cert_path}: pyjks not installed. "
                "Add 'pyjks' to requirements.txt to enable JKS support."
            )
            self.metrics.cert_analysis_errors.labels(error_type='jks_unavailable').inc()
            return []

        # Try the configured password first, then common defaults
        configured = os.getenv('JKS_PASSWORD', '')
        passwords_to_try = list(dict.fromkeys(
            [configured, 'changeit', 'changeme', 'password', '']
        ))

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

    def parse_certificates(self, cert_path: str) -> List[x509.Certificate]:
        """Parse ALL X.509 certificates from a file (supports PEM, DER, and JKS)"""
        # Dispatch JKS/keystore formats to the dedicated parser
        if Path(cert_path).suffix.lower() in self.JKS_EXTENSIONS:
            return self.parse_jks_certificates(cert_path)

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
    ) -> CertificateInfo:
        """Extract relevant information from an X.509 certificate"""

        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()

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

        return CertificateInfo(
            path=cert_path,
            subject=subject,
            issuer=issuer,
            serial_number=str(cert.serial_number),
            not_before=cert.not_valid_before,
            not_after=cert.not_valid_after,
            process=process,
            pid=pid,
            namespace=namespace,
            common_name=common_name,
            san_dns_names=san_dns_names,
            cert_index=cert_index
        )

    def analyze_certificate(
        self,
        cert_path: str,
        process: str,
        pid: int,
        namespace: str = ""
    ) -> List[CertificateInfo]:
        """Analyze a certificate file and return list of CertificateInfo (supports multi-cert files)"""

        certs = self.parse_certificates(cert_path)
        if not certs:
            return []

        cert_infos = []
        for idx, cert in enumerate(certs):
            try:
                cert_info = self.extract_certificate_info(
                    cert, cert_path, process, pid, namespace, cert_index=idx
                )
                cert_infos.append(cert_info)
                self.metrics.cert_events_total.labels(event_type='analysis', status='success').inc()
            except Exception as e:
                logger.error(f"Error extracting certificate info from {cert_path} (cert {idx}): {e}")
                self.metrics.cert_events_total.labels(event_type='analysis', status='failed').inc()
                self.metrics.cert_analysis_errors.labels(error_type='extraction_error').inc()

        self.processed_paths.add(cert_path)
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

        # Check if we've already analyzed this file
        if any(key.startswith(cert_path + ":") for key in self.known_certs.keys()):
            logger.info(f"Re-detected known certificate file: {cert_path}")
            for key, cert_info in self.known_certs.items():
                if key.startswith(cert_path + ":"):
                    # If this event carries pod context that the cached entry lacks,
                    # apply it now so log lines and metrics reflect the correct workload.
                    if tetragon_pod is not None and not cert_info.pod_name:
                        logger.debug(f"Applying pod context to cached entry for {cert_path}")
                        self._apply_pod_context(cert_info, tetragon_pod)
                    self.log_certificate_status(cert_info)
                    self.metrics.update_certificate_metrics(cert_info)
            self.metrics.last_event_timestamp.set(time.time())
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

        self.metrics.last_event_timestamp.set(time.time())

    def start(self):
        """Start listening to Tetragon events"""
        logger.info(f"Connecting to Tetragon at {self.tetragon_address}")

        if self.tetragon_address.startswith('unix://'):
            socket_path = self.tetragon_address[7:]
            channel = grpc.insecure_channel(f'unix:{socket_path}')
        else:
            channel = grpc.insecure_channel(self.tetragon_address)

        stub = sensors_pb2_grpc.FineGuidanceSensorsStub(channel)

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

        logger.info("Connected to Tetragon, listening for certificate events...")
        self.metrics.analyzer_healthy.set(1)

        try:
            for response in stub.GetEvents(request):
                try:
                    self.process_event(response)
                except Exception as e:
                    logger.error(f"Error processing event: {e}", exc_info=True)
                    self.metrics.cert_events_total.labels(
                        event_type='processing', status='error'
                    ).inc()

        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.metrics.analyzer_healthy.set(0)
        except Exception as e:
            logger.error(f"Error in event stream: {e}", exc_info=True)
            self.metrics.analyzer_healthy.set(0)
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
    alert_threshold  = int(os.getenv('ALERT_THRESHOLD_DAYS', '30'))
    log_level        = os.getenv('LOG_LEVEL', 'INFO')
    scan_paths_str   = os.getenv('CERT_SCAN_PATHS', '/etc/ssl,/etc/pki')
    scan_paths       = [p.strip() for p in scan_paths_str.split(',') if p.strip()]
    scan_interval    = int(os.getenv('SCAN_INTERVAL_SECONDS', '3600'))
    # Set to 'false' to allow the cert-analyzer to observe its own certificate
    # accesses - useful for demos showing self-pod enrichment
    filter_self      = os.getenv('FILTER_SELF_EVENTS', 'true').lower() != 'false'

    logging.getLogger().setLevel(getattr(logging, log_level.upper()))

    logger.info("="*60)
    logger.info("TLS Certificate Expiry Monitor (Multi-Cert + K8s Enrichment)")
    logger.info("="*60)
    logger.info(f"Tetragon address:  {tetragon_addr}")
    logger.info(f"Metrics port:      {metrics_port}")
    logger.info(f"Alert threshold:   {alert_threshold} days")
    logger.info(f"Scan paths:        {scan_paths}")
    logger.info(f"Scan interval:     {scan_interval} seconds")
    logger.info(f"Filter self events: {filter_self}")
    logger.info("="*60)

    logger.info(f"Starting Prometheus metrics server on port {metrics_port}")
    start_http_server(metrics_port)

    analyzer = CertificateAnalyzer(tetragon_addr, alert_threshold,
                                   filter_self_events=filter_self)

    if scan_paths and scan_paths[0]:
        import threading

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
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
