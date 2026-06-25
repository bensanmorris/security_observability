import grpc
import hashlib
import logging
import os
import re
import socket
import ssl
import struct
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from .health import HealthServer

from cryptography import x509
from cryptography.hazmat.backends import default_backend
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

from .constants import (
    _NODE_NAME, _POLICY_STATE_NAMES, _EKU_NAMES,
    TETRAGON_BUILD_VERSION,
)
from .models import CertificateInfo
from .metrics import PrometheusMetrics
from .cache import LRUCache
from .kafka import KafkaPublisher

logger = logging.getLogger(__name__)


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
                 kafka_publisher: Optional[KafkaPublisher] = None,
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
        self.metrics = PrometheusMetrics(node_name=_NODE_NAME)
        self.known_certs: LRUCache = LRUCache()
        self.processed_paths: LRUCache = LRUCache()
        # Paths that failed password attempts — cached to avoid repeating expensive
        # crypto operations on every subsequent Tetragon event for the same file.
        # LRU eviction gives previously-failed paths a second chance after enough
        # other activity, which is desirable if JKS_PASSWORD has since been set.
        self.password_failed_paths: LRUCache = LRUCache()
        self.health_server = health_server
        self._known_policy_labels: Set[Tuple[str, str, str, str]] = set()
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

        self.metrics.last_event_timestamp.labels(node_name=self.metrics._node_name).set(time.time())
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

        self.metrics.last_event_timestamp.labels(node_name=self.metrics._node_name).set(time.time())
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
        self.metrics.last_event_timestamp.labels(node_name=self.metrics._node_name).set(time.time())

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
        self.metrics.tetragon_version_match.labels(node_name=self.metrics._node_name).set(1 if versions_match else 0)

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

        new_labels: Set[Tuple[str, str, str, str]] = set()
        state_counts: Dict[str, int] = {}

        for policy in response.policies:
            state_str = _POLICY_STATE_NAMES.get(policy.state, 'unknown')
            ns = policy.namespace or ''
            key = (policy.name, ns, state_str, self.metrics._node_name)
            new_labels.add(key)
            state_counts[state_str] = state_counts.get(state_str, 0) + 1

        # Remove series for policies that were deleted or changed state
        for name, ns, state_str, node_name in self._known_policy_labels - new_labels:
            self.metrics.tetragon_policy_info.remove(name, ns, state_str, node_name)

        for name, ns, state_str, node_name in new_labels:
            self.metrics.tetragon_policy_info.labels(
                name=name, namespace=ns, state=state_str, node_name=node_name
            ).set(1)

        # Always emit a count for every known state so queries don't return no-data
        for state_str in _POLICY_STATE_NAMES.values():
            self.metrics.tetragon_policies_total.labels(state=state_str, node_name=self.metrics._node_name).set(
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
                    self.metrics.analyzer_healthy.labels(node_name=self.metrics._node_name).set(1)
                    self.metrics.tetragon_connected.labels(node_name=self.metrics._node_name).set(1)

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
                    self.metrics.analyzer_healthy.labels(node_name=self.metrics._node_name).set(0)
                    self.metrics.tetragon_connected.labels(node_name=self.metrics._node_name).set(0)
                    logger.warning(
                        f"Tetragon connection lost ({e.code().name}), "
                        f"retrying in {retry_delay}s..."
                    )
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, max_delay)

                except Exception as e:
                    self.metrics.analyzer_healthy.labels(node_name=self.metrics._node_name).set(0)
                    self.metrics.tetragon_connected.labels(node_name=self.metrics._node_name).set(0)
                    logger.error(
                        f"Unexpected error in event stream: {e} — "
                        f"retrying in {retry_delay}s",
                        exc_info=True,
                    )
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, max_delay)

        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.metrics.analyzer_healthy.labels(node_name=self.metrics._node_name).set(0)
            self.metrics.tetragon_connected.labels(node_name=self.metrics._node_name).set(0)
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
