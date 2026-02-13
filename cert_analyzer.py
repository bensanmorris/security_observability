#!/usr/bin/env python3
"""
TLS Certificate Expiry Monitor for RHEL9/Podman
Consumes Tetragon events and analyzes certificate expiry dates
"""

import os
import sys
import logging
import grpc
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from concurrent import futures
import time

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


class PrometheusMetrics:
    """Prometheus metrics for certificate monitoring"""
    
    def __init__(self):
        # Certificate expiry metrics
        self.cert_expiry_days = Gauge(
            'tls_certificate_expiry_days',
            'Days until TLS certificate expiry',
            ['cert_path', 'subject', 'issuer', 'serial', 'process', 'common_name']
        )
        
        self.cert_expiry_timestamp = Gauge(
            'tls_certificate_expiry_timestamp',
            'Unix timestamp of certificate expiry',
            ['cert_path', 'subject', 'issuer', 'serial', 'process', 'common_name']
        )
        
        self.cert_valid_from = Gauge(
            'tls_certificate_valid_from_timestamp',
            'Unix timestamp of certificate valid from date',
            ['cert_path', 'subject', 'issuer', 'serial', 'process', 'common_name']
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
            ['cert_path', 'process']
        )
        
        self.cert_expiring_soon = Gauge(
            'tls_certificate_expiring_soon',
            'Whether certificate expires within threshold (1=yes, 0=no)',
            ['cert_path', 'process', 'threshold_days']
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
            'cert_path': info.path,
            'subject': info.subject[:100],
            'issuer': info.issuer[:100],
            'serial': info.serial_number,
            'process': info.process,
            'common_name': info.common_name
        }
        
        self.cert_expiry_days.labels(**labels).set(info.days_until_expiry)
        self.cert_expiry_timestamp.labels(**labels).set(info.not_after.timestamp())
        self.cert_valid_from.labels(**labels).set(info.not_before.timestamp())
        
        self.cert_expired.labels(cert_path=info.path, process=info.process).set(
            1 if info.is_expired else 0
        )
        
        for threshold in [7, 30, 90]:
            self.cert_expiring_soon.labels(
                cert_path=info.path,
                process=info.process,
                threshold_days=str(threshold)
            ).set(1 if 0 < info.days_until_expiry < threshold else 0)


class CertificateAnalyzer:
    """Main analyzer that processes Tetragon events and extracts certificate info"""
    
    CERT_EXTENSIONS = {'.crt', '.pem', '.cert', '.cer', '.key'}
    
    def __init__(self, tetragon_address: str, alert_threshold_days: int = 30):
        self.tetragon_address = tetragon_address
        self.alert_threshold_days = alert_threshold_days
        self.metrics = PrometheusMetrics()
        self.known_certs: Dict[str, CertificateInfo] = {}
        self.processed_paths: Set[str] = set()
        
    def is_cert_path(self, path: str) -> bool:
        """Check if a path looks like a certificate file"""
        if not path:
            return False
        path_obj = Path(path)
        return path_obj.suffix.lower() in self.CERT_EXTENSIONS
    
    def parse_certificate(self, cert_path: str) -> Optional[x509.Certificate]:
        """Parse an X.509 certificate from a file"""
        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            # Try PEM format first
            try:
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                return cert
            except Exception:
                # Try DER format
                try:
                    cert = x509.load_der_x509_certificate(cert_data, default_backend())
                    return cert
                except Exception:
                    pass
            
            return None
            
        except FileNotFoundError:
            logger.debug(f"Certificate file not found: {cert_path}")
            self.metrics.cert_analysis_errors.labels(error_type='file_not_found').inc()
            return None
        except PermissionError:
            logger.debug(f"Permission denied reading certificate: {cert_path}")
            self.metrics.cert_analysis_errors.labels(error_type='permission_denied').inc()
            return None
        except Exception as e:
            logger.debug(f"Error reading certificate {cert_path}: {e}")
            self.metrics.cert_analysis_errors.labels(error_type='read_error').inc()
            return None
    
    def extract_certificate_info(
        self, 
        cert: x509.Certificate, 
        cert_path: str, 
        process: str, 
        pid: int,
        namespace: str = ""
    ) -> CertificateInfo:
        """Extract relevant information from an X.509 certificate"""
        
        # Extract subject and issuer
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        
        # Extract common name
        try:
            common_name_attrs = cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )
            common_name = common_name_attrs[0].value if common_name_attrs else ""
        except Exception:
            common_name = ""
        
        # Extract SAN DNS names
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
            san_dns_names=san_dns_names
        )
    
    def analyze_certificate(
        self, 
        cert_path: str, 
        process: str, 
        pid: int,
        namespace: str = ""
    ) -> Optional[CertificateInfo]:
        """Analyze a certificate file and return certificate info"""
        
        # Skip if already processed recently
        #if cert_path in self.processed_paths:
        #    logger.debug(f"Skipping already processed certificate: {cert_path}")
        #    return self.known_certs.get(cert_path)
        
        # Parse certificate
        cert = self.parse_certificate(cert_path)
        if cert is None:
            return None
        
        # Extract information
        try:
            cert_info = self.extract_certificate_info(cert, cert_path, process, pid, namespace)
            self.metrics.cert_events_total.labels(event_type='analysis', status='success').inc()
            self.processed_paths.add(cert_path)
            return cert_info
        except Exception as e:
            logger.error(f"Error extracting certificate info from {cert_path}: {e}")
            self.metrics.cert_events_total.labels(event_type='analysis', status='failed').inc()
            self.metrics.cert_analysis_errors.labels(error_type='extraction_error').inc()
            return None
    
    def log_certificate_status(self, info: CertificateInfo):
        """Log certificate status with appropriate severity"""
        days_left = info.days_until_expiry
        
        if info.is_expired:
            logger.error(
                f"🔴 EXPIRED: Certificate {info.path} "
                f"(process: {info.process}, CN: {info.common_name}) "
                f"expired {abs(days_left):.1f} days ago"
            )
        elif days_left < 7:
            logger.critical(
                f"🔴 CRITICAL: Certificate {info.path} "
                f"(process: {info.process}, CN: {info.common_name}) "
                f"expires in {days_left:.1f} days"
            )
        elif days_left < self.alert_threshold_days:
            logger.warning(
                f"⚠️  WARNING: Certificate {info.path} "
                f"(process: {info.process}, CN: {info.common_name}) "
                f"expires in {days_left:.1f} days"
            )
        else:
            logger.info(
                f"✅ OK: Certificate {info.path} "
                f"(process: {info.process}, CN: {info.common_name}) "
                f"valid for {days_left:.1f} more days"
            )
        
        # Log additional details at debug level
        logger.debug(f"   Subject: {info.subject}")
        logger.debug(f"   Issuer: {info.issuer}")
        logger.debug(f"   Serial: {info.serial_number}")
        logger.debug(
            f"   Valid: {info.not_before.strftime('%Y-%m-%d')} -> "
            f"{info.not_after.strftime('%Y-%m-%d')}"
        )
        if info.san_dns_names:
            logger.debug(f"   SAN DNS: {', '.join(info.san_dns_names[:5])}")
    
    def extract_cert_path_from_event(self, event) -> Tuple[Optional[str], str, int, str]:
        """Extract certificate path, process name, PID, and namespace from Tetragon event"""
        cert_path = None
        process_name = ""
        pid = 0
        namespace = ""
        
        # Handle kprobe events
        if event.HasField('process_kprobe'):
            kprobe = event.process_kprobe
            process_name = kprobe.process.binary
            pid = kprobe.process.pid.value if kprobe.process.HasField('pid') else 0
            
            if kprobe.process.HasField('pod'):
                namespace = kprobe.process.pod.namespace
            
            # Check arguments for certificate paths
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
                namespace = uprobe.process.pod.namespace
            
            # Check arguments for certificate paths
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
        return cert_path, process_name, pid, namespace
    
    def process_event(self, event):
        """Process a single Tetragon event"""
        logger.debug(f"Processing event...")
        cert_path, process_name, pid, namespace = self.extract_cert_path_from_event(event)
        logger.debug(f"Extracted: cert_path={cert_path}, process={process_name}, pid={pid}")
        
        if not cert_path:
            return
        
        logger.info(f"🔍 Detected certificate access: {cert_path} by {process_name} (PID: {pid})")
        
        # Analyze the certificate
        cert_info = self.analyze_certificate(cert_path, process_name, pid, namespace)
        if cert_info is None:
            return
        
        # Update metrics
        self.metrics.update_certificate_metrics(cert_info)
        self.metrics.last_event_timestamp.set(time.time())
        
        # Log status
        self.log_certificate_status(cert_info)
        
        # Store in known certificates
        self.known_certs[cert_path] = cert_info
    
    def start(self):
        """Start listening to Tetragon events"""
        logger.info(f"Connecting to Tetragon at {self.tetragon_address}")
        
        # Setup gRPC channel
        if self.tetragon_address.startswith('unix://'):
            socket_path = self.tetragon_address[7:]
            channel = grpc.insecure_channel(f'unix:{socket_path}')
        else:
            channel = grpc.insecure_channel(self.tetragon_address)
        
        stub = sensors_pb2_grpc.FineGuidanceSensorsStub(channel)
        
        # Create request with filters
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
            # Stream events
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
                
                # Find all certificate files
                cert_count = 0
                for cert_file in path_obj.rglob('*'):
                    if cert_file.is_file() and self.is_cert_path(str(cert_file)):
                        cert_info = self.analyze_certificate(
                            str(cert_file), 
                            "periodic_scan", 
                            0
                        )
                        if cert_info:
                            self.metrics.update_certificate_metrics(cert_info)
                            self.log_certificate_status(cert_info)
                            self.known_certs[str(cert_file)] = cert_info
                            cert_count += 1
                
                logger.info(f"Scanned {cert_count} certificates in {base_path}")
                            
            except Exception as e:
                logger.error(f"Error scanning {base_path}: {e}")


def main():
    """Main entry point"""
    # Configuration from environment
    tetragon_addr = os.getenv('TETRAGON_ADDR', 'localhost:54321')
    metrics_port = int(os.getenv('METRICS_PORT', '9090'))
    alert_threshold = int(os.getenv('ALERT_THRESHOLD_DAYS', '30'))
    log_level = os.getenv('LOG_LEVEL', 'INFO')
    
    # Paths to scan periodically
    scan_paths_str = os.getenv('CERT_SCAN_PATHS', '/etc/ssl,/etc/pki')
    scan_paths = [p.strip() for p in scan_paths_str.split(',') if p.strip()]
    scan_interval = int(os.getenv('SCAN_INTERVAL_SECONDS', '3600'))
    
    # Set log level
    logging.getLogger().setLevel(getattr(logging, log_level.upper()))
    
    logger.info("="*60)
    logger.info("TLS Certificate Expiry Monitor")
    logger.info("="*60)
    logger.info(f"Tetragon address: {tetragon_addr}")
    logger.info(f"Metrics port: {metrics_port}")
    logger.info(f"Alert threshold: {alert_threshold} days")
    logger.info(f"Scan paths: {scan_paths}")
    logger.info(f"Scan interval: {scan_interval} seconds")
    logger.info("="*60)
    
    # Start Prometheus metrics server
    logger.info(f"Starting Prometheus metrics server on port {metrics_port}")
    start_http_server(metrics_port)
    
    # Create analyzer
    analyzer = CertificateAnalyzer(tetragon_addr, alert_threshold)
    
    # Optional: Start periodic scanner in background
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
    
    # Start analyzer (blocks)
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
