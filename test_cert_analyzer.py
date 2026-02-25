"""
Test Suite for TLS Certificate Expiry Monitor
Tests multi-certificate file parsing and analysis
"""

import pytest
import tempfile
import os
from datetime import datetime, timedelta
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from prometheus_client import REGISTRY

# Import the analyzer (adjust path as needed)
import sys
sys.path.insert(0, os.path.dirname(__file__))
from cert_analyzer import CertificateAnalyzer, CertificateInfo


class TestCertificateGeneration:
    """Helper class for generating test certificates"""
    
    @staticmethod
    def generate_certificate(
        common_name: str,
        days_valid: int,
        is_ca: bool = False
    ) -> tuple:
        """Generate a self-signed test certificate and its private key"""
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Calculate validity dates
        if days_valid < 0:
            # Expired certificate
            not_valid_before = datetime.utcnow() + timedelta(days=days_valid) - timedelta(days=365)
            not_valid_after = datetime.utcnow() + timedelta(days=days_valid)
        else:
            # Valid certificate
            not_valid_before = datetime.utcnow()
            not_valid_after = datetime.utcnow() + timedelta(days=days_valid)
        
        # Build certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "TestState"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "TestCity"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TestOrg"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )
        
        # Add basic constraints for CA certificates
        if is_ca:
            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
        
        # Add SAN
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.DNSName(f"www.{common_name}"),
            ]),
            critical=False,
        )
        
        cert = builder.sign(private_key, hashes.SHA256(), backend=default_backend())
        
        return cert, private_key
    
    @staticmethod
    def save_certificate_pem(cert, filepath):
        """Save a certificate to a PEM file"""
        with open(filepath, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    @staticmethod
    def save_certificate_der(cert, filepath):
        """Save a certificate to a DER file"""
        with open(filepath, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.DER))
    
    @staticmethod
    def save_multi_certificate_pem(certs, filepath):
        """Save multiple certificates to a single PEM file (bundle)"""
        with open(filepath, 'wb') as f:
            for cert in certs:
                f.write(cert.public_bytes(serialization.Encoding.PEM))


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test certificates"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def analyzer():
    """Create a certificate analyzer instance, cleaning up Prometheus registry after each test"""
    # Clear collectors from previous tests
    collectors = list(REGISTRY._collector_to_names.keys())
    for collector in collectors:
        try:
            REGISTRY.unregister(collector)
        except Exception:
            pass
    
    # Create analyzer (will register metrics to clean registry)
    test_analyzer = CertificateAnalyzer(
        tetragon_address="unix:///dev/null",
        alert_threshold_days=30
    )
    
    yield test_analyzer
    
    # Cleanup after test
    collectors = list(REGISTRY._collector_to_names.keys())
    for collector in collectors:
        try:
            REGISTRY.unregister(collector)
        except Exception:
            pass


class TestSingleCertificateParsing:
    """Test parsing of single certificate files"""
    
    def test_parse_single_pem_certificate(self, analyzer, temp_dir):
        """Test parsing a single PEM certificate"""
        cert, _ = TestCertificateGeneration.generate_certificate("test.example.com", 365)
        cert_path = os.path.join(temp_dir, "single.pem")
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)
        
        certs = analyzer.parse_certificates(cert_path)
        
        assert len(certs) == 1
        assert certs[0].subject.rfc4514_string() == cert.subject.rfc4514_string()
    
    def test_parse_single_der_certificate(self, analyzer, temp_dir):
        """Test parsing a single DER certificate"""
        cert, _ = TestCertificateGeneration.generate_certificate("test.example.com", 365)
        cert_path = os.path.join(temp_dir, "single.der")
        TestCertificateGeneration.save_certificate_der(cert, cert_path)
        
        certs = analyzer.parse_certificates(cert_path)
        
        assert len(certs) == 1
        assert certs[0].subject.rfc4514_string() == cert.subject.rfc4514_string()
    
    def test_parse_nonexistent_file(self, analyzer):
        """Test parsing a file that doesn't exist"""
        certs = analyzer.parse_certificates("/nonexistent/file.pem")
        
        assert len(certs) == 0
    
    def test_parse_invalid_certificate(self, analyzer, temp_dir):
        """Test parsing an invalid certificate file"""
        cert_path = os.path.join(temp_dir, "invalid.pem")
        with open(cert_path, 'w') as f:
            f.write("This is not a certificate")
        
        certs = analyzer.parse_certificates(cert_path)
        
        assert len(certs) == 0


class TestMultiCertificateParsing:
    """Test parsing of multi-certificate bundle files"""
    
    def test_parse_multi_certificate_bundle(self, analyzer, temp_dir):
        """Test parsing a bundle with multiple certificates"""
        cert1, _ = TestCertificateGeneration.generate_certificate("cert1.example.com", 365)
        cert2, _ = TestCertificateGeneration.generate_certificate("cert2.example.com", 180)
        cert3, _ = TestCertificateGeneration.generate_certificate("cert3.example.com", 90)
        
        bundle_path = os.path.join(temp_dir, "bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem([cert1, cert2, cert3], bundle_path)
        
        certs = analyzer.parse_certificates(bundle_path)
        
        assert len(certs) == 3
        assert certs[0].subject.rfc4514_string() == cert1.subject.rfc4514_string()
        assert certs[1].subject.rfc4514_string() == cert2.subject.rfc4514_string()
        assert certs[2].subject.rfc4514_string() == cert3.subject.rfc4514_string()
    
    def test_parse_empty_bundle(self, analyzer, temp_dir):
        """Test parsing an empty bundle file"""
        bundle_path = os.path.join(temp_dir, "empty.pem")
        with open(bundle_path, 'w') as f:
            f.write("")
        
        certs = analyzer.parse_certificates(bundle_path)
        
        assert len(certs) == 0


class TestCertificateAnalysis:
    """Test certificate analysis and information extraction"""
    
    def test_analyze_valid_certificate(self, analyzer, temp_dir):
        """Test analyzing a valid certificate"""
        cert, _ = TestCertificateGeneration.generate_certificate("valid.example.com", 365)
        cert_path = os.path.join(temp_dir, "valid.pem")
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)
        
        cert_infos = analyzer.analyze_certificate(cert_path, "test_process", 1234)
        
        assert len(cert_infos) == 1
        assert cert_infos[0].common_name == "valid.example.com"
        assert cert_infos[0].process == "test_process"
        assert cert_infos[0].pid == 1234
        assert cert_infos[0].cert_index == 0
        assert not cert_infos[0].is_expired
        assert 360 < cert_infos[0].days_until_expiry < 370
    
    def test_analyze_multi_certificate_bundle(self, analyzer, temp_dir):
        """Test analyzing a bundle with multiple certificates"""
        cert1, _ = TestCertificateGeneration.generate_certificate("cert1.example.com", 365)
        cert2, _ = TestCertificateGeneration.generate_certificate("cert2.example.com", -10)  # Expired
        cert3, _ = TestCertificateGeneration.generate_certificate("cert3.example.com", 5)    # Expiring soon
        
        bundle_path = os.path.join(temp_dir, "bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem([cert1, cert2, cert3], bundle_path)
        
        cert_infos = analyzer.analyze_certificate(bundle_path, "test_process", 1234)
        
        assert len(cert_infos) == 3
        
        # Check cert indexes
        assert cert_infos[0].cert_index == 0
        assert cert_infos[1].cert_index == 1
        assert cert_infos[2].cert_index == 2
        
        # Check statuses
        assert not cert_infos[0].is_expired  # Valid
        assert cert_infos[1].is_expired      # Expired
        assert cert_infos[2].expires_soon(days=7)  # Expiring soon


class TestCertificateInfo:
    """Test CertificateInfo dataclass functionality"""
    
    def test_unique_key_generation(self):
        """Test unique key generation for certificates"""
        info1 = CertificateInfo(
            path="/test/cert.pem",
            subject="CN=test",
            issuer="CN=ca",
            serial_number="12345",
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow() + timedelta(days=365),
            process="test",
            pid=1234,
            cert_index=0
        )
        
        info2 = CertificateInfo(
            path="/test/cert.pem",
            subject="CN=test",
            issuer="CN=ca",
            serial_number="12345",
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow() + timedelta(days=365),
            process="test",
            pid=1234,
            cert_index=1  # Different index
        )
        
        # Same file but different cert index should have different keys
        assert info1.unique_key != info2.unique_key
        assert "/test/cert.pem:0:12345" == info1.unique_key
        assert "/test/cert.pem:1:12345" == info2.unique_key
    
    def test_expires_soon_thresholds(self):
        """Test expires_soon with different thresholds"""
        info = CertificateInfo(
            path="/test/cert.pem",
            subject="CN=test",
            issuer="CN=ca",
            serial_number="12345",
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow() + timedelta(days=15),
            process="test",
            pid=1234
        )
        
        assert info.expires_soon(days=7) == False   # Not expiring in 7 days
        assert info.expires_soon(days=30) == True   # Expiring in 30 days
        assert info.expires_soon(days=90) == True   # Expiring in 90 days


class TestPathDetection:
    """Test certificate path detection"""
    
    def test_is_cert_path_valid_extensions(self, analyzer):
        """Test detection of valid certificate file extensions"""
        assert analyzer.is_cert_path("/test/cert.pem")
        assert analyzer.is_cert_path("/test/cert.crt")
        assert analyzer.is_cert_path("/test/cert.cert")
        assert analyzer.is_cert_path("/test/cert.cer")
        assert analyzer.is_cert_path("/test/cert.key")
        assert analyzer.is_cert_path("/TEST/CERT.PEM")  # Case insensitive
    
    def test_is_cert_path_invalid_extensions(self, analyzer):
        """Test rejection of invalid file extensions"""
        assert not analyzer.is_cert_path("/test/file.txt")
        assert not analyzer.is_cert_path("/test/file.pdf")
        assert not analyzer.is_cert_path("/test/file")
        assert not analyzer.is_cert_path("")
        assert not analyzer.is_cert_path(None)


class TestCABundles:
    """Test handling of real-world CA bundle scenarios"""
    
    def test_ca_bundle_with_chain(self, analyzer, temp_dir):
        """Test parsing a typical CA bundle with root and intermediate CAs"""
        root_ca, _ = TestCertificateGeneration.generate_certificate("Root CA", 3650, is_ca=True)
        intermediate_ca, _ = TestCertificateGeneration.generate_certificate("Intermediate CA", 1825, is_ca=True)
        leaf_cert, _ = TestCertificateGeneration.generate_certificate("server.example.com", 365)
        
        bundle_path = os.path.join(temp_dir, "ca-bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem([root_ca, intermediate_ca, leaf_cert], bundle_path)
        
        cert_infos = analyzer.analyze_certificate(bundle_path, "test_process", 1234)
        
        assert len(cert_infos) == 3
        assert "Root CA" in cert_infos[0].common_name
        assert "Intermediate CA" in cert_infos[1].common_name
        assert "server.example.com" in cert_infos[2].common_name
    
    def test_expired_intermediate_in_chain(self, analyzer, temp_dir):
        """Test detection of expired intermediate certificate in chain"""
        root_ca, _ = TestCertificateGeneration.generate_certificate("Root CA", 3650, is_ca=True)
        intermediate_ca, _ = TestCertificateGeneration.generate_certificate("Intermediate CA", -30, is_ca=True)  # Expired
        leaf_cert, _ = TestCertificateGeneration.generate_certificate("server.example.com", 365)
        
        bundle_path = os.path.join(temp_dir, "chain-with-expired.pem")
        TestCertificateGeneration.save_multi_certificate_pem([root_ca, intermediate_ca, leaf_cert], bundle_path)
        
        cert_infos = analyzer.analyze_certificate(bundle_path, "test_process", 1234)
        
        assert len(cert_infos) == 3
        assert not cert_infos[0].is_expired  # Root is valid
        assert cert_infos[1].is_expired      # Intermediate is expired
        assert not cert_infos[2].is_expired  # Leaf is valid


class MockTetragonPod:
    """
    Minimal mock of the Tetragon pod proto object.
    Mirrors the fields read in _apply_pod_context so tests don't need
    the real protobuf package installed.
    """
    def __init__(
        self,
        name: str = "test-pod-abc12",
        namespace: str = "default",
        workload_kind: str = "Deployment",
        workload: str = "test-deployment",
        pod_labels: dict = None,
    ):
        self.name         = name
        self.namespace    = namespace
        self.workload_kind = workload_kind
        self.workload     = workload
        self.pod_labels   = pod_labels or {}


class MockK8sEnricher:
    """Minimal mock of KubernetesEnricher for testing the secondary enrichment path."""

    def __init__(self, container_name: str = "main", container_image: str = "nginx:latest"):
        self.available = True
        self._container_name  = container_name
        self._container_image = container_image

    def enrich(self, pod_name: str, namespace: str):
        from types import SimpleNamespace
        return SimpleNamespace(
            container_name=self._container_name,
            container_image=self._container_image,
        )


def _make_cert_info(**kwargs) -> CertificateInfo:
    """Return a minimal CertificateInfo with sensible defaults, overridable via kwargs."""
    defaults = dict(
        path="/tmp/test.crt",
        subject="CN=test",
        issuer="CN=ca",
        serial_number="99999",
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        process="/bin/cat",
        pid=1234,
        namespace="default",
        common_name="test.example.com",
    )
    defaults.update(kwargs)
    return CertificateInfo(**defaults)


class TestPodEnrichmentFromTetragonEvent:
    """
    Tests for _apply_pod_context - the primary path that reads workload context
    directly from the Tetragon event proto rather than via the Kubernetes API.
    """

    def test_tetragon_pod_fields_applied(self, analyzer):
        """Core fields from the Tetragon proto are written to CertificateInfo."""
        cert_info   = _make_cert_info()
        tetragon_pod = MockTetragonPod(
            name="myapp-7d6f9-xk2p1",
            namespace="production",
            workload_kind="Deployment",
            workload="myapp",
            pod_labels={"app": "myapp", "version": "v1"},
        )

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.pod_name      == "myapp-7d6f9-xk2p1"
        assert cert_info.namespace     == "production"
        assert cert_info.workload_kind == "Deployment"
        assert cert_info.workload_name == "myapp"
        assert cert_info.pod_labels    == {"app": "myapp", "version": "v1"}

    def test_app_label_derived_from_app_key(self, analyzer):
        """app_label is populated from the 'app' pod label."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(pod_labels={"app": "frontend"})

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.app_label == "frontend"

    def test_app_label_derived_from_app_kubernetes_io_name(self, analyzer):
        """app_label prefers 'app.kubernetes.io/name' over 'app'."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(
            pod_labels={"app.kubernetes.io/name": "canonical-name", "app": "other"}
        )

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.app_label == "canonical-name"

    def test_app_label_empty_when_no_matching_label(self, analyzer):
        """app_label stays empty when no recognised label key is present."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(pod_labels={"custom-label": "value"})

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.app_label == ""

    def test_no_op_when_tetragon_pod_is_none(self, analyzer):
        """_apply_pod_context is a no-op when Tetragon provided no pod context."""
        cert_info = _make_cert_info(namespace="original-ns")

        analyzer._apply_pod_context(cert_info, None)

        assert cert_info.pod_name  == ""
        assert cert_info.namespace == "original-ns"  # unchanged

    def test_empty_pod_labels_handled(self, analyzer):
        """Empty pod_labels dict on the proto doesn't raise."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(pod_labels={})

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.pod_labels == {}
        assert cert_info.app_label  == ""

    def test_workload_property_combines_kind_and_name(self, analyzer):
        """workload property returns 'Kind/name' when both fields are set."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(workload_kind="DaemonSet", workload="node-agent")

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.workload == "DaemonSet/node-agent"

    def test_workload_property_empty_when_fields_missing(self):
        """workload property is empty when kind or name are absent."""
        cert_info = _make_cert_info()
        assert cert_info.workload == ""


class TestK8sEnricherSecondaryPath:
    """
    Tests for the secondary enrichment path - the Kubernetes API enricher
    that supplements fields Tetragon doesn't provide (container name/image).
    """

    def test_container_fields_populated_by_enricher(self, analyzer):
        """container_name and container_image are filled in by the k8s enricher."""
        analyzer.enricher = MockK8sEnricher(
            container_name="app-container",
            container_image="myrepo/myapp:v2.3.1",
        )
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(name="mypod", namespace="default")

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.container_name  == "app-container"
        assert cert_info.container_image == "myrepo/myapp:v2.3.1"

    def test_enricher_not_called_when_unavailable(self, analyzer):
        """Enricher is skipped when enricher.available is False."""
        mock = MockK8sEnricher()
        mock.available = False
        analyzer.enricher = mock
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(name="mypod", namespace="default")

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.container_name  == ""
        assert cert_info.container_image == ""

    def test_enricher_not_called_when_pod_name_missing(self, analyzer):
        """Enricher is skipped when pod name is absent (no Tetragon pod context)."""
        analyzer.enricher = MockK8sEnricher()
        cert_info = _make_cert_info()

        analyzer._apply_pod_context(cert_info, None)

        assert cert_info.container_name  == ""
        assert cert_info.container_image == ""

    def test_tetragon_fields_not_overwritten_by_enricher(self, analyzer):
        """Tetragon-sourced fields (pod_name, workload etc.) are not touched by the enricher."""
        analyzer.enricher = MockK8sEnricher()
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(
            name="original-pod",
            workload_kind="StatefulSet",
            workload="my-statefulset",
        )

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.pod_name      == "original-pod"
        assert cert_info.workload_kind == "StatefulSet"
        assert cert_info.workload_name == "my-statefulset"


class TestLogCertificateStatusOutput:
    """
    Tests for log_certificate_status - verifies the correct log level is used
    and that pod enrichment context appears in the log message when present.
    """

    def test_expired_cert_logs_at_error(self, analyzer, caplog):
        """Expired certificate logs at ERROR level."""
        cert_info = _make_cert_info(
            not_after=datetime.utcnow() - timedelta(days=5),
            common_name="expired.example.com",
        )

        with caplog.at_level(logging.ERROR, logger="cert_analyzer"):
            analyzer.log_certificate_status(cert_info)

        assert any("EXPIRED" in r.message for r in caplog.records)
        assert any(r.levelno == logging.ERROR for r in caplog.records)

    def test_critical_expiry_logs_at_critical(self, analyzer, caplog):
        """Certificate expiring within 7 days logs at CRITICAL level."""
        cert_info = _make_cert_info(
            not_after=datetime.utcnow() + timedelta(days=3),
            common_name="critical.example.com",
        )

        with caplog.at_level(logging.CRITICAL, logger="cert_analyzer"):
            analyzer.log_certificate_status(cert_info)

        assert any("CRITICAL" in r.message for r in caplog.records)
        assert any(r.levelno == logging.CRITICAL for r in caplog.records)

    def test_warning_expiry_logs_at_warning(self, analyzer, caplog):
        """Certificate expiring within threshold (default 30 days) logs at WARNING."""
        cert_info = _make_cert_info(
            not_after=datetime.utcnow() + timedelta(days=15),
            common_name="warning.example.com",
        )

        with caplog.at_level(logging.WARNING, logger="cert_analyzer"):
            analyzer.log_certificate_status(cert_info)

        assert any("WARNING" in r.message for r in caplog.records)
        assert any(r.levelno == logging.WARNING for r in caplog.records)

    def test_valid_cert_logs_at_info(self, analyzer, caplog):
        """Valid certificate with plenty of time left logs at INFO level."""
        cert_info = _make_cert_info(
            not_after=datetime.utcnow() + timedelta(days=365),
            common_name="valid.example.com",
        )

        with caplog.at_level(logging.INFO, logger="cert_analyzer"):
            analyzer.log_certificate_status(cert_info)

        assert any("OK" in r.message for r in caplog.records)
        assert any(r.levelno == logging.INFO for r in caplog.records)

    def test_pod_context_included_in_log_when_present(self, analyzer, caplog):
        """Pod name and namespace appear in the log message when enrichment data is set."""
        cert_info = _make_cert_info(
            not_after=datetime.utcnow() - timedelta(days=1),
            pod_name="cert-test-abc",
            namespace="staging",
            workload_kind="Deployment",
            workload_name="cert-test",
        )

        with caplog.at_level(logging.ERROR, logger="cert_analyzer"):
            analyzer.log_certificate_status(cert_info)

        log_messages = " ".join(r.message for r in caplog.records)
        assert "cert-test-abc" in log_messages
        assert "staging"       in log_messages
        assert "Deployment/cert-test" in log_messages

    def test_pod_context_absent_from_log_when_not_enriched(self, analyzer, caplog):
        """No pod context suffix appears in the log when pod_name is empty."""
        cert_info = _make_cert_info(
            not_after=datetime.utcnow() + timedelta(days=365),
        )

        with caplog.at_level(logging.INFO, logger="cert_analyzer"):
            analyzer.log_certificate_status(cert_info)

        log_messages = " ".join(r.message for r in caplog.records)
        assert "pod=" not in log_messages
        assert "namespace=" not in log_messages

    def test_container_name_included_in_log_when_enriched(self, analyzer, caplog):
        """Container name appears in the log when set by the k8s enricher."""
        cert_info = _make_cert_info(
            not_after=datetime.utcnow() - timedelta(days=1),
            pod_name="mypod",
            namespace="default",
            container_name="sidecar",
        )

        with caplog.at_level(logging.ERROR, logger="cert_analyzer"):
            analyzer.log_certificate_status(cert_info)

        log_messages = " ".join(r.message for r in caplog.records)
        assert "sidecar" in log_messages

    def test_multi_cert_file_index_in_log(self, analyzer, caplog):
        """cert_index > 0 causes the cert number to appear in the log path."""
        cert_info = _make_cert_info(
            not_after=datetime.utcnow() + timedelta(days=365),
            cert_index=2,
        )

        with caplog.at_level(logging.INFO, logger="cert_analyzer"):
            analyzer.log_certificate_status(cert_info)

        log_messages = " ".join(r.message for r in caplog.records)
        assert "cert #3" in log_messages


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
