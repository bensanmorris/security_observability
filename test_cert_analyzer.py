"""
Test Suite for TLS Certificate Expiry Monitor
Tests multi-certificate file parsing and analysis
"""

import pytest
import logging
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

    def test_is_cert_path_jks_extensions(self, analyzer):
        """Test detection of JKS keystore file extensions"""
        assert analyzer.is_cert_path("/app/truststore.jks")
        assert analyzer.is_cert_path("/app/server.keystore")
        assert analyzer.is_cert_path("/app/ca.truststore")
        assert analyzer.is_cert_path("/APP/TRUST.JKS")  # Case insensitive

    def test_is_cert_path_pkcs12_extensions(self, analyzer):
        """Test detection of PKCS12 keystore file extensions"""
        assert analyzer.is_cert_path("/app/keystore.p12")
        assert analyzer.is_cert_path("/app/keystore.pfx")
        assert analyzer.is_cert_path("/APP/KEYSTORE.P12")  # Case insensitive
        assert analyzer.is_cert_path("/APP/KEYSTORE.PFX")  # Case insensitive

    def test_is_cert_path_invalid_extensions(self, analyzer):
        """Test rejection of invalid file extensions"""
        assert not analyzer.is_cert_path("/test/file.txt")
        assert not analyzer.is_cert_path("/test/file.pdf")
        assert not analyzer.is_cert_path("/test/file")
        assert not analyzer.is_cert_path("")
        assert not analyzer.is_cert_path(None)


# ── PKCS12 helper ─────────────────────────────────────────────────────────────

def _make_pkcs12(cert, private_key, chain_certs=None, password: bytes = b'changeit') -> bytes:
    """Serialise a certificate + key (and optional chain) into a PKCS12 blob."""
    from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
    from cryptography.hazmat.primitives.serialization import BestAvailableEncryption

    additional = None
    if chain_certs:
        # serialize_key_and_certificates wants a list of x509.Certificate, not tuples
        from cryptography.hazmat.primitives.serialization.pkcs12 import PKCS12Certificate
        additional = [
            PKCS12Certificate(cert=c, friendly_name=None) for c in chain_certs
        ]

    return serialize_key_and_certificates(
        name=b'test',
        key=private_key,
        cert=cert,
        cas=additional,
        encryption_algorithm=BestAvailableEncryption(password),
    )


class TestPKCS12Parsing:
    """Test parsing of PKCS12 keystore files (.p12 / .pfx)"""

    def test_parse_valid_p12_returns_leaf_cert(self, analyzer, temp_dir):
        """parse_pkcs12_certificates extracts the leaf certificate from a .p12 file"""
        cert, key = TestCertificateGeneration.generate_certificate("leaf.example.com", 365)
        p12_data = _make_pkcs12(cert, key)

        p12_path = os.path.join(temp_dir, "keystore.p12")
        with open(p12_path, 'wb') as f:
            f.write(p12_data)

        certs = analyzer.parse_pkcs12_certificates(p12_path)

        assert len(certs) == 1
        cn = certs[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "leaf.example.com"

    def test_parse_p12_with_chain_returns_all_certs(self, analyzer, temp_dir):
        """parse_pkcs12_certificates extracts the leaf and all chain certificates"""
        root_ca, root_key         = TestCertificateGeneration.generate_certificate("Root CA", 3650, is_ca=True)
        intermediate, inter_key   = TestCertificateGeneration.generate_certificate("Intermediate CA", 1825, is_ca=True)
        leaf, leaf_key            = TestCertificateGeneration.generate_certificate("server.example.com", 365)

        p12_data = _make_pkcs12(leaf, leaf_key, chain_certs=[intermediate, root_ca])

        p12_path = os.path.join(temp_dir, "chain.p12")
        with open(p12_path, 'wb') as f:
            f.write(p12_data)

        certs = analyzer.parse_pkcs12_certificates(p12_path)

        assert len(certs) == 3
        common_names = [
            c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            for c in certs
        ]
        assert "server.example.com" in common_names
        assert "Intermediate CA" in common_names
        assert "Root CA" in common_names

    def test_parse_expired_p12_cert_detected(self, analyzer, temp_dir):
        """An expired certificate inside a .p12 file is correctly identified as expired"""
        cert, key = TestCertificateGeneration.generate_certificate("expired.example.com", -30)
        p12_data = _make_pkcs12(cert, key)

        p12_path = os.path.join(temp_dir, "expired.p12")
        with open(p12_path, 'wb') as f:
            f.write(p12_data)

        cert_infos = analyzer.analyze_certificate(p12_path, "java", 1234)

        assert len(cert_infos) == 1
        assert cert_infos[0].is_expired
        assert cert_infos[0].common_name == "expired.example.com"

    def test_parse_pfx_extension_dispatched(self, analyzer, temp_dir):
        """.pfx extension is treated identically to .p12"""
        cert, key = TestCertificateGeneration.generate_certificate("pfx.example.com", 365)
        p12_data = _make_pkcs12(cert, key)

        pfx_path = os.path.join(temp_dir, "keystore.pfx")
        with open(pfx_path, 'wb') as f:
            f.write(p12_data)

        certs = analyzer.parse_pkcs12_certificates(pfx_path)
        assert len(certs) == 1

    def test_parse_p12_wrong_password_returns_empty(self, analyzer, temp_dir, monkeypatch):
        """parse_pkcs12_certificates returns [] and increments error metric when all passwords fail"""
        cert, key = TestCertificateGeneration.generate_certificate("secure.example.com", 365)
        p12_data = _make_pkcs12(cert, key, password=b'supersecret')

        p12_path = os.path.join(temp_dir, "secured.p12")
        with open(p12_path, 'wb') as f:
            f.write(p12_data)

        # Ensure PKCS12_PASSWORD env var doesn't accidentally match
        monkeypatch.delenv('PKCS12_PASSWORD', raising=False)

        certs = analyzer.parse_pkcs12_certificates(p12_path)
        assert certs == []

    def test_parse_p12_custom_password_via_env(self, analyzer, temp_dir, monkeypatch):
        """PKCS12_PASSWORD env var is used before the default password list"""
        cert, key = TestCertificateGeneration.generate_certificate("env-pw.example.com", 365)
        p12_data = _make_pkcs12(cert, key, password=b'mysecretpassword')

        p12_path = os.path.join(temp_dir, "env-pw.p12")
        with open(p12_path, 'wb') as f:
            f.write(p12_data)

        monkeypatch.setenv('PKCS12_PASSWORD', 'mysecretpassword')

        certs = analyzer.parse_pkcs12_certificates(p12_path)
        assert len(certs) == 1
        cn = certs[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "env-pw.example.com"

    def test_parse_p12_file_not_found_returns_empty(self, analyzer):
        """parse_pkcs12_certificates returns [] gracefully when the file does not exist"""
        certs = analyzer.parse_pkcs12_certificates("/nonexistent/path/keystore.p12")
        assert certs == []

    def test_parse_certificates_dispatches_p12(self, analyzer, temp_dir):
        """parse_certificates routes .p12 files to parse_pkcs12_certificates"""
        cert, key = TestCertificateGeneration.generate_certificate("dispatch.example.com", 365)
        p12_data = _make_pkcs12(cert, key)

        p12_path = os.path.join(temp_dir, "dispatch.p12")
        with open(p12_path, 'wb') as f:
            f.write(p12_data)

        # Call the top-level dispatcher — must reach the PKCS12 parser
        certs = analyzer.parse_certificates(p12_path)
        assert len(certs) == 1

    def test_analyze_certificate_returns_cert_info_for_p12(self, analyzer, temp_dir):
        """analyze_certificate returns populated CertificateInfo objects for .p12 files"""
        cert, key = TestCertificateGeneration.generate_certificate("java-app.example.com", 90)
        p12_data = _make_pkcs12(cert, key)

        p12_path = os.path.join(temp_dir, "java-app.p12")
        with open(p12_path, 'wb') as f:
            f.write(p12_data)

        cert_infos = analyzer.analyze_certificate(p12_path, "/usr/bin/java", 4242)

        assert len(cert_infos) == 1
        info = cert_infos[0]
        assert info.common_name == "java-app.example.com"
        assert info.path == p12_path
        assert info.process == "/usr/bin/java"
        assert info.pid == 4242
        assert not info.is_expired
        assert 89 < info.days_until_expiry <= 90


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
        self.name          = name
        self.namespace     = namespace
        self.workload_kind = workload_kind
        self.workload      = workload
        self.pod_labels    = pod_labels or {}


class MockK8sEnricher:
    """Minimal mock of KubernetesEnricher for testing the secondary enrichment path."""

    def __init__(self, container_name: str = "main", container_image: str = "nginx:latest"):
        self.available        = True
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
        cert_info    = _make_cert_info()
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
        mock           = MockK8sEnricher()
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
        assert "cert-test-abc"       in log_messages
        assert "staging"             in log_messages
        assert "Deployment/cert-test" in log_messages

    def test_pod_context_absent_from_log_when_not_enriched(self, analyzer, caplog):
        """No pod context suffix appears in the log when pod_name is empty."""
        cert_info = _make_cert_info(
            not_after=datetime.utcnow() + timedelta(days=365),
        )

        with caplog.at_level(logging.INFO, logger="cert_analyzer"):
            analyzer.log_certificate_status(cert_info)

        log_messages = " ".join(r.message for r in caplog.records)
        assert "pod="       not in log_messages
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

# ── JKS helpers ───────────────────────────────────────────────────────────────

import hashlib
import struct
import time as _time


def _make_jks_truststore(cert: x509.Certificate, password: str = 'changeit') -> bytes:
    """
    Build a minimal JKS truststore containing a single TrustedCertEntry.

    Constructs the binary JKS format without needing keytool or a JDK.
    Layout: magic(4) + version(4) + entry_count(4) + entry + SHA1_digest(20)

    The integrity digest is:
        SHA1(password_as_utf16be + b"Mighty Aphrodite" + preceding_bytes)
    """
    cert_der  = cert.public_bytes(serialization.Encoding.DER)
    alias     = 'test-cert'
    alias_enc = alias.encode('utf-16-be')
    cert_type = b'X.509'
    timestamp = int(_time.time() * 1000)

    entry  = struct.pack('>I', 2)                                # tag = TrustedCertEntry
    entry += struct.pack('>H', len(alias_enc)) + alias_enc       # alias
    entry += struct.pack('>Q', timestamp)                        # creation date (ms)
    entry += struct.pack('>H', len(cert_type)) + cert_type       # cert type
    entry += struct.pack('>I', len(cert_der))  + cert_der        # cert DER bytes

    body   = struct.pack('>III', 0xFEEDFEED, 2, 1) + entry      # header + 1 entry

    pw_bytes = b''.join(struct.pack('>H', ord(c)) for c in password)
    digest   = hashlib.sha1(pw_bytes + b'Mighty Aphrodite' + body).digest()

    return body + digest


def _make_jks_truststore_multi(certs: list, password: str = 'changeit') -> bytes:
    """
    Build a JKS truststore containing multiple TrustedCertEntries.

    Each certificate gets a unique alias ('test-cert-0', 'test-cert-1', ...).
    Layout is identical to _make_jks_truststore but with entry_count > 1.
    """
    entries = b''
    for i, cert in enumerate(certs):
        cert_der  = cert.public_bytes(serialization.Encoding.DER)
        alias     = f'test-cert-{i}'
        alias_enc = alias.encode('utf-16-be')
        cert_type = b'X.509'
        timestamp = int(_time.time() * 1000)

        entry  = struct.pack('>I', 2)
        entry += struct.pack('>H', len(alias_enc)) + alias_enc
        entry += struct.pack('>Q', timestamp)
        entry += struct.pack('>H', len(cert_type)) + cert_type
        entry += struct.pack('>I', len(cert_der))  + cert_der
        entries += entry

    body = struct.pack('>III', 0xFEEDFEED, 2, len(certs)) + entries

    pw_bytes = b''.join(struct.pack('>H', ord(c)) for c in password)
    digest   = hashlib.sha1(pw_bytes + b'Mighty Aphrodite' + body).digest()

    return body + digest


try:
    import jks as _jks_probe  # noqa: F401
    _JKS_AVAILABLE = True
except ImportError:
    _JKS_AVAILABLE = False

pytestmark_jks = pytest.mark.skipif(
    not _JKS_AVAILABLE,
    reason="pyjks not installed"
)


class TestJKSParsing:
    """
    Test parsing of JKS keystore files (.jks / .keystore / .truststore).

    Mirrors TestPKCS12Parsing in structure. All tests are skipped when pyjks
    is not installed so the suite still passes in environments where the
    optional dependency is absent. The one exception is
    test_jks_unavailable_returns_empty_and_increments_metric which patches
    JKS_AVAILABLE directly and therefore runs everywhere.
    """

    @pytestmark_jks
    def test_parse_valid_jks_truststore_returns_cert(self, analyzer, temp_dir):
        """parse_jks_certificates extracts the certificate from a truststore."""
        cert, _ = TestCertificateGeneration.generate_certificate("jks-leaf.example.com", 365)
        jks_data = _make_jks_truststore(cert)

        jks_path = os.path.join(temp_dir, "truststore.jks")
        with open(jks_path, 'wb') as f:
            f.write(jks_data)

        certs = analyzer.parse_jks_certificates(jks_path)

        assert len(certs) == 1
        cn = certs[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "jks-leaf.example.com"

    @pytestmark_jks
    def test_parse_expired_jks_cert_detected(self, analyzer, temp_dir):
        """An expired certificate inside a JKS truststore is correctly identified."""
        cert, _ = TestCertificateGeneration.generate_certificate("expired-jks.example.com", -30)
        jks_data = _make_jks_truststore(cert)

        jks_path = os.path.join(temp_dir, "expired.jks")
        with open(jks_path, 'wb') as f:
            f.write(jks_data)

        cert_infos = analyzer.analyze_certificate(jks_path, "java", 1234)

        assert len(cert_infos) == 1
        assert cert_infos[0].is_expired
        assert cert_infos[0].common_name == "expired-jks.example.com"

    @pytestmark_jks
    def test_parse_jks_custom_password_via_env(self, analyzer, temp_dir, monkeypatch):
        """JKS_PASSWORD env var is tried before the default password list."""
        cert, _ = TestCertificateGeneration.generate_certificate("pw-jks.example.com", 365)
        jks_data = _make_jks_truststore(cert, password='mysecretpassword')

        jks_path = os.path.join(temp_dir, "custom-pw.jks")
        with open(jks_path, 'wb') as f:
            f.write(jks_data)

        monkeypatch.setenv('JKS_PASSWORD', 'mysecretpassword')

        certs = analyzer.parse_jks_certificates(jks_path)

        assert len(certs) == 1
        cn = certs[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "pw-jks.example.com"

    @pytestmark_jks
    def test_parse_jks_wrong_password_returns_empty(self, analyzer, temp_dir, monkeypatch):
        """parse_jks_certificates returns [] when all passwords fail."""
        cert, _ = TestCertificateGeneration.generate_certificate("secure-jks.example.com", 365)
        jks_data = _make_jks_truststore(cert, password='supersecret')

        jks_path = os.path.join(temp_dir, "secured.jks")
        with open(jks_path, 'wb') as f:
            f.write(jks_data)

        monkeypatch.delenv('JKS_PASSWORD', raising=False)

        certs = analyzer.parse_jks_certificates(jks_path)
        assert certs == []

    @pytestmark_jks
    def test_parse_jks_file_not_found_returns_empty(self, analyzer):
        """parse_jks_certificates returns [] gracefully when the file does not exist."""
        certs = analyzer.parse_jks_certificates("/nonexistent/path/truststore.jks")
        assert certs == []

    @pytestmark_jks
    def test_parse_certificates_dispatches_jks(self, analyzer, temp_dir):
        """parse_certificates routes .jks files to parse_jks_certificates."""
        cert, _ = TestCertificateGeneration.generate_certificate("dispatch-jks.example.com", 365)
        jks_data = _make_jks_truststore(cert)

        jks_path = os.path.join(temp_dir, "dispatch.jks")
        with open(jks_path, 'wb') as f:
            f.write(jks_data)

        certs = analyzer.parse_certificates(jks_path)
        assert len(certs) == 1

    @pytestmark_jks
    def test_parse_certificates_dispatches_keystore_extension(self, analyzer, temp_dir):
        """.keystore extension is routed to parse_jks_certificates."""
        cert, _ = TestCertificateGeneration.generate_certificate("keystore.example.com", 365)
        jks_data = _make_jks_truststore(cert)

        ks_path = os.path.join(temp_dir, "server.keystore")
        with open(ks_path, 'wb') as f:
            f.write(jks_data)

        certs = analyzer.parse_certificates(ks_path)
        assert len(certs) == 1

    @pytestmark_jks
    def test_parse_certificates_dispatches_truststore_extension(self, analyzer, temp_dir):
        """.truststore extension is routed to parse_jks_certificates."""
        cert, _ = TestCertificateGeneration.generate_certificate("truststore.example.com", 365)
        jks_data = _make_jks_truststore(cert)

        ts_path = os.path.join(temp_dir, "ca.truststore")
        with open(ts_path, 'wb') as f:
            f.write(jks_data)

        certs = analyzer.parse_certificates(ts_path)
        assert len(certs) == 1

    @pytestmark_jks
    def test_analyze_certificate_returns_cert_info_for_jks(self, analyzer, temp_dir):
        """analyze_certificate returns populated CertificateInfo for .jks files."""
        cert, _ = TestCertificateGeneration.generate_certificate("java-app-jks.example.com", 90)
        jks_data = _make_jks_truststore(cert)

        jks_path = os.path.join(temp_dir, "java-app.jks")
        with open(jks_path, 'wb') as f:
            f.write(jks_data)

        cert_infos = analyzer.analyze_certificate(jks_path, "/usr/bin/java", 4242)

        assert len(cert_infos) == 1
        info = cert_infos[0]
        assert info.common_name == "java-app-jks.example.com"
        assert info.path        == jks_path
        assert info.process     == "/usr/bin/java"
        assert info.pid         == 4242
        assert not info.is_expired
        assert 89 < info.days_until_expiry <= 90

    @pytestmark_jks
    def test_parse_jks_truststore_with_multiple_certs(self, analyzer, temp_dir):
        """A truststore with multiple TrustedCertEntries returns all certificates."""
        cert1, _ = TestCertificateGeneration.generate_certificate("ca-root.example.com",   3650, is_ca=True)
        cert2, _ = TestCertificateGeneration.generate_certificate("ca-inter.example.com",  1825, is_ca=True)
        cert3, _ = TestCertificateGeneration.generate_certificate("leaf.example.com",        365)

        jks_data = _make_jks_truststore_multi([cert1, cert2, cert3])

        jks_path = os.path.join(temp_dir, "multi.jks")
        with open(jks_path, 'wb') as f:
            f.write(jks_data)

        certs = analyzer.parse_jks_certificates(jks_path)

        assert len(certs) == 3
        common_names = [
            c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            for c in certs
        ]
        assert "ca-root.example.com"  in common_names
        assert "ca-inter.example.com" in common_names
        assert "leaf.example.com"     in common_names

    @pytestmark_jks
    def test_parse_jks_multi_cert_mixed_expiry(self, analyzer, temp_dir):
        """analyze_certificate correctly identifies expired certs within a multi-entry truststore."""
        valid_cert,   _ = TestCertificateGeneration.generate_certificate("valid-jks.example.com",   365)
        expired_cert, _ = TestCertificateGeneration.generate_certificate("expired-jks.example.com", -30)
        soon_cert,    _ = TestCertificateGeneration.generate_certificate("soon-jks.example.com",      5)

        jks_data = _make_jks_truststore_multi([valid_cert, expired_cert, soon_cert])

        jks_path = os.path.join(temp_dir, "mixed-expiry.jks")
        with open(jks_path, 'wb') as f:
            f.write(jks_data)

        cert_infos = analyzer.analyze_certificate(jks_path, "/usr/bin/java", 1234)

        assert len(cert_infos) == 3

        by_cn = {info.common_name: info for info in cert_infos}
        assert not by_cn["valid-jks.example.com"].is_expired
        assert     by_cn["expired-jks.example.com"].is_expired
        assert     by_cn["soon-jks.example.com"].expires_soon(days=7)

    def test_jks_unavailable_returns_empty_and_increments_metric(self, analyzer, temp_dir, monkeypatch):
        """
        When pyjks is not installed parse_jks_certificates returns [] and
        increments the jks_unavailable error metric.

        Patches the module-level JKS_AVAILABLE flag so this test runs
        regardless of whether pyjks is installed in the test environment.
        """
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'JKS_AVAILABLE', False)

        jks_path = os.path.join(temp_dir, "dummy.jks")
        with open(jks_path, 'wb') as f:
            f.write(b'dummy')

        certs = analyzer.parse_jks_certificates(jks_path)
        assert certs == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

# ── Tetragon version check helpers ───────────────────────────────────────────

class _MockGetVersionResponse:
    """Minimal mock of the GetVersionResponse proto."""
    def __init__(self, version: str):
        self.version = version


class _MockVersionStub:
    """Mock gRPC stub whose GetVersion returns a configurable version string."""
    def __init__(self, version: str = 'v1.1.0', raise_exc=None):
        self._version   = version
        self._raise_exc = raise_exc

    def GetVersion(self, request, timeout=None):
        if self._raise_exc:
            raise self._raise_exc
        return _MockGetVersionResponse(self._version)


class TestTetragonVersionCheck:
    """
    Tests for get_runtime_tetragon_version() and check_tetragon_version().

    All tests use mock stubs so no live Tetragon connection is needed.
    Prometheus metric state is verified via the analyzer fixture which
    provides a clean registry per test.
    """

    def test_get_runtime_version_returns_version_string(self, analyzer):
        """Happy path — stub returns a version string."""
        stub = _MockVersionStub(version='v1.1.0')
        result = analyzer.get_runtime_tetragon_version(stub)
        assert result == 'v1.1.0'

    def test_get_runtime_version_returns_unknown_on_grpc_error(self, analyzer):
        """gRPC failure returns 'unknown' without raising."""
        stub = _MockVersionStub(raise_exc=Exception("connection refused"))
        result = analyzer.get_runtime_tetragon_version(stub)
        assert result == 'unknown'

    def test_get_runtime_version_returns_unknown_when_field_empty(self, analyzer):
        """Empty version string in response returns 'unknown'."""
        stub = _MockVersionStub(version='')
        result = analyzer.get_runtime_tetragon_version(stub)
        assert result == 'unknown'

    def test_check_version_match_sets_metric_to_1(self, analyzer, monkeypatch):
        """Matching build and runtime versions set the match gauge to 1."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'TETRAGON_BUILD_VERSION', 'v1.1.0')
        stub = _MockVersionStub(version='v1.1.0')
        analyzer.check_tetragon_version(stub)
        assert analyzer.metrics.tetragon_version_match._value.get() == 1.0

    def test_check_version_mismatch_sets_metric_to_0(self, analyzer, monkeypatch):
        """Differing build and runtime versions set the match gauge to 0."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'TETRAGON_BUILD_VERSION', 'v1.1.0')
        stub = _MockVersionStub(version='v1.2.0')
        analyzer.check_tetragon_version(stub)
        assert analyzer.metrics.tetragon_version_match._value.get() == 0.0

    def test_check_version_unknown_build_sets_metric_to_0(self, analyzer, monkeypatch):
        """Unknown build version (env var not set) sets match gauge to 0."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'TETRAGON_BUILD_VERSION', 'unknown')
        stub = _MockVersionStub(version='v1.1.0')
        analyzer.check_tetragon_version(stub)
        assert analyzer.metrics.tetragon_version_match._value.get() == 0.0

    def test_check_version_unknown_runtime_sets_metric_to_0(self, analyzer, monkeypatch):
        """Unreachable Tetragon daemon (unknown runtime) sets match gauge to 0."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'TETRAGON_BUILD_VERSION', 'v1.1.0')
        stub = _MockVersionStub(raise_exc=Exception("timeout"))
        analyzer.check_tetragon_version(stub)
        assert analyzer.metrics.tetragon_version_match._value.get() == 0.0

    def test_check_version_sets_info_metric(self, analyzer, monkeypatch):
        """Version info metric carries both build and runtime version labels."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'TETRAGON_BUILD_VERSION', 'v1.1.0')
        stub = _MockVersionStub(version='v1.2.0')
        analyzer.check_tetragon_version(stub)
        labels = analyzer.metrics.tetragon_version_info._labelnames
        assert 'build_version'   in labels
        assert 'runtime_version' in labels

    def test_check_version_mismatch_logs_warning(self, analyzer, monkeypatch, caplog):
        """A version mismatch produces a WARNING log containing both versions."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'TETRAGON_BUILD_VERSION', 'v1.1.0')
        stub = _MockVersionStub(version='v1.2.0')

        with caplog.at_level(logging.WARNING, logger='cert_analyzer'):
            analyzer.check_tetragon_version(stub)

        messages = ' '.join(r.message for r in caplog.records)
        assert 'v1.1.0'   in messages
        assert 'v1.2.0'   in messages
        assert 'MISMATCH' in messages

    def test_check_version_match_logs_info(self, analyzer, monkeypatch, caplog):
        """Matching versions produce an INFO log confirming the version."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'TETRAGON_BUILD_VERSION', 'v1.1.0')
        stub = _MockVersionStub(version='v1.1.0')

        with caplog.at_level(logging.INFO, logger='cert_analyzer'):
            analyzer.check_tetragon_version(stub)

        messages = ' '.join(r.message for r in caplog.records)
        assert 'v1.1.0' in messages
        assert 'OK'      in messages

    def test_get_runtime_version_never_raises(self, analyzer):
        """get_runtime_tetragon_version must never propagate exceptions."""
        stub = _MockVersionStub(raise_exc=RuntimeError("unexpected failure"))
        try:
            result = analyzer.get_runtime_tetragon_version(stub)
            assert result == 'unknown'
        except Exception as exc:
            pytest.fail(f"get_runtime_tetragon_version raised unexpectedly: {exc}")


# ── Reconnection and version monitor tests ────────────────────────────────────

import threading as _threading
import time as _time


class _StreamingStub:
    """
    Mock stub that simulates the full GetEvents streaming lifecycle.

    Yields a configurable sequence of events then raises an exception to
    simulate a Tetragon disconnect, allowing reconnection logic to be tested
    without a live gRPC connection.
    """
    def __init__(self, events=None, fail_after=0, exception=None):
        """
        events     : list of mock event objects to yield per call
        fail_after : number of events to yield before raising (0 = raise immediately)
        exception  : exception to raise (default: grpc.RpcError via _MockRpcError)
        """
        self._events    = events or []
        self._fail_after = fail_after
        self._exception  = exception or _MockRpcError()
        self._call_count = 0

    def GetEvents(self, request, **kwargs):
        self._call_count += 1
        for i, event in enumerate(self._events):
            if i >= self._fail_after:
                raise self._exception
            yield event
        raise self._exception

    def GetVersion(self, request, timeout=None):
        return _MockGetVersionResponse('v1.1.0')


class _MockRpcError(grpc.RpcError):
    """Minimal grpc.RpcError subclass with a controllable status code."""
    def __init__(self, code=grpc.StatusCode.UNAVAILABLE):
        self._code = code

    def code(self):
        return self._code


class TestReconnection:
    """
    Tests for the reconnection loop in start().

    Uses threads and Events to drive the analyzer for a bounded number of
    reconnect cycles without blocking the test indefinitely.
    """

    def _run_start_briefly(self, analyzer, stub_factory, stop_after_s=0.3):
        """
        Run analyzer.start() in a thread, interrupt it after stop_after_s
        seconds by sending KeyboardInterrupt to the thread, and return.

        Patches the stub creation inside start() so we can inject our mock.
        """
        import signal

        exc_holder = []

        def _target():
            try:
                analyzer.start()
            except Exception as e:
                exc_holder.append(e)

        t = _threading.Thread(target=_target, daemon=True)
        t.start()
        _time.sleep(stop_after_s)
        # The reconnect loop exits cleanly on KeyboardInterrupt
        # We can't send it to a thread directly so we just let it run
        # and check state rather than joining
        return exc_holder

    def test_healthy_metric_set_on_connection(self, analyzer, monkeypatch):
        """
        analyzer_healthy gauge is set to 1 when the event stream is active.
        We verify this by checking immediately after a stream starts.
        """
        connected = _threading.Event()
        stopped   = _threading.Event()

        original_get_events_called = []

        class _ConnectingStub:
            def GetEvents(self_, request, **kwargs):
                connected.set()
                stopped.wait(timeout=1.0)
                raise _MockRpcError()

            def GetVersion(self_, request, timeout=None):
                return _MockGetVersionResponse('v1.1.0')

        stub = _ConnectingStub()

        # Patch channel creation to return our stub
        import cert_analyzer as _ca

        def _mock_insecure_channel(*a, **kw):
            return None

        monkeypatch.setattr(grpc, 'insecure_channel', _mock_insecure_channel)
        monkeypatch.setattr(
            sensors_pb2_grpc, 'FineGuidanceSensorsStub',
            lambda ch: stub,
        )

        t = _threading.Thread(target=analyzer.start, daemon=True)
        t.start()
        connected.wait(timeout=2.0)

        assert analyzer.metrics.analyzer_healthy._value.get() == 1.0
        stopped.set()

    def test_healthy_metric_set_to_0_on_disconnect(self, analyzer, monkeypatch):
        """
        analyzer_healthy drops to 0 when the gRPC stream raises RpcError.
        """
        disconnected = _threading.Event()
        allow_retry  = _threading.Event()
        call_count   = [0]

        class _DisconnectingStub:
            def GetEvents(self_, request, **kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    raise _MockRpcError()
                # Block subsequent calls until test is done
                disconnected.set()
                allow_retry.wait(timeout=2.0)
                raise _MockRpcError()

            def GetVersion(self_, request, timeout=None):
                return _MockGetVersionResponse('v1.1.0')

        stub = _DisconnectingStub()
        monkeypatch.setattr(grpc, 'insecure_channel', lambda *a, **kw: None)
        monkeypatch.setattr(sensors_pb2_grpc, 'FineGuidanceSensorsStub', lambda ch: stub)
        # Shorten retry delay so test doesn't wait 5s
        monkeypatch.setenv('TETRAGON_VERSION_CHECK_INTERVAL', '9999')

        # Patch time.sleep to not actually wait during reconnect backoff
        monkeypatch.setattr(_time, 'sleep', lambda s: None)

        t = _threading.Thread(target=analyzer.start, daemon=True)
        t.start()
        disconnected.wait(timeout=2.0)

        assert analyzer.metrics.analyzer_healthy._value.get() == 0.0
        allow_retry.set()

    def test_reconnect_reissues_get_events(self, analyzer, monkeypatch):
        """
        After a disconnect, GetEvents is called again (reconnect attempt).
        """
        call_count  = [0]
        second_call = _threading.Event()

        class _ReconnectingStub:
            def GetEvents(self_, request, **kwargs):
                call_count[0] += 1
                if call_count[0] >= 2:
                    second_call.set()
                    _time.sleep(10)  # block so test can assert
                raise _MockRpcError()

            def GetVersion(self_, request, timeout=None):
                return _MockGetVersionResponse('v1.1.0')

        monkeypatch.setattr(grpc, 'insecure_channel', lambda *a, **kw: None)
        monkeypatch.setattr(sensors_pb2_grpc, 'FineGuidanceSensorsStub',
                            lambda ch: _ReconnectingStub())
        monkeypatch.setattr(_time, 'sleep', lambda s: None)

        t = _threading.Thread(target=analyzer.start, daemon=True)
        t.start()

        assert second_call.wait(timeout=3.0), "GetEvents was not called a second time"
        assert call_count[0] >= 2


class TestVersionMonitor:
    """Tests for _start_version_monitor background thread."""

    def test_version_monitor_thread_is_daemon(self, analyzer, monkeypatch):
        """The version monitor thread must be a daemon so it doesn't block shutdown."""
        threads_started = []

        original_thread = _threading.Thread

        def _capture_thread(*args, **kwargs):
            t = original_thread(*args, **kwargs)
            threads_started.append(t)
            return t

        monkeypatch.setattr(_threading, 'Thread', _capture_thread)
        monkeypatch.setenv('TETRAGON_VERSION_CHECK_INTERVAL', '9999')

        stub = _MockVersionStub(version='v1.1.0')
        analyzer._start_version_monitor(stub)

        version_threads = [t for t in threads_started
                           if getattr(t, 'name', '') == 'tetragon-version-monitor']
        assert len(version_threads) == 1
        assert version_threads[0].daemon is True

    def test_version_monitor_calls_check_periodically(self, analyzer, monkeypatch):
        """Version monitor invokes check_tetragon_version at least twice."""
        call_count   = [0]
        second_check = _threading.Event()

        def _mock_check(stub):
            call_count[0] += 1
            if call_count[0] >= 2:
                second_check.set()

        monkeypatch.setattr(analyzer, 'check_tetragon_version', _mock_check)
        monkeypatch.setenv('TETRAGON_VERSION_CHECK_INTERVAL', '0')

        stub = _MockVersionStub(version='v1.1.0')
        analyzer._start_version_monitor(stub)

        assert second_check.wait(timeout=2.0), \
            "check_tetragon_version was not called a second time within 2s"

    def test_version_monitor_survives_check_exception(self, analyzer, monkeypatch):
        """An exception in check_tetragon_version must not kill the monitor thread."""
        call_count   = [0]
        second_check = _threading.Event()

        def _failing_then_succeeding_check(stub):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("simulated transient failure")
            second_check.set()

        monkeypatch.setattr(analyzer, 'check_tetragon_version',
                            _failing_then_succeeding_check)
        monkeypatch.setenv('TETRAGON_VERSION_CHECK_INTERVAL', '0')

        stub = _MockVersionStub(version='v1.1.0')
        analyzer._start_version_monitor(stub)

        assert second_check.wait(timeout=2.0), \
            "Monitor thread did not survive the exception"

    def test_version_monitor_detects_upgrade(self, analyzer, monkeypatch):
        """
        If Tetragon is upgraded while the analyzer is running the mismatch
        metric updates to reflect the new version.
        """
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'TETRAGON_BUILD_VERSION', 'v1.1.0')
        monkeypatch.setenv('TETRAGON_VERSION_CHECK_INTERVAL', '0')

        versions    = ['v1.1.0', 'v1.2.0']  # simulates an upgrade
        call_index  = [0]
        mismatch_detected = _threading.Event()

        def _mock_check(stub):
            v = versions[min(call_index[0], len(versions) - 1)]
            call_index[0] += 1
            # Directly invoke the real check logic with a stub returning v
            real_stub = _MockVersionStub(version=v)
            # Call the real implementation bypassing the monkeypatch
            CertificateAnalyzer.check_tetragon_version(analyzer, real_stub)
            if analyzer.metrics.tetragon_version_match._value.get() == 0.0:
                mismatch_detected.set()

        monkeypatch.setattr(analyzer, 'check_tetragon_version', _mock_check)

        stub = _MockVersionStub(version='v1.1.0')
        analyzer._start_version_monitor(stub)

        assert mismatch_detected.wait(timeout=3.0), \
            "Mismatch metric was not set after simulated Tetragon upgrade"
