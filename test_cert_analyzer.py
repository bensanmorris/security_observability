"""
Test Suite for TLS Certificate Expiry Monitor
Tests multi-certificate file parsing and analysis
"""

import pytest
import logging
import tempfile
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend
from prometheus_client import REGISTRY

# Import the analyzer (adjust path as needed)
import sys
sys.path.insert(0, os.path.dirname(__file__))
from cert_analyzer import CertificateAnalyzer, CertificateInfo, LRUCache


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

    def test_parse_p12_failed_path_cached(self, analyzer, temp_dir, monkeypatch):
        """A PKCS12 file that fails password attempts is cached and skipped on retry."""
        cert, key = TestCertificateGeneration.generate_certificate("cached.example.com", 365)
        p12_data = _make_pkcs12(cert, key, password=b'supersecret')

        p12_path = os.path.join(temp_dir, "cached.p12")
        with open(p12_path, 'wb') as f:
            f.write(p12_data)

        monkeypatch.delenv('PKCS12_PASSWORD', raising=False)

        # First call — should attempt passwords and fail
        analyzer.parse_pkcs12_certificates(p12_path)
        assert p12_path in analyzer.password_failed_paths

        # Second call — should return immediately without attempting passwords
        # We verify by checking the error counter does not increment again
        before = analyzer.metrics.cert_analysis_errors.labels(
            error_type='pkcs12_password_failed'
        )._value.get()
        analyzer.parse_pkcs12_certificates(p12_path)
        after = analyzer.metrics.cert_analysis_errors.labels(
            error_type='pkcs12_password_failed'
        )._value.get()
        assert after == before  # no additional error increment on second call

    def test_parse_p12_password_list_does_not_include_changeme_or_password(
        self, analyzer, temp_dir, monkeypatch
    ):
        """
        The PKCS12 password list only tries env var, 'changeit', and empty string.
        'changeme' and 'password' are not attempted.
        """
        tried = []
        original_load = __import__(
            'cryptography.hazmat.primitives.serialization.pkcs12',
            fromlist=['load_pkcs12']
        ).load_pkcs12

        def _capturing_load(data, password):
            tried.append(password)
            raise ValueError("wrong password")

        import cryptography.hazmat.primitives.serialization.pkcs12 as _p12mod
        monkeypatch.setattr(_p12mod, 'load_pkcs12', _capturing_load)
        monkeypatch.delenv('PKCS12_PASSWORD', raising=False)

        cert, key = TestCertificateGeneration.generate_certificate("pw-list.example.com", 365)
        p12_path = os.path.join(temp_dir, "pw-list.p12")
        # Write any bytes — the mock intercepts before real parsing
        with open(p12_path, 'wb') as f:
            f.write(b'dummy')

        analyzer.parse_pkcs12_certificates(p12_path)

        assert b'changeme' not in tried
        assert b'password' not in tried

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


class MockTetragonContainer:
    """
    Minimal mock of the Tetragon Container proto object.
    Mirrors the fields read in _apply_pod_context (v1.7.0 schema).
    """
    def __init__(
        self,
        id: str = "abc123",
        name: str = "",
        image_name: str = "",
        image_id: str = "",
        maybe_exec_probe: bool = False,
        pid: int = None,
        start_time=None,
        privileged: bool = None,
    ):
        from types import SimpleNamespace
        self.id               = id
        self.name             = name
        self.image            = SimpleNamespace(name=image_name, id=image_id)
        self.maybe_exec_probe = maybe_exec_probe
        self._pid             = pid
        self._start_time      = start_time
        self._privileged      = privileged
        if pid is not None:
            self.pid = SimpleNamespace(value=pid)
        if start_time is not None:
            self.start_time = SimpleNamespace(ToDatetime=lambda: start_time)
        if privileged is not None:
            self.security_context = SimpleNamespace(privileged=privileged)

    def HasField(self, name):
        if name == 'pid':
            return self._pid is not None
        if name == 'start_time':
            return self._start_time is not None
        if name == 'security_context':
            return self._privileged is not None
        return False


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
        pod_annotations: dict = None,
        uid: str = "",
        container: 'MockTetragonContainer' = None,
    ):
        self.name            = name
        self.namespace       = namespace
        self.workload_kind   = workload_kind
        self.workload        = workload
        self.pod_labels      = pod_labels or {}
        self.pod_annotations = pod_annotations or {}
        self.uid             = uid
        self.container       = container if container is not None else MockTetragonContainer()


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

    def test_container_fields_populated_from_tetragon_proto(self, analyzer):
        """container_name and container_image are read from the Tetragon Container proto."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(
            name="mypod",
            namespace="default",
            container=MockTetragonContainer(
                name="app-container",
                image_name="myrepo/myapp:v2.3.1",
            ),
        )

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.container_name  == "app-container"
        assert cert_info.container_image == "myrepo/myapp:v2.3.1"

    def test_container_fields_empty_when_container_has_no_data(self, analyzer):
        """container_name and container_image default to empty when container fields are unset."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(name="mypod", namespace="default")
        # Default MockTetragonContainer has empty name/image

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.container_name  == ""
        assert cert_info.container_image == ""

    def test_container_fields_absent_when_no_pod_context(self, analyzer):
        """Container fields stay empty when there is no Tetragon pod context at all."""
        cert_info = _make_cert_info()

        analyzer._apply_pod_context(cert_info, None)

        assert cert_info.container_name  == ""
        assert cert_info.container_image == ""

    def test_tetragon_pod_fields_set_alongside_container(self, analyzer):
        """Pod-level fields (pod_name, workload etc.) are correctly set from the proto."""
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

    def test_pod_uid_populated_when_present(self, analyzer):
        """pod.uid (Tetragon v1.6.0+) is captured when the server supplies it."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(uid="550e8400-e29b-41d4-a716-446655440000")

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.pod_uid == "550e8400-e29b-41d4-a716-446655440000"

    def test_pod_uid_stays_empty_when_server_is_old(self, analyzer):
        """pod.uid is left empty when the server returns an empty string (pre-v1.6.0)."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(uid="")

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.pod_uid == ""

    def test_pod_annotations_populated_when_present(self, analyzer):
        """pod.pod_annotations (Tetragon v1.5.0+) is captured when the server supplies it."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(
            pod_annotations={"prometheus.io/scrape": "true", "sidecar.istio.io/inject": "false"},
        )

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.pod_annotations == {
            "prometheus.io/scrape": "true",
            "sidecar.istio.io/inject": "false",
        }

    def test_pod_annotations_empty_dict_when_server_is_old(self, analyzer):
        """pod.pod_annotations is an empty dict when the server supplies nothing (pre-v1.5.0)."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(pod_annotations={})

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.pod_annotations == {}

    def test_container_privileged_set_when_security_context_present(self, analyzer):
        """container.security_context.privileged (Tetragon v1.5.0+) is captured when supplied."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(
            container=MockTetragonContainer(privileged=True),
        )

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.container_privileged is True

    def test_container_privileged_false_when_security_context_absent(self, analyzer):
        """container_privileged stays False when the server doesn't send security_context (pre-v1.5.0)."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(
            container=MockTetragonContainer(privileged=None),
        )

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.container_privileged is False


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
    def test_parse_jks_failed_path_cached(self, analyzer, temp_dir, monkeypatch):
        """A JKS file that fails password attempts is cached and skipped on retry."""
        cert, _ = TestCertificateGeneration.generate_certificate("cached-jks.example.com", 365)
        jks_data = _make_jks_truststore(cert, password='supersecret')

        jks_path = os.path.join(temp_dir, "cached.jks")
        with open(jks_path, 'wb') as f:
            f.write(jks_data)

        monkeypatch.delenv('JKS_PASSWORD', raising=False)

        # First call — should attempt passwords and fail
        analyzer.parse_jks_certificates(jks_path)
        assert jks_path in analyzer.password_failed_paths

        # Second call — error counter must not increment again
        before = analyzer.metrics.cert_analysis_errors.labels(
            error_type='jks_password_failed'
        )._value.get()
        analyzer.parse_jks_certificates(jks_path)
        after = analyzer.metrics.cert_analysis_errors.labels(
            error_type='jks_password_failed'
        )._value.get()
        assert after == before

    def test_parse_jks_password_list_does_not_include_changeme_or_password(
        self, analyzer, temp_dir, monkeypatch
    ):
        """
        The JKS password list only tries env var, 'changeit', and empty string.
        'changeme' and 'password' are not attempted.
        """
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'JKS_AVAILABLE', True)
        monkeypatch.delenv('JKS_PASSWORD', raising=False)

        tried = []

        class _CapturingKeyStore:
            @staticmethod
            def load(path, password):
                tried.append(password)
                raise Exception("wrong password")

        import types
        jks_stub = types.ModuleType('jks')
        jks_stub.KeyStore = _CapturingKeyStore
        jks_stub.util = types.SimpleNamespace(BadKeystoreFormatException=Exception)
        monkeypatch.setattr(_ca, 'jks', jks_stub, raising=False)

        jks_path = os.path.join(temp_dir, "pw-list.jks")
        with open(jks_path, 'wb') as f:
            f.write(b'dummy')

        analyzer.parse_jks_certificates(jks_path)

        assert 'changeme' not in tried
        assert 'password'  not in tried

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


class TestProcessEventTimestamp:
    """
    Tests that last_event_timestamp is updated correctly in process_event,
    including when cert files are skipped due to password failure caching.
    """

    def _make_mock_event(self, cert_path):
        """Build a minimal mock Tetragon kprobe event for the given path."""
        class _MockArg:
            def __init__(self, path):
                self.string_arg = path
            def HasField(self, name):
                return name == 'string_arg'

        class _MockProcess:
            binary    = '/usr/bin/java'
            pid       = 1234
            arguments = ''
            def HasField(self, name):
                return False

        class _MockKprobe:
            def __init__(self, path):
                self.process = _MockProcess()
                self.args    = [_MockArg(path)]

        class _MockEvent:
            def __init__(self_, path):
                self_._kprobe = _MockKprobe(path)
            def HasField(self_, name):
                return name == 'process_kprobe'
            @property
            def process_kprobe(self_):
                return self_._kprobe

        return _MockEvent(cert_path)

    def test_timestamp_updated_when_cert_file_skipped_due_to_password_failure(
        self, analyzer, temp_dir
    ):
        """
        last_event_timestamp must be updated even when analyze_certificate
        returns [] because the file is in password_failed_paths.

        The mock event carries the bare path (no /host prefix). The analyzer
        prepends /host internally, so we register that prefixed path in
        password_failed_paths. No actual /host directory is needed.
        """
        disk_path = os.path.join(temp_dir, "pw-skip.p12")
        cert, key = TestCertificateGeneration.generate_certificate("pw-skip.example.com", 365)
        p12_data  = _make_pkcs12(cert, key, password=b'supersecret')
        with open(disk_path, 'wb') as f:
            f.write(p12_data)

        # The analyzer prepends /host to paths from events — register that
        # prefixed path so the file is recognised as previously failed
        host_path = '/host' + disk_path
        analyzer.password_failed_paths.add(host_path)
        analyzer.metrics.last_event_timestamp._value.set(0)

        # Event carries the bare (non-/host) path; analyzer adds /host
        analyzer.process_event(self._make_mock_event(disk_path))

        assert analyzer.metrics.last_event_timestamp._value.get() > 0, \
            "last_event_timestamp was not updated for a skipped password-failed file"

    def test_timestamp_updated_when_cert_file_successfully_parsed(
        self, analyzer, temp_dir
    ):
        """
        last_event_timestamp is updated when a cert is successfully parsed.

        Pre-seeds known_certs so process_event takes the re-detection branch,
        which avoids needing the /host symlink to exist on the runner.
        """
        disk_path = os.path.join(temp_dir, "ts-test.pem")
        cert, _   = TestCertificateGeneration.generate_certificate("ts-test.example.com", 365)
        TestCertificateGeneration.save_certificate_pem(cert, disk_path)

        # Pre-seed known_certs with the /host-prefixed path so process_event
        # hits the re-detection branch and updates the timestamp without
        # needing to read from /host on the filesystem
        host_path = '/host' + disk_path
        dummy = CertificateInfo(
            path=host_path, subject='CN=ts-test', issuer='CN=ca',
            serial_number='1',
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=365),
            process='test', pid=1,
        )
        analyzer.known_certs[dummy.unique_key] = dummy
        analyzer.metrics.last_event_timestamp._value.set(0)

        analyzer.process_event(self._make_mock_event(disk_path))

        assert analyzer.metrics.last_event_timestamp._value.get() > 0


class TestLRUCache:
    """
    Tests for the LRUCache class — eviction, LRU ordering, minimum size
    enforcement, set-like interface, and dict-like interface.
    """

    def test_basic_get_set(self):
        """Values can be stored and retrieved."""
        cache = LRUCache(maxsize=10_000)
        cache['a'] = 1
        assert cache['a'] == 1

    def test_contains(self):
        """'in' operator works correctly."""
        cache = LRUCache(maxsize=10_000)
        cache['x'] = True
        assert 'x' in cache
        assert 'y' not in cache

    def test_len(self):
        """len() reflects current entry count."""
        cache = LRUCache(maxsize=10_000)
        for i in range(5):
            cache[str(i)] = i
        assert len(cache) == 5

    def test_evicts_lru_entry_when_full(self):
        """When at capacity, the least-recently-used entry is evicted."""
        cache = LRUCache(maxsize=10_000)
        # Fill to capacity using internal store directly for speed
        for i in range(10_000):
            cache._store[str(i)] = i
        # 'str(0)' is the LRU entry — adding one more should evict it
        cache['new'] = 'new'
        assert '0' not in cache
        assert 'new' in cache
        assert len(cache) == 10_000

    def test_access_promotes_to_mru(self):
        """Accessing an entry moves it to the MRU end, protecting it from eviction."""
        cache = LRUCache(maxsize=10_000)
        for i in range(10_000):
            cache._store[str(i)] = i
        # Access '0' — it should move to MRU end
        _ = cache['0']
        # Add a new entry — '1' (now LRU) should be evicted, not '0'
        cache['new'] = 'new'
        assert '0' in cache
        assert '1' not in cache

    def test_update_existing_key_does_not_grow(self):
        """Updating an existing key does not add a new entry."""
        cache = LRUCache(maxsize=10_000)
        cache['a'] = 1
        cache['a'] = 2
        assert len(cache) == 1
        assert cache['a'] == 2

    def test_delete(self):
        """Entries can be deleted."""
        cache = LRUCache(maxsize=10_000)
        cache['a'] = 1
        del cache['a']
        assert 'a' not in cache
        assert len(cache) == 0

    def test_add_and_discard_set_interface(self):
        """add() and discard() provide a Set-like interface."""
        cache = LRUCache(maxsize=10_000)
        cache.add('path/to/keystore.jks')
        assert 'path/to/keystore.jks' in cache
        cache.discard('path/to/keystore.jks')
        assert 'path/to/keystore.jks' not in cache
        # discard on absent key must not raise
        cache.discard('nonexistent')

    def test_minimum_size_floor_enforced(self):
        """Requesting a size below CACHE_MIN_SIZE is silently raised to the minimum."""
        import cert_analyzer as _ca
        cache = LRUCache(maxsize=1)
        assert cache.maxsize == _ca.CACHE_MIN_SIZE

    def test_clear(self):
        """clear() empties the cache."""
        cache = LRUCache(maxsize=10_000)
        for i in range(5):
            cache[str(i)] = i
        cache.clear()
        assert len(cache) == 0

    def test_get_with_default(self):
        """get() returns default when key is absent."""
        cache = LRUCache(maxsize=10_000)
        assert cache.get('missing', 'default') == 'default'
        cache['key'] = 'value'
        assert cache.get('key', 'default') == 'value'

    def test_items_keys_values(self):
        """items(), keys(), values() expose the underlying store."""
        cache = LRUCache(maxsize=10_000)
        cache['a'] = 1
        cache['b'] = 2
        assert set(cache.keys()) == {'a', 'b'}
        assert set(cache.values()) == {1, 2}
        assert set(cache.items()) == {('a', 1), ('b', 2)}


class TestCacheIntegration:
    """
    Integration tests verifying that known_certs, processed_paths, and
    password_failed_paths are wired to LRUCache and that Prometheus
    cache size metrics are updated correctly.
    """

    def test_analyzer_uses_lru_cache_for_known_certs(self, analyzer):
        """known_certs is an LRUCache instance."""
        assert isinstance(analyzer.known_certs, LRUCache)

    def test_analyzer_uses_lru_cache_for_processed_paths(self, analyzer):
        """processed_paths is an LRUCache instance."""
        assert isinstance(analyzer.processed_paths, LRUCache)

    def test_analyzer_uses_lru_cache_for_password_failed_paths(self, analyzer):
        """password_failed_paths is an LRUCache instance."""
        assert isinstance(analyzer.password_failed_paths, LRUCache)

    def test_cache_max_size_metric_set_on_init(self, analyzer):
        """cert_analyzer_cache_max_size gauge is set at startup."""
        import cert_analyzer as _ca
        val = analyzer.metrics.cache_max_size._value.get()
        assert val == _ca.CACHE_MAX_SIZE

    def test_cache_size_metrics_updated_after_analyze(self, analyzer, temp_dir):
        """Cache size metrics update after a certificate is analyzed."""
        cert, _ = TestCertificateGeneration.generate_certificate("metrics.example.com", 365)
        path = os.path.join(temp_dir, "metrics.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        analyzer.analyze_certificate(path, "test", 1)

        assert analyzer.metrics.cache_processed_paths_size._value.get() == 1

    def test_cache_size_metrics_updated_after_password_failure(
        self, analyzer, temp_dir, monkeypatch
    ):
        """cache_password_failed_size metric updates after a password failure."""
        cert, key = TestCertificateGeneration.generate_certificate("fail.example.com", 365)
        p12_data  = _make_pkcs12(cert, key, password=b'supersecret')
        path      = os.path.join(temp_dir, "fail.p12")
        with open(path, 'wb') as f:
            f.write(p12_data)
        monkeypatch.delenv('PKCS12_PASSWORD', raising=False)

        analyzer.parse_pkcs12_certificates(path)

        assert analyzer.metrics.cache_password_failed_size._value.get() == 1

    def test_known_certs_evicts_lru_when_full(self, analyzer, temp_dir):
        """
        When known_certs reaches CACHE_MAX_SIZE the LRU entry is evicted
        rather than the cache growing beyond the cap.
        """
        import cert_analyzer as _ca

        # Directly fill known_certs to capacity using internal store
        for i in range(_ca.CACHE_MAX_SIZE):
            analyzer.known_certs._store[f"path:{i}:serial"] = None

        assert len(analyzer.known_certs) == _ca.CACHE_MAX_SIZE

        # Add one more — should evict the oldest, not grow
        analyzer.known_certs[f"path:{_ca.CACHE_MAX_SIZE}:serial"] = None

        assert len(analyzer.known_certs) == _ca.CACHE_MAX_SIZE
        assert "path:0:serial" not in analyzer.known_certs


class TestChecksum:
    """
    Tests for SHA-256 checksum computation on parsed certificates.
    Covers enabled/disabled behaviour, correctness, DER encoding,
    error handling, and the disabled-by-default contract.

    Checksum is now controlled via analyzer.checksum_enabled (an instance
    variable set from the config file or CERT_CHECKSUM_ENABLED env var in
    main()) rather than the module-level CERT_CHECKSUM_ENABLED constant.
    Tests set analyzer.checksum_enabled directly to reflect this.
    """

    def test_checksum_empty_by_default(self, analyzer, temp_dir):
        """checksum field is empty string when checksum_enabled is False (the default)."""
        assert analyzer.checksum_enabled is False, \
            "checksum_enabled must default to False on the analyzer instance"

        cert, _ = TestCertificateGeneration.generate_certificate("checksum.example.com", 365)
        path = os.path.join(temp_dir, "checksum.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert len(cert_infos) == 1
        assert cert_infos[0].checksum == ""

    def test_checksum_populated_when_enabled(self, analyzer, temp_dir):
        """checksum is a non-empty hex string when checksum_enabled=True."""
        analyzer.checksum_enabled = True

        cert, _ = TestCertificateGeneration.generate_certificate("checksum-on.example.com", 365)
        path = os.path.join(temp_dir, "checksum-on.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert len(cert_infos) == 1
        assert cert_infos[0].checksum != ""
        assert len(cert_infos[0].checksum) == 64  # SHA-256 hex digest is always 64 chars

    def test_checksum_is_valid_sha256_hex(self, analyzer, temp_dir):
        """checksum contains only valid lowercase hexadecimal characters."""
        analyzer.checksum_enabled = True

        cert, _ = TestCertificateGeneration.generate_certificate("hex.example.com", 365)
        path = os.path.join(temp_dir, "hex.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        checksum = cert_infos[0].checksum
        assert all(c in '0123456789abcdef' for c in checksum)

    def test_checksum_matches_manual_sha256(self, analyzer, temp_dir):
        """checksum matches SHA-256 of the DER-encoded certificate bytes."""
        import hashlib
        from cryptography.hazmat.primitives.serialization import Encoding
        analyzer.checksum_enabled = True

        cert, _ = TestCertificateGeneration.generate_certificate("sha256.example.com", 365)
        path = os.path.join(temp_dir, "sha256.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)

        # Compute expected checksum independently
        certs = analyzer.parse_certificates(path)
        der_bytes = certs[0].public_bytes(Encoding.DER)
        expected = hashlib.sha256(der_bytes).hexdigest()

        assert cert_infos[0].checksum == expected

    def test_checksum_differs_for_different_certs(self, analyzer, temp_dir):
        """Two different certificates produce different checksums."""
        analyzer.checksum_enabled = True

        cert1, _ = TestCertificateGeneration.generate_certificate("a.example.com", 365)
        cert2, _ = TestCertificateGeneration.generate_certificate("b.example.com", 365)
        path1 = os.path.join(temp_dir, "a.pem")
        path2 = os.path.join(temp_dir, "b.pem")
        TestCertificateGeneration.save_certificate_pem(cert1, path1)
        TestCertificateGeneration.save_certificate_pem(cert2, path2)

        infos1 = analyzer.analyze_certificate(path1, "test", 1)
        infos2 = analyzer.analyze_certificate(path2, "test", 1)

        assert infos1[0].checksum != infos2[0].checksum

    def test_checksum_identical_for_same_cert_at_different_paths(
        self, analyzer, temp_dir
    ):
        """
        The same certificate file copied to two paths produces identical checksums,
        demonstrating that checksum can correlate cert identity across paths.
        """
        import shutil
        analyzer.checksum_enabled = True

        cert, _ = TestCertificateGeneration.generate_certificate("same.example.com", 365)
        path1 = os.path.join(temp_dir, "copy1.pem")
        path2 = os.path.join(temp_dir, "copy2.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path1)
        shutil.copy2(path1, path2)

        infos1 = analyzer.analyze_certificate(path1, "test", 1)
        infos2 = analyzer.analyze_certificate(path2, "test", 1)

        assert infos1[0].checksum == infos2[0].checksum

    def test_checksum_disabled_via_config_file(self, temp_dir):
        """checksum_enabled=False when config file has checksum_enabled = false."""
        import configparser
        from cert_analyzer import cfg
        cp = configparser.ConfigParser()
        cp.read_dict({'certificates': {'checksum_enabled': 'false'}})
        result = cfg(cp, 'certificates', 'checksum_enabled', 'CERT_CHECKSUM_ENABLED', 'false')
        assert result.lower() == 'false'
        assert (result.lower() == 'true') is False

    def test_checksum_enabled_via_config_file(self, temp_dir):
        """checksum_enabled=True when config file has checksum_enabled = true."""
        import configparser
        from cert_analyzer import cfg
        cp = configparser.ConfigParser()
        cp.read_dict({'certificates': {'checksum_enabled': 'true'}})
        result = cfg(cp, 'certificates', 'checksum_enabled', 'CERT_CHECKSUM_ENABLED', 'false')
        assert result.lower() == 'true'
        assert (result.lower() == 'true') is True

    def test_checksum_enabled_via_env_var_when_no_config(self, monkeypatch, temp_dir):
        """checksum_enabled=True when env var set and no config file entry."""
        import configparser
        from cert_analyzer import cfg
        monkeypatch.setenv('CERT_CHECKSUM_ENABLED', 'true')
        cp = configparser.ConfigParser()  # empty — no config file
        result = cfg(cp, 'certificates', 'checksum_enabled', 'CERT_CHECKSUM_ENABLED', 'false')
        assert result.lower() == 'true'

    def test_config_file_takes_precedence_over_env_var(self, monkeypatch, temp_dir):
        """Config file value overrides env var — config file wins."""
        import configparser
        from cert_analyzer import cfg
        monkeypatch.setenv('CERT_CHECKSUM_ENABLED', 'true')  # env var says enabled
        cp = configparser.ConfigParser()
        cp.read_dict({'certificates': {'checksum_enabled': 'false'}})  # config says disabled
        result = cfg(cp, 'certificates', 'checksum_enabled', 'CERT_CHECKSUM_ENABLED', 'false')
        assert result.lower() == 'false'  # config file wins

    def test_checksum_error_does_not_prevent_cert_info_return(
        self, analyzer, temp_dir, monkeypatch
    ):
        """
        If checksum computation fails (e.g. public_bytes raises), extract_certificate_info
        still returns a valid CertificateInfo with an empty checksum rather than None.
        """
        analyzer.checksum_enabled = True

        cert, _ = TestCertificateGeneration.generate_certificate("err.example.com", 365)
        path = os.path.join(temp_dir, "err.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        # Patch hashlib.sha256 to raise so the checksum path fails
        import hashlib as _hashlib

        def _raising_sha256(*args, **kwargs):
            raise RuntimeError("simulated hash failure")

        monkeypatch.setattr(_hashlib, 'sha256', _raising_sha256)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)

        # Must still return cert info — checksum failure is non-fatal
        assert len(cert_infos) == 1
        assert cert_infos[0].checksum == ""


class TestFipsComplianceEnabled:
    """
    Tests for the fips_compliance_enabled config option.

    When True (the default): FIPS compliance is checked per-certificate and the
    results are stored in CertificateInfo fields and emitted as Prometheus metrics.

    When False: the check is skipped entirely — FIPS fields stay at empty defaults,
    the cert_fips_compliant metric is not emitted, and no FIPS log lines appear.
    """

    # ── Default / instance behaviour ──────────────────────────────────────────

    def test_fips_compliance_enabled_by_default(self, analyzer):
        """fips_compliance_enabled defaults to True on a new analyzer instance."""
        assert analyzer.fips_compliance_enabled is True

    def test_fips_fields_populated_when_enabled(self, analyzer, temp_dir):
        """FIPS fields on CertificateInfo are populated when fips_compliance_enabled=True."""
        assert analyzer.fips_compliance_enabled is True

        cert, _ = TestCertificateGeneration.generate_certificate("fips-on.example.com", 365)
        path = os.path.join(temp_dir, "fips-on.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert len(cert_infos) == 1
        info = cert_infos[0]
        # generate_certificate produces RSA-2048 / SHA-256 — always compliant
        assert info.key_algorithm == 'RSA'
        assert info.key_size == 2048
        assert info.signature_hash == 'sha256'
        assert info.fips_compliant is True
        assert info.fips_violations == []

    def test_fips_fields_empty_when_disabled(self, analyzer, temp_dir):
        """FIPS fields are at empty defaults when fips_compliance_enabled=False."""
        analyzer.fips_compliance_enabled = False

        cert, _ = TestCertificateGeneration.generate_certificate("fips-off.example.com", 365)
        path = os.path.join(temp_dir, "fips-off.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert len(cert_infos) == 1
        info = cert_infos[0]
        assert info.key_algorithm == ''
        assert info.key_size == 0
        assert info.signature_hash == ''
        assert info.curve_name == ''
        assert info.fips_compliant is False
        assert info.fips_violations == []

    def test_multi_cert_bundle_all_skipped_when_disabled(self, analyzer, temp_dir):
        """All certs in a multi-cert bundle have empty FIPS fields when disabled."""
        analyzer.fips_compliance_enabled = False

        certs_and_keys = [
            TestCertificateGeneration.generate_certificate(f"multi{i}.example.com", 365)
            for i in range(3)
        ]
        path = os.path.join(temp_dir, "bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem(
            [c for c, _ in certs_and_keys], path
        )

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert len(cert_infos) == 3
        for info in cert_infos:
            assert info.key_algorithm == ''
            assert info.fips_compliant is False
            assert info.fips_violations == []

    # ── _fips_check() call gating ──────────────────────────────────────────────

    def test_fips_check_not_called_when_disabled(self, analyzer, temp_dir, monkeypatch):
        """_fips_check() is never invoked when fips_compliance_enabled=False."""
        analyzer.fips_compliance_enabled = False

        calls = []

        import cert_analyzer as _ca
        from fips_compliance_checker import check_certificate as _real

        def _spy(cert):
            calls.append(cert)
            return _real(cert)

        monkeypatch.setattr(_ca, '_fips_check', _spy)

        cert, _ = TestCertificateGeneration.generate_certificate("skip.example.com", 365)
        path = os.path.join(temp_dir, "skip.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        analyzer.analyze_certificate(path, "test", 1)
        assert calls == [], "_fips_check must not be called when fips_compliance_enabled=False"

    def test_fips_check_called_when_enabled(self, analyzer, temp_dir, monkeypatch):
        """_fips_check() is called once per certificate when fips_compliance_enabled=True."""
        assert analyzer.fips_compliance_enabled is True

        calls = []

        import cert_analyzer as _ca
        from fips_compliance_checker import check_certificate as _real

        def _spy(cert):
            calls.append(cert)
            return _real(cert)

        monkeypatch.setattr(_ca, '_fips_check', _spy)

        cert, _ = TestCertificateGeneration.generate_certificate("check.example.com", 365)
        path = os.path.join(temp_dir, "check.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        analyzer.analyze_certificate(path, "test", 1)
        assert len(calls) == 1, "_fips_check must be called exactly once when enabled"

    def test_fips_check_error_is_non_fatal(self, analyzer, temp_dir, monkeypatch):
        """If _fips_check() raises, extract_certificate_info still returns CertificateInfo."""
        import cert_analyzer as _ca

        def _raising(cert):
            raise RuntimeError("simulated fips error")

        monkeypatch.setattr(_ca, '_fips_check', _raising)

        cert, _ = TestCertificateGeneration.generate_certificate("fips-err.example.com", 365)
        path = os.path.join(temp_dir, "fips-err.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert len(cert_infos) == 1
        info = cert_infos[0]
        assert info.fips_compliant is False
        assert 'FIPS check error' in info.fips_violations

    # ── Prometheus metric gating ───────────────────────────────────────────────

    def test_prometheus_metric_emitted_when_enabled(self, analyzer, temp_dir):
        """cert_fips_compliant metric has samples after update_certificate_metrics when enabled."""
        assert analyzer.fips_compliance_enabled is True

        cert, _ = TestCertificateGeneration.generate_certificate("metric-on.example.com", 365)
        path = os.path.join(temp_dir, "metric-on.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert cert_infos
        analyzer.metrics.update_certificate_metrics(cert_infos[0])

        samples = list(analyzer.metrics.cert_fips_compliant.collect()[0].samples)
        assert len(samples) > 0, \
            "cert_fips_compliant must have at least one sample when FIPS checking is enabled"

    def test_prometheus_metric_not_emitted_when_disabled(self, analyzer, temp_dir):
        """cert_fips_compliant metric has no samples after update_certificate_metrics when disabled."""
        analyzer.fips_compliance_enabled = False

        cert, _ = TestCertificateGeneration.generate_certificate("metric-off.example.com", 365)
        path = os.path.join(temp_dir, "metric-off.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert cert_infos
        analyzer.metrics.update_certificate_metrics(cert_infos[0])

        samples = list(analyzer.metrics.cert_fips_compliant.collect()[0].samples)
        assert len(samples) == 0, \
            "cert_fips_compliant must have no samples when FIPS checking is disabled"

    def test_prometheus_metric_value_one_for_compliant_cert(self, analyzer, temp_dir):
        """cert_fips_compliant metric is set to 1.0 for a FIPS-compliant certificate."""
        cert, _ = TestCertificateGeneration.generate_certificate("compliant.example.com", 365)
        path = os.path.join(temp_dir, "compliant.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert cert_infos
        analyzer.metrics.update_certificate_metrics(cert_infos[0])

        samples = list(analyzer.metrics.cert_fips_compliant.collect()[0].samples)
        assert len(samples) == 1
        assert samples[0].value == 1.0

    # ── Logging output ─────────────────────────────────────────────────────────

    def test_compliant_cert_fips_line_logged_when_enabled(self, analyzer, temp_dir, caplog):
        """A FIPS-compliant cert produces a 'FIPS: compliant' log line when enabled."""
        cert, _ = TestCertificateGeneration.generate_certificate("log-on.example.com", 365)
        path = os.path.join(temp_dir, "log-on.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert cert_infos

        with caplog.at_level(logging.DEBUG):
            analyzer.log_certificate_status(cert_infos[0])

        assert any(
            'FIPS' in r.message and 'compliant' in r.message
            for r in caplog.records
        ), "Expected a FIPS compliant log line when fips_compliance_enabled=True"

    def test_no_fips_log_lines_when_disabled(self, analyzer, temp_dir, caplog):
        """No FIPS log lines appear when fips_compliance_enabled=False."""
        analyzer.fips_compliance_enabled = False

        cert, _ = TestCertificateGeneration.generate_certificate("log-off.example.com", 365)
        path = os.path.join(temp_dir, "log-off.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert cert_infos

        with caplog.at_level(logging.DEBUG):
            analyzer.log_certificate_status(cert_infos[0])

        fips_lines = [r for r in caplog.records if 'FIPS' in r.message]
        assert fips_lines == [], \
            f"Expected no FIPS log lines when disabled, got: {[r.message for r in fips_lines]}"

    def test_fips_violation_logged_as_warning_when_enabled(self, analyzer, temp_dir, caplog):
        """FIPS violations are logged as WARNING when fips_compliance_enabled=True."""
        cert, _ = TestCertificateGeneration.generate_certificate("warn.example.com", 365)
        path = os.path.join(temp_dir, "warn.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert cert_infos
        info = cert_infos[0]
        # Inject a violation to simulate a non-compliant cert
        info.fips_compliant = False
        info.fips_violations = ["Signature hash 'sha1' is not FIPS-approved (use SHA-256 or stronger)"]

        with caplog.at_level(logging.WARNING):
            analyzer.log_certificate_status(info)

        assert any('FIPS NON-COMPLIANT' in r.message for r in caplog.records), \
            "Expected a FIPS NON-COMPLIANT warning when violations are present"

    # ── Config file / env var resolution ──────────────────────────────────────

    def test_disabled_via_config_file(self):
        """cfg() resolves to 'false' when config file sets fips_compliance_enabled = false."""
        import configparser
        from cert_analyzer import cfg
        cp = configparser.ConfigParser()
        cp.read_dict({'certificates': {'fips_compliance_enabled': 'false'}})
        result = cfg(cp, 'certificates', 'fips_compliance_enabled', 'FIPS_COMPLIANCE_ENABLED', 'true')
        assert result.lower() == 'false'

    def test_enabled_via_config_file(self):
        """cfg() resolves to 'true' when config file sets fips_compliance_enabled = true."""
        import configparser
        from cert_analyzer import cfg
        cp = configparser.ConfigParser()
        cp.read_dict({'certificates': {'fips_compliance_enabled': 'true'}})
        result = cfg(cp, 'certificates', 'fips_compliance_enabled', 'FIPS_COMPLIANCE_ENABLED', 'true')
        assert result.lower() == 'true'

    def test_disabled_via_env_var(self, monkeypatch):
        """cfg() resolves to 'false' from FIPS_COMPLIANCE_ENABLED=false when no config entry."""
        import configparser
        from cert_analyzer import cfg
        monkeypatch.setenv('FIPS_COMPLIANCE_ENABLED', 'false')
        cp = configparser.ConfigParser()
        result = cfg(cp, 'certificates', 'fips_compliance_enabled', 'FIPS_COMPLIANCE_ENABLED', 'true')
        assert result.lower() == 'false'

    def test_config_file_takes_precedence_over_env_var(self, monkeypatch):
        """Config file value overrides env var — config enabled wins over env disabled."""
        import configparser
        from cert_analyzer import cfg
        monkeypatch.setenv('FIPS_COMPLIANCE_ENABLED', 'false')  # env says disabled
        cp = configparser.ConfigParser()
        cp.read_dict({'certificates': {'fips_compliance_enabled': 'true'}})  # config says enabled
        result = cfg(cp, 'certificates', 'fips_compliance_enabled', 'FIPS_COMPLIANCE_ENABLED', 'true')
        assert result.lower() == 'true'  # config file wins

    def test_default_is_enabled_when_no_config_or_env(self, monkeypatch):
        """fips_compliance_enabled defaults to 'true' when neither config nor env var is set."""
        import configparser
        from cert_analyzer import cfg
        monkeypatch.delenv('FIPS_COMPLIANCE_ENABLED', raising=False)
        cp = configparser.ConfigParser()
        result = cfg(cp, 'certificates', 'fips_compliance_enabled', 'FIPS_COMPLIANCE_ENABLED', 'true')
        assert result.lower() == 'true'


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
        # Collect samples and verify both version label keys and values are present
        samples = list(analyzer.metrics.tetragon_version_info.collect()[0].samples)
        assert len(samples) > 0, "No samples emitted from tetragon_version_info"
        label_keys = samples[0].labels.keys()
        assert 'build_version'   in label_keys
        assert 'runtime_version' in label_keys
        assert samples[0].labels['build_version']   == 'v1.1.0'
        assert samples[0].labels['runtime_version'] == 'v1.2.0'

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

    def test_get_runtime_version_returns_unknown_when_get_version_request_absent(
        self, analyzer, monkeypatch, caplog
    ):
        """Tetragon <= v1.1.0 lacks GetVersionRequest — must return 'unknown' and warn."""
        import cert_analyzer as _ca
        monkeypatch.delattr(_ca.tetragon_pb2, 'GetVersionRequest')
        stub = _MockVersionStub(version='v1.0.0')

        with caplog.at_level(logging.WARNING, logger='cert_analyzer'):
            result = analyzer.get_runtime_tetragon_version(stub)

        assert result == 'unknown'
        assert any('GetVersionRequest' in r.message for r in caplog.records)

    def test_get_runtime_version_does_not_call_stub_when_get_version_request_absent(
        self, analyzer, monkeypatch
    ):
        """No RPC call is made when GetVersionRequest is missing from the bindings."""
        import cert_analyzer as _ca
        monkeypatch.delattr(_ca.tetragon_pb2, 'GetVersionRequest')

        calls = []
        stub = _MockVersionStub(version='v1.0.0')
        stub.GetVersion = lambda *a, **kw: calls.append(1)  # noqa: E731

        analyzer.get_runtime_tetragon_version(stub)

        assert calls == [], "GetVersion RPC should not be called on old Tetragon bindings"


class TestBuildInfo:
    """
    Tests for the cert_analyzer_build Info metric which exposes the
    cert-analyzer version and Tetragon build version as Prometheus labels.

    The build_info metric is populated at PrometheusMetrics.__init__ time
    from the module-level constants, so we read labels from the already-
    initialised metric on the analyzer fixture rather than creating a new
    PrometheusMetrics instance (which would clash with the registry).
    """

    def test_build_info_metric_exposes_version_label(self, analyzer):
        """cert_analyzer_build metric exposes a 'version' label."""
        samples = list(analyzer.metrics.build_info.collect()[0].samples)
        assert len(samples) > 0
        assert 'version' in samples[0].labels

    def test_build_info_metric_exposes_tetragon_build_version_label(self, analyzer):
        """cert_analyzer_build metric exposes a 'tetragon_build_version' label."""
        samples = list(analyzer.metrics.build_info.collect()[0].samples)
        assert len(samples) > 0
        assert 'tetragon_build_version' in samples[0].labels

    def test_build_info_version_matches_module_constant(self, analyzer):
        """The 'version' label value matches CERT_ANALYZER_VERSION at init time."""
        import cert_analyzer as _ca
        samples = list(analyzer.metrics.build_info.collect()[0].samples)
        assert samples[0].labels['version'] == _ca.CERT_ANALYZER_VERSION

    def test_build_info_tetragon_version_matches_module_constant(self, analyzer):
        """The 'tetragon_build_version' label matches TETRAGON_BUILD_VERSION at init time."""
        import cert_analyzer as _ca
        samples = list(analyzer.metrics.build_info.collect()[0].samples)
        assert samples[0].labels['tetragon_build_version'] == _ca.TETRAGON_BUILD_VERSION

    def test_cert_analyzer_version_constant_reads_env(self, monkeypatch):
        """CERT_ANALYZER_VERSION env var is read correctly by os.getenv."""
        monkeypatch.setenv('CERT_ANALYZER_VERSION', 'v2.0.0-test')
        value = os.getenv('CERT_ANALYZER_VERSION', 'dev')
        assert value == 'v2.0.0-test'

    def test_cert_analyzer_version_defaults_to_dev(self, monkeypatch):
        """CERT_ANALYZER_VERSION defaults to 'dev' when env var is absent."""
        monkeypatch.delenv('CERT_ANALYZER_VERSION', raising=False)
        value = os.getenv('CERT_ANALYZER_VERSION', 'dev')
        assert value == 'dev'


# ── Reconnection and version monitor tests ────────────────────────────────────

import threading as _threading
import time as _time
import grpc
from tetragon import sensors_pb2_grpc


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
        metric_set_to_zero = _threading.Event()
        original_set = analyzer.metrics.analyzer_healthy.set

        def _watched_set(value):
            original_set(value)
            if value == 0:
                metric_set_to_zero.set()

        analyzer.metrics.analyzer_healthy.set = _watched_set

        class _DisconnectingStub:
            def GetEvents(self_, request, **kwargs):
                raise _MockRpcError()

            def GetVersion(self_, request, timeout=None):
                return _MockGetVersionResponse('v1.1.0')

        monkeypatch.setattr(grpc, 'insecure_channel', lambda *a, **kw: None)
        monkeypatch.setattr(sensors_pb2_grpc, 'FineGuidanceSensorsStub',
                            lambda ch: _DisconnectingStub())
        # Patch sleep on the cert_analyzer module so the retry backoff is instant
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca.time, 'sleep', lambda s: None)

        t = _threading.Thread(target=analyzer.start, daemon=True)
        t.start()

        assert metric_set_to_zero.wait(timeout=3.0), \
            "analyzer_healthy was never set to 0 after disconnect"
        assert analyzer.metrics.analyzer_healthy._value.get() == 0.0

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


# ── Certificate parsing exception handling tests ──────────────────────────────

class _BrokenCert:
    """
    A mock x509.Certificate whose attributes raise exceptions on access,
    simulating malformed or encrypted certificates that cannot be parsed.
    Allows selective breakage of individual fields.
    """
    def __init__(
        self,
        break_subject=False,
        break_issuer=False,
        break_serial=False,
        break_dates=False,
    ):
        self._break_subject = break_subject
        self._break_issuer  = break_issuer
        self._break_serial  = break_serial
        self._break_dates   = break_dates

        # Provide working defaults for fields not being broken
        self._subject = type('S', (), {
            'rfc4514_string': lambda s: 'CN=test',
            'get_attributes_for_oid': lambda s, oid: [],
        })()
        self._issuer = type('I', (), {
            'rfc4514_string': lambda s: 'CN=ca',
        })()

    @property
    def subject(self):
        if self._break_subject:
            raise ValueError("Simulated subject parse failure")
        return self._subject

    @property
    def issuer(self):
        if self._break_issuer:
            raise ValueError("Simulated issuer parse failure")
        return self._issuer

    @property
    def serial_number(self):
        if self._break_serial:
            raise ValueError("Simulated serial number parse failure")
        return 12345

    @property
    def not_valid_before(self):
        if self._break_dates:
            raise ValueError("Simulated date parse failure")
        return datetime.utcnow() - timedelta(days=1)

    @property
    def not_valid_after(self):
        if self._break_dates:
            raise ValueError("Simulated date parse failure")
        return datetime.utcnow() + timedelta(days=365)

    # not_valid_before_utc / not_valid_after_utc intentionally absent so
    # extract_certificate_info falls back to the naive properties above

    @property
    def extensions(self):
        raise x509.ExtensionNotFound(
            "No extensions", x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )


class TestCertificateParsingExceptions:
    """
    Tests that verify the analyzer degrades gracefully when certificate
    parsing raises exceptions — returning [] or None rather than crashing,
    and incrementing the appropriate error metrics.
    """

    def test_extract_info_returns_none_when_subject_raises(self, analyzer, temp_dir):
        """A cert whose subject raises returns None from extract_certificate_info."""
        cert = _BrokenCert(break_subject=True)
        result = analyzer.extract_certificate_info(cert, "/tmp/bad.pem", "test", 1)
        assert result is None

    def test_extract_info_returns_none_when_issuer_raises(self, analyzer, temp_dir):
        """A cert whose issuer raises returns None from extract_certificate_info."""
        cert = _BrokenCert(break_issuer=True)
        result = analyzer.extract_certificate_info(cert, "/tmp/bad.pem", "test", 1)
        assert result is None

    def test_extract_info_returns_none_when_serial_raises(self, analyzer, temp_dir):
        """A cert whose serial number raises returns None from extract_certificate_info."""
        cert = _BrokenCert(break_serial=True)
        result = analyzer.extract_certificate_info(cert, "/tmp/bad.pem", "test", 1)
        assert result is None

    def test_extract_info_returns_none_when_dates_raise(self, analyzer, temp_dir):
        """A cert whose validity dates raise returns None from extract_certificate_info."""
        cert = _BrokenCert(break_dates=True)
        result = analyzer.extract_certificate_info(cert, "/tmp/bad.pem", "test", 1)
        assert result is None

    def test_extract_info_increments_error_metric_on_failure(self, analyzer):
        """extract_certificate_info increments extraction_error metric when it returns None."""
        cert = _BrokenCert(break_subject=True)
        before = analyzer.metrics.cert_analysis_errors.labels(
            error_type='extraction_error'
        )._value.get()
        analyzer.extract_certificate_info(cert, "/tmp/bad.pem", "test", 1)
        after = analyzer.metrics.cert_analysis_errors.labels(
            error_type='extraction_error'
        )._value.get()
        assert after == before + 1

    def test_analyze_certificate_skips_broken_cert_in_bundle(self, analyzer, temp_dir):
        """
        In a multi-cert bundle, a broken cert is skipped and valid certs
        are still returned — the analyzer does not crash or return empty.
        """
        # Write a valid 2-cert bundle
        cert1, _ = TestCertificateGeneration.generate_certificate("valid1.example.com", 365)
        cert2, _ = TestCertificateGeneration.generate_certificate("valid2.example.com", 180)
        bundle_path = os.path.join(temp_dir, "bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem([cert1, cert2], bundle_path)

        # Patch parse_certificates to inject a broken cert between the two valid ones
        original_parse = analyzer.parse_certificates

        def _inject_broken(path):
            certs = original_parse(path)
            return [certs[0], _BrokenCert(break_subject=True), certs[1]]

        analyzer.parse_certificates = _inject_broken

        cert_infos = analyzer.analyze_certificate(bundle_path, "test", 1)

        # Two valid certs should come through; broken one silently skipped
        assert len(cert_infos) == 2
        common_names = [c.common_name for c in cert_infos]
        assert "valid1.example.com" in common_names
        assert "valid2.example.com" in common_names

    def test_analyze_certificate_returns_empty_when_all_certs_broken(self, analyzer, temp_dir):
        """If every cert in a file is broken, analyze_certificate returns []."""
        cert, _ = TestCertificateGeneration.generate_certificate("test.example.com", 365)
        path = os.path.join(temp_dir, "single.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        analyzer.parse_certificates = lambda p: [_BrokenCert(break_dates=True)]

        result = analyzer.analyze_certificate(path, "test", 1)
        assert result == []

    def test_analyze_certificate_does_not_crash_on_parse_exception(self, analyzer, temp_dir):
        """
        If parse_certificates itself raises, analyze_certificate returns []
        rather than propagating the exception.
        """
        cert, _ = TestCertificateGeneration.generate_certificate("test.example.com", 365)
        path = os.path.join(temp_dir, "single.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        def _raise(*args, **kwargs):
            raise RuntimeError("Simulated catastrophic parse failure")

        analyzer.parse_certificates = _raise

        try:
            result = analyzer.analyze_certificate(path, "test", 1)
            assert result == []
        except Exception as exc:
            pytest.fail(f"analyze_certificate propagated exception: {exc}")

    def test_extract_info_handles_valid_cert_with_utc_dates(self, analyzer, temp_dir):
        """
        extract_certificate_info correctly handles certs that return
        timezone-aware datetimes from not_valid_after_utc (cryptography >= 42).
        The returned CertificateInfo should have naive datetimes.
        """
        from datetime import timezone

        cert, _ = TestCertificateGeneration.generate_certificate("utc.example.com", 365)
        path = os.path.join(temp_dir, "utc.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        # Wrap the cert to return tz-aware datetimes from the _utc properties
        class _UTCAwareCert:
            def __init__(self, inner):
                self._inner = inner

            def __getattr__(self, name):
                return getattr(self._inner, name)

            @property
            def not_valid_before_utc(self):
                return self._inner.not_valid_before.replace(tzinfo=timezone.utc)

            @property
            def not_valid_after_utc(self):
                return self._inner.not_valid_after.replace(tzinfo=timezone.utc)

        certs = analyzer.parse_certificates(path)
        wrapped = _UTCAwareCert(certs[0])
        info = analyzer.extract_certificate_info(wrapped, path, "test", 1)

        assert info is not None
        assert info.not_before.tzinfo is None, "not_before should be naive datetime"
        assert info.not_after.tzinfo  is None, "not_after should be naive datetime"
        assert info.common_name == "utc.example.com"


# ── Health server tests ───────────────────────────────────────────────────────

import urllib.request
import urllib.error
import json as _json

from cert_analyzer import HealthServer


class _MockChannel:
    """Mock gRPC channel with controllable connectivity state."""
    def __init__(self, state=grpc.ChannelConnectivity.READY):
        self._state = state
        self._channel = self

    def check_connectivity_state(self, try_to_connect):
        return self._state


def _make_health_server(analyzer, grace=0, staleness=300, port=None):
    """
    Create a HealthServer for testing.
    Uses grace=0 so readiness checks are immediate unless overridden.
    Port is auto-assigned if not specified.
    """
    import socket
    if port is None:
        # Find a free port
        with socket.socket() as s:
            s.bind(('', 0))
            port = s.getsockname()[1]
    return HealthServer(
        analyzer=analyzer,
        port=port,
        grace_period_seconds=grace,
        staleness_seconds=staleness,
    )


def _get(port, path):
    """Make a GET request to the health server, return (status_code, body_dict)."""
    try:
        with urllib.request.urlopen(f'http://localhost:{port}{path}', timeout=2) as r:
            raw = r.read()
            return r.status, _json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, _json.loads(raw) if raw else {}


class TestHealthServerLiveness:
    """Tests for GET /healthz (liveness probe)."""

    def test_liveness_returns_200_when_no_channel_yet(self, analyzer):
        """Liveness is 200 before the gRPC channel is created (starting up)."""
        hs = _make_health_server(analyzer)
        hs.start()
        status, body = _get(hs.port, '/healthz')
        hs.stop()
        assert status == 200
        assert body['status'] == 'ok'

    def test_liveness_returns_200_when_channel_ready(self, analyzer):
        """Liveness is 200 when the gRPC channel is in READY state."""
        hs = _make_health_server(analyzer)
        hs.set_channel(_MockChannel(grpc.ChannelConnectivity.READY))
        hs.start()
        status, body = _get(hs.port, '/healthz')
        hs.stop()
        assert status == 200

    def test_liveness_returns_200_when_channel_transient_failure(self, analyzer):
        """
        Liveness is 200 when Tetragon is temporarily unavailable
        (TRANSIENT_FAILURE) — the reconnect loop handles this, not the probe.
        """
        hs = _make_health_server(analyzer)
        hs.set_channel(_MockChannel(grpc.ChannelConnectivity.TRANSIENT_FAILURE))
        hs.start()
        status, body = _get(hs.port, '/healthz')
        hs.stop()
        assert status == 200

    def test_liveness_returns_200_when_channel_idle(self, analyzer):
        """Liveness is 200 when channel is IDLE (not yet connected)."""
        hs = _make_health_server(analyzer)
        hs.set_channel(_MockChannel(grpc.ChannelConnectivity.IDLE))
        hs.start()
        status, body = _get(hs.port, '/healthz')
        hs.stop()
        assert status == 200

    def test_liveness_returns_503_when_channel_shutdown(self, analyzer):
        """Liveness is 503 only when the channel has been explicitly shut down."""
        hs = _make_health_server(analyzer)
        hs.set_channel(_MockChannel(grpc.ChannelConnectivity.SHUTDOWN))
        hs.start()
        status, body = _get(hs.port, '/healthz')
        hs.stop()
        assert status == 503
        assert body['status'] == 'fail'

    def test_liveness_returns_404_for_unknown_path(self, analyzer):
        """Unknown paths return 404."""
        hs = _make_health_server(analyzer)
        hs.start()
        status, _ = _get(hs.port, '/unknown')
        hs.stop()
        assert status == 404

    def test_is_live_returns_true_without_channel(self, analyzer):
        """is_live() returns True when no channel has been set yet."""
        hs = _make_health_server(analyzer)
        ok, reason = hs.is_live()
        assert ok is True
        assert reason == 'starting'

    def test_is_live_returns_false_on_shutdown(self, analyzer):
        """is_live() returns False when channel is SHUTDOWN."""
        hs = _make_health_server(analyzer)
        hs.set_channel(_MockChannel(grpc.ChannelConnectivity.SHUTDOWN))
        ok, reason = hs.is_live()
        assert ok is False
        assert reason == 'channel_shutdown'


class TestHealthServerReadiness:
    """Tests for GET /readyz (readiness probe)."""

    def test_readiness_returns_200_during_grace_period(self, analyzer):
        """Readiness is 200 during the startup grace period."""
        hs = _make_health_server(analyzer, grace=9999)
        hs.start()
        status, body = _get(hs.port, '/readyz')
        hs.stop()
        assert status == 200
        assert body['status'] == 'ok'
        assert 'grace_period' in body['reason']

    def test_readiness_returns_200_when_no_events_seen(self, analyzer):
        """
        Readiness is 200 after the grace period when no events have been seen —
        a node with no cert activity is a valid state, not a failure.
        """
        hs = _make_health_server(analyzer, grace=0)
        # Ensure last_event_timestamp is 0 (never set)
        analyzer.metrics.last_event_timestamp._value.set(0)
        hs.start()
        status, body = _get(hs.port, '/readyz')
        hs.stop()
        assert status == 200
        assert 'no_events_seen' in body['reason']

    def test_readiness_returns_200_when_recent_event(self, analyzer):
        """Readiness is 200 when the last event was recent."""
        hs = _make_health_server(analyzer, grace=0, staleness=300)
        analyzer.metrics.last_event_timestamp._value.set(_time.time())
        hs.start()
        status, body = _get(hs.port, '/readyz')
        hs.stop()
        assert status == 200

    def test_readiness_returns_503_when_events_stale(self, analyzer):
        """Readiness is 503 when the last event is older than the staleness window."""
        hs = _make_health_server(analyzer, grace=0, staleness=10)
        # Set last event to 60 seconds ago — well past the 10s staleness window
        analyzer.metrics.last_event_timestamp._value.set(_time.time() - 60)
        hs.start()
        status, body = _get(hs.port, '/readyz')
        hs.stop()
        assert status == 503
        assert body['status'] == 'fail'
        assert 'stale' in body['reason']

    def test_is_ready_true_during_grace_period(self, analyzer):
        """is_ready() returns True during the grace period regardless of event state."""
        hs = _make_health_server(analyzer, grace=9999)
        ok, reason = hs.is_ready()
        assert ok is True
        assert 'grace_period' in reason

    def test_is_ready_true_with_no_events_after_grace(self, analyzer):
        """is_ready() returns True with no events seen after grace period."""
        hs = _make_health_server(analyzer, grace=0)
        analyzer.metrics.last_event_timestamp._value.set(0)
        ok, reason = hs.is_ready()
        assert ok is True
        assert reason == 'no_events_seen'

    def test_is_ready_false_when_stale(self, analyzer):
        """is_ready() returns False when last_event_timestamp is too old."""
        hs = _make_health_server(analyzer, grace=0, staleness=10)
        analyzer.metrics.last_event_timestamp._value.set(_time.time() - 60)
        ok, reason = hs.is_ready()
        assert ok is False
        assert 'stale' in reason

    def test_health_server_response_is_valid_json(self, analyzer):
        """Both endpoints return valid JSON bodies."""
        hs = _make_health_server(analyzer, grace=0)
        hs.start()
        for path in ('/healthz', '/readyz'):
            status, body = _get(hs.port, path)
            assert 'status' in body
            assert 'reason' in body
        hs.stop()

    def test_health_server_port_configurable(self, analyzer):
        """HealthServer respects the port passed at construction."""
        import socket
        with socket.socket() as s:
            s.bind(('', 0))
            port = s.getsockname()[1]
        hs = HealthServer(analyzer=analyzer, port=port)
        assert hs.port == port

class TestKafkaPublisher:
    """
    Tests for the optional KafkaPublisher class.

    Covers:
    - No-op when kafka-python is not installed
    - No-op when Kafka is disabled (kafka_publisher is None on analyzer)
    - Producer initialised with correct kwargs
    - publish() sends correct JSON message schema
    - publish() uses cert path as message key
    - publish() only fires for new certificates, not re-detections
    - publish() is silent on broker errors (never raises)
    - close() flushes and closes the producer
    - SASL kwargs passed through when security_protocol requires them
    - PLAINTEXT omits security_protocol kwarg
    """

    @pytest.fixture
    def sample_cert_info(self):
        """A fully-populated CertificateInfo for use in publisher tests."""
        from cert_analyzer import CertificateInfo
        return CertificateInfo(
            path='/etc/pki/tls/certs/test.crt',
            subject='CN=test.example.com',
            issuer='CN=Test CA',
            serial_number='abc123',
            not_before=datetime(2024, 1, 1),
            not_after=datetime(2025, 1, 1),
            process='/usr/bin/curl',
            pid=12345,
            namespace='default',
            common_name='test.example.com',
            san_dns_names=['test.example.com', 'www.test.example.com'],
            cert_index=0,
            pod_name='my-pod',
            workload_kind='Deployment',
            workload_name='my-app',
            pod_labels={'app': 'my-app'},
            app_label='my-app',
            container_name='main',
            container_image='my-app:1.0',
            checksum='',
        )

    def _make_publisher(self, mock_producer_class, **kwargs):
        """Helper — construct a KafkaPublisher with a mocked KafkaProducer."""
        from cert_analyzer import KafkaPublisher
        defaults = dict(
            bootstrap_servers='broker1:9092,broker2:9092',
            topic='cert-events',
        )
        defaults.update(kwargs)
        return KafkaPublisher(**defaults)

    # ── availability guard ────────────────────────────────────────────────────

    def test_noop_when_kafka_not_available(self, sample_cert_info, monkeypatch):
        """publish() is silent and never raises when kafka-python is absent."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', False)

        from cert_analyzer import KafkaPublisher
        publisher = KafkaPublisher(bootstrap_servers='broker:9092', topic='t')
        assert publisher._producer is None
        # Must not raise
        publisher.publish(sample_cert_info)

    def test_noop_when_producer_init_fails(self, monkeypatch, sample_cert_info):
        """publish() is silent when KafkaProducer.__init__ raises."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer', side_effect=Exception('broker down')):
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='broker:9092', topic='t')
            assert publisher._producer is None
            publisher.publish(sample_cert_info)   # must not raise

    # ── producer initialisation ───────────────────────────────────────────────

    def test_producer_initialised_with_correct_brokers(self, monkeypatch):
        """KafkaProducer is constructed with the parsed bootstrap_servers list."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_cls.return_value = MagicMock()
            from cert_analyzer import KafkaPublisher
            KafkaPublisher(bootstrap_servers='b1:9092, b2:9092', topic='t')
            call_kwargs = mock_cls.call_args[1]
            assert call_kwargs['bootstrap_servers'] == ['b1:9092', 'b2:9092']

    def test_producer_plaintext_omits_security_protocol(self, monkeypatch):
        """security_protocol kwarg is absent when protocol is PLAINTEXT."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_cls.return_value = MagicMock()
            from cert_analyzer import KafkaPublisher
            KafkaPublisher(
                bootstrap_servers='broker:9092',
                topic='t',
                security_protocol='PLAINTEXT',
            )
            call_kwargs = mock_cls.call_args[1]
            assert 'security_protocol' not in call_kwargs

    def test_producer_sasl_kwargs_passed_through(self, monkeypatch):
        """SASL kwargs are forwarded when security_protocol is SASL_SSL."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_cls.return_value = MagicMock()
            from cert_analyzer import KafkaPublisher
            KafkaPublisher(
                bootstrap_servers='broker:9092',
                topic='t',
                security_protocol='SASL_SSL',
                sasl_mechanism='PLAIN',
                sasl_username='user',
                sasl_password='secret',
            )
            call_kwargs = mock_cls.call_args[1]
            assert call_kwargs['security_protocol']     == 'SASL_SSL'
            assert call_kwargs['sasl_mechanism']        == 'PLAIN'
            assert call_kwargs['sasl_plain_username']   == 'user'
            assert call_kwargs['sasl_plain_password']   == 'secret'

    # ── message schema ────────────────────────────────────────────────────────

    def test_publish_sends_correct_event_type(self, monkeypatch, sample_cert_info):
        """Published message contains event_type = 'certificate_discovered'."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            publisher.publish(sample_cert_info)

            mock_producer.send.assert_called_once()
            _, send_kwargs = mock_producer.send.call_args
            msg = send_kwargs['value']
            assert msg['event_type'] == 'certificate_discovered'

    def test_publish_message_contains_all_fields(self, monkeypatch, sample_cert_info):
        """Published message contains all expected CertificateInfo fields."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            publisher.publish(sample_cert_info)

            _, send_kwargs = mock_producer.send.call_args
            msg = send_kwargs['value']

            required_fields = [
                'event_type', 'detected_at', 'path', 'cert_index',
                'subject', 'issuer', 'serial_number', 'common_name',
                'san_dns_names', 'not_before', 'not_after',
                'days_until_expiry', 'is_expired', 'process', 'pid',
                'namespace', 'pod_name', 'workload_kind', 'workload_name',
                'app_label', 'container_name', 'container_image', 'checksum',
            ]
            for field in required_fields:
                assert field in msg, f"Missing field: {field}"

    def test_publish_message_values_match_cert_info(self, monkeypatch, sample_cert_info):
        """Published message values correctly reflect the CertificateInfo."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            publisher.publish(sample_cert_info)

            _, send_kwargs = mock_producer.send.call_args
            msg = send_kwargs['value']

            assert msg['path']          == '/etc/pki/tls/certs/test.crt'
            assert msg['common_name']   == 'test.example.com'
            assert msg['process']       == '/usr/bin/curl'
            assert msg['pid']           == 12345
            assert msg['pod_name']      == 'my-pod'
            assert msg['namespace']     == 'default'
            assert msg['workload_kind'] == 'Deployment'
            assert msg['workload_name'] == 'my-app'
            assert msg['san_dns_names'] == ['test.example.com', 'www.test.example.com']
            assert msg['is_expired']    is True   # not_after is 2025-01-01, now > that

    def test_publish_uses_unique_key_as_partition_key(self, monkeypatch, sample_cert_info):
        """Message key is unique_key (path:cert_index:serial) for partition locality."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            publisher.publish(sample_cert_info)

            _, send_kwargs = mock_producer.send.call_args
            expected_key = sample_cert_info.unique_key  # path:cert_index:serial
            assert send_kwargs['key'] == expected_key
            # Verify it contains all three components
            assert sample_cert_info.path in expected_key
            assert str(sample_cert_info.cert_index) in expected_key
            assert sample_cert_info.serial_number in expected_key

    def test_publish_sends_to_configured_topic(self, monkeypatch, sample_cert_info):
        """Message is sent to the topic specified in configuration."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='my-topic')
            publisher.publish(sample_cert_info)

            topic_arg = mock_producer.send.call_args[0][0]
            assert topic_arg == 'my-topic'

    # ── error handling ────────────────────────────────────────────────────────

    def test_publish_silent_on_send_error(self, monkeypatch, sample_cert_info):
        """publish() logs a warning and never raises when send() throws."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_producer.send.side_effect = Exception('broker unavailable')
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            publisher.publish(sample_cert_info)   # must not raise

    def test_on_error_callback_logs_warning(self, monkeypatch, caplog):
        """_on_error() logs a warning without raising."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_cls.return_value = MagicMock()
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')

            with caplog.at_level(logging.WARNING):
                publisher._on_error(Exception('delivery failed'))

            assert any('delivery' in r.message.lower() or 'kafka' in r.message.lower()
                       for r in caplog.records)

    # ── close ─────────────────────────────────────────────────────────────────

    def test_close_flushes_and_closes_producer(self, monkeypatch):
        """close() calls flush() then close() on the underlying producer."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock, call
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            publisher.close()

            mock_producer.flush.assert_called_once()
            mock_producer.close.assert_called_once()

    def test_close_noop_when_producer_is_none(self):
        """close() is silent when _producer is None (Kafka not available)."""
        from cert_analyzer import KafkaPublisher
        publisher = KafkaPublisher.__new__(KafkaPublisher)
        publisher._producer = None
        publisher._topic = 't'
        publisher.close()   # must not raise

    # ── integration with CertificateAnalyzer ─────────────────────────────────

    def test_analyzer_publishes_new_cert_to_kafka(
        self, analyzer, temp_dir, monkeypatch
    ):
        """process_event publishes a new certificate to Kafka exactly once."""
        from unittest.mock import MagicMock, patch
        import cert_analyzer as _ca

        # Attach a mock KafkaPublisher to the analyzer
        mock_publisher = MagicMock()
        analyzer.kafka_publisher = mock_publisher

        cert, _ = TestCertificateGeneration.generate_certificate('kafka.example.com', 365)
        path = os.path.join(temp_dir, 'kafka.pem')
        TestCertificateGeneration.save_certificate_pem(cert, path)

        # Simulate a Tetragon event pointing at our cert file
        mock_event = MagicMock()
        mock_event.HasField.side_effect = lambda f: f == 'process_kprobe'
        mock_kprobe = MagicMock()
        mock_kprobe.process.binary = '/usr/bin/curl'
        mock_kprobe.process.pid.value = 99
        mock_kprobe.process.HasField.return_value = False
        mock_arg = MagicMock()
        mock_arg.HasField.side_effect = lambda f: f == 'file_arg'
        mock_arg.file_arg.path = path
        mock_kprobe.args = [mock_arg]
        mock_event.process_kprobe = mock_kprobe

        analyzer.process_event(mock_event)

        mock_publisher.publish.assert_called_once()
        published_cert = mock_publisher.publish.call_args[0][0]
        assert published_cert.path == path

    def test_analyzer_does_not_publish_redetected_cert(
        self, analyzer, temp_dir, monkeypatch
    ):
        """process_event does NOT publish to Kafka for re-detected known certs."""
        from unittest.mock import MagicMock
        import cert_analyzer as _ca

        mock_publisher = MagicMock()
        analyzer.kafka_publisher = mock_publisher

        cert, _ = TestCertificateGeneration.generate_certificate('redetect.example.com', 365)
        path = os.path.join(temp_dir, 'redetect.pem')
        TestCertificateGeneration.save_certificate_pem(cert, path)

        def make_event(p):
            mock_event = MagicMock()
            mock_event.HasField.side_effect = lambda f: f == 'process_kprobe'
            mock_kprobe = MagicMock()
            mock_kprobe.process.binary = '/usr/bin/curl'
            mock_kprobe.process.pid.value = 99
            mock_kprobe.process.HasField.return_value = False
            mock_arg = MagicMock()
            mock_arg.HasField.side_effect = lambda f: f == 'file_arg'
            mock_arg.file_arg.path = p
            mock_kprobe.args = [mock_arg]
            mock_event.process_kprobe = mock_kprobe
            return mock_event

        # First detection — should publish
        analyzer.process_event(make_event(path))
        assert mock_publisher.publish.call_count == 1

        # Second detection — same file, already in known_certs, must NOT publish again
        analyzer.process_event(make_event(path))
        assert mock_publisher.publish.call_count == 1

    def test_analyzer_without_kafka_publisher_works_normally(
        self, analyzer, temp_dir
    ):
        """analyzer continues working normally when kafka_publisher is None."""
        from unittest.mock import MagicMock

        assert analyzer.kafka_publisher is None

        cert, _ = TestCertificateGeneration.generate_certificate('nokafka.example.com', 365)
        path = os.path.join(temp_dir, 'nokafka.pem')
        TestCertificateGeneration.save_certificate_pem(cert, path)

        mock_event = MagicMock()
        mock_event.HasField.side_effect = lambda f: f == 'process_kprobe'
        mock_kprobe = MagicMock()
        mock_kprobe.process.binary = '/usr/bin/test'
        mock_kprobe.process.pid.value = 1
        mock_kprobe.process.HasField.return_value = False
        mock_arg = MagicMock()
        mock_arg.HasField.side_effect = lambda f: f == 'file_arg'
        mock_arg.file_arg.path = path
        mock_kprobe.args = [mock_arg]
        mock_event.process_kprobe = mock_kprobe

        # Must not raise even with no Kafka publisher
        analyzer.process_event(mock_event)
        assert path + ':0:' in ''.join(analyzer.known_certs.keys())


class TestKafkaReconnection:
    """
    Tests for KafkaPublisher automatic reconnection behaviour.

    Covers:
    - producer is nullified after a send failure so next publish retries
    - _connect() respects the cooldown period between reconnect attempts
    - _connect() succeeds after broker comes back up
    - publish() reconnects automatically when producer is None
    - publish() skips send if reconnect fails and cooldown has not elapsed
    - multiple sequential failures do not raise
    - _connect() closes broken producer before recreating it
    - cooldown resets after a successful reconnect
    - reconnect is attempted on first publish even if init failed
    """

    @pytest.fixture
    def reconnect_publisher(self, monkeypatch):
        """
        A KafkaPublisher constructed with a working producer, ready for
        reconnect tests. Returns (publisher, mock_producer_class) so tests
        can control subsequent KafkaProducer() calls.
        """
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            # Reset call count after init so tests start from a clean slate
            mock_cls.reset_mock()
            yield publisher, mock_cls

    @pytest.fixture
    def sample_cert_info(self):
        """Minimal CertificateInfo for reconnect tests."""
        from cert_analyzer import CertificateInfo
        return CertificateInfo(
            path='/etc/pki/tls/certs/test.crt',
            subject='CN=test.example.com',
            issuer='CN=Test CA',
            serial_number='abc123',
            not_before=datetime(2024, 1, 1),
            not_after=datetime(2025, 1, 1),
            process='/usr/bin/curl',
            pid=1,
            namespace='',
            common_name='test.example.com',
            san_dns_names=[],
            cert_index=0,
            pod_name='',
            workload_kind='',
            workload_name='',
            pod_labels=None,
            app_label='',
            container_name='',
            container_image='',
            checksum='',
        )

    # ── producer nullified after send failure ─────────────────────────────────

    def test_send_failure_nullifies_producer(self, monkeypatch, sample_cert_info):
        """A send() exception sets _producer to None so next publish retries."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_producer.send.side_effect = Exception('broker down')
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            assert publisher._producer is not None

            publisher.publish(sample_cert_info)

            assert publisher._producer is None, \
                'producer should be nullified after send failure'

    # ── cooldown ──────────────────────────────────────────────────────────────

    def test_connect_respects_cooldown(self, monkeypatch, sample_cert_info):
        """_connect() returns False immediately if called within the cooldown window."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_cls.return_value = MagicMock()
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')

            # Nullify producer and set last attempt to now
            publisher._producer = None
            publisher._last_connect_attempt = time.time()

            mock_cls.reset_mock()
            result = publisher._connect()

            assert result is False
            mock_cls.assert_not_called()

    def test_connect_proceeds_after_cooldown(self, monkeypatch, sample_cert_info):
        """_connect() creates a new producer once the cooldown has elapsed."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_cls.return_value = MagicMock()
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')

            # Simulate cooldown already elapsed
            publisher._producer = None
            publisher._last_connect_attempt = 0.0

            mock_cls.reset_mock()
            result = publisher._connect()

            assert result is True
            mock_cls.assert_called_once()
            assert publisher._producer is not None

    def test_publish_skips_send_when_reconnect_on_cooldown(
        self, monkeypatch, sample_cert_info
    ):
        """publish() silently skips sending if reconnect is still on cooldown."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_cls.return_value = MagicMock()
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')

            publisher._producer = None
            publisher._last_connect_attempt = time.time()  # cooldown active

            mock_cls.reset_mock()
            publisher.publish(sample_cert_info)  # must not raise

            mock_cls.assert_not_called()  # no reconnect attempted

    # ── automatic reconnect ───────────────────────────────────────────────────

    def test_publish_reconnects_when_producer_is_none(
        self, monkeypatch, sample_cert_info
    ):
        """publish() calls _connect() and sends when producer is None and cooldown elapsed."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')

            # Simulate broker restart — nullify producer and clear cooldown
            publisher._producer = None
            publisher._last_connect_attempt = 0.0

            mock_cls.reset_mock()
            mock_producer.reset_mock()

            publisher.publish(sample_cert_info)

            mock_cls.assert_called_once()          # reconnected
            mock_producer.send.assert_called_once() # message sent

    def test_publish_reconnects_and_sends_correct_message(
        self, monkeypatch, sample_cert_info
    ):
        """After reconnect the published message has the correct event_type and path."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')

            publisher._producer = None
            publisher._last_connect_attempt = 0.0
            mock_cls.reset_mock()
            mock_producer.reset_mock()

            publisher.publish(sample_cert_info)

            _, send_kwargs = mock_producer.send.call_args
            assert send_kwargs['value']['event_type'] == 'certificate_discovered'
            assert send_kwargs['value']['path'] == '/etc/pki/tls/certs/test.crt'

    # ── broken producer replaced on reconnect ─────────────────────────────────

    def test_connect_closes_broken_producer_before_reconnect(
        self, monkeypatch, sample_cert_info
    ):
        """_connect() calls close() on an existing broken producer before creating a new one."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            broken_producer = MagicMock()
            new_producer = MagicMock()
            mock_cls.side_effect = [broken_producer, new_producer]

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            assert publisher._producer is broken_producer

            # Simulate a reconnect with cooldown cleared
            publisher._last_connect_attempt = 0.0
            publisher._connect()

            broken_producer.close.assert_called_once()
            assert publisher._producer is new_producer

    # ── multiple sequential failures ──────────────────────────────────────────

    def test_multiple_sequential_failures_never_raise(
        self, monkeypatch, sample_cert_info
    ):
        """Three consecutive send failures all log warnings and never raise."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_producer.send.side_effect = Exception('broker down')
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')

            for _ in range(3):
                publisher._last_connect_attempt = 0.0  # bypass cooldown each time
                publisher.publish(sample_cert_info)     # must not raise

    # ── reconnect after init failure ──────────────────────────────────────────

    def test_reconnect_attempted_if_init_failed(
        self, monkeypatch, sample_cert_info
    ):
        """If the initial connection fails, publish() retries once cooldown elapses."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            # First call (init) fails, second call (reconnect) succeeds
            working_producer = MagicMock()
            mock_cls.side_effect = [Exception('broker down on startup'), working_producer]

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            assert publisher._producer is None  # init failed

            # Clear cooldown to allow immediate reconnect
            publisher._last_connect_attempt = 0.0

            publisher.publish(sample_cert_info)

            assert publisher._producer is working_producer
            working_producer.send.assert_called_once()

    # ── reconnect logs ─────────────────────────────────────────────────────────

    def test_reconnect_failure_logs_warning(self, monkeypatch, caplog):
        """A failed reconnect attempt logs a warning with retry interval."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_cls.side_effect = Exception('broker down')
            from cert_analyzer import KafkaPublisher

            with caplog.at_level(logging.WARNING):
                publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
                publisher._last_connect_attempt = 0.0
                publisher._connect()

            assert any('retry' in r.message.lower() or 'failed' in r.message.lower()
                       for r in caplog.records)

    def test_successful_reconnect_logs_info(self, monkeypatch, caplog):
        """A successful reconnect logs an info message."""
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('cert_analyzer.KafkaProducer') as mock_cls:
            mock_cls.return_value = MagicMock()
            from cert_analyzer import KafkaPublisher

            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            publisher._producer = None
            publisher._last_connect_attempt = 0.0

            with caplog.at_level(logging.INFO):
                publisher._connect()

            assert any('connected' in r.message.lower() or 'initialised' in r.message.lower()
                       for r in caplog.records)


class TestOpensslUprobeHooking:
    """
    Tests for OpenSSL uprobe interception (openssl3-cert-load policy).

    Two code paths are exercised:
    - File-path hooks (SSL_CTX_use_certificate_file / SSL_CTX_use_certificate_chain_file):
      cert path is carried in a string_arg and handled by the existing
      extract_cert_path_from_event / process_event flow.
    - In-memory hooks (SSL_CTX_use_certificate_ASN1): raw DER bytes arrive in a bytes_arg and are
      handled by _handle_uprobe_in_memory_cert, which parses them directly
      without touching the filesystem.
    """

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _cert_der(cn='openssl.example.com', days=365):
        cert, _ = TestCertificateGeneration.generate_certificate(cn, days)
        return cert, cert.public_bytes(Encoding.DER)

    @staticmethod
    def _make_string_arg(value):
        from unittest.mock import MagicMock
        arg = MagicMock()
        arg.HasField.side_effect = lambda f: f == 'string_arg'
        arg.string_arg = value
        return arg

    @staticmethod
    def _make_bytes_arg(data):
        from unittest.mock import MagicMock
        arg = MagicMock()
        arg.HasField.side_effect = lambda f: f == 'bytes_arg'
        arg.bytes_arg = data
        return arg

    @staticmethod
    def _make_uprobe_event(args, pid=1234, binary='/usr/bin/nginx', has_pod=False,
                           symbol='SSL_CTX_use_certificate_ASN1'):
        """Build a minimal mock process_uprobe event."""
        from unittest.mock import MagicMock

        mock_uprobe = MagicMock()
        mock_uprobe.process.binary = binary
        mock_uprobe.process.pid.value = pid
        mock_uprobe.symbol = symbol

        if has_pod:
            mock_uprobe.process.HasField.side_effect = lambda f: f in ('pid', 'pod')
            mock_uprobe.process.pod.namespace = 'test-ns'
            mock_uprobe.process.pod.name = 'test-pod'
            mock_uprobe.process.pod.workload_object.kind = 'Deployment'
            mock_uprobe.process.pod.workload_object.name = 'test-deploy'
            mock_uprobe.process.pod.labels = {}
        else:
            mock_uprobe.process.HasField.side_effect = lambda f: f == 'pid'

        mock_uprobe.args = args

        mock_event = MagicMock()
        mock_event.HasField.side_effect = lambda f: f == 'process_uprobe'
        mock_event.process_uprobe = mock_uprobe
        return mock_event

    @staticmethod
    def _make_kprobe_event():
        """Build a minimal mock process_kprobe event (no args)."""
        from unittest.mock import MagicMock
        mock_event = MagicMock()
        mock_event.HasField.side_effect = lambda f: f == 'process_kprobe'
        mock_kprobe = MagicMock()
        mock_kprobe.process.binary = '/usr/bin/curl'
        mock_kprobe.process.pid.value = 999
        mock_kprobe.process.HasField.return_value = False
        mock_kprobe.args = []
        mock_event.process_kprobe = mock_kprobe
        return mock_event

    # ----------------------------------------- file-path uprobe (string_arg)

    def test_file_path_uprobe_string_arg_is_extracted(self, analyzer, temp_dir):
        """extract_cert_path_from_event finds a cert path in a uprobe string_arg."""
        cert_path = os.path.join(temp_dir, 'server.pem')
        cert, _ = TestCertificateGeneration.generate_certificate('path-uprobe.example.com', 365)
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)

        event = self._make_uprobe_event([self._make_string_arg(cert_path)])
        extracted, _, _, _, _ = analyzer.extract_cert_path_from_event(event)

        assert extracted == cert_path

    def test_file_path_uprobe_non_cert_string_arg_is_ignored(self, analyzer):
        """extract_cert_path_from_event ignores a string_arg that is not a cert path."""
        event = self._make_uprobe_event([self._make_string_arg('/etc/hosts')])
        cert_path, _, _, _, _ = analyzer.extract_cert_path_from_event(event)

        assert cert_path is None

    def test_file_path_uprobe_process_event_end_to_end(self, analyzer, temp_dir):
        """process_event resolves a cert file referenced by a uprobe string_arg."""
        cert_path = os.path.join(temp_dir, 'uprobe-file.pem')
        cert, _ = TestCertificateGeneration.generate_certificate('uprobe-file.example.com', 365)
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)

        event = self._make_uprobe_event([self._make_string_arg(cert_path)])
        analyzer.process_event(event)

        assert any(k.startswith(cert_path + ':') for k in analyzer.known_certs)

    # ----------------------------------------- in-memory DER (bytes_arg)

    def test_handle_bytes_returns_false_for_kprobe_event(self, analyzer):
        """_handle_uprobe_in_memory_cert returns False for a non-uprobe event."""
        result = analyzer._handle_uprobe_in_memory_cert(self._make_kprobe_event())
        assert result is False

    def test_handle_bytes_returns_false_when_no_bytes_arg(self, analyzer):
        """_handle_uprobe_in_memory_cert returns False when args contain no bytes_arg."""
        _, der = self._cert_der()
        # Only a string_arg — no bytes_arg
        event = self._make_uprobe_event([self._make_string_arg('/some/path.pem')])
        assert analyzer._handle_uprobe_in_memory_cert(event) is False

    def test_handle_bytes_returns_false_for_garbage_bytes(self, analyzer):
        """_handle_uprobe_in_memory_cert returns False and does not raise on invalid DER."""
        event = self._make_uprobe_event([self._make_bytes_arg(b'\xde\xad\xbe\xef' * 16)])
        assert analyzer._handle_uprobe_in_memory_cert(event) is False

    def test_handle_bytes_returns_false_for_empty_bytes(self, analyzer):
        """_handle_uprobe_in_memory_cert returns False on empty bytes_arg."""
        event = self._make_uprobe_event([self._make_bytes_arg(b'')])
        assert analyzer._handle_uprobe_in_memory_cert(event) is False

    def test_handle_bytes_returns_true_for_valid_der(self, analyzer):
        """_handle_uprobe_in_memory_cert returns True when bytes_arg is valid DER."""
        _, der = self._cert_der()
        event = self._make_uprobe_event([self._make_bytes_arg(der)])
        assert analyzer._handle_uprobe_in_memory_cert(event) is True

    def test_handle_bytes_adds_cert_to_known_certs(self, analyzer):
        """A cert parsed from bytes_arg is stored in known_certs."""
        _, der = self._cert_der()
        event = self._make_uprobe_event([self._make_bytes_arg(der)])
        analyzer._handle_uprobe_in_memory_cert(event)
        assert len(analyzer.known_certs) == 1

    def test_handle_bytes_synthetic_path_format(self, analyzer):
        """CertificateInfo.path uses the uprobe://<symbol>/<pid>/<serial> scheme."""
        cert, der = self._cert_der()
        serial = str(cert.serial_number)
        event = self._make_uprobe_event([self._make_bytes_arg(der)], pid=5678,
                                        symbol='SSL_CTX_use_certificate_ASN1')
        analyzer._handle_uprobe_in_memory_cert(event)

        stored = list(analyzer.known_certs.values())[0]
        assert stored.path == f'uprobe://SSL_CTX_use_certificate_ASN1/5678/{serial}'

    def test_handle_bytes_deduplicates_same_cert(self, analyzer):
        """Calling _handle_uprobe_in_memory_cert twice with the same DER adds only one entry."""
        _, der = self._cert_der()
        event = self._make_uprobe_event([self._make_bytes_arg(der)])
        analyzer._handle_uprobe_in_memory_cert(event)
        analyzer._handle_uprobe_in_memory_cert(event)
        assert len(analyzer.known_certs) == 1

    def test_handle_bytes_two_distinct_certs_both_stored(self, analyzer):
        """Two different certs from separate bytes_arg events are both stored."""
        _, der1 = self._cert_der('a.example.com')
        _, der2 = self._cert_der('b.example.com')
        analyzer._handle_uprobe_in_memory_cert(
            self._make_uprobe_event([self._make_bytes_arg(der1)], pid=1)
        )
        analyzer._handle_uprobe_in_memory_cert(
            self._make_uprobe_event([self._make_bytes_arg(der2)], pid=2)
        )
        assert len(analyzer.known_certs) == 2

    def test_handle_bytes_cert_fields_populated(self, analyzer):
        """CertificateInfo fields are correctly populated from the DER cert."""
        cert, der = self._cert_der('fields.example.com', days=90)
        event = self._make_uprobe_event([self._make_bytes_arg(der)], pid=42,
                                        binary='/usr/bin/python3')
        analyzer._handle_uprobe_in_memory_cert(event)

        info = list(analyzer.known_certs.values())[0]
        assert 'fields.example.com' in info.subject
        assert info.pid == 42
        assert info.process == '/usr/bin/python3'
        assert info.days_until_expiry > 80

    def test_handle_bytes_updates_last_event_timestamp(self, analyzer):
        """last_event_timestamp is updated when a bytes_arg cert is successfully parsed."""
        analyzer.metrics.last_event_timestamp._value.set(0)
        _, der = self._cert_der()
        event = self._make_uprobe_event([self._make_bytes_arg(der)])
        analyzer._handle_uprobe_in_memory_cert(event)
        assert analyzer.metrics.last_event_timestamp._value.get() > 0

    def test_handle_bytes_timestamp_not_updated_on_invalid_der(self, analyzer):
        """last_event_timestamp is NOT updated when DER parsing fails."""
        analyzer.metrics.last_event_timestamp._value.set(0)
        event = self._make_uprobe_event([self._make_bytes_arg(b'not-a-cert')])
        analyzer._handle_uprobe_in_memory_cert(event)
        assert analyzer.metrics.last_event_timestamp._value.get() == 0

    def test_handle_bytes_self_filter_by_process_name(self, analyzer):
        """cert-analyzer process is silently dropped when filter_self_events is True."""
        assert analyzer.filter_self_events is True
        _, der = self._cert_der()
        event = self._make_uprobe_event([self._make_bytes_arg(der)],
                                        binary='/app/cert-analyzer')
        result = analyzer._handle_uprobe_in_memory_cert(event)
        assert result is False
        assert len(analyzer.known_certs) == 0

    def test_handle_bytes_self_filter_by_pid(self, analyzer, monkeypatch):
        """Own process PID is silently dropped when filter_self_events is True."""
        assert analyzer.filter_self_events is True
        monkeypatch.setattr(os, 'getpid', lambda: 9999)
        _, der = self._cert_der()
        event = self._make_uprobe_event([self._make_bytes_arg(der)], pid=9999)
        result = analyzer._handle_uprobe_in_memory_cert(event)
        assert result is False
        assert len(analyzer.known_certs) == 0

    def test_handle_bytes_self_filter_disabled(self, analyzer):
        """cert-analyzer process is NOT filtered when filter_self_events is False."""
        analyzer.filter_self_events = False
        _, der = self._cert_der()
        event = self._make_uprobe_event([self._make_bytes_arg(der)],
                                        binary='/app/cert-analyzer')
        result = analyzer._handle_uprobe_in_memory_cert(event)
        assert result is True

    def test_handle_bytes_pod_context_applied(self, analyzer):
        """Pod name and namespace from the uprobe event are stored on CertificateInfo."""
        _, der = self._cert_der()
        event = self._make_uprobe_event([self._make_bytes_arg(der)], has_pod=True)
        analyzer._handle_uprobe_in_memory_cert(event)

        info = list(analyzer.known_certs.values())[0]
        assert info.pod_name == 'test-pod'
        assert info.namespace == 'test-ns'

    # ----------------------------------------- process_event routing

    def test_process_event_routes_bytes_arg_to_in_memory_handler(self, analyzer):
        """process_event stores a cert when the uprobe event contains bytes_arg."""
        _, der = self._cert_der('route.example.com')
        event = self._make_uprobe_event([self._make_bytes_arg(der)])
        analyzer.process_event(event)
        assert len(analyzer.known_certs) == 1

    def test_process_event_skips_bytes_handler_for_kprobe(self, analyzer):
        """process_event does not attempt bytes parsing for a kprobe event with no path."""
        event = self._make_kprobe_event()
        analyzer.process_event(event)  # no path, no bytes_arg → nothing stored
        assert len(analyzer.known_certs) == 0

    def test_process_event_prefers_file_path_over_bytes_arg(self, analyzer, temp_dir):
        """When both string_arg and bytes_arg are present, the file path wins."""
        cert_path = os.path.join(temp_dir, 'both.pem')
        cert, der = self._cert_der('both.example.com')
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)

        event = self._make_uprobe_event([
            self._make_string_arg(cert_path),
            self._make_bytes_arg(der),
        ])
        analyzer.process_event(event)

        # Stored under the real file path, not a synthetic uprobe:// path
        assert any(k.startswith(cert_path + ':') for k in analyzer.known_certs)
        assert not any('uprobe://' in k for k in analyzer.known_certs)

    # ----------------------------------------- Kafka integration

    def test_kafka_published_for_new_in_memory_cert(self, analyzer):
        """A new cert extracted from bytes_arg is published to Kafka."""
        from unittest.mock import MagicMock
        mock_publisher = MagicMock()
        analyzer.kafka_publisher = mock_publisher

        _, der = self._cert_der('kafka-bytes.example.com')
        event = self._make_uprobe_event([self._make_bytes_arg(der)])
        analyzer._handle_uprobe_in_memory_cert(event)

        mock_publisher.publish.assert_called_once()
        published = mock_publisher.publish.call_args[0][0]
        assert 'uprobe://SSL_CTX_use_certificate_ASN1' in published.path

    def test_kafka_not_published_for_redetected_in_memory_cert(self, analyzer):
        """Re-detected in-memory cert (same DER) is NOT published to Kafka again."""
        from unittest.mock import MagicMock
        mock_publisher = MagicMock()
        analyzer.kafka_publisher = mock_publisher

        _, der = self._cert_der('kafka-dedup.example.com')
        event = self._make_uprobe_event([self._make_bytes_arg(der)])

        analyzer._handle_uprobe_in_memory_cert(event)
        analyzer._handle_uprobe_in_memory_cert(event)

        assert mock_publisher.publish.call_count == 1


class TestJavaNSSFIPSHooking:
    """
    Tests for NSC_CreateObject / NSC_FindObjectsInit uprobe handlers (java-fips-nss-cert policy).

    Both handlers decode a little-endian CK_ATTRIBUTE[] template read from /proc/<pid>/mem.
    _read_process_memory is patched throughout so no live process is needed.
    """

    # PKCS#11 constants mirrored from the production code
    CKA_CLASS        = 0x00000001
    CKA_VALUE        = 0x00000011
    CKO_CERTIFICATE  = 0x00000001
    TMPL_ADDR        = 0x1000
    CLASS_ADDR       = 0x2000
    DER_ADDR         = 0x3000

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _cert_der(cn='fips.example.com', days=365):
        cert, _ = TestCertificateGeneration.generate_certificate(cn, days)
        return cert, cert.public_bytes(Encoding.DER)

    @staticmethod
    def _make_uint64_arg(value):
        from unittest.mock import MagicMock
        arg = MagicMock()
        arg.HasField.side_effect = lambda f: f == 'size_arg'
        arg.size_arg = value
        return arg

    @staticmethod
    def _pack_attr(attr_type: int, p_value: int, val_len: int) -> bytes:
        """Pack one CK_ATTRIBUTE struct (24 bytes, little-endian LP64 layout)."""
        return (
            attr_type.to_bytes(8, 'little') +
            p_value.to_bytes(8, 'little') +
            val_len.to_bytes(8, 'little')
        )

    @classmethod
    def _make_event(cls, symbol, uint64_values, pid=1234, binary='/usr/bin/java',
                    has_pod=False):
        """Build a mock process_uprobe event with uint64 args."""
        from unittest.mock import MagicMock
        mock_uprobe = MagicMock()
        mock_uprobe.process.binary = binary
        mock_uprobe.process.pid.value = pid
        mock_uprobe.symbol = symbol
        if has_pod:
            mock_uprobe.process.HasField.side_effect = lambda f: f in ('pid', 'pod')
            mock_uprobe.process.pod.namespace = 'fips-ns'
            mock_uprobe.process.pod.name = 'java-pod'
            mock_uprobe.process.pod.workload_object.kind = 'Deployment'
            mock_uprobe.process.pod.workload_object.name = 'java-deploy'
            mock_uprobe.process.pod.labels = {}
        else:
            mock_uprobe.process.HasField.side_effect = lambda f: f == 'pid'
        mock_uprobe.args = [cls._make_uint64_arg(v) for v in uint64_values]
        mock_event = MagicMock()
        mock_event.HasField.side_effect = lambda f: f == 'process_uprobe'
        mock_event.process_uprobe = mock_uprobe
        return mock_event

    @staticmethod
    def _make_kprobe_event():
        from unittest.mock import MagicMock
        ev = MagicMock()
        ev.HasField.side_effect = lambda f: f == 'process_kprobe'
        return ev

    @classmethod
    def _cert_template(cls, der: bytes) -> tuple:
        """
        Build the three _read_process_memory return values for a successful
        _handle_nsc_create_object call: (template_bytes, ck_class_bytes, der_bytes).
        Template layout: [CKA_CLASS → CLASS_ADDR, CKA_VALUE → DER_ADDR].
        """
        tmpl = (
            cls._pack_attr(cls.CKA_CLASS, cls.CLASS_ADDR, 4) +
            cls._pack_attr(cls.CKA_VALUE, cls.DER_ADDR, len(der))
        )
        ck_class = cls.CKO_CERTIFICATE.to_bytes(4, 'little')
        return tmpl, ck_class, der

    # ------------------------------------------------------------------ _read_process_memory

    def test_read_memory_returns_none_for_zero_address(self, analyzer):
        assert analyzer._read_process_memory(1234, 0, 100) is None

    def test_read_memory_returns_none_for_zero_size(self, analyzer):
        assert analyzer._read_process_memory(1234, self.TMPL_ADDR, 0) is None

    def test_read_memory_returns_none_on_ioerror(self, analyzer):
        import unittest.mock as mock
        with mock.patch('builtins.open', side_effect=IOError('no such process')):
            assert analyzer._read_process_memory(99999, self.TMPL_ADDR, 16) is None

    def test_read_memory_returns_bytes_on_success(self, analyzer):
        import unittest.mock as mock
        data = b'\xde\xad\xbe\xef' * 4
        m = mock.MagicMock()
        m.__enter__ = mock.Mock(return_value=m)
        m.__exit__ = mock.Mock(return_value=False)
        m.read.return_value = data
        with mock.patch('builtins.open', return_value=m):
            result = analyzer._read_process_memory(1234, self.TMPL_ADDR, 16)
        assert result == data

    # ------------------------------------------------------------------ NSC_CreateObject

    def test_create_object_rejects_kprobe(self, analyzer):
        """Returns False immediately for a non-uprobe event type."""
        assert analyzer._handle_nsc_create_object(self._make_kprobe_event()) is False

    def test_create_object_rejects_too_few_args(self, analyzer):
        """Returns False when fewer than 3 uint64 args are present."""
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR])
        assert analyzer._handle_nsc_create_object(event) is False

    def test_create_object_rejects_zero_count(self, analyzer):
        """Returns False when attribute count arg is 0."""
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 0])
        assert analyzer._handle_nsc_create_object(event) is False

    def test_create_object_rejects_excessive_count(self, analyzer):
        """Returns False when attribute count exceeds the sanity cap of 64."""
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 65])
        assert analyzer._handle_nsc_create_object(event) is False

    def test_create_object_rejects_unreadable_template(self, analyzer):
        """Returns False when /proc/pid/mem cannot be read for the template."""
        import unittest.mock as mock
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_read_process_memory', return_value=None):
            assert analyzer._handle_nsc_create_object(event) is False

    def test_create_object_rejects_non_cert_ck_class(self, analyzer):
        """Returns False when CKA_CLASS is CKO_DATA (0x0), not CKO_CERTIFICATE."""
        import unittest.mock as mock
        _, der = self._cert_der()
        tmpl = (
            self._pack_attr(self.CKA_CLASS, self.CLASS_ADDR, 4) +
            self._pack_attr(self.CKA_VALUE, self.DER_ADDR, len(der))
        )
        ck_data = (0x00000000).to_bytes(4, 'little')
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_data, der]):
            assert analyzer._handle_nsc_create_object(event) is False

    def test_create_object_rejects_missing_cka_value(self, analyzer):
        """Returns False when template contains CKA_CLASS only (no DER payload pointer)."""
        import unittest.mock as mock
        tmpl = self._pack_attr(self.CKA_CLASS, self.CLASS_ADDR, 4)
        ck_cert = self.CKO_CERTIFICATE.to_bytes(4, 'little')
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 1])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert]):
            assert analyzer._handle_nsc_create_object(event) is False

    def test_create_object_rejects_garbage_der(self, analyzer):
        """Returns False when the CKA_VALUE bytes are not valid DER."""
        import unittest.mock as mock
        junk = b'\xde\xad\xbe\xef' * 50  # 200 bytes — passes size guard, fails DER parse
        tmpl, ck_cert, _ = self._cert_template(junk)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, junk]):
            assert analyzer._handle_nsc_create_object(event) is False

    def test_create_object_rejects_unreadable_der(self, analyzer):
        """Returns False when the DER memory read returns None."""
        import unittest.mock as mock
        _, der = self._cert_der()
        tmpl, ck_cert, _ = self._cert_template(der)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, None]):
            assert analyzer._handle_nsc_create_object(event) is False

    def test_create_object_accepts_valid_cert(self, analyzer):
        """Returns True when a well-formed DER cert is found in the template."""
        import unittest.mock as mock
        _, der = self._cert_der()
        tmpl, ck_cert, _ = self._cert_template(der)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, der]):
            assert analyzer._handle_nsc_create_object(event) is True

    def test_create_object_stores_cert_in_known_certs(self, analyzer):
        """A valid cert is persisted to known_certs after extraction."""
        import unittest.mock as mock
        _, der = self._cert_der()
        tmpl, ck_cert, _ = self._cert_template(der)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, der]):
            analyzer._handle_nsc_create_object(event)
        assert len(analyzer.known_certs) == 1

    def test_create_object_synthetic_path_format(self, analyzer):
        """CertificateInfo.path uses the uprobe://NSC_CreateObject/<pid>/<serial> scheme."""
        import unittest.mock as mock
        cert, der = self._cert_der()
        serial = str(cert.serial_number)
        tmpl, ck_cert, _ = self._cert_template(der)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2], pid=5555)
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, der]):
            analyzer._handle_nsc_create_object(event)
        stored = list(analyzer.known_certs.values())[0]
        assert stored.path == f'uprobe://NSC_CreateObject/5555/{serial}'

    def test_create_object_deduplicates_cert(self, analyzer):
        """A second event for the same cert returns True without adding a duplicate entry."""
        import unittest.mock as mock
        _, der = self._cert_der()
        tmpl, ck_cert, _ = self._cert_template(der)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, der]):
            analyzer._handle_nsc_create_object(event)
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, der]):
            result = analyzer._handle_nsc_create_object(event)
        assert result is True
        assert len(analyzer.known_certs) == 1

    def test_create_object_self_filter_by_process_name(self, analyzer):
        """Events from a cert-analyzer binary are silently dropped."""
        import unittest.mock as mock
        assert analyzer.filter_self_events is True
        _, der = self._cert_der()
        tmpl, ck_cert, _ = self._cert_template(der)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2],
                                 binary='/app/cert-analyzer')
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, der]):
            result = analyzer._handle_nsc_create_object(event)
        assert result is False
        assert len(analyzer.known_certs) == 0

    def test_create_object_self_filter_by_pid(self, analyzer, monkeypatch):
        """Events whose PID matches the analyzer's own PID are silently dropped."""
        import unittest.mock as mock
        assert analyzer.filter_self_events is True
        monkeypatch.setattr(os, 'getpid', lambda: 1234)
        _, der = self._cert_der()
        tmpl, ck_cert, _ = self._cert_template(der)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2], pid=1234)
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, der]):
            result = analyzer._handle_nsc_create_object(event)
        assert result is False

    def test_create_object_updates_event_timestamp(self, analyzer):
        """last_event_timestamp is updated after a successful cert extraction."""
        import unittest.mock as mock
        analyzer.metrics.last_event_timestamp._value.set(0)
        _, der = self._cert_der()
        tmpl, ck_cert, _ = self._cert_template(der)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, der]):
            analyzer._handle_nsc_create_object(event)
        assert analyzer.metrics.last_event_timestamp._value.get() > 0

    def test_create_object_applies_pod_context(self, analyzer):
        """Pod namespace from the uprobe event is stored on the resulting CertificateInfo."""
        import unittest.mock as mock
        _, der = self._cert_der()
        tmpl, ck_cert, _ = self._cert_template(der)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2], has_pod=True)
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, der]):
            analyzer._handle_nsc_create_object(event)
        stored = list(analyzer.known_certs.values())[0]
        assert stored.namespace == 'fips-ns'

    # ------------------------------------------------------------------ NSC_FindObjectsInit

    def test_find_objects_rejects_kprobe(self, analyzer):
        """Returns False immediately for a non-uprobe event type."""
        assert analyzer._handle_nsc_find_objects_init(self._make_kprobe_event()) is False

    def test_find_objects_rejects_too_few_args(self, analyzer):
        """Returns False when fewer than 3 uint64 args are present."""
        event = self._make_event('NSC_FindObjectsInit', [0, self.TMPL_ADDR])
        assert analyzer._handle_nsc_find_objects_init(event) is False

    def test_find_objects_rejects_zero_count(self, analyzer):
        """Returns False when the attribute count arg is 0."""
        event = self._make_event('NSC_FindObjectsInit', [0, self.TMPL_ADDR, 0])
        assert analyzer._handle_nsc_find_objects_init(event) is False

    def test_find_objects_rejects_excessive_count(self, analyzer):
        """Returns False when attribute count exceeds the sanity cap of 32."""
        event = self._make_event('NSC_FindObjectsInit', [0, self.TMPL_ADDR, 33])
        assert analyzer._handle_nsc_find_objects_init(event) is False

    def test_find_objects_rejects_unreadable_template(self, analyzer):
        """Returns False when /proc/pid/mem cannot be read for the template."""
        import unittest.mock as mock
        event = self._make_event('NSC_FindObjectsInit', [0, self.TMPL_ADDR, 1])
        with mock.patch.object(analyzer, '_read_process_memory', return_value=None):
            assert analyzer._handle_nsc_find_objects_init(event) is False

    def test_find_objects_rejects_non_cert_filter(self, analyzer):
        """Returns False when the template filters on CKO_DATA, not CKO_CERTIFICATE."""
        import unittest.mock as mock
        tmpl = self._pack_attr(self.CKA_CLASS, self.CLASS_ADDR, 4)
        ck_data = (0x00000000).to_bytes(4, 'little')
        event = self._make_event('NSC_FindObjectsInit', [0, self.TMPL_ADDR, 1])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_data]):
            assert analyzer._handle_nsc_find_objects_init(event) is False

    def test_find_objects_returns_true_for_cert_filter(self, analyzer):
        """Returns True when the template contains a CKO_CERTIFICATE class filter."""
        import unittest.mock as mock
        tmpl = self._pack_attr(self.CKA_CLASS, self.CLASS_ADDR, 4)
        ck_cert = self.CKO_CERTIFICATE.to_bytes(4, 'little')
        event = self._make_event('NSC_FindObjectsInit', [0, self.TMPL_ADDR, 1])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert]):
            assert analyzer._handle_nsc_find_objects_init(event) is True

    def test_find_objects_logs_cert_enumeration(self, analyzer, caplog):
        """An INFO log mentioning NSC_FindObjectsInit is emitted when cert enumeration fires."""
        import unittest.mock as mock
        tmpl = self._pack_attr(self.CKA_CLASS, self.CLASS_ADDR, 4)
        ck_cert = self.CKO_CERTIFICATE.to_bytes(4, 'little')
        event = self._make_event('NSC_FindObjectsInit', [0, self.TMPL_ADDR, 1],
                                 binary='/usr/bin/java', pid=9876)
        with caplog.at_level(logging.INFO):
            with mock.patch.object(analyzer, '_read_process_memory',
                                   side_effect=[tmpl, ck_cert]):
                analyzer._handle_nsc_find_objects_init(event)
        assert any('NSC_FindObjectsInit' in r.message for r in caplog.records)

    def test_find_objects_self_filter_by_pid(self, analyzer, monkeypatch):
        """Own PID is dropped before any memory reads occur."""
        import unittest.mock as mock
        assert analyzer.filter_self_events is True
        monkeypatch.setattr(os, 'getpid', lambda: 9876)
        event = self._make_event('NSC_FindObjectsInit', [0, self.TMPL_ADDR, 1], pid=9876)
        with mock.patch.object(analyzer, '_read_process_memory') as mock_mem:
            result = analyzer._handle_nsc_find_objects_init(event)
        assert result is False
        mock_mem.assert_not_called()

    # ------------------------------------------------------------------ process_event routing

    def test_process_event_routes_nsc_create_object(self, analyzer):
        """process_event dispatches NSC_CreateObject symbol to _handle_nsc_create_object."""
        import unittest.mock as mock
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_handle_nsc_create_object') as mock_handler:
            analyzer.process_event(event)
        mock_handler.assert_called_once_with(event)

    def test_process_event_routes_nsc_find_objects_init(self, analyzer):
        """process_event dispatches NSC_FindObjectsInit symbol to _handle_nsc_find_objects_init."""
        import unittest.mock as mock
        event = self._make_event('NSC_FindObjectsInit', [0, self.TMPL_ADDR, 1])
        with mock.patch.object(analyzer, '_handle_nsc_find_objects_init') as mock_handler:
            analyzer.process_event(event)
        mock_handler.assert_called_once_with(event)

    def test_process_event_nsc_symbols_do_not_fall_through_to_bytes_handler(self, analyzer):
        """_handle_uprobe_in_memory_cert is not called when the symbol is an NSC_ handler."""
        import unittest.mock as mock
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_handle_nsc_create_object', return_value=True), \
             mock.patch.object(analyzer, '_handle_uprobe_in_memory_cert') as mock_bytes:
            analyzer.process_event(event)
        mock_bytes.assert_not_called()


class TestResolveProcessBinary:
    """Tests for _resolve_process_binary fallback when Tetragon truncates the binary path."""

    def test_normal_path_confirmed_via_proc_exe(self, analyzer):
        """A non-truncated binary path is returned unchanged when proc/exe agrees."""
        import unittest.mock as mock
        with mock.patch('os.readlink', return_value='/usr/bin/nginx'):
            result = analyzer._resolve_process_binary('/usr/bin/nginx', 9999)
        assert result == '/usr/bin/nginx'

    def test_truncated_path_resolved_via_proc_exe(self, analyzer, tmp_path):
        """When Tetragon gives a directory (truncated), /proc/{pid}/exe provides the full path."""
        link_dir = tmp_path / 'build'
        link_dir.mkdir()
        binary = link_dir / 'test_openssl3_cert_load'
        binary.write_bytes(b'')

        import unittest.mock as mock

        original_readlink = __import__('os').readlink

        def mock_readlink(path):
            if path == '/proc/1234/exe':
                return str(binary)
            return original_readlink(path)

        with mock.patch('os.readlink', side_effect=mock_readlink):
            result = analyzer._resolve_process_binary(str(link_dir), 1234)
        assert result == str(binary)

    def test_protect_home_path_resolved_via_proc_exe(self, analyzer, tmp_path):
        """Works even when ProtectHome makes os.path.isdir() unreliable for /home paths."""
        import unittest.mock as mock

        home_dir = '/home/benm/app/build'
        home_binary = '/home/benm/app/build/myserver'

        original_readlink = __import__('os').readlink

        def mock_readlink(path):
            if path == '/proc/1234/exe':
                return home_binary
            return original_readlink(path)

        with mock.patch('os.readlink', side_effect=mock_readlink), \
             mock.patch('os.path.isdir', return_value=False):
            result = analyzer._resolve_process_binary(home_dir, 1234)
        assert result == home_binary

    def test_proc_exe_oserror_returns_original(self, analyzer):
        """Original path is returned when /proc/{pid}/exe raises OSError (process exited)."""
        import unittest.mock as mock

        with mock.patch('os.readlink', side_effect=OSError('no such process')):
            result = analyzer._resolve_process_binary('/some/build/dir', 42)
        assert result == '/some/build/dir'
