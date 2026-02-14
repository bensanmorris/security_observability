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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
