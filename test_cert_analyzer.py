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

# Import the analyzer (adjust path as needed)
import sys
sys.path.insert(0, os.path.dirname(__file__))
from cert_analyzer_multi import CertificateAnalyzer, CertificateInfo


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
    """Create a certificate analyzer instance"""
    return CertificateAnalyzer(
        tetragon_address="unix:///dev/null",  # Dummy address for testing
        alert_threshold_days=30
    )


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
    
    def test_parse_bundle_with_mixed_content(self, analyzer, temp_dir):
        """Test parsing a bundle with certificates and other content"""
        cert1, key1 = TestCertificateGeneration.generate_certificate("cert1.example.com", 365)
        cert2, _ = TestCertificateGeneration.generate_certificate("cert2.example.com", 180)
        
        bundle_path = os.path.join(temp_dir, "mixed.pem")
        with open(bundle_path, 'wb') as f:
            # Write cert
            f.write(cert1.public_bytes(serialization.Encoding.PEM))
            # Write key (should be ignored)
            f.write(key1.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            # Write another cert
            f.write(cert2.public_bytes(serialization.Encoding.PEM))
        
        certs = analyzer.parse_certificates(bundle_path)
        
        # Should only parse certificates, not keys
        assert len(certs) == 2


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
    
    def test_analyze_expired_certificate(self, analyzer, temp_dir):
        """Test analyzing an expired certificate"""
        cert, _ = TestCertificateGeneration.generate_certificate("expired.example.com", -10)
        cert_path = os.path.join(temp_dir, "expired.pem")
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)
        
        cert_infos = analyzer.analyze_certificate(cert_path, "test_process", 1234)
        
        assert len(cert_infos) == 1
        assert cert_infos[0].is_expired
        assert cert_infos[0].days_until_expiry < 0
    
    def test_analyze_expiring_soon_certificate(self, analyzer, temp_dir):
        """Test analyzing a certificate expiring soon"""
        cert, _ = TestCertificateGeneration.generate_certificate("expiring.example.com", 5)
        cert_path = os.path.join(temp_dir, "expiring.pem")
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)
        
        cert_infos = analyzer.analyze_certificate(cert_path, "test_process", 1234)
        
        assert len(cert_infos) == 1
        assert not cert_infos[0].is_expired
        assert cert_infos[0].expires_soon(days=7)
        assert cert_infos[0].expires_soon(days=30)
    
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
        
        # Check unique keys are different
        assert cert_infos[0].unique_key != cert_infos[1].unique_key
        assert cert_infos[1].unique_key != cert_infos[2].unique_key


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


class TestMetrics:
    """Test Prometheus metrics updates"""
    
    def test_metrics_update_single_cert(self, analyzer, temp_dir):
        """Test metrics are updated for a single certificate"""
        cert, _ = TestCertificateGeneration.generate_certificate("test.example.com", 365)
        cert_path = os.path.join(temp_dir, "test.pem")
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)
        
        cert_infos = analyzer.analyze_certificate(cert_path, "test_process", 1234)
        
        # Update metrics
        for cert_info in cert_infos:
            analyzer.metrics.update_certificate_metrics(cert_info)
        
        # Metrics should be set (we can't easily test exact values without accessing internal state)
        # But we can verify the function doesn't crash
        assert True
    
    def test_metrics_update_multi_cert(self, analyzer, temp_dir):
        """Test metrics are updated for multiple certificates"""
        cert1, _ = TestCertificateGeneration.generate_certificate("cert1.example.com", 365)
        cert2, _ = TestCertificateGeneration.generate_certificate("cert2.example.com", 180)
        
        bundle_path = os.path.join(temp_dir, "bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem([cert1, cert2], bundle_path)
        
        cert_infos = analyzer.analyze_certificate(bundle_path, "test_process", 1234)
        
        # Update metrics for all certificates
        for cert_info in cert_infos:
            analyzer.metrics.update_certificate_metrics(cert_info)
        
        assert True


class TestEdgeCases:
    """Test edge cases and error conditions"""
    
    def test_certificate_with_no_common_name(self, analyzer, temp_dir):
        """Test parsing a certificate without a common name"""
        # Generate a cert with minimal subject
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).sign(private_key, hashes.SHA256(), backend=default_backend())
        
        cert_path = os.path.join(temp_dir, "no_cn.pem")
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)
        
        cert_infos = analyzer.analyze_certificate(cert_path, "test_process", 1234)
        
        assert len(cert_infos) == 1
        assert cert_infos[0].common_name == ""
    
    def test_permission_denied_file(self, analyzer, temp_dir):
        """Test handling of permission denied errors"""
        cert, _ = TestCertificateGeneration.generate_certificate("test.example.com", 365)
        cert_path = os.path.join(temp_dir, "protected.pem")
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)
        
        # Remove read permissions
        os.chmod(cert_path, 0o000)
        
        try:
            certs = analyzer.parse_certificates(cert_path)
            assert len(certs) == 0
        finally:
            # Restore permissions for cleanup
            os.chmod(cert_path, 0o644)
    
    def test_corrupted_pem_in_bundle(self, analyzer, temp_dir):
        """Test handling of corrupted certificate in a bundle"""
        cert1, _ = TestCertificateGeneration.generate_certificate("cert1.example.com", 365)
        cert2, _ = TestCertificateGeneration.generate_certificate("cert2.example.com", 180)
        
        bundle_path = os.path.join(temp_dir, "corrupted_bundle.pem")
        with open(bundle_path, 'wb') as f:
            # Write valid cert
            f.write(cert1.public_bytes(serialization.Encoding.PEM))
            # Write corrupted cert
            f.write(b"-----BEGIN CERTIFICATE-----\nCORRUPTED DATA\n-----END CERTIFICATE-----\n")
            # Write valid cert
            f.write(cert2.public_bytes(serialization.Encoding.PEM))
        
        certs = analyzer.parse_certificates(bundle_path)
        
        # Should parse the valid certificates and skip the corrupted one
        assert len(certs) >= 1  # At least some valid certs parsed


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
