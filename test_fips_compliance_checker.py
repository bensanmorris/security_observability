"""Tests for fips_compliance_checker module."""

import os
import sys
import warnings
import pytest
from datetime import datetime, timedelta
from unittest.mock import mock_open, patch

from unittest.mock import MagicMock

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from agent.fips_compliance_checker import check_certificate, system_fips_enabled, FipsComplianceResult


def _build_cert(private_key, hash_algorithm=None) -> x509.Certificate:
    """Build a minimal self-signed cert using a FIPS-approved hash algorithm."""
    if hash_algorithm is None:
        hash_algorithm = hashes.SHA256()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
    ])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(private_key, hash_algorithm, default_backend())
    )


def _mock_cert(hash_alg, pub_key) -> MagicMock:
    """Build a mock cert with a specific hash algorithm and public key.

    Used for non-approved hash algorithms (SHA-1, MD5) that modern OpenSSL
    refuses to sign with — the checker logic is the same regardless.
    """
    cert = MagicMock()
    cert.signature_hash_algorithm = hash_alg
    cert.public_key.return_value = pub_key
    return cert


class TestCheckCertificateRSA:
    def test_rsa_2048_sha256_compliant(self):
        key = rsa.generate_private_key(65537, 2048, default_backend())
        result = check_certificate(_build_cert(key, hashes.SHA256()))
        assert result.compliant
        assert result.key_algorithm == 'RSA'
        assert result.key_size == 2048
        assert result.signature_hash == 'sha256'
        assert result.violations == []

    def test_rsa_4096_sha384_compliant(self):
        key = rsa.generate_private_key(65537, 4096, default_backend())
        result = check_certificate(_build_cert(key, hashes.SHA384()))
        assert result.compliant
        assert result.key_size == 4096
        assert result.signature_hash == 'sha384'

    def test_rsa_4096_sha512_compliant(self):
        key = rsa.generate_private_key(65537, 4096, default_backend())
        result = check_certificate(_build_cert(key, hashes.SHA512()))
        assert result.compliant
        assert result.signature_hash == 'sha512'

    def test_rsa_1024_non_compliant(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            key = rsa.generate_private_key(65537, 1024, default_backend())
            result = check_certificate(_build_cert(key, hashes.SHA256()))
        assert not result.compliant
        assert result.key_algorithm == 'RSA'
        assert result.key_size == 1024
        assert any('1024' in v for v in result.violations)

    def test_rsa_sha1_non_compliant(self):
        # Modern OpenSSL refuses to sign with SHA-1, so mock the cert object
        key = rsa.generate_private_key(65537, 2048, default_backend())
        result = check_certificate(_mock_cert(hashes.SHA1(), key.public_key()))
        assert not result.compliant
        assert result.signature_hash == 'sha1'
        assert any('sha1' in v for v in result.violations)

    def test_rsa_md5_non_compliant(self):
        key = rsa.generate_private_key(65537, 2048, default_backend())
        result = check_certificate(_mock_cert(hashes.MD5(), key.public_key()))
        assert not result.compliant
        assert result.signature_hash == 'md5'
        assert any('md5' in v for v in result.violations)

    def test_rsa_1024_sha1_two_violations(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            key = rsa.generate_private_key(65537, 1024, default_backend())
        result = check_certificate(_mock_cert(hashes.SHA1(), key.public_key()))
        assert not result.compliant
        assert len(result.violations) >= 2


class TestCheckCertificateEC:
    def test_p256_sha256_compliant(self):
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        result = check_certificate(_build_cert(key, hashes.SHA256()))
        assert result.compliant
        assert result.key_algorithm == 'EC'
        assert result.curve_name == 'secp256r1'
        assert result.violations == []

    def test_p384_sha384_compliant(self):
        key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        result = check_certificate(_build_cert(key, hashes.SHA384()))
        assert result.compliant
        assert result.curve_name == 'secp384r1'

    def test_p521_sha512_compliant(self):
        key = ec.generate_private_key(ec.SECP521R1(), default_backend())
        result = check_certificate(_build_cert(key, hashes.SHA512()))
        assert result.compliant
        assert result.curve_name == 'secp521r1'

    def test_non_approved_curve_non_compliant(self):
        key = ec.generate_private_key(ec.SECP192R1(), default_backend())
        result = check_certificate(_build_cert(key, hashes.SHA256()))
        assert not result.compliant
        assert result.curve_name == 'secp192r1'
        assert any('secp192r1' in v for v in result.violations)

    def test_p256_sha1_non_compliant(self):
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        result = check_certificate(_mock_cert(hashes.SHA1(), key.public_key()))
        assert not result.compliant
        assert any('sha1' in v for v in result.violations)


class TestFipsComplianceResultFields:
    def test_curve_name_empty_for_rsa(self):
        key = rsa.generate_private_key(65537, 2048, default_backend())
        result = check_certificate(_build_cert(key))
        assert result.curve_name == ''

    def test_key_size_set_for_ec(self):
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        result = check_certificate(_build_cert(key))
        assert result.key_size > 0

    def test_violations_empty_when_compliant(self):
        key = rsa.generate_private_key(65537, 2048, default_backend())
        result = check_certificate(_build_cert(key))
        assert result.compliant
        assert result.violations == []


class TestSystemFipsEnabled:
    def test_fips_enabled(self):
        with patch('builtins.open', mock_open(read_data='1\n')):
            assert system_fips_enabled() is True

    def test_fips_disabled(self):
        with patch('builtins.open', mock_open(read_data='0\n')):
            assert system_fips_enabled() is False

    def test_file_missing_returns_false(self):
        with patch('builtins.open', side_effect=OSError('no such file')):
            assert system_fips_enabled() is False

    def test_permission_denied_returns_false(self):
        with patch('builtins.open', side_effect=PermissionError('denied')):
            assert system_fips_enabled() is False
