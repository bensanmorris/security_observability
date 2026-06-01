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

sys.path.insert(0, os.path.dirname(__file__))
from fips_compliance_checker import (
    check_certificate, system_fips_enabled, FipsComplianceResult,
    check_cipher_list, check_tls_version, check_ssl_options, HandshakeFipsResult,
)


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


class TestHandshakeFipsResult:
    def test_compliant_result_has_empty_violations(self):
        r = HandshakeFipsResult(compliant=True)
        assert r.compliant is True
        assert r.violations == []

    def test_non_compliant_result_carries_violations(self):
        r = HandshakeFipsResult(compliant=False, violations=["bad cipher"])
        assert r.compliant is False
        assert "bad cipher" in r.violations


class TestCheckCipherList:
    def test_empty_string_is_compliant(self):
        assert check_cipher_list("").compliant is True

    def test_explicit_fips_ecdhe_aes_gcm_compliant(self):
        r = check_cipher_list("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384")
        assert r.compliant is True
        assert r.violations == []

    def test_tls13_approved_suites_compliant(self):
        r = check_cipher_list("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256")
        assert r.compliant is True

    def test_rc4_keyword_non_compliant(self):
        r = check_cipher_list("HIGH:RC4:!aNULL")
        assert r.compliant is False
        assert any("RC4" in v for v in r.violations)

    def test_3des_keyword_non_compliant(self):
        r = check_cipher_list("3DES")
        assert r.compliant is False
        assert any("3DES" in v for v in r.violations)

    def test_null_encryption_non_compliant(self):
        r = check_cipher_list("NULL")
        assert r.compliant is False
        assert any("NULL" in v for v in r.violations)

    def test_anull_auth_non_compliant(self):
        r = check_cipher_list("HIGH:ANULL")
        assert r.compliant is False
        assert any("ANULL" in v for v in r.violations)

    def test_md5_mac_non_compliant(self):
        r = check_cipher_list("HIGH:MD5")
        assert r.compliant is False
        assert any("MD5" in v for v in r.violations)

    def test_camellia_non_compliant(self):
        r = check_cipher_list("CAMELLIA")
        assert r.compliant is False
        assert any("CAMELLIA" in v for v in r.violations)

    def test_default_directive_non_compliant(self):
        r = check_cipher_list("DEFAULT")
        assert r.compliant is False
        assert any("DEFAULT" in v for v in r.violations)

    def test_all_directive_non_compliant(self):
        r = check_cipher_list("ALL:!EXPORT")
        assert r.compliant is False
        assert any("ALL" in v for v in r.violations)

    def test_negated_rc4_is_not_a_violation(self):
        r = check_cipher_list("HIGH:!RC4:!aNULL:!MD5:!CAMELLIA:!SEED:!3DES")
        assert r.compliant is True, (
            "Explicitly negated non-FIPS keywords must not be counted as violations"
        )

    def test_negated_default_is_not_a_violation(self):
        r = check_cipher_list("ECDHE-RSA-AES256-GCM-SHA384:!DEFAULT")
        assert r.compliant is True

    def test_multiple_violations_accumulated(self):
        r = check_cipher_list("RC4:3DES:NULL")
        assert r.compliant is False
        assert len(r.violations) >= 3

    def test_colon_and_space_delimited_parse_equally(self):
        r1 = check_cipher_list("HIGH:RC4")
        r2 = check_cipher_list("HIGH RC4")
        assert r1.compliant == r2.compliant

    def test_srp_non_compliant(self):
        r = check_cipher_list("SRP")
        assert r.compliant is False

    def test_export_non_compliant(self):
        r = check_cipher_list("EXPORT")
        assert r.compliant is False

    def test_case_insensitive_matching(self):
        r = check_cipher_list("rc4")
        assert r.compliant is False


class TestCheckTlsVersion:
    def test_unset_zero_is_compliant(self):
        r = check_tls_version(0)
        assert r.compliant is True
        assert r.violations == []

    def test_tls_1_2_is_compliant(self):
        r = check_tls_version(0x0303)
        assert r.compliant is True

    def test_tls_1_3_is_compliant(self):
        r = check_tls_version(0x0304)
        assert r.compliant is True

    def test_tls_1_1_non_compliant(self):
        r = check_tls_version(0x0302)
        assert r.compliant is False
        assert any("1.1" in v for v in r.violations)

    def test_tls_1_0_non_compliant(self):
        r = check_tls_version(0x0301)
        assert r.compliant is False
        assert any("1.0" in v for v in r.violations)

    def test_ssl_3_0_non_compliant(self):
        r = check_tls_version(0x0300)
        assert r.compliant is False
        assert any("SSL 3.0" in v for v in r.violations)

    def test_violation_message_references_nist_standard(self):
        r = check_tls_version(0x0301)
        assert any("800-52" in v for v in r.violations)

    def test_unknown_version_above_floor_is_compliant(self):
        r = check_tls_version(0x0305)
        assert r.compliant is True


class TestCheckSslOptions:
    _NO_TLS12 = 0x08000000
    _NO_TLS13 = 0x20000000

    def test_no_options_compliant(self):
        r = check_ssl_options(0x0)
        assert r.compliant is True
        assert r.violations == []

    def test_no_tls12_only_compliant(self):
        r = check_ssl_options(self._NO_TLS12)
        assert r.compliant is True

    def test_no_tls13_only_compliant(self):
        r = check_ssl_options(self._NO_TLS13)
        assert r.compliant is True

    def test_both_disabled_non_compliant(self):
        r = check_ssl_options(self._NO_TLS12 | self._NO_TLS13)
        assert r.compliant is False
        assert len(r.violations) == 1

    def test_violation_mentions_both_flags(self):
        r = check_ssl_options(self._NO_TLS12 | self._NO_TLS13)
        assert any("TLSv1_2" in v and "TLSv1_3" in v for v in r.violations)

    def test_unrelated_flags_do_not_trigger_violation(self):
        SSL_OP_NO_COMPRESSION = 0x00020000
        r = check_ssl_options(SSL_OP_NO_COMPRESSION)
        assert r.compliant is True

    def test_both_plus_other_flags_still_non_compliant(self):
        SSL_OP_NO_COMPRESSION = 0x00020000
        r = check_ssl_options(self._NO_TLS12 | self._NO_TLS13 | SSL_OP_NO_COMPRESSION)
        assert r.compliant is False
