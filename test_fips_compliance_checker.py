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

from agent.fips_compliance_checker import (
    check_certificate, system_fips_enabled, get_algorithm_oids, FipsComplianceResult,
    _der_read_tlv, _der_decode_oid,
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


class TestGetAlgorithmOids:
    def test_rsa_spki_oid(self):
        key = rsa.generate_private_key(65537, 2048, default_backend())
        spki_oid, _ = get_algorithm_oids(_build_cert(key))
        assert spki_oid == '1.2.840.113549.1.1.1'  # rsaEncryption

    def test_rsa_sha256_signature_oid(self):
        key = rsa.generate_private_key(65537, 2048, default_backend())
        _, sig_oid = get_algorithm_oids(_build_cert(key, hashes.SHA256()))
        assert sig_oid == '1.2.840.113549.1.1.11'  # sha256WithRSAEncryption

    def test_ec_spki_oid(self):
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        spki_oid, _ = get_algorithm_oids(_build_cert(key))
        assert spki_oid == '1.2.840.10045.2.1'  # id-ecPublicKey

    def test_ec_sha384_signature_oid(self):
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        _, sig_oid = get_algorithm_oids(_build_cert(key, hashes.SHA384()))
        assert sig_oid == '1.2.840.10045.4.3.3'  # ecdsa-with-SHA384

    def test_spki_oid_still_resolves_when_public_key_unsupported(self):
        """The whole point of decoding SPKI from raw DER instead of asking
        cert.public_key(): an algorithm this install of `cryptography` can't
        instantiate (post-quantum/composite keys today) still yields an OID
        here, where check_certificate()'s isinstance-based dispatch would
        collapse it to key_algorithm='unknown'.
        """
        key = rsa.generate_private_key(65537, 2048, default_backend())
        cert = _build_cert(key)
        with patch.object(type(cert), 'public_key', side_effect=Exception("unsupported key type")):
            spki_oid, sig_oid = get_algorithm_oids(cert)
        assert spki_oid == '1.2.840.113549.1.1.1'
        assert sig_oid == '1.2.840.113549.1.1.11'

    def test_signature_oid_empty_on_failure(self):
        cert = MagicMock()
        type(cert).signature_algorithm_oid = property(lambda self: (_ for _ in ()).throw(ValueError("boom")))
        cert.public_key_algorithm_oid = None  # simulate cryptography < 42, which has no such attribute
        cert.tbs_certificate_bytes = b'not valid der'
        spki_oid, sig_oid = get_algorithm_oids(cert)
        assert sig_oid == ''
        assert spki_oid == ''

    def test_spki_oid_correct_with_long_form_der_length(self):
        """A subject DN long enough to push some skipped TBSCertificate field
        (issuer/subject Name) past the 127-byte short-form DER length limit --
        exercises the long-form length branch of _der_read_tlv en route to
        subjectPublicKeyInfo, not just the common short-form case."""
        key = rsa.generate_private_key(65537, 2048, default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "x" * 40),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "y" * 40),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "z" * 40),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .sign(key, hashes.SHA256(), default_backend())
        )
        assert len(cert.subject.rfc4514_string()) > 127  # sanity check on the premise
        spki_oid, _ = get_algorithm_oids(cert)
        assert spki_oid == '1.2.840.113549.1.1.1'


class TestDerHelpers:
    """White-box tests for the DER TLV/OID helpers _spki_algorithm_oid_from_tbs
    relies on, isolated from certificate generation."""

    def test_read_tlv_short_form_length(self):
        # SEQUENCE, length 2, content b'\x01\x02'
        data = bytes([0x30, 0x02, 0x01, 0x02])
        tag, content_start, next_offset = _der_read_tlv(data, 0)
        assert tag == 0x30
        assert data[content_start:next_offset] == b'\x01\x02'
        assert next_offset == len(data)

    def test_read_tlv_long_form_length(self):
        # SEQUENCE, long-form length (0x81 0x80 -> 128 content bytes)
        content = bytes(range(128))
        data = bytes([0x30, 0x81, 0x80]) + content
        tag, content_start, next_offset = _der_read_tlv(data, 0)
        assert tag == 0x30
        assert data[content_start:next_offset] == content
        assert next_offset == len(data)

    def test_read_tlv_indefinite_length_rejected(self):
        with pytest.raises(ValueError):
            _der_read_tlv(bytes([0x30, 0x80]), 0)

    def test_read_tlv_truncated_long_form_length_rejected(self):
        """A long-form length header claiming more length-bytes than actually
        follow must raise rather than silently decoding from whatever fewer
        bytes happen to be present -- slicing past the end of `data` doesn't
        raise on its own, so this has to be checked explicitly."""
        # 0x84 says "4 length-bytes follow", but only 2 are present.
        data = bytes([0x30, 0x84, 0x00, 0x01])
        with pytest.raises(ValueError):
            _der_read_tlv(data, 0)

    def test_decode_oid_rsa_encryption(self):
        # rsaEncryption: 1.2.840.113549.1.1.1
        oid_bytes = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
        assert _der_decode_oid(oid_bytes) == '1.2.840.113549.1.1.1'

    def test_decode_oid_ec_public_key(self):
        # id-ecPublicKey: 1.2.840.10045.2.1
        oid_bytes = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])
        assert _der_decode_oid(oid_bytes) == '1.2.840.10045.2.1'


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
