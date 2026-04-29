#!/usr/bin/env python3
"""
Test script for certificate analyzer
Generates test certificates and verifies detection
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
import os
import struct
import hashlib
import time

def generate_test_certificate(days_valid: int, output_path: str, cn: str = None):
    """Generate a self-signed test certificate"""
    if cn is None:
        cn = f"test-{days_valid}days.local"

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # For expired certificates, set dates in the past
    if days_valid < 0:
        # Certificate expired 'days_valid' days ago
        not_valid_before = datetime.utcnow() + timedelta(days=days_valid) - timedelta(days=365)
        not_valid_after = datetime.utcnow() + timedelta(days=days_valid)
    else:
        # Normal certificate valid for 'days_valid' days
        not_valid_before = datetime.utcnow()
        not_valid_after = datetime.utcnow() + timedelta(days=days_valid)

    # Create certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "TestCity"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TestOrg"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
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
        not_valid_before
    ).not_valid_after(
        not_valid_after
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(cn),
            x509.DNSName(f"www.{cn}"),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    # Write certificate
    with open(output_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Write private key
    key_path = output_path.replace('.crt', '.key')
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    print(f"Generated: {output_path}")
    print(f"           Valid from: {not_valid_before.strftime('%Y-%m-%d')} to {not_valid_after.strftime('%Y-%m-%d')}")
    print(f"           Status: {'EXPIRED' if days_valid < 0 else f'Expires in {days_valid} days'}")

def generate_test_jks(days_valid: int, output_path: str, cn: str = None, password: str = 'changeit'):
    """
    Generate a minimal JKS keystore containing a single self-signed certificate.

    Constructs the JKS binary format by hand so that no JDK (keytool) is needed.
    The keystore contains one TrustedCertEntry under the alias 'test-cert', which
    is the format produced by 'keytool -importcert' and read by Java TrustManagers.

    JKS binary layout:
      magic(4) + version(4) + entry_count(4) + entries... + SHA1_digest(20)

    The SHA1 digest is computed over:
      password_as_java_chars + b"Mighty Aphrodite" + all_preceding_bytes
    """
    try:
        import jks  # noqa: verify pyjks is installed before writing the file
    except ImportError:
        print(f"Skipping {output_path}: pyjks not installed (pip install pyjks)")
        return

    if cn is None:
        cn = f"jks-test-{days_valid}days.local"

    # Build the certificate
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if days_valid < 0:
        not_valid_before = datetime.utcnow() + timedelta(days=days_valid) - timedelta(days=365)
        not_valid_after  = datetime.utcnow() + timedelta(days=days_valid)
    else:
        not_valid_before = datetime.utcnow()
        not_valid_after  = datetime.utcnow() + timedelta(days=days_valid)

    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .sign(private_key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    # Encode alias as UTF-16-BE (Java's internal string encoding)
    alias     = 'test-cert'
    alias_enc = alias.encode('utf-16-be')
    cert_type = b'X.509'
    timestamp = int(time.time() * 1000)  # Java Date: milliseconds since epoch

    # TrustedCertEntry: tag=2, alias, timestamp, cert_type, cert_der
    entry  = struct.pack('>I', 2)                               # tag
    entry += struct.pack('>H', len(alias_enc)) + alias_enc     # alias
    entry += struct.pack('>Q', timestamp)                       # date
    entry += struct.pack('>H', len(cert_type)) + cert_type     # cert type
    entry += struct.pack('>I', len(cert_der))  + cert_der      # cert data

    body = struct.pack('>III', 0xFEEDFEED, 2, 1) + entry      # header + 1 entry

    # JKS integrity digest: SHA1(pw_as_java_chars + "Mighty Aphrodite" + body)
    pw_bytes = b''.join(struct.pack('>H', ord(c)) for c in password)
    digest   = hashlib.sha1(pw_bytes + b'Mighty Aphrodite' + body).digest()

    with open(output_path, 'wb') as f:
        f.write(body + digest)

    status = 'EXPIRED' if days_valid < 0 else f'Expires in {days_valid} days'
    print(f"Generated: {output_path}")
    print(f"           CN={cn}")
    print(f"           Valid: {not_valid_before.strftime('%Y-%m-%d')} → {not_valid_after.strftime('%Y-%m-%d')}")
    print(f"           Status: {status}")
    print(f"           Password: {password}")


def generate_test_pkcs12(days_valid: int, output_path: str, cn: str = None, password: str = 'changeit'):
    """
    Generate a PKCS12 keystore (.p12) containing a self-signed certificate.

    Uses the cryptography library directly — no keytool or OpenSSL binary needed.
    The keystore contains a leaf certificate and its private key, matching the
    structure produced by 'keytool -importkeystore -deststoretype pkcs12'.
    """
    from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
    from cryptography.x509.oid import NameOID as _NameOID

    if cn is None:
        cn = f"pkcs12-test-{days_valid}days.local"

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if days_valid < 0:
        not_valid_before = datetime.utcnow() + timedelta(days=days_valid) - timedelta(days=365)
        not_valid_after  = datetime.utcnow() + timedelta(days=days_valid)
    else:
        not_valid_before = datetime.utcnow()
        not_valid_after  = datetime.utcnow() + timedelta(days=days_valid)

    subject = issuer = x509.Name([x509.NameAttribute(_NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .sign(private_key, hashes.SHA256())
    )

    p12_data = serialize_key_and_certificates(
        name=cn.encode(),
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )

    with open(output_path, 'wb') as f:
        f.write(p12_data)

    status = 'EXPIRED' if days_valid < 0 else f'Expires in {days_valid} days'
    print(f"Generated: {output_path}")
    print(f"           CN={cn}")
    print(f"           Valid: {not_valid_before.strftime('%Y-%m-%d')} → {not_valid_after.strftime('%Y-%m-%d')}")
    print(f"           Status: {status}")
    print(f"           Password: {password}")


if __name__ == '__main__':
    # In the container TEST_CERT_OUTPUT_DIR is set to /test-certs (mounted volume).
    # Outside a container it falls back to a test-certs/ dir next to this script.
    test_dir = os.environ.get(
        "TEST_CERT_OUTPUT_DIR",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "test-certs"),
    )

    # Remove old test certs if they exist
    if os.path.exists(test_dir):
        import shutil
        shutil.rmtree(test_dir)

    # Create fresh directory
    os.makedirs(test_dir)

    print(f"Creating test certificates in {test_dir}")
    print("="*60)

    test_cases = [
        ("expired.crt", -10, "expired.example.com"),
        ("expiring-soon.crt", 5, "soon.example.com"),
        ("expiring-week.crt", 7, "week.example.com"),
        ("expiring-month.crt", 25, "month.example.com"),
        ("expiring-quarter.crt", 85, "quarter.example.com"),
        ("valid.crt", 365, "valid.example.com"),
    ]

    for filename, days, cn in test_cases:
        cert_path = os.path.join(test_dir, filename)
        generate_test_certificate(days, cert_path, cn)
        print()

    print("="*60)
    print(f"\nTest certificates created in: {test_dir}")

    print()
    print("Generating JKS keystores...")
    print("="*60)
    jks_cases = [
        ("expired.jks",       -10,  "expired-jks.example.com"),
        ("expiring-soon.jks",   5,  "soon-jks.example.com"),
        ("valid.jks",         365,  "valid-jks.example.com"),
    ]
    for filename, days, cn in jks_cases:
        generate_test_jks(days, os.path.join(test_dir, filename), cn)
        print()

    print("="*60)
    print("Generating PKCS12 keystores...")
    print("="*60)
    pkcs12_cases = [
        ("expired.p12",       -10,  "expired-pkcs12.example.com"),
        ("expiring-soon.p12",   5,  "soon-pkcs12.example.com"),
        ("valid.p12",         365,  "valid-pkcs12.example.com"),
    ]
    for filename, days, cn in pkcs12_cases:
        generate_test_pkcs12(days, os.path.join(test_dir, filename), cn)
        print()

    print("="*60)
    print("\nTo test the analyzer:")
    print(f"  1. Trigger cert access:  cat {test_dir}/expired.crt")
    print(f"                           cat {test_dir}/expired.jks")
    print(f"                           cat {test_dir}/expired.p12")
    print(f"  2. Check metrics:        curl -s http://localhost:9090/metrics | grep expired")
