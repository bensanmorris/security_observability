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
import tempfile
import os

def generate_test_certificate(days_valid: int, output_path: str, cn: str = None):
    """Generate a self-signed test certificate"""
    if cn is None:
        cn = f"test-{days_valid}days.local"
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "TestCity"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TestOrg"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    
    not_valid_before = datetime.utcnow()
    not_valid_after = datetime.utcnow() + timedelta(days=days_valid)
    
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
    
    print(f"Generated: {output_path} (valid for {days_valid} days, expires {not_valid_after.strftime('%Y-%m-%d')})")
    print(f"           {key_path}")

if __name__ == '__main__':
    # Create test certificates with various expiry dates
    test_dir = tempfile.mkdtemp(prefix="test-certs-")
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
    
    print("="*60)
    print(f"\n✅ Test certificates created in: {test_dir}")
    print("\nTo test the analyzer:")
    print(f"  1. Start the analyzer: ./run-rootless.sh")
    print(f"  2. Access a certificate: cat {test_dir}/expiring-soon.crt")
    print(f"  3. Check logs: podman logs cert-analyzer | grep expiring-soon")
    print(f"  4. Check metrics: curl -s http://localhost:9090/metrics | grep expiring-soon")
    print(f"\nOr run periodic scan with:")
    print(f"  podman run -d -v {test_dir}:/test-certs:ro,Z -e CERT_SCAN_PATHS=/test-certs cert-analyzer:latest")
