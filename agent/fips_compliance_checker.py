"""
FIPS 140-2/140-3 compliance checker for X.509 certificates.

Checks certificates against NIST SP 800-131A Rev. 2 and FIPS 186-4/186-5
approved algorithm requirements. No Tetragon or Prometheus dependencies —
import and call check_certificate() from cert_analyzer.py.
"""

from dataclasses import dataclass, field
from typing import List, Tuple
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448


# FIPS 186-4 / NIST SP 800-131A Rev. 2 approved signature hash algorithms.
# SHA-1 was allowed for verification-only until 2013 but is no longer approved
# for new certificate signatures. MD5 was never approved for signatures.
_APPROVED_HASH_NAMES: frozenset = frozenset({
    'sha224', 'sha256', 'sha384', 'sha512',
    'sha512-224', 'sha512-256',
    'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512',
})

# FIPS 186-4 Section 6.1.1 approved NIST elliptic curves.
_APPROVED_EC_CURVES: frozenset = frozenset({
    'secp256r1',  # P-256
    'secp384r1',  # P-384
    'secp521r1',  # P-521
})

_MIN_RSA_BITS: int = 2048  # NIST SP 800-131A Rev. 2
_MIN_DSA_BITS: int = 2048  # FIPS 186-4


@dataclass
class FipsComplianceResult:
    """Result of a FIPS compliance check on a single X.509 certificate."""
    compliant: bool
    key_algorithm: str         # "RSA", "EC", "DSA", "Ed25519", "Ed448", "unknown"
    key_size: int              # bits; 0 for EdDSA (fixed-size keys)
    curve_name: str            # secp256r1 etc.; empty for non-EC keys
    signature_hash: str        # sha256, sha1, md5, etc.; "unknown" if unreadable
    violations: List[str] = field(default_factory=list)


def _get_key_info(pub_key) -> Tuple[str, int, str]:
    """Return (algorithm, key_size_bits, curve_name) for a public key object."""
    if isinstance(pub_key, rsa.RSAPublicKey):
        return 'RSA', pub_key.key_size, ''
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        return 'EC', pub_key.key_size, pub_key.curve.name
    if isinstance(pub_key, dsa.DSAPublicKey):
        return 'DSA', pub_key.key_size, ''
    if isinstance(pub_key, ed25519.Ed25519PublicKey):
        return 'Ed25519', 0, ''
    if isinstance(pub_key, ed448.Ed448PublicKey):
        return 'Ed448', 0, ''
    return 'unknown', 0, ''


def check_certificate(cert: x509.Certificate, *, pub_key=None) -> FipsComplianceResult:
    """
    Check an X.509 certificate against FIPS 140-2/140-3 algorithm requirements.

    Checks:
    - Signature hash algorithm (SHA-256 or stronger required; SHA-1 and MD5 are violations)
    - Public key algorithm, minimum key size, and approved EC curve

    pub_key may be supplied by the caller to avoid a second cert.public_key() extraction
    when the key object was already obtained during certificate info extraction.

    Returns a FipsComplianceResult with compliant=True only when no violations are found.
    """
    violations: List[str] = []

    # -- Signature hash -------------------------------------------------------
    hash_name = 'unknown'
    try:
        hash_alg = cert.signature_hash_algorithm
        if hash_alg is not None:
            hash_name = hash_alg.name.lower()
    except Exception:
        pass  # nosec B110 - hash_name stays 'unknown', flagged as a violation below, not swallowed

    if hash_name == 'unknown':
        violations.append("Could not determine signature hash algorithm")
    elif hash_name not in _APPROVED_HASH_NAMES:
        violations.append(
            f"Signature hash '{hash_name}' is not FIPS-approved (use SHA-256 or stronger)"
        )

    # -- Public key -----------------------------------------------------------
    algorithm = 'unknown'
    key_size = 0
    curve_name = ''
    try:
        pub = pub_key if pub_key is not None else cert.public_key()
        algorithm, key_size, curve_name = _get_key_info(pub)
    except Exception:
        violations.append("Could not read public key")

    if algorithm == 'RSA':
        if key_size < _MIN_RSA_BITS:
            violations.append(
                f"RSA key size {key_size} bits is below the "
                f"{_MIN_RSA_BITS}-bit FIPS minimum (NIST SP 800-131A Rev. 2)"
            )
    elif algorithm == 'EC':
        if curve_name not in _APPROVED_EC_CURVES:
            violations.append(
                f"EC curve '{curve_name}' is not FIPS-approved "
                f"(approved: secp256r1/P-256, secp384r1/P-384, secp521r1/P-521)"
            )
    elif algorithm == 'DSA':
        if key_size < _MIN_DSA_BITS:
            violations.append(
                f"DSA key size {key_size} bits is below the {_MIN_DSA_BITS}-bit FIPS minimum"
            )
        violations.append(
            "DSA is deprecated in FIPS 186-5; migrate to RSA or ECDSA"
        )
    elif algorithm == 'unknown':
        violations.append("Could not determine public key algorithm")
    # Ed25519 and Ed448 are approved in FIPS 186-5 — no violations added

    return FipsComplianceResult(
        compliant=len(violations) == 0,
        key_algorithm=algorithm,
        key_size=key_size,
        curve_name=curve_name,
        signature_hash=hash_name,
        violations=violations,
    )


def system_fips_enabled() -> bool:
    """
    Return True if the kernel reports FIPS mode enabled.

    Reads /proc/sys/crypto/fips_enabled (Linux only). Returns False if the
    file is absent or unreadable (non-Linux platforms, unprivileged containers).
    """
    try:
        with open('/proc/sys/crypto/fips_enabled', 'r') as f:
            return f.read().strip() == '1'
    except OSError:
        return False
