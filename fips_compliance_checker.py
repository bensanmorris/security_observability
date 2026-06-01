"""
FIPS 140-2/140-3 compliance checker for X.509 certificates and TLS handshake
configuration.

Checks certificates against NIST SP 800-131A Rev. 2 and FIPS 186-4/186-5
approved algorithm requirements.  Also checks OpenSSL SSL_CTX cipher list
strings, minimum TLS protocol versions, and SSL options bitmasks against
NIST SP 800-52 Rev. 2 requirements.

No Tetragon or Prometheus dependencies — import and call the check_*
functions from cert_analyzer.py.
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


def check_certificate(cert: x509.Certificate) -> FipsComplianceResult:
    """
    Check an X.509 certificate against FIPS 140-2/140-3 algorithm requirements.

    Checks:
    - Signature hash algorithm (SHA-256 or stronger required; SHA-1 and MD5 are violations)
    - Public key algorithm, minimum key size, and approved EC curve

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
        pass

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
        pub = cert.public_key()
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


# ── Handshake FIPS checking ───────────────────────────────────────────────────

# OpenSSL cipher string keywords and directives that introduce non-FIPS algorithms.
# NIST SP 800-52 Rev. 2 permits only AES-GCM/AES-CCM cipher suites with ECDHE
# or DHE key exchange and SHA-256/SHA-384 MACs over TLS 1.2 or 1.3.
_NON_FIPS_CIPHER_KEYWORDS: frozenset = frozenset({
    'RC4', 'RC2', 'RC5',
    'DES', '3DES', 'EDES',
    'EXPORT', 'EXP',
    'NULL', 'ENULL', 'ANULL',
    'ADH', 'AECDH',
    'IDEA', 'SEED', 'CAMELLIA', 'ARIA',
    'MD5',
    'SRP',
    'PSK',
})

# OpenSSL directives so broad they likely include non-FIPS ciphers.
_PERMISSIVE_CIPHER_DIRECTIVES: frozenset = frozenset({
    'DEFAULT', 'ALL', 'COMPLEMENTOFALL', 'COMPLEMENTOFDEFAULT',
})

# NIST SP 800-52 Rev. 2: TLS 1.2 (0x0303) or TLS 1.3 (0x0304) required.
_TLS_1_2_VERSION: int = 0x0303
_TLS_1_3_VERSION: int = 0x0304

_TLS_VERSION_NAMES: dict = {
    0x0304: 'TLS 1.3',
    0x0303: 'TLS 1.2',
    0x0302: 'TLS 1.1',
    0x0301: 'TLS 1.0',
    0x0300: 'SSL 3.0',
    0x0200: 'SSL 2.0',
}

# SSL_CTX_set_options() bitmask flags that affect FIPS-required TLS versions.
_SSL_OP_NO_TLSv1_2: int = 0x08000000
_SSL_OP_NO_TLSv1_3: int = 0x20000000


@dataclass
class HandshakeFipsResult:
    """Result of a FIPS compliance check on an SSL/TLS handshake configuration."""
    compliant: bool
    violations: List[str] = field(default_factory=list)


def check_cipher_list(cipher_str: str) -> HandshakeFipsResult:
    """
    Check an OpenSSL cipher list string for FIPS compliance.

    Parses the colon-separated cipher string for known non-FIPS cipher
    keywords (RC4, DES, NULL, anonymous DH, MD5 MAC, etc.) and overly
    permissive directives (DEFAULT, ALL) that include non-FIPS suites.

    Negated keywords (prefixed with !) are treated as exclusions and do not
    trigger a violation — e.g. '!RC4' in 'HIGH:!RC4' is not a violation.
    """
    if not cipher_str:
        return HandshakeFipsResult(compliant=True)

    violations: List[str] = []
    parts = cipher_str.replace(':', ' ').split()

    included = [p.upper() for p in parts if not p.startswith('!')]

    found_non_fips = [kw for kw in _NON_FIPS_CIPHER_KEYWORDS if kw in included]
    found_permissive = [kw for kw in _PERMISSIVE_CIPHER_DIRECTIVES if kw in included]

    for kw in sorted(found_non_fips):
        violations.append(f"Non-FIPS cipher keyword '{kw}' present in cipher list")
    for kw in sorted(found_permissive):
        violations.append(
            f"Permissive directive '{kw}' may include non-FIPS ciphers — "
            f"use an explicit FIPS cipher list instead"
        )

    return HandshakeFipsResult(compliant=len(violations) == 0, violations=violations)


def check_tls_version(version: int) -> HandshakeFipsResult:
    """
    Check a minimum TLS protocol version integer for FIPS compliance.

    NIST SP 800-52 Rev. 2 requires TLS 1.2 (0x0303) or TLS 1.3 (0x0304).
    A version of 0 means unset; OpenSSL will negotiate its own default, which
    is not treated as a violation here since the effective floor depends on
    OpenSSL's compiled-in minimum.
    """
    if version == 0:
        return HandshakeFipsResult(compliant=True)

    if version < _TLS_1_2_VERSION:
        name = _TLS_VERSION_NAMES.get(version, f"0x{version:04x}")
        return HandshakeFipsResult(
            compliant=False,
            violations=[
                f"Minimum TLS version {name} is below FIPS-required TLS 1.2 "
                f"(NIST SP 800-52 Rev. 2)"
            ],
        )
    return HandshakeFipsResult(compliant=True)


def check_ssl_options(options: int) -> HandshakeFipsResult:
    """
    Check an SSL_CTX_set_options() bitmask for FIPS-relevant flags.

    Only raises a violation when both TLS 1.2 and TLS 1.3 are explicitly
    disabled in the same call, leaving no FIPS-approved version available.
    Disabling only TLS 1.3 (leaving TLS 1.2) or only TLS 1.2 (leaving
    TLS 1.3) is not a violation — options accumulate across calls so a
    single call that disables one version may be complemented by another
    that keeps the other available.
    """
    no_tls12 = bool(options & _SSL_OP_NO_TLSv1_2)
    no_tls13 = bool(options & _SSL_OP_NO_TLSv1_3)

    if no_tls12 and no_tls13:
        return HandshakeFipsResult(
            compliant=False,
            violations=[
                "SSL_OP_NO_TLSv1_2 and SSL_OP_NO_TLSv1_3 both set in a single call — "
                "no FIPS-approved TLS version (1.2 or 1.3) available"
            ],
        )
    return HandshakeFipsResult(compliant=True)


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
