from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, List, Set, Tuple


@dataclass
class CertificateInfo:
    """Information extracted from an X.509 certificate"""
    path: str
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    process: str
    pid: int
    namespace: str = ""
    common_name: str = ""
    san_dns_names: list = field(default_factory=list)
    san_ip_addresses: list = field(default_factory=list)
    cert_index: int = 0
    # Kubernetes context sourced directly from the Tetragon event Pod proto
    pod_name: str = ""
    pod_uid: str = ""
    pod_labels: dict = None
    pod_annotations: dict = None
    workload_kind: str = ""
    workload_name: str = ""
    node_name: str = ""
    app_label: str = ""                      # derived from pod_labels
    container_id: str = ""
    container_name: str = ""
    container_image: str = ""
    container_image_id: str = ""
    container_privileged: bool = False
    container_pid: Optional[int] = None
    container_start_time: Optional[datetime] = None
    container_maybe_exec_probe: bool = False
    # Spawning process — binary path and PID of the process that launched
    # the cert loader. Empty when Tetragon's process cache didn't have the
    # parent at event time (common at startup).
    parent_process: str = ""
    parent_pid: int = 0
    # SHA-256 of the DER-encoded certificate bytes. Empty string when
    # CERT_CHECKSUM_ENABLED=false (the default).
    checksum: str = ""
    # SHA-256 of the DER-encoded SubjectPublicKeyInfo (the public key alone,
    # not the whole certificate) -- identical across a renewal that reuses
    # the same key pair, unlike `checksum` above which changes on every
    # renewal regardless of key reuse. Empty string when
    # SPKI_HASH_ENABLED=false. Unlike checksum, defaults to enabled: it's a
    # hash of public (non-sensitive) key material, and downstream consumers
    # need it on every cert to detect key reuse across renewals themselves.
    spki_hash: str = ""
    # Key metadata — populated by extract_certificate_info() unconditionally
    # (independent of fips_compliance_enabled; see extract_key_info() in
    # agent/fips_compliance_checker.py).
    key_algorithm: str = ""    # RSA, EC, DSA, Ed25519, Ed448, unknown
    key_size: int = 0          # bits; 0 for EdDSA
    signature_hash: str = ""   # sha256, sha1, md5, etc.
    curve_name: str = ""       # secp256r1 etc. (EC only)
    # FIPS 140-2/140-3 compliance judgement of the key metadata above —
    # only populated when fips_compliance_enabled is True. fips_checked
    # records whether that judgement actually ran, since fips_compliant=False
    # alone is ambiguous: it's also the untouched default when the check was
    # skipped, not just a genuine non-compliance result. Metrics emission
    # gates on this rather than key_algorithm (which now always populates).
    fips_checked: bool = False
    fips_compliant: bool = False
    fips_violations: list = field(default_factory=list)
    # Raw dotted-string OIDs read directly off the DER encoding, independent
    # of whether `cryptography` recognizes the algorithm -- unlike
    # key_algorithm/signature_hash above, these still populate for algorithm
    # types (e.g. post-quantum/composite keys) this install can't instantiate
    # as a key object. Feeds downstream PQC-readiness scoring.
    spki_algorithm_oid: str = ""
    signature_algorithm_oid: str = ""
    # RFC 5280 extension fields — None means the extension is absent from the certificate
    key_usage: Optional[list] = None
    extended_key_usage: Optional[list] = None
    ocsp_responder_urls: Optional[list] = None
    ca_issuers_urls: Optional[list] = None
    is_ca: Optional[bool] = None
    basic_constraints_path_length: Optional[int] = None
    # True when the certificate is self-signed (subject == issuer and signature
    # verifies against its own public key). Root CA certificates are legitimately
    # self-signed; self-signed leaf certificates are typically a configuration risk.
    is_self_signed: bool = False
    # Distinct (process, parent_process, pod_name, namespace, app_label,
    # container_name) tuples already given their own tls_certificate_process_info
    # series for this cert, capped at max_processes_per_cert (see
    # CertificateAnalyzer._record_cert_process_access). The pod/namespace/label
    # fields reflect the *accessing* event, not this CertificateInfo's own
    # (possibly different, sticky-to-the-discoverer) pod_name/namespace/etc.
    # Internal bookkeeping only — not cert data, not published to Kafka, and
    # excluded from repr/equality so it doesn't affect anything that compares
    # or prints a CertificateInfo. Dies naturally when the cert is LRU-evicted
    # from known_certs, so it needs no separate cleanup of its own.
    _seen_processes: Set[Tuple[str, str, str, str, str, str]] = field(default_factory=set, repr=False, compare=False)

    @property
    def days_until_expiry(self) -> float:
        """Calculate days until certificate expires"""
        delta = self.not_after - datetime.utcnow()
        return delta.total_seconds() / 86400

    @property
    def is_expired(self) -> bool:
        """Check if certificate has expired"""
        return datetime.utcnow() > self.not_after

    def expires_soon(self, days: int = 30) -> bool:
        """Check if certificate expires within specified days"""
        return 0 < self.days_until_expiry < days

    @property
    def unique_key(self) -> str:
        """Unique identifier for this certificate"""
        return f"{self.path}:{self.cert_index}:{self.serial_number}"

    @property
    def workload(self) -> str:
        """Human-readable workload reference e.g. DaemonSet/cert-analyzer"""
        if self.workload_kind and self.workload_name:
            return f"{self.workload_kind}/{self.workload_name}"
        return ""
