import os
import socket
from typing import Dict

TETRAGON_BUILD_VERSION: str = os.getenv('TETRAGON_BUILD_VERSION', 'unknown')
CERT_ANALYZER_VERSION: str = os.getenv('CERT_ANALYZER_VERSION', 'dev')

# Node identity used as a Prometheus label on health/Tetragon metrics so that
# multi-node dashboards can join on node_name. In Kubernetes, inject the real
# node name via: env: [{name: NODE_NAME, valueFrom: {fieldRef: {fieldPath: spec.nodeName}}}]
_NODE_NAME: str = os.getenv('NODE_NAME', socket.gethostname())

# Map TracingPolicyState enum integers to clean label strings.
_POLICY_STATE_NAMES: Dict[int, str] = {
    0: 'unknown',
    1: 'enabled',
    2: 'disabled',
    3: 'load_error',
    4: 'error',
    5: 'loading',
    6: 'unloading',
}

# Friendly names for the most common Extended Key Usage OIDs (RFC 5280 §4.2.1.12).
_EKU_NAMES = {
    '1.3.6.1.5.5.7.3.1': 'server_auth',
    '1.3.6.1.5.5.7.3.2': 'client_auth',
    '1.3.6.1.5.5.7.3.3': 'code_signing',
    '1.3.6.1.5.5.7.3.4': 'email_protection',
    '1.3.6.1.5.5.7.3.8': 'time_stamping',
    '1.3.6.1.5.5.7.3.9': 'ocsp_signing',
}

CACHE_MIN_SIZE: int = 10_000
CACHE_MAX_SIZE: int = max(CACHE_MIN_SIZE, int(os.getenv('CACHE_MAX_SIZE', str(CACHE_MIN_SIZE))))

# SHA-256 checksum computation on parsed certificates is disabled by default.
# Enable via CERT_CHECKSUM_ENABLED=true. When enabled, the DER-encoded bytes
# of each certificate are hashed and stored in CertificateInfo.checksum.
CERT_CHECKSUM_ENABLED: bool = os.getenv('CERT_CHECKSUM_ENABLED', 'false').lower() == 'true'

CONFIG_FILE_PATH = '/etc/cert-analyzer/cert-analyzer.conf'

# ---------------------------------------------------------------------------
# Event-source classification
#
# Every distinct mechanism that can surface certificate activity gets one
# stable label value here, used by tls_certificate_source_events_total. The
# point of the metric is tuning: it answers "which source is driving my event
# volume" so an operator can decide to unload a policy or narrow its filter.
#
# These values are a Prometheus label, so the set MUST stay small and fixed --
# that bounded cardinality is why the metric can be on by default, unlike the
# per-process tls_socket_bind_events_total/tls_tcp_connect_events_total pair.
# Anything unrecognised collapses into the *_OTHER buckets below rather than
# minting a new series per unknown symbol.
# ---------------------------------------------------------------------------

# kprobe function_name -> source label
EVENT_SOURCE_BY_KPROBE: Dict[str, str] = {
    'fd_install': 'file_access',
    'security_socket_bind': 'socket_bind',
    'sys_bind': 'socket_bind',
    'tcp_connect': 'tcp_connect',
}

# uprobe symbol -> source label
EVENT_SOURCE_BY_UPROBE: Dict[str, str] = {
    # OpenSSL explicit cert-file loads (the path arrives as a string arg)
    'SSL_CTX_use_certificate_file': 'openssl_file',
    'SSL_CTX_use_certificate_chain_file': 'openssl_file',
    # OpenSSL in-memory DER
    'SSL_CTX_use_certificate_ASN1': 'openssl_asn1',
    # Java JCA via the cert-agent native stub
    'java_cert_agent_write': 'java_jca',
    # NSS/PKCS11 (FIPS-mode JVMs)
    'NSC_CreateObject': 'pkcs11_create',
    'NSC_FindObjectsInit': 'pkcs11_find',
    # SNI hostname capture feeding the outbound connect probe
    'SSL_ctrl': 'sni_capture',
}

# Non-Tetragon sources — the analyzer generates these itself.
EVENT_SOURCE_PERIODIC_SCAN = 'periodic_scan'

# Catch-alls. A policy we don't know about still gets counted (so the total
# stays honest) without adding a series per unrecognised hook.
EVENT_SOURCE_OTHER_KPROBE = 'kprobe_other'
EVENT_SOURCE_OTHER_UPROBE = 'uprobe_other'
EVENT_SOURCE_OTHER = 'other'

# The real, nameable sources. These are zero-initialised at startup so the
# histogram panel shows an explicit 0 for a source that hasn't fired yet --
# "this policy is loaded but producing nothing" is itself a tuning answer, and
# is indistinguishable from "no data" if the series is simply absent.
EVENT_SOURCE_KNOWN_LABELS = sorted(
    set(EVENT_SOURCE_BY_KPROBE.values())
    | set(EVENT_SOURCE_BY_UPROBE.values())
    | {EVENT_SOURCE_PERIODIC_SCAN}
)

# Every label value the metric can emit, for tests. The catch-alls are
# deliberately NOT zero-initialised: they should appear on a dashboard only if
# something unrecognised actually fired, which is when you want to notice them.
EVENT_SOURCE_LABELS = sorted(
    set(EVENT_SOURCE_KNOWN_LABELS)
    | {
        EVENT_SOURCE_OTHER_KPROBE,
        EVENT_SOURCE_OTHER_UPROBE,
        EVENT_SOURCE_OTHER,
    }
)
