import os
import sys
import socket
import logging
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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

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
