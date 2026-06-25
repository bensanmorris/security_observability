#!/usr/bin/env python3
# Thin shim — all logic lives in the agent/ package.
#
# Module-level re-imports below exist for two reasons:
#   1. `from cert_analyzer import X` in existing code and tests continues to work.
#   2. Tests that do `import cert_analyzer as _ca; _ca.time.sleep = ...` or
#      `_ca.grpc.insecure_channel = ...` still patch the *module objects* (which
#      are singletons), so the patch is globally visible regardless of where in
#      the codebase the module is imported.

import grpc  # noqa: F401 — tests access cert_analyzer.grpc
import time  # noqa: F401 — tests access cert_analyzer.time

# Tetragon proto modules — imported here so tests that do
# `import cert_analyzer as _ca; monkeypatch.delattr(_ca.tetragon_pb2, 'X')`
# continue to work (they patch the singleton module object).
try:
    from tetragon import tetragon_pb2, events_pb2, sensors_pb2, sensors_pb2_grpc  # noqa: F401
except ImportError:
    pass

from agent import (
    CertificateAnalyzer,
    CertificateInfo,
    LRUCache,
    CACHE_MIN_SIZE,
    CACHE_MAX_SIZE,
)
from agent.kafka import KafkaPublisher
from agent.health import HealthServer
from agent.constants import (
    CERT_ANALYZER_VERSION,
    TETRAGON_BUILD_VERSION,
    CONFIG_FILE_PATH,
)
from agent.config import main, load_config, cfg

__all__ = [
    'CertificateAnalyzer',
    'CertificateInfo',
    'LRUCache',
    'CACHE_MIN_SIZE',
    'CACHE_MAX_SIZE',
    'KafkaPublisher',
    'HealthServer',
    'CERT_ANALYZER_VERSION',
    'TETRAGON_BUILD_VERSION',
    'CONFIG_FILE_PATH',
    'main',
    'load_config',
    'cfg',
]

if __name__ == '__main__':
    main()
