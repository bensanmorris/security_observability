import configparser
import logging
import os
import sys
import threading
import time
from typing import Optional

from .constants import (
    CERT_ANALYZER_VERSION, TETRAGON_BUILD_VERSION,
    CACHE_MAX_SIZE, CONFIG_FILE_PATH,
)
from .analyzer import CertificateAnalyzer
from .health import HealthServer
from .kafka import KafkaPublisher
from .metrics import start_metrics_server

logger = logging.getLogger(__name__)


def setup_logging(level: str = 'INFO') -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def load_config(path: str = CONFIG_FILE_PATH) -> configparser.ConfigParser:
    """
    Load the INI configuration file if it exists.

    Returns an empty ConfigParser (all lookups fall through to env var
    defaults) if the file is absent — this keeps the Kubernetes deployment
    path working without any config file present.

    The config file path can be overridden via the CERT_ANALYZER_CONFIG
    env var, which is useful for testing or non-standard deployments.
    """
    config_path = os.getenv('CERT_ANALYZER_CONFIG', path)
    cp = configparser.ConfigParser()

    if os.path.exists(config_path):
        if not os.access(config_path, os.R_OK):
            logger.error(
                f"Config file {config_path} exists but is not readable — "
                f"check ownership and permissions (expected: root:cert-analyzer 640). "
                f"Falling back to environment variables and defaults."
            )
            return cp
        try:
            cp.read(config_path)
            logger.info(f"Loaded configuration from {config_path}")
        except configparser.Error as e:
            logger.warning(
                f"Could not parse config file {config_path}: {e} — "
                f"falling back to environment variables and defaults"
            )
    else:
        logger.debug(
            f"Config file not found at {config_path} — "
            f"using environment variables and defaults"
        )

    return cp


def cfg(
    cp: configparser.ConfigParser,
    section: str,
    key: str,
    env_var: str,
    default: str,
) -> str:
    """
    Resolve a configuration value using the precedence chain:
      config file → env var → hardcoded default

    The config file takes precedence so that operators editing
    /etc/cert-analyzer/cert-analyzer.conf always see their changes
    reflected without needing to unset env vars.

    Returns a string — callers are responsible for casting to int/bool.
    """
    if cp.has_option(section, key):
        return cp.get(section, key)
    return os.getenv(env_var, default)


def main():
    """Main entry point"""
    cp = load_config()

    tetragon_addr   = cfg(cp, 'tetragon',  'addr',                        'TETRAGON_ADDR',                   'localhost:54321')
    metrics_port    = int(cfg(cp, 'metrics',  'port',                     'METRICS_PORT',                    '9090'))
    min_scrape_interval = int(cfg(cp, 'metrics', 'min_scrape_interval_seconds', 'MIN_SCRAPE_INTERVAL_SECONDS', '60'))
    health_port     = int(cfg(cp, 'health',   'port',                     'HEALTH_PORT',                     '8086'))
    alert_threshold = int(cfg(cp, 'alerting', 'threshold_days',           'ALERT_THRESHOLD_DAYS',            '30'))
    log_level       = cfg(cp, 'logging',   'level',                       'LOG_LEVEL',                       'INFO')
    scan_paths_str  = cfg(cp, 'scanning',  'paths',                       'CERT_SCAN_PATHS',                 '/etc/ssl,/etc/pki')
    scan_paths      = [p.strip() for p in scan_paths_str.split(',') if p.strip()]
    scan_interval   = int(cfg(cp, 'scanning',  'interval_seconds',        'SCAN_INTERVAL_SECONDS',           '3600'))
    grace_period    = int(cfg(cp, 'health',    'readiness_grace_period_seconds', 'READINESS_GRACE_PERIOD_SECONDS', '60'))
    staleness       = int(cfg(cp, 'health',    'readiness_staleness_seconds',    'READINESS_STALENESS_SECONDS',    '300'))
    filter_self     = cfg(cp, 'certificates', 'filter_self_events',       'FILTER_SELF_EVENTS',              'true').lower() != 'false'
    host_prefix     = cfg(cp, 'certificates', 'host_prefix',              'HOST_PREFIX',                     '')
    checksum_enabled        = cfg(cp, 'certificates', 'checksum_enabled',        'CERT_CHECKSUM_ENABLED',        'false').lower() == 'true'
    demo_mode               = cfg(cp, 'certificates', 'demo_mode',               'DEMO_MODE',                    'false').lower() == 'true'
    fips_compliance_enabled = cfg(cp, 'certificates', 'fips_compliance_enabled', 'FIPS_COMPLIANCE_ENABLED',      'true').lower() != 'false'
    large_file_cert_threshold = int(cfg(cp, 'certificates', 'large_file_cert_threshold', 'LARGE_FILE_CERT_THRESHOLD', '20'))
    # Deliberately separate from large_file_cert_threshold above: that one only
    # decides whether a file's parsing is deferred to a background thread, this
    # one caps how many certs in a bundle get full Prometheus metrics/logging.
    # Conflating them meant raising the metrics cap to cover a realistic CA
    # bundle (~130-150 certs) also disabled background-thread parsing for it.
    large_file_metrics_cap = int(cfg(cp, 'certificates', 'large_file_metrics_cap', 'LARGE_FILE_METRICS_CAP', '300'))
    # Caps how many bytes _count_pem_certs reads to decide whether a file is
    # "large" -- without this, that check reads the whole file up front, on
    # the Tetragon event-consumer thread, before any background-thread
    # dispatch decision is even made. 2MB comfortably covers real-world CA
    # trust bundles (a few hundred KB in practice) while bounding the
    # worst-case read for an oversized/degenerate file.
    large_file_byte_cap = int(cfg(cp, 'certificates', 'large_file_byte_cap', 'LARGE_FILE_BYTE_CAP', str(2 * 1024 * 1024)))
    # Caps concurrent TLS-probe / large-file-parse threads so a burst of events
    # (e.g. many pods reconnecting to dependencies at once) can't spawn
    # unbounded OS threads.
    max_concurrent_background_threads = int(cfg(cp, 'certificates', 'max_concurrent_background_threads', 'MAX_CONCURRENT_BACKGROUND_THREADS', '20'))
    # Caps how many distinct (process, parent_process) pairs get their own
    # tls_certificate_process_info series per cert -- otherwise a file opened
    # by many unrelated binaries over the process's lifetime (e.g. the system
    # CA trust bundle) accumulates one permanent series per distinct process,
    # forever, regardless of known_certs cache size.
    max_processes_per_cert = int(cfg(cp, 'certificates', 'max_processes_per_cert', 'MAX_PROCESSES_PER_CERT', '20'))

    event_rate_metrics_enabled = cfg(cp, 'metrics', 'event_rate_metrics_enabled', 'EVENT_RATE_METRICS_ENABLED', 'false').lower() == 'true'

    bind_probe_enabled    = cfg(cp, 'port_probe', 'bind_probe_enabled',    'BIND_PROBE_ENABLED',    'false').lower() == 'true'
    connect_probe_enabled = cfg(cp, 'port_probe', 'connect_probe_enabled', 'CONNECT_PROBE_ENABLED', 'false').lower() == 'true'
    port_probe_timeout       = float(cfg(cp, 'port_probe', 'timeout_seconds',        'PORT_PROBE_TIMEOUT',       '5'))
    port_probe_connect_delay = float(cfg(cp, 'port_probe', 'connect_delay_seconds',  'PORT_PROBE_CONNECT_DELAY', '2'))
    _tls_ports_raw = cfg(cp, 'port_probe', 'tls_outbound_ports', 'TLS_OUTBOUND_PORTS', '')
    if _tls_ports_raw.strip():
        try:
            tls_outbound_ports: Optional[frozenset] = frozenset(
                int(p.strip()) for p in _tls_ports_raw.split(',') if p.strip()
            )
        except ValueError as e:
            logger.error(f"Invalid tls_outbound_ports value '{_tls_ports_raw}': {e} — using built-in defaults")
            tls_outbound_ports = None
    else:
        tls_outbound_ports = None

    kafka_enabled          = cfg(cp, 'kafka', 'enabled',           'KAFKA_ENABLED',           'false').lower() == 'true'
    kafka_bootstrap        = cfg(cp, 'kafka', 'bootstrap_servers', 'KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092')
    kafka_topic            = cfg(cp, 'kafka', 'topic',             'KAFKA_TOPIC',             'cert-analyzer-events')
    kafka_security         = cfg(cp, 'kafka', 'security_protocol', 'KAFKA_SECURITY_PROTOCOL', 'PLAINTEXT')
    kafka_sasl_mechanism   = cfg(cp, 'kafka', 'sasl_mechanism',    'KAFKA_SASL_MECHANISM',    '')
    kafka_sasl_username    = cfg(cp, 'kafka', 'sasl_username',     'KAFKA_SASL_USERNAME',     '')
    kafka_sasl_password    = cfg(cp, 'kafka', 'sasl_password',     'KAFKA_SASL_PASSWORD',     '')

    setup_logging(log_level)

    logger.info("="*60)
    logger.info("TLS Certificate Expiry Monitor (Multi-Cert + K8s Enrichment)")
    logger.info("="*60)
    logger.info(f"Version:           {CERT_ANALYZER_VERSION}")
    logger.info(f"Config file:       {os.getenv('CERT_ANALYZER_CONFIG', CONFIG_FILE_PATH)}")
    logger.info(f"Tetragon address:  {tetragon_addr}")
    logger.info(f"Tetragon build:    {TETRAGON_BUILD_VERSION}")
    logger.info(f"Cache max size:    {CACHE_MAX_SIZE}")
    logger.info(f"Cert checksums:    {'enabled' if checksum_enabled else 'disabled'}")
    logger.info(f"FIPS checking:     {'enabled' if fips_compliance_enabled else 'disabled'}")
    logger.info(f"Large file threshold: >{large_file_cert_threshold} certs parsed in background")
    logger.info(f"Large file metrics cap: {large_file_metrics_cap} certs get full Prometheus tracking per bundle")
    logger.info(f"Large file byte cap: {large_file_byte_cap} bytes read to classify a file as large")
    logger.info(f"Max concurrent background threads: {max_concurrent_background_threads}")
    logger.info(f"Max processes tracked per cert: {max_processes_per_cert}")
    logger.info(f"Metrics port:      {metrics_port}")
    logger.info(f"Min scrape interval: {min_scrape_interval}s (too-frequent scrapes get a cached reply)" if min_scrape_interval > 0 else "Min scrape interval: disabled")
    logger.info(f"Health port:       {health_port}")
    logger.info(f"Alert threshold:   {alert_threshold} days")
    logger.info(f"Scan paths:        {scan_paths}")
    logger.info(f"Scan interval:     {scan_interval} seconds")
    logger.info(f"Filter self events: {filter_self}")
    logger.info(f"Host prefix:       '{host_prefix}' (empty = standalone mode)")
    logger.info(f"Kafka enabled:     {kafka_enabled}")
    if kafka_enabled:
        logger.info(f"Kafka brokers:     {kafka_bootstrap}")
        logger.info(f"Kafka topic:       {kafka_topic}")
        logger.info(f"Kafka security:    {kafka_security}")
    logger.info(f"Event rate metrics: {'enabled' if event_rate_metrics_enabled else 'disabled'}")
    logger.info(f"Bind probe:        {'enabled' if bind_probe_enabled else 'disabled'}")
    logger.info(f"Connect probe:     {'enabled' if connect_probe_enabled else 'disabled'}")
    if bind_probe_enabled or connect_probe_enabled:
        logger.info(f"Port probe timeout:        {port_probe_timeout}s")
    if bind_probe_enabled:
        logger.info(f"Port probe connect delay:  {port_probe_connect_delay}s")
    if connect_probe_enabled:
        _effective_ports = tls_outbound_ports if tls_outbound_ports is not None else CertificateAnalyzer.TLS_OUTBOUND_PORTS
        logger.info(f"TLS outbound ports:        {sorted(_effective_ports)}")
    logger.info("="*60)

    logger.info(f"Starting Prometheus metrics server on port {metrics_port}")
    try:
        start_metrics_server(metrics_port, min_scrape_interval)
    except OSError as e:
        logger.critical(
            f"Cannot bind Prometheus metrics server to port {metrics_port}: {e}. "
            f"Change [metrics] port in cert-analyzer.conf or set METRICS_PORT."
        )
        sys.exit(1)

    kafka_publisher = None
    if kafka_enabled:
        kafka_publisher = KafkaPublisher(
            bootstrap_servers=kafka_bootstrap,
            topic=kafka_topic,
            security_protocol=kafka_security,
            sasl_mechanism=kafka_sasl_mechanism,
            sasl_username=kafka_sasl_username,
            sasl_password=kafka_sasl_password,
        )

    analyzer = CertificateAnalyzer(tetragon_addr, alert_threshold,
                                   filter_self_events=filter_self,
                                   host_prefix=host_prefix,
                                   kafka_publisher=kafka_publisher,
                                   checksum_enabled=checksum_enabled,
                                   demo_mode=demo_mode,
                                   fips_compliance_enabled=fips_compliance_enabled,
                                   event_rate_metrics_enabled=event_rate_metrics_enabled,
                                   bind_probe_enabled=bind_probe_enabled,
                                   connect_probe_enabled=connect_probe_enabled,
                                   port_probe_timeout=port_probe_timeout,
                                   port_probe_connect_delay=port_probe_connect_delay,
                                   tls_outbound_ports=tls_outbound_ports,
                                   large_file_cert_threshold=large_file_cert_threshold,
                                   large_file_metrics_cap=large_file_metrics_cap,
                                   large_file_byte_cap=large_file_byte_cap,
                                   max_concurrent_background_threads=max_concurrent_background_threads,
                                   max_processes_per_cert=max_processes_per_cert)

    health = HealthServer(
        analyzer=analyzer,
        port=health_port,
        grace_period_seconds=grace_period,
        staleness_seconds=staleness,
    )
    health.start()

    analyzer.health_server = health

    if scan_paths and scan_paths[0]:
        def periodic_scanner():
            while True:
                try:
                    analyzer.periodic_scan(scan_paths)
                except Exception as e:
                    logger.error(f"Error in periodic scan: {e}")
                time.sleep(scan_interval)

        scanner_thread = threading.Thread(target=periodic_scanner, daemon=True)
        scanner_thread.start()
        logger.info(f"Started periodic scanner (interval: {scan_interval}s)")

    try:
        analyzer.start()
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down...")
        if kafka_publisher is not None:
            kafka_publisher.close()
        health.stop()
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        if kafka_publisher is not None:
            kafka_publisher.close()
        health.stop()
        sys.exit(1)
