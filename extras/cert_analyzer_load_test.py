#!/usr/bin/env python3
"""
cert_analyzer_loadtest.py
=========================
Performance load test for the TLS Certificate Expiry Monitor.

Measures two distinct costs:
  1. Python-side analysis latency — how long analyze_certificate() takes
     per file across different formats and cert counts.
  2. Event throughput — how many process_event() calls the analyzer can
     sustain per second before falling behind, simulating a burst of
     Tetragon events.

Usage
-----
  # Install deps (same as cert-analyzer runtime)
  pip install -r requirements.txt

  # Basic run — uses /tmp/loadtest-certs, prints a summary table
  python cert_analyzer_loadtest.py

  # Custom options
  python cert_analyzer_loadtest.py \\
      --cert-dir /tmp/my-certs \\
      --events   500 \\
      --workers  4 \\
      --metrics-port 9091 \\
      --output   results.json

Prerequisites
-------------
  * cert_analyzer.py must be on the Python path (run from repo root)
  * The Tetragon protobuf stubs are NOT required — event throughput tests
    use a mock event object that mirrors the proto interface
  * pyjks optional — JKS tests are skipped if not installed

Output
------
  Console: formatted results table + pass/fail verdict
  JSON:    machine-readable results written to --output path if specified
"""

import argparse
import gc
import json
import os
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional
import statistics
import struct
import hashlib

# ── Third-party ───────────────────────────────────────────────────────────────
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    serialize_key_and_certificates,
    PKCS12Certificate,
)
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.x509.oid import NameOID

try:
    import jks as _jks
    JKS_AVAILABLE = True
except ImportError:
    JKS_AVAILABLE = False

# ── cert_analyzer import ──────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from prometheus_client import REGISTRY
    from cert_analyzer import CertificateAnalyzer
except ImportError as e:
    print(f"ERROR: could not import cert_analyzer: {e}")
    print("Run this script from the repo root.")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Thresholds — adjust to match your SLA expectations
# ─────────────────────────────────────────────────────────────────────────────
THRESHOLD_SINGLE_CERT_MS   =  50.0   # single PEM parse + analyse
THRESHOLD_BUNDLE_10_MS     = 200.0   # 10-cert PEM bundle
THRESHOLD_PKCS12_MS        = 100.0   # single .p12
THRESHOLD_JKS_MS           = 100.0   # single .jks (if available)
THRESHOLD_THROUGHPUT_EPS   = 50.0    # minimum events/second sustained
THRESHOLD_MEMORY_GROWTH_MB =  50.0   # max RSS growth during throughput test


# ─────────────────────────────────────────────────────────────────────────────
# Certificate / keystore generators
# ─────────────────────────────────────────────────────────────────────────────

def _make_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _make_cert(cn: str, days: int, key=None, is_ca: bool = False):
    if key is None:
        key = _make_key()
    if days < 0:
        nvb = datetime.utcnow() + timedelta(days=days) - timedelta(days=365)
        nva = datetime.utcnow() + timedelta(days=days)
    else:
        nvb = datetime.utcnow()
        nva = datetime.utcnow() + timedelta(days=days)

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LoadTest"),
    ])
    b = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nvb).not_valid_after(nva)
    )
    if is_ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return b.sign(key, hashes.SHA256(), backend=default_backend()), key


def write_pem_bundle(path: str, certs: list):
    with open(path, 'wb') as f:
        for cert in certs:
            f.write(cert.public_bytes(serialization.Encoding.PEM))


def write_pkcs12(path: str, cert, key, chain=None):
    extras = None
    if chain:
        extras = [PKCS12Certificate(cert=c, friendly_name=None) for c in chain]
    data = serialize_key_and_certificates(
        name=b'loadtest', key=key, cert=cert, cas=extras,
        encryption_algorithm=BestAvailableEncryption(b'changeit'),
    )
    with open(path, 'wb') as f:
        f.write(data)


def write_jks(path: str, cert, password: str = 'changeit'):
    """Write a minimal single-entry JKS truststore."""
    cert_der  = cert.public_bytes(serialization.Encoding.DER)
    alias_enc = 'loadtest'.encode('utf-16-be')
    cert_type = b'X.509'
    timestamp = int(time.time() * 1000)

    entry  = struct.pack('>I', 2)
    entry += struct.pack('>H', len(alias_enc)) + alias_enc
    entry += struct.pack('>Q', timestamp)
    entry += struct.pack('>H', len(cert_type)) + cert_type
    entry += struct.pack('>I', len(cert_der))  + cert_der

    body     = struct.pack('>III', 0xFEEDFEED, 2, 1) + entry
    pw_bytes = b''.join(struct.pack('>H', ord(c)) for c in password)
    digest   = hashlib.sha1(pw_bytes + b'Mighty Aphrodite' + body).digest()

    with open(path, 'wb') as f:
        f.write(body + digest)


# ─────────────────────────────────────────────────────────────────────────────
# Mock Tetragon event — mirrors the proto interface used by process_event()
# so we can drive the full processing pipeline without a live Tetragon socket
# ─────────────────────────────────────────────────────────────────────────────

class _MockArg:
    def __init__(self, path):
        self.string_arg = path
    def HasField(self, name):
        return name == 'string_arg'

class _MockProcess:
    def __init__(self):
        # Use a /host-prefixed path so extract_cert_path_from_event does not
        # prepend /host again (it only prepends when path lacks the prefix)
        self.binary    = '/usr/bin/java'
        self.pid       = 12345
        self.arguments = ''

    def HasField(self, name):
        # Return False for 'pid' and 'pod' so the analyzer uses the plain
        # integer pid attribute and skips pod enrichment — both of which
        # require proto-specific wrappers we don't need here
        return False

class _MockKprobe:
    def __init__(self, cert_path):
        self.process = _MockProcess()
        self.args    = [_MockArg(cert_path)]

class _MockEvent:
    """Mimics a tetragon GetEventsResponse for a kprobe event."""
    def __init__(self, cert_path):
        # Prepend /host here so the path survives extract_cert_path_from_event
        # unchanged — the analyzer prepends /host to paths that lack it, but
        # the actual file on disk is at the original path.  We store both so
        # the worker can clear known_certs using the key the analyzer will use.
        self._host_path = '/host' + cert_path if not cert_path.startswith('/host') else cert_path
        self._disk_path = cert_path
        self._kprobe    = _MockKprobe(self._host_path)

    def HasField(self, name):
        return name == 'process_kprobe'

    @property
    def process_kprobe(self):
        return self._kprobe


# ─────────────────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class LatencyResult:
    name:        str
    samples:     int
    mean_ms:     float
    median_ms:   float
    p95_ms:      float
    p99_ms:      float
    min_ms:      float
    max_ms:      float
    threshold_ms: float
    passed:      bool


@dataclass
class ThroughputResult:
    events:           int
    duration_s:       float
    events_per_sec:   float
    mean_latency_ms:  float
    p99_latency_ms:   float
    memory_growth_mb: float
    threshold_eps:    float
    passed:           bool


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _fresh_analyzer():
    """Return a CertificateAnalyzer with a clean Prometheus registry."""
    for collector in list(REGISTRY._collector_to_names.keys()):
        try:
            REGISTRY.unregister(collector)
        except Exception:
            pass
    return CertificateAnalyzer(
        tetragon_address="unix:///dev/null",
        alert_threshold_days=30,
    )


def _measure(fn, samples: int) -> List[float]:
    """Run fn() `samples` times, return elapsed times in milliseconds."""
    times = []
    for _ in range(samples):
        gc.disable()
        t0 = time.perf_counter()
        fn()
        t1 = time.perf_counter()
        gc.enable()
        times.append((t1 - t0) * 1000)
    return times


def _rss_mb() -> float:
    try:
        with open(f'/proc/{os.getpid()}/status') as f:
            for line in f:
                if line.startswith('VmRSS:'):
                    return int(line.split()[1]) / 1024
    except Exception:
        pass
    return 0.0


def _latency_result(name, times, threshold_ms) -> LatencyResult:
    s = sorted(times)
    n = len(s)
    return LatencyResult(
        name         = name,
        samples      = n,
        mean_ms      = statistics.mean(s),
        median_ms    = statistics.median(s),
        p95_ms       = s[int(n * 0.95)],
        p99_ms       = s[int(n * 0.99)],
        min_ms       = s[0],
        max_ms       = s[-1],
        threshold_ms = threshold_ms,
        passed       = statistics.mean(s) < threshold_ms,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test scenarios
# ─────────────────────────────────────────────────────────────────────────────

def test_single_pem(cert_dir: str, samples: int) -> LatencyResult:
    cert, _ = _make_cert("single-pem.loadtest", 365)
    path = os.path.join(cert_dir, "single.pem")
    write_pem_bundle(path, [cert])
    a = _fresh_analyzer()
    times = _measure(lambda: a.analyze_certificate(path, "loadtest", 1), samples)
    return _latency_result("Single PEM", times, THRESHOLD_SINGLE_CERT_MS)


def test_pem_bundle(cert_dir: str, samples: int, bundle_size: int = 10) -> LatencyResult:
    certs = [_make_cert(f"bundle-{i}.loadtest", 365 - i * 10)[0] for i in range(bundle_size)]
    path = os.path.join(cert_dir, f"bundle-{bundle_size}.pem")
    write_pem_bundle(path, certs)
    a = _fresh_analyzer()
    times = _measure(lambda: a.analyze_certificate(path, "loadtest", 1), samples)
    return _latency_result(f"PEM bundle ({bundle_size} certs)", times, THRESHOLD_BUNDLE_10_MS)


def test_pkcs12(cert_dir: str, samples: int) -> LatencyResult:
    cert, key = _make_cert("pkcs12.loadtest", 365)
    path = os.path.join(cert_dir, "keystore.p12")
    write_pkcs12(path, cert, key)
    a = _fresh_analyzer()
    times = _measure(lambda: a.analyze_certificate(path, "loadtest", 1), samples)
    return _latency_result("PKCS12 (.p12)", times, THRESHOLD_PKCS12_MS)


def test_pkcs12_with_chain(cert_dir: str, samples: int) -> LatencyResult:
    root, _      = _make_cert("root-ca.loadtest",   3650, is_ca=True)
    inter, _     = _make_cert("inter-ca.loadtest",  1825, is_ca=True)
    leaf, leaf_k = _make_cert("leaf.loadtest",        365)
    path = os.path.join(cert_dir, "chain.p12")
    write_pkcs12(path, leaf, leaf_k, chain=[inter, root])
    a = _fresh_analyzer()
    times = _measure(lambda: a.analyze_certificate(path, "loadtest", 1), samples)
    return _latency_result("PKCS12 with chain (3 certs)", times, THRESHOLD_PKCS12_MS * 2)


def test_jks(cert_dir: str, samples: int) -> Optional[LatencyResult]:
    if not JKS_AVAILABLE:
        return None
    cert, _ = _make_cert("jks.loadtest", 365)
    path = os.path.join(cert_dir, "truststore.jks")
    write_jks(path, cert)
    a = _fresh_analyzer()
    times = _measure(lambda: a.analyze_certificate(path, "loadtest", 1), samples)
    return _latency_result("JKS truststore", times, THRESHOLD_JKS_MS)


def test_expired_cert(cert_dir: str, samples: int) -> LatencyResult:
    """Expired certs should parse just as fast — verify no slow path."""
    cert, _ = _make_cert("expired.loadtest", -30)
    path = os.path.join(cert_dir, "expired.pem")
    write_pem_bundle(path, [cert])
    a = _fresh_analyzer()
    times = _measure(lambda: a.analyze_certificate(path, "loadtest", 1), samples)
    return _latency_result("Expired PEM (no slow path)", times, THRESHOLD_SINGLE_CERT_MS)


def test_throughput(cert_dir: str, num_events: int, num_workers: int) -> ThroughputResult:
    """
    Drive process_event() at full speed across `num_workers` threads and
    measure sustained events/second and memory growth.

    Uses mock events pointing at real cert files so the full analysis
    pipeline executes — parse, analyse, update metrics — on every call.

    The analyzer prepends /host to all paths before reading them, so we
    create a /host symlink pointing at cert_dir so the files are resolvable.
    If the symlink cannot be created (e.g. permission denied) the test falls
    back to calling analyze_certificate() directly and notes the limitation.
    """
    # Create /host/<cert_dir> so the analyzer can open files at /host/... paths
    host_cert_dir   = '/host' + cert_dir
    created_symlink = False
    use_direct      = False

    try:
        os.makedirs(os.path.dirname(host_cert_dir) or '/', exist_ok=True)
        if not os.path.exists(host_cert_dir):
            os.symlink(cert_dir, host_cert_dir)
            created_symlink = True
    except (OSError, PermissionError) as e:
        print(f"\n  WARNING: could not create {host_cert_dir}: {e}")
        print("  Falling back to direct analyze_certificate() calls.")
        use_direct = True

    # Generate pool of cert files
    pool_size = min(num_events, 50)
    disk_paths = []
    mock_events = []
    for i in range(pool_size):
        cert, _ = _make_cert(f"throughput-{i}.loadtest", 365)
        path = os.path.join(cert_dir, f"throughput-{i}.pem")
        write_pem_bundle(path, [cert])
        disk_paths.append(path)
        mock_events.append(_MockEvent(path))

    a = _fresh_analyzer()
    latencies = []
    lock = threading.Lock()
    counter = [0]

    rss_before = _rss_mb()

    def worker():
        while True:
            with lock:
                if counter[0] >= num_events:
                    return
                idx = counter[0] % pool_size
                counter[0] += 1

            if use_direct:
                # Direct path: bypass process_event and call analyze_certificate
                t0 = time.perf_counter()
                try:
                    a.analyze_certificate(disk_paths[idx], "/usr/bin/java", 1)
                except Exception:
                    pass
                elapsed_ms = (time.perf_counter() - t0) * 1000
            else:
                # Full pipeline: clear this cert from known_certs so the
                # analyzer doesn't short-circuit on the dedup check
                event     = mock_events[idx]
                host_path = event._host_path
                with lock:
                    keys = [k for k in a.known_certs if k.startswith(host_path + ':')]
                    for k in keys:
                        del a.known_certs[k]

                t0 = time.perf_counter()
                try:
                    a.process_event(event)
                except Exception:
                    pass
                elapsed_ms = (time.perf_counter() - t0) * 1000

            with lock:
                latencies.append(elapsed_ms)

    t_start = time.perf_counter()
    threads = [threading.Thread(target=worker) for _ in range(num_workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    duration = time.perf_counter() - t_start

    if created_symlink and os.path.islink(host_cert_dir):
        os.unlink(host_cert_dir)

    rss_after    = _rss_mb()
    memory_delta = max(0.0, rss_after - rss_before)

    s   = sorted(latencies)
    n   = len(s)
    eps = n / duration if duration > 0 else 0

    return ThroughputResult(
        events           = n,
        duration_s       = round(duration, 3),
        events_per_sec   = round(eps, 1),
        mean_latency_ms  = round(statistics.mean(s), 2) if s else 0.0,
        p99_latency_ms   = round(s[int(n * 0.99)], 2)  if s else 0.0,
        memory_growth_mb = round(memory_delta, 1),
        threshold_eps    = THRESHOLD_THROUGHPUT_EPS,
        passed           = eps >= THRESHOLD_THROUGHPUT_EPS and memory_delta < THRESHOLD_MEMORY_GROWTH_MB,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

def _bar(value, threshold, width=20) -> str:
    ratio = min(value / threshold, 2.0)
    filled = int(ratio * width / 2)
    bar = '█' * filled + '░' * (width - filled)
    return f"[{bar}]"


def print_latency_table(results: List[LatencyResult]):
    print("\n── Analysis Latency ─────────────────────────────────────────────────")
    fmt = "  {:<32} {:>8} {:>8} {:>8} {:>8} {:>10}  {}"
    print(fmt.format("Scenario", "mean", "p95", "p99", "max", "threshold", ""))
    print("  " + "─" * 80)
    for r in results:
        status = "✅ PASS" if r.passed else "❌ FAIL"
        print(fmt.format(
            r.name,
            f"{r.mean_ms:.1f}ms",
            f"{r.p95_ms:.1f}ms",
            f"{r.p99_ms:.1f}ms",
            f"{r.max_ms:.1f}ms",
            f"{r.threshold_ms:.0f}ms",
            status,
        ))


def print_throughput_table(r: ThroughputResult):
    status = "✅ PASS" if r.passed else "❌ FAIL"
    print("\n── Throughput ───────────────────────────────────────────────────────")
    print(f"  Events processed : {r.events}")
    print(f"  Duration         : {r.duration_s:.2f}s")
    print(f"  Throughput       : {r.events_per_sec:.1f} events/sec  "
          f"(threshold: {r.threshold_eps:.0f})  {status}")
    print(f"  Mean latency     : {r.mean_latency_ms:.2f}ms")
    print(f"  p99 latency      : {r.p99_latency_ms:.2f}ms")
    print(f"  Memory growth    : {r.memory_growth_mb:.1f}MB  "
          f"(threshold: {THRESHOLD_MEMORY_GROWTH_MB:.0f}MB)")


def print_summary(latency_results, throughput_result):
    all_passed = all(r.passed for r in latency_results) and throughput_result.passed
    print("\n── Summary ──────────────────────────────────────────────────────────")
    if all_passed:
        print("  ✅ All tests passed — analyzer meets performance thresholds")
    else:
        failed = [r.name for r in latency_results if not r.passed]
        if not throughput_result.passed:
            failed.append("Throughput")
        print(f"  ❌ {len(failed)} test(s) failed: {', '.join(failed)}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="cert-analyzer performance load test"
    )
    parser.add_argument("--cert-dir",      default="/tmp/loadtest-certs",
                        help="Directory for generated test certificates")
    parser.add_argument("--samples",       type=int, default=100,
                        help="Latency measurement repetitions per scenario (default: 100)")
    parser.add_argument("--events",        type=int, default=500,
                        help="Total events for throughput test (default: 500)")
    parser.add_argument("--workers",       type=int, default=1,
                        help="Concurrent threads for throughput test (default: 1)")
    parser.add_argument("--output",        default=None,
                        help="Write JSON results to this file")
    parser.add_argument("--bundle-size",   type=int, default=10,
                        help="Number of certs in PEM bundle test (default: 10)")
    args = parser.parse_args()

    os.makedirs(args.cert_dir, exist_ok=True)

    print(f"cert-analyzer load test")
    print(f"  cert dir   : {args.cert_dir}")
    print(f"  samples    : {args.samples} per latency scenario")
    print(f"  events     : {args.events} (throughput test)")
    print(f"  workers    : {args.workers}")
    print(f"  JKS support: {'yes' if JKS_AVAILABLE else 'no (pyjks not installed)'}")

    # ── Latency tests ─────────────────────────────────────────────────────────
    print("\nRunning latency tests...", flush=True)
    latency_results = []

    scenarios = [
        ("Single PEM",              lambda: test_single_pem(args.cert_dir, args.samples)),
        (f"PEM bundle",             lambda: test_pem_bundle(args.cert_dir, args.samples, args.bundle_size)),
        ("PKCS12",                  lambda: test_pkcs12(args.cert_dir, args.samples)),
        ("PKCS12 with chain",       lambda: test_pkcs12_with_chain(args.cert_dir, args.samples)),
        ("Expired cert",            lambda: test_expired_cert(args.cert_dir, args.samples)),
    ]
    if JKS_AVAILABLE:
        scenarios.append(("JKS", lambda: test_jks(args.cert_dir, args.samples)))

    for name, fn in scenarios:
        print(f"  {name}...", end=" ", flush=True)
        result = fn()
        if result is not None:
            latency_results.append(result)
            status = "✅" if result.passed else "❌"
            print(f"{status} {result.mean_ms:.1f}ms mean")
        else:
            print("skipped")

    # ── Throughput test ───────────────────────────────────────────────────────
    print(f"\nRunning throughput test ({args.events} events, {args.workers} worker(s))...",
          flush=True)
    throughput_result = test_throughput(args.cert_dir, args.events, args.workers)
    status = "✅" if throughput_result.passed else "❌"
    print(f"  {status} {throughput_result.events_per_sec:.1f} events/sec")

    # ── Output ────────────────────────────────────────────────────────────────
    print_latency_table(latency_results)
    print_throughput_table(throughput_result)
    print_summary(latency_results, throughput_result)

    if args.output:
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "config": vars(args),
            "latency": [asdict(r) for r in latency_results],
            "throughput": asdict(throughput_result),
        }
        with open(args.output, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"  Results written to {args.output}")

    all_passed = all(r.passed for r in latency_results) and throughput_result.passed
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
