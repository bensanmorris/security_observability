#!/usr/bin/env python3
"""
cert_analyzer_perf_comparison.py
=================================
Throughput comparison across four cert-analyzer configurations:

  1. Vanilla       — full analysis, FIPS disabled, checksum disabled
  2. FIPS only     — full analysis, FIPS enabled,  checksum disabled
  3. Checksum only — full analysis, FIPS disabled, checksum enabled
  4. FIPS+Checksum — full analysis, FIPS and checksum enabled

Two measurement passes per configuration
-----------------------------------------
  Throughput  — process_event() pipeline, multi-worker, steady-state events/sec.

  Analysis latency — analyze_certificate() in a tight single-thread GC-disabled loop.
                     This isolates the cert-analysis cost from Prometheus/lock overhead
                     and gives stable, comparable per-feature overhead numbers.

Usage
-----
  python extras/cert_analyzer_perf_comparison.py
  python extras/cert_analyzer_perf_comparison.py \\
      --events 10000 --workers 4 --output results.json

Prerequisites
-------------
  * cert_analyzer.py importable (run from repo root, or add repo root to PYTHONPATH)
  * No live Tetragon socket required — mock events drive the full pipeline
"""

import argparse
import gc
import json
import os
import sys
import threading
import time
import warnings
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Tuple
import statistics

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).parent.parent))
try:
    from prometheus_client import REGISTRY
    from cert_analyzer import CertificateAnalyzer
except ImportError as e:
    print(f"ERROR: could not import cert_analyzer: {e}", file=sys.stderr)
    print("Run this script from the repo root or add it to PYTHONPATH.", file=sys.stderr)
    sys.exit(1)

import logging as _logging
_logging.getLogger("cert_analyzer").setLevel(_logging.ERROR)


# ── Configuration table ───────────────────────────────────────────────────────

CONFIGURATIONS = [
    {"name": "Vanilla",       "fips": False, "checksum": False},
    {"name": "FIPS only",     "fips": True,  "checksum": False},
    {"name": "Checksum only", "fips": False, "checksum": True},
    {"name": "FIPS + Checksum", "fips": True, "checksum": True},
]


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class ConfigResult:
    name: str
    fips_enabled: bool
    checksum_enabled: bool
    # Throughput (process_event pipeline)
    events_per_sec: float
    mean_pipeline_ms: float
    p99_pipeline_ms: float
    # Analysis latency (analyze_certificate only)
    mean_analysis_ms: float
    p99_analysis_ms: float
    # Overhead vs vanilla (set in _compute_overheads)
    overhead_vs_vanilla_ms: Optional[float] = None


# ── Certificate generators ────────────────────────────────────────────────────

def _make_cert(cn: str, key_size: int, days: int = 365) -> x509.Certificate:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    nvb = datetime.utcnow()
    nva = datetime.utcnow() + timedelta(days=days)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nvb).not_valid_after(nva)
        .sign(key, hashes.SHA256(), default_backend())
    )


def build_cert_pool(
    cert_dir: str, pool_size: int, fips_mix: float
) -> List[Tuple[str, "_MockEvent"]]:
    """
    Write pool_size PEM files; return (disk_path, mock_event) pairs.
    fips_mix is the fraction of RSA-2048 (FIPS-compliant) certs; the rest are
    RSA-1024 (non-compliant — key size below FIPS 140-2/140-3 minimum).
    """
    pool = []
    n_compliant = round(pool_size * fips_mix)
    for i in range(pool_size):
        key_size = 2048 if i < n_compliant else 1024
        label = "fips" if key_size == 2048 else "nonfips"
        cert = _make_cert(f"perf-{label}-{i}", key_size=key_size)
        path = os.path.join(cert_dir, f"perf-{i}.pem")
        with open(path, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        pool.append((path, _MockEvent(path)))
    return pool


# ── Mock Tetragon event ───────────────────────────────────────────────────────

class _MockArg:
    def __init__(self, path: str) -> None:
        self.string_arg = path

    def HasField(self, name: str) -> bool:
        return name == "string_arg"


class _MockProcess:
    binary = "/usr/bin/java"
    pid = 12345
    arguments = ""

    def HasField(self, _: str) -> bool:
        return False


class _MockKprobe:
    def __init__(self, path: str) -> None:
        self.process = _MockProcess()
        self.args = [_MockArg(path)]


class _MockEvent:
    node_name = ""

    def __init__(self, path: str) -> None:
        self._host_path = path
        self._disk_path = path
        self._kprobe = _MockKprobe(self._host_path)

    def HasField(self, name: str) -> bool:
        return name == "process_kprobe"

    @property
    def process_kprobe(self) -> _MockKprobe:
        return self._kprobe


# ── Analyzer factory ──────────────────────────────────────────────────────────

def _fresh_analyzer(fips_enabled: bool, checksum_enabled: bool) -> CertificateAnalyzer:
    for collector in list(REGISTRY._collector_to_names.keys()):
        try:
            REGISTRY.unregister(collector)
        except Exception:
            pass
    return CertificateAnalyzer(
        tetragon_address="unix:///dev/null",
        alert_threshold_days=30,
        fips_compliance_enabled=fips_enabled,
        checksum_enabled=checksum_enabled,
    )


# ── Throughput measurement (process_event pipeline) ───────────────────────────

def _run_pipeline_events(
    analyzer: CertificateAnalyzer,
    pool: List[Tuple[str, _MockEvent]],
    num_events: int,
    num_workers: int,
) -> Tuple[List[float], float]:
    """Drive process_event() for num_events; return (latencies_ms, wall_s)."""
    pool_size = len(pool)
    counter = [0]
    latencies: List[float] = []
    lock = threading.Lock()

    gc.disable()
    t_start = time.perf_counter()

    def worker() -> None:
        while True:
            with lock:
                if counter[0] >= num_events:
                    return
                idx = counter[0] % pool_size
                counter[0] += 1
            _, mock_event = pool[idx]
            host_path = mock_event._host_path
            with lock:
                for k in [k for k in analyzer.known_certs if k.startswith(host_path + ":")]:
                    del analyzer.known_certs[k]
            t0 = time.perf_counter()
            try:
                analyzer.process_event(mock_event)
            except Exception:
                pass
            elapsed_ms = (time.perf_counter() - t0) * 1_000
            with lock:
                latencies.append(elapsed_ms)

    threads = [threading.Thread(target=worker) for _ in range(num_workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    duration = time.perf_counter() - t_start

    gc.enable()
    gc.collect()
    return latencies, duration


def measure_throughput(
    cfg: dict,
    pool: List[Tuple[str, _MockEvent]],
    num_events: int,
    num_workers: int,
    warmup: int,
    reps: int,
) -> Tuple[float, float, float]:
    """Return median (events_per_sec, mean_ms, p99_ms) across reps."""
    all_eps, all_mean, all_p99 = [], [], []
    for _ in range(reps):
        analyzer = _fresh_analyzer(cfg["fips"], cfg["checksum"])
        if warmup > 0:
            _run_pipeline_events(analyzer, pool, warmup, num_workers)
            analyzer.known_certs.clear()
        lats, dur = _run_pipeline_events(analyzer, pool, num_events, num_workers)
        s = sorted(lats)
        n = len(s)
        all_eps.append(n / dur if dur > 0 else 0.0)
        all_mean.append(statistics.mean(s) if s else 0.0)
        all_p99.append(s[int(n * 0.99)] if n > 1 else 0.0)

    return (statistics.median(all_eps), statistics.median(all_mean), statistics.median(all_p99))


# ── Analysis latency measurement (analyze_certificate only) ───────────────────

def measure_analysis_latency(
    cfg: dict,
    pool: List[Tuple[str, _MockEvent]],
    reps: int,
) -> Tuple[float, float]:
    """
    Time analyze_certificate() in a tight GC-disabled loop.

    This isolates cert-parsing + FIPS/checksum cost from Prometheus lock,
    threading, and mock-event overhead, giving stable per-feature overhead numbers.
    Returns median (mean_ms, p99_ms) across reps.
    """
    fips = cfg["fips"]
    checksum = cfg["checksum"]
    disk_paths = [p for p, _ in pool]
    pool_size = len(disk_paths)

    all_mean, all_p99 = [], []

    for _ in range(reps):
        analyzer = _fresh_analyzer(fips, checksum)
        # Warmup: fill caches, stabilise JIT paths
        for i in range(min(200, pool_size * 4)):
            analyzer.known_certs.clear()
            analyzer.analyze_certificate(disk_paths[i % pool_size], "perf-test", 1)

        latencies: List[float] = []
        gc.disable()
        for i in range(2000):
            analyzer.known_certs.clear()
            t0 = time.perf_counter()
            analyzer.analyze_certificate(disk_paths[i % pool_size], "perf-test", 1)
            latencies.append((time.perf_counter() - t0) * 1_000)
        gc.enable()
        gc.collect()

        s = sorted(latencies)
        n = len(s)
        all_mean.append(statistics.mean(s))
        all_p99.append(s[int(n * 0.99)])

    return (statistics.median(all_mean), statistics.median(all_p99))


# ── Overhead computation ──────────────────────────────────────────────────────

def _compute_overheads(results: List[ConfigResult]) -> None:
    vanilla_r = next((r for r in results if r.name == "Vanilla"), None)
    if vanilla_r is None:
        return
    for r in results:
        if r is vanilla_r:
            r.overhead_vs_vanilla_ms = 0.0
        else:
            r.overhead_vs_vanilla_ms = round(r.mean_analysis_ms - vanilla_r.mean_analysis_ms, 4)


# ── Reporting ─────────────────────────────────────────────────────────────────

def print_results(results: List[ConfigResult], fips_mix: float, num_workers: int) -> None:
    compliant_pct = int(fips_mix * 100)
    nonfips_pct   = 100 - compliant_pct
    workers_note  = f", {num_workers} workers" if num_workers > 1 else ""

    vanilla_r = next((r for r in results if r.name == "Vanilla"), None)

    print()
    print(f"── Pipeline throughput "
          f"(cert pool: {compliant_pct}% FIPS-compliant / {nonfips_pct}% non-compliant"
          + workers_note + ") ──")
    print()
    hdr = (f"  {'Configuration':<22}"
           f"{'events/s':>11}"
           f"{'mean ms':>11}"
           f"{'p99 ms':>11}")
    print(hdr)
    print("  " + "─" * 58)
    for r in results:
        print(f"  {r.name:<22}{r.events_per_sec:>11.1f}{r.mean_pipeline_ms:>11.4f}"
              f"{r.p99_pipeline_ms:>11.4f}")

    print()
    print("── Analysis-only latency (analyze_certificate, GC-disabled, 2000-event tight loop) ──")
    print()
    print(f"  {'Configuration':<22}{'mean ms':>11}{'p99 ms':>11}  vs vanilla")
    print("  " + "─" * 70)
    for r in results:
        if r.overhead_vs_vanilla_ms == 0.0:
            vs_vanilla = "  (baseline)"
        else:
            pct = (r.overhead_vs_vanilla_ms / vanilla_r.mean_analysis_ms * 100
                   if vanilla_r and vanilla_r.mean_analysis_ms > 0 else 0.0)
            vs_vanilla = f"  {r.overhead_vs_vanilla_ms:+.4f} ms  ({pct:+.1f}%)"
        print(f"  {r.name:<22}{r.mean_analysis_ms:>11.4f}{r.p99_analysis_ms:>11.4f}{vs_vanilla}")

    print()
    print("  Note: 'vs vanilla' = analysis-only marginal cost of each optional feature.")
    print("        Analysis latency excludes Prometheus/lock overhead for a stable comparison.")
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="cert-analyzer throughput comparison across five configurations",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--cert-dir",     default="/tmp/perf-certs",
                        help="Directory for generated test certificates")
    parser.add_argument("--pool-size",    type=int, default=50,
                        help="Cert files in the rotation pool")
    parser.add_argument("--events",       type=int, default=10000,
                        help="Events per config per rep in the throughput test")
    parser.add_argument("--warmup",       type=int, default=500,
                        help="Warmup events before each throughput measurement rep")
    parser.add_argument("--workers",      type=int, default=1,
                        help="Concurrent worker threads for the throughput test")
    parser.add_argument("--throughput-reps", type=int, default=3,
                        help="Throughput measurement repetitions per config; median reported")
    parser.add_argument("--latency-reps", type=int, default=3,
                        help="Analysis-latency measurement repetitions; median reported")
    parser.add_argument("--fips-mix",     type=float, default=0.5,
                        help="Fraction of FIPS-compliant (RSA-2048) certs in pool")
    parser.add_argument("--output",       default=None,
                        help="Write JSON results to this path")
    args = parser.parse_args()

    os.makedirs(args.cert_dir, exist_ok=True)

    print("cert-analyzer performance comparison")
    print(f"  cert dir   : {args.cert_dir}")
    print(f"  pool size  : {args.pool_size} files "
          f"({int(args.fips_mix*100)}% FIPS-compliant / "
          f"{int((1-args.fips_mix)*100)}% non-compliant)")
    print(f"  throughput : {args.events} events per rep × {args.throughput_reps} reps "
          f"(+ {args.warmup} warmup), {args.workers} worker(s)")
    print(f"  latency    : 2000 events per rep × {args.latency_reps} reps (tight loop)")
    print()

    print("Generating cert pool...", end=" ", flush=True)
    pool = build_cert_pool(args.cert_dir, args.pool_size, args.fips_mix)
    print(f"{len(pool)} files written.")

    # Global warmup — exercise all code paths so CPython specialises them before measuring
    print("Running global warmup...", end=" ", flush=True)
    for cfg in CONFIGURATIONS:
        a = _fresh_analyzer(cfg["fips"], cfg["checksum"])
        for i in range(args.warmup):
            a.known_certs.clear()
            a.analyze_certificate(pool[i % len(pool)][0], "warmup", 1)
    print("done.")
    print()

    results: List[ConfigResult] = []
    print("Measuring throughput (process_event pipeline)...")
    for cfg in CONFIGURATIONS:
        print(f"  {cfg['name']:<22}", end=" ", flush=True)
        eps, mean_ms, p99_ms = measure_throughput(
            cfg, pool, args.events, args.workers, args.warmup, args.throughput_reps
        )
        print(f"{eps:>10.1f} events/s")
        results.append(ConfigResult(
            name=cfg["name"],
            fips_enabled=cfg["fips"],
            checksum_enabled=cfg["checksum"],
            events_per_sec=round(eps, 1),
            mean_pipeline_ms=round(mean_ms, 4),
            p99_pipeline_ms=round(p99_ms, 4),
            mean_analysis_ms=0.0,
            p99_analysis_ms=0.0,
        ))

    print()
    print("Measuring analysis latency (analyze_certificate tight loop)...")
    for r, cfg in zip(results, CONFIGURATIONS):
        print(f"  {cfg['name']:<22}", end=" ", flush=True)
        mean_ms, p99_ms = measure_analysis_latency(cfg, pool, args.latency_reps)
        r.mean_analysis_ms = round(mean_ms, 4)
        r.p99_analysis_ms  = round(p99_ms, 4)
        print(f"mean {mean_ms:.4f} ms")

    _compute_overheads(results)
    print_results(results, args.fips_mix, args.workers)

    if args.output:
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "parameters": vars(args),
            "results": [asdict(r) for r in results],
        }
        with open(args.output, "w") as fh:
            json.dump(data, fh, indent=2)
        print(f"Results written to {args.output}")


if __name__ == "__main__":
    main()
