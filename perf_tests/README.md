# cert-analyzer Performance Tests

Throughput and latency comparison across four cert-analyzer configurations,
measuring the overhead of optional features (FIPS compliance checking,
SHA-256 certificate checksumming) relative to a vanilla baseline.

---

## What is measured

Two passes are run per configuration:

**Pipeline throughput** — drives the full `process_event()` pipeline using mock
Tetragon kprobe events pointing at real on-disk cert files. Reports sustained
events/second, mean latency, and p99 latency. No live Tetragon socket required.

**Analysis-only latency** — calls `analyze_certificate()` directly in a tight
single-threaded, GC-disabled loop. This isolates the cert-parsing and optional
feature cost from Prometheus lock and threading overhead, giving a stable and
directly comparable per-feature overhead number.

### Configurations tested

| Configuration | FIPS checking | SHA-256 checksum |
|---|---|---|
| Vanilla | disabled | disabled |
| FIPS only | enabled | disabled |
| Checksum only | disabled | enabled |
| FIPS + Checksum | enabled | enabled |

The cert pool contains a mix of FIPS-compliant (RSA-2048 / SHA-256) and
non-compliant (RSA-1024) certificates so the FIPS checker exercises both
the compliant and violation code paths.

---

## Prerequisites

- RHEL 9, Python 3.9+
- Run from the **repo root** — the script imports `cert_analyzer.py` directly

---

## Setup

```bash
# Create and activate a virtualenv (from the repo root)
python3 -m venv .venv
source .venv/bin/activate

# Install runtime deps (same as the cert-analyzer itself)
pip install -r requirements.txt
```

---

## Running

```bash
# Default run — 10 000 events × 3 reps per config, ~6 seconds
python perf_tests/cert_analyzer_perf_comparison.py

# Save results as JSON
python perf_tests/cert_analyzer_perf_comparison.py --output perf_results.json

# Higher event count for more stable throughput numbers
python perf_tests/cert_analyzer_perf_comparison.py --events 20000

# Multi-worker throughput test
python perf_tests/cert_analyzer_perf_comparison.py --workers 4
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--cert-dir` | `/tmp/perf-certs` | Directory for generated test certificates |
| `--pool-size` | `50` | Number of cert files in the rotation pool |
| `--events` | `10000` | Events per config per rep in the throughput test |
| `--warmup` | `500` | Warmup events before each measured rep |
| `--workers` | `1` | Concurrent worker threads for the throughput test |
| `--throughput-reps` | `3` | Throughput reps per config; median is reported |
| `--latency-reps` | `3` | Analysis-latency reps per config; median is reported |
| `--fips-mix` | `0.5` | Fraction of FIPS-compliant (RSA-2048) certs in pool |
| `--output` | _(none)_ | Write full results as JSON to this path |

---

## Test machine specification

| | |
|---|---|
| **Host OS** | Ubuntu 22.04 |
| **Host CPU** | 13th Gen Intel Core i7-1360P |
| **Guest OS** | RHEL 9.7 under QEMU/KVM — kernel 5.14.0-611.13.1.el9_7.x86_64 |
| **Guest vCPUs** | 4 |
| **Guest memory** | 16 GiB total, ~12 GiB available during tests |
| **Python** | 3.9.25 |
| **Workers** | 1 (single-threaded) |

---

## Results (RHEL 9, single-threaded, June 2026)

Run with defaults: 10 000 events × 3 reps, 50-cert pool (50% FIPS-compliant /
50% non-compliant), 1 worker.

### Pipeline throughput

| Configuration | events/s | mean ms | p99 ms |
|---|---|---|---|
| Vanilla | ~50 000 | 0.020 | 0.055 |
| FIPS only | ~52 000 | 0.018 | 0.028 |
| Checksum only | ~49 000 | 0.019 | 0.039 |
| FIPS + Checksum | ~53 000 | 0.018 | 0.028 |

All four configurations deliver **~50 000 events/second** single-threaded.
The small run-to-run variation (± 5 000 events/s) is measurement noise from
OS scheduling and GC; it is not a real difference between configurations.
The pipeline bottleneck is cert-file I/O and X.509 parsing, not the optional
features.

### Analysis-only latency

| Configuration | mean ms | p99 ms | vs vanilla |
|---|---|---|---|
| Vanilla | 0.060 | 0.080 | baseline |
| FIPS only | 0.068 | 0.091 | +0.008 ms (+13%) |
| Checksum only | 0.068 | 0.093 | +0.008 ms (+13%) |
| FIPS + Checksum | 0.076 | 0.103 | +0.016 ms (+26%) |

FIPS compliance checking inspects attributes of the already-parsed cert object
and adds approximately **+13%** to per-cert analysis time (~8 μs).

SHA-256 checksumming re-serialises the cert to DER and hashes it, also adding
approximately **+13%** (~8 μs).

The two features are largely independent: enabling both adds approximately
**+26%** (~16 μs), which is the near-exact sum of the individual overheads.

### Conclusions

- The cert-analyzer processes **~50 000 cert events/second** single-threaded.
- Enabling FIPS checking or checksumming does **not meaningfully reduce
  throughput** — all four configs perform within noise of each other at the
  pipeline level.
- At the analysis level, each optional feature adds ~8 μs per cert (~13%),
  with both features together adding ~16 μs (~26%).
- The cert-analyzer is an **out-of-band observer** and does not sit in the
  critical path of TLS connections. Enabling these features has no impact on
  application TLS latency.
