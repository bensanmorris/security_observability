# cert-analyzer Performance Tests

Throughput and latency comparison across four cert-analyzer configurations,
measuring the overhead of optional features (FIPS compliance checking,
SHA-256 certificate checksumming) relative to a vanilla baseline.

---

## Scope and limitations

These tests deliberately mock the Tetragon event stream to isolate the
cert-analysis cost. All four configurations receive events via the same mock
path, so the relative comparison between them is unaffected by gRPC or socket
overhead. Running under a real Tetragon instance would add constant overhead
to all configurations equally and would not change the relative conclusions.

For the complementary question — what is the end-to-end throughput ceiling of
the full pipeline including Tetragon's gRPC stream, proto deserialisation, and
kprobe event generation — see the three-scenario evaluation in
[extras/LOADTEST-README.md](../extras/LOADTEST-README.md).

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
| Vanilla | ~6 600 | 0.144 | 0.208 |
| FIPS only | ~4 000 | 0.243 | 0.321 |
| Checksum only | ~6 400 | 0.149 | 0.204 |
| FIPS + Checksum | ~3 700 | 0.262 | 0.335 |

The pipeline mean per-event time (~144 μs for vanilla) is higher than the
analysis-only latency (~65 μs) because `process_event()` also updates
Prometheus metric labels and runs the full event-routing logic.

### Analysis-only latency

| Configuration | mean ms | p99 ms | vs vanilla |
|---|---|---|---|
| Vanilla | 0.065 | 0.092 | baseline |
| FIPS only | 0.140 | 0.186 | +0.075 ms (+115%) |
| Checksum only | 0.071 | 0.095 | +0.006 ms (+9%) |
| FIPS + Checksum | 0.154 | 0.210 | +0.089 ms (+137%) |

**FIPS compliance checking** is the dominant cost. It calls `cert.public_key()`
on every analysed certificate to inspect algorithm, key size, and curve. This
is a second OpenSSL key-extraction pass — separate from the initial
`load_pem_x509_certificate()` — and costs roughly as much as the cert parse
itself, adding approximately **+115%** (~75 μs per cert).

**SHA-256 checksumming** re-serialises the cert to DER and hashes it. This is
cheap: approximately **+9%** (~6 μs per cert).

With both enabled, FIPS dominates: **+137%** total (~89 μs per cert).

> **Note on caching:** this test deliberately clears the `known_certs` LRU
> cache before every event (worst-case scenario — every unique cert triggers
> full re-analysis). In production, each distinct certificate path is analysed
> once; subsequent accesses are cache hits and cost a map lookup, not a full
> parse. Sustained per-event cost at production cache-hit rates is near-zero.

### Where the time goes

The ~65 μs vanilla analysis-only cost breaks down into three main buckets,
derived from profiler runs against `analyze_certificate()`:

| Cost source | Approx. μs | Code location |
|---|---|---|
| File I/O (`open` + `read` + pathlib) | ~15 μs | `cert_analyzer.py` → `parse_certificates()` |
| PEM → X.509 parse (`load_pem_x509_certificate`) | ~25 μs | `cert_analyzer.py` → `parse_certificates()` |
| Attribute extraction (subject, issuer, SANs, serial, validity) | ~25 μs | `cert_analyzer.py` → `extract_certificate_info()` |

`load_pem_x509_certificate` is a C extension call into OpenSSL's ASN.1 decoder
that builds the full certificate struct in memory. The attribute extraction
phase invokes multiple Python properties on the resulting object, each of which
makes a small round-trip back into OpenSSL.

**FIPS adds a fourth bucket:**

| Cost source | Approx. μs | Code location |
|---|---|---|
| `cert.public_key()` (OpenSSL key extraction) | ~65–75 μs | `fips_compliance_checker.py` |

The FIPS checker calls `cert.public_key()` to inspect algorithm, key size, and
(for EC keys) approved curve. Even though the certificate struct is already in
memory from the initial `load_pem_x509_certificate()` call, `public_key()`
triggers a separate `X509_get_pubkey()` → `EVP_PKEY` extraction in OpenSSL —
it does not return a cached object. This single call costs roughly as much as
the initial cert parse and is the reason FIPS checking roughly doubles the
per-cert cost.

This overhead is inherent to the current design: `cert.public_key()` is called
exactly once per certificate, but it cannot be avoided without replacing it with
lower-level ASN.1 inspection. A future optimisation could use
`cert.public_key_algorithm_oid` (cryptography ≥ 42.0.0) to determine the key
algorithm and read the key size from the SubjectPublicKeyInfo bit string
directly, avoiding the full `EVP_PKEY` object construction entirely.

**Checksum adds a fifth bucket:**

| Cost source | Approx. μs | Code location |
|---|---|---|
| `cert.public_bytes(DER)` + `sha256()` | ~6 μs | `cert_analyzer.py:1172` |

DER serialisation is fast because it works from the already-in-memory cert
struct with no further OpenSSL parsing. SHA-256 over a few hundred bytes is
negligible.

---

### Conclusions

- Single-threaded vanilla throughput is approximately **6 600 events/second**
  (cache-miss worst case, every event triggers a full cert parse and
  Prometheus update).
- **Checksum has negligible throughput impact** — only ~9% overhead at the
  analysis level and indistinguishable from vanilla at the pipeline level.
- **FIPS compliance checking is expensive**: +115% analysis overhead, reducing
  pipeline throughput from ~6 600 to ~4 000 events/second. The cost is a single
  `cert.public_key()` OpenSSL call per certificate that is required to inspect
  the key algorithm and size, and is not currently cached or avoidable within
  the cryptography library's public API.
- In practice the LRU cache absorbs most of this cost — only newly-seen cert
  paths incur the full analysis overhead.
- The cert-analyzer is an **out-of-band observer** and does not sit in the
  critical path of TLS connections. Enabling these features has no impact on
  application TLS latency.
