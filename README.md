# CertSight - Realtime certificate monitoring via eBPF

![Tests](https://github.com/bensanmorris/security_observability/actions/workflows/test.yml/badge.svg)
![CI Pipeline](https://github.com/bensanmorris/security_observability/actions/workflows/ci.yml/badge.svg)

CertSight provides real-time runtime certificate observability for Linux via eBPF — without private keys, CA impersonation, or application changes.

---

## The problem

Certificate expiry causes outages that are entirely preventable. At scale with hundreds of machines and thousands of certificates tracking what's actually running in your estate is hard, especially when certificates are loaded dynamically, passed in memory between TLS stack components, or processed by runtimes that never call system crypto libraries.

## How CertSight differs from existing approaches

| Approach | What it sees | What it misses |
|---|---|---|
| Network scanner | Certs on open ports | In-memory certs, internal services, file-only loads |
| Binary scanner | Vulnerable components in artefacts at build time | Runtime execution paths, dynamically loaded certs |
| Scheduled filesystem scan | File-backed certs | In-memory certs, blind spots between scans |
| **CertSight** | Every cert access at runtime with process and k8s context | Statically linked crypto that never calls system libs |

An application is not a single binary. It is a tree of executables and shared libraries (and kernel activity) where each node may have its own dependencies. A binary scanner inventories each node in isolation. An exploit may target a specific branch of that tree that the scanner considers clean. CertSight observes what is actually executing and performing certificate operations at runtime, irrespective of where in the dependency tree that activity originates.

## What CertSight detects

- Every certificate file access system-wide via eBPF fd_install kprobe — PEM, DER, JKS, PKCS12
- In-memory certificates post-handshake via OpenSSL and NSS uprobes — no private keys required
- Java certificate operations in both FIPS and non-FIPS environments via the Java agent
- Which process accessed which certificate, when, and from which Kubernetes pod

Utilises eBPF to hook kprobes and uprobes for safe and low overhead detection of certificate accesses in realtime. Parses and surfaces certificate, process and k8s data (where applicable) as both Prometheus metrics and Kafka topics.

Supports PEM (`.pem`, `.crt`, `.cert`, `.cer`), DER, Java KeyStore (`.jks`, `.keystore`, `.truststore`), and PKCS12 (`.p12`, `.pfx`).

---

## Prerequisites

- RHEL 8 or RHEL 9 (x86_64)
- [Tetragon](https://tetragon.io) installed and running

---

## Installation

Download the RPMs from the [latest release](../../releases/latest).

**Agent only:**
```bash
sudo dnf install ./cert-analyzer-<version>.el9.x86_64.rpm   # RHEL 9
sudo dnf install ./cert-analyzer-<version>.el8.x86_64.rpm   # RHEL 8
```

**Agent + Tetragon policies** (automatically loads the `certificate-file-access` kprobe policy on Tetragon start):
```bash
sudo dnf install ./cert-analyzer-<version>.el9.x86_64.rpm ./cert-analyzer-policies-<version>.el9.noarch.rpm   # RHEL 9
sudo dnf install ./cert-analyzer-<version>.el8.x86_64.rpm ./cert-analyzer-policies-<version>.el8.noarch.rpm   # RHEL 8
```

The installer will fail with a clear error if Tetragon is not found.

---

## Post-install

The RPM installs a systemd drop-in that grants cert-analyzer access to the Tetragon socket. Restart Tetragon to apply it:

```bash
sudo systemctl restart tetragon
```

Edit the config file, then start the service:

```bash
sudo vim /etc/cert-analyzer/cert-analyzer.conf
sudo systemctl enable --now cert-analyzer
```

---

## Configuration

`/etc/cert-analyzer/cert-analyzer.conf` — preserved across upgrades.

**[tetragon]**

| Setting | Default | Description |
|---|---|---|
| `addr` | `unix:///run/tetragon/tetragon.sock` | Tetragon gRPC address |
| `version_check_interval` | `300` | Seconds between Tetragon version checks |

**[metrics]**

| Setting | Default | Description |
|---|---|---|
| `port` | `9090` | Prometheus metrics port |

**[health]**

| Setting | Default | Description |
|---|---|---|
| `port` | `8086` | Liveness (`/healthz`) and readiness (`/readyz`) probe port |
| `readiness_grace_period_seconds` | `60` | Seconds after startup before readiness checking begins |
| `readiness_staleness_seconds` | `300` | Max age of last event before pod is marked not-ready |

**[alerting]**

| Setting | Default | Description |
|---|---|---|
| `threshold_days` | `30` | Days before expiry at which to emit warning-level log output |

**[scanning]**

| Setting | Default | Description |
|---|---|---|
| `paths` | `/etc/ssl,/etc/pki` | Comma-separated directories for periodic certificate scanning |
| `interval_seconds` | `3600` | Seconds between periodic scans |

**[logging]**

| Setting | Default | Description |
|---|---|---|
| `level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |

**[cache]**

| Setting | Default | Description |
|---|---|---|
| `max_size` | `10000` | LRU cache size for known certs, processed paths, and failed passwords (minimum 10,000) |

**[certificates]**

| Setting | Default | Description |
|---|---|---|
| `checksum_enabled` | `false` | Compute SHA-256 fingerprints per certificate |
| `filter_self_events` | `true` | Ignore certificate accesses made by the analyzer itself |
| `host_prefix` | _(empty)_ | Path prefix prepended to certificate paths from Tetragon events — leave empty for bare metal, set to `/host` for Kubernetes |

**[passwords]**

| Setting | Default | Description |
|---|---|---|
| `jks_password` | _(unset)_ | Password tried when opening encrypted JKS keystores |
| `pkcs12_password` | _(unset)_ | Password tried when opening encrypted PKCS12 keystores |

**[kafka]**

| Setting | Default | Description |
|---|---|---|
| `enabled` | `false` | Publish certificate discovery events to Kafka |
| `bootstrap_servers` | `localhost:9092` | Comma-separated broker addresses |
| `topic` | `cert-analyzer-events` | Topic to publish events to |
| `security_protocol` | `PLAINTEXT` | `PLAINTEXT`, `SSL`, `SASL_PLAINTEXT`, `SASL_SSL` |
| `sasl_mechanism` | _(unset)_ | SASL mechanism — required for `SASL_*` protocols |
| `sasl_username` | _(unset)_ | SASL username |
| `sasl_password` | _(unset)_ | SASL password |

---

## Verify

```bash
sudo systemctl status cert-analyzer
sudo journalctl -u cert-analyzer -f

# Metrics
curl -s http://localhost:9090/metrics | grep tls_certificate_expiry_days
```

## Further reading

- [Quick start demo](README-QUICKSTART.md)
- [Kubernetes / pod enrichment demo](POD-ENRICHMENT-DEMO-README.md)
- [Deployment guide](DEPLOYMENT-README.md)
- [Testing guide](TEST-README.md)
