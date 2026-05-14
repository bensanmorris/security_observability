# CertSight - Realtime certificate monitoring via eBPF

![Tests](https://github.com/bensanmorris/security_observability/actions/workflows/test.yml/badge.svg)
![CI Pipeline](https://github.com/bensanmorris/security_observability/actions/workflows/ci.yml/badge.svg)

Utilises eBPF to hook kprobes and uprobes for safe and low overhead detection of certificate accesses in realtime. Parses and surfaces certificate, process and k8s data (where applicable) as both Prometheus metrics and Kafka topics.

Supports in-memory certificate intercepts (via system crypto lib uprobe hooks) for post-decrypt inspection (no keys required) in addition to file-based PEM (`.pem`, `.crt`, `.cert`, `.cer`), DER, Java KeyStore (`.jks`, `.keystore`, `.truststore`), and PKCS12 (`.p12`, `.pfx`) formats.

---

## Prerequisites

- RHEL 8 or RHEL 9 (x86_64)
- [Tetragon](https://tetragon.io) installed and running

---

## Installation

Download the RPM from the [latest release](../../releases/latest).

```bash
sudo dnf install ./cert-analyzer-<version>.el9.x86_64.rpm   # RHEL 9
sudo dnf install ./cert-analyzer-<version>.el8.x86_64.rpm   # RHEL 8
```

The installer will fail with a clear error if Tetragon is not found.

**Applying Tetragon policies:**

Policies are not bundled in the RPM — they are shipped separately so they can be updated independently of the agent. Each CI run and release attaches a `tetragon-policies-<version>.tar.gz` artifact containing all policy YAMLs (including those under `experimental/`).

```bash
tar -xzf tetragon-policies-<version>.tar.gz

# Load immediately (active until Tetragon restarts):
sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/certificate-file-access.yaml
sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/experimental/openssl3-cert-load.yaml     # RHEL 9
sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/experimental/openssl1_1-cert-load.yaml   # RHEL 8

# Or install persistently (loaded automatically on Tetragon start):
sudo cp tetragon-policies/certificate-file-access.yaml /etc/tetragon/tetragon.tp.d/
sudo systemctl restart tetragon
```

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

---

## Further reading

- [Quick start demo](extras/README-QUICKSTART.md)
- [Kubernetes / pod enrichment demo](extras/POD-ENRICHMENT-DEMO-README.md)
- [Deployment guide](extras/DEPLOYMENT-README.md)
- [Testing guide](extras/TEST-README.md)
- [Uprobe hook tests](probe_tests/README.md) — C++ programs for verifying Tetragon uprobe policies fire correctly
