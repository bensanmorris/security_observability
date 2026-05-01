# CertSight - Realtime certificate monitoring via eBPF

![Tests](https://github.com/bensanmorris/security_observability/actions/workflows/test.yml/badge.svg)
![CI Pipeline](https://github.com/bensanmorris/security_observability/actions/workflows/ci.yml/badge.svg)

Monitor TLS certificate expiry in real-time without modifying applications. Hooks Tetragon's eBPF `fd_install` kprobe to detect certificate file access the moment any process opens it, then parses and exposes expiry metadata as Prometheus metrics.

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

| Setting | Default | Description |
|---|---|---|
| `TETRAGON_ADDR` | `unix:///var/run/tetragon/tetragon.sock` | Tetragon gRPC address |
| `METRICS_PORT` | `9090` | Prometheus metrics port |
| `ALERT_THRESHOLD_DAYS` | `30` | Days before expiry to flag a certificate |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

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

- [Quick start demo](README-QUICKSTART.md)
- [Kubernetes / pod enrichment demo](POD-ENRICHMENT-DEMO-README.md)
- [Deployment guide](DEPLOYMENT-README.md)
- [Testing guide](TEST-README.md)
