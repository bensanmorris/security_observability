# CertSight - Realtime certificate monitoring via eBPF

![Tests](https://github.com/bensanmorris/security_observability/actions/workflows/test.yml/badge.svg)
![CI Pipeline](https://github.com/bensanmorris/security_observability/actions/workflows/ci.yml/badge.svg)

Utilises eBPF to hook kprobes and uprobes for safe and low overhead detection of certificate accesses in realtime. Parses and surfaces certificate, process and k8s data (where applicable) as both Prometheus metrics and Kafka topics.

Supports in-memory certificate intercepts (via system crypto lib uprobe hooks) for post-decrypt inspection (no keys required) in addition to file-based PEM (`.pem`, `.crt`, `.cert`, `.cer`), DER, Java KeyStore (`.jks`, `.keystore`, `.truststore`), and PKCS12 (`.p12`, `.pfx`) formats.

Each detected certificate is automatically checked for FIPS 140-2/140-3 algorithm compliance including key type, minimum key size, approved curves, and signature hash with results surfaced in the same Prometheus metrics and Kafka events alongside expiry data.

Java certificate visibility is supported in both FIPS and non-FIPS environments. In FIPS mode, uprobe hooks on NSS (`libsoftokn3.so`) capture certificates at the native layer. In non-FIPS mode, a lightweight Java agent instruments the JCA `KeyStore` API and reports certificates via a native stub hooked by Tetragon — see the [cert-agent (Java, non-FIPS)](probe_tests/README.md#cert-agent-java-non-fips) test for details.

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

| Policy | Purpose | RHEL |
|---|---|---|
| `certificate-file-access.yaml` | Detects certificate file opens by process (`.pem`, `.crt`, `.jks`, `.p12`, etc.) | 8 and 9 |
| `tls-service-tracking-fixed.yaml` | Identifies processes binding on TLS-capable ports (nginx, httpd) via `sys_bind` | 8 and 9 |
| `experimental/openssl1_1-cert-load.yaml` | Intercepts in-memory certificate loads via OpenSSL 1.1 (`libssl.so.1.1`) | 8 only |
| `experimental/openssl3-cert-load.yaml` | Intercepts in-memory certificate loads via OpenSSL 3 (`libssl.so.3`) | 9 only |
| `experimental/java-fips-nss-cert.yaml` | Intercepts certificate objects created via NSS/PKCS11 (FIPS-mode JVMs) | 9 only |
| `experimental/java-non-fips-cert.yaml` | Intercepts certificates exported via the Java cert-agent native stub | 8 and 9 |
| `experimental/tls-service-tracking.yaml` | Identifies TLS service binds using Tetragon's `Protocol` selector (requires Tetragon ≥ v1.4) | 8 and 9 |

Policies are not bundled in the RPM — they are shipped separately so they can be updated independently of the agent. Each CI run and release attaches a `tetragon-policies-<version>.tar.gz` artifact containing all policy YAMLs (including those under `experimental/`).

```bash
tar -xzf tetragon-policies-<version>.tar.gz

# Load all policies immediately (active until Tetragon restarts):
sudo ./tetragon-policies/apply-policies.sh

# Or install persistently (loaded automatically on Tetragon start):
sudo cp tetragon-policies/*.yaml /etc/tetragon/tetragon.tp.d/
sudo cp tetragon-policies/experimental/*.yaml /etc/tetragon/tetragon.tp.d/
sudo systemctl restart tetragon
```

> **Note:** `experimental/java-fips-nss-cert.yaml` hooks `NSC_CreateObject` and `NSC_FindObjectsInit` inside `libsoftokn3.so`. These symbols are not exported in the stripped RHEL package, so Tetragon resolves them via build-ID debuginfo lookup. Install the debuginfo package before loading this policy or the uprobe will fail to attach:
> ```bash
> sudo dnf debuginfo-install nss-softokn
> ```

**Java agent (non-FIPS JVMs):**

For JVMs running without FIPS mode, install the two Java agent RPMs from the [latest release](../../releases/latest) and enable the deployer service:

```bash
sudo dnf install ./cert-agent-jni-<version>.el9.x86_64.rpm
sudo dnf install ./cert-agent-deployer-<version>.el9.x86_64.rpm
sudo systemctl enable --now cert-agent-deployer
```

The deployer scans `/proc` every 30 seconds and uses `jattach` to inject `cert-agent.jar` into each new JVM it finds. The RPM automatically installs and loads a bundled SELinux policy module (`cert_agent_deployer`) that grants the permissions jattach requires (ptrace, signal, `/proc` reads, `/tmp` socket access). Once the `.so` is mapped into a JVM process, load the policy:

```bash
sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/experimental/java-non-fips-cert.yaml
```

> **Note:** the policy must be loaded _after_ the deployer has attached to at least one JVM. Tetragon enumerates processes with `libcert_agent_stub.so` mapped at policy-load time — if no JVM has it mapped yet, the uprobe will not attach to JVMs that load it later.

**Verifying with the probe-tests archive:**

The `probe-tests-<version>.tar.gz` artifact (attached to each release) includes `CertAgentTest` — a small program that continuously loads certificates into a JCA `KeyStore`, giving the uprobe a repeating target to fire on.

```bash
tar -xzf probe-tests-<version>.tar.gz

# Start the test program (loads a cert every 5 s, runs until killed)
# Pass any PEM/DER certificate — e.g. one from your existing PKI or /etc/ssl
java -cp java CertAgentTest /path/to/cert.pem &

# Wait for the deployer to attach — confirm with:
sudo journalctl -u cert-agent-deployer -f

# If the deployer logs "Could not dynamically attach" (e.g. on systems where the
# bundled SELinux module has not yet taken effect), attach manually as a one-off:
sudo jattach <pid> load instrument false \
    /opt/cert-agent/cert-agent.jar=/opt/cert-agent/libcert_agent_stub.so

# Once attached, load (or reload) the policy:
sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/experimental/java-non-fips-cert.yaml

# Confirm detection in cert-analyzer:
sudo journalctl -u cert-analyzer -f | grep java_cert_agent_write
```

See [probe_tests/README.md](probe_tests/README.md#cert-agent-java-non-fips) for the full test procedure and static-agent injection alternative.

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
| `fips_compliance_enabled` | `true` | Check each certificate for FIPS 140-2/140-3 algorithm compliance (key type, minimum key size, approved curves, signature hash) |
| `filter_self_events` | `true` | Ignore certificate accesses made by the analyzer itself |
| `host_prefix` | _(empty)_ | Path prefix prepended to certificate paths from Tetragon events — leave empty for bare metal, set to `/host` for Kubernetes |
| `demo_mode` | `false` | Log certificate details (subject, issuer, serial, validity, SANs) at INFO level instead of DEBUG — for demos only, leave false in production |

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

- [Linux capabilities reference](linux-capabilities.md) - Required Linux capabilities for each component
- [Uprobe hook tests](probe_tests/README.md) - Programs for verifying Tetragon uprobe policies fire correctly
- [Performance tests](perf_tests/README.md) - Throughput and latency comparison across cert-analyzer configurations
- [Surfaced fields reference](extras/FIELDS-README.md) - All Prometheus metrics and Kafka event fields
- [Quick start demo](extras/README-QUICKSTART.md)
- [Kubernetes / pod enrichment demo](extras/POD-ENRICHMENT-DEMO-README.md)
- [Deployment guide](extras/DEPLOYMENT-README.md)
- [Testing guide](extras/TEST-README.md)
