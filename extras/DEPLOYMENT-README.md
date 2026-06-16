# Production Deployment Guide

## Overview

This document describes the steps and topology required to deploy the TLS Certificate Expiry Monitor. Two deployment modes are supported:

- **Standalone RHEL9 (RPM)** — the primary mode, covered in the Standalone RHEL9 Deployment section. cert-analyzer runs as a systemd service installed from a self-contained RPM package on each RHEL9 node alongside Tetragon.
- **Kubernetes DaemonSet** — covered in the Deployment Steps section. Tetragon and cert-analyzer run as co-located DaemonSets on each node, with Prometheus, Alertmanager, and Grafana for observability.

## Architecture

The full production stack consists of five components:

```
┌─────────────────────────────────────────────────────────────┐
│ Kubernetes Node                                             │
│                                                             │
│  ┌──────────────────────┐   gRPC   ┌───────────────────┐    │
│  │  Tetragon (DaemonSet)│ ───────► │ cert-analyzer     │    │
│  │  eBPF interception   │          │ (DaemonSet)       │    │
│  │  of cert file access │          │ Publishes metrics │    │
│  └──────────────────────┘          └────────┬──────────┘    │
│                                             │ :9090         │
└─────────────────────────────────────────────┼───────────────┘
                              ┌───────────────┼───────────────────┐
                              │               │                   │
                    ┌─────────▼──────────┐    │  (optional)       │
                    │    Prometheus      │    ▼                   │
                    │  Stores metrics &  │  ┌─────────────────┐   │
                    │  evaluates rules   │  │     Kafka       │   │
                    └─────────┬──────────┘  │  New cert event │   │
                              │ fires alerts│  stream         │   │
                    ┌─────────▼──────────┐  └─────────────────┘   │
                    │    Alertmanager    │                        │
                    │  Routes & notifies │                        │
                    └─────────┬──────────┘                        │
                              │                                   │
                    ┌─────────▼──────────┐                        │
                    │      Grafana       │                        │
                    │  Visualises metrics│                        │
                    └────────────────────┘                        │
                              └───────────────────────────────────┘
```

**Tetragon** is the eyes — it uses eBPF to intercept certificate file access at the kernel level and exposes events via a gRPC socket on each node.

**cert-analyzer** is the brain — it connects to the local Tetragon gRPC socket, parses X.509 certificates, and publishes Prometheus metrics on port 9090.

Both are deployed as DaemonSets so that each node has exactly one of each, co-located and paired via the local socket. Running cert-analyzer as a regular Deployment would risk it landing on a different node to its Tetragon instance, breaking the gRPC connection.

---

## Standalone RHEL9 Deployment (RPM)

For environments where cert-analyzer runs as a systemd service on bare-metal or VM RHEL9 nodes rather than inside Kubernetes, an RPM package is available. The RPM bundles a self-contained Python virtualenv so no internet access or pip install is required at install time.

### RPM Contents

The RPM installs the following layout:

```
/opt/cert-analyzer/cert_analyzer.py              # main analyzer script
/opt/cert-analyzer/tetragon/                     # compiled Tetragon gRPC protos
/opt/cert-analyzer/venv/                         # bundled Python virtualenv
/etc/cert-analyzer/cert-analyzer.conf            # operator configuration file
/usr/lib/systemd/system/cert-analyzer.service
/usr/lib/systemd/system/cert-analyzer.service.d/version.conf  # stamped build versions
/var/log/cert-analyzer/
/usr/share/licenses/cert-analyzer/LICENSE
```

A dedicated `cert-analyzer` system user and group are created during installation. The service runs as this user with `NoNewPrivileges` and a restricted filesystem view.

### Stamped Build Versions

The RPM stamps two read-only version constants into a systemd drop-in at build time:

```ini
# /usr/lib/systemd/system/cert-analyzer.service.d/version.conf
[Service]
Environment=TETRAGON_BUILD_VERSION=v1.1.0
Environment=CERT_ANALYZER_VERSION=1.0.0
```

These are injected automatically from the rpmbuild `--define` arguments and cannot be modified by operators — the file is owned by the RPM and replaced on every upgrade. They serve two purposes:

- `TETRAGON_BUILD_VERSION` — the Tetragon version the protos were compiled against. The analyzer compares this against the running Tetragon daemon version at startup and every 5 minutes thereafter. A mismatch fires the `TetragonVersionMismatch` alert.
- `CERT_ANALYZER_VERSION` — the cert-analyzer version, exposed via the `cert_analyzer_build` Prometheus Info metric alongside `TETRAGON_BUILD_VERSION`.

After installation verify the versions were stamped correctly:

```bash
cat /usr/lib/systemd/system/cert-analyzer.service.d/version.conf

# Also visible via systemctl
systemctl show cert-analyzer | grep -i version

# And via Prometheus once the service is running
curl -s http://localhost:9090/metrics | grep cert_analyzer_build
```

If you see `Tetragon version check incomplete — build: unknown` in the logs it means either the drop-in was not installed (check the file exists) or the service was not reloaded after install (`sudo systemctl daemon-reload`).

### Building the RPM

Prerequisites on the build machine:

```bash
sudo dnf install python3.11 python3.11-devel rpm-build git gcc
```

Run the build script from the repository root:

```bash
# Build against the default Tetragon version (v1.1.0)
./rpm/build-rpm.sh

# Build against a specific Tetragon version
./rpm/build-rpm.sh --tetragon-version v1.2.0

# Build with an explicit version string
./rpm/build-rpm.sh --version 1.0.0 --release 1
```

The version is auto-detected from the git tag if building from a tagged commit, or set to `0.0.0~git<sha>` for snapshot builds. The resulting RPM is written to `~/rpmbuild/RPMS/<arch>/`.

### Installing the RPM

Tetragon must be installed and reachable in `$PATH` before installing cert-analyzer. The RPM's pre-install scriptlet checks for the `tetragon` binary and aborts with a clear message if it is absent — this is intentional since cert-analyzer is non-functional without Tetragon regardless of installation path:

```
ERROR: tetragon binary not found in PATH.
       Install Tetragon before installing cert-analyzer.
       See https://tetragon.io/docs/installation/
```

Once Tetragon is installed, verify it is visible before proceeding:

```bash
command -v tetragon
tetragon version
```

Then copy the RPM to each target node and install:

```bash
sudo dnf install ./cert-analyzer-<version>.<arch>.rpm
```

`dnf` is preferred over `rpm -i` as it handles dependency resolution automatically.

To verify the RPM's declared dependencies and pre-install scriptlet:

```bash
# Show declared package dependencies
rpm -qp --requires cert-analyzer-<version>.<arch>.rpm

# Show the pre-install scriptlet including the Tetragon check
rpm -qp --scripts cert-analyzer-<version>.<arch>.rpm
```

### Configuration

All runtime options are set in `/etc/cert-analyzer/cert-analyzer.conf`. This file is installed with secure permissions (`0640`, owned by `root:cert-analyzer`) and is marked `%config(noreplace)` in the RPM — upgrades will never overwrite your changes.

The configuration file is INI format with named sections:

```ini
[tetragon]
addr = unix:///run/tetragon/tetragon.sock

[metrics]
port = 9090

[health]
port = 8086
readiness_grace_period_seconds = 60
readiness_staleness_seconds = 300

[alerting]
threshold_days = 30

[scanning]
paths = /etc/ssl,/etc/pki
interval_seconds = 3600

[logging]
level = INFO

[cache]
max_size = 10000

[certificates]
checksum_enabled = false
filter_self_events = true
# Leave empty for standalone deployment — set to /host for Kubernetes
host_prefix =

[passwords]
# jks_password =
# pkcs12_password =

[kafka]
# Set enabled = true to publish new certificate discovery events to Kafka.
# When disabled (the default) the analyzer publishes to Prometheus only.
enabled = false
bootstrap_servers = localhost:9092
topic = cert-analyzer-events
security_protocol = PLAINTEXT
# sasl_mechanism = PLAIN
# sasl_username  =
# sasl_password  =
```

Values in the config file take precedence over environment variables, which in turn take precedence over built-in defaults. This means the Kubernetes deployment path (which uses environment variables and has no config file) continues to work unchanged.

The config file path can be overridden via the `CERT_ANALYZER_CONFIG` environment variable, which is useful for testing or non-standard deployments:

```bash
CERT_ANALYZER_CONFIG=/tmp/test.conf /opt/cert-analyzer/venv/bin/python3 \
    /opt/cert-analyzer/cert_analyzer.py
```

> **Note on upgrades and config changes** — `%config(noreplace)` preserves your
> config file if it has been locally modified. However if the RPM ships a new
> default config (e.g. with new options added), RPM will install the new version
> as `cert-analyzer.conf.rpmnew` rather than overwriting your file. Always check
> for this file after an upgrade and merge any new options — see the Upgrading
> section below.

### Tetragon Socket Permissions

The cert-analyzer runs as the `cert-analyzer` system user and must be able to read the Tetragon gRPC socket. The socket is owned by `root:root` by default and the `cert-analyzer` user has no access to it.

Grant access by changing the socket group:

```bash
sudo chgrp cert-analyzer /run/tetragon/tetragon.sock
```

Verify:

```bash
ls -la /run/tetragon/tetragon.sock
# Expected: srw-rw----. 1 root cert-analyzer 0 ...
```

This change does not survive a Tetragon restart. To make it permanent add a systemd drop-in to the Tetragon service:

```bash
sudo systemctl edit tetragon
```

Add the following and save:

```ini
[Service]
ExecStartPost=/bin/chgrp cert-analyzer /run/tetragon/tetragon.sock
```

Reload systemd and verify it takes effect on the next Tetragon restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart tetragon
ls -la /run/tetragon/tetragon.sock
# Group should now be cert-analyzer
```

### Starting the Service

```bash
# Edit configuration before first start
sudo vi /etc/cert-analyzer/cert-analyzer.conf

# Enable and start
sudo systemctl enable --now cert-analyzer

# Verify
sudo systemctl status cert-analyzer
sudo journalctl -u cert-analyzer -f
```

### Verifying Operation

```bash
# Check the analyzer is producing metrics
curl -s http://localhost:9090/metrics | grep tls_certificate_expiry_days

# Check liveness and readiness probes
curl -s http://localhost:8086/healthz
curl -s http://localhost:8086/readyz

# Check the version that was installed
curl -s http://localhost:9090/metrics | grep cert_analyzer_build

# Trigger a detection by reading a certificate file — check the logs
cat /etc/pki/tls/certs/ca-bundle.crt
sudo journalctl -u cert-analyzer -n 10
```

You should see a `🔍 Detected certificate access` line in the logs within a second of the `cat` command.

> **Periodic scan and feedback loop** — by default the periodic scan runs every
> hour against `/etc/ssl,/etc/pki`. On a standalone node where Tetragon is
> already delivering real-time fd_install events, the periodic scan is redundant
> and can cause a feedback loop where the cert-analyzer's own file accesses
> generate events back to itself. If you observe repeated detections with
> `process=periodic_scan` or PID matching the cert-analyzer process, disable
> the periodic scan:
> ```ini
> [scanning]
> paths =
> ```

### Upgrading

```bash
sudo dnf upgrade ~/rpmbuild/RPMS/x86_64/cert-analyzer-<new-version>.<arch>.rpm
```

If rebuilding without a new git commit (i.e. the version string is unchanged), increment the release number to ensure dnf recognises it as a newer package:

```bash
./build-rpm.sh --release 2
sudo dnf upgrade ~/rpmbuild/RPMS/x86_64/cert-analyzer-0.0.0~git<sha>-2.el9.x86_64.rpm
```

**Config file behaviour on upgrade** — if the packaged default `cert-analyzer.conf` has changed since your last install (e.g. new options added), RPM cannot silently overwrite your customised file. Instead it installs the new default as `cert-analyzer.conf.rpmnew` and leaves your file untouched. Always check for this after an upgrade and merge any new options:

```bash
# Check if a new default config was installed
ls /etc/cert-analyzer/
diff /etc/cert-analyzer/cert-analyzer.conf \
     /etc/cert-analyzer/cert-analyzer.conf.rpmnew
```

If no `.rpmnew` file exists, your config was identical to the new default and no merge is needed.

### Uninstalling

```bash
sudo systemctl stop cert-analyzer
sudo dnf remove cert-analyzer
# Configuration and logs are preserved — remove manually if desired:
sudo rm -rf /etc/cert-analyzer /var/log/cert-analyzer
```

---

## Kubernetes DaemonSet Deployment

### 1. Verify Node Prerequisites

Confirm each node meets the requirements before proceeding:

- RHEL 9.x (or compatible: Rocky Linux, AlmaLinux)
- Kernel 5.x or later
- BTF (BPF Type Format) enabled — verify with `ls /sys/kernel/btf/vmlinux`
- Podman 4.x or later
- Python 3.11+

### 2. Build and Push the cert-analyzer Image

Run the following on your build machine:

```bash
# Generate Tetragon gRPC protobuf bindings (must match your Tetragon version)
chmod +x generate_tetragon_protos.sh
./generate_tetragon_protos.sh

# Build the container image
chmod -R a+rX tetragon/
chmod +x build.sh
./build.sh

# Tag with a versioned label (avoid 'latest' in production)
podman tag cert-analyzer:latest your-registry.internal/security/cert-analyzer:1.0.0

# Push to your internal registry
podman push your-registry.internal/security/cert-analyzer:1.0.0
```

> **cert-analyzer version** — the image is stamped at build time with a version
> string derived from the git tag (for releases) or the full commit SHA (for
> branch builds). This is stored as the `CERT_ANALYZER_VERSION` environment
> variable inside the container and exposed via the `cert_analyzer_build` Info
> metric alongside the Tetragon build version. To inspect the version of a
> running container:
> ```bash
> # From the Prometheus metrics endpoint
> curl -s http://localhost:9090/metrics | grep cert_analyzer_build
>
> # From the container environment directly
> podman exec cert-analyzer env | grep CERT_ANALYZER_VERSION
>
> # From the image labels
> podman inspect cert-analyzer | grep -i version
> ```

> **Tetragon version lockstep** — the cert-analyzer image is built against a
> specific Tetragon version (set via the `TETRAGON_VERSION` build arg in the
> Containerfile). The build version is stamped into the image as the
> `TETRAGON_BUILD_VERSION` environment variable and checked against the running
> Tetragon daemon at startup and periodically at runtime. Always rebuild the
> cert-analyzer image when upgrading Tetragon. A mismatch will log a `WARNING`
> and set the `cert_analyzer_tetragon_version_match` Prometheus gauge to `0`,
> which fires the `TetragonVersionMismatch` alert. See the Production
> Considerations section for the recommended alert rule.

### 3. Configure Node Registry Access

Ensure all nodes can pull from your internal registry. On each node:

- Add your registry to `/etc/containers/registries.conf`
- Authenticate via `podman login` or configure a Kubernetes pull secret

### 4. Deploy Tetragon

**Kubernetes (recommended):**

```bash
helm repo add cilium https://helm.cilium.io
helm install tetragon cilium/tetragon -n kube-system
```

Review the default RBAC and security context — Tetragon requires elevated privileges to load eBPF programs.

**Standalone RHEL9:**

Follow the standalone Tetragon installation steps in the main README, then enable the systemd service:

```bash
sudo systemctl enable --now tetragon
sudo systemctl status tetragon
```

### 5. Load Tetragon Tracing Policies

These policies tell Tetragon what to intercept. All three must be loaded or certificate events will not be captured.

**Kubernetes:**

```bash
kubectl apply -f tetragon-policies/certificate-file-access.yaml
kubectl apply -f tetragon-policies/openssl-cert-load.yaml
kubectl apply -f tetragon-policies/tls-service-tracking.yaml

# Verify
kubectl get tracingpolicies
```

**Standalone:**

```bash
sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/certificate-file-access.yaml
sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/openssl-cert-load.yaml
sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/tls-service-tracking.yaml

# Verify
sudo /usr/local/bin/tetra tracingpolicy list
```

Confirm that tracing policies survive node reboots — configure them to load automatically via systemd or your configuration management tooling.

### 6. Install the SELinux Policy Module

Required on RHEL9 nodes running SELinux in enforcing mode. Skipping this step may cause silent failures when the analyzer attempts to access the Tetragon socket or certificate directories.

```bash
cd selinux/
sudo checkmodule -M -m -o cert-analyzer.mod cert-analyzer.te
sudo semodule_package -o cert-analyzer.pp -m cert-analyzer.mod
sudo semodule -i cert-analyzer.pp

# Verify
sudo semodule -l | grep cert-analyzer
```

### 7. Deploy cert-analyzer as a DaemonSet

Update `kubernetes/deployment.yaml` to reference your internal registry image, then apply:

```bash
kubectl apply -f kubernetes/deployment.yaml

# Verify one pod per node
kubectl get pods -n kube-system -l app=cert-expiry-monitor -o wide
kubectl logs -n kube-system -l app=cert-expiry-monitor -f
```

Once pods are running, verify the health endpoints are responding correctly on each node:

```bash
# Liveness probe — should return 200 with {"status": "ok"}
curl -s http://<node-ip>:8086/healthz

# Readiness probe — should return 200 with {"status": "ok"}
# Note: during the 60s grace period this will always return ready
curl -s http://<node-ip>:8086/readyz
```

The probes are configured in `deployment.yaml` with the following behaviour:

- **Liveness** (`/healthz`) — checks the gRPC channel is not in a terminal shutdown state. Temporary Tetragon unavailability (e.g. during an upgrade) does not fail liveness — the reconnection loop handles that transparently. Only an explicit channel shutdown triggers a pod restart.
- **Readiness** (`/readyz`) — returns ready during the startup grace period (default 60s). After the grace period, returns ready if no events have ever been seen (silence is valid) or if at least one event has been processed within the staleness window (default 300s). Returns not-ready only if events were seen previously but the stream has since gone stale.

The following env vars control probe behaviour and can be overridden in `deployment.yaml`:

| Env var | Default | Description |
|---|---|---|
| `HEALTH_PORT` | `8086` | Port for `/healthz` and `/readyz` |
| `READINESS_GRACE_PERIOD_SECONDS` | `60` | Seconds after startup before readiness checking begins |
| `READINESS_STALENESS_SECONDS` | `300` | Max age of last event before pod is marked not-ready |

The following env vars control keystore password handling and should be set via Kubernetes Secrets (see Production Considerations):

| Env var | Default | Description |
|---|---|---|
| `JKS_PASSWORD` | _(none)_ | Password for JKS keystores. Tried first, before `changeit` and empty string |
| `PKCS12_PASSWORD` | _(none)_ | Password for PKCS12 keystores. Tried first, before `changeit` and empty string |

The following env var controls internal cache sizing:

| Env var | Default | Minimum | Description |
|---|---|---|---|
| `CACHE_MAX_SIZE` | `10000` | `10000` | Maximum entries in each of the three LRU caches (known certs, processed paths, password-failed paths). Cannot be set below 10,000. |

The following env var controls optional certificate checksum computation:

| Env var | Default | Description |
|---|---|---|
| `CERT_CHECKSUM_ENABLED` | `false` | Set to `true` to compute a SHA-256 checksum of each certificate's DER-encoded bytes. Useful for detecting silent cert rotation and correlating the same cert at multiple paths. Disabled by default — see Production Considerations. |

### 8. Deploy Prometheus and Alertmanager

The repository does not provision Prometheus or Alertmanager. The recommended approach for Kubernetes is the kube-prometheus-stack Helm chart, which bundles Prometheus, Alertmanager, and Grafana together:

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack -n monitoring --create-namespace
```

Once deployed, configure Prometheus to scrape the cert-analyzer metrics by adding the following to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'cert-expiry-monitor'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 30s
```

Apply the pre-built alerting rules:

```bash
kubectl apply -f kubernetes/prometheus-rules.yaml
```

This creates the following alerts:

- `CertificateExpiringSoon` — certificate expires in fewer than 30 days
- `CertificateExpiringCritical` — certificate expires in fewer than 7 days
- `CertificateExpired` — certificate has already expired
- `CertificateAnalyzerDown` — metrics endpoint unreachable for 5 minutes
- `CertificateAnalysisErrors` — high rate of cert parsing errors
- `TetragonVersionMismatch` — build and runtime Tetragon versions differ
- `CertAnalyzerNotReady` — readiness probe failing for 5 minutes
- `KeystorePasswordFailed` — JKS or PKCS12 keystore cannot be opened
- `CertAnalyzerCacheNearCapacity` — known_certs cache over 90% full

### 9. Configure Alertmanager

Wire Prometheus to Alertmanager in your `prometheus.yml`:

```yaml
alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']
```

Configure `alertmanager.yml` to route notifications to your chosen channel (Slack, email, PagerDuty, etc.). Set an appropriate `repeat_interval` — for expired certificates a short interval (e.g. 1h) is recommended to ensure the alert keeps firing until the certificate is replaced.

### 10. Import the Grafana Dashboard

1. Open Grafana
2. Go to Dashboards → Import
3. Upload `examples/grafana-dashboard.json`
4. Select your Prometheus datasource

---

## Production Considerations

**Metrics endpoint security** — the cert-analyzer metrics endpoint is plain HTTP on port 9090 and unauthenticated. Place a reverse proxy in front of it if the endpoint is exposed on a shared network.

**Liveness and readiness probes** — the health server runs on port 8086 (configurable via `HEALTH_PORT`) and serves two endpoints. `/healthz` is the liveness probe — it only fails if the gRPC channel has been explicitly shut down, meaning OpenShift will not restart the pod during normal Tetragon maintenance windows. `/readyz` is the readiness probe — it uses a startup grace period to avoid false failures on initial deployment, then monitors event stream freshness. If the readiness probe fires the `CertAnalyzerNotReady` alert in Prometheus, check the pod logs for gRPC errors and verify the Tetragon socket is accessible. Tune `READINESS_STALENESS_SECONDS` to match your environment's expected event frequency — on a quiet node with infrequent cert access, increase this value to avoid spurious not-ready states.

**Version diagnostics** — the `cert_analyzer_build` Info metric is the primary tool for diagnosing version-related issues in production. It carries both the cert-analyzer version and the Tetragon build version as labels, so a single query tells you exactly what is running and what it was built against:

```promql
cert_analyzer_build_info
```

The cert-analyzer version also appears on the first line of the startup log. When raising a support issue or bug report, always include the output of:

```bash
curl -s http://localhost:9090/metrics | grep cert_analyzer_build
```

**Tetragon version monitoring** — the analyzer checks its build version against the running Tetragon daemon at startup and every 5 minutes thereafter (configurable via `TETRAGON_VERSION_CHECK_INTERVAL`). If Tetragon is upgraded without a corresponding cert-analyzer rebuild, proto incompatibilities may cause silent event processing failures. Add the following alert rule to catch this:

```yaml
- alert: TetragonVersionMismatch
  expr: cert_analyzer_tetragon_version_match == 0
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "cert-analyzer built against wrong Tetragon version"
    description: >
      The cert-analyzer was built against a different Tetragon version than
      the one currently running. Check the cert_analyzer_tetragon_version
      metric for build_version and runtime_version labels, then rebuild the
      cert-analyzer image against the runtime version.
```

The `cert_analyzer_tetragon_version` Info metric carries both `build_version` and `runtime_version` labels and can be inspected directly:

```bash
curl -s http://localhost:9090/metrics | grep tetragon_version
```

**Prometheus storage** — configure Prometheus with sufficient retention for certificate expiry trending. 90 days is a reasonable minimum given the alerting thresholds in use.

**Scan interval** — the default `SCAN_INTERVAL_SECONDS` is 3600 (1 hour). After a process restart there will be a gap before metrics are repopulated. Lower this value if a faster recovery time is required.

**Log aggregation** — the analyzer logs to stdout. Ensure your existing log shipping setup (Fluentd, Filebeat, etc.) is configured to collect from the cert-analyzer pods.

**Keystore password management** — the cert-analyzer attempts to open JKS and PKCS12 keystores using `JKS_PASSWORD`/`PKCS12_PASSWORD` env vars first, then falls back to `changeit` (the Java ecosystem default), then empty string. If all attempts fail, the file is skipped, a `KeystorePasswordFailed` alert fires, and the path is cached so subsequent Tetragon events for the same file do not repeat the expensive crypto operations.

Passwords must be provided via Kubernetes Secrets — never hardcoded in `deployment.yaml`. Create the Secret and reference it in the DaemonSet:

```bash
kubectl create secret generic cert-analyzer-keystore-passwords \
  --from-literal=jks-password=your-jks-password \
  --from-literal=pkcs12-password=your-pkcs12-password \
  -n kube-system
```

Then reference in `deployment.yaml`:

```yaml
env:
  - name: JKS_PASSWORD
    valueFrom:
      secretKeyRef:
        name: cert-analyzer-keystore-passwords
        key: jks-password
  - name: PKCS12_PASSWORD
    valueFrom:
      secretKeyRef:
        name: cert-analyzer-keystore-passwords
        key: pkcs12-password
```

If the `KeystorePasswordFailed` alert fires after deployment, check the pod logs at `DEBUG` level to identify the specific file paths that could not be opened:

```bash
kubectl logs -n kube-system -l app=cert-expiry-monitor | grep "password-failed"
```

Note that a single password env var applies to all keystores of that format. If your environment has multiple keystores with different passwords, contact the security team to discuss a password map file approach backed by a mounted Secret.

**Certificate checksums** — SHA-256 checksum computation is disabled by default (`CERT_CHECKSUM_ENABLED=false`). When enabled, the DER-encoded bytes of each parsed certificate are hashed and the result is stored in the `CertificateInfo` object. This has two practical uses:

- **Rotation detection** — if a certificate at a known path is replaced (same path, new cert), the checksum changes while the path stays the same, making silent rotations visible
- **Cross-path correlation** — the same certificate distributed to multiple paths (e.g. a CA bundle copied across namespaces) produces identical checksums, allowing deduplication

The CPU cost is negligible — SHA-256 of a few KB of DER bytes takes microseconds. The feature is disabled by default because the serial number combined with issuer already provides a globally unique certificate identity per the X.509 spec, and most deployments don't need the additional signal. Enable it if you have specific rotation tracking or cross-path deduplication requirements:

```yaml
env:
  - name: CERT_CHECKSUM_ENABLED
    value: "true"
```

When enabled, checksums are surfaced in three places:

- **Prometheus labels** — the `checksum` label is present on `tls_certificate_expiry_days`, `tls_certificate_expiry_timestamp`, and `tls_certificate_valid_from`, allowing PromQL queries to group or filter by certificate identity across paths
- **Alert annotations** — the `CertificateExpiringSoon`, `CertificateExpiringCritical`, and `CertificateExpired` alerts include `sha256: <checksum>` in their description when the label is non-empty, making it straightforward to verify exactly which certificate instance triggered the alert
- **Debug logs** — the SHA-256 is logged alongside the subject and serial number at DEBUG level

When checksums are disabled (the default), the `checksum` label is present but empty on all metrics — existing queries and dashboards are unaffected.

**Kafka event publishing (optional)** — cert-analyzer can publish a JSON message to a Kafka topic each time a certificate is seen for the first time. This is disabled by default and completely independent of Prometheus — enabling it does not affect metrics, alerts, or the health probes. It is intended for downstream consumers that need a real-time event stream of certificate discoveries: SIEMs, ticketing integrations, audit pipelines, or custom alerting systems.

Each message is published to a single configurable topic with the certificate file path as the partition key, ensuring all events for the same certificate file land on the same partition for ordered consumption. The message schema is:

```json
{
  "event_type":        "certificate_discovered",
  "detected_at":       "2026-03-31T10:00:00.000000",
  "path":              "/etc/pki/tls/certs/ca-bundle.crt",
  "cert_index":        0,
  "subject":           "CN=example.com",
  "issuer":            "CN=Example CA",
  "serial_number":     "abc123",
  "common_name":       "example.com",
  "san_dns_names":     ["example.com", "www.example.com"],
  "not_before":        "2024-01-01T00:00:00",
  "not_after":         "2025-01-01T00:00:00",
  "days_until_expiry": 44.9,
  "is_expired":        false,
  "process":           "/usr/bin/curl",
  "pid":               12345,
  "namespace":         "default",
  "pod_name":          "my-pod",
  "workload_kind":     "Deployment",
  "workload_name":     "my-app",
  "app_label":         "my-app",
  "container_name":    "main",
  "container_image":   "my-app:1.0",
  "checksum":          ""
}
```

To enable in standalone RPM deployment, edit `/etc/cert-analyzer/cert-analyzer.conf`:

```ini
[kafka]
enabled = true
bootstrap_servers = broker1:9092,broker2:9092
topic = cert-analyzer-events
security_protocol = PLAINTEXT
```

For authenticated brokers (SASL/SSL), set the additional fields:

```ini
[kafka]
enabled = true
bootstrap_servers = broker1:9092
topic = cert-analyzer-events
security_protocol = SASL_SSL
sasl_mechanism = PLAIN
sasl_username = your-username
sasl_password = your-password
```

> **Credentials in the config file** — the config file is installed with `0640` permissions owned by `root:cert-analyzer`, so only root and the cert-analyzer service account can read it. This is acceptable for standalone RPM deployments. For Kubernetes, supply credentials via environment variables backed by a Kubernetes Secret rather than a config file:
> ```bash
> kubectl create secret generic cert-analyzer-kafka \
>   --from-literal=sasl-username=your-username \
>   --from-literal=sasl-password=your-password \
>   -n kube-system
> ```
> Then reference in `deployment.yaml`:
> ```yaml
> env:
>   - name: KAFKA_ENABLED
>     value: "true"
>   - name: KAFKA_BOOTSTRAP_SERVERS
>     value: "broker1:9092,broker2:9092"
>   - name: KAFKA_TOPIC
>     value: "cert-analyzer-events"
>   - name: KAFKA_SECURITY_PROTOCOL
>     value: "SASL_SSL"
>   - name: KAFKA_SASL_MECHANISM
>     value: "PLAIN"
>   - name: KAFKA_SASL_USERNAME
>     valueFrom:
>       secretKeyRef:
>         name: cert-analyzer-kafka
>         key: sasl-username
>   - name: KAFKA_SASL_PASSWORD
>     valueFrom:
>       secretKeyRef:
>         name: cert-analyzer-kafka
>         key: sasl-password
> ```

If the Kafka broker is unreachable at startup the analyzer logs a warning and continues with Prometheus-only operation — a broker outage never prevents certificate detection. Delivery errors are logged at `WARNING` level and do not affect the health probes or readiness state.

The analyzer reconnects to Kafka automatically — no restart is required after a broker outage or restart. When a `send()` fails the producer is marked as disconnected and the next certificate detection event triggers a reconnect attempt. A 30-second cooldown between reconnect attempts prevents hammering a down broker. You will see the following in the logs as the broker recovers:

```
Kafka producer connection failed (will retry in 30s): ...
Kafka producer connected — brokers: localhost:9092, topic: cert-analyzer-events
```

*Verifying Kafka end to end*

For local testing on RHEL9, run a Kafka broker in a container. The critical detail is that both the Kafka container and the cert-analyzer container must be on the same network, and Kafka must advertise `localhost` as its listener address — otherwise `kafka-python` will connect successfully for metadata but then fail to reach the broker address that Kafka advertises back:

```bash
# Run Kafka with --network host and explicit advertised listener
podman run -d \
  --name kafka-test \
  --network host \
  -e KAFKA_NODE_ID=1 \
  -e KAFKA_PROCESS_ROLES=broker,controller \
  -e KAFKA_LISTENERS=PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093 \
  -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://localhost:9092 \
  -e KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
  -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT \
  -e KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9093 \
  -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
  -e KAFKA_AUTO_CREATE_TOPICS_ENABLE=true \
  docker.io/apache/kafka:latest
```

Wait about 10 seconds for the broker to start, then verify it is ready:

```bash
podman exec kafka-test /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server localhost:9092 \
  --list
```

Enable Kafka in the cert-analyzer. For the RPM service edit `/etc/cert-analyzer/cert-analyzer.conf`. For the container pass env vars — since `run-rootful.sh` already uses `--network host`, `localhost:9092` reaches the Kafka container directly:

```bash
-e KAFKA_ENABLED=true \
-e KAFKA_BOOTSTRAP_SERVERS=localhost:9092 \
-e KAFKA_TOPIC=cert-analyzer-events
```

> **First-time enable** — a restart is required only when enabling Kafka for the first time, since the env vars or config change must be picked up at startup. Once Kafka is enabled, the analyzer reconnects automatically after broker restarts or outages — no further analyzer restarts are needed.

If restarting the container to pick up the new env vars:

```bash
sudo ./run-rootful.sh
```

Confirm Kafka initialised successfully in the logs:

```bash
sudo podman logs cert-analyzer | grep -i kafka
# Expected:
# Kafka enabled:     True
# Kafka brokers:     localhost:9092
# Kafka topic:       cert-analyzer-events
# Kafka producer connected — brokers: localhost:9092, topic: cert-analyzer-events
```

If instead you see `Node 1 connection failed -- refreshing metadata` it means Kafka is advertising an internal hostname rather than `localhost` — recreate the Kafka container with the `KAFKA_ADVERTISED_LISTENERS` env var set as shown above.

Trigger a detection to publish a message:

```bash
cat /etc/pki/tls/certs/ca-bundle.crt
```

Then consume from the topic to confirm the message arrived:

```bash
podman exec kafka-test /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic cert-analyzer-events \
  --from-beginning
```

Each message is a JSON object. Press `Ctrl+C` to stop the consumer. If the topic does not exist yet (`UNKNOWN_TOPIC_OR_PARTITION`) it means no messages have been published — check the analyzer logs for Kafka errors and confirm at least one new certificate was detected since the analyzer started with Kafka enabled.

Tear down the test broker when finished:

```bash
podman stop kafka-test && podman rm kafka-test
```

**Alertmanager silences** — when deliberately rotating a certificate, create an Alertmanager silence for that cert's `cert_path` label to suppress alerts during the rotation window.

**Resource limits** — set CPU and memory limits on the cert-analyzer container. Expected memory usage is 50–150MB depending on the number of certificates being tracked.

**LRU cache sizing** — the cert-analyzer maintains three internal LRU caches, each capped at `CACHE_MAX_SIZE` entries (default and minimum: 10,000):

- `known_certs` — parsed certificate metadata, keyed by path + index + serial number
- `processed_paths` — file paths that have been successfully analyzed
- `password_failed_paths` — keystore paths that failed all password attempts

When a cache reaches its cap the least-recently-used entry is evicted. For `known_certs` and `processed_paths` this means an evicted cert will be re-analyzed the next time its file is accessed — correct behaviour for a long-running analyzer. For `password_failed_paths` eviction gives previously-failed keystores a second chance, which is desirable if `JKS_PASSWORD` or `PKCS12_PASSWORD` has since been set.

Each `CertificateInfo` entry in `known_certs` is approximately 500 bytes–1KB depending on label lengths. At the default cap of 10,000 entries this is roughly 5–10MB — well within the container memory limit. On nodes with very large numbers of distinct certificate files, increase `CACHE_MAX_SIZE` and the container memory limit proportionally.

Monitor cache occupancy via Prometheus before hitting the cap:

```promql
cert_analyzer_cache_known_certs_size
cert_analyzer_cache_processed_paths_size
cert_analyzer_cache_password_failed_size
cert_analyzer_cache_max_size
```

The `CertAnalyzerCacheNearCapacity` alert in `kubernetes/prometheus-rules.yaml` fires when `known_certs` exceeds 90% of its cap for more than 10 minutes. If this alert fires, increase `CACHE_MAX_SIZE` in `deployment.yaml` and raise the container memory limit proportionally.

---

## Validation

Before going live, validate the full pipeline end to end in a staging environment:

```bash
# Generate test certificates with various expiry dates
python3 test_analyzer.py

# Manually trigger detection
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /tmp/test.key \
    -out /tmp/test.crt \
    -days 5 \
    -subj "/CN=test.local"
cat /tmp/test.crt

# Confirm the cert appears in metrics
curl -s http://localhost:9090/metrics | grep tls_certificate_expiry_days

# Confirm the alert fires through to your notification channel
```
