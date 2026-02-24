# Production Deployment Guide

## Overview

This document describes the steps and topology required to deploy the TLS Certificate Expiry Monitor into a production Kubernetes environment.

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
                                              │ scrape
                                    ┌─────────▼──────────┐
                                    │    Prometheus      │
                                    │  Stores metrics &  │
                                    │  evaluates rules   │
                                    └─────────┬──────────┘
                                              │ fires alerts
                                    ┌─────────▼──────────┐
                                    │    Alertmanager    │
                                    │  Routes & notifies │
                                    └─────────┬──────────┘
                                              │
                                    ┌─────────▼──────────┐
                                    │      Grafana       │
                                    │  Visualises metrics│
                                    └────────────────────┘
```

**Tetragon** is the eyes — it uses eBPF to intercept certificate file access at the kernel level and exposes events via a gRPC socket on each node.

**cert-analyzer** is the brain — it connects to the local Tetragon gRPC socket, parses X.509 certificates, and publishes Prometheus metrics on port 9090.

Both are deployed as DaemonSets so that each node has exactly one of each, co-located and paired via the local socket. Running cert-analyzer as a regular Deployment would risk it landing on a different node to its Tetragon instance, breaking the gRPC connection.

---

## Deployment Steps

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

This creates three alerts:

- `CertificateExpiringSoon` — certificate expires in fewer than 30 days
- `CertificateExpiringCritical` — certificate expires in fewer than 7 days
- `CertificateExpired` — certificate has already expired

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

**Prometheus storage** — configure Prometheus with sufficient retention for certificate expiry trending. 90 days is a reasonable minimum given the alerting thresholds in use.

**Scan interval** — the default `SCAN_INTERVAL_SECONDS` is 3600 (1 hour). After a process restart there will be a gap before metrics are repopulated. Lower this value if a faster recovery time is required.

**Log aggregation** — the analyzer logs to stdout. Ensure your existing log shipping setup (Fluentd, Filebeat, etc.) is configured to collect from the cert-analyzer pods.

**Alertmanager silences** — when deliberately rotating a certificate, create an Alertmanager silence for that cert's `cert_path` label to suppress alerts during the rotation window.

**Resource limits** — set CPU and memory limits on the cert-analyzer container. Expected memory usage is 50–150MB depending on the number of certificates being tracked.

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
