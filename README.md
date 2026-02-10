# TLS Certificate Expiry Monitor

A comprehensive solution for monitoring TLS certificate expiry using Tetragon (eBPF) and Python, designed for RHEL9 with Podman.

## Overview

This tool monitors TLS certificate usage and expiry in real-time by:
- Using Tetragon (eBPF) to intercept certificate file access and SSL/TLS library calls
- Analyzing certificates to extract expiry information
- Exposing Prometheus metrics for monitoring and alerting
- Providing both event-driven and periodic scanning capabilities

## Architecture

```
┌─────────────────────────────────────────────────┐
│ Kernel Space (eBPF via Tetragon)               │
│ - Intercept TLS operations                      │
│ - Monitor file access to certificates          │
└──────────────────┬──────────────────────────────┘
                   │ Events via gRPC
                   ▼
┌─────────────────────────────────────────────────┐
│ Certificate Analyzer (Python/Podman)           │
│ - Parse X.509 certificates                      │
│ - Extract expiry dates                          │
│ - Generate metrics & alerts                     │
└──────────────────┬──────────────────────────────┘
                   │ Prometheus Metrics
                   ▼
┌─────────────────────────────────────────────────┐
│ Observability Stack (Prometheus/Grafana)       │
└─────────────────────────────────────────────────┘
```

## Features

- 🔍 **Real-time Detection**: Captures certificate access via eBPF
- 📊 **Prometheus Metrics**: Exposes detailed certificate expiry metrics
- ⚠️ **Multi-level Alerts**: 7, 30, and 90-day expiry thresholds
- 🔄 **Periodic Scanning**: Proactively scans certificate directories
- 🐳 **Podman Native**: Designed for RHEL9 with rootless/rootful support
- 🔒 **SELinux Compatible**: Includes SELinux policy module
- 📈 **Grafana Dashboards**: Pre-built visualization templates

## Prerequisites

### System Requirements
- RHEL 9.x or compatible (Rocky Linux, AlmaLinux)
- Kernel 5.x or later (for eBPF support)
- Podman 4.x or later
- Python 3.11+
- Tetragon installed and running

### Install Dependencies

```bash
# Install system packages
sudo dnf install -y \
    podman \
    python3.11 \
    python3-pip \
    gcc \
    python3-devel \
    git

# Verify Podman
podman --version

# Verify Python
python3 --version
```

### Install Tetragon

**Option 1: Kubernetes/OpenShift**
```bash
helm repo add cilium https://helm.cilium.io
helm install tetragon cilium/tetragon -n kube-system
```

**Option 2: Standalone on RHEL9**
```bash
# Download Tetragon binary
TETRAGON_VERSION=v1.0.0
curl -LO https://github.com/cilium/tetragon/releases/download/${TETRAGON_VERSION}/tetragon-${TETRAGON_VERSION}-amd64.tar.gz
tar xzf tetragon-${TETRAGON_VERSION}-amd64.tar.gz

sudo mkdir -p /var/log/tetragon

cat <<EOF | sudo tee /etc/systemd/system/tetragon.service
[Unit]
Description=Tetragon eBPF Security Observability
Documentation=https://tetragon.io/
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tetragon --export-filename /var/log/tetragon/tetragon.log
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF


# Copy BPF files to where Tetragon is actually looking
sudo mkdir -p /usr/local/lib/tetragon/bpf
sudo cp tetragon-v1.0.0-amd64/usr/local/lib/tetragon/bpf/* /usr/local/lib/tetragon/bpf/

# Verify
ls -la /usr/local/lib/tetragon/bpf/ | head -10

# Also copy the config directory (optional but good to have)
sudo mkdir -p /etc/tetragon/tetragon.conf.d
sudo cp tetragon-v1.0.0-amd64/usr/local/lib/tetragon/tetragon.conf.d/* /etc/tetragon/tetragon.conf.d/

# Now start Tetragon
sudo systemctl start tetragon

# Wait a moment for it to start
sleep 3

# Check status
sudo systemctl status tetragon

# Check for the socket
sudo ls -la /var/run/tetragon/tetragon.sock

# If successful, watch the logs briefly
sudo journalctl -u tetragon -n 50

sudo systemctl daemon-reload
sudo systemctl enable --now tetragon
sudo systemctl status tetragon

```

## Quick Start

### 1. Generate Tetragon Protocol Buffers

```bash
chmod +x generate_tetragon_protos.sh
./generate_tetragon_protos.sh
```

This will create a `tetragon/` directory with the necessary Python gRPC files.

### 2. Build the Container Image

```bash
chmod -R a+rX tetragon/
chmod +x build.sh
./build.sh
```

This creates a Podman image: `cert-analyzer:latest`

### 3. Apply Tetragon Tracing Policies

```bash
# If using Kubernetes/OpenShift
kubectl apply -f tetragon-policies/certificate-file-access.yaml
kubectl apply -f tetragon-policies/openssl-cert-load.yaml

# If using standalone Tetragon
sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/certificate-file-access.yaml

sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/openssl-cert-load.yaml

sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/tls-service-tracking.yaml

# Verify they were loaded
sudo /usr/local/bin/tetra tracingpolicy list
```

### 4. Run the Analyzer

**Option A: Rootful Podman (Full system access)**
```bash
chmod +x run-rootful.sh
sudo ./run-rootful.sh
```

**Option B: Systemd Service (Production)**
```bash
# Traditional systemd service
sudo cp systemd/cert-analyzer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cert-analyzer
sudo systemctl status cert-analyzer

# OR modern Quadlet (Podman 4.4+)
sudo cp systemd/cert-analyzer.container /etc/containers/systemd/
sudo systemctl daemon-reload
sudo systemctl enable --now cert-analyzer
sudo systemctl status cert-analyzer
```

### 5. Verify Operation

```bash
# Check container logs
podman logs -f cert-analyzer
# OR with systemd
sudo journalctl -u cert-analyzer -f

# Check metrics endpoint
curl http://localhost:9090/metrics | grep tls_certificate

# View specific metrics
curl -s http://localhost:9090/metrics | grep 'tls_certificate_expiry_days'
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TETRAGON_ADDR` | `localhost:54321` | Tetragon gRPC address (unix:// or tcp://) |
| `METRICS_PORT` | `9090` | Prometheus metrics port |
| `ALERT_THRESHOLD_DAYS` | `30` | Days before expiry to trigger warnings |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `CERT_SCAN_PATHS` | `/etc/ssl,/etc/pki` | Comma-separated paths to scan |
| `SCAN_INTERVAL_SECONDS` | `3600` | Interval between periodic scans |

### Customize Configuration

Edit the run scripts or systemd files to change environment variables:

```bash
# Example: Increase alert threshold to 60 days
-e ALERT_THRESHOLD_DAYS=60 \
-e SCAN_INTERVAL_SECONDS=1800 \
-e LOG_LEVEL=DEBUG
```

## Metrics

The analyzer exposes the following Prometheus metrics on port 9090:

### Gauges

- `tls_certificate_expiry_days` - Days until certificate expiry
  - Labels: `cert_path`, `subject`, `issuer`, `serial`, `process`, `common_name`

- `tls_certificate_expiry_timestamp` - Unix timestamp of certificate expiry
  - Labels: `cert_path`, `subject`, `issuer`, `serial`, `process`, `common_name`

- `tls_certificate_valid_from_timestamp` - Unix timestamp when certificate becomes valid
  - Labels: `cert_path`, `subject`, `issuer`, `serial`, `process`, `common_name`

- `tls_certificate_expired` - Binary indicator if certificate is expired (1=yes, 0=no)
  - Labels: `cert_path`, `process`

- `tls_certificate_expiring_soon` - Binary indicator if expires within threshold
  - Labels: `cert_path`, `process`, `threshold_days`

- `cert_analyzer_healthy` - Health status of analyzer (1=healthy, 0=unhealthy)

- `cert_analyzer_last_event_timestamp` - Unix timestamp of last processed event

### Counters

- `tls_certificate_events_total` - Total certificate events detected
  - Labels: `event_type`, `status`

- `tls_certificate_analysis_errors_total` - Total analysis errors
  - Labels: `error_type`

## Prometheus Integration

### Prometheus Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'cert-expiry-monitor'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 30s
```

### Alerting Rules

The repository includes pre-configured alerting rules in `kubernetes/prometheus-rules.yaml`:

- **CertificateExpiringSoon**: Triggers when certificate expires in < 30 days
- **CertificateExpiringCritical**: Triggers when certificate expires in < 7 days  
- **CertificateExpired**: Triggers when certificate has expired

Apply to Kubernetes/OpenShift:
```bash
kubectl apply -f kubernetes/prometheus-rules.yaml
```

For standalone Prometheus, copy the rules section to your `prometheus.yml`.

## Grafana Dashboard

A pre-built dashboard is available in `examples/grafana-dashboard.json`.

### Import Dashboard

1. Open Grafana
2. Go to Dashboards → Import
3. Upload `examples/grafana-dashboard.json`
4. Select your Prometheus datasource

### Dashboard Features

- Certificate expiry timeline
- List of certificates expiring soon
- Certificate event rate graphs
- Error tracking
- Health status

## SELinux Configuration (RHEL9)

If running with SELinux enforcing mode, you may need to install the custom policy:

```bash
cd selinux/
sudo checkmodule -M -m -o cert-analyzer.mod cert-analyzer.te
sudo semodule_package -o cert-analyzer.pp -m cert-analyzer.mod
sudo semodule -i cert-analyzer.pp

# Verify installation
sudo semodule -l | grep cert-analyzer
```

## Testing

### Generate Test Certificates

```bash
python3 test_analyzer.py
```

This creates test certificates with various expiry dates in `/tmp/test-certs-*/`

### Manual Testing

```bash
# Create a test certificate
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /tmp/test.key \
    -out /tmp/test.crt \
    -days 10 \
    -subj "/CN=test.local"

# Trigger detection by reading it
cat /tmp/test.crt

# Check logs for detection
podman logs cert-analyzer | grep test.crt
```

### Verify Metrics

```bash
# Check if certificate was detected
curl -s http://localhost:9090/metrics | grep 'cert_path="/tmp/test.crt"'

# Check expiry days for all certificates
curl -s http://localhost:9090/metrics | \
    grep tls_certificate_expiry_days | \
    grep -v '#'
```

## Kubernetes/OpenShift Deployment

For Kubernetes or OpenShift environments:

```bash
# Deploy as DaemonSet
kubectl apply -f kubernetes/deployment.yaml

# Add Prometheus monitoring
kubectl apply -f kubernetes/service-monitor.yaml

# Add alerting rules
kubectl apply -f kubernetes/prometheus-rules.yaml

# Verify deployment
kubectl get pods -n kube-system -l app=cert-expiry-monitor
kubectl logs -n kube-system -l app=cert-expiry-monitor -f
```

## Troubleshooting

### Container won't start

```bash
# Check Podman logs
podman logs cert-analyzer

# Check if Tetragon socket is accessible
ls -la /run/cilium/tetragon/tetragon.sock

# Verify Tetragon is running
ps aux | grep tetragon
```

### No events detected

```bash
# Check Tetragon policies are applied
kubectl get tracingpolicies
# OR for standalone
ls -la /etc/tetragon/policies/

# Verify Tetragon is capturing events
sudo tetra getevents

# Check analyzer is connected
podman logs cert-analyzer | grep "Connected to Tetragon"
```

### Permission errors

```bash
# For rootless, ensure socket permissions
sudo chmod 666 /run/cilium/tetragon/tetragon.sock

# For SELinux issues
sudo ausearch -m avc -ts recent | grep cert-analyzer
sudo audit2allow -a -M cert-analyzer-custom
sudo semodule -i cert-analyzer-custom.pp
```

### Metrics not appearing

```bash
# Verify metrics endpoint is accessible
curl http://localhost:9090/metrics

# Check if port is bound
ss -tlnp | grep 9090

# Verify Prometheus is scraping
# Check Prometheus UI → Status → Targets
```

### High memory usage

```bash
# Reduce scan frequency
-e SCAN_INTERVAL_SECONDS=7200

# Limit scan paths
-e CERT_SCAN_PATHS=/etc/pki/tls

# Reduce log verbosity
-e LOG_LEVEL=WARNING
```

## Advanced Usage

### Custom Certificate Paths

```bash
# Monitor additional directories
podman run -d \
    --name cert-analyzer \
    -v /opt/certs:/opt/certs:ro,Z \
    -e CERT_SCAN_PATHS=/etc/ssl,/etc/pki,/opt/certs \
    cert-analyzer:latest
```

### Integration with cert-manager

```bash
# Monitor Kubernetes secrets containing certificates
-e CERT_SCAN_PATHS=/var/run/secrets/kubernetes.io/serviceaccount
```

## Performance Considerations

- **eBPF Overhead**: Minimal (<1% CPU typically)
- **Memory**: ~50-150MB depending on certificate count
- **Disk I/O**: Negligible (only reads certificates when accessed)
- **Network**: ~1KB/s for Prometheus scraping

### Scaling

For large deployments:
- Run as DaemonSet in Kubernetes (one per node)
- Use Prometheus federation for multi-cluster setups
- Adjust `SCAN_INTERVAL_SECONDS` to reduce load

## Security Considerations

- Container runs as non-root user (UID 1001)
- Read-only access to certificate directories
- SELinux policy restricts access to necessary files only
- No secrets stored in container
- Metrics endpoint is HTTP (use reverse proxy for HTTPS)

## License

MIT License

## Support

For issues or questions, please open an issue in the repository.

## Acknowledgments

- [Cilium Tetragon](https://github.com/cilium/tetragon) - eBPF security observability
- [cryptography](https://cryptography.io/) - Python cryptography library
- [Prometheus](https://prometheus.io/) - Monitoring and alerting

## Changelog

### v1.0.0 (2025-02-10)
- Initial release
- Support for RHEL9/Podman
- Real-time certificate monitoring
- Prometheus metrics integration
- Grafana dashboard
- SELinux policy
- Systemd integration
