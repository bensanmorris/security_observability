# TLS Certificate Expiry Monitor - Quick Start Guide

This guide assumes you've already completed the initial setup from the main README.md. Use this for quick restarts after system reboots or for demos.

## Prerequisites

Before starting, ensure you've already:
- ✅ Installed Tetragon (v1.0.0 or later)
- ✅ Built the cert-analyzer container image
- ✅ Applied Tetragon tracing policies

If you haven't done the initial setup, see the main [README.md](README.md).

---

## Quick Start (3 Commands)

### 1. Start Tetragon (if not running)

```bash
sudo systemctl start tetragon

# Verify it's running
sudo systemctl status tetragon
```

### 2. Start the Certificate Analyzer

```bash
sudo ./run-rootful.sh
```

### 3. Verify Operation

```bash
# Check logs
sudo podman logs cert-analyzer | tail -20

# Check metrics
curl -s http://localhost:9090/metrics | grep tls_certificate_expiry_days | head -5
```

**Done!** The monitor is now running.

---

## Demo Workflow (5 minutes)

### Step 0: Set Up Live Log Monitoring (Recommended)

**In a separate terminal**, run the colorized log watcher:

```bash
./watch-certs.sh
```

Keep this running during the demo to show real-time detection!

---

### Step 1: Show Baseline

**In your main terminal:**

```bash
echo "Currently monitoring certificates:"
curl -s http://localhost:9090/metrics | grep -c tls_certificate_expiry_days
echo "certificates tracked"
```

### Step 2: Generate Test Certificates

```bash
python3 test_analyzer.py
```

This creates certificates in `./test-certs/`:
- `expired.crt` - Expired 10 days ago 🔴
- `expiring-soon.crt` - Expires in 5 days 🔴
- `expiring-week.crt` - Expires in 7 days ⚠️
- `valid.crt` - Valid for 1 year ✅

```bash
# Verify they're created
ls -la test-certs/
```

### Step 3: Copy Certificates to Monitored Path

```bash
# Copy test certificates to a path the analyzer monitors
sudo cp test-certs/*.crt /etc/pki/tls/certs/

# Verify they're copied
ls -la /etc/pki/tls/certs/*.crt | tail -6
```

### Step 3.5: Load Tetragon Policies

**Important**: Policies need to be loaded after each Tetragon restart.

```bash
# Load the certificate monitoring policies
sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/certificate-file-access.yaml
sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/openssl-cert-load-fixed.yaml
sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/tls-service-tracking-fixed.yaml

# Verify they're loaded
sudo /usr/local/bin/tetra tracingpolicy list
```

You should see:
```
[1] certificate-file-access enabled:true filterID:0 namespace:(global) sensors:gkp-sensor-1
[2] openssl-cert-load enabled:true filterID:0 namespace:(global) sensors:gkp-sensor-2
[3] tls-service-tracking enabled:true filterID:0 namespace:(global) sensors:gkp-sensor-3
```

### Step 4: Trigger Real-Time Detection

```bash
# Access the test certificates to trigger eBPF detection
cat /etc/pki/tls/certs/expired.crt
cat /etc/pki/tls/certs/expiring-soon.crt
cat /etc/pki/tls/certs/expiring-week.crt
cat /etc/pki/tls/certs/valid.crt
```

**Watch Terminal 2** - You'll see real-time detection as certificates are accessed!

### Step 5: View Detection Results

```bash
# Show real-time detections in logs (if not watching in Terminal 2)
sudo podman logs cert-analyzer | tail -30 | grep -E "🔴|⚠️|✅"
```

**Expected output:**
```
🔴 EXPIRED: Certificate /host/etc/pki/tls/certs/expired.crt expired 10.0 days ago
🔴 CRITICAL: Certificate /host/etc/pki/tls/certs/expiring-soon.crt expires in 5.0 days
⚠️  WARNING: Certificate /host/etc/pki/tls/certs/expiring-week.crt expires in 7.0 days
✅ OK: Certificate /host/etc/pki/tls/certs/valid.crt valid for 365.0 more days
```

### Step 6: Show Prometheus Metrics

```bash
# Expired certificates
echo "Expired certificates:"
curl -s http://localhost:9090/metrics | grep '^tls_certificate_expiry_days' | awk '$NF < 0' | head -3

# Certificates expiring within 7 days
echo -e "\nCertificates expiring soon (< 7 days):"
curl -s http://localhost:9090/metrics | grep '^tls_certificate_expiry_days' | awk '$NF > 0 && $NF < 7' | head -3

# Certificates expiring within 30 days
echo -e "\nCertificates expiring soon (< 30 days):"
curl -s http://localhost:9090/metrics | grep '^tls_certificate_expiry_days' | awk '$NF > 0 && $NF < 30' | head -3
```

---

## Two-Terminal Demo Setup

For the best demo experience, use two terminals side-by-side:

**Terminal 1 (Main Commands):**
```bash
./quick-demo.sh
```

**Terminal 2 (Live Monitoring):**
```bash
./watch-certs.sh
```

This shows real-time detection as you run commands in Terminal 1!

---

## Useful Commands

### Monitor Live Activity

```bash
# Color-coded live log monitoring (recommended for demos)
./watch-certs.sh

# Simple tail of logs
sudo podman logs -f cert-analyzer

# Show only certificate detections
sudo podman logs -f cert-analyzer | grep -E "🔴|⚠️|✅"

# Show logs from last 5 minutes
sudo podman logs cert-analyzer --since 5m
```

### Check Status

```bash
# Tetragon status
sudo systemctl status tetragon

# Analyzer status
sudo podman ps | grep cert-analyzer

# View live logs
sudo podman logs -f cert-analyzer
```

### View Metrics

```bash
# All metrics
curl http://localhost:9090/metrics

# Certificate expiry metrics only
curl -s http://localhost:9090/metrics | grep tls_certificate

# Count monitored certificates
curl -s http://localhost:9090/metrics | grep -c tls_certificate_expiry_days
```

### Stop Services

```bash
# Stop analyzer
sudo podman stop cert-analyzer
sudo podman rm cert-analyzer

# Stop Tetragon (optional)
sudo systemctl stop tetragon
```

### Restart Everything

```bash
# Restart Tetragon
sudo systemctl restart tetragon

# Restart analyzer
sudo podman stop cert-analyzer
sudo podman rm cert-analyzer
sudo ./run-rootful.sh
```

---

## Troubleshooting Quick Fixes

### Analyzer won't start

```bash
# Check if old container is running
sudo podman ps -a | grep cert-analyzer

# Remove old container
sudo podman stop cert-analyzer
sudo podman rm cert-analyzer

# Restart
sudo ./run-rootful.sh
```

### Tetragon not running

```bash
# Check status
sudo systemctl status tetragon

# View recent errors
sudo journalctl -u tetragon -n 50

# Restart
sudo systemctl restart tetragon
```

### No metrics appearing

```bash
# Verify port is listening
ss -tlnp | grep 9090

# Check analyzer logs
sudo podman logs cert-analyzer | tail -50

# Verify Tetragon connection
sudo podman logs cert-analyzer | grep "Connected to Tetragon"
```

### Policies not loaded

```bash
# List current policies
sudo /usr/local/bin/tetra tracingpolicy list

# Re-apply if needed
sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/certificate-file-access.yaml
sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/openssl-cert-load-fixed.yaml
sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/tls-service-tracking-fixed.yaml
```

---

### Policies not loaded

```bash
# Check if policies are loaded
sudo /usr/local/bin/tetra tracingpolicy list

# If empty, reload them
sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/certificate-file-access.yaml
sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/openssl-cert-load-fixed.yaml
sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/tls-service-tracking-fixed.yaml

# Verify
sudo /usr/local/bin/tetra tracingpolicy list
```

**Note**: Policies are lost when Tetragon restarts and must be reloaded.

## Demo Talking Points

1. **eBPF-based monitoring** - Zero application changes, kernel-level visibility
2. **Real-time detection** - Certificates detected as they're accessed
3. **Proactive scanning** - Hourly scans catch unused certificates
4. **Production-ready** - Prometheus metrics, systemd integration, SELinux compatible
5. **Multi-level alerts** - 7, 30, and 90-day warning thresholds

---

## Next Steps

After the demo, you can:

- **Integrate with Prometheus**: See [Prometheus Integration](../README.md#prometheus-integration)
- **Set up Grafana dashboards**: See [Grafana Dashboard](../README.md#grafana-dashboard)
- **Deploy to Kubernetes**: See [Kubernetes DaemonSet Deployment](DEPLOYMENT-README.md#kubernetes-daemonset-deployment)
- **Deploy to OpenShift**: See [OpenShift Deployment Guide](OPENSHIFT-DEPLOYMENT-README.md)
- **Upgrade to Tetragon v1.6**: For uprobe support and TLS handshake monitoring

---

## Quick Reference

| Command | Purpose |
|---------|---------|
| `sudo systemctl start tetragon` | Start Tetragon service |
| `sudo ./run-rootful.sh` | Start analyzer |
| `./watch-certs.sh` | Monitor live with colors (Terminal 2) |
| `sudo podman logs -f cert-analyzer` | View live logs |
| `curl http://localhost:9090/metrics` | View metrics |
| `python3 test_analyzer.py` | Generate test certificates |
| `./quick-demo.sh` | Run automated demo |

---

For full documentation, see [README.md](README.md)
