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

### Step 1: Show Baseline

```bash
echo "Currently monitoring certificates:"
curl -s http://localhost:9090/metrics | grep -c tls_certificate_expiry_days
echo "certificates tracked"
```

### Step 2: Generate Test Certificates

```bash
python3 test_analyzer.py
```

This creates certificates in `/tmp/test-certs-*/`:
- `expired.crt` - Expired 10 days ago 🔴
- `expiring-soon.crt` - Expires in 5 days 🔴
- `expiring-week.crt` - Expires in 7 days ⚠️
- `valid.crt` - Valid for 1 year ✅

### Step 3: Trigger Real-Time Detection

```bash
# Access the test certificates to trigger eBPF detection
CERT_DIR=$(ls -d /tmp/test-certs-* | tail -1)
cat $CERT_DIR/expired.crt
cat $CERT_DIR/expiring-soon.crt
cat $CERT_DIR/expiring-week.crt
cat $CERT_DIR/valid.crt
```

### Step 4: View Detection Results

```bash
# Show real-time detections in logs
sudo podman logs cert-analyzer | tail -20 | grep -E "🔴|⚠️|✅"
```

**Expected output:**
```
🔴 EXPIRED: Certificate /tmp/test-certs-.../expired.crt expired 10.0 days ago
🔴 CRITICAL: Certificate /tmp/test-certs-.../expiring-soon.crt expires in 5.0 days
⚠️  WARNING: Certificate /tmp/test-certs-.../expiring-week.crt expires in 7.0 days
✅ OK: Certificate /tmp/test-certs-.../valid.crt valid for 365.0 more days
```

### Step 5: Show Prometheus Metrics

```bash
# Expired certificates
echo "Expired certificates:"
curl -s http://localhost:9090/metrics | grep 'tls_certificate_expired.*1$' | head -3

# Certificates expiring within 7 days
echo -e "\nCertificates expiring soon (< 7 days):"
curl -s http://localhost:9090/metrics | grep 'tls_certificate_expiring_soon.*"7".*1$' | head -3

# Certificates expiring within 30 days
echo -e "\nCertificates expiring soon (< 30 days):"
curl -s http://localhost:9090/metrics | grep 'tls_certificate_expiring_soon.*"30".*1$' | head -3
```

---

## One-Command Demo

Create an automated demo script:

```bash
cat > quick-demo.sh << 'EOF'
#!/bin/bash
set -e

echo "======================================"
echo "TLS Certificate Expiry Monitor Demo"
echo "======================================"
echo ""

# Ensure services are running
echo "Starting services..."
sudo systemctl is-active --quiet tetragon || sudo systemctl start tetragon
sudo podman ps | grep -q cert-analyzer || sudo ./run-rootful.sh
sleep 3

echo "✅ Services running"
echo ""

# Show baseline
echo "📊 Current monitoring status:"
CERT_COUNT=$(curl -s http://localhost:9090/metrics | grep -c tls_certificate_expiry_days)
echo "   Monitoring $CERT_COUNT certificates"
echo ""

# Generate test certificates
echo "🔧 Generating test certificates..."
python3 test_analyzer.py 2>&1 | grep -E "Generated:|created in:"
CERT_DIR=$(ls -d /tmp/test-certs-* | tail -1)
echo ""

# Trigger detection
echo "🔍 Triggering real-time detection..."
cat $CERT_DIR/expired.crt $CERT_DIR/expiring-soon.crt $CERT_DIR/expiring-week.crt $CERT_DIR/valid.crt > /dev/null
sleep 2
echo "   Certificates accessed - waiting for eBPF events..."
sleep 1
echo ""

# Show detections
echo "📋 Detection Results:"
sudo podman logs cert-analyzer | tail -20 | grep -E "🔴|⚠️|✅" || echo "   (Check logs with: sudo podman logs cert-analyzer)"
echo ""

# Show metrics
echo "📈 Prometheus Metrics:"
echo ""
echo "Expired certificates:"
curl -s http://localhost:9090/metrics | grep 'tls_certificate_expired{.*}.*1$' | head -3 | sed 's/^/  /'
echo ""
echo "Expiring soon (< 7 days):"
curl -s http://localhost:9090/metrics | grep 'tls_certificate_expiring_soon{.*threshold_days="7"}.*1$' | head -3 | sed 's/^/  /'
echo ""

# Show real-world finding
echo "🔎 Real-world finding on this system:"
sudo podman logs cert-analyzer | grep "🔴 EXPIRED" | grep -v "test-certs" | head -1 | sed 's/^/  /'
echo ""

echo "======================================"
echo "✅ Demo Complete!"
echo "======================================"
echo ""
echo "Access metrics at: http://localhost:9090/metrics"
echo "View logs: sudo podman logs -f cert-analyzer"
EOF

chmod +x quick-demo.sh
```

**Run the demo:**
```bash
./quick-demo.sh
```

---

## Useful Commands

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

## Demo Talking Points

1. **eBPF-based monitoring** - Zero application changes, kernel-level visibility
2. **Real-time detection** - Certificates detected as they're accessed
3. **Proactive scanning** - Hourly scans catch unused certificates
4. **Production-ready** - Prometheus metrics, systemd integration, SELinux compatible
5. **Multi-level alerts** - 7, 30, and 90-day warning thresholds

---

## Next Steps

After the demo, you can:

- **Integrate with Prometheus**: See [Prometheus Integration](README.md#prometheus-integration)
- **Set up Grafana dashboards**: See [Grafana Dashboard](README.md#grafana-dashboard)
- **Deploy to Kubernetes**: See [Kubernetes Deployment](README.md#kubernetesopenshift-deployment)
- **Upgrade to Tetragon v1.6**: For uprobe support and TLS handshake monitoring

---

## Quick Reference

| Command | Purpose |
|---------|---------|
| `sudo systemctl start tetragon` | Start Tetragon service |
| `sudo ./run-rootful.sh` | Start analyzer |
| `sudo podman logs -f cert-analyzer` | View live logs |
| `curl http://localhost:9090/metrics` | View metrics |
| `python3 test_analyzer.py` | Generate test certificates |
| `./quick-demo.sh` | Run automated demo |

---

For full documentation, see [README.md](README.md)
