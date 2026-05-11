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

# Load Tetragon policies (needed after Tetragon restart)
echo "📜 Loading Tetragon policies..."
POLICIES_LOADED=$(sudo /usr/local/bin/tetra tracingpolicy list 2>/dev/null | wc -l)
if [ "$POLICIES_LOADED" -lt 3 ]; then
    sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/certificate-file-access.yaml 2>/dev/null || true
    sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/openssl-cert-load-fixed.yaml 2>/dev/null || true
    sudo /usr/local/bin/tetra tracingpolicy add tetragon-policies/tls-service-tracking-fixed.yaml 2>/dev/null || true
    echo "   Policies loaded"
else
    echo "   Policies already loaded"
fi
echo ""

# Show baseline
echo "📊 Current monitoring status:"
CERT_COUNT=$(curl -s http://localhost:9090/metrics | grep -c tls_certificate_expiry_days)
echo "   Monitoring $CERT_COUNT certificates"
echo ""

# Generate test certificates
echo "🔧 Generating test certificates..."
python3 test_analyzer.py 2>&1 | grep -E "Generated:|created in:"
echo ""

# Copy to monitored path
echo "📋 Copying certificates to monitored path..."
sudo cp test-certs/*.crt /etc/pki/tls/certs/
echo "   Copied to /etc/pki/tls/certs/"
echo ""

# Trigger detection
echo "🔍 Triggering real-time detection..."
cat /etc/pki/tls/certs/expired.crt /etc/pki/tls/certs/expiring-soon.crt \
    /etc/pki/tls/certs/expiring-week.crt /etc/pki/tls/certs/valid.crt > /dev/null
echo "   Certificates accessed - waiting for eBPF events..."
sleep 3
echo ""

# Show detections
echo "📋 Detection Results:"
sudo podman logs cert-analyzer | tail -30 | grep -E "🔴|⚠️|✅" | grep "pki/tls/certs" || \
    echo "   (Check logs with: sudo podman logs cert-analyzer)"
echo ""

# Show metrics
echo "📈 Prometheus Metrics:"
echo ""
echo "Expired certificates:"
curl -s http://localhost:9090/metrics | grep 'tls_certificate_expired{.*}.*1$' | \
    grep "pki/tls/certs" | head -3 | sed 's/^/  /'
echo ""
echo "Expiring soon (< 7 days):"
curl -s http://localhost:9090/metrics | grep 'tls_certificate_expiring_soon{.*threshold_days="7"}.*1$' | \
    grep "pki/tls/certs" | head -3 | sed 's/^/  /'
echo ""

# Show real-world finding
echo "🔎 Real-world finding on this system:"
sudo podman logs cert-analyzer | grep "🔴 EXPIRED" | grep -v "test-certs\|pki/tls/certs" | head -1 | sed 's/^/  /'
echo ""

echo "======================================"
echo "✅ Demo Complete!"
echo "======================================"
echo ""
echo "Access metrics at: http://localhost:9090/metrics"
echo "View logs: sudo podman logs -f cert-analyzer"
echo ""
echo "💡 TIP: Run './watch-certs.sh' in a separate terminal for live monitoring"
