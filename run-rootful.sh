#!/bin/bash
set -e

echo "Starting Certificate Analyzer (rootful mode)..."

# Stop existing container if running
sudo podman stop cert-analyzer 2>/dev/null || true
sudo podman rm cert-analyzer 2>/dev/null || true

# Run with elevated privileges (requires sudo)
sudo podman run -d \
    --name cert-analyzer \
    --privileged \
    --network host \
    --pid host \
    -v /var/run/tetragon/tetragon.sock:/var/run/tetragon/tetragon.sock:Z \
    -v /:/host:ro,rslave \
    -e TETRAGON_ADDR=unix:///var/run/tetragon/tetragon.sock \
    -e METRICS_PORT=9090 \
    -e ALERT_THRESHOLD_DAYS=30 \
    -e LOG_LEVEL=DEBUG \
    -e CERT_SCAN_PATHS=/host/etc/ssl,/host/etc/pki,/host/etc/kubernetes/pki \
    -e SCAN_INTERVAL_SECONDS=3600 \
    localhost/cert-analyzer:latest

echo ""
echo "✅ Container started!"
echo ""
echo "View logs:    sudo podman logs -f cert-analyzer"
echo "View metrics: curl http://localhost:9090/metrics"
echo "Stop:         sudo podman stop cert-analyzer"
