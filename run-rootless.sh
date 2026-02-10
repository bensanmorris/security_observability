#!/bin/bash
set -e

echo "Starting Certificate Analyzer (rootless mode)..."

# Stop existing container if running
podman stop cert-analyzer 2>/dev/null || true
podman rm cert-analyzer 2>/dev/null || true

# Run in rootless mode with necessary mounts
podman run -d \
    --name cert-analyzer \
    --userns=keep-id \
    -v /run/cilium/tetragon/tetragon.sock:/var/run/cilium/tetragon/tetragon.sock:Z \
    -v /etc/ssl:/host/etc/ssl:ro,Z \
    -v /etc/pki:/host/etc/pki:ro,Z \
    -p 9090:9090 \
    -e TETRAGON_ADDR=unix:///var/run/cilium/tetragon/tetragon.sock \
    -e METRICS_PORT=9090 \
    -e ALERT_THRESHOLD_DAYS=30 \
    -e LOG_LEVEL=INFO \
    -e CERT_SCAN_PATHS=/host/etc/ssl,/host/etc/pki \
    -e SCAN_INTERVAL_SECONDS=3600 \
    cert-analyzer:latest

echo ""
echo "✅ Container started!"
echo ""
echo "View logs:    podman logs -f cert-analyzer"
echo "View metrics: curl http://localhost:9090/metrics"
echo "Stop:         podman stop cert-analyzer"
