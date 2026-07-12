#!/bin/bash
set -euo pipefail

PROMETHEUS_VERSION="2.53.4"
PROMETHEUS_PORT="9091"
CERT_ANALYZER_PORT="9090"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/prometheus"
SERVICE_FILE="/etc/systemd/system/prometheus.service"

GRAFANA_URL="${GRAFANA_URL:-http://localhost:3000}"
GRAFANA_USER="${GRAFANA_USER:-admin}"
GRAFANA_PASS="${GRAFANA_PASS:-admin}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASHBOARD_JSON="${SCRIPT_DIR}/examples/grafana-dashboard.json"

echo "============================================"
echo " Prometheus ${PROMETHEUS_VERSION} Installer"
echo " for CertSight / RHEL 9"
echo "============================================"

# ── Already installed? ────────────────────────────────────────────────────────
PROMETHEUS_ALREADY_RUNNING=false
if systemctl is-active --quiet prometheus 2>/dev/null; then
    echo "prometheus.service is already running — skipping install steps."
    PROMETHEUS_ALREADY_RUNNING=true
fi

if [ "${PROMETHEUS_ALREADY_RUNNING}" = false ]; then
    # ── Download ──────────────────────────────────────────────────────────────
    ARCHIVE="prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz"
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    echo ""
    echo "[1/5] Downloading Prometheus ${PROMETHEUS_VERSION}..."
    curl -fsSL \
        "https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/${ARCHIVE}" \
        -o "${TMPDIR}/${ARCHIVE}"

    # ── Extract and install binaries ──────────────────────────────────────────
    echo "[2/5] Installing binaries to ${INSTALL_DIR}..."
    tar -xzf "${TMPDIR}/${ARCHIVE}" -C "${TMPDIR}"
    SRCDIR="${TMPDIR}/prometheus-${PROMETHEUS_VERSION}.linux-amd64"

    sudo install -m 755 "${SRCDIR}/prometheus" "${INSTALL_DIR}/prometheus"
    sudo install -m 755 "${SRCDIR}/promtool"   "${INSTALL_DIR}/promtool"

    # ── Write config ──────────────────────────────────────────────────────────
    echo "[3/5] Writing config to ${CONFIG_DIR}/prometheus.yml..."
    sudo mkdir -p "${CONFIG_DIR}"

    if [ ! -f "${CONFIG_DIR}/prometheus.yml" ]; then
        sudo tee "${CONFIG_DIR}/prometheus.yml" > /dev/null <<EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: cert-analyzer
    # Matches [metrics] min_scrape_interval_seconds in cert-analyzer.conf (60s) --
    # scraping faster than that just re-polls a replayed response and renders
    # as a staircase in Grafana instead of a smooth line.
    scrape_interval: 60s
    static_configs:
      - targets: ['localhost:${CERT_ANALYZER_PORT}']
EOF
        echo "    Written ${CONFIG_DIR}/prometheus.yml"
    else
        echo "    ${CONFIG_DIR}/prometheus.yml already exists — left unchanged."
    fi

    # ── Write systemd unit ────────────────────────────────────────────────────
    echo "[4/5] Installing systemd service..."
    sudo tee "${SERVICE_FILE}" > /dev/null <<EOF
[Unit]
Description=Prometheus monitoring server
Documentation=https://prometheus.io/docs
After=network.target

[Service]
ExecStart=${INSTALL_DIR}/prometheus \\
  --config.file=${CONFIG_DIR}/prometheus.yml \\
  --web.listen-address=:${PROMETHEUS_PORT} \\
  --storage.tsdb.path=/var/lib/prometheus \\
  --storage.tsdb.retention.time=15d
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    sudo mkdir -p /var/lib/prometheus
    sudo systemctl daemon-reload
    sudo systemctl enable --now prometheus

    # ── Verify Prometheus ─────────────────────────────────────────────────────
    echo "[5/6] Verifying Prometheus..."
    sleep 3
    if ! systemctl is-active --quiet prometheus; then
        echo "ERROR: prometheus.service failed to start."
        sudo journalctl -u prometheus -n 20 --no-pager
        exit 1
    fi
    echo "    Prometheus is running on port ${PROMETHEUS_PORT}"
fi

# ── Import Grafana datasource and dashboard ───────────────────────────────────
echo "[6/6] Importing CertSight dashboard into Grafana..."

if ! systemctl is-active --quiet grafana-server 2>/dev/null; then
    echo "    Grafana is not running — skipping dashboard import."
    echo "    Run this script again after starting grafana-server, or import"
    echo "    ${DASHBOARD_JSON} manually via the Grafana UI."
else
    if [ ! -f "${DASHBOARD_JSON}" ]; then
        echo "    Dashboard JSON not found at ${DASHBOARD_JSON} — skipping import."
    else
        # Create the Prometheus datasource (ignore conflict if it already exists)
        DS_RESPONSE=$(curl -sf -X POST \
            -H "Content-Type: application/json" \
            -u "${GRAFANA_USER}:${GRAFANA_PASS}" \
            "${GRAFANA_URL}/api/datasources" \
            -d "{
                \"name\": \"Prometheus\",
                \"type\": \"prometheus\",
                \"url\":  \"http://localhost:${PROMETHEUS_PORT}\",
                \"access\": \"proxy\",
                \"isDefault\": true
            }" 2>&1 || true)

        if echo "${DS_RESPONSE}" | grep -q '"already exists"'; then
            echo "    Prometheus datasource already exists in Grafana."
        elif echo "${DS_RESPONSE}" | grep -qi '"id"'; then
            echo "    Prometheus datasource created in Grafana."
        else
            echo "    Warning: unexpected response creating datasource: ${DS_RESPONSE}"
        fi

        # Build the import payload and POST it using Python (avoids jq dependency)
        IMPORT_RESULT=$(python3 - <<PYEOF
import json, urllib.request, urllib.error, base64

with open('${DASHBOARD_JSON}') as f:
    db = json.load(f)

# Strip import-wizard metadata before sending to the API
for key in ('__inputs', '__elements', '__requires'):
    db.pop(key, None)
db['id'] = None  # let Grafana assign a new id

payload = json.dumps({
    'dashboard': db,
    'overwrite': True,
    'folderId': 0,
}).encode()

creds = base64.b64encode(b'${GRAFANA_USER}:${GRAFANA_PASS}').decode()
req = urllib.request.Request(
    '${GRAFANA_URL}/api/dashboards/import',
    data=payload,
    headers={'Content-Type': 'application/json', 'Authorization': f'Basic {creds}'},
    method='POST',
)
try:
    with urllib.request.urlopen(req) as resp:
        result = json.load(resp)
        print('ok:' + result.get('url', ''))
except urllib.error.HTTPError as e:
    body = e.read().decode()
    print('err:' + body)
PYEOF
        )

        if echo "${IMPORT_RESULT}" | grep -q '^ok:'; then
            DASHBOARD_URL="${GRAFANA_URL}$(echo "${IMPORT_RESULT}" | sed 's/^ok://')"
            echo "    Dashboard imported: ${DASHBOARD_URL}"
        else
            echo "    Warning: dashboard import failed: $(echo "${IMPORT_RESULT}" | sed 's/^err://')"
            echo "    You can import it manually: Grafana → Dashboards → Import → ${DASHBOARD_JSON}"
        fi
    fi
fi

echo ""
echo "============================================"
echo " Prometheus is running on port ${PROMETHEUS_PORT}"
echo " Scraping cert-analyzer on port ${CERT_ANALYZER_PORT}"
echo ""
echo " CertSight dashboard: ${GRAFANA_URL}/d/certsight-v1"
echo ""
echo " Override Grafana credentials if needed:"
echo "   GRAFANA_USER=admin GRAFANA_PASS=<pass> bash $0"
echo "============================================"
