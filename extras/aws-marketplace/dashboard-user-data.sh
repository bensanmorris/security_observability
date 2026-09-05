#!/bin/bash
# EC2 user-data / AMI build script for the CertSight Dashboard product:
# Prometheus (fleet-discovery via EC2 tags, no manual target list) + Grafana
# (real login required) + certsight-test-server running in --mode explorer
# (read-only fleet explorers only -- no Kafka, no unauthenticated action
# endpoints). Pairs with one or more CertSight Analyzer instances (see
# analyzer-user-data.sh) reachable on :9090.
#
# This is the Dashboard half of extras/aws-marketplace/'s two-AMI split (see
# extras/aws-marketplace/README.md). extras/aws-demo/user-data.sh (the
# existing single-box demo, which still runs certsight-test-server in its
# original full/Kafka-backed mode) is separate and untouched by this file.
#
# Runs as root via cloud-init on first boot, or as the install step of the
# Packer build that bakes the CertSight Dashboard AMI.
#
# Progress/errors: /var/log/certsight-dashboard-install.log

set -uo pipefail
exec > >(tee -a /var/log/certsight-dashboard-install.log) 2>&1
set -x

CERTSIGHT_VERSION="${CERTSIGHT_VERSION:-v0.96}"
REPO_URL="https://github.com/bensanmorris/security_observability.git"
RELEASE_BASE="https://github.com/bensanmorris/security_observability/releases/download/${CERTSIGHT_VERSION}"
WORKDIR="/opt/certsight-install"
mkdir -p "${WORKDIR}"
cd "${WORKDIR}"

# EC2 fleet-discovery tag: every CertSight Analyzer instance in this
# region/VPC must carry this tag for Prometheus's ec2_sd_configs below to
# find it. Fixed, not customer-configurable, for this first version -- see
# analyzer-user-data.sh / cloudformation.yaml, which apply it at instance
# launch (a tag is EC2 resource metadata set via the API, not something an
# instance can set on itself from inside).
ANALYZER_TAG_KEY="certsight-role"
ANALYZER_TAG_VALUE="analyzer"
ANALYZER_METRICS_PORT="9090"
PROMETHEUS_PORT="9091"

echo "=== [1/7] Base packages ==="
dnf -y install git curl tar jq policycoreutils-python-utils firewalld python3 || true
systemctl enable --now firewalld || true

echo "=== [2/7] Local firewall (the CertSight Dashboard security group is the primary control -- see cloudformation.yaml -- but firewalld runs on this AMI too) ==="
if systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-port=3000/tcp   # Grafana
    firewall-cmd --permanent --add-port=8090/tcp   # certsight-test-server explorer pages
    firewall-cmd --reload
fi

echo "=== [3/7] CertSight source (for extras/examples/grafana-dashboard.json + test-server) ==="
git clone --depth 1 --branch "${CERTSIGHT_VERSION}" "${REPO_URL}" certsight-src

echo "=== [4/7] Region (IMDSv2 -- token required, matches this AMI's MetadataOptions HttpTokens=required) ==="
IMDS_TOKEN="$(curl -fsSL -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")"
AWS_REGION="$(curl -fsSL -H "X-aws-ec2-metadata-token: ${IMDS_TOKEN}" "http://169.254.169.254/latest/meta-data/placement/region")"
if [[ -z "${AWS_REGION}" ]]; then
    echo "ERROR: could not determine region from instance metadata -- Prometheus ec2_sd_configs cannot be written without it."
    exit 1
fi
echo "    Region: ${AWS_REGION}"

echo "=== [5/7] Prometheus (fleet discovery via EC2 tags, no manual target list) ==="
PROMETHEUS_VERSION="2.53.4"
ARCHIVE="prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz"
curl -fsSL "https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/${ARCHIVE}" -o "${ARCHIVE}"
tar -xzf "${ARCHIVE}"
install -m 755 "prometheus-${PROMETHEUS_VERSION}.linux-amd64/prometheus" /usr/local/bin/prometheus
install -m 755 "prometheus-${PROMETHEUS_VERSION}.linux-amd64/promtool" /usr/local/bin/promtool

mkdir -p /etc/prometheus /var/lib/prometheus
cat > /etc/prometheus/prometheus.yml <<EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: cert-analyzer
    # Matches cert-analyzer's [metrics] min_scrape_interval_seconds (60s
    # default) -- scraping faster just re-polls a replayed response.
    scrape_interval: 60s
    ec2_sd_configs:
      - region: ${AWS_REGION}
        port: ${ANALYZER_METRICS_PORT}
        filters:
          - name: tag:${ANALYZER_TAG_KEY}
            values: [${ANALYZER_TAG_VALUE}]
    # New Analyzer instances appear on the next refresh_interval (default
    # 60s) with zero customer configuration -- no target list to maintain,
    # unlike the static/file_sd guidance in extras/install-prometheus.sh
    # (which is for non-AWS bare-metal fleets, not this deployment path).
    # This IAM role only grants ec2:DescribeInstances (see
    # cloudformation.yaml's DashboardRole) -- an account/region-wide read
    # permission, since EC2's Describe* actions have no resource-level
    # condition to scope it further to just CertSight-tagged instances.
    relabel_configs:
      - source_labels: [__meta_ec2_private_ip]
        target_label: __address__
        replacement: '\${1}:${ANALYZER_METRICS_PORT}'
EOF

cat > /etc/systemd/system/prometheus.service <<EOF
[Unit]
Description=Prometheus monitoring server (CertSight fleet)
Documentation=https://prometheus.io/docs
After=network.target

[Service]
ExecStart=/usr/local/bin/prometheus \\
  --config.file=/etc/prometheus/prometheus.yml \\
  --web.listen-address=:${PROMETHEUS_PORT} \\
  --storage.tsdb.path=/var/lib/prometheus \\
  --storage.tsdb.retention.time=15d
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now prometheus

for i in $(seq 1 30); do
    systemctl is-active --quiet prometheus && break
    sleep 2
done
systemctl is-active --quiet prometheus || echo "WARNING: prometheus.service did not become active in time"

echo "=== [6/7] Grafana (real login required -- no anonymous-viewer mode on this product) ==="
cat <<'EOF' > /etc/yum.repos.d/grafana.repo
[grafana]
name=grafana
baseurl=https://rpm.grafana.com
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://rpm.grafana.com/gpg.key
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
EOF
dnf -y install grafana

# Generated fresh per-instance. Unlike extras/aws-demo/user-data.sh (which
# only writes this to a root-only file, fine for a demo box the operator
# personally SSHes into), also echo it to this log -- which cloud-init
# mirrors to the EC2 console output -- so a Marketplace customer can
# retrieve their own instance's admin password via "Get system log" in the
# EC2 console with no SSH access needed at all.
set +x
GRAFANA_ADMIN_PASSWORD=$(openssl rand -base64 24 | tr -d '=+/' | cut -c1-24)
cat <<EOF >> /etc/grafana/grafana.ini

[security]
admin_user = admin
admin_password = ${GRAFANA_ADMIN_PASSWORD}
EOF
CREDFILE=/root/.grafana-admin-credentials
cat <<EOF > "${CREDFILE}"
# Grafana admin credentials, generated at provisioning time by dashboard-user-data.sh.
username: admin
password: ${GRAFANA_ADMIN_PASSWORD}
EOF
chmod 600 "${CREDFILE}"
echo "=================================================================="
echo " CertSight Dashboard -- Grafana admin credentials (generated once,"
echo " shown here and in ${CREDFILE} on this instance -- this is the only"
echo " time the password is printed in full):"
echo "   username: admin"
echo "   password: ${GRAFANA_ADMIN_PASSWORD}"
echo "=================================================================="
unset GRAFANA_ADMIN_PASSWORD
set -x
# No [auth.anonymous] block -- deliberately absent, unlike
# extras/aws-demo/user-data.sh. Anonymous read access was an acceptable
# shortcut for a demo link; it is not the default for a paid product.
systemctl enable --now grafana-server

setsebool -P httpd_can_network_connect on || true
semanage port -l | grep -qw "${PROMETHEUS_PORT}" || semanage port -a -t http_port_t -p tcp "${PROMETHEUS_PORT}" || true

for i in $(seq 1 30); do
    systemctl is-active --quiet grafana-server && break
    sleep 2
done

echo "=== [7/7] Prometheus datasource + CertSight dashboard import, certsight-test-server (explorer mode) ==="
# GRAFANA_ADMIN_PASSWORD was unset above once 'set -x' resumed (so it never
# lands in the install log) -- re-read it from the credentials file here.
GRAFANA_ADMIN_PASSWORD="$(awk -F': ' '/^password:/ {print $2}' "${CREDFILE}")"
DASHBOARD_JSON="${WORKDIR}/certsight-src/extras/examples/grafana-dashboard.json"
python3 - <<PYEOF
import json, urllib.request, urllib.error, base64

grafana_url = "http://localhost:3000"
user = "admin"
password = "${GRAFANA_ADMIN_PASSWORD}"
creds = base64.b64encode(f"{user}:{password}".encode()).decode()

def _post(path, payload):
    req = urllib.request.Request(
        grafana_url + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Basic {creds}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"    Warning: POST {path} failed: {body}")
        return None

_post("/api/datasources", {
    "name": "Prometheus",
    "type": "prometheus",
    "url": "http://localhost:${PROMETHEUS_PORT}",
    "access": "proxy",
    "isDefault": True,
})

with open("${DASHBOARD_JSON}") as f:
    db = json.load(f)
for key in ("__inputs", "__elements", "__requires"):
    db.pop(key, None)
db["id"] = None

result = _post("/api/dashboards/import", {"dashboard": db, "overwrite": True, "folderId": 0})
if result:
    print(f"    Dashboard imported: {grafana_url}{result.get('url', '')}")
PYEOF

TSCONF=/etc/certsight-test-server/test-server.conf
mkdir -p "$(dirname "${TSCONF}")"
cat <<EOF > "${TSCONF}"
TEST_SERVER_MODE=explorer
TEST_SERVER_PORT=8090
TEST_SERVER_BIND=0.0.0.0
TEST_SERVER_PROMETHEUS_URL=http://127.0.0.1:${PROMETHEUS_PORT}
EOF
# No TEST_SERVER_KAFKA_HOST/PORT above -- explorer mode doesn't require them
# (extras/test-server/server.py's --mode explorer, see that file's own
# commit history for why). TEST_SERVER_BIND=0.0.0.0 rather than the demo's
# 127.0.0.1-behind-nginx pattern: explorer mode has no action endpoints to
# rate-limit, so the security-group-level restriction on :3000 in
# cloudformation.yaml is the access control here, not an nginx proxy.
mkdir -p rpms-testserver && cd rpms-testserver
# certsight-test-server.spec has a hard `Requires: cert-agent-deployer` (in
# turn requiring cert-agent-jni) -- inherited from the full/demo test
# console's JCA-keystore use case, which explorer mode never runs. Neither
# package is in any public repo, so `dnf install` on the test-server RPM
# alone would fail on an unmet dependency; download and install all three
# together (same one-transaction pattern extras/aws-demo/user-data.sh uses,
# just without cert-analyzer, which isn't installed on this AMI at all).
# The Java cert-agent itself is never used on the Dashboard instance in
# explorer mode -- pure packaging cost, not a functional need.
for pkg in cert-agent-jni cert-agent-deployer certsight-test-server; do
    curl -fsSL -O "${RELEASE_BASE}/${pkg}-${CERTSIGHT_VERSION#v}-1.el9.x86_64.rpm"
done
dnf -y install ./*.rpm
cd "${WORKDIR}"
systemctl reset-failed certsight-test-server || true
systemctl enable --now certsight-test-server

touch /var/lib/certsight-dashboard-install-complete
echo "=== CertSight Dashboard install complete ==="
