#!/bin/bash
# Per-instance half of the CertSight Dashboard install: everything that must
# be unique to this instance or depend on facts only known at real boot time
# (this instance's own AWS region, a freshly generated Grafana admin
# password) -- see dashboard-install.sh's header for why these two are
# deliberately kept out of the Packer-baked half.
#
# Must run after dashboard-install.sh has already installed the Prometheus/
# Grafana/certsight-test-server packages and systemd units on this host
# (either via cloud-init on a stock AMI, or already baked into a Packer
# image -- either way this script itself is safe and fast to (re-)run since
# it's the actual per-instance work, not a packaging step).
#
# Runs as root via cloud-init/EC2 user-data on first boot. See
# cloudformation.yaml's DashboardInstance UserData for how the two scripts
# are chained together.
#
# Progress/errors: /var/log/certsight-dashboard-firstboot.log

set -uo pipefail
exec > >(tee -a /var/log/certsight-dashboard-firstboot.log) 2>&1
set -x

WORKDIR="/opt/certsight-install"
PROMETHEUS_PORT="9091"
ANALYZER_METRICS_PORT="9090"
# EC2 fleet-discovery tag: every CertSight Analyzer instance in this
# region/VPC must carry this tag for the ec2_sd_configs below to find it.
# Fixed, not customer-configurable, for this first version -- see
# analyzer-user-data.sh / cloudformation.yaml, which apply it at instance
# launch (a tag is EC2 resource metadata set via the API, not something an
# instance can set on itself from inside).
ANALYZER_TAG_KEY="certsight-role"
ANALYZER_TAG_VALUE="analyzer"
DASHBOARD_JSON="${WORKDIR}/certsight-src/extras/examples/grafana-dashboard.json"

echo "=== [1/4] Region (IMDSv2 -- token required, matches this AMI's MetadataOptions HttpTokens=required) ==="
IMDS_TOKEN="$(curl -fsSL -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")"
AWS_REGION="$(curl -fsSL -H "X-aws-ec2-metadata-token: ${IMDS_TOKEN}" "http://169.254.169.254/latest/meta-data/placement/region")"
if [[ -z "${AWS_REGION}" ]]; then
    echo "ERROR: could not determine region from instance metadata -- Prometheus ec2_sd_configs cannot be written without it."
    exit 1
fi
echo "    Region: ${AWS_REGION}"

echo "=== [2/4] Prometheus config (fleet discovery via EC2 tags, no manual target list) + start ==="
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
systemctl start prometheus
for i in $(seq 1 30); do
    systemctl is-active --quiet prometheus && break
    sleep 2
done
systemctl is-active --quiet prometheus || echo "WARNING: prometheus.service did not become active in time"

echo "=== [3/4] Grafana admin password (generated once per instance) + start ==="
# Generated fresh per-instance -- this is the whole reason
# dashboard-install.sh never starts Grafana: doing this at Packer bake time
# instead would put one shared, extractable password in the golden image,
# reused by every instance ever launched from it.
#
# Also echoed to this log -- which cloud-init mirrors to the EC2 console
# output -- so a Marketplace customer can retrieve their own instance's
# admin password via "Get system log" in the EC2 console with no SSH access
# needed at all. Unlike extras/aws-demo/user-data.sh (which only writes this
# to a root-only file, fine for a demo box the operator personally SSHes
# into), this is a customer-facing product where SSH access may not even be
# offered.
set +x
GRAFANA_ADMIN_PASSWORD=$(openssl rand -base64 24 | tr -d '=+/' | cut -c1-24)
cat <<EOF >> /etc/grafana/grafana.ini

[security]
admin_user = admin
admin_password = ${GRAFANA_ADMIN_PASSWORD}
EOF
CREDFILE=/root/.grafana-admin-credentials
cat <<EOF > "${CREDFILE}"
# Grafana admin credentials, generated at first boot by dashboard-firstboot.sh.
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
systemctl start grafana-server
for i in $(seq 1 30); do
    systemctl is-active --quiet grafana-server && break
    sleep 2
done

echo "=== [4/4] Prometheus datasource + CertSight dashboard import, certsight-test-server start ==="
# GRAFANA_ADMIN_PASSWORD was unset above once 'set -x' resumed (so it never
# lands in the log) -- re-read it from the credentials file here.
GRAFANA_ADMIN_PASSWORD="$(awk -F': ' '/^password:/ {print $2}' "${CREDFILE}")"
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

systemctl reset-failed certsight-test-server || true
systemctl start certsight-test-server

touch /var/lib/certsight-dashboard-firstboot-complete
echo "=== CertSight Dashboard first-boot configuration complete ==="
