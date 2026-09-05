#!/bin/bash
# Bake-time half of the CertSight Dashboard install: packages and files only,
# nothing instance-specific. Safe to run once inside a Packer build and
# snapshot the result -- see dashboard-firstboot.sh for the half that must
# run per-instance instead (secrets, and anything that depends on the
# instance's own region).
#
# Why the split: this script installs Grafana and Prometheus but never
# starts either service or writes Grafana's admin password -- starting
# Grafana initializes its sqlite DB with whatever admin_password is in
# grafana.ini at that moment. Doing that here, inside a Packer build, would
# bake one shared, extractable admin password into the golden image itself,
# silently reused by every instance ever launched from that AMI. That
# password generation belongs at first real boot instead, run once per
# instance (see dashboard-firstboot.sh).
#
# Run standalone (cloud-init on a stock AMI, or manual testing) followed by
# dashboard-firstboot.sh -- see cloudformation.yaml's DashboardInstance
# UserData, which runs both in sequence. Or run only this one inside a
# Packer build (see extras/aws-marketplace/packer/dashboard.pkr.hcl); the
# resulting AMI still needs dashboard-firstboot.sh run via EC2 user-data at
# every instance's first real boot.
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

# TEST_SERVER_MODE=explorer needs no Kafka broker anywhere in this product --
# see extras/test-server/server.py's --mode flag and this directory's README
# ("Why no Kafka"). Not a secret, so (unlike the Grafana/Prometheus config
# below) this is safe to write at bake time.
mkdir -p /etc/certsight-test-server
cat > /etc/certsight-test-server/test-server.conf <<'EOF'
TEST_SERVER_MODE=explorer
TEST_SERVER_PORT=8090
TEST_SERVER_BIND=0.0.0.0
TEST_SERVER_PROMETHEUS_URL=http://127.0.0.1:9091
EOF

echo "=== [1/5] Base packages ==="
dnf -y install git curl tar jq policycoreutils-python-utils firewalld python3 || true
systemctl enable --now firewalld || true

echo "=== [2/5] Local firewall (the CertSight Dashboard security group is the primary control -- see cloudformation.yaml -- but firewalld runs on this AMI too) ==="
if systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-port=3000/tcp   # Grafana
    firewall-cmd --permanent --add-port=8090/tcp   # certsight-test-server explorer pages
    firewall-cmd --reload
fi

echo "=== [3/5] CertSight source (for extras/examples/grafana-dashboard.json, imported by dashboard-firstboot.sh) ==="
git clone --depth 1 --branch "${CERTSIGHT_VERSION}" "${REPO_URL}" certsight-src

echo "=== [4/5] Prometheus binaries + systemd unit (config file and service start deferred to dashboard-firstboot.sh -- the config needs this instance's own region, which isn't known until it actually boots) ==="
PROMETHEUS_VERSION="2.53.4"
ARCHIVE="prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz"
curl -fsSL "https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/${ARCHIVE}" -o "${ARCHIVE}"
tar -xzf "${ARCHIVE}"
install -m 755 "prometheus-${PROMETHEUS_VERSION}.linux-amd64/prometheus" /usr/local/bin/prometheus
install -m 755 "prometheus-${PROMETHEUS_VERSION}.linux-amd64/promtool" /usr/local/bin/promtool
mkdir -p /etc/prometheus /var/lib/prometheus

cat > /etc/systemd/system/prometheus.service <<'EOF'
[Unit]
Description=Prometheus monitoring server (CertSight fleet)
Documentation=https://prometheus.io/docs
After=network.target

[Service]
ExecStart=/usr/local/bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --web.listen-address=:9091 \
  --storage.tsdb.path=/var/lib/prometheus \
  --storage.tsdb.retention.time=15d
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
# Enabled (starts automatically on every future boot) but not started now --
# /etc/prometheus/prometheus.yml doesn't exist yet, so starting it here
# would just fail; dashboard-firstboot.sh writes it and starts the service.
systemctl enable prometheus
setsebool -P httpd_can_network_connect on || true
semanage port -l | grep -qw 9091 || semanage port -a -t http_port_t -p tcp 9091 || true

echo "=== [5/5] Grafana + certsight-test-server packages (Grafana's admin password/DB init and all service starts deferred to dashboard-firstboot.sh) ==="
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
# No [auth.anonymous] block -- deliberately absent, unlike
# extras/aws-demo/user-data.sh. Anonymous read access was an acceptable
# shortcut for a demo link; it is not the default for a paid product.
# Enabled for future boots, not started now (see the Prometheus comment above
# -- and more importantly, see this script's own header on why starting
# Grafana before its per-instance admin password is generated must never
# happen here).
systemctl enable grafana

# certsight-test-server.spec has a hard `Requires: cert-agent-deployer` (in
# turn requiring cert-agent-jni) -- inherited from the full/demo test
# console's JCA-keystore use case, which explorer mode never runs. Neither
# package is in any public repo, so `dnf install` on the test-server RPM
# alone would fail on an unmet dependency; download and install all three
# together (same one-transaction pattern extras/aws-demo/user-data.sh uses,
# just without cert-analyzer, which isn't installed on this AMI at all).
# The Java cert-agent itself is never used on the Dashboard instance in
# explorer mode -- pure packaging cost, not a functional need.
mkdir -p rpms-testserver && cd rpms-testserver
for pkg in cert-agent-jni cert-agent-deployer certsight-test-server; do
    curl -fsSL -O "${RELEASE_BASE}/${pkg}-${CERTSIGHT_VERSION#v}-1.el9.x86_64.rpm"
done
dnf -y install ./*.rpm
cd "${WORKDIR}"
systemctl enable certsight-test-server

touch /var/lib/certsight-dashboard-install-complete
echo "=== CertSight Dashboard package install complete -- run dashboard-firstboot.sh next (per-instance, at real boot) ==="
