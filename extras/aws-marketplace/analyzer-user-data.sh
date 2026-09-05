#!/bin/bash
# EC2 user-data / AMI build script for the CertSight Analyzer product:
# Tetragon + cert-analyzer + the Java cert-agent on a fresh Rocky Linux 9
# instance. No Kafka, no test-server -- this instance only ever needs to be
# reachable by the companion CertSight Dashboard instance on :9090.
#
# This is the Analyzer half of extras/aws-marketplace/'s two-AMI split (see
# extras/aws-marketplace/README.md). extras/aws-demo/user-data.sh (the
# existing single-box demo) is separate and untouched by this file.
#
# Runs as root via cloud-init on first boot, or as the install step of the
# Packer build that bakes the CertSight Analyzer AMI (a pre-baked AMI is
# what AWS Marketplace requires; a stock AMI + this script as EC2 user-data
# also works for manual testing before that pipeline exists).
#
# Progress/errors: /var/log/certsight-analyzer-install.log

set -uo pipefail
exec > >(tee -a /var/log/certsight-analyzer-install.log) 2>&1
set -x

CERTSIGHT_VERSION="${CERTSIGHT_VERSION:-v0.96}"
TETRAGON_VERSION="${TETRAGON_VERSION:-1.7.0}"
REPO_URL="https://github.com/bensanmorris/security_observability.git"
RELEASE_BASE="https://github.com/bensanmorris/security_observability/releases/download/${CERTSIGHT_VERSION}"
WORKDIR="/opt/certsight-install"
mkdir -p "${WORKDIR}"
cd "${WORKDIR}"

echo "=== [1/7] Base packages ==="
dnf -y install git curl tar jq policycoreutils-python-utils firewalld || true
systemctl enable --now firewalld || true

echo "=== [2/7] Local firewall (the CertSight Analyzer security group is the primary control -- see cloudformation.yaml -- but firewalld runs on this AMI too) ==="
if systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-port=9090/tcp   # cert-analyzer Prometheus metrics -- scraped by the Dashboard instance
    firewall-cmd --reload
fi

echo "=== [3/7] Tetragon ${TETRAGON_VERSION} (standalone systemd install) ==="
curl -fsSL -o tetragon.tar.gz \
    "https://github.com/cilium/tetragon/releases/download/v${TETRAGON_VERSION}/tetragon-v${TETRAGON_VERSION}-amd64.tar.gz"
tar -xzf tetragon.tar.gz
"./tetragon-v${TETRAGON_VERSION}-amd64/install.sh"

for i in $(seq 1 30); do
    systemctl is-active --quiet tetragon && break
    sleep 2
done
systemctl is-active --quiet tetragon || echo "WARNING: tetragon.service did not become active in time"

echo "=== [4/7] CertSight source (for tetragon-policies/apply-policies.sh) ==="
git clone --depth 1 --branch "${CERTSIGHT_VERSION}" "${REPO_URL}" certsight-src

echo "=== [5/7] Tetragon policies ==="
curl -fsSL -o tetragon-policies.tar.gz "${RELEASE_BASE}/tetragon-policies-${CERTSIGHT_VERSION}.tar.gz"
tar -xzf tetragon-policies.tar.gz
# Some experimental policies (e.g. FIPS/NSS uprobes needing debuginfo) may
# legitimately fail on a stock image -- don't let that abort the whole install.
./tetragon-policies/apply-policies.sh || true

echo "=== [6/7] CertSight RPMs (cert-analyzer, Java cert-agent) -- no certsight-test-server on this AMI ==="
mkdir -p rpms && cd rpms
for pkg in cert-analyzer cert-agent-jni cert-agent-deployer; do
    curl -fsSL -O "${RELEASE_BASE}/${pkg}-${CERTSIGHT_VERSION#v}-1.el9.x86_64.rpm"
done
dnf -y install ./*.rpm
cd "${WORKDIR}"

echo "=== [7/7] cert-analyzer: enable probes, restart Tetragon to pick up the socket ACL drop-in ==="
systemctl restart tetragon
sleep 5

# Kafka is deliberately left disabled (the RPM default) -- this product has
# no Kafka broker anywhere (see extras/aws-marketplace/README.md's "why no
# Kafka" note); the Dashboard instance's explorer pages and the fleet
# dashboard both work over Prometheus alone.
CONF=/etc/cert-analyzer/cert-analyzer.conf
sed -i \
    -e 's/^bind_probe_enabled = false/bind_probe_enabled = true/' \
    -e 's/^connect_probe_enabled = false/connect_probe_enabled = true/' \
    -e 's/^event_rate_metrics_enabled = false/event_rate_metrics_enabled = true/' \
    "${CONF}"

systemctl enable --now cert-analyzer

# KNOWN LIMITATION (documented, not fixed here): on a cold boot, Tetragon's
# java-non-fips-cert uprobe only attaches to libcert_agent_stub.so if that
# library is already mapped into *some* process at the moment the policy is
# (re)loaded -- apply-policies.sh above ran before any Java workload existed.
# extras/aws-demo/user-data.sh works around this with a synthetic warm-up JVM
# built from certsight-test-server's CertAgentTest.class, which isn't
# installed on this AMI (it ships only with the test console, not the Java
# cert-agent RPMs -- confirmed via certsight-test-server.spec). On this AMI,
# the fix is the same one extras/aws-demo/README.md documents manually: once
# a real customer JVM has loaded the cert-agent native library (i.e. after
# their first real Java workload using it starts), `systemctl restart
# tetragon` while that JVM is still running attaches the uprobe for good.
touch /var/lib/certsight-analyzer-install-complete
echo "=== CertSight Analyzer install complete ==="
