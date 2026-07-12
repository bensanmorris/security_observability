#!/bin/bash
# EC2 user-data: installs the full CertSight demo stack on a fresh Rocky Linux 9
# instance -- Tetragon, cert-analyzer, the Java cert-agent, Prometheus, Grafana
# (dashboard), and the certsight-test-server (test console).
#
# Runs as root via cloud-init on first boot. Idempotent-ish: safe to re-run by
# hand (e.g. over SSH) if a step failed, though most steps assume a clean box.
#
# Progress/errors: /var/log/certsight-demo-install.log

set -uo pipefail
exec > >(tee -a /var/log/certsight-demo-install.log) 2>&1
set -x

CERTSIGHT_VERSION="${CERTSIGHT_VERSION:-v0.73}"
TETRAGON_VERSION="${TETRAGON_VERSION:-1.7.0}"
REPO_URL="https://github.com/bensanmorris/security_observability.git"
RELEASE_BASE="https://github.com/bensanmorris/security_observability/releases/download/${CERTSIGHT_VERSION}"
WORKDIR="/opt/certsight-install"
mkdir -p "${WORKDIR}"
cd "${WORKDIR}"

echo "=== [1/9] Base packages ==="
dnf -y install git curl tar jq policycoreutils-python-utils firewalld || true
systemctl enable --now firewalld || true

echo "=== [2/9] Local firewall (security group is the primary control, but firewalld runs on this AMI too) ==="
if systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-port=3000/tcp   # Grafana dashboard
    firewall-cmd --permanent --add-port=8090/tcp   # test console
    firewall-cmd --reload
fi

echo "=== [3/9] Tetragon ${TETRAGON_VERSION} (standalone systemd install) ==="
curl -fsSL -o tetragon.tar.gz \
    "https://github.com/cilium/tetragon/releases/download/v${TETRAGON_VERSION}/tetragon-v${TETRAGON_VERSION}-amd64.tar.gz"
tar -xzf tetragon.tar.gz
"./tetragon-v${TETRAGON_VERSION}-amd64/install.sh"

for i in $(seq 1 30); do
    systemctl is-active --quiet tetragon && break
    sleep 2
done
systemctl is-active --quiet tetragon || echo "WARNING: tetragon.service did not become active in time"

echo "=== [4/9] CertSight source (for scripts: apply-policies.sh, install-prometheus.sh, dashboard json) ==="
git clone --depth 1 --branch "${CERTSIGHT_VERSION}" "${REPO_URL}" certsight-src

echo "=== [5/9] Tetragon policies ==="
curl -fsSL -o tetragon-policies.tar.gz "${RELEASE_BASE}/tetragon-policies-${CERTSIGHT_VERSION}.tar.gz"
tar -xzf tetragon-policies.tar.gz
# Some experimental policies (e.g. FIPS/NSS uprobes needing debuginfo) may
# legitimately fail on a stock image -- don't let that abort the whole install.
./tetragon-policies/apply-policies.sh || true

echo "=== [6/9] CertSight RPMs (cert-analyzer, Java cert-agent, test console) ==="
mkdir -p rpms && cd rpms
for pkg in cert-analyzer cert-agent-jni cert-agent-deployer certsight-test-server; do
    curl -fsSL -O "${RELEASE_BASE}/${pkg}-${CERTSIGHT_VERSION#v}-1.el9.x86_64.rpm"
done
# Installed together so dnf can resolve the local inter-package deps in one transaction
dnf -y install ./*.rpm
cd "${WORKDIR}"

echo "=== [7/9] cert-analyzer: enable Kafka + probes, restart Tetragon to pick up the socket ACL drop-in ==="
systemctl restart tetragon
sleep 5

CONF=/etc/cert-analyzer/cert-analyzer.conf
sed -i \
    -e 's/^enabled = false/enabled = true/' \
    -e 's/^bind_probe_enabled = false/bind_probe_enabled = true/' \
    -e 's/^connect_probe_enabled = false/connect_probe_enabled = true/' \
    "${CONF}"

echo "=== [8/9] Kafka (single-node, throwaway, KRaft mode) ==="
dnf -y install java-11-openjdk-headless || true
"${WORKDIR}/certsight-src/extras/kafka/install-kafka.sh"

systemctl enable --now cert-analyzer

echo "=== [9/9] Prometheus + Grafana (dashboard) ==="
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

cat <<'EOF' >> /etc/grafana/grafana.ini

[auth.anonymous]
enabled = true
org_name = Main Org.
org_role = Viewer
EOF
systemctl enable --now grafana-server

setsebool -P httpd_can_network_connect on || true
semanage port -l | grep -qw 9091 || semanage port -a -t http_port_t -p tcp 9091 || true

for i in $(seq 1 30); do
    systemctl is-active --quiet grafana-server && break
    sleep 2
done
bash "${WORKDIR}/certsight-src/extras/install-prometheus.sh"

echo "=== Test console ==="
# Bound to localhost only -- nginx (below) is the public-facing side on 8090,
# so it can rate-limit before requests ever reach this unauthenticated server.
TSCONF=/etc/certsight-test-server/test-server.conf
cat <<'EOF' > "${TSCONF}"
TEST_SERVER_KAFKA_HOST=localhost
TEST_SERVER_KAFKA_PORT=9092
TEST_SERVER_TOPIC=cert-analyzer-events
TEST_SERVER_PORT=8091
TEST_SERVER_BIND=127.0.0.1
EOF
systemctl reset-failed certsight-test-server || true
systemctl enable --now certsight-test-server

echo "=== nginx reverse proxy in front of the test console (rate limiting) ==="
# The test console has no auth and executes real actions (spawn JVMs, generate
# certs, bind ports) on request -- with the link shared publicly, this caps
# how hard any one client can hit it. /api/run/* (the actual action endpoints)
# gets the tightest limit; /api/events (the SSE live-event stream) is exempted
# from request-rate limiting since it's one long-lived connection per visitor,
# but still capped on concurrent connections per IP.
dnf -y install nginx || true
cat <<'EOF' > /etc/nginx/conf.d/certsight-test-console.conf
limit_req_zone $binary_remote_addr zone=tc_general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=tc_actions:10m rate=12r/m;
limit_conn_zone $binary_remote_addr zone=tc_conn:10m;
limit_req_status 429;
limit_conn_status 429;

server {
    listen 8090 default_server;
    server_name _;

    location /api/run/ {
        limit_req zone=tc_actions burst=3 nodelay;
        limit_conn tc_conn 3;
        proxy_pass http://127.0.0.1:8091;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /api/events {
        limit_conn tc_conn 5;
        proxy_pass http://127.0.0.1:8091;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 1h;
        proxy_set_header Connection '';
    }

    location / {
        limit_req zone=tc_general burst=20 nodelay;
        proxy_pass http://127.0.0.1:8091;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
EOF
restorecon -v /etc/nginx/conf.d/certsight-test-console.conf || true
setsebool -P httpd_can_network_connect on || true
# SELinux only pre-labels standard ports (80, 443, 8080, ...) as httpd-bindable;
# 8090 needs an explicit label or nginx's bind() fails with EACCES.
semanage port -l | grep -qw 8090 || semanage port -a -t http_port_t -p tcp 8090 || true
systemctl enable --now nginx
nginx -t && systemctl reload nginx

echo "=== Java JCA warm-up (fixes policy-load-timing issue on the java-non-fips-cert uprobe) ==="
# Tetragon only attaches the java-non-fips-cert uprobe to libcert_agent_stub.so
# correctly if that library is already mapped into some process at the time
# the policy is (re)loaded. apply-policies.sh ran earlier, before the cert-agent
# RPMs even existed on disk, so on a cold box the uprobe never attaches until
# something reloads the policy after a JVM has actually loaded the library --
# without this, the first "load a certificate into a Java KeyStore (JCA)" test
# console click (and every one after it) silently produces no Kafka event.
curl -fsSL -o probe-tests.tar.gz "${RELEASE_BASE}/probe-tests-${CERTSIGHT_VERSION}.tar.gz"
mkdir -p probe-tests && tar -xzf probe-tests.tar.gz -C probe-tests
openssl req -x509 -newkey rsa:2048 -keyout /tmp/jca-warmup-key.pem \
    -out /tmp/jca-warmup-cert.pem -days 1 -nodes -subj "/CN=certsight-jca-warmup" 2>/dev/null

java -cp "${WORKDIR}/probe-tests/java" CertAgentTest /tmp/jca-warmup-cert.pem &
WARMUP_JAVA_PID=$!

ATTACHED=false
for i in $(seq 1 40); do
    journalctl -u cert-agent-deployer --no-pager 2>/dev/null | grep -q "Attached cert-agent to PID ${WARMUP_JAVA_PID}" && { ATTACHED=true; break; }
    sleep 2
done

if [[ "${ATTACHED}" == true ]]; then
    echo "    Warm-up JVM (PID ${WARMUP_JAVA_PID}) attached -- reloading policies so the uprobe binds"
    ./tetragon-policies/apply-policies.sh || true
else
    echo "    WARNING: cert-agent-deployer never attached to the warm-up JVM within 80s -- the JCA use case may need a manual 'sudo systemctl restart tetragon' (see extras/aws-demo/README.md)"
fi

kill "${WARMUP_JAVA_PID}" 2>/dev/null || true
rm -f /tmp/jca-warmup-key.pem /tmp/jca-warmup-cert.pem

touch /var/lib/certsight-demo-install-complete
echo "=== CertSight demo install complete ==="
