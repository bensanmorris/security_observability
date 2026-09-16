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
# Separate from CERTSIGHT_VERSION above: that one names a real GitHub Release
# (RPMs + the tetragon-policies tarball, via RELEASE_BASE below, must exist
# at that tag). This one is just the git ref cloned for *scripts*
# (apply-policies.sh, install-prometheus.sh, install-kafka.sh, dashboard
# json) -- defaults to the same tag, but deploy-demo.sh overrides it
# separately to a branch when WITH_K8S_NODE=true, for a script fix
# (install-kafka.sh's KAFKA_ADVERTISED_HOST) that isn't in any release yet.
CERTSIGHT_GIT_REF="${CERTSIGHT_GIT_REF:-${CERTSIGHT_VERSION}}"
TETRAGON_VERSION="${TETRAGON_VERSION:-1.7.0}"
# Set (uncommented, to "true") by deploy-demo.sh when WITH_K8S_NODE=true --
# makes Kafka advertise this box's own private IP instead of localhost-only,
# so the optional second, k8s-hosted analyzer node can reach it. See
# extras/aws-demo/deploy-k8s-node.sh.
WITH_K8S_NODE="${WITH_K8S_NODE:-false}"
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
    firewall-cmd --permanent --add-port=8092/tcp   # MCP server (rate-limited by nginx)
    firewall-cmd --permanent --add-port=8094/tcp   # fleet manager (login-protected, nginx in front)
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
git clone --depth 1 --branch "${CERTSIGHT_GIT_REF}" "${REPO_URL}" certsight-src

echo "=== [5/9] Tetragon policies ==="
curl -fsSL -o tetragon-policies.tar.gz "${RELEASE_BASE}/tetragon-policies-${CERTSIGHT_VERSION}.tar.gz"
tar -xzf tetragon-policies.tar.gz
# Some experimental policies (e.g. FIPS/NSS uprobes needing debuginfo) may
# legitimately fail on a stock image -- don't let that abort the whole install.
./tetragon-policies/apply-policies.sh || true

echo "=== [6/9] CertSight RPMs (cert-analyzer + control, Java cert-agent, test console, MCP server, fleet manager) ==="
mkdir -p rpms && cd rpms
for pkg in cert-analyzer cert-agent-jni cert-agent-deployer certsight-test-server certsight-mcp; do
    curl -fsSL -O "${RELEASE_BASE}/${pkg}-${CERTSIGHT_VERSION#v}-1.el9.x86_64.rpm"
done
# Fleet control is a separate, deliberately opt-in package: the base
# cert-analyzer RPM has no [control] code at all. This box runs the fleet
# manager and is one of the nodes it drives, so it gets cert-analyzer-control
# too. Both it and the (noarch) fleet manager first shipped after v0.99 --
# tolerate a release that predates them so an older CERTSIGHT_VERSION still
# deploys; the [control] and fleet-manager sections further down then find
# nothing to enable and are skipped.
curl -fsSL -O "${RELEASE_BASE}/cert-analyzer-control-${CERTSIGHT_VERSION#v}-1.el9.x86_64.rpm" \
    || echo "    no cert-analyzer-control RPM in ${CERTSIGHT_VERSION} -- this node will not be fleet-controllable"
curl -fsSL -O "${RELEASE_BASE}/certsight-fleet-manager-${CERTSIGHT_VERSION#v}-1.el9.noarch.rpm" \
    || echo "    no certsight-fleet-manager RPM in ${CERTSIGHT_VERSION} -- skipping the fleet manager"
# Installed together so dnf can resolve the local inter-package deps in one
# transaction -- certsight-mcp Requires certsight-test-server (it imports
# that package's blast_radius.py/fleet_blast_radius.py/chain_explorer.py/
# fleet_fips_rollout.py rather than bundling copies).
dnf -y install ./*.rpm
cd "${WORKDIR}"

echo "=== [7/9] cert-analyzer: enable Kafka + probes, restart Tetragon to pick up the socket ACL drop-in ==="
systemctl restart tetragon
sleep 5

CONF=/etc/cert-analyzer/cert-analyzer.conf
# The first sed flips every section's bare "enabled = false" -- [kafka] and,
# since the fleet manager landed, [control] too. [control] additionally
# needs a token or cert-analyzer leaves control off; it's generated here and
# saved for deploy-k8s-node.sh to hand to the k8s node (both nodes must
# share it) and for the fleet manager's own config below. The listener
# keeps its loopback default (127.0.0.1:8087): the fleet manager runs on
# this same box, so nothing control-related is reachable from outside it.
# set +x for the same reason as the Grafana password below: this script's
# trace goes to a world-readable install log, and the token would otherwise
# appear in it three times (the assignment, the echo, the sed).
set +x
CONTROL_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
install -m 0600 /dev/null /root/certsight-control-token
echo "${CONTROL_TOKEN}" > /root/certsight-control-token
sed -i \
    -e 's/^enabled = false/enabled = true/' \
    -e 's/^bind_probe_enabled = false/bind_probe_enabled = true/' \
    -e 's/^connect_probe_enabled = false/connect_probe_enabled = true/' \
    -e 's/^event_rate_metrics_enabled = false/event_rate_metrics_enabled = true/' \
    -e "s|^#token =.*|token = ${CONTROL_TOKEN}|" \
    "${CONF}"
set -x
echo "Fleet-control token generated -- see /root/certsight-control-token (root-only) on this instance"

echo "=== [8/9] Kafka (single-node, throwaway, KRaft mode) ==="
dnf -y install java-11-openjdk-headless || true
if [[ "${WITH_K8S_NODE}" == "true" ]]; then
    # IMDSv2 -- deploy-demo.sh launches with HttpTokens=required, so a plain
    # metadata GET without a token is refused.
    IMDS_TOKEN="$(curl -fsS -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 60")"
    OWN_PRIVATE_IP="$(curl -fsS -H "X-aws-ec2-metadata-token: ${IMDS_TOKEN}" \
        http://169.254.169.254/latest/meta-data/local-ipv4)"
    echo "    WITH_K8S_NODE=true -- advertising Kafka on ${OWN_PRIVATE_IP} instead of localhost-only"
    KAFKA_ADVERTISED_HOST="${OWN_PRIVATE_IP}" "${WORKDIR}/certsight-src/extras/kafka/install-kafka.sh"
else
    "${WORKDIR}/certsight-src/extras/kafka/install-kafka.sh"
fi

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

# Generated fresh per-instance so the admin account is never left on Grafana's
# well-known admin/admin factory default while port 3000 is open to 0.0.0.0/0
# in the security group. Only takes effect on first start (Grafana seeds the
# admin user from grafana.ini once, into its own sqlite DB) -- re-running this
# script by hand against an already-initialized box will NOT reset it.
set +x
GRAFANA_ADMIN_PASSWORD=$(openssl rand -base64 24 | tr -d '=+/' | cut -c1-24)
cat <<EOF >> /etc/grafana/grafana.ini

[security]
admin_user = admin
admin_password = ${GRAFANA_ADMIN_PASSWORD}
EOF
CREDFILE=/root/.grafana-admin-credentials
cat <<EOF > "${CREDFILE}"
# Grafana admin credentials, generated at provisioning time by user-data.sh.
username: admin
password: ${GRAFANA_ADMIN_PASSWORD}
EOF
chmod 600 "${CREDFILE}"
unset GRAFANA_ADMIN_PASSWORD
set -x
echo "Grafana admin password generated -- see ${CREDFILE} (root-only) on this instance"

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
# Separate zones per location -- /api/events connections are long-lived by
# design (kept open for a whole page visit, one per browser tab), so a
# shared zone let them silently consume the budget /api/run/'s own limit
# was meant to police: a client with 3+ tabs open (or a couple of stale
# reconnects) could saturate the shared counter on /api/events alone and
# then have every /api/run POST rejected with no request-rate involved at
# all, which is what a live 2026-07-21 investigation found happening.
limit_conn_zone $binary_remote_addr zone=tc_conn_actions:10m;
limit_conn_zone $binary_remote_addr zone=tc_conn_events:10m;
limit_req_status 429;
limit_conn_status 429;

server {
    listen 8090 default_server;
    server_name _;

    location /api/run/ {
        limit_req zone=tc_actions burst=6 nodelay;
        limit_conn tc_conn_actions 3;
        proxy_pass http://127.0.0.1:8091;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /api/events {
        limit_conn tc_conn_events 5;
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

echo "=== MCP server (read-only fleet queries, no auth -- nginx rate-limits it) ==="
# Installed via RPM alongside the other packages in step [6/9] above (bundled
# venv, systemd unit, dedicated user all come from the package -- see
# extras/mcp-server/certsight-mcp.spec). Its own default
# /etc/certsight-mcp/mcp.conf is a %config(noreplace) file with everything
# commented out; overwritten here with this demo's real values the same way
# TSCONF is above -- noreplace only protects an *upgrade* from clobbering an
# operator's edits, not this first-boot provisioning step.
#
# No auth -- open like the dashboard/test console. Bound to localhost only
# (127.0.0.1:8093); nginx below is the public-facing side on 8092, same
# division of labor as the test console (8091 internal / 8090 public).
cat <<'EOF' > /etc/certsight-mcp/mcp.conf
CERTSIGHT_MCP_TRANSPORT=streamable-http
CERTSIGHT_MCP_HOST=127.0.0.1
CERTSIGHT_MCP_PORT=8093
CERTSIGHT_PROMETHEUS_URL=http://127.0.0.1:9091
EOF
chmod 644 /etc/certsight-mcp/mcp.conf
systemctl reset-failed certsight-mcp || true
systemctl enable --now certsight-mcp

echo "=== nginx reverse proxy in front of the MCP server (rate limiting) ==="
# Same rationale as the test-console proxy above: no auth means anyone who
# can reach port 8092 can call these tools, so this bounds how hard any one
# client can hit it. MCP has no cheap/expensive split like the test console
# does (every tool here is one bounded Prometheus query) -- one zone covers
# request rate, a separate one bounds concurrent connections so a client
# holding several sessions open (or the streamable-http SSE stream) can't
# alone exhaust a shared budget, the same failure mode the test console's
# /api/events split was fixed for.
cat <<'EOF' > /etc/nginx/conf.d/certsight-mcp.conf
limit_req_zone $binary_remote_addr zone=mcp_general:10m rate=20r/s;
limit_conn_zone $binary_remote_addr zone=mcp_conn:10m;
# limit_req_status/limit_conn_status are already set (429) http-wide by
# certsight-test-console.conf -- nginx merges all conf.d/*.conf into one
# http context, so redeclaring them here is a duplicate-directive error,
# not a harmless override.

server {
    listen 8092 default_server;
    server_name _;

    location / {
        limit_req zone=mcp_general burst=40 nodelay;
        limit_conn mcp_conn 10;
        proxy_pass http://127.0.0.1:8093;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_read_timeout 1h;
        # No "proxy_set_header Host $host" here, unlike the test-console proxy
        # above -- the mcp SDK auto-enables DNS-rebinding protection whenever
        # the app is bound to 127.0.0.1 (see server.py's CERTSIGHT_MCP_HOST),
        # restricting the Host header it accepts to 127.0.0.1:*. Leaving Host
        # unset here falls back to nginx's default ($proxy_host, i.e.
        # "127.0.0.1:8093"), which satisfies that check; forwarding the
        # original public Host would get every request rejected 421.
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Connection '';
    }
}
EOF
restorecon -v /etc/nginx/conf.d/certsight-mcp.conf || true
# 8092 needs the same explicit SELinux port label 8090 needed above.
semanage port -l | grep -qw 8092 || semanage port -a -t http_port_t -p tcp 8092 || true
nginx -t && systemctl reload nginx

if rpm -q certsight-fleet-manager >/dev/null 2>&1; then
echo "=== Fleet manager (policy control console -- read-only for visitors, admin login for changes, nginx in front) ==="
# The landing page is the admin sign-in with a "Continue as read-only
# viewer" link (FLEET_MANAGER_ANONYMOUS_VIEWER) -- so the console is as
# open as the dashboard/console/MCP server for looking, but unlike those,
# this one can switch detection off, so *changing* anything needs the admin
# login. Viewer sessions are refused every write server-side; the UI shows
# the controls disabled with the reason. The admin password is generated
# here and saved root-only; deploy-demo.sh prints where to find it. The
# node token is the one [control] above was given, so this console can
# drive this node's cert-analyzer (and the k8s node's, once
# deploy-k8s-node.sh has passed it the same token). Bound to 127.0.0.1:8095;
# nginx below is the public side on 8094, same split as the MCP server.
# This box's own node is reached on its loopback [control] listener; the
# k8s node on its node IP (see deploy-k8s-node.sh / user-data-k8s-node.sh).
# set +x: the password, its hash and the node token all pass through here
# and none of them belong in the install log (see the Grafana section).
set +x
FM_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')"
install -m 0600 /dev/null /root/certsight-fleet-manager-password
echo "${FM_PASSWORD}" > /root/certsight-fleet-manager-password
FM_HASH="$(echo "${FM_PASSWORD}" | certsight-fleet-manager --hash-password)"
cat <<FMEOF > /etc/certsight-fleet-manager/fleet-manager.conf
FLEET_MANAGER_ADMIN_PASSWORD_HASH=${FM_HASH}
FLEET_MANAGER_ANONYMOUS_VIEWER=1
FLEET_MANAGER_READ_ONLY_NOTE=Public demo: anyone may look; changing a policy needs the admin login.
FLEET_MANAGER_NODE_TOKEN=${CONTROL_TOKEN}
FLEET_MANAGER_PROMETHEUS_URL=http://127.0.0.1:9091
FLEET_MANAGER_BIND=127.0.0.1
FLEET_MANAGER_PORT=8095
FLEET_MANAGER_AUDIT_LOG=/var/lib/certsight-fleet-manager/audit.jsonl
FMEOF
chown root:certsight-fleet-manager /etc/certsight-fleet-manager/fleet-manager.conf
chmod 640 /etc/certsight-fleet-manager/fleet-manager.conf
unset FM_PASSWORD FM_HASH
set -x
echo "Fleet manager admin password generated -- see /root/certsight-fleet-manager-password (root-only) on this instance"
systemctl reset-failed certsight-fleet-manager || true
systemctl enable --now certsight-fleet-manager

echo "=== nginx reverse proxy in front of the fleet manager ==="
# The app does its own auth; nginx here rate-limits (a tight per-IP budget
# on /api/login on top of the app's own limiter) and forwards the headers
# the app needs: Host unchanged so its Origin/Host CSRF comparison holds,
# X-Forwarded-For (only trusted from loopback, which this is) so audit
# entries carry the real client, and X-Forwarded-Proto so the session
# cookie turns Secure once enable-mcp-https.sh adds TLS to this block.
cat <<'NGEOF' > /etc/nginx/conf.d/certsight-fleet-manager.conf
limit_req_zone $binary_remote_addr zone=fm_general:10m rate=20r/s;
limit_req_zone $binary_remote_addr zone=fm_login:10m rate=6r/m;

server {
    listen 8094 default_server;
    server_name _;

    location = /api/login {
        limit_req zone=fm_login burst=4 nodelay;
        proxy_pass http://127.0.0.1:8095;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    location / {
        limit_req zone=fm_general burst=40 nodelay;
        proxy_pass http://127.0.0.1:8095;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
NGEOF
restorecon -v /etc/nginx/conf.d/certsight-fleet-manager.conf || true
semanage port -l | grep -qw 8094 || semanage port -a -t http_port_t -p tcp 8094 || true
nginx -t && systemctl reload nginx
fi

echo "=== Java JCA warm-up (fixes policy-load-timing issue on the java-non-fips-cert uprobe) ==="
# Tetragon only attaches the java-non-fips-cert uprobe to libcert_agent_stub.so
# correctly if that library is already mapped into some process at the time
# the policy is (re)loaded. apply-policies.sh ran earlier, before the cert-agent
# RPMs even existed on disk, so on a cold box the uprobe never attaches until
# something reloads the policy after a JVM has actually loaded the library --
# without this, the first "load a certificate into a Java KeyStore (JCA)" test
# console click (and every one after it) silently produces no Kafka event.
#
# This step previously polled `journalctl -u cert-agent-deployer` for an
# "Attached cert-agent to PID ..." line to decide whether the warm-up JVM was
# ready -- that line is only ever emitted by java-agent/java_agent_deployer.py,
# which nothing here ever invokes, and cert-agent-deployer is an RPM (installs
# the jattach binary), not a systemd unit. That check could never succeed, so
# this warm-up silently never actually attached anything and always fell
# through to the WARNING below, on every deploy -- confirmed by reproducing
# and fixing the exact symptom on a live demo instance (see git history).
# Below, jattach the same way the test console's own JCA use case does
# (extras/test-server/use_cases.py's _run_java_keystore_cert), against the
# already-installed test-server's own CertAgentTest.class, and use a real
# Tetragon restart -- not apply-policies.sh -- which is the one remedy
# confirmed to actually fix this on a running instance (see
# extras/aws-demo/README.md's troubleshooting section).
CERT_AGENT_JAR=/opt/cert-agent/cert-agent.jar
CERT_AGENT_NATIVE_LIB=/opt/cert-agent/libcert_agent_stub.so
JATTACH_BIN=/opt/cert-agent-deployer/jattach

openssl req -x509 -newkey rsa:2048 -keyout /tmp/jca-warmup-key.pem \
    -out /tmp/jca-warmup-cert.pem -days 1 -nodes -subj "/CN=certsight-jca-warmup" 2>/dev/null

java -cp /opt/certsight-test-server CertAgentTest /tmp/jca-warmup-cert.pem &
WARMUP_JAVA_PID=$!
sleep 2  # let the JVM finish starting before jattach-ing into it

ATTACHED=false
if "${JATTACH_BIN}" "${WARMUP_JAVA_PID}" load instrument false "${CERT_AGENT_JAR}=${CERT_AGENT_NATIVE_LIB}"; then
    ATTACHED=true
fi

if [[ "${ATTACHED}" == true ]]; then
    echo "    Warm-up JVM (PID ${WARMUP_JAVA_PID}) attached -- restarting Tetragon so the uprobe binds against it"
    systemctl restart tetragon
    sleep 3
else
    echo "    WARNING: jattach into the warm-up JVM (PID ${WARMUP_JAVA_PID}) failed -- the JCA use case may need a manual 'sudo systemctl restart tetragon' (see extras/aws-demo/README.md)"
fi

kill "${WARMUP_JAVA_PID}" 2>/dev/null || true
rm -f /tmp/jca-warmup-key.pem /tmp/jca-warmup-cert.pem

touch /var/lib/certsight-demo-install-complete
echo "=== CertSight demo install complete ==="
