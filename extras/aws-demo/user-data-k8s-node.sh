#!/bin/bash
# EC2 user-data for the OPTIONAL second, k8s-hosted analyzer node
# (extras/aws-demo/deploy-k8s-node.sh) -- installs k3s, upstream Tetragon,
# and this repo's cert-analyzer Helm chart (with the demo test-console pod),
# wired to publish into the main demo instance's existing Kafka/Prometheus.
#
# Runs as root via cloud-init on first boot. Requires three placeholders to
# be substituted by deploy-k8s-node.sh before this is passed as --user-data:
#   __MAIN_PRIVATE_IP__      -- the main demo instance's private IP (Kafka target)
#   __CERTSIGHT_GIT_REF__    -- git ref to clone this repo at (branch or tag)
#   __K8S_ANALYZER_IMAGE_TAG__ -- image tag for cert-analyzer/cert-test-server
#
# Progress/errors: /var/log/certsight-k8s-node-install.log

set -uo pipefail
exec > >(tee -a /var/log/certsight-k8s-node-install.log) 2>&1
set -x

MAIN_PRIVATE_IP="__MAIN_PRIVATE_IP__"
CERTSIGHT_GIT_REF="__CERTSIGHT_GIT_REF__"
# No vX.Y-ubi9 tag is ever actually published on GHCR (known gap -- see
# project_ghcr_version_tags_never_published memory) -- the chart's own
# default (latest-ubi9) floats with whatever's newest on main, which is
# fine for throwaway test instances but not for a live deployment that
# should stay pinned. Pass the immutable sha-<commit>-ubi9 for the release
# you actually want (e.g. sha-f5c492d-ubi9 for v0.97 -- confirm via
# `git rev-parse vX.Y` which commit a version tag maps to).
K8S_ANALYZER_IMAGE_TAG="__K8S_ANALYZER_IMAGE_TAG__"
REPO_URL="https://github.com/bensanmorris/security_observability.git"
WORKDIR="/opt/certsight-k8s-install"
mkdir -p "${WORKDIR}"
cd "${WORKDIR}"

export PATH="${PATH}:/usr/local/bin"
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

echo "=== [1/6] Base packages ==="
dnf -y install git curl tar policycoreutils-python-utils nginx || true

echo "=== [2/6] k3s (single-node) ==="
curl -sfL https://get.k3s.io | sh -
for i in $(seq 1 30); do
    k3s kubectl get nodes 2>/dev/null | grep -q Ready && break
    sleep 5
done
k3s kubectl get nodes -o wide

echo "=== [3/6] Helm ==="
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

echo "=== [4/6] CertSight source (Helm chart + TracingPolicy files) ==="
git clone --depth 1 --branch "${CERTSIGHT_GIT_REF}" "${REPO_URL}" certsight-src

echo "=== [5/6] Tetragon (upstream chart) with the host-libssl mount uprobes need ==="
# Confirmed by a live spike (2026-09-07, see project memory) -- the upstream
# chart's default DaemonSet doesn't mount host /usr/lib64 into the tetragon
# container, so any uprobe policy with a hardcoded /usr/lib64/libssl.so.3
# path (openssl3-cert-load.yaml) fails to attach with "no such file or
# directory" even though the library exists on the actual host.
helm repo add cilium https://helm.cilium.io
helm repo update
cat <<'EOF' > /tmp/tetragon-values.yaml
extraHostPathMounts:
  - name: host-usr-lib64
    mountPath: /usr/lib64
EOF
# Only extraHostPathMounts -- it creates BOTH the volume and its mount on
# its own. Adding a matching tetragon.extraVolumeMounts entry too (as an
# earlier version of this script did, based on a spike that used `helm
# upgrade` rather than a first `helm install`) produces a duplicate
# mountPath and Kubernetes rejects the DaemonSet outright: "must be
# unique" -- confirmed via `helm template` against the live chart.
helm install tetragon cilium/tetragon -n kube-system -f /tmp/tetragon-values.yaml

for i in $(seq 1 30); do
    kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon 2>/dev/null | grep -q "2/2.*Running" && break
    sleep 5
done
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon

echo "=== [6/6] cert-analyzer chart (analyzer DaemonSet + test-console pod + TracingPolicies) ==="
# TracingPolicies are NOT applied separately here -- the chart's own
# templates/policies/*.yaml already create them (policies.*.enabled
# defaults to true for all three we need). Applying the raw files too, as
# an earlier version of this script did, creates them without Helm's
# ownership annotations first; the chart install then fails outright
# ("exists and cannot be imported ... missing key
# app.kubernetes.io/managed-by") -- confirmed in testing. scc/route/
# monitoring.* are all OpenShift-specific -- disabled here for plain k8s.
# kafka.bootstrapServers/demo.testServer.kafka.host point at the MAIN demo
# instance's Kafka, which install-kafka.sh there only advertises on its
# private IP when WITH_K8S_NODE=true was set for that instance.
# demo.testServer.prometheusUrl points at that same instance's real
# Prometheus (:9091) rather than the chart's own unreachable in-cluster
# demo-prometheus default -- needed for the test console's fleet
# blast-radius/chain-explorer/FIPS-rollout panels specifically (everything
# else works without it). Also needs deploy-k8s-node.sh's SG rule + a
# firewalld port opened on the main instance -- see its comments.
IMAGE_TAG_ARGS=()
if [[ -n "${K8S_ANALYZER_IMAGE_TAG}" ]]; then
    IMAGE_TAG_ARGS=(--set "image.tag=${K8S_ANALYZER_IMAGE_TAG}" --set "demo.testServer.image.tag=${K8S_ANALYZER_IMAGE_TAG}")
fi
helm install cert-analyzer "${WORKDIR}/certsight-src/extras/helm/cert-analyzer" \
    -n certsight --create-namespace \
    "${IMAGE_TAG_ARGS[@]}" \
    --set scc.hostaccess.enabled=false \
    --set route.enabled=false \
    --set monitoring.serviceMonitor.enabled=false \
    --set monitoring.prometheusRule.enabled=false \
    --set kafka.bootstrapServers="${MAIN_PRIVATE_IP}:9092" \
    --set demo.testServer.enabled=true \
    --set demo.testServer.kafka.host="${MAIN_PRIVATE_IP}" \
    --set demo.testServer.prometheusUrl="http://${MAIN_PRIVATE_IP}:9091"

for i in $(seq 1 30); do
    kubectl get pods -n certsight 2>/dev/null | grep -q "cert-test-server.*Running" && break
    sleep 5
done
kubectl get pods -n certsight -o wide
kubectl get tracingpolicies

echo "=== Exposing the test console (NodePort -- not part of the Helm release) ==="
# The chart's test-server Pod has no Service (upstream OpenShift usage is
# `oc port-forward`) -- a plain NodePort here is the simplest way to give
# this a public URL for the demo. The NodePort itself is bound to 30091,
# *not* the public 30090 the security group opens (see deploy-k8s-node.sh)
# -- nginx below sits in front on 30090, same division of labor as the main
# instance's 127.0.0.1:8091-internal / 0.0.0.0:8090-public split, so
# requests get rate-limited before they ever reach this unauthenticated,
# action-executing server. kube-proxy's NodePort DNAT applies to any local
# address, so nginx reaching 127.0.0.1:30091 works the same as it would
# reaching any other node IP -- confirmed live.
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: cert-test-server-nodeport
  namespace: certsight
spec:
  type: NodePort
  selector:
    app: cert-test-server
  ports:
  - port: 8090
    targetPort: 8090
    nodePort: 30091
EOF

echo "=== nginx reverse proxy in front of the test console (rate limiting) ==="
# Same config as the main instance's certsight-test-console.conf (see
# user-data.sh) -- this pod is the same cert-test-server app, so it exposes
# the same /api/run/* (expensive: spawns a JVM, generates certs, binds
# ports) and /api/events (long-lived SSE stream) paths.
cat <<'EOF' > /etc/nginx/conf.d/certsight-test-console.conf
limit_req_zone $binary_remote_addr zone=tc_general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=tc_actions:10m rate=12r/m;
limit_conn_zone $binary_remote_addr zone=tc_conn_actions:10m;
limit_conn_zone $binary_remote_addr zone=tc_conn_events:10m;
limit_req_status 429;
limit_conn_status 429;

server {
    listen 30090 default_server;
    server_name _;

    location /api/run/ {
        limit_req zone=tc_actions burst=6 nodelay;
        limit_conn tc_conn_actions 3;
        proxy_pass http://127.0.0.1:30091;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /api/events {
        limit_conn tc_conn_events 5;
        proxy_pass http://127.0.0.1:30091;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 1h;
        proxy_set_header Connection '';
    }

    location / {
        limit_req zone=tc_general burst=20 nodelay;
        proxy_pass http://127.0.0.1:30091;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
EOF
restorecon -v /etc/nginx/conf.d/certsight-test-console.conf || true
setsebool -P httpd_can_network_connect on || true
# SELinux only pre-labels standard ports as httpd-bindable; 30090 (k8s's
# NodePort range) needs an explicit label or nginx's bind() fails with EACCES.
semanage port -l | grep -qw 30090 || semanage port -a -t http_port_t -p tcp 30090 || true
# Belt-and-suspenders, matching deploy-k8s-node.sh's own firewalld handling
# for this box: the security group is the primary control (already open on
# 30090, unchanged), but if firewalld is active locally it must also allow
# nginx's own listen port. 30091 (the actual NodePort) is deliberately left
# closed here -- nginx reaches it over loopback, which firewalld doesn't
# filter by default, so it stays unreachable from outside even though it's
# not in the security group either.
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-port=30090/tcp
    firewall-cmd --reload
fi
systemctl enable --now nginx
nginx -t && systemctl reload nginx

touch /var/lib/certsight-k8s-node-install-complete
echo "=== CertSight k8s node install complete ==="
