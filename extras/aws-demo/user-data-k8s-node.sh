#!/bin/bash
# EC2 user-data for the OPTIONAL second, k8s-hosted analyzer node
# (extras/aws-demo/deploy-k8s-node.sh) -- installs k3s, upstream Tetragon,
# and this repo's cert-analyzer Helm chart (with the demo test-console pod),
# wired to publish into the main demo instance's existing Kafka/Prometheus.
#
# Runs as root via cloud-init on first boot. Requires two placeholders to be
# substituted by deploy-k8s-node.sh before this is passed as --user-data:
#   __MAIN_PRIVATE_IP__   -- the main demo instance's private IP (Kafka target)
#   __CERTSIGHT_GIT_REF__ -- git ref to clone this repo at (branch or tag)
#
# Progress/errors: /var/log/certsight-k8s-node-install.log

set -uo pipefail
exec > >(tee -a /var/log/certsight-k8s-node-install.log) 2>&1
set -x

MAIN_PRIVATE_IP="__MAIN_PRIVATE_IP__"
CERTSIGHT_GIT_REF="__CERTSIGHT_GIT_REF__"
REPO_URL="https://github.com/bensanmorris/security_observability.git"
WORKDIR="/opt/certsight-k8s-install"
mkdir -p "${WORKDIR}"
cd "${WORKDIR}"

export PATH="${PATH}:/usr/local/bin"
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

echo "=== [1/6] Base packages ==="
dnf -y install git curl tar || true

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
tetragon:
  extraVolumeMounts:
    - name: host-usr-lib64
      mountPath: /usr/lib64
      readOnly: true
EOF
helm install tetragon cilium/tetragon -n kube-system -f /tmp/tetragon-values.yaml

for i in $(seq 1 30); do
    kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon 2>/dev/null | grep -q "2/2.*Running" && break
    sleep 5
done
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon

echo "=== Applying TracingPolicies ==="
kubectl apply -f "${WORKDIR}/certsight-src/tetragon-policies/certificate-file-access.yaml"
kubectl apply -f "${WORKDIR}/certsight-src/tetragon-policies/experimental/tls-service-tracking.yaml"
kubectl apply -f "${WORKDIR}/certsight-src/tetragon-policies/experimental/openssl3-cert-load.yaml"
kubectl get tracingpolicies

echo "=== [6/6] cert-analyzer chart (analyzer DaemonSet + test-console pod) ==="
# scc/route/monitoring.* are all OpenShift-specific -- disabled here for
# plain k8s. kafka.bootstrapServers/demo.testServer.kafka.host point at the
# MAIN demo instance's Kafka, which install-kafka.sh there only advertises
# on its private IP when WITH_K8S_NODE=true was set for that instance.
helm install cert-analyzer "${WORKDIR}/certsight-src/extras/helm/cert-analyzer" \
    -n certsight --create-namespace \
    --set scc.hostaccess.enabled=false \
    --set route.enabled=false \
    --set monitoring.serviceMonitor.enabled=false \
    --set monitoring.prometheusRule.enabled=false \
    --set kafka.bootstrapServers="${MAIN_PRIVATE_IP}:9092" \
    --set demo.testServer.enabled=true \
    --set demo.testServer.kafka.host="${MAIN_PRIVATE_IP}"

for i in $(seq 1 30); do
    kubectl get pods -n certsight 2>/dev/null | grep -q "cert-test-server.*Running" && break
    sleep 5
done
kubectl get pods -n certsight -o wide

echo "=== Exposing the test console (NodePort -- not part of the Helm release) ==="
# The chart's test-server Pod has no Service (upstream OpenShift usage is
# `oc port-forward`) -- a plain NodePort here is the simplest way to give
# this a public URL for the demo, matching the main instance's own
# nginx-fronted :8090 in spirit if not in hardening (no rate limiting here
# yet -- see extras/aws-demo/README.md's k8s-node section for the caveat).
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
    nodePort: 30090
EOF

touch /var/lib/certsight-k8s-node-install-complete
echo "=== CertSight k8s node install complete ==="
