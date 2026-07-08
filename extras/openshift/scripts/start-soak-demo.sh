#!/usr/bin/env bash
# description: Start the OpenShift soak-test demo after a reboot (crc start, verify Tetragon/cert-analyzer/policies, relaunch the soak Job)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
NAMESPACE=certsight

step() { echo; echo "==> $*"; }

step "Starting CRC (no-op if already running)"
if ! command -v crc >/dev/null 2>&1; then
    echo "'crc' not found on PATH — install OpenShift Local first." >&2
    exit 1
fi
CRC_STATE=$(crc status -o json 2>/dev/null | grep -o '"OpenshiftStatus":[[:space:]]*"[^"]*"' | cut -d'"' -f4)
if [[ "$CRC_STATE" != "Running" ]]; then
    crc start
else
    echo "CRC already running."
fi

eval "$(crc oc-env)"

step "Checking cluster login"
if ! oc whoami >/dev/null 2>&1; then
    echo "Not logged in. Use the kubeadmin credentials printed above by 'crc start'"
    echo "(or run: crc console --credentials)"
    read -rp "Run 'oc login ...' in another terminal, then press Enter to continue: " _
    if ! oc whoami >/dev/null 2>&1; then
        echo "Still not logged in — aborting." >&2
        exit 1
    fi
fi
echo "Logged in as $(oc whoami) against $(oc whoami --show-server)"

step "Waiting for Tetragon to be ready (kube-system)"
if ! oc wait --for=condition=Ready pod -l app.kubernetes.io/name=tetragon -n kube-system --timeout=180s; then
    echo "Tetragon pod(s) not ready — check: oc get pods -n kube-system -l app.kubernetes.io/name=tetragon" >&2
    exit 1
fi

step "Waiting for cert-analyzer DaemonSet to be ready ($NAMESPACE)"
if ! oc rollout status daemonset/cert-expiry-monitor -n "$NAMESPACE" --timeout=180s; then
    echo "cert-analyzer DaemonSet not ready — check: oc get pods -n $NAMESPACE -o wide" >&2
    exit 1
fi

step "Checking Tetragon tracing policies"
POLICY_COUNT=$(oc get tracingpolicies -o name 2>/dev/null | wc -l)
if [[ "$POLICY_COUNT" -eq 0 ]]; then
    echo "No tracing policies found — re-applying core policies."
    oc apply -f "$REPO_ROOT/tetragon-policies/certificate-file-access.yaml"
    oc apply -f "$REPO_ROOT/tetragon-policies/tcp-connect-tls.yaml"
    oc apply -f "$REPO_ROOT/tetragon-policies/experimental/tls-service-tracking.yaml"
else
    echo "$POLICY_COUNT tracing polic(y/ies) already loaded."
fi

step "Relaunching the soak-test Job"
# Jobs are immutable once created, and a prior run has usually already
# Completed/Failed by the time of a reboot — delete before re-apply rather
# than letting `oc apply` fail on the immutable spec.
oc delete job cert-soak-test -n "$NAMESPACE" --ignore-not-found
oc apply -f "$REPO_ROOT/probe_tests/openshift-soak/job.yaml"

step "Demo is up"
echo "Follow the soak Job:   oc logs -n $NAMESPACE -l job-name=cert-soak-test -f"
echo "Follow the analyzer:   oc logs -n $NAMESPACE -l app=cert-expiry-monitor -f"
echo "Metrics:                oc exec -n $NAMESPACE <cert-analyzer-pod> -- curl -s http://localhost:9090/metrics"
echo

read -rp "Tail the soak Job logs now? [y/N] " REPLY
if [[ "$REPLY" =~ ^[Yy]$ ]]; then
    oc logs -n "$NAMESPACE" -l job-name=cert-soak-test -f
fi
