#!/usr/bin/env bash
# description: Restart the cert-expiry-monitor DaemonSet after a crash/stall, no image rebuild
set -uo pipefail

NAMESPACE=certsight
DAEMONSET=cert-expiry-monitor

step() { echo; echo "==> $*"; }

step "Checking cluster login"
if ! oc whoami >/dev/null 2>&1; then
    echo "Not logged in to the cluster — run 'oc login ...' first." >&2
    exit 1
fi

step "Restarting the DaemonSet"
# Unlike cert-test-server (a bare Pod with no controller), the DaemonSet keeps its own spec --
# no image tag to rediscover, just ask the controller to replace the pod(s).
oc rollout restart daemonset/"$DAEMONSET" -n "$NAMESPACE"

# openshift-marketplace's catalog-refresh pods run at system-cluster-critical priority; this
# DaemonSet is pinned to the same priority (see the priorityClassName comment in
# daemonset.yaml) specifically so it can no longer lose scheduling contention to them. If it
# still can't schedule, the real blocker is the node being out of *headroom* altogether, not a
# priority fight -- clearing any catalog pods stuck in ImagePullBackOff (they hold their memory
# request even while permanently failing, and openshift-marketplace's own CronJobs replace them
# on their next cycle regardless) is the same fix used by hand earlier and is safe to automate.
free_stuck_marketplace_pods() {
    local stuck
    stuck=$(oc get pods -n openshift-marketplace --field-selector=status.phase!=Running \
        -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)
    if [[ -z "$stuck" ]]; then
        return 1
    fi
    echo "Found stuck openshift-marketplace pod(s), clearing to free memory headroom:"
    echo "$stuck" | sed 's/^/  /'
    # shellcheck disable=SC2086
    oc delete pod $stuck -n openshift-marketplace --ignore-not-found 2>&1
    return 0
}

step "Waiting for the rollout"
if ! oc rollout status daemonset/"$DAEMONSET" -n "$NAMESPACE" --timeout=90s; then
    echo "Rollout stalled — checking for a memory-scheduling blocker before giving up..." >&2
    if free_stuck_marketplace_pods; then
        step "Retrying the rollout wait"
        if ! oc rollout status daemonset/"$DAEMONSET" -n "$NAMESPACE" --timeout=90s; then
            echo "Still not ready — check: oc get pods -n $NAMESPACE -l app=$DAEMONSET -o wide" >&2
            echo "                         oc describe node crc | grep -A8 'Allocated resources'" >&2
            exit 1
        fi
    else
        echo "No stuck marketplace pods found — something else is blocking the rollout." >&2
        echo "Check: oc get pods -n $NAMESPACE -l app=$DAEMONSET -o wide" >&2
        echo "       oc get events -n $NAMESPACE --sort-by='.lastTimestamp' | tail -20" >&2
        exit 1
    fi
fi

step "Restarted"
POD=$(oc get pods -n "$NAMESPACE" -l app="$DAEMONSET" -o jsonpath='{.items[0].metadata.name}')
oc get pod "$POD" -n "$NAMESPACE" -o wide
echo
echo "Image running: $(oc get pod "$POD" -n "$NAMESPACE" -o jsonpath='{.status.containerStatuses[0].image}')"
echo "Readiness:     $(oc exec -n "$NAMESPACE" "$POD" -- curl -s localhost:8086/readyz 2>/dev/null || echo 'not reachable yet')"
