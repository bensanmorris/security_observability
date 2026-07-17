#!/usr/bin/env bash
# description: Quick-recreate the cert-test-server Pod after a crash/preemption, no image rebuild
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
NAMESPACE=certsight
MANIFEST="$REPO_ROOT/extras/openshift/test-server-pod.yaml"

step() { echo; echo "==> $*"; }

KAFKA_HOST_ARG=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kafka-host)
            KAFKA_HOST_ARG="$2"
            shift 2
            ;;
        --kafka-host=*)
            KAFKA_HOST_ARG="${1#*=}"
            shift
            ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Usage: $0 [--kafka-host <ip>]" >&2
            exit 1
            ;;
    esac
done

step "Checking cluster login"
if ! oc whoami >/dev/null 2>&1; then
    echo "Not logged in to the cluster — run 'oc login ...' first." >&2
    exit 1
fi

step "Resolving the Kafka host"
if [[ -n "$KAFKA_HOST_ARG" ]]; then
    KAFKA_HOST="$KAFKA_HOST_ARG"
    echo "Using --kafka-host: $KAFKA_HOST"
else
    KAFKA_HOST=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") print $(i+1)}')
    if [[ -z "$KAFKA_HOST" ]]; then
        echo "Could not auto-detect the host's IP -- pass it explicitly: $0 --kafka-host <ip>" >&2
        exit 1
    fi
    echo "Auto-detected: $KAFKA_HOST (override with --kafka-host <ip>)"
fi

render_manifest() {
    sed "s#__TEST_SERVER_KAFKA_HOST__#$KAFKA_HOST#g" "$MANIFEST"
}

step "Picking an image tag to redeploy"
# The Pod that just crashed (or got preempted by CRC's marketplace catalog
# refresh — see OPENSHIFT-DEPLOYMENT-README.md) may or may not still be
# visible: preemption can delete the Pod object outright, with no leftover
# to read the image from. Prefer the currently-set image if the Pod object
# is still around; otherwise fall back to the newest cert-test-server tag
# already sitting in the internal registry — no rebuild either way.
IMAGE=$(oc get pod cert-test-server -n "$NAMESPACE" \
    -o jsonpath='{.spec.containers[?(@.name=="test-server")].image}' 2>/dev/null || true)
if [[ -n "$IMAGE" ]]; then
    echo "Reusing the crashed Pod's image: $IMAGE"
else
    TAG_NAME=$(oc get istag -n "$NAMESPACE" -o jsonpath='{range .items[*]}{.metadata.creationTimestamp}{" "}{.metadata.name}{"\n"}{end}' 2>/dev/null \
        | grep '^[^ ]* cert-test-server:' | sort | tail -1 | awk '{print $2}')
    if [[ -z "$TAG_NAME" ]]; then
        echo "Could not find any cert-test-server image in the registry — run deploy-test-server.sh instead (it builds one)." >&2
        exit 1
    fi
    IMAGE="image-registry.openshift-image-registry.svc:5000/certsight/$TAG_NAME"
    echo "Pod is gone — using the newest registry tag instead: $IMAGE"
fi

step "Recreating the Pod"
if oc get pod cert-test-server -n "$NAMESPACE" >/dev/null 2>&1; then
    oc delete pod cert-test-server -n "$NAMESPACE" --wait=true
fi
render_manifest | oc apply -f -
oc set image pod/cert-test-server test-server="$IMAGE" -n "$NAMESPACE"

step "Waiting for the rollout"
if ! oc wait --for=condition=Ready pod/cert-test-server -n "$NAMESPACE" --timeout=120s; then
    echo "Pod not ready — check: oc get pod cert-test-server -n $NAMESPACE -o wide" >&2
    echo "                       oc logs cert-test-server -n $NAMESPACE" >&2
    exit 1
fi

step "Deployed"
oc get pod cert-test-server -n "$NAMESPACE" -o wide

step "Port-forwarding to the Pod"
PF_LOG="$(mktemp)"
pkill -f "oc port-forward -n $NAMESPACE pod/cert-test-server 8090:8090" 2>/dev/null || true
nohup oc port-forward -n "$NAMESPACE" pod/cert-test-server 8090:8090 >"$PF_LOG" 2>&1 &
PF_PID=$!
disown "$PF_PID"

for _ in $(seq 1 20); do
    if curl -sf -o /dev/null http://localhost:8090/; then
        break
    fi
    if ! kill -0 "$PF_PID" 2>/dev/null; then
        echo "port-forward exited unexpectedly:" >&2
        cat "$PF_LOG" >&2
        exit 1
    fi
    sleep 0.5
done

if ! curl -sf -o /dev/null http://localhost:8090/; then
    echo "Port-forward did not come up in time — check $PF_LOG" >&2
    exit 1
fi

echo
echo "Test console:  http://localhost:8090"
echo "Stop it with:  kill $PF_PID"
