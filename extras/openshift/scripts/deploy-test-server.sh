#!/usr/bin/env bash
# description: Build the interactive test-console image and (re)deploy the cert-test-server Pod on OpenShift
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

step "Resolving the Kafka host"
if [[ -n "$KAFKA_HOST_ARG" ]]; then
    KAFKA_HOST="$KAFKA_HOST_ARG"
    echo "Using --kafka-host: $KAFKA_HOST"
else
    # Default-route source IP -- the address the pod network can actually
    # reach back to (see the Kafka reachability section of
    # extras/OPENSHIFT-DEPLOYMENT-README.md for why plain localhost/127.0.0.1
    # doesn't work here).
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

step "Checking cluster login"
if ! oc whoami >/dev/null 2>&1; then
    echo "Not logged in to the cluster — run 'oc login ...' first." >&2
    exit 1
fi

step "Building the test-server image"
(cd "$REPO_ROOT/extras/test-server" && sudo podman build -t cert-test-server:latest -f Containerfile .)

step "Locating the internal image registry route"
HOST=$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}' 2>/dev/null)
if [[ -z "$HOST" ]]; then
    echo "Could not find the internal registry route. Enable it first:" >&2
    echo "  oc patch configs.imageregistry.operator.openshift.io/cluster --patch '{\"spec\":{\"defaultRoute\":true}}' --type=merge" >&2
    exit 1
fi

step "Logging into the internal registry"
# Always sudo podman: extras/build.sh-style images are built via 'sudo podman build', which
# writes into root's podman storage, separate from the current user's own storage.
sudo podman login -u kubeadmin -p "$(oc whoami -t)" --tls-verify=false "$HOST"

# A fresh tag every run, not :latest -- imagePullPolicy: IfNotPresent means a node that already
# pulled ':latest' once will never re-pull it just because the registry content changed under
# the same tag (see "Why a fresh tag, not just re-pushing :latest" in
# extras/OPENSHIFT-DEPLOYMENT-README.md). A fresh tag was never cached, so the pull is
# unconditionally fresh.
TAG="dev-$(date +%s)"
PUSH_IMAGE="$HOST/certsight/cert-test-server:$TAG"
IN_CLUSTER_IMAGE="image-registry.openshift-image-registry.svc:5000/certsight/cert-test-server:$TAG"

step "Tagging and pushing $PUSH_IMAGE"
sudo podman tag localhost/cert-test-server:latest "$PUSH_IMAGE"
sudo podman push --tls-verify=false "$PUSH_IMAGE"

step "Deploying the Pod"
# Almost every field on a live Pod other than spec.containers[*].image is
# immutable (env vars, volumes, serviceAccountName, ...), and this manifest
# has grown several of those over time -- Kafka host, the hostPath mount for
# TEST_SERVER_CERT_DIR, etc. Trying to special-case which fields changed has
# already missed a real change once (the hostPath volume slipped through a
# check that only compared image/Kafka-host). This is a lightweight demo
# pod with no state worth preserving, so just always delete and recreate
# rather than chase field-by-field drift detection.
if oc get pod cert-test-server -n "$NAMESPACE" >/dev/null 2>&1; then
    oc delete pod cert-test-server -n "$NAMESPACE" --wait=true
fi
render_manifest | oc apply -f -
oc set image pod/cert-test-server test-server="$IN_CLUSTER_IMAGE" -n "$NAMESPACE"

step "Waiting for the rollout"
if ! oc wait --for=condition=Ready pod/cert-test-server -n "$NAMESPACE" --timeout=120s; then
    echo "Pod not ready — check: oc get pod cert-test-server -n $NAMESPACE -o wide" >&2
    echo "                       oc logs cert-test-server -n $NAMESPACE" >&2
    exit 1
fi

step "Deployed"
oc get pod cert-test-server -n "$NAMESPACE" -o wide
echo
echo "Image now running: $(oc get pod cert-test-server -n "$NAMESPACE" -o jsonpath='{.status.containerStatuses[0].image}')"
echo "Digest:             $(oc get pod cert-test-server -n "$NAMESPACE" -o jsonpath='{.status.containerStatuses[0].imageID}')"

step "Port-forwarding to the Pod"
PF_LOG="$(mktemp)"
# Kill any stale forward left running from a previous invocation of this script.
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
echo "Or shell in:   oc rsh -n $NAMESPACE cert-test-server"
echo
echo "Once you're happy with this build, tag a real version and update"
echo "extras/openshift/test-server-pod.yaml's image field to match — the checked-in manifest"
echo "should stay on a stable tag rather than $TAG."
