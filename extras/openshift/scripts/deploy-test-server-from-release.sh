#!/usr/bin/env bash
# description: Load a pre-built cert-test-server image from a downloaded GitHub Release tar and (re)deploy the Pod on OpenShift (no local build required)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
NAMESPACE=certsight
MANIFEST="$REPO_ROOT/extras/openshift/test-server-pod.yaml"

step() { echo; echo "==> $*"; }

usage() {
    echo "Usage: $0 --image-tar <path> [--kafka-host <ip>]" >&2
    echo >&2
    echo "  --image-tar   Path to a cert-test-server-ubi{8,9}-<version>.tar.gz asset downloaded" >&2
    echo "                from this repo's GitHub Releases page (docker save/gzip format)." >&2
    echo "                For locked-down hosts with no registry egress: download it on any" >&2
    echo "                machine with internet access, then copy the file over." >&2
    exit 1
}

IMAGE_TAR=""
KAFKA_HOST_ARG=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --image-tar)
            IMAGE_TAR="$2"
            shift 2
            ;;
        --image-tar=*)
            IMAGE_TAR="${1#*=}"
            shift
            ;;
        --kafka-host)
            KAFKA_HOST_ARG="$2"
            shift 2
            ;;
        --kafka-host=*)
            KAFKA_HOST_ARG="${1#*=}"
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage
            ;;
    esac
done

[[ -n "$IMAGE_TAR" ]] || usage
[[ -f "$IMAGE_TAR" ]] || { echo "No such file: $IMAGE_TAR" >&2; exit 1; }

step "Resolving the Kafka host"
if [[ -n "$KAFKA_HOST_ARG" ]]; then
    KAFKA_HOST="$KAFKA_HOST_ARG"
    echo "Using --kafka-host: $KAFKA_HOST"
else
    # Default-route source IP -- the address the pod network can actually reach back to
    # (see the Kafka reachability section of extras/OPENSHIFT-DEPLOYMENT-README.md).
    KAFKA_HOST=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") print $(i+1)}')
    if [[ -z "$KAFKA_HOST" ]]; then
        echo "Could not auto-detect the host's IP -- pass it explicitly: $0 --image-tar $IMAGE_TAR --kafka-host <ip>" >&2
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

step "Loading $IMAGE_TAR"
LOAD_OUTPUT=$(sudo podman load -i "$IMAGE_TAR")
echo "$LOAD_OUTPUT"
LOADED_IMAGE=$(echo "$LOAD_OUTPUT" | sed -nE 's/^Loaded image\(s\)?: *//p' | tail -1)
if [[ -z "$LOADED_IMAGE" ]]; then
    echo "Could not determine the loaded image reference from the 'podman load' output above." >&2
    exit 1
fi
echo "Loaded: $LOADED_IMAGE"

step "Locating the internal image registry route"
HOST=$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}' 2>/dev/null)
if [[ -z "$HOST" ]]; then
    echo "Could not find the internal registry route. Enable it first:" >&2
    echo "  oc patch configs.imageregistry.operator.openshift.io/cluster --patch '{\"spec\":{\"defaultRoute\":true}}' --type=merge" >&2
    exit 1
fi

step "Logging into the internal registry"
sudo podman login -u kubeadmin -p "$(oc whoami -t)" --tls-verify=false "$HOST"

TAG="dev-$(date +%s)"
PUSH_IMAGE="$HOST/certsight/cert-test-server:$TAG"
IN_CLUSTER_IMAGE="image-registry.openshift-image-registry.svc:5000/certsight/cert-test-server:$TAG"
LATEST_PUSH_IMAGE="$HOST/certsight/cert-test-server:latest"

step "Tagging and pushing $PUSH_IMAGE"
sudo podman tag "$LOADED_IMAGE" "$PUSH_IMAGE"
sudo podman push --tls-verify=false "$PUSH_IMAGE"

step "Also pushing :latest"
# test-server-pod.yaml's fix-cert-dir-perms initContainer has 'image:' hardcoded to the
# ':latest' tag (not a substitution placeholder like the main container's image field) --
# nothing else in this script updates it via 'oc set image', so on a namespace where
# ':latest' was never pushed before, that initContainer would ImagePullBackOff even though
# the main container below deploys fine under the fresh dev-<timestamp> tag. Pushing the
# same freshly-loaded image under ':latest' too keeps the initContainer working without
# having to restructure the manifest/other scripts.
sudo podman tag "$LOADED_IMAGE" "$LATEST_PUSH_IMAGE"
sudo podman push --tls-verify=false "$LATEST_PUSH_IMAGE"

step "Deploying the Pod"
# Almost every field on a live Pod other than spec.containers[*].image is immutable -- see
# the comment in deploy-test-server.sh. Just delete and recreate rather than chase
# field-by-field drift detection.
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
