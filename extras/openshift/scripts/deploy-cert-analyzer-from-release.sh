#!/usr/bin/env bash
# description: Load a pre-built cert-analyzer image from a downloaded GitHub Release tar and deploy it to OpenShift (no local build required)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
NAMESPACE=certsight
MANIFEST="$REPO_ROOT/extras/openshift/daemonset.yaml"

step() { echo; echo "==> $*"; }

usage() {
    echo "Usage: $0 --image-tar <path> [--kafka-host <ip>]" >&2
    echo >&2
    echo "  --image-tar   Path to a cert-analyzer-ubi{8,9}-<version>.tar.gz asset downloaded" >&2
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
    # Default-route source IP -- the address the hostNetwork DaemonSet pod can actually reach
    # the host broker on (see the Kafka reachability section of
    # extras/OPENSHIFT-DEPLOYMENT-README.md).
    KAFKA_HOST=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") print $(i+1)}')
    if [[ -z "$KAFKA_HOST" ]]; then
        echo "Could not auto-detect the host's IP -- pass it explicitly: $0 --image-tar $IMAGE_TAR --kafka-host <ip>" >&2
        exit 1
    fi
    echo "Auto-detected: $KAFKA_HOST (override with --kafka-host <ip>)"
fi

render_manifest() {
    sed "s#__KAFKA_BOOTSTRAP_SERVERS__#$KAFKA_HOST:9092#g" "$MANIFEST"
}

step "Checking cluster login"
if ! oc whoami >/dev/null 2>&1; then
    echo "Not logged in to the cluster — run 'oc login ...' first." >&2
    exit 1
fi

step "Loading $IMAGE_TAR"
# sudo podman throughout, same as every other script in this directory -- keeps every
# tag/push below reading from the same podman storage the image was just loaded into,
# rather than a separate (and possibly stale) plain-user rootless storage.
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

# A fresh tag every run, not :latest -- imagePullPolicy: IfNotPresent means a node that
# already pulled ":latest" once will never re-pull it just because the registry content
# changed under the same tag. See "Why a fresh tag, not just re-pushing :latest" in
# extras/OPENSHIFT-DEPLOYMENT-README.md.
TAG="dev-$(date +%s)"
PUSH_IMAGE="$HOST/certsight/cert-analyzer:$TAG"
IN_CLUSTER_IMAGE="image-registry.openshift-image-registry.svc:5000/certsight/cert-analyzer:$TAG"

step "Tagging and pushing $PUSH_IMAGE"
sudo podman tag "$LOADED_IMAGE" "$PUSH_IMAGE"
sudo podman push --tls-verify=false "$PUSH_IMAGE"

step "Applying the DaemonSet manifest"
render_manifest | oc apply -f -

step "Pointing the DaemonSet at the new tag"
oc set image daemonset/cert-expiry-monitor analyzer="$IN_CLUSTER_IMAGE" -n "$NAMESPACE"

step "Waiting for the rollout"
if ! oc rollout status daemonset/cert-expiry-monitor -n "$NAMESPACE" --timeout=180s; then
    echo "Rollout did not finish — check: oc get pods -n $NAMESPACE -o wide" >&2
    exit 1
fi

step "Deployed"
oc get pods -n "$NAMESPACE" -l app=cert-expiry-monitor -o wide
NEW_POD=$(oc get pods -n "$NAMESPACE" -l app=cert-expiry-monitor -o jsonpath='{.items[0].metadata.name}')
echo
echo "Image now running: $(oc get pod "$NEW_POD" -n "$NAMESPACE" -o jsonpath='{.status.containerStatuses[0].image}')"
echo "Digest:             $(oc get pod "$NEW_POD" -n "$NAMESPACE" -o jsonpath='{.status.containerStatuses[0].imageID}')"
echo
echo "Once you're happy with this build, tag a real version and update"
echo "extras/openshift/daemonset.yaml's image field to match — the checked-in manifest should"
echo "stay on a stable tag rather than $TAG."
