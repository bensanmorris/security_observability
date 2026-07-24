#!/usr/bin/env bash
# description: Mirror a Prometheus image into OpenShift's internal registry for the cert-analyzer Helm chart's demo.prometheus (air-gapped hosts with no reachable quay.io)
set -uo pipefail

NAMESPACE=certsight

step() { echo; echo "==> $*"; }

usage() {
    cat <<'USAGE' >&2
Usage: mirror-prometheus-image.sh --image-tar <path> [--namespace <ns>]

On a machine with internet access, first fetch a pinned Prometheus version -- avoid :latest,
since it also becomes the mirrored tag, and a pod tagged :latest defaults to
imagePullPolicy: Always, which means it re-checks the (unreachable, air-gapped) upstream on
every restart instead of trusting the image already sitting in the internal registry:
  docker pull quay.io/prometheus/prometheus:v2.54.1
  docker save quay.io/prometheus/prometheus:v2.54.1 | gzip > prometheus-v2.54.1.tar.gz
Then copy the tar onto this host.

Required:
  --image-tar <path>   docker-save tar for quay.io/prometheus/prometheus (from 'docker save'
                        above).

Optional:
  --namespace <ns>      Default: certsight -- must match the namespace demo.prometheus.enabled
                         is installed into (its ServiceAccount only has pull access within its
                         own namespace's image streams).
USAGE
    exit 1
}

IMAGE_TAR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --image-tar) IMAGE_TAR="$2"; shift 2 ;;
        --image-tar=*) IMAGE_TAR="${1#*=}"; shift ;;
        --namespace) NAMESPACE="$2"; shift 2 ;;
        --namespace=*) NAMESPACE="${1#*=}"; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown argument: $1" >&2; usage ;;
    esac
done

[[ -n "$IMAGE_TAR" ]] || usage
[[ -f "$IMAGE_TAR" ]] || { echo "No such file: $IMAGE_TAR" >&2; exit 1; }

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

# Keep the tag baked into the tar (e.g. v2.54.1) rather than inventing our own -- one less
# place for the mirrored version to drift out of sync with what was actually downloaded, and
# avoids ever landing on :latest (see the imagePullPolicy note in usage() above).
TAG="${LOADED_IMAGE##*:}"
PUSH_IMAGE="$HOST/$NAMESPACE/prometheus:$TAG"
IN_CLUSTER_IMAGE="image-registry.openshift-image-registry.svc:5000/$NAMESPACE/prometheus:$TAG"

step "Tagging and pushing $PUSH_IMAGE"
sudo podman tag "$LOADED_IMAGE" "$PUSH_IMAGE"
sudo podman push --tls-verify=false "$PUSH_IMAGE"

step "Mirrored"
echo "In-cluster image reference: $IN_CLUSTER_IMAGE"
echo
echo "Use it with the cert-analyzer Helm chart:"
echo "  helm upgrade --install cert-analyzer ./extras/helm/cert-analyzer -n $NAMESPACE \\"
echo "    --reuse-values \\"
echo "    --set demo.prometheus.enabled=true \\"
echo "    --set demo.prometheus.image=$IN_CLUSTER_IMAGE"
