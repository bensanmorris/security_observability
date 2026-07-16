#!/usr/bin/env bash
# description: Build the interactive test-console image and (re)deploy the cert-test-server Pod on OpenShift
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
NAMESPACE=certsight

step() { echo; echo "==> $*"; }

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
if ! oc get pod cert-test-server -n "$NAMESPACE" >/dev/null 2>&1; then
    oc apply -f "$REPO_ROOT/extras/openshift/test-server-pod.yaml"
fi
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
echo
echo "Drive it:  oc port-forward -n $NAMESPACE pod/cert-test-server 8090:8090   (then open http://localhost:8090)"
echo "Or:        oc rsh -n $NAMESPACE cert-test-server"
echo
echo "Once you're happy with this build, tag a real version and update"
echo "extras/openshift/test-server-pod.yaml's image field to match — the checked-in manifest"
echo "should stay on a stable tag rather than $TAG."
