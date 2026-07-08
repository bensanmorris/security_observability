#!/usr/bin/env bash
# description: Rebuild the cert-analyzer image and redeploy it to the OpenShift DaemonSet under a fresh tag
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

step "Rebuilding cert-analyzer image"
# build.sh must run from the repo root (it builds against the root Containerfile).
(cd "$REPO_ROOT" && bash extras/build.sh)

step "Locating the internal image registry route"
HOST=$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}' 2>/dev/null)
if [[ -z "$HOST" ]]; then
    echo "Could not find the internal registry route. Enable it first:" >&2
    echo "  oc patch configs.imageregistry.operator.openshift.io/cluster --patch '{\"spec\":{\"defaultRoute\":true}}' --type=merge" >&2
    exit 1
fi

step "Logging into the internal registry"
# build.sh runs 'sudo podman build', which writes into root's podman image
# storage — every tag/push/login below has to use the same 'sudo podman', or
# it'll silently tag/push a stale image from the current user's own storage
# instead. See "Rebuilding and redeploying after a code change" in
# extras/OPENSHIFT-DEPLOYMENT-README.md.
sudo podman login -u kubeadmin -p "$(oc whoami -t)" --tls-verify=false "$HOST"

# A fresh tag every run, not :latest — imagePullPolicy: IfNotPresent means a
# node that already pulled ":latest" once will never re-pull it just because
# the registry content changed under the same tag.
TAG="dev-$(date +%s)"
PUSH_IMAGE="$HOST/certsight/cert-analyzer:$TAG"
IN_CLUSTER_IMAGE="image-registry.openshift-image-registry.svc:5000/certsight/cert-analyzer:$TAG"

step "Tagging and pushing $PUSH_IMAGE"
sudo podman tag localhost/cert-analyzer:latest "$PUSH_IMAGE"
sudo podman push --tls-verify=false "$PUSH_IMAGE"

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
