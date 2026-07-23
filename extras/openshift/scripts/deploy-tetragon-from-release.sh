#!/usr/bin/env bash
# description: Mirror the Tetragon Helm chart's images into OpenShift's internal registry and install/upgrade it from them (for air-gapped hosts with no reachable quay.io/helm.cilium.io)
set -uo pipefail

step() { echo; echo "==> $*"; }

MIRROR_NAMESPACE=tetragon-mirror
RELEASE_NAMESPACE=kube-system
RELEASE_NAME=tetragon

usage() {
    cat <<'USAGE' >&2
Usage: deploy-tetragon-from-release.sh --chart <tetragon-X.Y.Z.tgz> --agent-image-tar <path> [options]

On a machine with internet access, first fetch the chart and the images it references
(check 'helm show values cilium/tetragon --version X.Y.Z' for the exact image/tag pairs --
they can change between chart versions):
  helm repo add cilium https://helm.cilium.io
  helm pull cilium/tetragon --version 1.7.0                        # -> tetragon-1.7.0.tgz
  docker pull quay.io/cilium/tetragon:v1.7.0
  docker save quay.io/cilium/tetragon:v1.7.0 | gzip > tetragon-agent.tar.gz
  docker pull quay.io/cilium/tetragon-operator:v1.7.0
  docker save quay.io/cilium/tetragon-operator:v1.7.0 | gzip > tetragon-operator.tar.gz
  docker pull quay.io/cilium/hubble-export-stdout:v1.1.1
  docker save quay.io/cilium/hubble-export-stdout:v1.1.1 | gzip > hubble-export-stdout.tar.gz
Then copy the chart tarball and whichever image tars you need onto this host.

Required:
  --chart <path>                   Tetragon Helm chart tarball (from 'helm pull' above).
  --agent-image-tar <path>         docker-save tar for quay.io/cilium/tetragon (the agent
                                    DaemonSet -- always required, this component can't be
                                    disabled).

Optional (the chart's default values.yaml enables both of these -- pass the matching
--skip-* flag only if you're also disabling the component itself via --extra-set):
  --operator-image-tar <path>      docker-save tar for quay.io/cilium/tetragon-operator.
  --export-stdout-image-tar <path> docker-save tar for quay.io/cilium/hubble-export-stdout.
  --rthooks-image-tar <path>       docker-save tar for quay.io/cilium/tetragon-rthooks. Only
                                    needed if you pass --extra-set rthooks.enabled=true (the
                                    chart default is disabled).
  --skip-operator                  Don't mirror/require the operator image -- pass
                                    --extra-set tetragonOperator.enabled=false too, or the
                                    install will still try to pull the real quay.io image.
  --skip-export-stdout             Don't mirror/require the export-stdout image -- pass
                                    --extra-set export.mode="" too, same reasoning.
  --release-namespace <ns>         Default: kube-system.
  --release-name <name>            Default: tetragon.
  --extra-set <key=value>          Extra --set passed to 'helm upgrade --install' (repeatable).
USAGE
    exit 1
}

CHART=""
AGENT_TAR=""
OPERATOR_TAR=""
EXPORT_TAR=""
RTHOOKS_TAR=""
SKIP_OPERATOR=false
SKIP_EXPORT=false
EXTRA_SET_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --chart) CHART="$2"; shift 2 ;;
        --chart=*) CHART="${1#*=}"; shift ;;
        --agent-image-tar) AGENT_TAR="$2"; shift 2 ;;
        --agent-image-tar=*) AGENT_TAR="${1#*=}"; shift ;;
        --operator-image-tar) OPERATOR_TAR="$2"; shift 2 ;;
        --operator-image-tar=*) OPERATOR_TAR="${1#*=}"; shift ;;
        --export-stdout-image-tar) EXPORT_TAR="$2"; shift 2 ;;
        --export-stdout-image-tar=*) EXPORT_TAR="${1#*=}"; shift ;;
        --rthooks-image-tar) RTHOOKS_TAR="$2"; shift 2 ;;
        --rthooks-image-tar=*) RTHOOKS_TAR="${1#*=}"; shift ;;
        --skip-operator) SKIP_OPERATOR=true; shift ;;
        --skip-export-stdout) SKIP_EXPORT=true; shift ;;
        --release-namespace) RELEASE_NAMESPACE="$2"; shift 2 ;;
        --release-namespace=*) RELEASE_NAMESPACE="${1#*=}"; shift ;;
        --release-name) RELEASE_NAME="$2"; shift 2 ;;
        --release-name=*) RELEASE_NAME="${1#*=}"; shift ;;
        --extra-set) EXTRA_SET_ARGS+=(--set "$2"); shift 2 ;;
        --extra-set=*) EXTRA_SET_ARGS+=(--set "${1#*=}"); shift ;;
        -h|--help) usage ;;
        *) echo "Unknown argument: $1" >&2; usage ;;
    esac
done

[[ -n "$CHART" ]] || usage
[[ -f "$CHART" ]] || { echo "No such file: $CHART" >&2; exit 1; }
[[ -n "$AGENT_TAR" ]] || usage
[[ -f "$AGENT_TAR" ]] || { echo "No such file: $AGENT_TAR" >&2; exit 1; }
for tar_var in OPERATOR_TAR EXPORT_TAR RTHOOKS_TAR; do
    tar_path="${!tar_var}"
    if [[ -n "$tar_path" ]]; then
        [[ -f "$tar_path" ]] || { echo "No such file: $tar_path" >&2; exit 1; }
    fi
done

if [[ -z "$OPERATOR_TAR" && "$SKIP_OPERATOR" != true ]]; then
    echo "Default chart values enable the operator (tetragonOperator.enabled: true)." >&2
    echo "Pass --operator-image-tar <path>, or --skip-operator if you're disabling it" >&2
    echo "yourself via --extra-set tetragonOperator.enabled=false." >&2
    exit 1
fi
if [[ -z "$EXPORT_TAR" && "$SKIP_EXPORT" != true ]]; then
    echo "Default chart values enable stdout export (export.mode: stdout)." >&2
    echo "Pass --export-stdout-image-tar <path>, or --skip-export-stdout if you're disabling" >&2
    echo 'it yourself via --extra-set export.mode="".' >&2
    exit 1
fi

step "Checking cluster login"
if ! oc whoami >/dev/null 2>&1; then
    echo "Not logged in to the cluster — run 'oc login ...' first." >&2
    exit 1
fi

step "Ensuring the $MIRROR_NAMESPACE namespace exists"
if oc get namespace "$MIRROR_NAMESPACE" >/dev/null 2>&1; then
    echo "Already exists."
else
    oc new-project "$MIRROR_NAMESPACE" >/dev/null
fi

step "Granting $RELEASE_NAMESPACE service accounts pull access to $MIRROR_NAMESPACE"
# Tetragon's agent/operator pods run under service accounts in $RELEASE_NAMESPACE (kube-system
# by default), not in $MIRROR_NAMESPACE -- without this cross-namespace grant every pod sits
# in ImagePullBackOff/Unauthorized even though the image is sitting right there in the
# registry. Idempotent, safe to re-run.
oc adm policy add-role-to-group system:image-puller \
    "system:serviceaccounts:$RELEASE_NAMESPACE" -n "$MIRROR_NAMESPACE" >/dev/null

step "Locating the internal image registry route"
HOST=$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}' 2>/dev/null)
if [[ -z "$HOST" ]]; then
    echo "Could not find the internal registry route. Enable it first:" >&2
    echo "  oc patch configs.imageregistry.operator.openshift.io/cluster --patch '{\"spec\":{\"defaultRoute\":true}}' --type=merge" >&2
    exit 1
fi

step "Logging into the internal registry"
sudo podman login -u kubeadmin -p "$(oc whoami -t)" --tls-verify=false "$HOST"

# Populated by mirror_image() on each call.
MIRRORED_REF=""

mirror_image() {
    local tar_path="$1" image_name="$2"
    step "Loading $tar_path"
    local load_output
    load_output=$(sudo podman load -i "$tar_path")
    echo "$load_output"
    local loaded_image
    loaded_image=$(echo "$load_output" | sed -nE 's/^Loaded image\(s\)?: *//p' | tail -1)
    if [[ -z "$loaded_image" ]]; then
        echo "Could not determine the loaded image reference from the 'podman load' output above ($tar_path)." >&2
        exit 1
    fi
    echo "Loaded: $loaded_image"
    # Keep the tag baked into the tar (e.g. v1.7.0) rather than inventing our own -- one
    # less place for the mirrored version to drift out of sync with what was actually
    # downloaded.
    local tag="${loaded_image##*:}"
    local push_image="$HOST/$MIRROR_NAMESPACE/$image_name:$tag"
    step "Tagging and pushing $push_image"
    sudo podman tag "$loaded_image" "$push_image"
    sudo podman push --tls-verify=false "$push_image"
    MIRRORED_REF="image-registry.openshift-image-registry.svc:5000/$MIRROR_NAMESPACE/$image_name:$tag"
}

# Every '.image.override' path below is a verbatim full-image-reference field the chart's
# templates check first (see e.g. templates/_container_tetragon.tpl) -- confirmed against
# the actual 1.7.0 chart, not assumed from values.yaml's repository/tag fields alone.
mirror_image "$AGENT_TAR" "tetragon"
SET_ARGS=(--set "tetragon.image.override=$MIRRORED_REF")

if [[ -n "$OPERATOR_TAR" ]]; then
    mirror_image "$OPERATOR_TAR" "tetragon-operator"
    SET_ARGS+=(--set "tetragonOperator.image.override=$MIRRORED_REF")
fi

if [[ -n "$EXPORT_TAR" ]]; then
    mirror_image "$EXPORT_TAR" "hubble-export-stdout"
    SET_ARGS+=(--set "export.stdout.image.override=$MIRRORED_REF")
fi

if [[ -n "$RTHOOKS_TAR" ]]; then
    mirror_image "$RTHOOKS_TAR" "tetragon-rthooks"
    SET_ARGS+=(--set "rthooks.image.override=$MIRRORED_REF")
fi

step "Installing/upgrading the $RELEASE_NAME Helm release in $RELEASE_NAMESPACE"
helm upgrade --install "$RELEASE_NAME" "$CHART" \
    -n "$RELEASE_NAMESPACE" --create-namespace \
    "${SET_ARGS[@]}" "${EXTRA_SET_ARGS[@]}"

step "Binding the privileged SCC"
# The chart's DaemonSet runs securityContext.privileged: true, hostNetwork: true, and mounts
# several hostPath volumes (including /sys/fs/bpf) -- needs the 'privileged' SCC bound to its
# ServiceAccount, same as the non-air-gapped path in OPENSHIFT-DEPLOYMENT-README.md. Both the
# DaemonSet and its ServiceAccount default to the release name when nameOverride/
# serviceAccount.name are unset (confirmed against the chart's _helpers.tpl), so
# $RELEASE_NAME is correct for -z here even if you passed --release-name.
oc adm policy add-scc-to-user privileged -z "$RELEASE_NAME" -n "$RELEASE_NAMESPACE"

step "Waiting for the Tetragon DaemonSet"
if ! oc rollout status daemonset/"$RELEASE_NAME" -n "$RELEASE_NAMESPACE" --timeout=180s; then
    echo "Rollout did not finish — check:" >&2
    echo "  oc get pods -n $RELEASE_NAMESPACE -l app.kubernetes.io/name=tetragon -o wide" >&2
    echo "  oc get events -n $RELEASE_NAMESPACE --field-selector reason=FailedCreate" >&2
    exit 1
fi

step "Deployed"
oc get pods -n "$RELEASE_NAMESPACE" -l app.kubernetes.io/name=tetragon -o wide
