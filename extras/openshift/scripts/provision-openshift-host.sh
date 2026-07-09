#!/usr/bin/env bash
# description: Provision a fresh RHEL9 host with CRC (OpenShift Local) and deploy the full CertSight stack (Tetragon, cert-analyzer, tracing policies, monitoring)
#
# Replicates the CRC-based rehearsal environment documented in
# extras/OPENSHIFT-DEPLOYMENT-README.md end to end, from bare RHEL9 packages
# through a running cert-analyzer DaemonSet with tracing policies loaded.
# Safe to re-run — each phase checks whether its result already exists before
# doing anything. Expect 15-30 minutes on a fresh host (CRC bundle extraction
# and first `crc start` are the slow parts).
#
# Requires a personal pull secret from https://console.redhat.com/openshift/create/local
# saved locally first (default path: ~/pull-secret.json, override with
# PULL_SECRET_FILE=/path/to/pull-secret.json).
#
# --- Airgapped hosts: set OFFLINE=1 and stage these locally first ---
# Every one of these is produced on a connected machine and copied over (scp/USB);
# nothing below is fetched by this script when OFFLINE=1 — it fails fast instead of
# hanging on a dead network call if a required one is missing.
#
#   OFFLINE_RPM_DIR         Dir of .rpm files for NetworkManager/libvirt/qemu-kvm/podman and
#                           every dependency they need beyond a standard RHEL9 install (see
#                           rpms/README.md for exactly how the set was computed). Defaults to
#                           this script's own rpms/ subdirectory if it exists and isn't empty
#                           — a pre-populated set for RHEL 9.8/x86_64 already lives there;
#                           regenerate it if the target runs a different minor version.
#   HELM_BINARY_FILE        A helm binary (it's a single static Go binary — just copy
#                           /usr/local/bin/helm from a connected machine).
#   CRC_TARBALL_FILE        crc-linux-amd64.tar.xz (or an already-extracted crc binary)
#                           for the matching CRC_VERSION.
#   CRC_BUNDLE_FILE         The matching crc_libvirt_<ocp-version>_amd64.crcbundle from
#                           ~/.crc/cache on a connected machine (~7GB) — this is what lets
#                           'crc start' bring up the actual OpenShift cluster with zero
#                           network access, since the cluster is fully pre-baked inside it.
#   TETRAGON_CHART_FILE     Tetragon chart tarball: 'helm pull cilium/tetragon --version
#                           <TETRAGON_VERSION>' on a connected machine.
#   TETRAGON_IMAGES_TAR     'podman save' of the 3 images the default chart install pulls,
#                           in one archive, e.g.:
#                             podman save -o tetragon-images.tar \
#                               quay.io/cilium/tetragon:v1.7.0 \
#                               quay.io/cilium/tetragon-operator:v1.7.0 \
#                               quay.io/cilium/hubble-export-stdout:v1.1.1
#                           Loaded locally and re-pushed to the CRC internal registry —
#                           the CRC VM's own CRI-O can't reach quay.io either.
#   CERT_ANALYZER_IMAGE_TAR 'podman save' of an image built by extras/build.sh elsewhere
#                           (that build needs a UBI base image + PyPI, so it can't run on
#                           the airgapped host itself unless UBI_PYTHON_IMAGE/PIP_INDEX_URL
#                           already point at an internal mirror reachable from this host).
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
NAMESPACE=certsight
OFFLINE="${OFFLINE:-0}"
CRC_VERSION="${CRC_VERSION:-2.57.0}"
CRC_DISK_SIZE="${CRC_DISK_SIZE:-60}"
TETRAGON_VERSION="${TETRAGON_VERSION:-1.7.0}"
PULL_SECRET_FILE="${PULL_SECRET_FILE:-$HOME/pull-secret.json}"
if [[ -n "${OFFLINE_RPM_DIR:-}" ]]; then
    OFFLINE_RPM_DIR="$OFFLINE_RPM_DIR"
elif [[ -d "$SCRIPT_DIR/rpms" ]] && compgen -G "$SCRIPT_DIR/rpms/*.rpm" >/dev/null; then
    OFFLINE_RPM_DIR="$SCRIPT_DIR/rpms"
else
    OFFLINE_RPM_DIR=""
fi
HELM_BINARY_FILE="${HELM_BINARY_FILE:-}"
CRC_TARBALL_FILE="${CRC_TARBALL_FILE:-}"
CRC_BUNDLE_FILE="${CRC_BUNDLE_FILE:-}"
TETRAGON_CHART_FILE="${TETRAGON_CHART_FILE:-}"
TETRAGON_IMAGES_TAR="${TETRAGON_IMAGES_TAR:-}"
CERT_ANALYZER_IMAGE_TAR="${CERT_ANALYZER_IMAGE_TAR:-}"

step() { echo; echo "==> $*"; }

require_offline_file() {
    local var_name="$1" path="${!1}"
    if [[ -z "$path" ]]; then
        echo "OFFLINE=1 requires $var_name to be set — see this script's header for what to stage." >&2
        exit 1
    fi
    if [[ ! -f "$path" ]]; then
        echo "$var_name=$path does not exist." >&2
        exit 1
    fi
}

if [[ "$(uname -m)" != "x86_64" ]]; then
    echo "This script targets x86_64 RHEL9 hosts (CRC's libvirt bundle is amd64-only)." >&2
    exit 1
fi

if [[ ! -e /dev/kvm ]]; then
    echo "/dev/kvm not found — hardware virtualization isn't available or isn't enabled" >&2
    echo "(check BIOS/UEFI virtualization settings, or nested virt if this is itself a VM)." >&2
    exit 1
fi

step "Installing host virtualization/container packages"
if [[ -n "$OFFLINE_RPM_DIR" ]]; then
    [[ -d "$OFFLINE_RPM_DIR" ]] || { echo "OFFLINE_RPM_DIR=$OFFLINE_RPM_DIR not found." >&2; exit 1; }
    sudo dnf install -y "$OFFLINE_RPM_DIR"/*.rpm
else
    sudo dnf install -y NetworkManager libvirt qemu-kvm podman
fi

step "Enabling libvirt"
if systemctl list-unit-files virtqemud.socket &>/dev/null; then
    sudo systemctl enable --now virtqemud.socket virtnetworkd.socket
else
    sudo systemctl enable --now libvirtd
fi

if ! groups "$USER" | grep -qw libvirt; then
    step "Adding $USER to the libvirt group"
    sudo usermod -aG libvirt "$USER"
    echo "Group membership only takes effect in a new login session." >&2
    echo "Log out/in (or run 'newgrp libvirt' in a fresh shell), then re-run this script to continue." >&2
    exit 0
fi

step "Installing helm"
if ! command -v helm &>/dev/null; then
    if [[ "$OFFLINE" == "1" ]]; then
        require_offline_file HELM_BINARY_FILE
        sudo install -m 0755 "$HELM_BINARY_FILE" /usr/local/bin/helm
    else
        curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    fi
fi

step "Installing crc $CRC_VERSION"
if ! command -v crc &>/dev/null; then
    if [[ "$OFFLINE" == "1" ]]; then
        require_offline_file CRC_TARBALL_FILE
        if [[ "$CRC_TARBALL_FILE" == *.tar.xz ]]; then
            TMP=$(mktemp -d)
            tar -xJf "$CRC_TARBALL_FILE" -C "$TMP"
            sudo install -m 0755 "$TMP"/crc-linux-*-amd64/crc /usr/local/bin/crc
            rm -rf "$TMP"
        else
            sudo install -m 0755 "$CRC_TARBALL_FILE" /usr/local/bin/crc
        fi
    else
        TMP=$(mktemp -d)
        curl -fsSL -o "$TMP/crc.tar.xz" \
            "https://mirror.openshift.com/pub/openshift-v4/clients/crc/${CRC_VERSION}/crc-linux-amd64.tar.xz"
        tar -xJf "$TMP/crc.tar.xz" -C "$TMP"
        sudo install -m 0755 "$TMP"/crc-linux-*-amd64/crc /usr/local/bin/crc
        rm -rf "$TMP"
    fi
fi

step "Configuring crc (disk-size=$CRC_DISK_SIZE)"
if [[ "$OFFLINE" == "1" ]]; then
    # Avoid any phone-home attempt on a host with no route out at all.
    crc config set consent-telemetry no >/dev/null
else
    crc config set consent-telemetry yes >/dev/null
fi
crc config set disk-size "$CRC_DISK_SIZE" >/dev/null

if [[ ! -f "$PULL_SECRET_FILE" ]]; then
    echo "No pull secret at $PULL_SECRET_FILE." >&2
    echo "Download your own from https://console.redhat.com/openshift/create/local, save it there," >&2
    echo "then re-run (or re-run with PULL_SECRET_FILE=/path/to/pull-secret.json)." >&2
    exit 1
fi

step "Running crc setup"
crc setup

step "Starting the CRC VM (first start extracts a ~7GB bundle — this takes a while)"
START_ARGS=(--pull-secret-file "$PULL_SECRET_FILE")
if [[ "$OFFLINE" == "1" ]]; then
    require_offline_file CRC_BUNDLE_FILE
    START_ARGS+=(--bundle "$CRC_BUNDLE_FILE")
fi
crc start "${START_ARGS[@]}"

eval "$(crc oc-env)"
if ! grep -qF 'crc oc-env' ~/.bashrc 2>/dev/null; then
    echo 'eval "$(crc oc-env)"' >> ~/.bashrc
    echo "Added 'eval \$(crc oc-env)' to ~/.bashrc so future shells get oc on PATH."
fi

step "Logging in to the cluster"
if oc whoami &>/dev/null; then
    echo "Already logged in as $(oc whoami)."
else
    KUBEADMIN_PW=$(crc console --credentials | grep -oP "kubeadmin -p \K[^ ']+")
    if [[ -z "$KUBEADMIN_PW" ]]; then
        echo "Could not parse kubeadmin credentials from 'crc console --credentials' — log in manually:" >&2
        echo "  crc console --credentials" >&2
        echo "  oc login -u kubeadmin -p <password> https://api.crc.testing:6443" >&2
        exit 1
    fi
    oc login -u kubeadmin -p "$KUBEADMIN_PW" https://api.crc.testing:6443 --insecure-skip-tls-verify=true
fi

step "Verifying node kernel/BTF"
oc get nodes -o wide
NODE=$(oc get nodes -o jsonpath='{.items[0].metadata.name}')
if oc debug node/"$NODE" -- chroot /host test -e /sys/kernel/btf/vmlinux &>/dev/null; then
    echo "BTF present on $NODE."
else
    echo "WARNING: no BTF found on $NODE — Tetragon needs a BTF-enabled kernel." >&2
fi

step "Enabling the internal image registry route"
oc patch configs.imageregistry.operator.openshift.io/cluster --patch '{"spec":{"defaultRoute":true}}' --type=merge
HOST=$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}')
sudo podman login -u kubeadmin -p "$(oc whoami -t)" --tls-verify=false "$HOST"

step "Deploying Tetragon (Helm)"
HELM_IMAGE_ARGS=()
if [[ -n "$TETRAGON_IMAGES_TAR" ]]; then
    [[ -f "$TETRAGON_IMAGES_TAR" ]] || { echo "TETRAGON_IMAGES_TAR=$TETRAGON_IMAGES_TAR not found." >&2; exit 1; }
    step "Loading Tetragon images and re-hosting them in the internal registry"
    sudo podman load -i "$TETRAGON_IMAGES_TAR"
    # kube-system already exists, so images can be re-hosted there without creating a
    # project up front — this is just where Tetragon itself is about to be deployed.
    declare -A TETRAGON_IMAGE_MAP=(
        ["quay.io/cilium/tetragon:v${TETRAGON_VERSION}"]=tetragon
        ["quay.io/cilium/tetragon-operator:v${TETRAGON_VERSION}"]=tetragon-operator
        ["quay.io/cilium/hubble-export-stdout:v1.1.1"]=hubble-export-stdout
    )
    for SRC in "${!TETRAGON_IMAGE_MAP[@]}"; do
        NAME="${TETRAGON_IMAGE_MAP[$SRC]}"
        TAG="${SRC##*:}"
        DEST="$HOST/kube-system/$NAME:$TAG"
        sudo podman tag "$SRC" "$DEST"
        sudo podman push --tls-verify=false "$DEST"
    done
    HELM_IMAGE_ARGS=(
        --set "tetragon.image.repository=$HOST/kube-system/tetragon"
        --set "tetragon.image.tag=v${TETRAGON_VERSION}"
        --set "tetragonOperator.image.repository=$HOST/kube-system/tetragon-operator"
        --set "tetragonOperator.image.tag=v${TETRAGON_VERSION}"
        --set "export.stdout.image.repository=$HOST/kube-system/hubble-export-stdout"
        --set "export.stdout.image.tag=v1.1.1"
    )
fi

if [[ "$OFFLINE" == "1" ]]; then
    require_offline_file TETRAGON_CHART_FILE
    CHART_REF="$TETRAGON_CHART_FILE"
else
    helm repo add cilium https://helm.cilium.io >/dev/null 2>&1 || true
    helm repo update cilium >/dev/null
    CHART_REF="cilium/tetragon"
fi

if ! helm status tetragon -n kube-system &>/dev/null; then
    HELM_INSTALL_ARGS=(tetragon "$CHART_REF" -n kube-system)
    [[ "$CHART_REF" == "cilium/tetragon" ]] && HELM_INSTALL_ARGS+=(--version "$TETRAGON_VERSION")
    HELM_INSTALL_ARGS+=("${HELM_IMAGE_ARGS[@]}")
    helm install "${HELM_INSTALL_ARGS[@]}"
fi
oc adm policy add-scc-to-user privileged -z tetragon -n kube-system

step "Waiting for Tetragon"
if ! oc wait --for=condition=Ready pod -l app.kubernetes.io/name=tetragon -n kube-system --timeout=180s; then
    echo "Tetragon pod(s) not ready — check: oc get pods -n kube-system -l app.kubernetes.io/name=tetragon" >&2
    exit 1
fi

step "Preparing the cert-analyzer image"
if [[ -n "$CERT_ANALYZER_IMAGE_TAR" ]]; then
    [[ -f "$CERT_ANALYZER_IMAGE_TAR" ]] || { echo "CERT_ANALYZER_IMAGE_TAR=$CERT_ANALYZER_IMAGE_TAR not found." >&2; exit 1; }
    sudo podman load -i "$CERT_ANALYZER_IMAGE_TAR"
elif [[ "$OFFLINE" == "1" ]]; then
    echo "OFFLINE=1 with no CERT_ANALYZER_IMAGE_TAR set — extras/build.sh needs a UBI base image" >&2
    echo "and PyPI packages, neither reachable from an airgapped host. Either set" >&2
    echo "CERT_ANALYZER_IMAGE_TAR to a 'podman save' of an image built elsewhere, or point" >&2
    echo "UBI_PYTHON_IMAGE/PIP_INDEX_URL/PIP_TRUSTED_HOST at an internal mirror reachable from" >&2
    echo "this host before re-running." >&2
    exit 1
else
    (cd "$REPO_ROOT" && bash extras/build.sh)
fi

if ! oc get project "$NAMESPACE" &>/dev/null; then
    oc new-project "$NAMESPACE"
fi

step "Pushing cert-analyzer image to the internal registry"
sudo podman tag localhost/cert-analyzer:latest "$HOST/certsight/cert-analyzer:latest"
sudo podman push --tls-verify=false "$HOST/certsight/cert-analyzer:latest"

step "Deploying cert-analyzer"
oc apply -f "$REPO_ROOT/extras/openshift/scc-hostaccess-binding.yaml"
oc apply -f "$REPO_ROOT/extras/openshift/daemonset.yaml"
if ! oc rollout status daemonset/cert-expiry-monitor -n "$NAMESPACE" --timeout=180s; then
    echo "cert-analyzer DaemonSet not ready — check: oc get pods -n $NAMESPACE -o wide" >&2
    exit 1
fi

step "Loading Tetragon tracing policies"
oc apply -f "$REPO_ROOT/tetragon-policies/certificate-file-access.yaml"
oc apply -f "$REPO_ROOT/tetragon-policies/tcp-connect-tls.yaml"
oc apply -f "$REPO_ROOT/tetragon-policies/experimental/tls-service-tracking.yaml"

step "Enabling User Workload Monitoring"
oc apply -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-monitoring-config
  namespace: openshift-monitoring
data:
  config.yaml: |
    enableUserWorkload: true
EOF
oc apply -f "$REPO_ROOT/extras/openshift/service-monitor.yaml"
oc apply -f "$REPO_ROOT/extras/openshift/prometheus-rule.yaml"

step "Done"
oc get pods -n "$NAMESPACE" -o wide
echo
echo "Next, to run the soak test: build/push probe_tests/openshift-soak/ (see its README), then"
echo "  oc apply -f probe_tests/openshift-soak/job.yaml"
echo
echo "Full reference and troubleshooting: extras/OPENSHIFT-DEPLOYMENT-README.md"
