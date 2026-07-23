#!/usr/bin/env bash
# description: Pull the Tetragon Helm chart and its container images on a networked machine, saving them as tars to transfer to an air-gapped OpenShift host
set -uo pipefail

step() { echo; echo "==> $*"; }

VERSION="1.7.0"
NAMESPACE="kube-system"
RELEASE_NAME="tetragon"
OUTPUT_DIR="."
TOOL=""
EXTRA_SET_ARGS=()

usage() {
    cat <<'USAGE' >&2
Usage: fetch-tetragon-images.sh [--version X.Y.Z] [--output-dir <dir>] [--tool docker|podman] [--extra-set key=value ...]

Run this on any machine with internet access (NOT the locked-down/air-gapped OpenShift
host) to prepare everything extras/openshift/scripts/deploy-tetragon-from-release.sh needs:

  1. 'helm pull's the Tetragon chart to <output-dir>/tetragon-<version>.tgz.
  2. 'helm template's the chart to discover exactly which images the current values (chart
     defaults plus whatever --extra-set you pass) actually reference -- so a component
     you've disabled is correctly skipped, and a future chart version that adds/removes an
     image doesn't need this script updated.
  3. Pulls + saves each discovered image as <output-dir>/<name>.tar.gz via docker or podman.

Then copy everything under <output-dir> to the air-gapped host and run (adjust flags to
match what actually got fetched -- the summary printed at the end lists exact paths):

  bash extras/openshift/scripts/deploy-tetragon-from-release.sh \
    --chart <output-dir>/tetragon-<version>.tgz \
    --agent-image-tar <output-dir>/tetragon-agent.tar.gz \
    --operator-image-tar <output-dir>/tetragon-operator.tar.gz \
    --export-stdout-image-tar <output-dir>/hubble-export-stdout.tar.gz

Options:
  --version <X.Y.Z>       Tetragon chart version (default: 1.7.0, matching this repo's
                           default TETRAGON_VERSION in .github/workflows/build.yml).
  --output-dir <dir>      Where to write the chart + image tars (default: current directory).
  --tool docker|podman    Container tool to pull/save with (default: whichever is found on
                           PATH, preferring docker).
  --extra-set <key=value> Extra --set passed to 'helm template' when discovering images --
                           pass the same overrides you intend to use with
                           deploy-tetragon-from-release.sh (e.g. --extra-set
                           rthooks.enabled=true --extra-set rthooks.interface=oci-hooks) so
                           the right images get fetched. Repeatable.
USAGE
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --version=*) VERSION="${1#*=}"; shift ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --output-dir=*) OUTPUT_DIR="${1#*=}"; shift ;;
        --tool) TOOL="$2"; shift 2 ;;
        --tool=*) TOOL="${1#*=}"; shift ;;
        --extra-set) EXTRA_SET_ARGS+=(--set "$2"); shift 2 ;;
        --extra-set=*) EXTRA_SET_ARGS+=(--set "${1#*=}"); shift ;;
        -h|--help) usage ;;
        *) echo "Unknown argument: $1" >&2; usage ;;
    esac
done

if [[ -z "$TOOL" ]]; then
    if command -v docker >/dev/null 2>&1; then
        TOOL=docker
    elif command -v podman >/dev/null 2>&1; then
        TOOL=podman
    else
        echo "Neither docker nor podman found on PATH -- install one or pass --tool explicitly." >&2
        exit 1
    fi
fi

for cmd in helm "$TOOL"; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "'$cmd' not found on PATH." >&2; exit 1; }
done

mkdir -p "$OUTPUT_DIR"

step "Adding/updating the cilium Helm repo"
helm repo add cilium https://helm.cilium.io >/dev/null 2>&1 || true
helm repo update cilium

step "Pulling the tetragon chart ($VERSION) to $OUTPUT_DIR"
helm pull cilium/tetragon --version "$VERSION" --destination "$OUTPUT_DIR"
CHART_PATH="$OUTPUT_DIR/tetragon-$VERSION.tgz"
[[ -f "$CHART_PATH" ]] || { echo "Expected chart at $CHART_PATH but it's not there." >&2; exit 1; }
echo "Chart: $CHART_PATH"

step "Discovering images referenced by this chart/values"
# Render rather than parse values.yaml directly -- this reflects exactly what would be
# deployed (skips components disabled via --extra-set, matches whatever the chart version
# actually ships) instead of assuming today's image set stays correct forever.
if ! TEMPLATE_OUTPUT=$(helm template "$RELEASE_NAME" cilium/tetragon --version "$VERSION" \
        -n "$NAMESPACE" "${EXTRA_SET_ARGS[@]}" 2>&1); then
    echo "'helm template' failed -- fix the --extra-set values below and retry:" >&2
    echo "$TEMPLATE_OUTPUT" >&2
    exit 1
fi

IMAGES=$(echo "$TEMPLATE_OUTPUT" | grep -oE 'image: "[^"]+"' | sed -E 's/image: "([^"]+)"/\1/' | sort -u)
if [[ -z "$IMAGES" ]]; then
    echo "No images found in the rendered chart output -- something's wrong." >&2
    exit 1
fi

echo "Found:"
echo "$IMAGES" | sed 's/^/  /'

# Canonical names matching deploy-tetragon-from-release.sh's --agent-image-tar/
# --operator-image-tar/--export-stdout-image-tar/--rthooks-image-tar flags. Anything the
# chart adds in a future version falls through to a name derived from the image itself --
# still fetched and saved, just not one of the four the deploy script names explicitly.
canonical_name() {
    case "$1" in
        */tetragon-operator)    echo "tetragon-operator" ;;
        */tetragon-rthooks)     echo "tetragon-rthooks" ;;
        */hubble-export-stdout) echo "hubble-export-stdout" ;;
        */tetragon)             echo "tetragon-agent" ;;
        *)                      basename "$1" ;;
    esac
}

SAVED_PATHS=()
while IFS= read -r image; do
    [[ -z "$image" ]] && continue
    repo="${image%:*}"
    name=$(canonical_name "$repo")
    out="$OUTPUT_DIR/$name.tar.gz"
    step "Pulling $image"
    "$TOOL" pull "$image"
    step "Saving to $out"
    "$TOOL" save "$image" | gzip > "$out"
    SAVED_PATHS+=("$out")
done <<< "$IMAGES"

step "Done"
echo "Chart + images are in: $OUTPUT_DIR"
ls -lh "$CHART_PATH" "${SAVED_PATHS[@]}"
echo
echo "Copy these files to the air-gapped host, then run (drop any --*-image-tar flag whose"
echo "file isn't in the list above, and add the matching --skip-* flag instead):"
echo
DEPLOY_CMD_LINES=("bash extras/openshift/scripts/deploy-tetragon-from-release.sh" "--chart $CHART_PATH")
for path in "${SAVED_PATHS[@]}"; do
    base="$(basename "$path" .tar.gz)"
    case "$base" in
        tetragon-agent)       DEPLOY_CMD_LINES+=("--agent-image-tar $path") ;;
        tetragon-operator)    DEPLOY_CMD_LINES+=("--operator-image-tar $path") ;;
        hubble-export-stdout) DEPLOY_CMD_LINES+=("--export-stdout-image-tar $path") ;;
        tetragon-rthooks)     DEPLOY_CMD_LINES+=("--rthooks-image-tar $path") ;;
        *)                    DEPLOY_CMD_LINES+=("# unrecognized image, pass it through --extra-set on the deploy side: $path") ;;
    esac
done
last=$(( ${#DEPLOY_CMD_LINES[@]} - 1 ))
for i in "${!DEPLOY_CMD_LINES[@]}"; do
    if [[ "$i" -eq 0 ]]; then
        printf '  %s' "${DEPLOY_CMD_LINES[$i]}"
    else
        printf '    %s' "${DEPLOY_CMD_LINES[$i]}"
    fi
    if [[ "$i" -eq "$last" ]]; then
        printf '\n'
    else
        printf ' \\\n'
    fi
done
