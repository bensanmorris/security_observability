#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TETRA=/usr/local/bin/tetra
if [[ ! -x "$TETRA" ]]; then
    echo "Error: '$TETRA' not found. Is Tetragon installed?" >&2
    exit 1
fi

TETRAGON_POLICY_DIR=/etc/tetragon/tetragon.tp.d

# Detect which libssl versions are installed and the RHEL major version.
# RHEL version is only needed to pick the right openssl3 policy variant —
# RHEL 8's kernel (4.18) cannot handle string uprobe args so it has its own.
RHEL_MAJOR=0
if [[ -f /etc/os-release ]]; then
    VERSION_ID=$(. /etc/os-release && echo "$VERSION_ID")
    RHEL_MAJOR="${VERSION_ID%%.*}"
fi

HAS_SSL11=false
HAS_SSL3=false
[[ -e /usr/lib64/libssl.so.1.1 ]] && HAS_SSL11=true
[[ -e /usr/lib64/libssl.so.3   ]] && HAS_SSL3=true

echo "Detected: RHEL ${RHEL_MAJOR}, libssl.so.1.1=${HAS_SSL11}, libssl.so.3=${HAS_SSL3}"

declare -a SUCCEEDED=()
declare -a FAILED=()
declare -a SKIPPED=()
declare -a PERSIST_FAILED=()

persist_policy() {
    local policy_file="$1"
    local label="$2"
    local dest_name="${label//\//-}"
    if sudo mkdir -p "$TETRAGON_POLICY_DIR" && sudo cp "$policy_file" "$TETRAGON_POLICY_DIR/$dest_name"; then
        :
    else
        echo "    Warning: failed to copy $label to $TETRAGON_POLICY_DIR" >&2
        PERSIST_FAILED+=("$label")
    fi
}

apply_policy() {
    local policy_file="$1"
    local label="$2"
    local policy_name
    policy_name=$(awk '/^metadata:/{found=1} found && /^  name:/{print $2; exit}' "$policy_file")
    printf "  %-55s " "$label"
    if [[ -n "$policy_name" ]]; then
        sudo "$TETRA" tracingpolicy delete "$policy_name" 2>/dev/null || true
    fi
    if output=$(sudo "$TETRA" tracingpolicy add "$policy_file" 2>&1); then
        printf "OK\n"
        SUCCEEDED+=("$label")
        persist_policy "$policy_file" "$label"
    else
        printf "FAILED\n"
        # Indent the error output so it's visually grouped with the policy
        echo "$output" | sed 's/^/    /' >&2
        FAILED+=("$label")
    fi
}

echo ""
echo "Applying Tetragon policies from: $SCRIPT_DIR"
echo ""

shopt -s nullglob
MAIN_POLICIES=("$SCRIPT_DIR"/*.yaml)
EXPERIMENTAL_POLICIES=("$SCRIPT_DIR"/experimental/*.yaml)
shopt -u nullglob

if [[ ${#MAIN_POLICIES[@]} -gt 0 ]]; then
    echo "Core policies:"
    for policy in "${MAIN_POLICIES[@]}"; do
        apply_policy "$policy" "$(basename "$policy")"
    done
fi

if [[ ${#EXPERIMENTAL_POLICIES[@]} -gt 0 ]]; then
    echo ""
    echo "Experimental policies:"
    for policy in "${EXPERIMENTAL_POLICIES[@]}"; do
        local_name="$(basename "$policy")"
        # OpenSSL policies are handled explicitly below — skip them in the glob pass
        case "$local_name" in openssl*-cert-load*.yaml) continue ;; esac
        apply_policy "$policy" "experimental/$local_name"
    done

    # Apply whichever OpenSSL policies match the installed libraries.
    # For OpenSSL 3, the policy variant is chosen by RHEL version: RHEL 8's kernel
    # cannot handle string uprobe args so it uses a separate compat policy.
    if $HAS_SSL11; then
        apply_policy "$SCRIPT_DIR/experimental/openssl1_1-cert-load.yaml" "experimental/openssl1_1-cert-load.yaml"
    fi
    if $HAS_SSL3; then
        if [[ "$RHEL_MAJOR" == "8" ]]; then
            apply_policy "$SCRIPT_DIR/experimental/openssl3-cert-load-rhel8.yaml" "experimental/openssl3-cert-load-rhel8.yaml"
        else
            apply_policy "$SCRIPT_DIR/experimental/openssl3-cert-load.yaml" "experimental/openssl3-cert-load.yaml"
        fi
    fi
fi

TOTAL=$(( ${#SUCCEEDED[@]} + ${#FAILED[@]} ))

echo ""
echo "================================================"
echo " Summary: ${#SUCCEEDED[@]}/${TOTAL} policies applied successfully"
if [[ ${#SUCCEEDED[@]} -gt 0 ]]; then
    echo " Persisted to: $TETRAGON_POLICY_DIR"
fi
echo "================================================"

for label in "${SUCCEEDED[@]}"; do
    echo "  [OK]      $label"
done
for label in "${FAILED[@]}"; do
    echo "  [FAIL]    $label"
done
for label in "${SKIPPED[@]}"; do
    echo "  [SKIPPED] $label"
done
for label in "${PERSIST_FAILED[@]}"; do
    echo "  [NO PERSIST] $label"
done

if [[ ${#FAILED[@]} -gt 0 ]]; then
    exit 1
fi
