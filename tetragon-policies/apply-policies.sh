#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TETRA=/usr/local/bin/tetra
if [[ ! -x "$TETRA" ]]; then
    echo "Error: '$TETRA' not found. Is Tetragon installed?" >&2
    exit 1
fi

# Detect RHEL major version to select the correct OpenSSL policy variant.
# RHEL 8 ships OpenSSL 1.1 (libssl.so.1.1); RHEL 9 ships OpenSSL 3 (libssl.so.3).
RHEL_MAJOR=0
if [[ -f /etc/os-release ]]; then
    VERSION_ID=$(. /etc/os-release && echo "$VERSION_ID")
    RHEL_MAJOR="${VERSION_ID%%.*}"
fi

case "$RHEL_MAJOR" in
    8)
        echo "Detected: RHEL 8 — using OpenSSL 1.1 policy"
        OPENSSL_SKIP="openssl3-cert-load.yaml"
        ;;
    9)
        echo "Detected: RHEL 9 — using OpenSSL 3 policy"
        OPENSSL_SKIP="openssl1_1-cert-load.yaml"
        ;;
    *)
        echo "Warning: could not detect RHEL major version (got '${RHEL_MAJOR}'). Applying all OpenSSL policies." >&2
        OPENSSL_SKIP=""
        ;;
esac

declare -a SUCCEEDED=()
declare -a FAILED=()
declare -a SKIPPED=()

apply_policy() {
    local policy_file="$1"
    local label="$2"
    printf "  %-55s " "$label"
    if output=$(sudo "$TETRA" tracingpolicy add "$policy_file" 2>&1); then
        printf "OK\n"
        SUCCEEDED+=("$label")
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
        if [[ -n "$OPENSSL_SKIP" && "$local_name" == "$OPENSSL_SKIP" ]]; then
            printf "  %-55s SKIPPED (wrong RHEL version)\n" "experimental/$local_name"
            SKIPPED+=("experimental/$local_name")
            continue
        fi
        apply_policy "$policy" "experimental/$local_name"
    done
fi

TOTAL=$(( ${#SUCCEEDED[@]} + ${#FAILED[@]} ))

echo ""
echo "================================================"
echo " Summary: ${#SUCCEEDED[@]}/${TOTAL} policies applied successfully"
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

if [[ ${#FAILED[@]} -gt 0 ]]; then
    exit 1
fi
