#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TETRA=/usr/local/bin/tetra
if [[ ! -x "$TETRA" ]]; then
    echo "Error: '$TETRA' not found. Is Tetragon installed?" >&2
    exit 1
fi

declare -a SUCCEEDED=()
declare -a FAILED=()

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
        apply_policy "$policy" "experimental/$(basename "$policy")"
    done
fi

TOTAL=$(( ${#SUCCEEDED[@]} + ${#FAILED[@]} ))

echo ""
echo "================================================"
echo " Summary: ${#SUCCEEDED[@]}/${TOTAL} policies applied successfully"
echo "================================================"

for label in "${SUCCEEDED[@]}"; do
    echo "  [OK]   $label"
done
for label in "${FAILED[@]}"; do
    echo "  [FAIL] $label"
done

if [[ ${#FAILED[@]} -gt 0 ]]; then
    exit 1
fi
