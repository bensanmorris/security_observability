#!/usr/bin/env bash
# Menu launcher for the OpenShift utility scripts in scripts/.
#
# To add a new utility: drop a script into scripts/, make it executable, and
# give it a `# description: ...` line as its second line (right after the
# shebang) — it picks up automatically, no changes needed here.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UTILS_DIR="$SCRIPT_DIR/scripts"

if [[ ! -d "$UTILS_DIR" ]]; then
    echo "No scripts/ directory found next to this menu ($UTILS_DIR)." >&2
    exit 1
fi

shopt -s nullglob
SCRIPTS=("$UTILS_DIR"/*.sh)
shopt -u nullglob

if [[ ${#SCRIPTS[@]} -eq 0 ]]; then
    echo "No utility scripts found in $UTILS_DIR." >&2
    exit 1
fi

describe() {
    local desc
    desc=$(sed -n '2{/^# description: /{s/^# description: //p}}' "$1")
    echo "${desc:-$(basename "$1")}"
}

while true; do
    echo
    echo "OpenShift utilities"
    echo "===================="
    for i in "${!SCRIPTS[@]}"; do
        printf '  %d) %s\n' "$((i + 1))" "$(describe "${SCRIPTS[$i]}")"
    done
    echo "  q) Quit"
    echo
    read -rp "Select a utility: " CHOICE

    if [[ "$CHOICE" == "q" || "$CHOICE" == "Q" ]]; then
        exit 0
    fi

    if ! [[ "$CHOICE" =~ ^[0-9]+$ ]] || (( CHOICE < 1 || CHOICE > ${#SCRIPTS[@]} )); then
        echo "Not a valid choice: $CHOICE"
        continue
    fi

    CHOSEN="${SCRIPTS[$((CHOICE - 1))]}"
    echo
    bash "$CHOSEN"
    echo
    read -rp "Press Enter to return to the menu, or Ctrl+C to exit: " _
done
