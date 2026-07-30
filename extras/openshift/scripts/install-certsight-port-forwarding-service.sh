#!/usr/bin/env bash
# description: One-time install of the persistent port-forwarding daemon as a systemd --user service (see OPENSHIFT-DEPLOYMENT-README.md)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
SERVICE_NAME=certsight-port-forwarding.service

step() { echo; echo "==> $*"; }

step "Checking prerequisites"
for bin in oc socat systemctl; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "Required command not found: $bin" >&2
        exit 1
    fi
done

step "Installing daemon script and service unit into $UNIT_DIR"
mkdir -p "$UNIT_DIR"
install -m 755 "$SCRIPT_DIR/certsight-port-forwarding-daemon.sh" "$UNIT_DIR/certsight-port-forwarding-daemon.sh"
install -m 644 "$SCRIPT_DIR/$SERVICE_NAME" "$UNIT_DIR/$SERVICE_NAME"

step "Enabling and starting the service"
systemctl --user daemon-reload
systemctl --user enable --now "$SERVICE_NAME"

step "Done"
echo "Status:   systemctl --user status $SERVICE_NAME"
echo "Logs:     journalctl --user -u $SERVICE_NAME -n 50 -f"
echo
echo "The unit is WantedBy=default.target, so it (re)starts automatically on login."
echo "If you need it running before any interactive login too -- e.g. right after a"
echo "host reboot with no session open yet -- enable lingering for this user:"
echo "  sudo loginctl enable-linger $(whoami)"
echo
echo "To customize ports/host IP, edit the ExecStart line in:"
echo "  $UNIT_DIR/$SERVICE_NAME"
echo "then: systemctl --user daemon-reload && systemctl --user restart $SERVICE_NAME"
