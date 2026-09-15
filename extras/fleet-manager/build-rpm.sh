#!/usr/bin/env bash
# build-rpm.sh — Build the certsight-fleet-manager RPM (noarch, RHEL 8/9)
#
# Pure-Python, stdlib only: nothing is vendored, so this needs only rpmbuild
# and can run anywhere. The result installs on any host with python3.11 and
# certsight-test-server (a declared dependency, for the fleet explorer
# modules) -- see FLEET-MANAGER-README.md.
#
# Usage:
#   ./build-rpm.sh [--version <version>] [--release <release>]
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

RPM_RELEASE="${RPM_RELEASE:-1}"
VERSION="${RPM_VERSION:-0.1.0}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2";     shift 2 ;;
        --release) RPM_RELEASE="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

echo "============================================================"
echo " Building certsight-fleet-manager RPM"
echo " Version: $VERSION"
echo " Release: $RPM_RELEASE"
echo "============================================================"

if ! command -v rpmbuild &>/dev/null; then
    echo "ERROR: rpmbuild is required but not installed."
    echo "Run: dnf install rpm-build"
    exit 1
fi

RPMBUILD_ROOT="${RPMBUILD_ROOT:-$HOME/rpmbuild}"
for dir in BUILD BUILDROOT RPMS SOURCES SPECS SRPMS; do
    mkdir -p "$RPMBUILD_ROOT/$dir"
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [[ ! -f "$REPO_ROOT/LICENSE" ]]; then
    echo "ERROR: Required file not found: $REPO_ROOT/LICENSE"
    exit 1
fi

TARNAME="certsight-fleet-manager-${VERSION}"
TARBALL="$RPMBUILD_ROOT/SOURCES/${TARNAME}.tar.gz"
echo "Creating source tarball: $TARBALL"

TMPDIR_SRC="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_SRC"' EXIT

mkdir -p "$TMPDIR_SRC/$TARNAME/static"
for f in server.py auth.py fleet_state.py node_client.py audit.py gen-control-certs.sh \
         certsight-fleet-manager.service fleet-manager.conf FLEET-MANAGER-README.md; do
    cp "$SCRIPT_DIR/$f" "$TMPDIR_SRC/$TARNAME/"
done
cp "$SCRIPT_DIR"/static/index.html "$SCRIPT_DIR"/static/app.js "$SCRIPT_DIR"/static/app.css \
   "$TMPDIR_SRC/$TARNAME/static/"
cp "$REPO_ROOT/LICENSE" "$TMPDIR_SRC/$TARNAME/"

tar -czf "$TARBALL" -C "$TMPDIR_SRC" "$TARNAME"
echo "Tarball created: $TARBALL"

cp "$SCRIPT_DIR/certsight-fleet-manager.spec" "$RPMBUILD_ROOT/SPECS/certsight-fleet-manager.spec"

echo "Running rpmbuild..."
rpmbuild -ba \
    --define "_topdir $RPMBUILD_ROOT" \
    --define "_version $VERSION" \
    --define "_release $RPM_RELEASE" \
    "$RPMBUILD_ROOT/SPECS/certsight-fleet-manager.spec"

echo ""
echo "============================================================"
echo " Build complete"
echo "============================================================"
echo ""
echo "RPM package:"
find "$RPMBUILD_ROOT/RPMS" -name "certsight-fleet-manager-*.rpm" | sort
echo ""
echo "Install on the target host (also pulls in certsight-test-server if"
echo "it isn't already present):"
echo "  sudo dnf install ./certsight-fleet-manager-${VERSION}-${RPM_RELEASE}.*.noarch.rpm"
echo ""
echo "Then set the two secrets in /etc/certsight-fleet-manager/fleet-manager.conf"
echo "(certsight-fleet-manager --hash-password prints the first) and:"
echo "  systemctl enable --now certsight-fleet-manager"
