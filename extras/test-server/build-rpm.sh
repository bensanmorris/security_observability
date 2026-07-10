#!/usr/bin/env bash
# build-rpm.sh — Build the certsight-test-server RPM on RHEL9
#
# Bundles a Python virtualenv (cryptography + kafka-python) into the RPM so
# it can be installed and run on a target host with no pip/internet access
# at all — see TEST-SERVER-README.md. Run this on a machine that *does*
# have normal pip/PyPI access (it need not be the target host), then copy
# the resulting RPM over.
#
# Usage:
#   ./build-rpm.sh [--version <version>] [--release <release>]
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

RPM_RELEASE="${RPM_RELEASE:-1}"
VERSION="${RPM_VERSION:-0.1.0}"

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2";     shift 2 ;;
        --release) RPM_RELEASE="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

echo "============================================================"
echo " Building certsight-test-server RPM"
echo " Version: $VERSION"
echo " Release: $RPM_RELEASE"
echo "============================================================"

# ── Verify prerequisites ──────────────────────────────────────────────────────
for cmd in python3.11 rpmbuild; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd is required but not installed."
        echo "Run: dnf install python3.11 python3.11-devel python3.11-pip rpm-build gcc"
        exit 1
    fi
done

# ── Set up rpmbuild tree ──────────────────────────────────────────────────────
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

# ── Create source tarball ─────────────────────────────────────────────────────
TARNAME="certsight-test-server-${VERSION}"
TARBALL="$RPMBUILD_ROOT/SOURCES/${TARNAME}.tar.gz"

echo "Creating source tarball: $TARBALL"

TMPDIR_SRC="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_SRC"' EXIT

mkdir -p "$TMPDIR_SRC/$TARNAME"
cp "$SCRIPT_DIR/server.py"                       "$TMPDIR_SRC/$TARNAME/"
cp "$SCRIPT_DIR/use_cases.py"                    "$TMPDIR_SRC/$TARNAME/"
cp "$SCRIPT_DIR/tls_probe_helper.py"             "$TMPDIR_SRC/$TARNAME/"
cp "$SCRIPT_DIR/tcp_connect_probe_helper.py"     "$TMPDIR_SRC/$TARNAME/"
cp -r "$SCRIPT_DIR/static"                       "$TMPDIR_SRC/$TARNAME/static"
cp "$SCRIPT_DIR/certsight-test-server.service"   "$TMPDIR_SRC/$TARNAME/"
cp "$SCRIPT_DIR/test-server.conf"                "$TMPDIR_SRC/$TARNAME/"
cp "$REPO_ROOT/LICENSE"                          "$TMPDIR_SRC/$TARNAME/"

tar -czf "$TARBALL" -C "$TMPDIR_SRC" "$TARNAME"
echo "Tarball created: $TARBALL"

# ── Copy spec file ────────────────────────────────────────────────────────────
cp "$SCRIPT_DIR/certsight-test-server.spec" "$RPMBUILD_ROOT/SPECS/certsight-test-server.spec"

# ── Run rpmbuild ──────────────────────────────────────────────────────────────
echo "Running rpmbuild..."
rpmbuild -ba \
    --define "_topdir $RPMBUILD_ROOT" \
    --define "_version $VERSION" \
    --define "_release $RPM_RELEASE" \
    "$RPMBUILD_ROOT/SPECS/certsight-test-server.spec"

# ── Report output ─────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo " Build complete"
echo "============================================================"
echo ""
echo "RPM package:"
find "$RPMBUILD_ROOT/RPMS" -name "certsight-test-server-*.rpm" | sort
echo ""
echo "Source RPM:"
find "$RPMBUILD_ROOT/SRPMS" -name "certsight-test-server-*.src.rpm" | sort
echo ""
echo "Copy the RPM to the target host, then install it there with no"
echo "pip/internet access required:"
echo "  sudo dnf install ./certsight-test-server-${VERSION}-${RPM_RELEASE}.*.rpm"
echo ""
echo "Then either run it in the foreground (on the same host as Tetragon + cert-analyzer):"
echo "  certsight-test-server --kafka-host localhost --kafka-port 9092"
echo ""
echo "...or configure /etc/certsight-test-server/test-server.conf and let"
echo "systemd manage it (starts on boot, binds 0.0.0.0 by default):"
echo "  systemctl start certsight-test-server"
