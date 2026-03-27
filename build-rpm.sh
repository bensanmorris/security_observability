#!/usr/bin/env bash
# build-rpm.sh — Build the cert-analyzer RPM on RHEL9
#
# Usage:
#   ./build-rpm.sh [--version <version>] [--release <release>]
#                  [--tetragon-version <version>]
#
# Defaults:
#   version          — git tag if on a tag, otherwise short SHA
#   release          — 1
#   tetragon-version — v1.1.0
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Your Organisation

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
TETRAGON_VERSION="${TETRAGON_VERSION:-v1.1.0}"
RPM_RELEASE="${RPM_RELEASE:-1}"
GRPCIO_VERSION="1.60.1"
PROTOBUF_VERSION="4.25.3"

# Determine version from git if not explicitly set
if [[ -n "${RPM_VERSION:-}" ]]; then
    VERSION="$RPM_VERSION"
elif git describe --exact-match --tags HEAD 2>/dev/null; then
    VERSION="$(git describe --exact-match --tags HEAD | sed 's/^v//')"
else
    VERSION="0.0.0~git$(git rev-parse --short HEAD)"
fi

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)          VERSION="$2";          shift 2 ;;
        --release)          RPM_RELEASE="$2";      shift 2 ;;
        --tetragon-version) TETRAGON_VERSION="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

echo "============================================================"
echo " Building cert-analyzer RPM"
echo " Version:          $VERSION"
echo " Release:          $RPM_RELEASE"
echo " Tetragon version: $TETRAGON_VERSION"
echo "============================================================"

# ── Verify prerequisites ──────────────────────────────────────────────────────
for cmd in python3.11 rpmbuild git; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd is required but not installed."
        echo "Run: dnf install python3.11 python3.11-devel python3.11-pip rpm-build git gcc"
        exit 1
    fi
done

# ── Set up rpmbuild tree ──────────────────────────────────────────────────────
RPMBUILD_ROOT="${RPMBUILD_ROOT:-$HOME/rpmbuild}"
for dir in BUILD BUILDROOT RPMS SOURCES SPECS SRPMS; do
    mkdir -p "$RPMBUILD_ROOT/$dir"
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Validate required source files exist ─────────────────────────────────────
for f in cert_analyzer.py LICENSE; do
    if [[ ! -f "$REPO_ROOT/$f" ]]; then
        echo "ERROR: Required file not found: $REPO_ROOT/$f"
        exit 1
    fi
done

# ── Create source tarball ─────────────────────────────────────────────────────
TARNAME="cert-analyzer-${VERSION}"
TARBALL="$RPMBUILD_ROOT/SOURCES/${TARNAME}.tar.gz"

echo "Creating source tarball: $TARBALL"

TMPDIR_SRC="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_SRC"' EXIT

mkdir -p "$TMPDIR_SRC/$TARNAME"
cp "$REPO_ROOT/cert_analyzer.py"     "$TMPDIR_SRC/$TARNAME/"
cp "$REPO_ROOT/LICENSE"              "$TMPDIR_SRC/$TARNAME/"
cp "$SCRIPT_DIR/cert-analyzer.service" "$TMPDIR_SRC/$TARNAME/"
cp "$SCRIPT_DIR/cert-analyzer.conf"    "$TMPDIR_SRC/$TARNAME/"

tar -czf "$TARBALL" -C "$TMPDIR_SRC" "$TARNAME"
echo "Tarball created: $TARBALL"

# ── Copy spec file ────────────────────────────────────────────────────────────
cp "$SCRIPT_DIR/cert-analyzer.spec" "$RPMBUILD_ROOT/SPECS/cert-analyzer.spec"

# ── Run rpmbuild ──────────────────────────────────────────────────────────────
echo "Running rpmbuild..."
rpmbuild -ba \
    --define "_topdir $RPMBUILD_ROOT" \
    --define "_version $VERSION" \
    --define "_release $RPM_RELEASE" \
    --define "_tetragon_version $TETRAGON_VERSION" \
    --define "_grpcio_version $GRPCIO_VERSION" \
    --define "_protobuf_version $PROTOBUF_VERSION" \
    "$RPMBUILD_ROOT/SPECS/cert-analyzer.spec"

# ── Report output ─────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo " Build complete"
echo "============================================================"
echo ""
echo "RPM packages:"
find "$RPMBUILD_ROOT/RPMS" -name "cert-analyzer-*.rpm" | sort
echo ""
echo "Source RPM:"
find "$RPMBUILD_ROOT/SRPMS" -name "cert-analyzer-*.src.rpm" | sort
echo ""
echo "To install:"
echo "  sudo dnf install $RPMBUILD_ROOT/RPMS/$(uname -m)/cert-analyzer-${VERSION}-${RPM_RELEASE}.*.rpm"
echo ""
echo "After install:"
echo "  sudo vi /etc/cert-analyzer/cert-analyzer.conf"
echo "  sudo systemctl enable --now cert-analyzer"
echo "  sudo systemctl status cert-analyzer"
echo "  sudo journalctl -u cert-analyzer -f"
