#!/usr/bin/env bash
# build-rpm.sh — Build the cert-agent-jni and cert-agent-deployer RPMs on RHEL9
#
# Usage:
#   ./build-rpm.sh [OPTIONS]
#
# Options:
#   --version <ver>       RPM version (default: git tag or short SHA)
#   --release <rel>       RPM release number (default: 1)
#   --java-version <ver>  JDK major version to build the native stub against
#                         (default: 11); passed as _java_version to rpmbuild
#   --rebuild-jar         Rebuild cert-agent.jar from source before packaging
#                         (requires JDK + network access for ASM download).
#                         By default the pre-built JAR from probe_tests/ is used.
#   --jni-only            Build only cert-agent-jni RPM
#   --deployer-only       Build only cert-agent-deployer RPM
#
# Environment variables override defaults:
#   RPM_VERSION, RPM_RELEASE, JAVA_VERSION, RPMBUILD_ROOT
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
RPM_RELEASE="${RPM_RELEASE:-1}"
JAVA_VERSION="${JAVA_VERSION:-11}"
REBUILD_JAR=0
BUILD_JNI=1
BUILD_DEPLOYER=1

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
        --version)        VERSION="$2";       shift 2 ;;
        --release)        RPM_RELEASE="$2";   shift 2 ;;
        --java-version)   JAVA_VERSION="$2";  shift 2 ;;
        --rebuild-jar)    REBUILD_JAR=1;      shift   ;;
        --jni-only)       BUILD_DEPLOYER=0;   shift   ;;
        --deployer-only)  BUILD_JNI=0;        shift   ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "============================================================"
echo " Building Java agent RPMs"
echo " Version:      $VERSION"
echo " Release:      $RPM_RELEASE"
echo " Java version: $JAVA_VERSION"
echo " Repo root:    $REPO_ROOT"
echo " Build JNI:    $BUILD_JNI  |  Build deployer: $BUILD_DEPLOYER"
echo "============================================================"

# ── Verify prerequisites ──────────────────────────────────────────────────────
REQUIRED_CMDS=(rpmbuild git)
[[ "$BUILD_JNI"      -eq 1 ]] && REQUIRED_CMDS+=(gcc)
[[ "$REBUILD_JAR"    -eq 1 ]] && REQUIRED_CMDS+=(javac jar)

for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd is required but not found in PATH." >&2
        exit 1
    fi
done

# ── Locate source artifacts ───────────────────────────────────────────────────
JAVA_AGENT_SRC="$REPO_ROOT/probe_tests/java/cert-agent"

PREBUILT_JAR="$JAVA_AGENT_SRC/cert-agent.jar"
NATIVE_C_SRC="$JAVA_AGENT_SRC/native/cert_agent_stub.c"
NATIVE_MAKEFILE="$JAVA_AGENT_SRC/native/Makefile"
JATTACH_BIN="$JAVA_AGENT_SRC/jattach-linux-x64/jattach"
DEPLOYER_SCRIPT="$REPO_ROOT/java_agent_deployer.py"
DEPLOYER_SERVICE="$SCRIPT_DIR/cert-agent-deployer.service"
LICENSE="$REPO_ROOT/LICENSE"

for f in "$NATIVE_C_SRC" "$NATIVE_MAKEFILE" "$JATTACH_BIN" \
          "$DEPLOYER_SCRIPT" "$DEPLOYER_SERVICE" "$LICENSE"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: Required source file not found: $f" >&2
        exit 1
    fi
done

# ── Optionally rebuild the fat JAR from source ────────────────────────────────
if [[ "$REBUILD_JAR" -eq 1 ]]; then
    echo "Rebuilding cert-agent.jar from source..."
    # build.sh installs to /opt/cert-agent/ as a side effect; we only need the
    # JAR so we copy it out immediately after and ignore the install step.
    (cd "$JAVA_AGENT_SRC" && bash build.sh)
    echo "JAR rebuilt."
fi

if [[ ! -f "$PREBUILT_JAR" ]]; then
    echo "ERROR: cert-agent.jar not found at $PREBUILT_JAR" >&2
    echo "       Run with --rebuild-jar to build it from source, or build" >&2
    echo "       probe_tests/java/cert-agent/build.sh manually first." >&2
    exit 1
fi

# ── Set up rpmbuild tree ──────────────────────────────────────────────────────
RPMBUILD_ROOT="${RPMBUILD_ROOT:-$HOME/rpmbuild}"
for dir in BUILD BUILDROOT RPMS SOURCES SPECS SRPMS; do
    mkdir -p "$RPMBUILD_ROOT/$dir"
done

TMPDIR_SRC="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_SRC"' EXIT

# ── Build cert-agent-jni RPM ──────────────────────────────────────────────────
if [[ "$BUILD_JNI" -eq 1 ]]; then
    echo ""
    echo "--- cert-agent-jni ---"

    JNI_TARNAME="cert-agent-jni-${VERSION}"
    JNI_TARBALL="$RPMBUILD_ROOT/SOURCES/${JNI_TARNAME}.tar.gz"
    JNI_STAGING="$TMPDIR_SRC/$JNI_TARNAME"

    mkdir -p "$JNI_STAGING/native"
    cp "$PREBUILT_JAR"    "$JNI_STAGING/cert-agent.jar"
    cp "$NATIVE_C_SRC"    "$JNI_STAGING/native/cert_agent_stub.c"
    cp "$NATIVE_MAKEFILE" "$JNI_STAGING/native/Makefile"
    cp "$LICENSE"         "$JNI_STAGING/LICENSE"

    tar -czf "$JNI_TARBALL" -C "$TMPDIR_SRC" "$JNI_TARNAME"
    echo "Source tarball: $JNI_TARBALL"

    cp "$SCRIPT_DIR/cert-agent-jni.spec" "$RPMBUILD_ROOT/SPECS/cert-agent-jni.spec"

    rpmbuild -ba \
        --define "_topdir      $RPMBUILD_ROOT" \
        --define "_version     $VERSION" \
        --define "_release     $RPM_RELEASE" \
        --define "_java_version $JAVA_VERSION" \
        "$RPMBUILD_ROOT/SPECS/cert-agent-jni.spec"

    echo "cert-agent-jni build done."
fi

# ── Build cert-agent-deployer RPM ─────────────────────────────────────────────
if [[ "$BUILD_DEPLOYER" -eq 1 ]]; then
    echo ""
    echo "--- cert-agent-deployer ---"

    DEP_TARNAME="cert-agent-deployer-${VERSION}"
    DEP_TARBALL="$RPMBUILD_ROOT/SOURCES/${DEP_TARNAME}.tar.gz"
    DEP_STAGING="$TMPDIR_SRC/$DEP_TARNAME"

    mkdir -p "$DEP_STAGING"
    cp "$DEPLOYER_SCRIPT"  "$DEP_STAGING/java_agent_deployer.py"
    cp "$JATTACH_BIN"      "$DEP_STAGING/jattach"
    cp "$DEPLOYER_SERVICE" "$DEP_STAGING/cert-agent-deployer.service"
    cp "$LICENSE"          "$DEP_STAGING/LICENSE"

    tar -czf "$DEP_TARBALL" -C "$TMPDIR_SRC" "$DEP_TARNAME"
    echo "Source tarball: $DEP_TARBALL"

    cp "$SCRIPT_DIR/cert-agent-deployer.spec" \
        "$RPMBUILD_ROOT/SPECS/cert-agent-deployer.spec"

    rpmbuild -ba \
        --define "_topdir  $RPMBUILD_ROOT" \
        --define "_version $VERSION" \
        --define "_release $RPM_RELEASE" \
        "$RPMBUILD_ROOT/SPECS/cert-agent-deployer.spec"

    echo "cert-agent-deployer build done."
fi

# ── Report output ─────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo " Build complete"
echo "============================================================"
echo ""
echo "RPM packages:"
find "$RPMBUILD_ROOT/RPMS" \( -name "cert-agent-jni-*.rpm" \
                            -o -name "cert-agent-deployer-*.rpm" \) | sort
echo ""
echo "Source RPMs:"
find "$RPMBUILD_ROOT/SRPMS" \( -name "cert-agent-jni-*.src.rpm" \
                             -o -name "cert-agent-deployer-*.src.rpm" \) | sort
echo ""
echo "To install:"
ARCH="$(uname -m)"
[[ "$BUILD_JNI"      -eq 1 ]] && \
    echo "  sudo dnf install $RPMBUILD_ROOT/RPMS/$ARCH/cert-agent-jni-${VERSION}-${RPM_RELEASE}.*.rpm"
[[ "$BUILD_DEPLOYER" -eq 1 ]] && \
    echo "  sudo dnf install $RPMBUILD_ROOT/RPMS/$ARCH/cert-agent-deployer-${VERSION}-${RPM_RELEASE}.*.rpm"
echo ""
echo "After install:"
echo "  sudo systemctl enable --now cert-agent-deployer"
echo "  sudo journalctl -u cert-agent-deployer -f"
