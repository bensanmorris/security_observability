#!/bin/bash
set -euo pipefail

# Sparse-clones the api/ subtree of the Tetragon repo at TETRAGON_VERSION into
# ./tetragon-src, for use as Containerfile build context (see the
# proto-builder stage in Containerfile). Kept out of the Containerfile itself
# so `docker build` / `podman build` can run with no outbound network access
# at all — only this script needs to reach a Tetragon git remote, and it can
# be run ahead of time (e.g. in CI, or once against an internal mirror before
# an air-gapped build).
#
# Point TETRAGON_REPO_URL at an internal mirror for locked-down corporate
# environments, e.g.:
#   TETRAGON_REPO_URL=https://git.corp.example.com/mirror/tetragon.git \
#   ./fetch-tetragon-src.sh v1.7.0

TETRAGON_VERSION="${1:-${TETRAGON_VERSION:-v1.7.0}}"
TETRAGON_REPO_URL="${TETRAGON_REPO_URL:-https://github.com/cilium/tetragon.git}"
DEST="tetragon-src"

echo "Fetching Tetragon ${TETRAGON_VERSION} api/ sources from ${TETRAGON_REPO_URL} into ${DEST}/ ..."

rm -rf "${DEST}"
git clone --depth 1 --branch "${TETRAGON_VERSION}" \
    --filter=blob:none --sparse \
    "${TETRAGON_REPO_URL}" "${DEST}"
git -C "${DEST}" sparse-checkout set api

# Drop .git — it's not needed past this point, and leaving it out keeps the
# Containerfile's build context (which includes tetragon-src/) small.
rm -rf "${DEST}/.git"

echo "Done: ${DEST}/api"
