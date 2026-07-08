#!/bin/bash

echo "============================================"
echo "Building Certificate Analyzer for Podman"
echo "============================================"

# Generate Tetragon protobuf files if not present
if [ ! -d "tetragon" ] || [ ! -f "tetragon/tetragon_pb2.py" ]; then
    echo "Generating Tetragon protobuf files..."
    bash generate_tetragon_protos.sh
fi

# Stop and remove running container (ignore errors if not running/present)
sudo podman stop cert-analyzer 2>/dev/null || true
sudo podman rm cert-analyzer 2>/dev/null || true
sudo podman rmi localhost/cert-analyzer:latest 2>/dev/null || true

# Optional overrides for corporate environments that mirror/proxy the UBI
# Python base image and/or the PyPI index at their own URLs, e.g.:
#   UBI_PYTHON_IMAGE=registry.corp.example.com/ubi9/python-311:latest \
#   PIP_INDEX_URL=https://pypi.corp.example.com/simple/ \
#   PIP_TRUSTED_HOST=pypi.corp.example.com \
#   ./build.sh
BUILD_ARGS=()
[ -n "$UBI_PYTHON_IMAGE" ] && BUILD_ARGS+=(--build-arg "UBI_PYTHON_IMAGE=$UBI_PYTHON_IMAGE")
[ -n "$PIP_INDEX_URL" ] && BUILD_ARGS+=(--build-arg "PIP_INDEX_URL=$PIP_INDEX_URL")
[ -n "$PIP_TRUSTED_HOST" ] && BUILD_ARGS+=(--build-arg "PIP_TRUSTED_HOST=$PIP_TRUSTED_HOST")

# Build with Podman
echo "Building container image..."
sudo podman build \
    --tag cert-analyzer:latest \
    --file Containerfile \
    "${BUILD_ARGS[@]}" \
    .

echo ""
echo "✅ Build complete!"
echo "   Image: cert-analyzer:latest"
echo ""
echo "Next steps:"
echo "  - Run with: ./run-rootless.sh or ./run-rootful.sh"
echo "  - Deploy to systemd: sudo cp systemd/cert-analyzer.service /etc/systemd/system/"
