#!/bin/bash
set -e

echo "Generating Tetragon Protocol Buffer files..."

TETRAGON_VERSION="v1.7.0"
BASE_URL="https://raw.githubusercontent.com/cilium/tetragon/${TETRAGON_VERSION}/api/v1"

# Use an isolated venv so grpcio-tools does not interfere with the
# caller's Python environment (avoids PyO3 conflicts in CI).
VENV_DIR="$(mktemp -d)"
trap 'rm -rf "$VENV_DIR"' EXIT

python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --quiet --upgrade pip setuptools
"$VENV_DIR/bin/python" -m pip install --quiet grpcio-tools==1.60.1 protobuf==4.25.3

# Create directory for proto files
mkdir -p tetragon

echo "Downloading Tetragon proto files from version ${TETRAGON_VERSION}..."

curl -sL "${BASE_URL}/tetragon/tetragon.proto"    -o tetragon/tetragon.proto
curl -sL "${BASE_URL}/tetragon/bpf.proto"         -o tetragon/bpf.proto
curl -sL "${BASE_URL}/tetragon/capabilities.proto" -o tetragon/capabilities.proto
curl -sL "${BASE_URL}/tetragon/events.proto"       -o tetragon/events.proto
curl -sL "${BASE_URL}/tetragon/sensors.proto"      -o tetragon/sensors.proto

# Generate Python code
echo "Generating Python gRPC code..."
"$VENV_DIR/bin/python" -m grpc_tools.protoc \
    -I. \
    --python_out=. \
    --pyi_out=. \
    --grpc_python_out=. \
    tetragon/tetragon.proto \
    tetragon/bpf.proto \
    tetragon/capabilities.proto \
    tetragon/events.proto \
    tetragon/sensors.proto

# Fix imports in generated files
echo "Fixing imports in generated files..."
sed -i 's/^import tetragon\./from . import /g' tetragon/*_pb2.py tetragon/*_pb2_grpc.py 2>/dev/null || true

# Create __init__.py
touch tetragon/__init__.py

# Clean up downloaded proto files
rm tetragon/tetragon.proto \
   tetragon/bpf.proto \
   tetragon/capabilities.proto \
   tetragon/events.proto \
   tetragon/sensors.proto

echo ""
echo "Tetragon proto files generated successfully in tetragon/"
ls -1 tetragon/*.py
