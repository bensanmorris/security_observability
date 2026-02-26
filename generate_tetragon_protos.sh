#!/bin/bash
set -e

# TETRAGON_VERSION must be set by the caller, e.g.:
#   TETRAGON_VERSION=v1.6.0 ./generate_tetragon_protos.sh
if [ -z "${TETRAGON_VERSION}" ]; then
    echo "ERROR: TETRAGON_VERSION is not set. Usage: TETRAGON_VERSION=v1.6.0 $0"
    exit 1
fi

echo "Generating Tetragon Protocol Buffer files for version ${TETRAGON_VERSION}..."

# Install grpcio-tools if not present
pip install --quiet grpcio-tools==1.60.1 protobuf==4.25.3

# Create directory for proto files
mkdir -p tetragon

BASE_URL="https://raw.githubusercontent.com/cilium/tetragon/${TETRAGON_VERSION}/api/v1"

echo "Downloading Tetragon proto files from version ${TETRAGON_VERSION}..."

# Note: bpf.proto was added in v1.6.0 and is required by tetragon.proto
PROTO_FILES=(
    "tetragon.proto"
    "capabilities.proto"
    "events.proto"
    "sensors.proto"
    "stack.proto"
    "bpf.proto"
)

for proto in "${PROTO_FILES[@]}"; do
    echo "  Downloading ${proto}..."
    curl -sL "${BASE_URL}/tetragon/${proto}" -o "tetragon/${proto}"
    # Verify the file was downloaded and is not empty/an error page
    if [ ! -s "tetragon/${proto}" ]; then
        echo "ERROR: Failed to download ${proto} (file is empty)"
        exit 1
    fi
done

# Generate Python code with protoc 3 compatibility
echo "Generating Python gRPC code..."
python -m grpc_tools.protoc \
    -I. \
    --python_out=. \
    --pyi_out=. \
    --grpc_python_out=. \
    tetragon/tetragon.proto \
    tetragon/capabilities.proto \
    tetragon/events.proto \
    tetragon/sensors.proto \
    tetragon/stack.proto \
    tetragon/bpf.proto

# Fix imports in generated files (Python relative import issue)
echo "Fixing imports in generated files..."
sed -i 's/^import tetragon\./from . import /g' tetragon/*_pb2.py tetragon/*_pb2_grpc.py 2>/dev/null || true

# Create __init__.py
touch tetragon/__init__.py

# Clean up downloaded proto files
echo "Cleaning up proto source files..."
for proto in "${PROTO_FILES[@]}"; do
    rm -f "tetragon/${proto}"
done

echo ""
echo "✅ Tetragon proto files generated successfully in tetragon/"
ls -1 tetragon/*.py
