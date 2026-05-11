#!/bin/bash
set -e

echo "Generating Tetragon Protocol Buffer files..."

# Install grpcio-tools if not present
pip install --quiet grpcio-tools==1.60.1 protobuf==4.25.3

# Create directory for proto files
mkdir -p tetragon

# Download Tetragon proto files
TETRAGON_VERSION="v1.0.0"
BASE_URL="https://raw.githubusercontent.com/cilium/tetragon/${TETRAGON_VERSION}/api/v1"

echo "Downloading Tetragon proto files from version ${TETRAGON_VERSION}..."

# Download all proto files into the tetragon directory
curl -sL "${BASE_URL}/tetragon/tetragon.proto" -o tetragon/tetragon.proto
curl -sL "${BASE_URL}/tetragon/capabilities.proto" -o tetragon/capabilities.proto
curl -sL "${BASE_URL}/tetragon/events.proto" -o tetragon/events.proto
curl -sL "${BASE_URL}/tetragon/sensors.proto" -o tetragon/sensors.proto
curl -sL "${BASE_URL}/tetragon/stack.proto" -o tetragon/stack.proto

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
    tetragon/stack.proto

# Fix imports in generated files (Python import issue)
echo "Fixing imports in generated files..."
sed -i 's/^import tetragon\./from . import /g' tetragon/*_pb2.py tetragon/*_pb2_grpc.py 2>/dev/null || true

# Create __init__.py
touch tetragon/__init__.py

# Clean up downloaded proto files
rm tetragon/tetragon.proto
rm tetragon/capabilities.proto
rm tetragon/events.proto  
rm tetragon/sensors.proto
rm tetragon/stack.proto

echo ""
echo "✅ Tetragon proto files generated successfully in tetragon/"
ls -1 tetragon/*.py
