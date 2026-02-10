#!/bin/bash
set -e

echo "Generating Tetragon Protocol Buffer files..."

# Install grpcio-tools if not present
pip install --quiet grpcio-tools

# Create directory for proto files
mkdir -p tetragon

# Download Tetragon proto files
TETRAGON_VERSION="v1.0.0"
echo "Downloading Tetragon proto from version ${TETRAGON_VERSION}..."

curl -sL "https://raw.githubusercontent.com/cilium/tetragon/${TETRAGON_VERSION}/api/v1/tetragon/tetragon.proto" \
    -o tetragon.proto

# Generate Python code
echo "Generating Python gRPC code..."
python -m grpc_tools.protoc \
    -I. \
    --python_out=tetragon \
    --grpc_python_out=tetragon \
    tetragon.proto

# Create __init__.py
touch tetragon/__init__.py

# Clean up
rm tetragon.proto

echo "✅ Tetragon proto files generated successfully in tetragon/"
echo "   - tetragon_pb2.py"
echo "   - tetragon_pb2_grpc.py"
