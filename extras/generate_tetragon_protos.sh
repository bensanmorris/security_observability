#!/bin/bash
set -e

echo "Generating Tetragon Protocol Buffer files..."

TETRAGON_VERSION="v1.7.0"
BASE_URL="https://raw.githubusercontent.com/cilium/tetragon/${TETRAGON_VERSION}/api/v1"

# setuptools provides pkg_resources, which grpcio-tools imports but does not
# declare as a dependency.  Python 3.12+ no longer ships it by default, so we
# always ensure it is present before the grpc_tools check.
pip install --quiet setuptools

if ! python3 -c "import grpc_tools" 2>/dev/null; then
    pip install --quiet grpcio-tools==1.60.1 protobuf==4.25.3
fi

# Create directory for proto files
mkdir -p tetragon

echo "Downloading Tetragon proto files from version ${TETRAGON_VERSION}..."

curl -sL "${BASE_URL}/tetragon/tetragon.proto"     -o tetragon/tetragon.proto
curl -sL "${BASE_URL}/tetragon/bpf.proto"          -o tetragon/bpf.proto
curl -sL "${BASE_URL}/tetragon/capabilities.proto" -o tetragon/capabilities.proto
curl -sL "${BASE_URL}/tetragon/events.proto"       -o tetragon/events.proto
curl -sL "${BASE_URL}/tetragon/sensors.proto"      -o tetragon/sensors.proto

# Generate Python code
echo "Generating Python gRPC code..."
python3 -m grpc_tools.protoc \
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
