#!/bin/bash
set -e

echo "============================================"
echo "Building Certificate Analyzer for Podman"
echo "============================================"

# Generate Tetragon protobuf files if not present
if [ ! -d "tetragon" ] || [ ! -f "tetragon/tetragon_pb2.py" ]; then
    echo "Generating Tetragon protobuf files..."
    bash generate_tetragon_protos.sh
fi

# Stop and remove running container
sudo podman stop cert-analyzer
sudo podman rm cert-analyzer
sudo podman rmi localhost/cert-analyzer:latest

# Build with Podman
echo "Building container image..."
sudo podman build \
    --tag cert-analyzer:latest \
    --file Containerfile \
    .

echo ""
echo "✅ Build complete!"
echo "   Image: cert-analyzer:latest"
echo ""
echo "Next steps:"
echo "  - Run with: ./run-rootless.sh or ./run-rootful.sh"
echo "  - Deploy to systemd: sudo cp systemd/cert-analyzer.service /etc/systemd/system/"
