#!/usr/bin/env bash
# Build FipsJavaCertLoad.java.
# Requires: java-11-openjdk-devel, nss-tools (certutil)
set -euo pipefail
cd "$(dirname "$0")"
javac FipsJavaCertLoad.java
echo "Build OK — run with:"
echo "  java -cp . FipsJavaCertLoad [--pause] [cert.pem]"
