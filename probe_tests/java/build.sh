#!/usr/bin/env bash
# Build Java probe test programs.
# Requires: java-11-openjdk-devel, nss-tools (certutil)
set -euo pipefail
cd "$(dirname "$0")"
javac -encoding UTF-8 FipsJavaCertLoad.java CertAgentTest.java
echo "Build OK"
echo ""
echo "FIPS path (NSS/PKCS11 hooks):"
echo "  java -cp . FipsJavaCertLoad [--pause] [cert.pem]"
echo ""
echo "Non-FIPS path (cert-agent dynamic attach):"
echo "  java -cp . CertAgentTest [cert.pem] [interval_ms]"
