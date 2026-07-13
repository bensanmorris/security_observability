#!/usr/bin/env bash
# Build the cert-agent JAR and native stub library.
#
# Requires (build toolchain):
#   - Any JDK 11+ devel package (javac, jar, java) -- e.g. java-11-openjdk-devel
#   - gcc
#
# The JAR is compiled at -source/-target 11 regardless of which JDK's javac
# builds it, producing a classfile-version-55 JAR that's forward-compatible
# with newer JVMs -- one build artifact serves multiple target JVM versions.
# Validated end-to-end (unmodified, no rebuild) on both Java 11 and Java 17
# target JVMs; see probe_tests/README.md and extras/PRESENTATION-QA.md.
#
# The build downloads asm-9.7.jar and asm-commons-9.7.jar from Maven Central
# on first run and caches them in .deps/. Set OFFLINE=1 to skip the download
# if they are already present.
set -euo pipefail
cd "$(dirname "$0")"

JAVA_HOME="${JAVA_HOME:-$(java -XshowSettings:all -version 2>&1 | grep 'java.home' | awk '{print $3}')}"
ASM_VERSION="9.7"
DEPS_DIR=".deps"
ASM_JAR="$DEPS_DIR/asm-${ASM_VERSION}.jar"
ASM_COMMONS_JAR="$DEPS_DIR/asm-commons-${ASM_VERSION}.jar"
CLASSES_DIR="classes"
FAT_DIR="fat"
OUTPUT_JAR="cert-agent.jar"

MAVEN_BASE="https://repo1.maven.org/maven2/org/ow2/asm"

# ── Download ASM if needed ──────────────────────────────────────────────────
mkdir -p "$DEPS_DIR"
if [[ ! -f "$ASM_JAR" ]]; then
    echo "Downloading asm-${ASM_VERSION}.jar..."
    curl -sSfL "${MAVEN_BASE}/asm/${ASM_VERSION}/asm-${ASM_VERSION}.jar" -o "$ASM_JAR"
fi
if [[ ! -f "$ASM_COMMONS_JAR" ]]; then
    echo "Downloading asm-commons-${ASM_VERSION}.jar..."
    curl -sSfL "${MAVEN_BASE}/asm-commons/${ASM_VERSION}/asm-commons-${ASM_VERSION}.jar" -o "$ASM_COMMONS_JAR"
fi

# ── Compile Java sources ────────────────────────────────────────────────────
mkdir -p "$CLASSES_DIR"
javac -source 11 -target 11 -encoding UTF-8 \
    -cp "$ASM_JAR:$ASM_COMMONS_JAR" \
    -d "$CLASSES_DIR" \
    src/com/security/certagent/*.java
echo "Compilation OK"

# ── Build fat JAR (bundle ASM classes to avoid version conflicts at runtime) ─
mkdir -p "$FAT_DIR"
# Extract ASM into a temp dir
mkdir -p "$FAT_DIR/asm_extract"
(cd "$FAT_DIR/asm_extract" && jar xf "../../$ASM_JAR" && jar xf "../../$ASM_COMMONS_JAR")
# Remove META-INF from extracted ASM (we use our own manifest)
rm -rf "$FAT_DIR/asm_extract/META-INF"

# Assemble final JAR: agent classes + bundled ASM
cp -r "$CLASSES_DIR/." "$FAT_DIR/asm_extract/"
jar cfm "$OUTPUT_JAR" MANIFEST.MF -C "$FAT_DIR/asm_extract" .
echo "Built $OUTPUT_JAR"

# ── Build native stub ───────────────────────────────────────────────────────
make -C native JAVA_HOME="$JAVA_HOME"
echo "Built native/libcert_agent_stub.so"

# ── Install to the path expected by java-non-fips-cert.yaml ─────────────────
# Both local testing and production use /opt/cert-agent/ so the Tetragon
# policy path never needs editing.
INSTALL_DIR="/opt/cert-agent"
sudo mkdir -p "$INSTALL_DIR"
sudo cp native/libcert_agent_stub.so "$INSTALL_DIR/libcert_agent_stub.so"
sudo cp "$OUTPUT_JAR" "$INSTALL_DIR/$OUTPUT_JAR"
echo "Installed to $INSTALL_DIR/"

echo ""
echo "Artifacts:"
echo "  $INSTALL_DIR/$OUTPUT_JAR"
echo "  $INSTALL_DIR/libcert_agent_stub.so"
echo ""
echo "Static injection:"
echo "  java -javaagent:$INSTALL_DIR/$OUTPUT_JAR=$INSTALL_DIR/libcert_agent_stub.so -jar yourapp.jar"
echo ""
echo "Dynamic attach (bundled jattach):"
echo "  ./jattach-linux-x64/jattach <pid> load instrument false $INSTALL_DIR/$OUTPUT_JAR=$INSTALL_DIR/libcert_agent_stub.so"
