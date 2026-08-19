#!/bin/bash
set -euo pipefail

# Installs a single-node Apache Kafka broker in KRaft mode (no ZooKeeper)
# as a native systemd service, for local testing of cert-analyzer's Kafka
# publishing (KAFKA_ENABLED=true). Not hardened for production use: no
# TLS, no SASL, no dedicated system user -- matches cert-analyzer's own
# PLAINTEXT default and this repo's install-prometheus.sh conventions.

KAFKA_VERSION="3.9.0"
SCALA_VERSION="2.13"
KAFKA_PORT="9092"
CONTROLLER_PORT="9093"
INSTALL_ROOT="/opt"
INSTALL_DIR="${INSTALL_ROOT}/kafka"
CONFIG_DIR="/etc/kafka"
DATA_DIR="/var/lib/kafka/data"
SERVICE_FILE="/etc/systemd/system/kafka.service"
CERT_ANALYZER_TOPIC="${CERT_ANALYZER_TOPIC:-cert-analyzer-events}"
CERT_ANALYZER_ACCESS_TOPIC="${CERT_ANALYZER_ACCESS_TOPIC:-cert-analyzer-access-events}"
CERT_ANALYZER_CONNECT_TOPIC="${CERT_ANALYZER_CONNECT_TOPIC:-cert-analyzer-events-connect}"
CERT_ANALYZER_ACCESS_CONNECT_TOPIC="${CERT_ANALYZER_ACCESS_CONNECT_TOPIC:-cert-analyzer-access-events-connect}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================"
echo " Apache Kafka ${KAFKA_VERSION} (KRaft) Installer"
echo " for cert-analyzer testing / RHEL 9"
echo "============================================"

# ── Preflight ─────────────────────────────────────────────────────────────────
if ! command -v java >/dev/null 2>&1; then
    echo "ERROR: java not found on PATH. Kafka ${KAFKA_VERSION} requires Java 11+"
    echo "       (e.g. sudo dnf install java-11-openjdk-headless)."
    exit 1
fi

# systemctl is-active flips to "active" as soon as the JVM process starts --
# well before Kafka has finished replaying its metadata log and is actually
# accepting client connections. kafka-broker-api-versions.sh speaks the real
# Kafka protocol, so it only succeeds once the broker is genuinely ready.
wait_for_broker() {
    local timeout_seconds=60
    local waited=0
    until "${INSTALL_DIR}/bin/kafka-broker-api-versions.sh" \
        --bootstrap-server "localhost:${KAFKA_PORT}" >/dev/null 2>&1; do
        waited=$((waited + 2))
        if [ "${waited}" -ge "${timeout_seconds}" ]; then
            return 1
        fi
        sleep 2
    done
    return 0
}

# ── Already installed? ────────────────────────────────────────────────────────
KAFKA_ALREADY_RUNNING=false
if systemctl is-active --quiet kafka 2>/dev/null; then
    echo "kafka.service is already running — skipping install steps."
    KAFKA_ALREADY_RUNNING=true
fi

if [ "${KAFKA_ALREADY_RUNNING}" = false ]; then
    # ── Download (or reuse a local copy) ──────────────────────────────────────
    ARCHIVE="kafka_${SCALA_VERSION}-${KAFKA_VERSION}.tgz"
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    echo ""
    if [ -f "${SCRIPT_DIR}/${ARCHIVE}" ]; then
        echo "[1/6] Using local tarball ${SCRIPT_DIR}/${ARCHIVE}..."
        cp "${SCRIPT_DIR}/${ARCHIVE}" "${TMPDIR}/${ARCHIVE}"
    else
        echo "[1/6] Downloading Kafka ${KAFKA_VERSION}..."
        curl -fsSL \
            "https://archive.apache.org/dist/kafka/${KAFKA_VERSION}/${ARCHIVE}" \
            -o "${TMPDIR}/${ARCHIVE}"
    fi

    # ── Extract and install ───────────────────────────────────────────────────
    echo "[2/6] Installing to ${INSTALL_DIR}..."
    tar -xzf "${TMPDIR}/${ARCHIVE}" -C "${TMPDIR}"
    SRCDIR="${TMPDIR}/kafka_${SCALA_VERSION}-${KAFKA_VERSION}"

    sudo rm -rf "${INSTALL_ROOT}/kafka_${SCALA_VERSION}-${KAFKA_VERSION}"
    sudo mv "${SRCDIR}" "${INSTALL_ROOT}/"
    sudo ln -sfn "${INSTALL_ROOT}/kafka_${SCALA_VERSION}-${KAFKA_VERSION}" "${INSTALL_DIR}"

    # Belt-and-suspenders after the cross-filesystem mv (tmpdir -> /opt):
    # re-assert the execute bit in case it was lost, and relabel SELinux
    # context in case the files kept a context (e.g. tmp_t) that a
    # systemd-launched process isn't permitted to exec -- both would
    # otherwise surface identically as "Permission denied" from systemd.
    sudo chmod +x "${INSTALL_ROOT}/kafka_${SCALA_VERSION}-${KAFKA_VERSION}"/bin/*.sh
    if command -v restorecon >/dev/null 2>&1; then
        sudo restorecon -R "${INSTALL_ROOT}/kafka_${SCALA_VERSION}-${KAFKA_VERSION}"
    fi

    # ── Write config ──────────────────────────────────────────────────────────
    echo "[3/6] Writing config to ${CONFIG_DIR}/server.properties..."
    sudo mkdir -p "${CONFIG_DIR}"

    if [ ! -f "${CONFIG_DIR}/server.properties" ]; then
        sudo tee "${CONFIG_DIR}/server.properties" > /dev/null <<EOF
# Single-node combined broker+controller KRaft config -- testing only.
process.roles=broker,controller
node.id=1
controller.quorum.voters=1@localhost:${CONTROLLER_PORT}

listeners=PLAINTEXT://localhost:${KAFKA_PORT},CONTROLLER://localhost:${CONTROLLER_PORT}
advertised.listeners=PLAINTEXT://localhost:${KAFKA_PORT}
inter.broker.listener.name=PLAINTEXT
controller.listener.names=CONTROLLER
listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT

log.dirs=${DATA_DIR}
num.partitions=1
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
EOF
        echo "    Written ${CONFIG_DIR}/server.properties"
    else
        echo "    ${CONFIG_DIR}/server.properties already exists — left unchanged."
    fi

    # ── Format storage (only once, before the first-ever start) ──────────────
    echo "[4/6] Formatting KRaft storage..."
    sudo mkdir -p "${DATA_DIR}"
    if [ -f "${DATA_DIR}/meta.properties" ]; then
        echo "    ${DATA_DIR}/meta.properties already exists — skipping format."
    else
        CLUSTER_ID=$("${INSTALL_DIR}/bin/kafka-storage.sh" random-uuid)
        sudo "${INSTALL_DIR}/bin/kafka-storage.sh" format \
            -t "${CLUSTER_ID}" \
            -c "${CONFIG_DIR}/server.properties"
    fi

    # ── Write systemd unit ────────────────────────────────────────────────────
    echo "[5/6] Installing systemd service..."
    sudo tee "${SERVICE_FILE}" > /dev/null <<EOF
[Unit]
Description=Apache Kafka (KRaft, single-node, testing)
Documentation=https://kafka.apache.org/documentation/
After=network.target

[Service]
Environment="KAFKA_HEAP_OPTS=-Xmx512M -Xms512M"
ExecStart=${INSTALL_DIR}/bin/kafka-server-start.sh ${CONFIG_DIR}/server.properties
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable --now kafka

    # ── Verify ────────────────────────────────────────────────────────────────
    echo "[6/6] Verifying Kafka..."
    if ! systemctl is-active --quiet kafka; then
        echo "ERROR: kafka.service failed to start."
        sudo journalctl -u kafka -n 40 --no-pager
        exit 1
    fi
    echo "    Waiting for the broker to accept connections..."
    if ! wait_for_broker; then
        echo "ERROR: Kafka did not become ready within 60s."
        sudo journalctl -u kafka -n 40 --no-pager
        exit 1
    fi
    echo "    Kafka is running on port ${KAFKA_PORT}"
fi

# ── Create the cert-analyzer topic ────────────────────────────────────────────
# Also needed on the "already running" path -- a service just started by a
# prior invocation of this script may still be replaying its log.
echo ""
echo "Waiting for the broker to accept connections..."
if ! wait_for_broker; then
    echo "ERROR: Kafka is not accepting connections on localhost:${KAFKA_PORT}."
    sudo journalctl -u kafka -n 40 --no-pager
    exit 1
fi

echo "Ensuring topic '${CERT_ANALYZER_TOPIC}' exists..."
"${INSTALL_DIR}/bin/kafka-topics.sh" --create --if-not-exists \
    --topic "${CERT_ANALYZER_TOPIC}" \
    --bootstrap-server "localhost:${KAFKA_PORT}" \
    --partitions 1 --replication-factor 1 > /dev/null
echo "    Topic ready."

# certificate_accessed publishing is opt-in ([kafka] access_enabled = true,
# off by default) but the topic is created unconditionally here -- cheap to
# have it exist and idle versus a producer.send() failing later because it
# doesn't, if access_enabled gets flipped on after this script already ran.
echo "Ensuring topic '${CERT_ANALYZER_ACCESS_TOPIC}' exists..."
"${INSTALL_DIR}/bin/kafka-topics.sh" --create --if-not-exists \
    --topic "${CERT_ANALYZER_ACCESS_TOPIC}" \
    --bootstrap-server "localhost:${KAFKA_PORT}" \
    --partitions 1 --replication-factor 1 > /dev/null
echo "    Topic ready."

# Same rationale as the access topic above -- connect_enabled defaults to
# false, but the topic is created unconditionally so flipping it on later
# doesn't need a re-run of this script.
echo "Ensuring topic '${CERT_ANALYZER_CONNECT_TOPIC}' exists..."
"${INSTALL_DIR}/bin/kafka-topics.sh" --create --if-not-exists \
    --topic "${CERT_ANALYZER_CONNECT_TOPIC}" \
    --bootstrap-server "localhost:${KAFKA_PORT}" \
    --partitions 1 --replication-factor 1 > /dev/null
echo "    Topic ready."

# Same rationale again -- access_connect_enabled defaults to false too.
echo "Ensuring topic '${CERT_ANALYZER_ACCESS_CONNECT_TOPIC}' exists..."
"${INSTALL_DIR}/bin/kafka-topics.sh" --create --if-not-exists \
    --topic "${CERT_ANALYZER_ACCESS_CONNECT_TOPIC}" \
    --bootstrap-server "localhost:${KAFKA_PORT}" \
    --partitions 1 --replication-factor 1 > /dev/null
echo "    Topic ready."

echo ""
echo "============================================"
echo " Kafka is running on localhost:${KAFKA_PORT}"
echo " Topics: ${CERT_ANALYZER_TOPIC}, ${CERT_ANALYZER_ACCESS_TOPIC}, ${CERT_ANALYZER_CONNECT_TOPIC}, ${CERT_ANALYZER_ACCESS_CONNECT_TOPIC}"
echo ""
echo " Point cert-analyzer at it:"
echo "   [kafka]"
echo "   enabled = true"
echo "   bootstrap_servers = localhost:${KAFKA_PORT}"
echo "   topic = ${CERT_ANALYZER_TOPIC}"
echo "   access_enabled = true   # optional -- off by default"
echo "   access_topic = ${CERT_ANALYZER_ACCESS_TOPIC}"
echo "   connect_enabled = true   # optional -- off by default"
echo "   connect_topic = ${CERT_ANALYZER_CONNECT_TOPIC}"
echo "   access_connect_enabled = true   # optional -- off by default"
echo "   access_connect_topic = ${CERT_ANALYZER_ACCESS_CONNECT_TOPIC}"
echo ""
echo " Tail messages:"
echo "   ${INSTALL_DIR}/bin/kafka-console-consumer.sh \\"
echo "     --bootstrap-server localhost:${KAFKA_PORT} --topic ${CERT_ANALYZER_TOPIC} --from-beginning"
echo ""
echo " Override the topic names if needed:"
echo "   CERT_ANALYZER_TOPIC=<name> CERT_ANALYZER_ACCESS_TOPIC=<name> CERT_ANALYZER_CONNECT_TOPIC=<name> CERT_ANALYZER_ACCESS_CONNECT_TOPIC=<name> bash $0"
echo "============================================"
