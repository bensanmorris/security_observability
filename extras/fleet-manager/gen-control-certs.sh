#!/usr/bin/env bash
# gen-control-certs.sh — Create a small private PKI for cert-analyzer's
# fleet-control listener and the fleet manager's client identity.
#
# Produces, under <outdir> (default ./control-pki):
#   ca.crt / ca.key                  the CA (keep ca.key offline once done)
#   node-<name>.crt / .key           one server cert per node, SAN = the
#                                    address the fleet manager will dial
#   fleet-manager.crt / .key         client cert, CN=fleet-manager
#   fleet-auditor.crt / .key         optional read-only client, CN=fleet-auditor
#
# Then on each node (cert-analyzer.conf [control]):
#   tls_cert = /etc/cert-analyzer/control/server.crt      (node-<name>.crt)
#   tls_key  = /etc/cert-analyzer/control/server.key
#   tls_client_ca = /etc/cert-analyzer/control/ca.crt
#   authorized_clients = fleet-manager
#   readonly_clients = fleet-auditor
# and in fleet-manager.conf:
#   FLEET_MANAGER_NODE_TLS_CA=.../ca.crt
#   FLEET_MANAGER_NODE_CLIENT_CERT=.../fleet-manager.crt
#   FLEET_MANAGER_NODE_CLIENT_KEY=.../fleet-manager.key
#
# Usage:
#   ./gen-control-certs.sh [--out DIR] [--days N] [--auditor] node1[:san1[,san2]] [node2 ...]
#   e.g. ./gen-control-certs.sh --auditor web-01:10.0.1.7 k8s-a:10.0.1.9,k8s-a.internal
#
# A node's SAN list defaults to its name; put the IP the fleet manager
# actually connects to in there or hostname verification fails. This is a
# convenience for labs and the demo -- an organisation with its own PKI
# should issue from that instead; the listener only needs standard X.509.
#
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

OUT=./control-pki
DAYS=825
AUDITOR=false
NODES=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out)     OUT="$2"; shift 2 ;;
        --days)    DAYS="$2"; shift 2 ;;
        --auditor) AUDITOR=true; shift ;;
        -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
        *)         NODES+=("$1"); shift ;;
    esac
done
if [[ ${#NODES[@]} -eq 0 ]]; then
    echo "usage: $0 [--out DIR] [--days N] [--auditor] node[:san,...] ..." >&2
    exit 1
fi
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

mkdir -p "$OUT"
chmod 700 "$OUT"
cd "$OUT"

if [[ ! -f ca.key ]]; then
    echo "==> CA"
    openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days "$DAYS" \
        -keyout ca.key -out ca.crt -subj "/CN=certsight-control-ca" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
    chmod 600 ca.key
else
    echo "==> CA: reusing existing ca.key/ca.crt"
fi

issue() {   # issue <basename> <CN> <extfile-content>
    local base="$1" cn="$2" ext="$3"
    openssl req -new -newkey rsa:2048 -nodes -sha256 -keyout "$base.key" -out "$base.csr" -subj "/CN=$cn" >/dev/null 2>&1
    printf '%s\n' "$ext" > "$base.ext"
    openssl x509 -req -in "$base.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days "$DAYS" -sha256 \
        -extfile "$base.ext" -out "$base.crt" >/dev/null 2>&1
    rm -f "$base.csr" "$base.ext"
    chmod 600 "$base.key"
}

for spec in "${NODES[@]}"; do
    name="${spec%%:*}"
    sans="${spec#*:}"; [[ "$sans" == "$spec" ]] && sans="$name"
    san_list=""
    IFS=',' read -ra parts <<< "$sans"
    for p in "${parts[@]}"; do
        if [[ "$p" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$p" == *:*:* ]]; then
            san_list+="IP:$p,"
        else
            san_list+="DNS:$p,"
        fi
    done
    echo "==> node $name (SAN ${san_list%,})"
    issue "node-$name" "$name" "subjectAltName=${san_list%,}
extendedKeyUsage=serverAuth
keyUsage=critical,digitalSignature,keyEncipherment"
done

echo "==> client fleet-manager"
issue fleet-manager fleet-manager "extendedKeyUsage=clientAuth
keyUsage=critical,digitalSignature"
if $AUDITOR; then
    echo "==> client fleet-auditor (read-only)"
    issue fleet-auditor fleet-auditor "extendedKeyUsage=clientAuth
keyUsage=critical,digitalSignature"
fi
rm -f ca.srl

echo ""
echo "Written to $(pwd):"
ls -1 *.crt *.key
echo ""
echo "Copy node-<name>.crt/.key + ca.crt to each node's /etc/cert-analyzer/control/ (root:cert-analyzer 0640),"
echo "and ca.crt + fleet-manager.crt/.key to the fleet manager host. Keep ca.key offline."
