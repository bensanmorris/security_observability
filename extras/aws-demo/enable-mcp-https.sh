#!/usr/bin/env bash
# enable-mcp-https.sh — Terminate TLS at nginx for the MCP server (port 8092)
# with a real Let's Encrypt certificate, rather than adding TLS support to
# server.py itself -- matches how the rest of this stack already works
# (nginx already fronts the MCP server for rate-limiting; see
# user-data.sh's "nginx reverse proxy in front of the MCP server" section).
#
# Deliberately a separate script, not folded into user-data.sh: user-data.sh
# runs during instance *boot*, before deploy-demo.sh has pointed DNS at the
# new instance's IP -- Let's Encrypt's HTTP-01 challenge validates domain
# control by connecting back to port 80 on that name, so it can only run
# once DNS has actually propagated. Run this after deploy-demo.sh finishes
# (and, for a fresh instance, after giving DNS a minute or two to catch up).
#
# Also usable to retrofit an already-running demo instance that predates
# this script -- reads connection details from .certsight-demo-state the
# same way update-ssh-ip.sh does, and is safe to re-run (certbot no-ops on
# an existing non-expiring-soon cert; the SG rule authorize is idempotent).
#
# Usage:
#   ./enable-mcp-https.sh [domain]   # defaults to DOMAIN_NAME in the state file

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="${SCRIPT_DIR}/.certsight-demo-state"

if [[ ! -f "${STATE_FILE}" ]]; then
    echo "No ${STATE_FILE} found -- run deploy-demo.sh first."
    exit 1
fi
# shellcheck disable=SC1090
source "${STATE_FILE}"

DOMAIN="${1:-${DOMAIN_NAME:-}}"
if [[ -z "${DOMAIN}" ]]; then
    echo "No domain given and DOMAIN_NAME isn't set in ${STATE_FILE} -- pass one explicitly:" >&2
    echo "  ./enable-mcp-https.sh certsight-demo.com" >&2
    exit 1
fi

echo "==> Confirming ${DOMAIN} resolves to this instance's public IP (${PUBLIC_IP})..."
RESOLVED_IP="$(dig +short "${DOMAIN}" A | tail -1)"
if [[ "${RESOLVED_IP}" != "${PUBLIC_IP}" ]]; then
    echo "WARNING: ${DOMAIN} currently resolves to '${RESOLVED_IP:-<nothing>}', not ${PUBLIC_IP}." >&2
    echo "         Let's Encrypt's HTTP-01 challenge will fail until DNS has propagated -- wait a" >&2
    echo "         few minutes (DNS TTL is 300s) and retry." >&2
    exit 1
fi

echo "==> Ensuring port 80 (needed for the HTTP-01 challenge, both now and on every renewal) is open on ${SG_ID}..."
aws ec2 authorize-security-group-ingress --region "${AWS_REGION}" --group-id "${SG_ID}" \
    --ip-permissions "IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges=[{CidrIp=0.0.0.0/0,Description='Lets Encrypt HTTP-01 challenge'}]" \
    2>/dev/null || true   # already-open is a harmless duplicate-rule error

echo "==> Obtaining/renewing the certificate and reconfiguring nginx over SSH..."
ssh -o StrictHostKeyChecking=no -i "${SCRIPT_DIR}/${KEY_NAME}.pem" "rocky@${PUBLIC_IP}" "DOMAIN='${DOMAIN}' sudo -E bash -s" <<'REMOTE'
set -euo pipefail

echo "--- installing certbot ---"
dnf -y install epel-release || true
dnf -y install certbot

echo "--- obtaining/renewing the certificate (standalone mode, port 80) ---"
# --standalone briefly binds port 80 itself for the HTTP-01 challenge --
# nothing else on this box listens there (nginx is only ever on
# 3000/8090/8092), so there's no conflict. --deploy-hook is persisted into
# certbot's own renewal config (/etc/letsencrypt/renewal/<domain>.conf), so
# certbot-renew.timer's automatic future renewals reload nginx too, not
# just this first run. certbot itself no-ops (exit 0, nothing re-issued) if
# a valid cert for this name already exists and isn't close to expiring.
certbot certonly --standalone --non-interactive --agree-tos \
    --register-unsafely-without-email \
    --deploy-hook "systemctl reload nginx" \
    -d "${DOMAIN}"

echo "--- adding TLS to the MCP server's nginx block (idempotent) ---"
CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
if ! grep -q "listen 8092 ssl" /etc/nginx/conf.d/certsight-mcp.conf; then
    sed -i \
        -e "s#listen 8092 default_server;#listen 8092 ssl default_server;\n    ssl_certificate ${CERT_DIR}/fullchain.pem;\n    ssl_certificate_key ${CERT_DIR}/privkey.pem;#" \
        /etc/nginx/conf.d/certsight-mcp.conf
fi

nginx -t && systemctl reload nginx
echo "--- done ---"
REMOTE

echo ""
echo "==> Point an MCP client at the TLS endpoint:"
echo "    claude mcp add --transport http certsight https://${DOMAIN}:8092/mcp"
