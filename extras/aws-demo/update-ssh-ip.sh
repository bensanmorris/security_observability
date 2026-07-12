#!/bin/bash
# Re-points the demo security group's SSH rule at a given (or auto-detected)
# IP. Use this any time SSH access breaks -- most commonly because
# deploy-demo.sh was run from a different machine/network than the one you
# actually want to SSH in from (e.g. an agent sandbox vs. your own laptop),
# or because your IP changed since deploy time.
#
# Usage:
#   ./update-ssh-ip.sh                # auto-detects the IP of the machine
#                                      # running *this* script
#   ./update-ssh-ip.sh 203.0.113.7    # or pass one explicitly -- e.g. run
#                                      # `curl -s https://checkip.amazonaws.com`
#                                      # on the machine you'll SSH from and
#                                      # paste its output here

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="${SCRIPT_DIR}/.certsight-demo-state"

if [[ ! -f "${STATE_FILE}" ]]; then
    echo "No ${STATE_FILE} found -- run deploy-demo.sh first."
    exit 1
fi
# shellcheck disable=SC1090
source "${STATE_FILE}"

if [[ -n "${1:-}" ]]; then
    NEW_IP="$1"
else
    NEW_IP="$(curl -fsSL --max-time 5 https://checkip.amazonaws.com | tr -d '[:space:]')"
    [[ -z "${NEW_IP}" ]] && { echo "Could not auto-detect an IP. Pass one explicitly: ./update-ssh-ip.sh x.x.x.x"; exit 1; }
    echo "Auto-detected IP of the machine running this script: ${NEW_IP}"
    echo "(If you'll SSH in from a *different* machine, Ctrl-C now and re-run with that machine's IP instead.)"
fi
NEW_CIDR="${NEW_IP}/32"

echo "==> Removing existing SSH (port 22) rules on ${SG_ID}..."
EXISTING="$(aws ec2 describe-security-groups --region "${AWS_REGION}" --group-ids "${SG_ID}" \
    --query 'SecurityGroups[0].IpPermissions[?FromPort==`22`]' --output json)"
if [[ "${EXISTING}" != "[]" ]]; then
    aws ec2 revoke-security-group-ingress --region "${AWS_REGION}" --group-id "${SG_ID}" \
        --ip-permissions "${EXISTING}" >/dev/null
fi

echo "==> Authorizing SSH from ${NEW_CIDR}..."
aws ec2 authorize-security-group-ingress --region "${AWS_REGION}" --group-id "${SG_ID}" \
    --ip-permissions "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=${NEW_CIDR},Description='SSH (updated)'}]" >/dev/null

echo "==> Done. SSH is now allowed only from ${NEW_CIDR}."
echo "    ssh -i ${SCRIPT_DIR}/${KEY_NAME}.pem rocky@${PUBLIC_IP}"
