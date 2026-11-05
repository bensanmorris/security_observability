#!/usr/bin/env bash
# enable-k8s-on-demand.sh -- Run the demo's k8s node only when someone asks for
# it, instead of around the clock. A Start panel on the main test console boots
# the node, the node powers itself off after one session, and a daily limit
# bounds what the public button can spend. See k8s-on-demand/ and the README.
#
# Run after deploy-k8s-node.sh, with the node running. Safe to re-run, and works
# on an already-live demo. Node sessions end by boot time, so a node that has
# been up longer than one session powers off as soon as this finishes.
#
# Usage:
#   ./enable-k8s-on-demand.sh
#   K8S_SESSION_MINUTES=90 K8S_STARTS_PER_DAY=2 ./enable-k8s-on-demand.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="${SCRIPT_DIR}/.certsight-demo-state"
SOURCE_DIR="${SCRIPT_DIR}/k8s-on-demand"

if [[ ! -f "${STATE_FILE}" ]]; then
    echo "No ${STATE_FILE} found -- run deploy-demo.sh first."
    exit 1
fi
# shellcheck disable=SC1090
source "${STATE_FILE}"
if [[ -z "${K8S_NODE_INSTANCE_ID:-}" ]]; then
    echo "No k8s node in ${STATE_FILE} -- run deploy-k8s-node.sh first."
    exit 1
fi

SESSION_MINUTES="${K8S_SESSION_MINUTES:-60}"
STARTS_PER_DAY="${K8S_STARTS_PER_DAY:-4}"
ROLE_NAME="${K8S_ON_DEMAND_ROLE:-certsight-demo-k8s-on-demand}"
KEY="${SCRIPT_DIR}/${KEY_NAME}.pem"
CONSOLE_HOST="${K8S_NODE_DOMAIN_NAME:-${K8S_NODE_PUBLIC_IP}}"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=6 -o BatchMode=yes -i "${KEY}")

NODE_STATE="$(aws ec2 describe-instances --region "${AWS_REGION}" --instance-ids "${K8S_NODE_INSTANCE_ID}" \
    --query 'Reservations[0].Instances[0].State.Name' --output text)"
if [[ "${NODE_STATE}" != "running" ]]; then
    echo "The k8s node is ${NODE_STATE}. Start it first, then re-run this."
    exit 1
fi

# A carrier-NAT egress can change between connections, so one failed SSH often
# just means a different source IP. Re-point the rule and try again.
retry_ssh() {
    local attempt
    for attempt in 1 2 3 4 5 6 7 8; do
        "$@" && return 0
        [[ $(( attempt % 3 )) -eq 0 ]] && "${SCRIPT_DIR}/update-ssh-ip.sh" >/dev/null 2>&1 || true
        sleep 2
    done
    return 1
}

echo "==> IAM role ${ROLE_NAME} (start this one node, read instance state)..."
if ! aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; then
    aws iam create-role --role-name "${ROLE_NAME}" \
        --description "CertSight demo: lets the main box start the k8s node" \
        --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
fi
aws iam put-role-policy --role-name "${ROLE_NAME}" --policy-name start-k8s-node --policy-document "{
  \"Version\": \"2012-10-17\",
  \"Statement\": [
    {\"Effect\": \"Allow\", \"Action\": \"ec2:StartInstances\",
     \"Resource\": \"arn:aws:ec2:${AWS_REGION}:${ACCOUNT_ID}:instance/${K8S_NODE_INSTANCE_ID}\"},
    {\"Effect\": \"Allow\", \"Action\": \"ec2:DescribeInstances\", \"Resource\": \"*\"}
  ]
}"
if ! aws iam get-instance-profile --instance-profile-name "${ROLE_NAME}" >/dev/null 2>&1; then
    aws iam create-instance-profile --instance-profile-name "${ROLE_NAME}" >/dev/null
    aws iam add-role-to-instance-profile --instance-profile-name "${ROLE_NAME}" --role-name "${ROLE_NAME}"
fi

ASSOCIATED="$(aws ec2 describe-iam-instance-profile-associations --region "${AWS_REGION}" \
    --filters "Name=instance-id,Values=${INSTANCE_ID}" "Name=state,Values=associated,associating" \
    --query 'IamInstanceProfileAssociations[0].IamInstanceProfile.Arn' --output text)"
if [[ "${ASSOCIATED}" == "None" ]]; then
    # A new instance profile takes a few seconds to become visible to EC2.
    for attempt in $(seq 1 12); do
        aws ec2 associate-iam-instance-profile --region "${AWS_REGION}" --instance-id "${INSTANCE_ID}" \
            --iam-instance-profile "Name=${ROLE_NAME}" >/dev/null 2>&1 && break
        [[ "${attempt}" -eq 12 ]] && { echo "Could not attach ${ROLE_NAME} to ${INSTANCE_ID}." >&2; exit 1; }
        sleep 5
    done
elif [[ "${ASSOCIATED}" != */"${ROLE_NAME}" ]]; then
    echo "${INSTANCE_ID} already has instance profile ${ASSOCIATED}; not replacing it." >&2
    exit 1
fi
grep -q '^K8S_ON_DEMAND_ROLE=' "${STATE_FILE}" || echo "K8S_ON_DEMAND_ROLE=${ROLE_NAME}" >> "${STATE_FILE}"

echo "==> Control service and console panel on the main box..."
"${SCRIPT_DIR}/update-ssh-ip.sh" >/dev/null
BUNDLE="$(mktemp -d)"
cleanup_bundle() { rm -rf "${BUNDLE}"; }
trap cleanup_bundle EXIT
cat > "${BUNDLE}/control.conf" <<EOF
AWS_REGION=${AWS_REGION}
K8S_NODE_INSTANCE_ID=${K8S_NODE_INSTANCE_ID}
K8S_NODE_PRIVATE_IP=${K8S_NODE_PRIVATE_IP}
K8S_PUBLIC_CONSOLE_URL=http://${CONSOLE_HOST}:30090
SESSION_MINUTES=${SESSION_MINUTES}
STARTS_PER_DAY=${STARTS_PER_DAY}
EOF
retry_ssh scp "${SSH_OPTS[@]}" -q "${BUNDLE}/control.conf" "${SOURCE_DIR}/k8s_demo_control.py" \
    "${SOURCE_DIR}/panel.js" "${SOURCE_DIR}/k8s-demo-control.service" "${SOURCE_DIR}/nginx-zones.conf" \
    "${SOURCE_DIR}/nginx-locations.inc" "rocky@${PUBLIC_IP}:/tmp/"

retry_ssh ssh "${SSH_OPTS[@]}" "rocky@${PUBLIC_IP}" 'bash -s' <<'REMOTE'
set -euo pipefail
cd /tmp
sudo install -d -m 0755 /usr/local/lib/k8s-demo-control /etc/k8s-demo-control
sudo install -m 0644 -Z k8s_demo_control.py panel.js /usr/local/lib/k8s-demo-control/
sudo install -m 0644 -Z control.conf /etc/k8s-demo-control/control.conf
sudo install -m 0644 -Z k8s-demo-control.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable k8s-demo-control >/dev/null 2>&1
sudo systemctl restart k8s-demo-control

sudo install -m 0644 -Z nginx-zones.conf /etc/nginx/conf.d/00-k8s-demo-zones.conf
sudo install -m 0644 -Z nginx-locations.inc /etc/nginx/k8s-demo-locations.inc
BACKUP="$(sudo mktemp -d /root/nginx-before-k8s-demo.XXXXXX)"
for conf in certsight-test-console.conf certsight-fleet-manager.conf; do
    path="/etc/nginx/conf.d/${conf}"
    sudo test -f "${path}" || continue
    sudo cp -p "${path}" "${BACKUP}/"
    sudo grep -q 'k8s-demo-locations.inc' "${path}" ||
        sudo sed -i '0,/server_name _;/s||server_name _;\n    include /etc/nginx/k8s-demo-locations.inc;|' "${path}"
done
if ! sudo nginx -t 2>/dev/null; then
    sudo sh -c "cp -p ${BACKUP}/*.conf /etc/nginx/conf.d/"
    sudo nginx -t
    echo "nginx rejected the new config; restored the previous one." >&2
    exit 1
fi
sudo systemctl reload nginx
rm -f control.conf k8s_demo_control.py panel.js k8s-demo-control.service nginx-zones.conf nginx-locations.inc
REMOTE

echo "==> Auto-stop timer on the k8s node (${SESSION_MINUTES} minutes after each boot)..."
# The node has no SSH rule of its own; open one from the main box just for this.
RULE_ID="$(aws ec2 authorize-security-group-ingress --region "${AWS_REGION}" --group-id "${K8S_NODE_SG_ID}" \
    --ip-permissions "IpProtocol=tcp,FromPort=22,ToPort=22,UserIdGroupPairs=[{GroupId=${SG_ID},Description='TEMP enable-k8s-on-demand'}]" \
    --query 'SecurityGroupRules[0].SecurityGroupRuleId' --output text)"
cleanup_all() {
    aws ec2 revoke-security-group-ingress --region "${AWS_REGION}" --group-id "${K8S_NODE_SG_ID}" \
        --security-group-rule-ids "${RULE_ID}" >/dev/null || \
        echo "WARNING: could not remove temporary SSH rule ${RULE_ID} from ${K8S_NODE_SG_ID}." >&2
    cleanup_bundle
}
trap cleanup_all EXIT
JUMP=(-o "ProxyCommand=ssh ${SSH_OPTS[*]} -W %h:%p rocky@${PUBLIC_IP}")
sed "s/^OnBootSec=.*/OnBootSec=${SESSION_MINUTES}min/" "${SOURCE_DIR}/k8s-demo-autostop.timer" > "${BUNDLE}/k8s-demo-autostop.timer"
retry_ssh scp "${SSH_OPTS[@]}" "${JUMP[@]}" -q "${BUNDLE}/k8s-demo-autostop.timer" \
    "${SOURCE_DIR}/k8s-demo-autostop.service" "rocky@${K8S_NODE_PRIVATE_IP}:/tmp/"
retry_ssh ssh "${SSH_OPTS[@]}" "${JUMP[@]}" "rocky@${K8S_NODE_PRIVATE_IP}" \
    'sudo install -m 0644 -Z /tmp/k8s-demo-autostop.timer /tmp/k8s-demo-autostop.service /etc/systemd/system/ &&
     rm -f /tmp/k8s-demo-autostop.timer /tmp/k8s-demo-autostop.service &&
     sudo systemctl daemon-reload && sudo systemctl enable k8s-demo-autostop.timer 2>/dev/null'
# Deferred a few seconds because this can power the node off at once, which
# would otherwise look like a failed SSH session.
retry_ssh ssh "${SSH_OPTS[@]}" "${JUMP[@]}" "rocky@${K8S_NODE_PRIVATE_IP}" \
    'sudo systemd-run --quiet --on-active=5 systemctl restart k8s-demo-autostop.timer'

echo ""
echo "Done. The Start panel is on http://${DOMAIN_NAME:-${PUBLIC_IP}}:8090"
echo "Sessions: ${SESSION_MINUTES} minutes, ${STARTS_PER_DAY} starts per UTC day."
