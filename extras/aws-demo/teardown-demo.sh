#!/bin/bash
# Tears down everything deploy-demo.sh created: terminates the instance and
# deletes the security group. Leaves the SSH key pair (local .pem + the AWS
# key pair object) in place by default so re-running deploy-demo.sh later
# doesn't need a fresh one -- pass --delete-key to remove it too.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="${SCRIPT_DIR}/.certsight-demo-state"

DELETE_KEY=false
[[ "${1:-}" == "--delete-key" ]] && DELETE_KEY=true

if [[ ! -f "${STATE_FILE}" ]]; then
    echo "No ${STATE_FILE} found -- nothing to tear down (or it was already removed)."
    exit 0
fi

# shellcheck disable=SC1090
source "${STATE_FILE}"

echo "==> Terminating instance ${INSTANCE_ID} in ${AWS_REGION}..."
aws ec2 terminate-instances --region "${AWS_REGION}" --instance-ids "${INSTANCE_ID}" >/dev/null
aws ec2 wait instance-terminated --region "${AWS_REGION}" --instance-ids "${INSTANCE_ID}"
echo "    Terminated."

if [[ -n "${ALLOCATION_ID:-}" ]]; then
    echo "==> Releasing Elastic IP (allocation ${ALLOCATION_ID})..."
    # Termination auto-disassociates the EIP but doesn't release it -- an
    # unattached EIP keeps billing hourly until explicitly released.
    aws ec2 release-address --region "${AWS_REGION}" --allocation-id "${ALLOCATION_ID}" || true
fi

echo "==> Deleting security group ${SG_ID}..."
# Can take a few seconds after termination for the ENI to detach.
for i in $(seq 1 12); do
    if aws ec2 delete-security-group --region "${AWS_REGION}" --group-id "${SG_ID}" 2>/dev/null; then
        echo "    Deleted."
        break
    fi
    sleep 5
done

if [[ "${DELETE_KEY}" == true ]]; then
    echo "==> Deleting key pair ${KEY_NAME}..."
    aws ec2 delete-key-pair --region "${AWS_REGION}" --key-name "${KEY_NAME}" || true
    rm -f "${SCRIPT_DIR}/${KEY_NAME}.pem"
fi

rm -f "${STATE_FILE}"
echo "==> Done."
