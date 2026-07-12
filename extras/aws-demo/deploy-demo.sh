#!/bin/bash
# Launches a Rocky Linux 9 t3.medium EC2 instance and bootstraps it (via
# user-data.sh) into a full CertSight demo: Tetragon + cert-analyzer + Java
# cert-agent + Kafka + Prometheus + Grafana dashboard + the test console.
#
# Requires: AWS CLI v2 configured with credentials that can create EC2/VPC
# resources (ec2:RunInstances, ec2:CreateSecurityGroup, ec2:CreateKeyPair,
# ec2:Describe*, ec2:AuthorizeSecurityGroupIngress).
#
# The dashboard (Grafana, port 3000) and test console (port 8090) are opened
# to the *entire internet*, unauthenticated, by design -- this is a demo box,
# not a production deployment. See extras/aws-demo/README.md before running.
#
# Usage:
#   ./deploy-demo.sh
#   AWS_REGION=eu-west-1 ./deploy-demo.sh
#
# State (instance id, security group id, key name, region) is written to
# .certsight-demo-state next to this script for teardown-demo.sh to consume.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="${SCRIPT_DIR}/.certsight-demo-state"

AWS_REGION="${AWS_REGION:-us-east-1}"
INSTANCE_TYPE="${INSTANCE_TYPE:-t3.medium}"
KEY_NAME="${KEY_NAME:-certsight-demo}"
SG_NAME="${SG_NAME:-certsight-demo-sg}"
VOLUME_SIZE_GB="${VOLUME_SIZE_GB:-20}"
CERTSIGHT_VERSION="${CERTSIGHT_VERSION:-v0.73}"
TETRAGON_VERSION="${TETRAGON_VERSION:-1.7.0}"
# CIDR allowed to SSH in -- defaults to your current public IP. The dashboard
# (3000) and test console (8090) are intentionally opened to 0.0.0.0/0
# separately, per the access-control choice this script assumes was made
# deliberately for a public demo.
SSH_CIDR="${SSH_CIDR:-}"

if [[ -f "${STATE_FILE}" ]]; then
    echo "State file ${STATE_FILE} already exists -- a demo instance may already be running."
    echo "Run ./teardown-demo.sh first, or remove ${STATE_FILE} if it's stale."
    exit 1
fi

command -v aws >/dev/null || { echo "AWS CLI not found. Install it: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"; exit 1; }
aws sts get-caller-identity --region "${AWS_REGION}" >/dev/null || { echo "AWS credentials not configured/valid for region ${AWS_REGION}."; exit 1; }

echo "==> Region: ${AWS_REGION}  Instance type: ${INSTANCE_TYPE}  CertSight: ${CERTSIGHT_VERSION}"

if [[ -z "${SSH_CIDR}" ]]; then
    MY_IP="$(curl -fsSL --max-time 5 https://checkip.amazonaws.com || true)"
    MY_IP="$(echo "${MY_IP}" | tr -d '[:space:]')"
    if [[ -z "${MY_IP}" ]]; then
        echo "Could not auto-detect your public IP for the SSH rule. Set SSH_CIDR=x.x.x.x/32 and re-run."
        exit 1
    fi
    SSH_CIDR="${MY_IP}/32"
    echo "==> No SSH_CIDR given -- auto-detected the IP of THIS machine (${SSH_CIDR})."
    echo "    If you'll SSH in from a *different* machine (e.g. this script ran in an agent"
    echo "    sandbox but you'll connect from your own laptop), that SSH rule will be wrong."
    echo "    Fix it any time with: ./update-ssh-ip.sh [ip-to-allow]"
fi
echo "==> SSH will be restricted to ${SSH_CIDR}"

echo "==> Finding latest Rocky Linux 9 AMI..."
AMI_ID="$(aws ec2 describe-images \
    --region "${AWS_REGION}" \
    --owners 792107900819 \
    --filters "Name=name,Values=Rocky-9-EC2-Base-9*" "Name=architecture,Values=x86_64" \
    --query 'reverse(sort_by(Images, &CreationDate))[0].ImageId' \
    --output text)"
if [[ -z "${AMI_ID}" || "${AMI_ID}" == "None" ]]; then
    echo "Could not find a Rocky Linux 9 AMI in ${AWS_REGION} owned by 792107900819."
    echo "Check https://rockylinux.org/cloud-images/ and set AMI_ID manually if needed."
    exit 1
fi
echo "==> AMI: ${AMI_ID}"

VPC_ID="$(aws ec2 describe-vpcs --region "${AWS_REGION}" --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
if [[ -z "${VPC_ID}" || "${VPC_ID}" == "None" ]]; then
    echo "No default VPC found in ${AWS_REGION}. This script assumes one exists; pass a VPC/subnet manually if not."
    exit 1
fi

echo "==> Key pair..."
if aws ec2 describe-key-pairs --region "${AWS_REGION}" --key-names "${KEY_NAME}" >/dev/null 2>&1; then
    echo "    Using existing key pair '${KEY_NAME}' (make sure you still have its .pem)."
else
    aws ec2 create-key-pair --region "${AWS_REGION}" --key-name "${KEY_NAME}" \
        --query 'KeyMaterial' --output text > "${SCRIPT_DIR}/${KEY_NAME}.pem"
    chmod 400 "${SCRIPT_DIR}/${KEY_NAME}.pem"
    echo "    Created ${SCRIPT_DIR}/${KEY_NAME}.pem"
fi

echo "==> Security group..."
SG_ID="$(aws ec2 describe-security-groups --region "${AWS_REGION}" \
    --filters "Name=group-name,Values=${SG_NAME}" "Name=vpc-id,Values=${VPC_ID}" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)"
if [[ -z "${SG_ID}" || "${SG_ID}" == "None" ]]; then
    SG_ID="$(aws ec2 create-security-group --region "${AWS_REGION}" \
        --group-name "${SG_NAME}" --description "CertSight demo (SSH restricted, dashboard/test-console public)" \
        --vpc-id "${VPC_ID}" --query 'GroupId' --output text)"
    aws ec2 authorize-security-group-ingress --region "${AWS_REGION}" --group-id "${SG_ID}" \
        --ip-permissions \
        "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=${SSH_CIDR},Description='SSH (deploy-time IP)'}]" \
        "IpProtocol=tcp,FromPort=3000,ToPort=3000,IpRanges=[{CidrIp=0.0.0.0/0,Description='Grafana dashboard'}]" \
        "IpProtocol=tcp,FromPort=8090,ToPort=8090,IpRanges=[{CidrIp=0.0.0.0/0,Description='CertSight test console'}]" \
        >/dev/null
    echo "    Created security group ${SG_ID}"
else
    echo "    Using existing security group ${SG_ID}"
fi

echo "==> Launching instance..."
USER_DATA_FILE="${SCRIPT_DIR}/user-data.sh"
INSTANCE_ID="$(aws ec2 run-instances --region "${AWS_REGION}" \
    --image-id "${AMI_ID}" \
    --instance-type "${INSTANCE_TYPE}" \
    --key-name "${KEY_NAME}" \
    --security-group-ids "${SG_ID}" \
    --block-device-mappings "[{\"DeviceName\":\"/dev/sda1\",\"Ebs\":{\"VolumeSize\":${VOLUME_SIZE_GB},\"VolumeType\":\"gp3\"}}]" \
    --user-data "file://${USER_DATA_FILE}" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=certsight-demo}]" \
    --metadata-options "HttpTokens=required" \
    --query 'Instances[0].InstanceId' --output text)"
echo "    Instance: ${INSTANCE_ID}"

cat > "${STATE_FILE}" <<EOF
AWS_REGION=${AWS_REGION}
INSTANCE_ID=${INSTANCE_ID}
SG_ID=${SG_ID}
SG_NAME=${SG_NAME}
KEY_NAME=${KEY_NAME}
EOF

echo "==> Waiting for instance to enter 'running' state..."
aws ec2 wait instance-running --region "${AWS_REGION}" --instance-ids "${INSTANCE_ID}"
PUBLIC_IP="$(aws ec2 describe-instances --region "${AWS_REGION}" --instance-ids "${INSTANCE_ID}" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
echo "PUBLIC_IP=${PUBLIC_IP}" >> "${STATE_FILE}"

echo ""
echo "============================================================"
echo " Instance is up: ${PUBLIC_IP}"
echo ""
echo " The install (Tetragon, cert-analyzer, Kafka, Prometheus,"
echo " Grafana, test console) runs via cloud-init and typically"
echo " takes 5-8 minutes. This script will now poll until the"
echo " dashboard and test console respond."
echo ""
echo " SSH (to watch progress):"
echo "   ssh -i ${SCRIPT_DIR}/${KEY_NAME}.pem rocky@${PUBLIC_IP}"
echo "   sudo tail -f /var/log/certsight-demo-install.log"
echo "   (SSH times out? Wrong IP allow-listed -- run ./update-ssh-ip.sh)"
echo "============================================================"
echo ""

GRAFANA_UP=false
echo -n "Waiting for Grafana"
for i in $(seq 1 60); do
    if curl -fsS --max-time 3 "http://${PUBLIC_IP}:3000/api/health" >/dev/null 2>&1; then
        GRAFANA_UP=true
        break
    fi
    echo -n "."
    sleep 10
done
echo ""

CONSOLE_UP=false
echo -n "Waiting for test console"
for i in $(seq 1 60); do
    if curl -fsS --max-time 3 "http://${PUBLIC_IP}:8090/" >/dev/null 2>&1; then
        CONSOLE_UP=true
        break
    fi
    echo -n "."
    sleep 10
done
echo ""

echo "============================================================"
if [[ "${GRAFANA_UP}" == true && "${CONSOLE_UP}" == true ]]; then
    echo " CertSight demo ready"
else
    echo " Timed out waiting for one or both services -- install may still"
    echo " be in progress, or a step failed. Check the log over SSH:"
    echo "   ssh -i ${SCRIPT_DIR}/${KEY_NAME}.pem rocky@${PUBLIC_IP}"
    echo "   sudo tail -100 /var/log/certsight-demo-install.log"
fi
echo ""
echo " Dashboard:     http://${PUBLIC_IP}:3000/d/certsight-v1  (up: ${GRAFANA_UP})"
echo " Test console:  http://${PUBLIC_IP}:8090                (up: ${CONSOLE_UP})"
echo ""
echo " Both are open to the internet with no authentication."
echo " Tear down when done:  ./teardown-demo.sh"
echo "============================================================"
