#!/bin/bash
# Launches a SECOND, separate EC2 instance running k3s + upstream Tetragon +
# this repo's cert-analyzer Helm chart, so a user can see real Kubernetes
# pod/namespace attribution alongside the main (bare-metal) demo instance.
# It publishes into the MAIN instance's existing Kafka/Prometheus/Grafana --
# nothing new to look at, the existing dashboard's $node/$namespace filters
# already handle a second node (see project_grafana_multihost memory).
#
# Requires deploy-demo.sh to have already been run successfully in this
# directory (reads its instance/security-group details from
# .certsight-demo-state) -- run this after that instance is up, or set
# WITH_K8S_NODE=true before running deploy-demo.sh to have it call this
# automatically once the main instance is ready.
#
# k3s was chosen over CRC deliberately: CRC needs nested virtualization,
# which standard (non-metal) EC2 instance types don't expose. See
# project_k3s_pod_attribution_spike_confirmed memory for the spike that
# validated this on 2026-09-07.
#
# Usage:
#   ./deploy-k8s-node.sh
#
# State (this instance's id, security group id, key name) is appended to
# .certsight-demo-state for teardown-demo.sh to also clean this up.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="${SCRIPT_DIR}/.certsight-demo-state"

if [[ ! -f "${STATE_FILE}" ]]; then
    echo "No ${STATE_FILE} found -- run ./deploy-demo.sh first (this script adds a second"
    echo "node onto an already-running main demo instance, it doesn't stand alone)."
    exit 1
fi

# shellcheck disable=SC1090
source "${STATE_FILE}"

if [[ -n "${K8S_NODE_INSTANCE_ID:-}" ]]; then
    echo "K8S_NODE_INSTANCE_ID already present in ${STATE_FILE} -- a k8s node may already"
    echo "be running. Tear it down first (teardown-demo.sh handles both instances), or"
    echo "remove that line from the state file if it's stale."
    exit 1
fi

K8S_NODE_INSTANCE_TYPE="${K8S_NODE_INSTANCE_TYPE:-t3.large}"
# The Helm chart itself (extras/helm/cert-analyzer) is unchanged by this
# feature -- only the AWS demo scripts are -- so this can safely point at a
# real release tag instead of a WIP branch (e.g. CERTSIGHT_GIT_REF=v0.97);
# only defaults to the feature branch for convenience during development.
CERTSIGHT_GIT_REF="${CERTSIGHT_GIT_REF:-k8s-pod-attribution-demo}"
# Empty = use the chart's own default (latest-ubi9, floats with main -- fine
# for throwaway test instances). No vX.Y-ubi9 tag is ever actually published
# on GHCR (known gap), so for a real/live deployment pass the immutable
# sha-<commit>-ubi9 for the release you want instead, e.g.
# K8S_ANALYZER_IMAGE_TAG=sha-f5c492d-ubi9 for v0.97 (confirm the mapping via
# `git rev-parse vX.Y`).
K8S_ANALYZER_IMAGE_TAG="${K8S_ANALYZER_IMAGE_TAG:-}"

command -v aws >/dev/null || { echo "AWS CLI not found."; exit 1; }

echo "==> Main instance: ${INSTANCE_ID} in ${AWS_REGION}"
MAIN_PRIVATE_IP="$(aws ec2 describe-instances --region "${AWS_REGION}" --instance-ids "${INSTANCE_ID}" \
    --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)"
if [[ -z "${MAIN_PRIVATE_IP}" || "${MAIN_PRIVATE_IP}" == "None" ]]; then
    echo "Could not determine the main instance's private IP -- is it still running?"
    exit 1
fi
echo "    Private IP: ${MAIN_PRIVATE_IP}"

if [[ -z "${SSH_CIDR:-}" ]]; then
    MY_IP="$(curl -fsSL --max-time 5 https://checkip.amazonaws.com | tr -d '[:space:]')"
    SSH_CIDR="${MY_IP}/32"
fi
echo "==> SSH will be restricted to ${SSH_CIDR}"

echo "==> Finding latest Rocky Linux 9 AMI..."
AMI_ID="$(aws ec2 describe-images \
    --region "${AWS_REGION}" \
    --owners 792107900819 \
    --filters "Name=name,Values=Rocky-9-EC2-Base-9*" "Name=architecture,Values=x86_64" \
    --query 'reverse(sort_by(Images, &CreationDate))[0].ImageId' \
    --output text)"
echo "==> AMI: ${AMI_ID}"

VPC_ID="$(aws ec2 describe-vpcs --region "${AWS_REGION}" --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"

K8S_SG_NAME="certsight-demo-k8s-node-sg"
echo "==> Security group..."
K8S_SG_ID="$(aws ec2 describe-security-groups --region "${AWS_REGION}" \
    --filters "Name=group-name,Values=${K8S_SG_NAME}" "Name=vpc-id,Values=${VPC_ID}" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)"
if [[ -z "${K8S_SG_ID}" || "${K8S_SG_ID}" == "None" ]]; then
    K8S_SG_ID="$(aws ec2 create-security-group --region "${AWS_REGION}" \
        --group-name "${K8S_SG_NAME}" --description "CertSight demo k8s node (SSH restricted, test console via NodePort)" \
        --vpc-id "${VPC_ID}" --query 'GroupId' --output text)"
    aws ec2 authorize-security-group-ingress --region "${AWS_REGION}" --group-id "${K8S_SG_ID}" \
        --ip-permissions \
        "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=${SSH_CIDR},Description='SSH (deploy-time IP)'}]" \
        "IpProtocol=tcp,FromPort=30090,ToPort=30090,IpRanges=[{CidrIp=0.0.0.0/0,Description='k8s test console (NodePort)'}]" \
        >/dev/null
    echo "    Created security group ${K8S_SG_ID}"
else
    echo "    Using existing security group ${K8S_SG_ID}"
fi

echo "==> Cross-instance rules (Kafka producer -> main box, metrics scrape -> this box, Prometheus query API -> main box)..."
# Kafka: this node pushes to the main instance's broker. No-op (AWS ignores
# duplicate rule errors here via || true) if already added by a prior run.
aws ec2 authorize-security-group-ingress --region "${AWS_REGION}" --group-id "${SG_ID}" \
    --ip-permissions "IpProtocol=tcp,FromPort=9092,ToPort=9092,UserIdGroupPairs=[{GroupId=${K8S_SG_ID},Description='Kafka from k8s node'}]" \
    2>/dev/null || true
# Metrics: the main box's Prometheus pulls from this node's cert-analyzer :9090.
aws ec2 authorize-security-group-ingress --region "${AWS_REGION}" --group-id "${K8S_SG_ID}" \
    --ip-permissions "IpProtocol=tcp,FromPort=9090,ToPort=9090,UserIdGroupPairs=[{GroupId=${SG_ID},Description='Prometheus scrape from main box'}]" \
    2>/dev/null || true
# Prometheus query API: this node's test-server queries it directly for the
# fleet blast-radius/chain-explorer/FIPS-rollout panels (demo.testServer.
# prometheusUrl below) -- found missing in testing (those panels errored
# with a DNS lookup failure against the chart's unreachable in-cluster
# demo-prometheus default before this was wired up).
aws ec2 authorize-security-group-ingress --region "${AWS_REGION}" --group-id "${SG_ID}" \
    --ip-permissions "IpProtocol=tcp,FromPort=9091,ToPort=9091,UserIdGroupPairs=[{GroupId=${K8S_SG_ID},Description='Prometheus query API from k8s node'}]" \
    2>/dev/null || true

echo "==> Key pair (reusing the main instance's ${KEY_NAME})..."
if [[ ! -f "${SCRIPT_DIR}/${KEY_NAME}.pem" ]]; then
    echo "    ${SCRIPT_DIR}/${KEY_NAME}.pem not found -- can't SSH-verify this instance later,"
    echo "    but it'll still launch fine (same key pair as the main instance)."
fi

echo "==> Launching k8s node instance (${K8S_NODE_INSTANCE_TYPE})..."
USER_DATA_CONTENT="$(sed \
    -e "s/__MAIN_PRIVATE_IP__/${MAIN_PRIVATE_IP}/" \
    -e "s/__CERTSIGHT_GIT_REF__/${CERTSIGHT_GIT_REF}/" \
    -e "s/__K8S_ANALYZER_IMAGE_TAG__/${K8S_ANALYZER_IMAGE_TAG}/" \
    "${SCRIPT_DIR}/user-data-k8s-node.sh")"

K8S_NODE_INSTANCE_ID="$(aws ec2 run-instances --region "${AWS_REGION}" \
    --image-id "${AMI_ID}" \
    --instance-type "${K8S_NODE_INSTANCE_TYPE}" \
    --key-name "${KEY_NAME}" \
    --security-group-ids "${K8S_SG_ID}" \
    --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":30,"VolumeType":"gp3"}}]' \
    --user-data "${USER_DATA_CONTENT}" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=certsight-demo-k8s-node}]" \
    --metadata-options "HttpTokens=required" \
    --credit-specification "CpuCredits=standard" \
    --query 'Instances[0].InstanceId' --output text)"
echo "    Instance: ${K8S_NODE_INSTANCE_ID}"

cat >> "${STATE_FILE}" <<EOF
K8S_NODE_INSTANCE_ID=${K8S_NODE_INSTANCE_ID}
K8S_NODE_SG_ID=${K8S_SG_ID}
EOF

echo "==> Waiting for instance to enter 'running' state..."
aws ec2 wait instance-running --region "${AWS_REGION}" --instance-ids "${K8S_NODE_INSTANCE_ID}"
K8S_NODE_PRIVATE_IP="$(aws ec2 describe-instances --region "${AWS_REGION}" --instance-ids "${K8S_NODE_INSTANCE_ID}" \
    --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)"

echo "==> Allocating Elastic IP (so the k8s test console link is stable across replacements)..."
K8S_NODE_ALLOCATION_ID="$(aws ec2 allocate-address --region "${AWS_REGION}" --domain vpc \
    --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=Name,Value=certsight-demo-k8s-node}]" \
    --query 'AllocationId' --output text)"
aws ec2 associate-address --region "${AWS_REGION}" \
    --instance-id "${K8S_NODE_INSTANCE_ID}" --allocation-id "${K8S_NODE_ALLOCATION_ID}" >/dev/null
K8S_NODE_PUBLIC_IP="$(aws ec2 describe-addresses --region "${AWS_REGION}" --allocation-ids "${K8S_NODE_ALLOCATION_ID}" \
    --query 'Addresses[0].PublicIp' --output text)"
echo "    Private IP: ${K8S_NODE_PRIVATE_IP}  Elastic IP: ${K8S_NODE_PUBLIC_IP} (allocation ${K8S_NODE_ALLOCATION_ID})"

# Reuses the main instance's own hosted zone (from the sourced state file) --
# a subdomain under the same domain, not a second domain. Skips cleanly if
# the main instance itself was deployed without DNS (DOMAIN_NAME/
# HOSTED_ZONE_ID empty, e.g. a throwaway test run).
K8S_NODE_DOMAIN_NAME=""
K8S_LINK_HOST="${K8S_NODE_PUBLIC_IP}"
if [[ -n "${DOMAIN_NAME:-}" && -n "${HOSTED_ZONE_ID:-}" ]]; then
    K8S_SUBDOMAIN="${K8S_SUBDOMAIN:-k8s}"
    K8S_NODE_DOMAIN_NAME="${K8S_SUBDOMAIN}.${DOMAIN_NAME}"
    echo "==> Pointing ${K8S_NODE_DOMAIN_NAME} at ${K8S_NODE_PUBLIC_IP}..."
    CHANGE_ID="$(aws route53 change-resource-record-sets --hosted-zone-id "${HOSTED_ZONE_ID}" \
        --change-batch "{\"Changes\":[{\"Action\":\"UPSERT\",\"ResourceRecordSet\":{\"Name\":\"${K8S_NODE_DOMAIN_NAME}\",\"Type\":\"A\",\"TTL\":300,\"ResourceRecords\":[{\"Value\":\"${K8S_NODE_PUBLIC_IP}\"}]}}]}" \
        --query 'ChangeInfo.Id' --output text)"
    aws route53 wait resource-record-sets-changed --id "${CHANGE_ID}"
    echo "    ${K8S_NODE_DOMAIN_NAME} -> ${K8S_NODE_PUBLIC_IP} (DNS change in sync)"
    K8S_LINK_HOST="${K8S_NODE_DOMAIN_NAME}"
else
    echo "==> No DOMAIN_NAME/HOSTED_ZONE_ID on the main instance -- skipping DNS, using the raw IP."
fi

cat >> "${STATE_FILE}" <<EOF
K8S_NODE_PRIVATE_IP=${K8S_NODE_PRIVATE_IP}
K8S_NODE_PUBLIC_IP=${K8S_NODE_PUBLIC_IP}
K8S_NODE_ALLOCATION_ID=${K8S_NODE_ALLOCATION_ID}
K8S_NODE_DOMAIN_NAME=${K8S_NODE_DOMAIN_NAME}
EOF

echo ""
echo "============================================================"
echo " k3s + Tetragon + cert-analyzer install runs via cloud-init and"
echo " typically takes 5-10 minutes (k3s + Helm + image pulls)."
echo ""
echo " SSH (to watch progress):"
echo "   ssh -i ${SCRIPT_DIR}/${KEY_NAME}.pem rocky@${K8S_NODE_PUBLIC_IP}"
echo "   sudo tail -f /var/log/certsight-k8s-node-install.log"
echo "============================================================"
echo ""

echo "==> Wiring the main box's Prometheus to also scrape this node..."
# The main instance's SG only allows SSH from whatever IP was current when
# deploy-demo.sh ran -- on a NAT'd/rotating egress this script's own SSH
# connection a few minutes later can already be a different IP and get
# refused (confirmed happening in testing). Re-detect and authorize fresh
# rather than trust the earlier SSH_CIDR value: idempotent (duplicate-rule
# errors are expected and harmless on a re-run against the same main box).
CURRENT_IP="$(curl -fsSL --max-time 5 https://checkip.amazonaws.com | tr -d '[:space:]')"
if [[ -n "${CURRENT_IP}" ]]; then
    aws ec2 authorize-security-group-ingress --region "${AWS_REGION}" --group-id "${SG_ID}" \
        --ip-permissions "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=${CURRENT_IP}/32,Description='SSH (k8s-node wiring IP)'}]" \
        2>/dev/null || true
fi
# Surgical edit rather than re-running install-prometheus.sh (which no-ops
# once prometheus.yml already exists) -- adds this node's target and
# restarts (not reload -- the systemd unit has no ExecReload=, `systemctl
# reload` always fails with "Job type reload is not applicable", confirmed
# in testing). Matches the whole "- targets:" line and replaces it wholesale
# (not just the pristine single-target form) so this is safe to re-run even
# if the main box was already wired to a *different* k8s node's IP by an
# earlier run -- confirmed necessary in testing (a stale IP from a replaced
# node otherwise silently survives, since a narrower pattern just fails to
# match and leaves the old content untouched).
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=15 -i "${SCRIPT_DIR}/${KEY_NAME}.pem" "rocky@${PUBLIC_IP}" "
    sudo sed -i \"s|^\(\\\\s*- targets:\).*|\\\\1 ['localhost:9090', '${K8S_NODE_PRIVATE_IP}:9090']|\" /etc/prometheus/prometheus.yml
    sudo systemctl restart prometheus
    # Belt-and-suspenders local-firewall opens -- covers both the fresh-deploy
    # path (WITH_K8S_NODE=true, where install-kafka.sh already opens 9092
    # itself) and the bolt-on-to-an-existing-main-box path this script is
    # actually for, where nothing else ever opens either port. Found the
    # hard way: the security group alone wasn't enough for either 9092
    # (Kafka) or 9091 (Prometheus query API, needed for the test-server's
    # fleet blast-radius/chain-explorer/FIPS-rollout panels) -- firewalld
    # rejected both with 'No route to host' until opened explicitly.
    if command -v firewall-cmd >/dev/null 2>&1 && sudo systemctl is-active --quiet firewalld; then
        sudo firewall-cmd --permanent --add-port=9091/tcp
        sudo firewall-cmd --permanent --add-port=9092/tcp
        sudo firewall-cmd --reload
    fi
" || echo "    WARNING: could not wire Prometheus automatically -- see extras/aws-demo/README.md to do it by hand."

echo ""
echo "============================================================"
echo " k8s node: ${K8S_NODE_PUBLIC_IP}"
echo " k8s test console (once install completes): http://${K8S_LINK_HOST}:30090"
echo " Same Grafana dashboard as the main demo -- filter \$node to this node's"
echo " name, or \$namespace=certsight, to see real pod/namespace attribution."
echo "============================================================"
