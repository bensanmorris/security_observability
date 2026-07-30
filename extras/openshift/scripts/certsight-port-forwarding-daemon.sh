#!/usr/bin/env bash
# description: Persistent restart-loop daemon exposing CertSight metrics, the OpenShift API server, and the test console to an externally reachable host IP (installed as a systemd --user service by install-certsight-port-forwarding-service.sh)
#
# For each forwarded port this runs one `oc port-forward` (bridges the in-cluster
# Service/Pod to localhost on the CRC host) plus one `socat` (binds the host's
# external IP and relays to that localhost port) — see the "External metrics access
# via persistent port-forwarding daemon" section of ../../OPENSHIFT-DEPLOYMENT-README.md
# for why both layers are needed. Each of the six processes is supervised
# independently and restarted a fixed delay after it exits, so a single failure
# (API server restart, host suspend/resume, etc.) doesn't take down the others.
set -uo pipefail

NAMESPACE=certsight
METRICS_SERVICE=cert-expiry-monitor
TEST_SERVER_POD=cert-test-server
# The API server has no dedicated Pod/Service of its own to `oc port-forward` to;
# every cluster exposes it internally via the built-in `kubernetes` Service in the
# `default` namespace, so that's what gets bridged for the same two-layer treatment.
API_NAMESPACE=default
API_SERVICE=kubernetes
API_SERVICE_PORT=443

HOST_IP=""
METRICS_POD_PORT=9090
METRICS_HOST_PORT=9090
TEST_SERVER_PORT=8090
API_PORT=6443
RESTART_DELAY=5
CLUSTER_WAIT_INTERVAL=5

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Persistent restart-loop daemon exposing CertSight's metrics endpoint, the
OpenShift API server, and the test-console Pod on an externally reachable
address. Waits for the cluster to become reachable, then runs one
oc port-forward + one socat per forwarded port, each independently supervised
and restarted ${RESTART_DELAY}s after it exits.

Normally installed as a systemd --user service via
install-certsight-port-forwarding-service.sh rather than run directly.

Options:
  --host-ip <ip>              External IP to bind the socat listeners to
                               (default: auto-detected from the default route)
  --namespace <ns>            Namespace cert-expiry-monitor/cert-test-server run in
                               (default: $NAMESPACE)
  --metrics-pod-port <port>    Target port on the cert-expiry-monitor Service
                               (default: $METRICS_POD_PORT)
  --metrics-host-port <port>   Local/external port for metrics
                               (default: $METRICS_HOST_PORT)
  --test-server-port <port>    Local/external port for the test console
                               (default: $TEST_SERVER_PORT)
  --api-port <port>            Local/external port for the API server
                               (default: $API_PORT)
  --restart-delay <secs>       Delay before restarting a failed forwarder
                               (default: ${RESTART_DELAY}s)
  -h, --help                   Show this help and exit
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host-ip) HOST_IP="$2"; shift 2 ;;
        --host-ip=*) HOST_IP="${1#*=}"; shift ;;
        --namespace) NAMESPACE="$2"; shift 2 ;;
        --namespace=*) NAMESPACE="${1#*=}"; shift ;;
        --metrics-pod-port) METRICS_POD_PORT="$2"; shift 2 ;;
        --metrics-pod-port=*) METRICS_POD_PORT="${1#*=}"; shift ;;
        --metrics-host-port) METRICS_HOST_PORT="$2"; shift 2 ;;
        --metrics-host-port=*) METRICS_HOST_PORT="${1#*=}"; shift ;;
        --test-server-port) TEST_SERVER_PORT="$2"; shift 2 ;;
        --test-server-port=*) TEST_SERVER_PORT="${1#*=}"; shift ;;
        --api-port) API_PORT="$2"; shift 2 ;;
        --api-port=*) API_PORT="${1#*=}"; shift ;;
        --restart-delay) RESTART_DELAY="$2"; shift 2 ;;
        --restart-delay=*) RESTART_DELAY="${1#*=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

for bin in oc socat; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "Required command not found: $bin" >&2
        exit 1
    fi
done

if [[ -z "$HOST_IP" ]]; then
    HOST_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") print $(i+1)}')
    if [[ -z "$HOST_IP" ]]; then
        echo "Could not auto-detect the host's IP -- pass it explicitly: $0 --host-ip <ip>" >&2
        exit 1
    fi
    echo "Auto-detected --host-ip: $HOST_IP"
fi

# No job control here, so background jobs (and everything they spawn) stay in this
# script's own process group -- `kill 0` reaches all of them in one shot. Also
# covered independently by systemd's default KillMode=control-group when run as
# the service's ExecStart. Each `supervise` subshell below inherits this same
# trap, so it must disarm itself (`trap - TERM INT`) before broadcasting --
# otherwise every subshell's own `kill 0` re-delivers TERM to every other
# subshell that hasn't disarmed yet, which re-enters this handler and
# broadcasts again, cascading into a signal storm instead of a clean exit.
trap 'trap - TERM INT; echo "Stopping forwarders..."; kill 0; exit 0' TERM INT

wait_for_cluster() {
    echo "Waiting for the cluster to become reachable..."
    until oc whoami >/dev/null 2>&1; do
        sleep "$CLUSTER_WAIT_INTERVAL"
    done
    echo "Cluster reachable."
}

supervise() {
    local label="$1"
    shift
    while true; do
        echo "[$label] starting: $*"
        "$@"
        echo "[$label] exited (rc=$?) -- restarting in ${RESTART_DELAY}s"
        sleep "$RESTART_DELAY"
    done
}

wait_for_cluster

supervise metrics-oc-pf \
    oc port-forward -n "$NAMESPACE" "svc/$METRICS_SERVICE" "${METRICS_HOST_PORT}:${METRICS_POD_PORT}" &

supervise metrics-socat \
    socat "TCP-LISTEN:${METRICS_HOST_PORT},bind=${HOST_IP},fork,reuseaddr" "TCP:127.0.0.1:${METRICS_HOST_PORT}" &

supervise test-server-oc-pf \
    oc port-forward -n "$NAMESPACE" "pod/$TEST_SERVER_POD" "${TEST_SERVER_PORT}:${TEST_SERVER_PORT}" &

supervise test-server-socat \
    socat "TCP-LISTEN:${TEST_SERVER_PORT},bind=${HOST_IP},fork,reuseaddr" "TCP:127.0.0.1:${TEST_SERVER_PORT}" &

supervise api-oc-pf \
    oc port-forward -n "$API_NAMESPACE" "svc/$API_SERVICE" "${API_PORT}:${API_SERVICE_PORT}" &

supervise api-socat \
    socat "TCP-LISTEN:${API_PORT},bind=${HOST_IP},fork,reuseaddr" "TCP:127.0.0.1:${API_PORT}" &

wait
