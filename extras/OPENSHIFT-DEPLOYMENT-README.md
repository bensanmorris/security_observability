# OpenShift Deployment Guide

## Overview

This document covers deploying CertSight (Tetragon + cert-analyzer) on OpenShift, as a
supplement to the [Kubernetes DaemonSet Deployment](DEPLOYMENT-README.md#kubernetes-daemonset-deployment)
section of the main deployment guide. OpenShift's default `restricted-v2` Security Context
Constraint (SCC) blocks everything that deployment relies on — `hostNetwork`, `hostPID`,
`hostPath`, `privileged` containers, and a fixed `runAsUser` — so the vanilla
`kubernetes/deployment.yaml` will not admit as-is. This guide documents the SCC bindings,
namespace layout, and manifest changes (`extras/openshift/`) needed to run the same stack on
OpenShift, validated end-to-end against a local CRC (OpenShift Local) cluster running
OpenShift 4.20.

All commands below assume `oc` is authenticated against the target cluster and, where noted,
that `KUBECONFIG`/`oc project` is pointed at the `certsight` namespace.

---

## Local rehearsal with CRC (OpenShift Local)

Useful for validating the whole pipeline before touching a real pilot cluster.

```bash
crc setup
# Give CRC a bigger disk than the 31GB default if you plan to do more than a single
# rehearsal — the cache + VM disk alone are ~45GB, and DiskPressure will start evicting
# pods once the VM disk fills up.
crc config set disk-size 60
crc start
eval $(crc oc-env)
oc login -u kubeadmin <cluster-address>   # credentials are printed by `crc start`
```

Verify the node before deploying anything:

```bash
oc get nodes -o wide                      # kernel >= 4.18, RHCOS ships BTF-enabled kernels
oc debug node/<node> -- chroot /host ls /sys/kernel/btf/vmlinux
```

> **Resource note**: CRC's own VM disk is separate from the host's free disk space and is
> capped at whatever `--disk-size`/`disk-size` config was set at creation time (default 31GB).
> If `oc describe node` shows `DiskPressure: True`, that's the VM's own disk, not the host's —
> `crc delete` and recreate with a larger `disk-size` rather than trying to free space on the
> host.
>
> **Cluster monitoring is disabled by default on CRC** (`enable-cluster-monitoring=false`) to
> reduce its resource footprint — there is no monitoring `ClusterOperator` and no pods in
> `openshift-monitoring` unless you explicitly enable it (`crc config set
> enable-cluster-monitoring true`, which typically also needs materially more VM memory, on
> the order of 14-16GB). The User Workload Monitoring steps below (ConfigMap,
> ServiceMonitor, PrometheusRule) are still worth applying on CRC — they're exactly what a
> real cluster needs — but don't expect a live Prometheus to consume them locally unless you've
> enabled monitoring and have the memory headroom for it. Validate via `curl`/`oc exec` against
> the analyzer's own `:9090/metrics` and `:8086/healthz`/`readyz` endpoints instead (see
> Validation below).

---

## 1. Deploy Tetragon

Same Helm chart as the vanilla Kubernetes path:

```bash
helm repo add cilium https://helm.cilium.io
helm install tetragon cilium/tetragon --version 1.7.0 -n kube-system
```

The chart's DaemonSet runs `securityContext.privileged: true`, `hostNetwork: true`, and mounts
several `hostPath` volumes (including `/sys/fs/bpf`) — this needs the `privileged` SCC bound to
its ServiceAccount:

```bash
oc adm policy add-scc-to-user privileged -z tetragon -n kube-system
```

> Some clusters' `kube-system` namespace already carries
> `pod-security.kubernetes.io/enforce: privileged` out of the box (true of the CRC bundle used
> to validate this guide), in which case the Tetragon pod admits without the explicit grant
> above. Apply it anyway — it's idempotent and makes the deployment portable to clusters where
> `kube-system` is locked down more tightly.

Verify:

```bash
oc get pods -n kube-system -l app.kubernetes.io/name=tetragon
oc logs -n kube-system -l app.kubernetes.io/name=tetragon -c tetragon --tail=20
# Look for "Listening for events..." and no SCC-related admission errors in:
oc get events -n kube-system --field-selector reason=FailedCreate
```

---

## 2. Build and import the cert-analyzer image

Build exactly as documented in the main guide (from the repository root, not `extras/`):

```bash
bash extras/generate_tetragon_protos.sh   # only if tetragon/tetragon_pb2.py doesn't exist yet
bash extras/build.sh                      # produces localhost/cert-analyzer:latest
```

OpenShift's internal image registry is the supported way to get a locally-built image into the
cluster (the cluster's CRI-O image store is not the same as the build host's podman store):

```bash
oc new-project certsight

oc patch configs.imageregistry.operator.openshift.io/cluster \
  --patch '{"spec":{"defaultRoute":true}}' --type=merge

HOST=$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}')
sudo podman login -u kubeadmin -p "$(oc whoami -t)" --tls-verify=false "$HOST"
sudo podman tag localhost/cert-analyzer:latest "$HOST/certsight/cert-analyzer:latest"
sudo podman push --tls-verify=false "$HOST/certsight/cert-analyzer:latest"
```

The DaemonSet (below) references the resulting in-cluster path:
`image-registry.openshift-image-registry.svc:5000/certsight/cert-analyzer:latest`. Avoid
`latest` in production — use a versioned tag and bump it explicitly on each rebuild.

**Fallback** if the registry route hits TLS/trust friction in your environment: build inside
the cluster instead, which populates the ImageStream directly without a local `podman push`:

```bash
oc new-build --binary --strategy=docker --name cert-analyzer -n certsight
oc start-build cert-analyzer --from-dir=extras --follow
```

---

## 3. Deploy cert-analyzer

Apply `extras/openshift/scc-hostaccess-binding.yaml` and `extras/openshift/daemonset.yaml`:

```bash
oc apply -f extras/openshift/scc-hostaccess-binding.yaml
oc apply -f extras/openshift/daemonset.yaml
```

These differ from the vanilla `kubernetes/deployment.yaml` in ways discovered while validating
against a real OpenShift cluster:

- **Dedicated `certsight` namespace** rather than `kube-system` — customer workloads shouldn't
  live in `kube-system` on OpenShift.
- **`TETRAGON_ADDR` corrected to `unix:///var/run/tetragon/tetragon.sock`.** This was actually a
  bug in `kubernetes/deployment.yaml` too (now fixed there as well) — the gRPC socket lives at
  `/var/run/tetragon/tetragon.sock` for `cilium/tetragon` 1.6+, confirmed from the chart's
  `daemonset.yaml` and `_container_tetragon.tpl`. `/var/run/cilium/tetragon` is only used for
  the JSON export log file, not the gRPC socket.
- **No fixed `runAsUser`.** The `hostaccess` SCC (bound via `scc-hostaccess-binding.yaml`)
  enforces `MustRunAsRange`, so a UID from the `certsight` namespace's allocated range
  (`oc get ns certsight -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.uid-range}'`)
  is assigned automatically. A hardcoded UID like the vanilla manifest's `1001` will not be in
  that range and gets rejected.
- **`securityContext.supplementalGroups: [0]`.** The Tetragon gRPC socket is `root:root` mode
  `0660` (`srw-rw----`) on the host. `fsGroup` doesn't apply to `hostPath` volumes, so the only
  way to read/write a root-group-owned host socket without running the container as root itself
  is to join supplemental group 0. `hostaccess`'s `supplementalGroups: RunAsAny` policy permits
  this.
- **No `seccompProfile` set.** This was the trickiest one to track down: `hostaccess` advertises
  `seccompProfiles: ["runtime/default"]` as allowed, but on the cluster used to validate this
  guide, setting `securityContext.seccompProfile: {type: RuntimeDefault}` — at either the pod or
  container level — caused **every** SCC including `hostaccess` to reject the pod (confirmed
  with `oc adm policy scc-review -z cert-expiry-monitor -f pod.yaml`, which returned no matching
  SCC only when this field was present). Omitting the field entirely admits fine and falls back
  to `hostaccess`'s own default. Re-test this specifically against the real pilot cluster in
  case it's a CRC-bundle-specific quirk rather than a general OpenShift one.

Binding `hostaccess` is expressed declaratively as a RoleBinding to the
`system:openshift:scc:hostaccess` ClusterRole (equivalent to
`oc adm policy add-scc-to-user hostaccess -z cert-expiry-monitor -n certsight`, just checked in
alongside everything else).

Verify:

```bash
oc get pods -n certsight -o wide
oc get pod -n certsight -l app=cert-expiry-monitor -o jsonpath='{.items[0].metadata.annotations.openshift\.io/scc}'
# should print "hostaccess", not a fallback like "anyuid" or "privileged"

oc logs -n certsight -l app=cert-expiry-monitor --tail=20
# expect: "Connecting to Tetragon at unix:///var/run/tetragon/tetragon.sock"
#         "Tetragon version OK — build and runtime both at vX.Y.Z"
#         "Listening for Tetragon certificate events..."
```

If admission fails, iterate against the real error rather than guessing — `oc describe pod` /
`oc get events --field-selector reason=FailedCreate` name the exact SCC fields at fault, and
`oc adm policy scc-review -z <service-account> -f <pod-or-daemonset.yaml> -n <namespace>` gives
an authoritative allowed/denied answer for a specific ServiceAccount (unlike testing via
`oc apply` as `kubeadmin`/cluster-admin, whose own broad SCC access can mask whether the
workload's actual ServiceAccount would really be admitted).

### Configuration

cert-analyzer resolves every setting through the precedence chain in `agent/config.py`:
`/etc/cert-analyzer/cert-analyzer.conf` → environment variable → hardcoded default. The
RPM/bare-metal install ships that conf file to `/etc/cert-analyzer/cert-analyzer.conf`
(`root:cert-analyzer`, mode `640`), but **the OpenShift image ships no conf file at all** —
`Containerfile` never copies one in, and `daemonset.yaml` mounts no ConfigMap at
`/etc/cert-analyzer`. At startup `load_config()` finds nothing there, logs it at `debug`, and
falls through cleanly to env vars — this is expected, not broken. In practice this means **on
OpenShift, `daemonset.yaml`'s `env:` block is the only place cert-analyzer's configuration
lives.**

Currently set there:

| Env var                          | Value                                             | Purpose                                  |
|-----------------------------------|----------------------------------------------------|-------------------------------------------|
| `TETRAGON_ADDR`                    | `unix:///var/run/tetragon/tetragon.sock`           | Tetragon gRPC socket (see fix above)      |
| `METRICS_PORT`                     | `9090`                                              | Prometheus `/metrics` listener            |
| `HEALTH_PORT`                      | `8086`                                              | `/healthz` / `/readyz` listener           |
| `ALERT_THRESHOLD_DAYS`             | `30`                                                 | Cert-expiry warning threshold             |
| `LOG_LEVEL`                        | `DEBUG`                                             | Application log verbosity                |
| `CERT_SCAN_PATHS`                  | `/host/etc/ssl,/host/etc/pki,/host/etc/kubernetes/pki` | Periodic filesystem scan roots         |
| `SCAN_INTERVAL_SECONDS`            | `3600`                                              | Periodic scan cadence                     |
| `READINESS_GRACE_PERIOD_SECONDS`   | `60`                                                | Startup grace before `/readyz` can fail   |
| `READINESS_STALENESS_SECONDS`      | `300`                                               | Max age of last-seen-event before not-ready |
| `HOST_PREFIX`                      | `/host`                                             | Prefix for the `host-root` hostPath mount |

To change a setting, edit the `env:` block in `daemonset.yaml` directly and re-apply — there's
no ConfigMap to patch separately, and no in-cluster way to drop in a `cert-analyzer.conf`
without adding one:

```bash
oc apply -f extras/openshift/daemonset.yaml
oc rollout restart daemonset/cert-expiry-monitor -n certsight
```

Any `[section] key` handled by `cfg()`/`cfg_int()`/`cfg_float()` in `agent/config.py` that
*isn't* listed above (e.g. `[cache]`/`[kafka]` options) still has an `env_var` fallback per that
function's signature — check `agent/config.py` for the exact name before assuming a setting is
unreachable on OpenShift.

---

## 4. Load Tetragon tracing policies

Identical to the vanilla Kubernetes path — `TracingPolicy` is a cluster-scoped CRD:

```bash
kubectl apply -f tetragon-policies/certificate-file-access.yaml
kubectl apply -f tetragon-policies/tcp-connect-tls.yaml
kubectl apply -f tetragon-policies/experimental/tls-service-tracking.yaml
kubectl get tracingpolicies
```

**Known gap on containerized/RHCOS nodes**: the `openssl3-cert-load`, `java-fips-nss-cert`, and
`java-non-fips-cert` experimental policies are host-uprobe policies that hook a specific
absolute host library/agent path (`/usr/lib64/libssl.so.3`, `libsoftokn3.so`, the cert-agent
native stub respectively). On a bare RHCOS node none of these paths exist by default, so the
tetragon agent logs `adding tracing policy failed: open <path>: no such file or directory` for
each and the policy simply doesn't attach — this is expected, not a misconfiguration, unless
those libraries/agents are actually present at those exact host paths (e.g. via the optional
Java agent RPM, or a workload that installs OpenSSL 3 at the host level rather than inside its
own container image). Revisit whether in-memory OpenSSL/Java cert detection is in scope for the
pilot, and if so, confirm the actual library paths on the real pilot cluster's nodes before
assuming these three policies will "just work".

---

## 5. OpenShift-native monitoring (User Workload Monitoring)

Rather than installing a separate `kube-prometheus-stack`, use OpenShift's own Prometheus
operator:

```bash
oc apply -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-monitoring-config
  namespace: openshift-monitoring
data:
  config.yaml: |
    enableUserWorkload: true
EOF

oc apply -f extras/openshift/service-monitor.yaml
oc apply -f extras/openshift/prometheus-rule.yaml
```

These are the same `ServiceMonitor`/`PrometheusRule` CRDs and alert rules as
`extras/kubernetes/service-monitor.yaml` / `prometheus-rules.yaml` — OpenShift's UWM Prometheus
operator reconciles the identical CRDs — just repointed at the `certsight` namespace, with the
`prometheus: kube-prometheus` label dropped (that's a `kube-prometheus-stack` Helm chart
selector artifact, not meaningful to OpenShift's own UWM).

Alertmanager: route through OpenShift's own platform Alertmanager rather than standing up a
separate one. Grafana is not bundled by default in OpenShift; the community Grafana Operator is
the option if dashboards are explicitly wanted — out of scope unless the pilot specifically
asks for it, since UWM's own web console `Observe → Metrics`/`Observe → Alerting` views cover
basic operational needs.

---

## Rebuilding and redeploying after a code change

Once the DaemonSet is up, iterating on `agent/`/`cert_analyzer.py` changes means getting a new
image built and actually picked up — which is less trivial than it sounds.

```bash
# 1. Rebuild (from the repository root, not extras/)
bash extras/build.sh

# 2. Push under a FRESH tag, not :latest
HOST=$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}')
TAG="dev-$(date +%s)"
sudo podman tag localhost/cert-analyzer:latest "$HOST/certsight/cert-analyzer:$TAG"
sudo podman push --tls-verify=false "$HOST/certsight/cert-analyzer:$TAG"

# 3. Point the DaemonSet at the new tag
oc set image daemonset/cert-expiry-monitor \
  analyzer="image-registry.openshift-image-registry.svc:5000/certsight/cert-analyzer:$TAG" \
  -n certsight

# 4. Confirm the new pod picked up the new digest
oc get pods -n certsight -o wide
oc get pod <new-pod> -n certsight -o jsonpath='{.status.containerStatuses[0].imageID}'
```

All four steps are automated by
[`extras/openshift/scripts/rebuild-redeploy-cert-analyzer.sh`](openshift/scripts/rebuild-redeploy-cert-analyzer.sh)
(reachable via the [`extras/openshift/openshift-utils.sh`](openshift/openshift-utils.sh) menu) —
useful to know the manual steps below for troubleshooting, but day to day the script is faster.

**Why a fresh tag, not just re-pushing `:latest`**: the DaemonSet's `imagePullPolicy:
IfNotPresent` means the node only checks whether an image with that exact tag *string* is
already present locally — it does not compare digests. Re-pushing new content under `:latest`
and deleting the pod is not enough; CRI-O still considers `cert-analyzer:latest` "present" from
the previous pull and skips re-pulling, so the DaemonSet controller happily recreates the pod
with the stale image. Evicting the node's cached copy first
(`oc debug node/<node> -- chroot /host crictl rmi <image>`) works in principle, but the
DaemonSet controller recreates the pod near-instantly after a delete, and `oc debug node`'s own
startup overhead is too slow to win that race reliably — the image is usually still "in use by a
container" by the time the `crictl rmi` call lands. A fresh tag sidesteps the whole problem: it
was never cached, so the pull is unconditionally fresh regardless of policy.

Once you're happy with a build, consider tagging and committing a real version instead of an
ad hoc `dev-<timestamp>` tag, and updating `extras/openshift/daemonset.yaml`'s image field to
match — the checked-in manifest intentionally stays on a stable tag rather than a moving one.

**Always use `sudo podman` for every step above, not plain `podman`** — `extras/build.sh` builds
via `sudo podman build`, which writes into *root's* podman image storage, entirely separate from
your own user's storage. Tagging or pushing with plain `podman` reads from your user's storage
instead, which may contain an old, unrelated `cert-analyzer:latest` from some earlier manual
build. The two storages don't share content, and podman gives no warning that it just silently
tagged/pushed a different image than the one `build.sh` produced — the push and deploy both
"succeed" and everything looks fine until you notice the running pod is inexplicably missing a
fix that's definitely in the source. Confirm which image you're actually about to push with
`sudo podman images localhost/cert-analyzer:latest` immediately before tagging it.

---

## Validation

Mirrors the flow in [`README-QUICKSTART.md`](README-QUICKSTART.md), adapted for `oc`:

```bash
# Generate a short-expiry test certificate directly on a node (via a debug pod) and access it
# to trigger real-time eBPF detection:
oc debug node/<node> -- chroot /host bash -c '
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /tmp/test.key -out /etc/pki/tls/certs/pilot-test.crt \
    -days 5 -subj "/CN=pilot-test.local"
  cat /etc/pki/tls/certs/pilot-test.crt
'

# Confirm detection in the analyzer logs (look for a CRITICAL line — 5 days is under the
# 7-day critical threshold):
oc logs -n certsight -l app=cert-expiry-monitor --tail=50 | grep pilot-test

# Confirm the metric and its full k8s enrichment:
oc exec -n certsight <pod> -- curl -s http://localhost:9090/metrics | grep pilot-test

# Confirm health/readiness:
oc exec -n certsight <pod> -- curl -s http://localhost:8086/healthz
oc exec -n certsight <pod> -- curl -s http://localhost:8086/readyz
```

A 5-day test certificate should produce `tls_certificate_expiry_days` just under `5.0` and
`tls_certificate_expiring_soon{threshold_days="7"} 1.0` — the exact condition
`CertificateExpiringCritical`'s expression (`tls_certificate_expiry_days < 7 and
tls_certificate_expiry_days > 0`) checks for. Where a live UWM Prometheus is available, confirm
the alert actually fires (`for: 5m`) via `Observe → Alerting` in the console rather than just
checking the raw metric value.

For a longer-running soak — repeated large-bundle background-parsing bursts and re-access
cardinality-cap checks over hours instead of a single burst — see
[`probe_tests/openshift-soak/`](../probe_tests/openshift-soak/).

To bring the whole demo (CRC, Tetragon, cert-analyzer, tracing policies, soak Job) back up after
a host reboot without re-running every step above by hand, use the menu-driven
[`extras/openshift/openshift-utils.sh`](openshift/openshift-utils.sh) — it currently offers
"start the soak demo from a reboot" and is the home for future OpenShift utility scripts.
