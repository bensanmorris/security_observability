# k8s_enrich_demo — test cert generator

Periodically generates PEM, JKS and PKCS12 test certificates (expired, expiring-soon,
and valid) so that `cert_analyzer.py` has real material to detect and report on.

Certificates are regenerated every `CERT_REGEN_INTERVAL_SECONDS` (default: 60 s).

## Build the image

```bash
podman build -t cert-test-generator:latest k8s_enrich_demo/
# or
docker build -t cert-test-generator:latest k8s_enrich_demo/
```

Or pull the pre-built image from GHCR:

```bash
podman pull ghcr.io/bensanmorris/cert-test-generator:latest
```

---

## Run under kind (RHEL9)

### 1. Load the image into the cluster

```bash
# If you built locally with docker:
kind load docker-image cert-test-generator:latest

# If you pulled from GHCR:
kind load docker-image ghcr.io/bensanmorris/cert-test-generator:latest
```

### 2. Deploy

```bash
kubectl apply -f k8s_enrich_demo/job.yaml
kubectl -n kube-system rollout status deployment/cert-test-generator
kubectl -n kube-system logs -f deployment/cert-test-generator
```

Certs are written to `/tmp/cert-analyzer-test/` on the kind node every 60 s.

### 3. Wire up cert-analyzer

Add `/host/tmp/cert-analyzer-test` to the `CERT_SCAN_PATHS` env var in
`kubernetes/deployment.yaml` and re-apply:

```bash
kubectl apply -f kubernetes/deployment.yaml
```

### 4. Tear down

```bash
kubectl delete -f k8s_enrich_demo/job.yaml
```

---

## Run under podman (RHEL9)

Mount a directory that `cert_analyzer.py` already monitors (e.g. `/etc/pki/tls/certs`),
or any custom path — then add that path to the analyzer's `CERT_SCAN_PATHS`.

```bash
# Write certs directly into a monitored path (requires the dir to be writable):
podman run -d \
  --name cert-test-generator \
  -v /etc/pki/tls/certs:/test-certs:Z \
  -e CERT_REGEN_INTERVAL_SECONDS=60 \
  cert-test-generator:latest

# Or write to a scratch dir first, then point the analyzer at it:
mkdir -p /tmp/cert-analyzer-test
podman run -d \
  --name cert-test-generator \
  -v /tmp/cert-analyzer-test:/test-certs:Z \
  -e CERT_REGEN_INTERVAL_SECONDS=60 \
  cert-test-generator:latest
```

> **Note:** The `:Z` label is required on RHEL9 so SELinux allows the container to
> write to the host path.

Check output:

```bash
podman logs -f cert-test-generator
ls /tmp/cert-analyzer-test/
```

Stop:

```bash
podman rm -f cert-test-generator
```

---

## Kubernetes context enrichment

`cert_analyzer.py` annotates every detected certificate with workload context
(pod name, namespace, workload kind/name, container name and image). Getting
that enrichment in kind on RHEL9 requires the full Tetragon stack to be in
place. Here is how it works and what you need.

### How enrichment works

Detection happens via two independent paths:

**1. Tetragon event path (full enrichment)**
Tetragon hooks the `fd_install` kernel function, which fires on every file
descriptor install — both reads *and* writes. When this generator opens a
`.crt`, `.jks`, or `.p12` file to write it, Tetragon emits a `process_kprobe`
event carrying the pod's name, namespace, workload kind/name, and labels.
`cert_analyzer.py` reads those fields directly from the event proto, then
makes a secondary call to the Kubernetes API to add `container_name` and
`container_image`. The result is a fully-enriched metric with all k8s labels
populated.

**2. Periodic scan path (no enrichment)**
cert-analyzer independently scans `CERT_SCAN_PATHS` on a timer. It will find
and parse the generated certs, but because there is no Tetragon event there is
no pod context — the workload labels in the Prometheus metrics will be empty.

### Prerequisites for full enrichment in kind

| Requirement | Notes |
|---|---|
| RHEL9 kernel ≥ 5.14 with BTF | Satisfied out of the box; verify with `ls /sys/kernel/btf/vmlinux` |
| SELinux permissive (test only) | `sudo setenforce 0` — eBPF operations inside containers are blocked by enforcing mode without a custom policy |
| kind nodes with eBPF access | kind node containers need `/sys/kernel/debug` mounted and privileged mode so Tetragon can load eBPF programs (see kind config below) |
| Tetragon DaemonSet deployed | Install via the Tetragon Helm chart with `privileged: true`; see the [Tetragon kind quickstart](https://tetragon.io/docs/getting-started/install-k8s/) |
| TracingPolicy applied | `kubectl apply -f tetragon-policies/certificate-file-access.yaml` |
| cert-analyzer DaemonSet deployed | `kubernetes/deployment.yaml` with `CERT_SCAN_PATHS` including `/host/tmp/cert-analyzer-test` |

### kind cluster configuration for eBPF

Create a kind cluster config that exposes the kernel debug filesystem to node
containers:

```yaml
# kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: /sys/kernel/debug
    containerPath: /sys/kernel/debug
```

```bash
kind create cluster --config kind-config.yaml
```

### Full setup sequence

```bash
# 1. Relax SELinux for testing
sudo setenforce 0

# 2. Create the cluster with eBPF access
kind create cluster --config kind-config.yaml

# 3. Install Tetragon
helm repo add cilium https://helm.cilium.io
helm install tetragon cilium/tetragon -n kube-system \
  --set tetragon.securityContext.privileged=true

# 4. Wait for Tetragon to be ready, then load the cert tracing policy
kubectl -n kube-system rollout status ds/tetragon
kubectl apply -f tetragon-policies/certificate-file-access.yaml

# 5. Load the cert-test-generator image and deploy it
kind load docker-image cert-test-generator:latest
kubectl apply -f k8s_enrich_demo/job.yaml

# 6. Deploy cert-analyzer with the test cert path included in its scan paths
# Edit kubernetes/deployment.yaml: add /host/tmp/cert-analyzer-test to CERT_SCAN_PATHS
kubectl apply -f kubernetes/deployment.yaml
```

### Path translation note

Inside the cert-test-generator container, certs live at `/test-certs/expired.crt`.
Tetragon reports the container-namespace path, not the `hostPath`, so
cert-analyzer may not be able to open that path via its `/host` bind mount.
The periodic scanner is not affected — it reads `/host/tmp/cert-analyzer-test`
directly. For Tetragon-driven detection with pod context, the most reliable
approach is to deploy a separate pod that periodically `cat`s the generated
cert files; those read events carry the reader pod's full workload identity.

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `TEST_CERT_OUTPUT_DIR` | `/test-certs` | Directory to write generated certs into |
| `CERT_REGEN_INTERVAL_SECONDS` | `60` | Seconds between regeneration cycles |
