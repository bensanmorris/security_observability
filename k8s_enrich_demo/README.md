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

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `TEST_CERT_OUTPUT_DIR` | `/test-certs` | Directory to write generated certs into |
| `CERT_REGEN_INTERVAL_SECONDS` | `60` | Seconds between regeneration cycles |
