# cert-analyzer Helm chart

Packages the OpenShift deployment of cert-expiry-monitor (the Tetragon-driven certificate
expiry/discovery agent) that was previously a set of manifests applied by hand
(`extras/openshift/*.yaml`) or via `extras/openshift/scripts/deploy-cert-analyzer-from-release.sh`.
See [`extras/OPENSHIFT-DEPLOYMENT-README.md`](../../OPENSHIFT-DEPLOYMENT-README.md) for the
full narrative background (SCC quirks, Kafka reachability, why each field is set the way it
is) -- this chart is a Helm-native re-expression of the same manifests, not a new design.

## Out of scope

This chart deploys the cert-analyzer product plus optional demo/test tooling. It does **not**
install:

- **Tetragon itself.** Install it first via its own upstream chart:
  `helm repo add cilium https://helm.cilium.io && helm install tetragon cilium/tetragon -n kube-system`
  (or `extras/openshift/scripts/deploy-tetragon-from-release.sh` for an air-gapped host).
- **OpenShift User Workload Monitoring enablement** -- a cluster-wide setting
  (`cluster-monitoring-config` ConfigMap), out of this chart's blast radius. Turn it on before
  `monitoring.serviceMonitor.enabled=true` will have anything to scrape it.

## Demo/test tooling

`demo.testServer.enabled` (default `false`) adds the interactive test-console Pod
(`extras/test-server/`) so you can trigger use cases (write a cert, bind/connect over TLS,
load a JKS/PKCS12 keystore) in-cluster and visually confirm cert-expiry-monitor picks them up
-- the fastest way to validate a fresh install actually works end-to-end, not just that the
pods are Running. `demo.prometheus.enabled` (default `false`) adds a throwaway Prometheus the
test-console's blast-radius/chain-explorer panels query; everything else in the test-console
works without it.

```bash
helm install cert-analyzer ./cert-analyzer -n certsight --create-namespace \
  --set kafka.bootstrapServers=<kafka-host-ip>:9092 \
  --set demo.testServer.enabled=true \
  --set demo.testServer.kafka.host=<kafka-host-ip> \
  --set demo.prometheus.enabled=true

oc port-forward -n certsight pod/cert-test-server 8090:8090
# open http://localhost:8090
```

Both are demo/test tooling, not part of the deployed product -- leave them off for anything
resembling a real pilot install.

## Install

```bash
helm install cert-analyzer ./cert-analyzer -n certsight --create-namespace \
  --set kafka.bootstrapServers=<kafka-host-ip>:9092
```

`examples/crc-demo-values.yaml` is a real, verified-working values file -- the exact
configuration currently running in the `certsight` namespace on the local CRC pilot cluster
(`api.crc.testing`), captured after adopting it under Helm and confirming every resource's
live content matches what the chart renders:

```bash
helm install cert-analyzer ./cert-analyzer -n certsight -f examples/crc-demo-values.yaml
```

Its `image.tag`/`demo.testServer.image.tag` are ephemeral local-build tags that go stale the
next time either image is rebuilt -- see the comments in that file for how to check the
current live tag before reusing it.

`kafka.bootstrapServers` must be a node-reachable `host:port` (not a ClusterIP Service) --
the DaemonSet runs with `hostNetwork: true`, same constraint as the old
`deploy-cert-analyzer-from-release.sh --kafka-host` flag. Set `kafka.enabled=false` instead if
this deployment doesn't publish to Kafka.

To use a locally built image rather than the published GHCR release:

```bash
--set image.registry=image-registry.openshift-image-registry.svc:5000 \
--set image.repository=certsight/cert-analyzer \
--set image.tag=latest
```

`demo.testServer.image` and `demo.prometheus.image` follow the same `registry`/`repository`/
`tag` shape. If every image you use is mirrored under the same registry host, set
`global.imageRegistry` once instead of `image.registry` (and the demo ones, if enabled)
separately -- see "Air-gapped install" below.

See `values.yaml` for every other setting (alert threshold, log level, scan paths, resource
limits, which TracingPolicies/monitoring resources to install, etc).

## Air-gapped install

`helm install` itself has no air-gap concerns -- this chart has no `dependencies:` block, so
there's no `helm dependency update`/chart-repo fetch involved, just a local directory once
you've copied the repo in. The only internet-dependent part is images: every default
`image`/`demo.testServer.image`/`demo.prometheus.image` in `values.yaml` points at GHCR or
quay.io, which won't be reachable. Mirror first, then install -- `helm install` only creates
objects that *reference* an image by name; the kubelet does the actual pull later when it
schedules the pod, so installing before the image is reachable just leaves pods stuck in
`ImagePullBackOff` rather than failing the install outright.

1. **Tetragon first, and it must finish before this chart's `TracingPolicy` objects can be
   created** -- they need the `cilium.io/v1alpha1` CRD already registered, or the API server
   rejects them outright.
   `extras/openshift/scripts/deploy-tetragon-from-release.sh` mirrors its images and installs
   it end-to-end from a `scp`'d chart tarball + `docker save` image tars.

2. **Mirror the cert-analyzer image.**
   `extras/openshift/scripts/deploy-cert-analyzer-from-release.sh` already does the mirroring
   half of this (load the release tar → find the internal registry route → tag → push) before
   going on to do its own `oc apply`/`oc set image` deploy. Run it through the push step, note
   the `image-registry.openshift-image-registry.svc:5000/certsight/cert-analyzer:dev-<tag>`
   it prints, then use that instead of its own deploy steps:

   ```bash
   helm install cert-analyzer ./cert-analyzer -n certsight --create-namespace \
     --set image.registry=image-registry.openshift-image-registry.svc:5000 \
     --set image.repository=certsight/cert-analyzer \
     --set image.tag=dev-<timestamp> \
     --set kafka.bootstrapServers=<kafka-host-ip>:9092
   ```

3. **Same for `cert-test-server`** if using `demo.testServer.enabled=true` --
   `deploy-test-server-from-release.sh` mirrors it the same way; point
   `demo.testServer.image.registry`/`.repository`/`.tag` at the result.

4. **Same for `demo.prometheus.enabled=true`.** On a connected machine, pull and save a
   *pinned* version (not `:latest` -- see why in the script's `--help`):
   `docker pull quay.io/prometheus/prometheus:v2.54.1 && docker save quay.io/prometheus/prometheus:v2.54.1 | gzip > prometheus-v2.54.1.tar.gz`.
   Copy the tar over, then `extras/openshift/scripts/mirror-prometheus-image.sh --image-tar
   prometheus-v2.54.1.tar.gz` mirrors it and prints the exact `--set` flags to use.

**If all three end up mirrored under the same registry host** (the common case -- the scripts
above all push to `<internal-registry>/<namespace>/<image-name>`), set `global.imageRegistry`
once instead of three separate `*.registry` overrides. It replaces the registry host on
*every* image the chart renders, so only use it when that's true for all of them -- if even
one (e.g. a `demo.prometheus` you deliberately left pointed at the real `quay.io`) should stay
on a different host, override that image's own `.registry` instead:

```bash
helm install cert-analyzer ./cert-analyzer -n certsight --create-namespace \
  --set global.imageRegistry=image-registry.openshift-image-registry.svc:5000 \
  --set image.repository=certsight/cert-analyzer \
  --set image.tag=dev-<timestamp> \
  --set demo.testServer.enabled=true \
  --set demo.testServer.image.repository=certsight/cert-test-server \
  --set demo.testServer.image.tag=dev-<timestamp> \
  --set demo.testServer.kafka.host=<kafka-host-ip> \
  --set demo.prometheus.enabled=true \
  --set demo.prometheus.image.repository=certsight/prometheus \
  --set demo.prometheus.image.tag=v2.54.1 \
  --set kafka.bootstrapServers=<kafka-host-ip>:9092
```

## External metrics access

`route.enabled` (default `true`) creates an OpenShift Route exposing `/metrics` outside the
cluster -- not for OpenShift's own monitoring (that's `monitoring.serviceMonitor`, a separate
in-cluster path via UWM), but for anything external that scrapes it directly, e.g. a
host-level Prometheus feeding a Grafana instance that isn't part of this chart. The host is
left unset so OpenShift assigns its standard `<name>-<namespace>.<router subdomain>` default
rather than hardcoding one cluster's subdomain; set `route.host` to override.

**Not sufficient on CRC.** The Route only helps if its hostname actually resolves to something
reachable from outside the cluster -- true on a real OpenShift cluster, where the router's
wildcard subdomain has a real external IP/LoadBalancer behind it. On CRC, `*.apps-crc.testing`
(and `api.crc.testing`) are configured by `crc setup` to resolve to `127.0.0.1`, same as
everything else on the VM -- so a Route's hostname is exactly as unreachable from another host
as the raw Service was. For CRC specifically (or any cluster whose router subdomain isn't
externally resolvable), use the persistent port-forwarding daemon instead -- see "External
metrics access via persistent port-forwarding daemon" in
[`OPENSHIFT-DEPLOYMENT-README.md`](../../OPENSHIFT-DEPLOYMENT-README.md#external-metrics-access-via-persistent-port-forwarding-daemon).
It also covers the API server and test-console ports, neither of which a Route can expose
anyway (Routes only proxy HTTP(S) on 80/443, not arbitrary raw TCP ports like 6443/8090).

## Upgrade

```bash
helm upgrade cert-analyzer ./cert-analyzer -n certsight --reuse-values \
  --set image.tag=<new-tag>
```

`<new-tag>` -- as of 2026-07-24 there are no `vX.Y-ubi9` tags actually published on GHCR for
either image (confirmed via `skopeo list-tags`), only `main-ubi9`/`latest-ubi9`/
`sha-<commit>-ubi9`, despite `build.yml` supposedly building one on every `vX.Y` tag push.
That's a gap in the release pipeline, not this chart -- `image.tag`/
`demo.testServer.image.tag` default to `latest-ubi9` as a stopgap (paired with
`pullPolicy: Always`, since it's a floating tag) until it's fixed.

## Uninstall

```bash
helm uninstall cert-analyzer -n certsight
```

TracingPolicy and ClusterRole/ClusterRoleBinding objects are cluster-scoped and get removed
too -- if you've installed this chart more than once in the same cluster with
`policies.*.enabled`/`rbac.podReader.enabled` split across releases, only uninstall the
release that owns them, or events/pod-enrichment will silently stop working cluster-wide.

## Verify

```bash
oc get pods -n certsight -o wide
oc get pod -n certsight -l app=cert-expiry-monitor \
  -o jsonpath='{.items[0].metadata.annotations.openshift\.io/scc}'
# expect "hostaccess"
kubectl get tracingpolicies
```

## Adopting pre-existing (non-Helm) resources

If `extras/openshift/*.yaml` was applied by hand before this chart existed, `helm install`
can take over those objects in place instead of erroring on "already exists" -- stamp each
one with Helm's ownership metadata first:

```bash
for obj in serviceaccount/cert-expiry-monitor rolebinding/cert-expiry-monitor-hostaccess-scc \
           service/cert-expiry-monitor daemonset/cert-expiry-monitor route/cert-expiry-monitor \
           servicemonitor/cert-expiry-monitor prometheusrule/certificate-expiry-alerts; do
  oc annotate $obj -n certsight meta.helm.sh/release-name=cert-analyzer \
    meta.helm.sh/release-namespace=certsight --overwrite
  oc label $obj -n certsight app.kubernetes.io/managed-by=Helm --overwrite
done
for obj in clusterrole/cert-expiry-monitor-pod-reader clusterrolebinding/cert-expiry-monitor-pod-reader \
           tracingpolicy/certificate-file-access tracingpolicy/tcp-connect-tls \
           tracingpolicy/tls-service-tracking tracingpolicy/openssl3-cert-load; do
  oc annotate $obj meta.helm.sh/release-name=cert-analyzer \
    meta.helm.sh/release-namespace=certsight --overwrite
  oc label $obj app.kubernetes.io/managed-by=Helm --overwrite
done

helm install cert-analyzer ./cert-analyzer -n certsight --set ...
```

**Verify content actually landed -- don't trust `STATUS: deployed` alone.** Confirmed against
a real adoption: if an adopted CRD object's live spec differs from what the chart renders
(e.g. a `TracingPolicy` that had drifted from the checked-in policy file), the *first*
`helm install` can silently skip patching that object's spec while still reporting success --
and because Helm records the chart's *intended* values as if they'd been applied, a follow-up
`helm upgrade` with the same values sees no diff against its own bookkeeping and also skips
it. `metadata.generation` not incrementing across the install/upgrade is the tell. The fix:
`oc apply -f` the specific rendered resource once to force real content (this also updates
Helm's own baseline, so future `helm upgrade`s reconcile normally afterward), or force a diff
by upgrading with genuinely different values first. Built-in types (Deployment, DaemonSet,
Service, RBAC) reconciled correctly on first adoption in testing -- this was only observed on
`cilium.io/v1alpha1 TracingPolicy` CRD objects with actual live/chart drift; objects whose
live content already matched the chart adopted cleanly regardless of kind.
