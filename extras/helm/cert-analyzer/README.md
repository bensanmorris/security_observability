# cert-analyzer Helm chart

Packages the OpenShift deployment of cert-expiry-monitor (the Tetragon-driven certificate
expiry/discovery agent) that was previously a set of manifests applied by hand
(`extras/openshift/*.yaml`) or via `extras/openshift/scripts/deploy-cert-analyzer-from-release.sh`.
See [`extras/OPENSHIFT-DEPLOYMENT-README.md`](../../OPENSHIFT-DEPLOYMENT-README.md) for the
full narrative background (SCC quirks, Kafka reachability, why each field is set the way it
is) -- this chart is a Helm-native re-expression of the same manifests, not a new design.

## Out of scope

This chart deploys the cert-analyzer product only. It does **not** install:

- **Tetragon itself.** Install it first via its own upstream chart:
  `helm repo add cilium https://helm.cilium.io && helm install tetragon cilium/tetragon -n kube-system`
  (or `extras/openshift/scripts/deploy-tetragon-from-release.sh` for an air-gapped host).
- **Demo/test tooling** (`extras/openshift/test-server-pod.yaml`, `demo-prometheus.yaml`) --
  those are for driving/demoing the product, not part of it. Apply them separately if needed.
- **OpenShift User Workload Monitoring enablement** -- a cluster-wide setting
  (`cluster-monitoring-config` ConfigMap), out of this chart's blast radius. Turn it on before
  `monitoring.serviceMonitor.enabled=true` will have anything to scrape it.

## Install

```bash
helm install cert-analyzer ./cert-analyzer -n certsight --create-namespace \
  --set kafka.bootstrapServers=<kafka-host-ip>:9092
```

`kafka.bootstrapServers` must be a node-reachable `host:port` (not a ClusterIP Service) --
the DaemonSet runs with `hostNetwork: true`, same constraint as the old
`deploy-cert-analyzer-from-release.sh --kafka-host` flag. Set `kafka.enabled=false` instead if
this deployment doesn't publish to Kafka.

To use a locally built image rather than the published GHCR release:

```bash
--set image.repository=image-registry.openshift-image-registry.svc:5000/certsight/cert-analyzer \
--set image.tag=latest
```

See `values.yaml` for every other setting (alert threshold, log level, scan paths, resource
limits, which TracingPolicies/monitoring resources to install, etc).

## Upgrade

```bash
helm upgrade cert-analyzer ./cert-analyzer -n certsight --reuse-values \
  --set image.tag=v0.87-ubi9
```

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
