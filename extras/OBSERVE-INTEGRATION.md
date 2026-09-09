# CertSight → Observe Inc integration guide (Prometheus path)

This is a preparation guide for feeding cert-analyzer's Prometheus metrics
into [Observe Inc](https://observeinc.com)'s platform via an
**already-deployed OpenTelemetry Collector** in the target environment.
It intentionally covers **metrics only** — the two Kafka event streams
(`certificate_discovered` / `certificate_accessed`, see
[FIELDS-README.md](FIELDS-README.md)) are a separate, later phase.

No changes are required on the cert-analyzer side. This is entirely a
collector-config change made by whoever owns the Observe-facing collector.

---

## What's being scraped

Every cert-analyzer instance exposes Prometheus exposition format on
`:9090/metrics` by default (`[metrics] port` in `cert-analyzer.conf`, or
`METRICS_PORT`), **plain HTTP, no auth, no TLS**. Full metric/label
reference: [FIELDS-README.md](FIELDS-README.md#prometheus-metrics).

Two config values on the cert-analyzer side matter for how the collector
should scrape it:

| Setting | Default | Why it matters here |
|---|---|---|
| `min_scrape_interval_seconds` | `60` | A scrape faster than this gets a replayed cached response, not fresh data. Set the collector's `scrape_interval` to **≥ 60s**, matching this. |
| `event_rate_metrics_enabled` | `false` | Leave off unless already needed elsewhere — it adds a process-name-labelled cardinality axis (`tls_tcp_connect_events_total`, `tls_socket_bind_events_total`) that this integration doesn't need. |

---

## 1. Bare-metal / systemd hosts

Add a `prometheus` receiver to the Observe-bound collector's config,
targeting each cert-analyzer host directly:

```yaml
receivers:
  prometheus:
    config:
      global:
        scrape_interval: 60s     # match min_scrape_interval_seconds
      scrape_configs:
        - job_name: certsight
          static_configs:
            - targets:
                - "host1.internal:9090"
                - "host2.internal:9090"
              labels:
                service: certsight

processors:
  # optional, see "Cardinality" below
  batch: {}

exporters:
  # whatever the collector already uses to reach Observe
  # (otlphttp/observe, or your existing Observe exporter block)

service:
  pipelines:
    metrics/certsight:
      receivers: [prometheus]
      processors: [batch]
      exporters: [<existing Observe exporter>]
```

Add one target per host, or generate the list from your existing fleet
inventory if you're scraping more than a handful of nodes (see
`EXTRA_SCRAPE_TARGETS` in [`install-prometheus.sh`](install-prometheus.sh)
for the pattern the local Grafana setup already uses).

---

## 2. Kubernetes / OpenShift

The Helm chart (`extras/helm/cert-analyzer/`) already exposes a `metrics`
port on the `cert-expiry-monitor` Service, and optionally a
`ServiceMonitor` (`monitoring.serviceMonitor.enabled`). Two ways to point
the Observe collector at it, depending on what's already running in that
cluster:

- **No Prometheus Operator / Target Allocator in the mix** — use the
  collector's `prometheus` receiver with `kubernetes_sd_configs` (role:
  `service`) filtered to `app: cert-expiry-monitor`, same effect as the
  static config above but discovered rather than hardcoded.
- **OpenTelemetry Operator + Target Allocator already deployed** — enable
  `monitoring.serviceMonitor.enabled` in the Helm values and let the
  Target Allocator pick up the existing `ServiceMonitor` automatically;
  no receiver config needed on the collector side.

Either way, confirm network policy allows the collector (which may run in
a different namespace, or outside the cluster entirely) to reach the
`cert-expiry-monitor` Service on the metrics port.

---

## 3. Cardinality — check before scaling to the full fleet

Four gauges (`tls_certificate_expiry_days`, `_expiry_timestamp`,
`_valid_from_timestamp`, `_last_accessed_timestamp`) carry ~20 labels
each, including SAN DNS name lists and full subject/issuer strings. This
is the same series-count profile behind a real cardinality-driven outage
during an earlier pilot — see the CA-bundle parsing incident referenced in
project history. If Observe ingests or bills by series count:

1. Point the receiver at **one node first**.
2. Check the actual series count that lands in Observe.
3. Only then widen `static_configs`/`kubernetes_sd_configs` to the rest of
   the fleet.

If cost or series count is a problem, add a collector-side
`filter`/`attributes` processor to drop or truncate the highest-cardinality
labels (e.g. `san_dns_names`) before export, rather than changing anything
in cert-analyzer itself.

---

## 4. Network and exposure

`:9090/metrics` has no auth and no TLS — it relies entirely on network
reachability for its access control. Adding an Observe-bound collector as
a scraper means:

- Opening a path (firewall/security group/NetworkPolicy) from the
  collector to each host's metrics port, if one doesn't already exist.
- Being aware this is an *additional* consumer of an already-open port,
  not a new exposure of cert-analyzer itself — but confirm the collector
  host/network is one you'd trust to read fleet-wide certificate identity
  data (subjects, SANs, issuers), since that's what these labels carry.

---

## 5. Verifying it worked

- On each scraped host: `curl -s localhost:9090/metrics | head` to confirm
  the endpoint is live and confirm your firewall change with a `curl` from
  the collector host itself.
- On the collector: check its own internal telemetry (`otelcol_receiver_*`
  metrics, or debug logs) for scrape errors against the `certsight` job.
- In Observe: confirm the `certsight` series are queryable and that
  `node_name` (already present as a metric label from cert-analyzer, not
  something the collector needs to add) is usable for per-node filtering.

---

## Open items to confirm with the collector owner

- [ ] Which exporter block already ships to Observe, so the new
      `metrics/certsight` pipeline can be attached to it (vs. this being
      the collector's first metrics pipeline).
- [ ] Whether the target environment is bare-metal/systemd, k8s, or mixed
      — determines section 1 vs. 2 above.
- [ ] Network path from the collector to cert-analyzer hosts (same
      segment, VPN, jump host?).
- [ ] Observe's cost/limits model for metric series, to size step 3 above
      correctly before fleet-wide rollout.
