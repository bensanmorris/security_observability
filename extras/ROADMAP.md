# CertSight Roadmap

This document captures planned and proposed improvements to CertSight, organized by theme and rough priority.

---

## Detection depth

### SAN IP address extraction
`extract_certificate_info` captures `san_dns_names` but discards IP SANs (`x509.IPAddress`). Many internal and Kubernetes certs use IP SANs rather than DNS names. Adding a `san_ip_addresses` list field alongside the existing `san_dns_names` closes this gap with a small extraction addition.

### Parent process capture
Tetragon's `process_kprobe` and `process_uprobe` protos include a `parent` field with the PID and binary of the spawning process. Capturing this surfaces "which service launched the binary that loaded this cert" — a meaningful security signal for unexpected cert loaders. Currently untouched.

### Certificate rotation detection
When a new serial appears at a previously-known path, the current code re-analyzes it after LRU eviction with no explicit signal. An explicit `tls_certificate_rotations_total` counter (incrementing when the serial changes at the same `cert_path`) makes rotation velocity visible and enables alerting on failed or stalled rotations.

---

## Security analysis

### Wildcard certificate metric
A `tls_certificate_wildcard` gauge (1 when the CN or any SAN starts with `*.`) lets security teams audit wildcard usage across the fleet. Wildcard certs have a large blast radius when compromised and are often issued more permissively than scoped certs.

### CA/leaf key usage mismatch detection
`is_ca` and `key_usage` are already extracted. A metric or log warning for certs where `key_cert_sign` is set but `is_ca=false`, or where `is_ca=true` but the cert is being loaded as an endpoint cert, catches PKI misconfigurations that expiry monitors will never surface.

### OCSP/CRL revocation checking
The most significant functional gap. Every major cert monitoring tool checks expiry; almost none check revocation at load time. An async OCSP check on newly-discovered certs — with aggressive caching and a configurable timeout — would be a genuine differentiator, especially for security teams tracking compromised CA events. CRL as a fallback when OCSP is unavailable.

### Rogue CA alerting
Build a per-CN/SAN baseline of which issuers have historically signed certs for that identity. Alert and emit a metric when a new issuer appears signing for a previously-seen CN or SAN. This is the cert-level equivalent of detecting a rogue DNS resolver — it catches MITM and unexpected-CA attacks that no expiry monitor would surface.

---

## Operational value

### Certificate inventory REST endpoint
The `HealthServer` at `:8086` only serves `/healthz` and `/readyz`. Adding:
- `GET /certs` — returns the current `known_certs` inventory as JSON
- `GET /summary` — counts by status (expired, expiring-soon, FIPS-non-compliant, self-signed) and by namespace/workload

This lets operators query the live cert inventory without Prometheus, makes debugging trivial, and opens integration paths with CMDB and asset inventory tools.

### Grafana dashboard
A bundled dashboard JSON dramatically lowers time-to-value for new users. Proposed panels:
- Expiry heatmap by workload and namespace
- FIPS compliance ratio over time
- Self-signed certificate inventory
- Rotation rate (using the rotation counter above)
- Error rate by type (`tls_certificate_analysis_errors_total`)
- Cache occupancy and LRU eviction rate

No changes to `cert_analyzer.py` required — purely a tooling artifact shipped alongside the RPM.

### Webhook output for cert events
Kafka suits streaming pipelines, but many operators want a direct Slack, Teams, or PagerDuty notification for critical events (expired cert detected, FIPS violation, rogue CA, wildcard cert). A configurable webhook destination alongside Kafka, firing on configurable thresholds (expired, expiring-within-N-days, FIPS-non-compliant, self-signed leaf, rogue CA), would remove the "requires Prometheus Alertmanager" dependency for basic alerting.

---

## Priority summary

| Item | Impact | Effort |
|---|---|---|
| SAN IP extraction | Medium | Low |
| Parent process capture | Medium | Low |
| Wildcard cert metric | Medium | Low |
| Grafana dashboard | High | Low |
| CA/leaf key usage mismatch | Medium | Low |
| Certificate rotation counter | Medium | Medium |
| Certificate inventory REST endpoint | High | Medium |
| Webhook alerting output | High | Medium |
| OCSP/CRL revocation checking | High | High |
| Rogue CA alerting | High | High |
