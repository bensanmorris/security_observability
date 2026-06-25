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

### SIGHUP-triggered reload tracking (`signal` tracepoints)
Most TLS daemons (nginx, haproxy, Envoy, Postfix, Apache httpd) reload their certificates on SIGHUP rather than on a timer. The current `fd_install` kprobe catches the resulting file opens, but misses reloads where the daemon serves a cert already held in memory without re-opening the file. A `signal_generate` tracepoint policy filtered on signal 1 destined for known TLS binary paths would surface reload events explicitly — giving attribution (who sent the signal and when), enabling proactive re-probing, and catching the in-memory-reload blind spot.

### Outbound TLS connection tracking (`tcp` tracepoints)
`security_socket_bind` covers server-side TLS endpoints; the client side is currently invisible. A `tcp_connect` tracepoint policy would fire when a process opens an outbound connection to common TLS ports (443, 8443, 5671, etc.), supplying the destination address. The existing port-probe logic (TLS handshake, read the leaf cert) can then be applied in the outbound direction — making remote server certificate expiry visible without any configuration by operators.

### Kernel TLS coverage auditing (`tls` tracepoints)
When an application offloads TLS record processing to the kernel via `setsockopt(SOL_TLS, TLS_TX/RX, ...)`, the cert is still loaded in userspace first (and caught by the existing OpenSSL uprobes), but the kTLS activation event independently confirms that TLS is live on that socket. Hooking the kTLS tracepoints and cross-referencing against the set of sockets already observed via uprobes provides a coverage completeness check — any kTLS socket with no corresponding uprobe hit indicates a TLS library path not yet instrumented. Nginx and haproxy both use kTLS on RHEL 9/10 with sufficiently modern kernels.

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
| kTLS coverage auditing (`tls` tracepoints) | Low | Low |
| Certificate rotation counter | Medium | Medium |
| SIGHUP reload tracking (`signal` tracepoints) | Medium | Medium |
| Certificate inventory REST endpoint | High | Medium |
| Outbound TLS tracking (`tcp` tracepoints) | Medium | Medium |
| Webhook alerting output | High | Medium |
| OCSP/CRL revocation checking | High | High |
| Rogue CA alerting | High | High |
