# cert-analyzer — Surfaced Fields Reference

The cert-analyzer surfaces certificate data through two independent channels:
**Prometheus metrics** (always on, port 9090 by default) and two optional
**Kafka event streams** — `certificate_discovered` (one message per
newly-discovered certificate) and `certificate_accessed` (one message per
distinct process/pod that subsequently re-accesses an already-known
certificate).

This document is a reference for engineers writing dashboards, alert rules,
or consuming either Kafka topic.

---

## Prometheus metrics

### Certificate expiry and validity

The following gauges carry the full certificate identity as labels and are updated
every time a certificate is seen.

| Metric | Type | Description |
|---|---|---|
| `tls_certificate_expiry_days` | Gauge | Floating-point days until the certificate expires (negative when expired) |
| `tls_certificate_expiry_timestamp` | Gauge | Unix timestamp of `not_after` |
| `tls_certificate_valid_from_timestamp` | Gauge | Unix timestamp of `not_before` |
| `tls_certificate_last_accessed_timestamp` | Gauge | Unix timestamp of the most recent access event for this certificate |

All share the same label set:

| Label | Source | Notes |
|---|---|---|
| `cert_path` | Tetragon event | Filesystem path where the certificate was accessed |
| `subject` | X.509 | RFC 4514 string, truncated to 100 chars |
| `issuer` | X.509 | RFC 4514 string, truncated to 100 chars |
| `serial` | X.509 | Decimal serial number as string |
| `common_name` | X.509 | CN from the Subject, empty if absent |
| `san_dns_names` | X.509 | Comma-joined DNS SANs; empty string if none |
| `san_ip_addresses` | X.509 | Comma-joined IP SANs; empty string if none |
| `cert_index` | Internal | 0-based index within a multi-cert PEM file |
| `pod_name` | Tetragon / k8s | Empty on bare metal |
| `namespace` | Tetragon / k8s | Empty on bare metal |
| `workload_kind` | Tetragon / k8s | e.g. `DaemonSet`, `Deployment` — empty on bare metal |
| `workload_name` | Tetragon / k8s | Empty on bare metal |
| `node_name` | Tetragon | Node where the event was generated |
| `app_label` | k8s pod labels | Value of `app`, `app.kubernetes.io/name`, or `k8s-app` label; empty if none |
| `container_name` | Tetragon / k8s | Empty on bare metal |
| `checksum` | X.509 | SHA-256 hex fingerprint of DER-encoded cert; empty string when `checksum_enabled=false` |
| `key_usage` | X.509 | Comma-joined Key Usage bits (e.g. `digital_signature,key_encipherment`); empty string if the extension is absent |
| `extended_key_usage` | X.509 | Comma-joined Extended Key Usage OIDs (e.g. `server_auth,client_auth`); empty string if the extension is absent |

Note: `process`/`parent_process` are per-*access*, not per-certificate, so they are
deliberately not labels on these four gauges — they're tracked instead on the
`tls_certificate_process_info` gauge, which maps certificates to the processes
observed loading them (see below).

### Certificate status flags

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tls_certificate_fips_compliant` | Gauge | `cert_path`, `cert_index`, `pod_name`, `namespace`, `workload_kind`, `workload_name`, `node_name`, `app_label`, `container_name`, `key_algorithm`, `signature_hash`, `key_size`, `curve_name`, `issuer`, `serial`, `checksum` | `1` if FIPS-compliant, `0` if not. Only emitted when `fips_compliance_enabled=true` |
| `tls_certificate_self_signed` | Gauge | `cert_path`, `cert_index`, `pod_name`, `namespace`, `workload_kind`, `workload_name`, `node_name`, `app_label`, `container_name`, `is_ca`, `issuer`, `serial`, `checksum` | `1` if the certificate is self-signed, `0` if issued by a separate CA. Always emitted. `is_ca` label: `true` / `false` / `unknown` (when Basic Constraints extension is absent) |

There is no separate "expired" or "expiring soon" gauge — both are derivable from
`tls_certificate_expiry_days` (see above) with a plain comparison, exactly how
`CertificateExpiringCritical`/`CertificateExpiringWarning`/`CertificateExpired` in
`extras/openshift/prometheus-rule.yaml` already alert (`tls_certificate_expiry_days < 0`
for expired, `< 7 and > 0` / `< 30 and > 7` for the two warning tiers). Pre-computing
these as their own boolean gauges used to cost 4 extra Prometheus series per certificate
(one "expired" plus three "expiring_soon" threshold buckets) for values a query can derive
for free.

### Certificate-to-process map

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tls_certificate_process_info` | Gauge | `cert_path`, `cert_index`, `serial`, `process`, `parent_process`, `node_name`, `pod_name`, `namespace`, `app_label`, `container_name`, `checksum` | `1` per distinct process observed loading this certificate. One series per distinct `(process, parent_process, pod_name, namespace, app_label, container_name)` tuple, capped at `max_processes_per_cert` (default 20) per certificate |

Unlike the certificate status flags above, `pod_name`/`namespace`/`app_label`/`container_name`
here describe the *accessing* process's own pod at the time it was recorded — not necessarily
the same pod that first discovered the certificate (that pod's context is what's attached to
the four status-flag gauges and the four expiry gauges instead). A cert bundle read by the same
binary running in several different pods shows up as several distinct series here, one per pod.

### Event and error counters

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tls_certificate_events_total` | Counter | `event_type`, `status` | Total certificate events processed. `event_type=analysis`, `status=success\|failed` |
| `tls_certificate_analysis_errors_total` | Counter | `error_type` | Parse and extraction failures. See error types below |

`error_type` values for `tls_certificate_analysis_errors_total`:

| Value | Meaning |
|---|---|
| `file_not_found` | Certificate path did not exist when opened |
| `permission_denied` | Insufficient permissions to read the file |
| `read_error` | File opened but could not be read |
| `parse_error` | File could not be parsed as a valid certificate format |
| `extraction_error` | Certificate parsed but a mandatory field could not be extracted |
| `jks_unavailable` | JKS parsing attempted but `javaobj-types` is not installed |
| `jks_password_failed` | JKS keystore could not be opened with the configured password |
| `pkcs12_password_failed` | PKCS12 bundle could not be opened with the configured password |

### TLS port probes

Only emitted when `bind_probe_enabled=true` or `connect_probe_enabled=true` (both default `false`).

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tls_port_probes_total` | Counter | `status` | Total TLS port probe attempts. `status=success\|failed\|skipped` (`skipped` = endpoint already probed) |
| `tls_certificate_negotiated_protocol` | Gauge | `cert_path`, `cert_index`, `serial`, `node_name`, `protocol`, `cipher`, `process` | `1` if observed. Records the TLS protocol version and cipher suite negotiated with `ssl.create_default_context()` during the probe — the server's ceiling with a modern client, not necessarily what every real client gets. `process` is the binary that triggered the probe (the bind/connect event's process). Only emitted for TLS-probed endpoints; file-discovered certificates have no live connection to negotiate |

### Analyzer health and operational metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `cert_analyzer_healthy` | Gauge | — | `1` while the analyzer is running normally |
| `tetragon_connected` | Gauge | — | `1` when the event stream to Tetragon is active, `0` when disconnected or not yet connected. Set to `0` on `gRPC` error or shutdown; returns to `1` as soon as the stream is re-established |
| `cert_analyzer_last_event_timestamp` | Gauge | — | Unix timestamp of the last event received from Tetragon |
| `cert_analyzer_tetragon_version` | Info | `node_name` | `build_version` and `runtime_version` labels |
| `cert_analyzer_tetragon_version_match` | Gauge | `node_name` | `1` if build and runtime Tetragon versions match, `0` if mismatched |
| `cert_analyzer_build` | Info | `node_name` | `version` (cert-analyzer) and `tetragon_build_version`. `node_name`-labeled so a fleet-wide view can show which analyzer version is running per node |
| `cert_analyzer_scrape_interval_seconds` | Gauge | `node_name` | Observed wall-clock interval since the previous `/metrics` scrape of this node. Computed at scrape time rather than read from Prometheus config, so it reflects actual scheduler drift/overhead; absent on a node's first-ever scrape |
| `cert_analyzer_last_scrape_timestamp_seconds` | Gauge | `node_name` | Unix timestamp of this scrape of `/metrics`. Present from the very first scrape (unlike the interval metric above); `time() - this` gives a per-node staleness indicator that keeps growing if Prometheus stops reaching this node |
| `cert_analyzer_cache_known_certs_size` | Gauge | — | Current number of entries in the known-certs LRU cache |
| `cert_analyzer_cache_processed_paths_size` | Gauge | — | Current number of entries in the processed-paths LRU cache |
| `cert_analyzer_cache_password_failed_size` | Gauge | — | Current number of entries in the password-failed LRU cache |
| `cert_analyzer_cache_max_size` | Gauge | — | Configured `max_size` for all LRU caches |
| `kafka_delivery_errors_total` | Counter | — | Cumulative async Kafka delivery failures |
| `kafka_connected_at_timestamp_seconds` | Gauge | `node_name` | Unix timestamp of the last successful Kafka producer connection. Absent if Kafka is disabled or has never connected |
| `kafka_last_published_timestamp_seconds` | Gauge | `node_name` | Unix timestamp of the last message successfully acked by the broker. Absent if Kafka is disabled or nothing has published yet |
| `tetragon_policy_info` | Gauge | `name`, `namespace`, `state` | One series per tracing policy, value always `1`. Stale series are removed when a policy is deleted or changes state. `namespace` is empty for cluster-scoped policies |
| `tetragon_policies_total` | Gauge | `state` | Count of tracing policies in each state. All state values are always emitted (including `0`) so alert rules can rely on the series being present |

`state` values for `tetragon_policy_info` and `tetragon_policies_total`:

| Value | Meaning |
|---|---|
| `enabled` | Policy is loaded and actively generating events |
| `disabled` | Policy is loaded but has been administratively disabled |
| `loading` | Policy is being loaded into the kernel (transient) |
| `unloading` | Policy is being removed from the kernel (transient) |
| `load_error` | Policy failed to load — sensors will not fire. Requires operator attention |
| `error` | Policy encountered a runtime error after loading |
| `unknown` | State could not be determined |

Alert guidance: `tetragon_policies_total{state=~"load_error|error"} > 0` means at least one policy is broken and the cert-analyzer may not be receiving events for the affected probes.

---

## Kafka event schema

Published to the configured topic each time a certificate is seen **for the
first time**. Re-encounters of a known certificate do not produce a message —
Prometheus handles ongoing state; Kafka handles the stream of new discoveries.

The partition key is `path:cert_index:serial_number` — stable across restarts,
unique per certificate, and rotated when the cert at a path changes.

```json
{
  "schema_version":    1,
  "event_type":        "certificate_discovered",
  "detected_at":       "2026-06-10T10:00:00.000000",

  "path":              "/etc/ssl/certs/my-service.pem",
  "cert_index":        0,

  "subject":           "CN=my-service,O=Example Corp",
  "issuer":            "CN=Example CA,O=Example Corp",
  "serial_number":     "123456789",
  "common_name":       "my-service",
  "san_dns_names":     ["my-service.example.com", "my-service"],
  "san_ip_addresses":  ["10.96.0.1", "192.168.1.100"],

  "not_before":        "2025-01-01T00:00:00",
  "not_after":         "2026-01-01T00:00:00",
  "days_until_expiry": 204.35,
  "is_expired":        false,

  "process":           "/usr/bin/nginx",
  "pid":               12345,
  "parent_process":    "/usr/bin/containerd-shim",
  "parent_pid":        12300,

  "namespace":         "production",
  "pod_name":          "nginx-7d6b9c-xkp2q",
  "pod_uid":           "a1b2c3d4-...",
  "node_name":         "worker-1",
  "pod_annotations":   {},
  "workload_kind":     "Deployment",
  "workload_name":     "nginx",
  "app_label":         "nginx",

  "container_id":               "containerd://abc123",
  "container_name":             "nginx",
  "container_image":            "nginx:1.25",
  "container_image_id":         "sha256:abc...",
  "container_privileged":       false,
  "container_pid":              12344,
  "container_start_time":       "2026-06-01T08:00:00",
  "container_maybe_exec_probe": false,

  "checksum":        "e3b0c44298fc1c149afb...",
  "key_algorithm":   "RSA",
  "key_size":        2048,
  "signature_hash":  "sha256",
  "curve_name":      "",
  "fips_compliant":  true,
  "fips_violations": [],

  "key_usage":                     ["digital_signature", "key_encipherment"],
  "extended_key_usage":            ["server_auth"],
  "is_ca":                         false,
  "basic_constraints_path_length": null,
  "is_self_signed":                false
}
```

### Field reference

#### Discovery context

| Field | Type | Description |
|---|---|---|
| `schema_version` | int | Bumped only on breaking schema changes (renamed/removed field, changed type) — not on every release |
| `event_type` | string | Always `"certificate_discovered"` |
| `detected_at` | ISO 8601 | UTC timestamp when the event was processed |
| `path` | string | Filesystem path of the certificate file |
| `cert_index` | int | 0-based index within a multi-cert PEM file |

#### Certificate identity

| Field | Type | Description |
|---|---|---|
| `subject` | string | RFC 4514 Subject DN |
| `issuer` | string | RFC 4514 Issuer DN |
| `serial_number` | string | Decimal serial number |
| `common_name` | string | CN from Subject; empty if absent |
| `san_dns_names` | string[] | DNS SANs; empty list if none |
| `san_ip_addresses` | string[] | IP SANs as strings (IPv4 or IPv6); empty list if none |

#### Validity

| Field | Type | Description |
|---|---|---|
| `not_before` | ISO 8601 | Certificate valid-from date (UTC, no timezone suffix) |
| `not_after` | ISO 8601 | Certificate expiry date (UTC, no timezone suffix) |
| `days_until_expiry` | float | Positive = days remaining; negative = already expired |
| `is_expired` | bool | `true` if `not_after` is in the past |

#### Process context

| Field | Type | Description |
|---|---|---|
| `process` | string | Binary path of the process that accessed the certificate |
| `pid` | int | PID of that process |
| `parent_process` | string | Binary path of the process that spawned the cert loader; empty string when Tetragon's process cache did not have the parent at event time (common at startup or for short-lived processes) |
| `parent_pid` | int | PID of the parent process; `0` when unavailable |

> **Security note**: `parent_process` surfaces the spawn chain — e.g. a cert loaded by `/usr/bin/java` whose parent is `/bin/bash` rather than your service manager is a strong signal of unexpected activity. Because Tetragon populates this field from its in-kernel process cache, it may be absent (`""`) for processes that were already running before Tetragon started. Filter on `parent_process != ""` to scope queries to events where the chain is known.

#### Kubernetes context

All fields are empty strings / null on bare-metal deployments.

| Field | Type | Description |
|---|---|---|
| `namespace` | string | Kubernetes namespace |
| `pod_name` | string | Pod name |
| `pod_uid` | string | Pod UID |
| `node_name` | string | Node name |
| `pod_annotations` | object | Full pod annotation map |
| `workload_kind` | string | Controller kind: `Deployment`, `DaemonSet`, `StatefulSet`, etc. |
| `workload_name` | string | Controller name |
| `app_label` | string | Value of `app`, `app.kubernetes.io/name`, or `k8s-app` pod label |
| `container_id` | string | Full container ID including runtime prefix |
| `container_name` | string | Container name within the pod |
| `container_image` | string | Image name and tag |
| `container_image_id` | string | Image digest |
| `container_privileged` | bool | Whether the container runs in privileged mode |
| `container_pid` | int\|null | PID of the container's init process in the host PID namespace |
| `container_start_time` | ISO 8601\|null | Container start time |
| `container_maybe_exec_probe` | bool | Heuristic: `true` if this event looks like a Kubernetes exec liveness/readiness probe rather than normal application activity |

#### Certificate cryptography

| Field | Type | Description | Config dependency |
|---|---|---|---|
| `checksum` | string | SHA-256 hex fingerprint of DER-encoded cert; empty string if disabled | `checksum_enabled=true` |
| `key_algorithm` | string | `RSA`, `EC`, `DSA`, `Ed25519`, `Ed448`, or `unknown` | `fips_compliance_enabled=true` |
| `key_size` | int | Key size in bits; `0` for EdDSA (fixed-size keys) | `fips_compliance_enabled=true` |
| `signature_hash` | string | Hash algorithm name e.g. `sha256`, `sha384`, `sha1` | `fips_compliance_enabled=true` |
| `curve_name` | string | EC curve name e.g. `secp256r1`; empty for non-EC keys | `fips_compliance_enabled=true` |
| `fips_compliant` | bool | `true` only when no violations found | `fips_compliance_enabled=true` |
| `fips_violations` | string[] | Human-readable violation descriptions; empty list when compliant | `fips_compliance_enabled=true` |

> When `fips_compliance_enabled=false`, the cryptography fields (`key_algorithm`,
> `key_size`, `signature_hash`, `curve_name`) are empty / zero and `fips_compliant`
> is `false`. Consumers should check `fips_compliance_enabled` configuration rather
> than treating `fips_compliant=false` as a violation signal in that case.

#### RFC 5280 certificate extensions

These fields are extracted unconditionally — no configuration flag required.
`null` means the extension is absent from the certificate; an empty array means
the extension is present but no values are set.

| Field | Type | Description |
|---|---|---|
| `key_usage` | string[]\|null | Key Usage bits set on the certificate. `null` if the extension is absent. Possible values: `digital_signature`, `content_commitment`, `key_encipherment`, `data_encipherment`, `key_agreement`, `key_cert_sign`, `crl_sign`, `encipher_only`, `decipher_only` |
| `extended_key_usage` | string[]\|null | Extended Key Usage OIDs. `null` if the extension is absent. Common values: `server_auth`, `client_auth`, `code_signing`, `email_protection`, `time_stamping`, `ocsp_signing`. Unknown OIDs appear as dotted strings e.g. `1.3.6.1.4.1.311.10.3.4` |
| `is_ca` | bool\|null | `true` if the Basic Constraints extension is present and `CA` is set; `false` if the extension is present but `CA` is not set; `null` if the extension is absent |
| `basic_constraints_path_length` | int\|null | Maximum CA chain depth from the Basic Constraints extension. `null` if the extension is absent or no path length constraint is specified |

#### Certificate trust

| Field | Type | Description |
|---|---|---|
| `is_self_signed` | bool | `true` if the certificate's subject and issuer names are identical **and** the signature verifies against its own public key. Root CA certificates are legitimately self-signed; self-signed leaf certificates are typically a misconfiguration risk. Always populated — no configuration flag required |

> **Alert guidance**: filter `is_ca="false"` on `tls_certificate_self_signed == 1` to target non-CA self-signed certificates — the genuinely risky case. Root CA certificates (`is_ca="true"`) are legitimately self-signed and can be excluded. `is_ca="unknown"` means the certificate has no Basic Constraints extension, which itself is unusual for a modern cert and worth alerting on alongside `is_self_signed=1`.
>
> Example PromQL: `tls_certificate_self_signed{is_ca="false"} == 1`

---

## Kafka event schema: certificate_accessed

Disabled by default — set `[kafka] access_enabled = true` (in addition to
`[kafka] enabled = true`) to publish these. Published to the configured
`access_topic` each time a certificate already known to the analyzer is
re-accessed by a **new** distinct `(process, parent_process, pod_name,
namespace, app_label, container_name)` tuple — not on every raw file-access
event. The same process/pod combination re-accessing the same cert again does
not produce a second message. This mirrors — and is capped by the same
`max_processes_per_cert` limit as — the `cert_process_info` Prometheus gauge
(see [Certificate-to-process map](#certificate-to-process-map)).

The certificate's own discovery is *not* re-published here — the discovering
process/pod is already captured in that certificate's `certificate_discovered`
event. This topic only covers subsequent accesses by other processes/pods.

The message intentionally omits certificate metadata (subject, SANs, key
info, FIPS status, etc.) already carried by `certificate_discovered` —
consumers should join the two streams on `cert_unique_key` (equivalent to
`certificate_discovered`'s partition key, `path:cert_index:serial_number`).

The partition key is the same `cert_unique_key`, so all accesses for a given
certificate land on the same partition.

```json
{
  "schema_version":   1,
  "event_type":       "certificate_accessed",
  "accessed_at":      "2026-07-22T10:00:00.000000",

  "cert_unique_key":  "/etc/ssl/certs/my-service.pem:0:123456789",
  "path":             "/etc/ssl/certs/my-service.pem",
  "cert_index":       0,
  "serial_number":    "123456789",

  "process":          "/usr/bin/curl",
  "pid":              23456,
  "parent_process":   "/usr/bin/bash",
  "parent_pid":       23400,

  "namespace":        "production",
  "pod_name":         "debug-pod-x7z2q",
  "pod_uid":          "b2c3d4e5-...",
  "node_name":        "worker-1",
  "app_label":        "debug-pod",
  "container_name":   "main",
  "container_id":     "containerd://def456",
  "container_image":  "debug-tools:1.0"
}
```

### Field reference

| Field | Type | Description |
|---|---|---|
| `schema_version` | int | Same versioning scheme as `certificate_discovered` |
| `event_type` | string | Always `"certificate_accessed"` |
| `accessed_at` | ISO 8601 | UTC timestamp of this access event |
| `cert_unique_key` | string | Join key back to the certificate's `certificate_discovered` event |
| `path` | string | Filesystem path of the certificate file |
| `cert_index` | int | 0-based index within a multi-cert PEM file |
| `serial_number` | string | Decimal serial number |
| `process` | string | Binary path of the accessing process |
| `pid` | int | PID of that process |
| `parent_process` | string | Binary path of the parent process; empty when Tetragon's process cache lacked the parent at event time |
| `parent_pid` | int | PID of the parent process; `0` when unavailable |
| `namespace` | string | Kubernetes namespace of the accessing pod; empty on bare-metal |
| `pod_name` | string | Name of the accessing pod |
| `pod_uid` | string | UID of the accessing pod |
| `node_name` | string | Node the access occurred on |
| `app_label` | string | Value of `app`, `app.kubernetes.io/name`, or `k8s-app` label on the accessing pod |
| `container_name` | string | Container name within the accessing pod |
| `container_id` | string | Full container ID including runtime prefix |
| `container_image` | string | Image name and tag of the accessing container |

> **Note**: these pod/container fields describe *this specific access* and
> can differ from the pod/container fields on the certificate's own
> `certificate_discovered` event, which stay sticky to whichever pod first
> discovered the certificate.
