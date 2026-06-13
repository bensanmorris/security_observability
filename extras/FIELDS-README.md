# cert-analyzer — Surfaced Fields Reference

The cert-analyzer surfaces certificate data through two independent channels:
**Prometheus metrics** (always on, port 9090 by default) and an optional
**Kafka event stream** (one JSON message per newly-discovered certificate).

This document is a reference for engineers writing dashboards, alert rules,
or consuming the Kafka topic.

---

## Prometheus metrics

### Certificate expiry and validity

Three gauges carry the full certificate identity as labels and are updated
every time a certificate is seen.

| Metric | Type | Description |
|---|---|---|
| `tls_certificate_expiry_days` | Gauge | Floating-point days until the certificate expires (negative when expired) |
| `tls_certificate_expiry_timestamp` | Gauge | Unix timestamp of `not_after` |
| `tls_certificate_valid_from_timestamp` | Gauge | Unix timestamp of `not_before` |

All three share the same label set:

| Label | Source | Notes |
|---|---|---|
| `cert_path` | Tetragon event | Filesystem path where the certificate was accessed |
| `subject` | X.509 | RFC 4514 string, truncated to 100 chars |
| `issuer` | X.509 | RFC 4514 string, truncated to 100 chars |
| `serial` | X.509 | Decimal serial number as string |
| `process` | Tetragon event | Binary path of the process that accessed the cert |
| `common_name` | X.509 | CN from the Subject, empty if absent |
| `cert_index` | Internal | 0-based index within a multi-cert PEM file |
| `pod_name` | Tetragon / k8s | Empty on bare metal |
| `namespace` | Tetragon / k8s | Empty on bare metal |
| `workload_kind` | Tetragon / k8s | e.g. `DaemonSet`, `Deployment` — empty on bare metal |
| `workload_name` | Tetragon / k8s | Empty on bare metal |
| `node_name` | Tetragon | Node where the event was generated |
| `app_label` | k8s pod labels | Value of `app`, `app.kubernetes.io/name`, or `k8s-app` label; empty if none |
| `container_name` | Tetragon / k8s | Empty on bare metal |
| `checksum` | X.509 | SHA-256 hex fingerprint of DER-encoded cert; empty string when `checksum_enabled=false` |

### Certificate status flags

| Metric | Type | Labels | Description |
|---|---|---|---|
| `tls_certificate_expired` | Gauge | `cert_path`, `process`, `cert_index`, `pod_name`, `namespace`, `workload_kind`, `workload_name`, `node_name` | `1` if expired, `0` if valid |
| `tls_certificate_expiring_soon` | Gauge | above + `threshold_days` | `1` if expiring within threshold, `0` otherwise. Emitted for thresholds `7`, `30`, and `90` days |
| `tls_certificate_fips_compliant` | Gauge | `cert_path`, `process`, `cert_index`, `pod_name`, `namespace`, `workload_kind`, `workload_name`, `node_name`, `key_algorithm`, `signature_hash` | `1` if FIPS-compliant, `0` if not. Only emitted when `fips_compliance_enabled=true` |
| `tls_certificate_self_signed` | Gauge | `cert_path`, `process`, `cert_index`, `pod_name`, `namespace`, `workload_kind`, `workload_name`, `node_name`, `is_ca` | `1` if the certificate is self-signed, `0` if issued by a separate CA. Always emitted. `is_ca` label: `true` / `false` / `unknown` (when Basic Constraints extension is absent) |

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

### Analyzer health and operational metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `cert_analyzer_healthy` | Gauge | — | `1` while the analyzer is running normally |
| `cert_analyzer_last_event_timestamp` | Gauge | — | Unix timestamp of the last event received from Tetragon |
| `cert_analyzer_tetragon_version` | Info | — | `build_version` and `runtime_version` labels |
| `cert_analyzer_tetragon_version_match` | Gauge | — | `1` if build and runtime Tetragon versions match, `0` if mismatched |
| `cert_analyzer_build` | Info | — | `version` (cert-analyzer) and `tetragon_build_version` |
| `cert_analyzer_cache_known_certs_size` | Gauge | — | Current number of entries in the known-certs LRU cache |
| `cert_analyzer_cache_processed_paths_size` | Gauge | — | Current number of entries in the processed-paths LRU cache |
| `cert_analyzer_cache_password_failed_size` | Gauge | — | Current number of entries in the password-failed LRU cache |
| `cert_analyzer_cache_max_size` | Gauge | — | Configured `max_size` for all LRU caches |
| `kafka_delivery_errors_total` | Counter | — | Cumulative async Kafka delivery failures |

---

## Kafka event schema

Published to the configured topic each time a certificate is seen **for the
first time**. Re-encounters of a known certificate do not produce a message —
Prometheus handles ongoing state; Kafka handles the stream of new discoveries.

The partition key is `path:cert_index:serial_number` — stable across restarts,
unique per certificate, and rotated when the cert at a path changes.

```json
{
  "event_type":        "certificate_discovered",
  "detected_at":       "2026-06-10T10:00:00.000000",

  "path":              "/etc/ssl/certs/my-service.pem",
  "cert_index":        0,

  "subject":           "CN=my-service,O=Example Corp",
  "issuer":            "CN=Example CA,O=Example Corp",
  "serial_number":     "123456789",
  "common_name":       "my-service",
  "san_dns_names":     ["my-service.example.com", "my-service"],

  "not_before":        "2025-01-01T00:00:00",
  "not_after":         "2026-01-01T00:00:00",
  "days_until_expiry": 204.35,
  "is_expired":        false,

  "process":           "/usr/bin/nginx",
  "pid":               12345,

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
