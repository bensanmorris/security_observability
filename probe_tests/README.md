# probe_tests

Programs that exercise the Tetragon uprobe hooks defined in
`tetragon-policies/experimental/`. Run these with Tetragon active to confirm
that `cert_analyzer.py` receives the expected events.

## Generate test certificates

cert-analyzer runs under systemd with `ProtectHome=true` and `PrivateTmp=true`,
so it cannot read files under `/home` or `/tmp`.  Generate a throwaway cert and
key in `/etc/pki/tls/certs/` — already listed in the service's `ReadOnlyPaths`
— before running any test that exercises file-path-based uprobe hooks (tests 1
and 2 of `test_openssl3_cert_load` and the port-probe test):

```bash
sudo openssl req -x509 -newkey rsa:2048 \
    -keyout /etc/pki/tls/certs/cert-analyzer-test.key \
    -out    /etc/pki/tls/certs/cert-analyzer-test.crt \
    -days 365 -nodes \
    -subj "/CN=cert-analyzer-test.example.com"
sudo chmod 644 /etc/pki/tls/certs/cert-analyzer-test.key
```

Both files are placed in `/etc/pki/tls/certs/` (mode `644`) so they are
readable by the cert-analyzer service user and by the test scripts running as a
normal user.  Remove them when done:

```bash
sudo rm /etc/pki/tls/certs/cert-analyzer-test.{crt,key}
```

---

## Tests

### test_openssl3_cert_load (C++)

Exercises the three uprobe hooks in `openssl3-cert-load.yaml`.

**Build:**
```bash
sudo dnf install cmake   # if not already installed
mkdir build && cd build && cmake .. && make
```

**Run:**
```bash
# Generate test cert first — see "Generate test certificates" above
CERT=/etc/pki/tls/certs/cert-analyzer-test.crt

./test_openssl3_cert_load "$CERT"                # run all three tests
./test_openssl3_cert_load --test 1 "$CERT"       # SSL_CTX_use_certificate_file only
./test_openssl3_cert_load --test 2 "$CERT"       # SSL_CTX_use_certificate_chain_file only
./test_openssl3_cert_load --test 3               # SSL_CTX_use_certificate_ASN1 only (embedded cert, no file needed)
./test_openssl3_cert_load --test 1 --pause "$CERT"  # run test 1 then hold — useful for inspecting Tetragon events
```

| # | Function | Uprobe hook captures |
|---|----------|----------------------|
| 1 | `SSL_CTX_use_certificate_file` | `args[1]` = file path as `string_arg` |
| 2 | `SSL_CTX_use_certificate_chain_file` | `args[1]` = file path as `string_arg` |
| 3 | `SSL_CTX_use_certificate_ASN1` | `args[1]` = DER length, `args[2]` = raw DER bytes as `char_buf` → handled by `cert_analyzer._handle_uprobe_in_memory_cert` |

---

### FipsJavaCertLoad (Java)

Exercises the two uprobe hooks in `java-fips-nss-cert.yaml`.  Demonstrates that
`cert_analyzer` can observe Java certificate operations when FIPS mode is enabled
on RHEL — in FIPS mode Java's `SunPKCS11-NSS-FIPS` provider routes cert imports
through `libsoftokn3.so`, making them visible to Tetragon uprobes.

**Why FIPS matters:** Without FIPS mode Java uses pure-Java crypto — no native
library calls occur at the cert-loading level, so there is nothing to uprobe.
FIPS forces the PKCS11/NSS native path, enabling these hooks.

**Build:**
```bash
sudo dnf install java-11-openjdk-devel nss-tools   # if not already installed
cd java && ./build.sh
```

**Run:**
```bash
cd java
java -cp . FipsJavaCertLoad                        # run all three tests
java -cp . FipsJavaCertLoad --pause                # pause after tests (useful for inspecting events)
java -cp . FipsJavaCertLoad /path/to/other.crt     # custom cert
```

> **FIPS mode note:** When running on a system with OS-level FIPS enabled
> (`/proc/sys/crypto/fips_enabled = 1`), Red Hat's JDK replaces the base
> `SunPKCS11` provider with the pre-configured `SunPKCS11-NSS-FIPS`, which
> cannot be reconfigured to use a custom test database.  Pass
> `-Dcom.redhat.fips=false` to restore the configurable SunPKCS11 base so
> the test can set up its own NSS database:
>
> ```bash
> java -Dcom.redhat.fips=false -cp . FipsJavaCertLoad
> ```
>
> This flag only bypasses Java's FIPS provider auto-configuration — the test
> still explicitly routes all cert operations through NSS native (libsoftokn3.so),
> so the uprobe hooks on `NSC_CreateObject` and `NSC_FindObjectsInit` still fire.

| # | Java operation | libsoftokn3.so hook | cert_analyzer handler |
|---|---------------|---------------------|-----------------------|
| 1 | `KeyStore.load(null,null)` via PKCS11 | `NSC_FindObjectsInit` — cert class filter detected | `_handle_nsc_find_objects_init` — logs enumeration event |
| 2 | `CertificateFactory.generateCertificate` (file) | `NSC_CreateObject` — digest session objects | skipped (CKA_CLASS ≠ CKO_CERTIFICATE) |
| 3 | `KeyStore.setCertificateEntry` | `NSC_CreateObject` with CKA_CLASS=CKO_CERTIFICATE | `_handle_nsc_create_object` — walks `pTemplate` via `/proc/<pid>/mem`, extracts DER bytes |

**Why `/proc/<pid>/mem` instead of `char_buf`?**
The cert DER bytes are not a direct argument to `NSC_CreateObject` — they are
nested inside a `CK_ATTRIBUTE[]` array (pointer → struct array → pValue pointer →
DER data).  Tetragon's eBPF policy cannot chain two `bpf_probe_read_user` calls,
so `cert_analyzer` receives the template *pointer* and *count* as `uint64` args,
then performs the two-hop dereference in Python via `/proc/<pid>/mem`.  This
requires `CAP_SYS_PTRACE` (or root), which cert_analyzer holds in the
security-monitoring context.

---

### cert-agent (Java, non-FIPS)

Exercises the uprobe hook in `java-non-fips-cert.yaml`.  Provides certificate
visibility for JVMs running **without** FIPS mode, where Java uses pure-Java
JSSE crypto — no NSS native library calls occur at the cert-loading level, so
the `java-fips-nss-cert.yaml` hooks have nothing to attach to.

The solution mirrors the approach described in the
[Coroot Java TLS instrumentation article](https://coroot.com/blog/java-tls-instrumentation-with-ebpf/):
a Java agent instruments a JCA method, copies certificate DER bytes into a
thread-local native buffer (avoiding GC-visible array pinning), then calls a
tiny native stub function that serves as the uprobe target.  Tetragon reads the
DER bytes atomically at stub entry as a `char_buf` — the same mechanism used
for `SSL_CTX_use_certificate_ASN1` — so `cert_analyzer` needs no changes.

**Build:**
```bash
sudo dnf install java-11-openjdk-devel gcc   # if not already installed
cd java/cert-agent && ./build.sh
# Installs both artifacts to /opt/cert-agent/:
#   /opt/cert-agent/cert-agent.jar
#   /opt/cert-agent/libcert_agent_stub.so
```

`build.sh` installs both artifacts to `/opt/cert-agent/` automatically — the
same path `java-non-fips-cert.yaml` expects in production, so no yaml edits are
needed for local testing.

**End-to-end test procedure:**

**Step 1 — Load the Tetragon policy** (from the repo root):
```bash
sudo tetra tracingpolicy add tetragon-policies/experimental/java-non-fips-cert.yaml
```

The uprobe is installed on the `libcert_agent_stub.so` file inode, so it fires
for any JVM that loads the library — including those injected after the policy
is loaded.

**Step 2 — Start the target JVM**:
```bash
# prints PID and loops every 5 seconds
java -cp probe_tests/java CertAgentTest
```

**Step 3 — Inject the agent** using the PID printed in step 2:
```bash
probe_tests/java/cert-agent/jattach-linux-x64/jattach <pid> load instrument false \
    /opt/cert-agent/cert-agent.jar=/opt/cert-agent/libcert_agent_stub.so
```

The JVM terminal should print:
```
[cert-agent] Initialized — intercepting KeyStore.setCertificateEntry
```

**Step 4 — Watch cert_analyzer** for events (within one 5-second loop interval):
```bash
sudo journalctl -u cert-analyzer -f
# Expected:
# 🔍 Detected in-memory certificate: uprobe://java_cert_agent_write/<pid>/... by /usr/bin/java
```

**Or inject statically** (agent is pre-loaded before the JVM starts):
```bash
# Terminal 1: load policy once
sudo tetra tracingpolicy add tetragon-policies/experimental/java-non-fips-cert.yaml

# Terminal 2: start JVM with agent pre-loaded
java -javaagent:/opt/cert-agent/cert-agent.jar=/opt/cert-agent/libcert_agent_stub.so \
     -cp probe_tests/java CertAgentTest
```

**Automate deployment** across all running JVMs with the deployer:
```bash
python3 java-agent/java_agent_deployer.py \
    --agent-jar /opt/cert-agent/cert-agent.jar \
    --native-lib /opt/cert-agent/libcert_agent_stub.so
# Scans /proc every 30s, tries jattach for each new JVM,
# and prints -javaagent instructions for any that reject dynamic attach.
```

**Verify with bpftrace** (independent of Tetragon — confirms the native stub is
being called before involving cert_analyzer):
```bash
sudo bpftrace -e 'uprobe:/opt/cert-agent/libcert_agent_stub.so:java_cert_agent_write {
    printf("hit pid=%d len=%d\n", pid, arg1);
}'
# Should print a line every 5 seconds while CertAgentTest is running with the agent attached.
```

| Hook | What fires it | How cert bytes reach cert_analyzer |
|---|---|---|
| `KeyStore.setCertificateEntry` (instrumented by agent) | Any explicit cert store: `KeyStore.setCertificateEntry(alias, cert)` | Agent calls `cert.getEncoded()` → copies DER to thread-local native buffer → calls `java_cert_agent_write(buf, len)` → Tetragon `char_buf` → `_handle_uprobe_in_memory_cert` |

**Why `char_buf` works here (unlike the FIPS case):**
The DER bytes are a direct, stable pointer in native memory by the time the
uprobe fires — no two-hop dereference is needed.  The thread-local buffer
ensures the GC cannot move the data between the Java copy and the eBPF read.
No `CAP_SYS_PTRACE` or `/proc/<pid>/mem` access is required.

---

### test_tls_port_probe (Python)

Exercises the end-to-end port-probe pipeline: `security_socket_bind` kprobe →
cert_analyzer bind event handler → TLS handshake back to the server →
certificate extraction and Prometheus metric emission.

This test uses `tls-service-tracking.yaml` (the experimental LSM hook variant),
which hooks all TCP binds with no binary filter.  The fixed variant
(`tls-service-tracking-fixed.yaml`) retains a `matchBinaries` allowlist for
production use where event volume must be controlled.

**Prerequisites:**

```bash
# cert_analyzer must have the inbound bind probe enabled:
# [port_probe]
# bind_probe_enabled = true
# in /etc/cert-analyzer/cert-analyzer.conf  (or BIND_PROBE_ENABLED=true env var)
```

**Step 1 — Load the policy:**

```bash
sudo tetra tracingpolicy add \
    tetragon-policies/experimental/tls-service-tracking.yaml
```

**Step 2 — Run the probe test:**

```bash
# Generate test cert first — see "Generate test certificates" above
CERT=/etc/pki/tls/certs/cert-analyzer-test.crt
KEY=/etc/pki/tls/certs/cert-analyzer-test.key

python3 probe_tests/test_tls_port_probe.py --cert "$CERT" --key "$KEY"
python3 probe_tests/test_tls_port_probe.py --cert "$CERT" --key "$KEY" --port 9443
python3 probe_tests/test_tls_port_probe.py --cert "$CERT" --key "$KEY" --pause
```

**Step 3 — Verify cert_analyzer output** (within a few seconds of the bind):

```
🔍 TLS probe: discovered cert at 127.0.0.1:8443 CN=valid.example.com process=...
✅ OK: tls-probe://127.0.0.1:8443 (process=... CN=valid.example.com) valid for ...
```

**Step 4 — Verify Prometheus metric:**

```bash
curl -s http://localhost:9090/metrics | grep tls_port_probes_total
# Expected:
# tls_port_probes_total{status="success"} 1
```

**Step 5 — Remove the policy:**

```bash
sudo tetra tracingpolicy delete tls-service-tracking
```

**Pipeline summary:**

| Step | Component | What happens |
|---|---|---|
| 1 | Python script | Binds TLS server to `0.0.0.0:8443` |
| 2 | Tetragon | `security_socket_bind` kprobe fires; event delivered to cert_analyzer via gRPC |
| 3 | cert_analyzer `_handle_tls_bind_event` | Extracts port; checks `_probed_endpoints` and `_probe_in_flight` (O(1)) — returns immediately if already probed or in flight; otherwise resolves probe IP via `/proc/<pid>/net/fib_trie` (K8s) or falls back to `127.0.0.1` (bare metal) and spawns probe thread |
| 4 | cert_analyzer `_probe_tls_endpoint` | Connects to `127.0.0.1:8443`, completes TLS handshake, reads leaf cert via `getpeercert(binary_form=True)` |
| 5 | cert_analyzer | Parses DER cert, registers endpoint in `_probed_endpoints`, updates Prometheus metrics, emits log line, publishes to Kafka if configured |

**Production note:**

`tls-service-tracking.yaml` hooks all TCP binds with no binary filter, making it
suitable for broad coverage but potentially noisy on busy hosts.
`tls-service-tracking-fixed.yaml` retains a `matchBinaries` allowlist (nginx,
httpd) for deployments where event volume must be controlled — add any additional
TLS server binaries there as needed.

---

### test_tcp_connect_probe (Python)

Exercises the end-to-end outbound port-probe pipeline: `tcp_connect` kprobe →
cert_analyzer connect event handler → TLS handshake back to the same server →
certificate extraction and Prometheus metric emission.

Unlike the bind probe test (where the script only runs the server and cert_analyzer
acts as the client), this test plays both roles.  It binds a local TLS server on
port 9093, then makes an outbound `socket.connect()` to it — the connect fires
the `tcp_connect` kprobe.  cert_analyzer receives the destination address and port
from the `sock_arg`, then independently probes that endpoint to retrieve the leaf
certificate.

Port 9093 (Kafka TLS) is used because it is already in the `tcp-connect-tls.yaml`
DPort filter, does not require root, and is unlikely to be in use on test machines.

**Prerequisites:**

```bash
# cert_analyzer must have the outbound connect probe enabled:
# [port_probe]
# connect_probe_enabled = true
# in /etc/cert-analyzer/cert-analyzer.conf  (or CONNECT_PROBE_ENABLED=true env var)
```

**Step 1 — Load the policy:**

```bash
sudo tetra tracingpolicy add tetragon-policies/tcp-connect-tls.yaml
```

**Step 2 — Run the probe test:**

```bash
# Uses test-certs/valid.crt and valid.key by default
python3 probe_tests/test_tcp_connect_probe.py

# Custom cert / port (port must be in tcp-connect-tls.yaml DPort filter):
python3 probe_tests/test_tcp_connect_probe.py --cert /etc/pki/tls/certs/cert-analyzer-test.crt \
    --key /etc/pki/tls/certs/cert-analyzer-test.key --port 8443

# Keep server running after the wait period (useful for inspecting events):
python3 probe_tests/test_tcp_connect_probe.py --pause
```

**Step 3 — Verify cert_analyzer output** (within a few seconds of the connect):

```
🔍 TLS probe: discovered cert at 127.0.0.1:9093 CN=valid.example.com process=...
✅ OK: tls-probe://127.0.0.1:9093 (process=... CN=valid.example.com) valid for ...
```

**Step 4 — Verify Prometheus metric:**

```bash
curl -s http://localhost:9090/metrics | grep tls_port_probes_total
# Expected:
# tls_port_probes_total{status="success"} 1
```

**Step 5 — Remove the policy:**

```bash
sudo tetra tracingpolicy delete tcp-connect-tls
```

**Pipeline summary:**

| Step | Component | What happens |
|---|---|---|
| 1 | Python script | Starts TLS server on `127.0.0.1:9093` |
| 2 | Python script | Calls `socket.connect(("127.0.0.1", 9093))` — fires `tcp_connect` kprobe |
| 3 | Tetragon | `tcp_connect` kprobe fires; event with `sock_arg.daddr=127.0.0.1, sock_arg.dport=9093` delivered to cert_analyzer via gRPC |
| 4 | cert_analyzer `_handle_tls_connect_event` | Port matches `TLS_OUTBOUND_PORTS`; checks `_probed_endpoints` and `_probe_in_flight` (O(1)) — returns immediately if already probed or in flight; otherwise spawns probe thread (no connect delay) |
| 5 | cert_analyzer `_probe_tls_endpoint` | Connects to `127.0.0.1:9093`, completes TLS handshake, reads leaf cert via `getpeercert(binary_form=True)` |
| 6 | cert_analyzer | Parses DER cert, registers endpoint in `_probed_endpoints`, updates Prometheus metrics, emits log line, publishes to Kafka if configured |

**How this differs from test_tls_port_probe:**

The inbound probe test only needs to bind a server — cert_analyzer probes it
reactively when it sees the bind event.  The outbound probe test must also make
the client-side connect itself, because the kprobe trigger is the connect, not
the bind.  Both tests use the same `_probe_tls_endpoint` path inside cert_analyzer;
the difference is which Tetragon event starts the chain.
