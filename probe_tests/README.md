# probe_tests

Programs that exercise the Tetragon uprobe hooks defined in
`tetragon-policies/experimental/`. Run these with Tetragon active to confirm
that `cert_analyzer.py` receives the expected events.

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
./test_openssl3_cert_load                        # run all three tests
./test_openssl3_cert_load --test 1               # SSL_CTX_use_certificate_file only
./test_openssl3_cert_load --test 2               # SSL_CTX_use_certificate_chain_file only
./test_openssl3_cert_load --test 3               # SSL_CTX_use_certificate_ASN1 only (embedded cert, no file needed)
./test_openssl3_cert_load --test 1 --pause       # run test 1 then hold — useful for inspecting Tetragon events
./test_openssl3_cert_load /path/to/other.crt     # custom cert for tests 1 & 2
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
# Outputs: cert-agent.jar
#          /opt/cert-agent/libcert_agent_stub.so  (installed by build.sh)
```

`build.sh` installs `libcert_agent_stub.so` to `/opt/cert-agent/` automatically,
which is the same path `java-non-fips-cert.yaml` expects in production — no yaml
edits needed for local testing.

**Attach dynamically to a running JVM** (requires `jattach`):
```bash
# install: https://github.com/jattach/jattach
AGENT=$(pwd)/cert-agent.jar
LIB=/opt/cert-agent/libcert_agent_stub.so
jattach <pid> load instrument false ${AGENT}=${LIB}
```

**Or inject statically** (requires JVM restart):
```bash
java -javaagent:$(pwd)/cert-agent.jar=/opt/cert-agent/libcert_agent_stub.so \
     -jar yourapp.jar
```

**Automate deployment** across all running JVMs with the deployer:
```bash
python3 java_agent_deployer.py \
    --agent-jar $(pwd)/cert-agent.jar \
    --native-lib /opt/cert-agent/libcert_agent_stub.so
# Scans /proc every 30s, tries jattach for each new JVM,
# and prints -javaagent instructions for any that reject dynamic attach.
```

| Hook | What fires it | How cert bytes reach cert_analyzer |
|---|---|---|
| `KeyStore.setCertificateEntry` (instrumented by agent) | Any explicit cert store: `KeyStore.setCertificateEntry(alias, cert)` | Agent calls `cert.getEncoded()` → copies DER to thread-local native buffer → calls `java_cert_agent_write(buf, len)` → Tetragon `char_buf` → `_handle_uprobe_in_memory_cert` |

**Why `char_buf` works here (unlike the FIPS case):**
The DER bytes are a direct, stable pointer in native memory by the time the
uprobe fires — no two-hop dereference is needed.  The thread-local buffer
ensures the GC cannot move the data between the Java copy and the eBPF read.
No `CAP_SYS_PTRACE` or `/proc/<pid>/mem` access is required.
