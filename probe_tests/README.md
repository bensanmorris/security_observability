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
