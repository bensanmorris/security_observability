# CertSight — Presentation Q&A Reference

Questions and answers covering architecture, bare metal deployment, Kubernetes deployment, scale, security, roadmap, and the Java JCA/JNI hooking mechanism.

---

## Architecture & Detection

**How does CertSight avoid needing a network scanner or CA impersonation?**
It hooks the kernel and crypto libraries directly via eBPF. The `fd_install` kprobe fires when any process installs a file descriptor — including certificate files — so CertSight sees the cert at the moment the process opens it, before any network traffic occurs. OpenSSL/NSS uprobes hook the post-handshake certificate object in memory. No ports need to be open, no MITM is required, and no private keys are ever read.

**What happens with statically linked crypto?**
This is a known gap, called out explicitly in the comparison table. Statically linked binaries (common in Go) don't call `libssl.so`, so the uprobes don't fire and the `fd_install` kprobe only catches file-backed certs, not in-memory ones. Java is the exception — the JCA agent bridges that gap for JVM workloads regardless of FIPS mode.

**The `fd_install` kprobe fires on writes too, not just reads — doesn't that mean you see certs being generated, not just loaded?**
Yes. The `cert-test-generator` demo actually relies on this — it writes cert files and Tetragon still fires on the `fd_install`. In practice this is generally a feature rather than noise: a cert being written is also a cert you want to track. The `filter_self_events` config option handles the specific case of the analyzer opening files itself.

**How do you detect in-memory certificates without a network tap?**
The OpenSSL uprobes hook `SSL_read` (or equivalent) inside `libssl.so` at the point after the TLS handshake completes. The certificate object is in the process's heap at that point. Tetragon reads the memory and emits the DER/PEM bytes as event arguments — no private key is ever touched.

---

## Bare Metal Deployment

**What's the Tetragon dependency story?**
Tetragon is a hard dependency — the installer fails with a clear error if it's not found. CertSight consumes Tetragon's gRPC socket (`/run/tetragon/tetragon.sock`) and applies its own `TracingPolicy` resources. Running alongside Falco is fine at the kernel level, but there's no Falco integration path — all policy-based detection goes through Tetragon.

**RHEL 8 vs RHEL 9 — what's the actual kernel constraint that forces the policy split?**
Three stacked issues: (1) underscores are invalid in Tetragon policy names on older kernels, (2) dots break the bpffs directory creation on kernel 4.18 (RHEL 8), and (3) string uprobe arguments require `bpf_copy_from_user_str` which only landed in kernel 6.3+. That's why the OpenSSL uprobe policies are split — `openssl1_1-cert-load.yaml` for RHEL 8 (OpenSSL 1.1), `openssl3-cert-load.yaml` for RHEL 9 (OpenSSL 3).

**How does the Java agent deployer find running JVMs and what happens in the 30-second gap?**
The deployer scans `/proc` every 30 seconds, identifies JVM processes by resolving `/proc/<pid>/exe`, and uses `jattach` to inject `cert-agent.jar`. A JVM that starts and loads certificates within that window before the next scan will be missed for that initial load — though any subsequent cert operations after injection will be caught. The uprobe is installed on the `libcert_agent_stub.so` file inode, so once the library is loaded into a JVM, it fires for that process going forward with no ordering constraint.

**What happens if Tetragon restarts — do policies reload automatically?**
Policies applied via `apply-policies.sh` are persisted to `/etc/tetragon/tetragon.tp.d/` so they survive Tetragon restarts and are reloaded automatically on startup. The cert-analyzer service reconnects to the gRPC socket; a previous bug where the socket remained `root:root` after a crash loop (fixed in the 0.49 RPM) would have broken this — the `ExecStartPost` race caused the socket to have wrong permissions before the systemd drop-in could fix ownership.

**What capabilities does the cert-agent-deployer actually need?**

| Capability | Reason |
|---|---|
| `CAP_SYS_PTRACE` | Read `/proc/<pid>/exe` for JVMs owned by other users |
| `CAP_DAC_READ_SEARCH` | Open `/proc/<pid>/cmdline` for processes owned by any UID |
| `CAP_KILL` | Signal JVMs owned by a different user (required by the attach protocol) |
| `CAP_SETUID` / `CAP_SETGID` | `jattach` switches credentials to match the target JVM before connecting to its attach socket; `setresuid`/`setresgid` require these even for root once absent from the bounding set |

**The `PrivateTmp` issue — what was the symptom and how would an operator have diagnosed it?**
The deployer uses `/tmp` to pass a handshake socket path to `jattach`. With `PrivateTmp=true` in the systemd unit, the deployer's `/tmp` is a private namespace that the target JVM process can't see, so the handshake fails silently. The symptom was `jattach` reporting success but the agent never loading. The fix was removing `PrivateTmp` from the deployer's unit.

---

## Kubernetes Deployment

**Why is `host_prefix` set to `/host` for Kubernetes?**
cert-analyzer runs in a container with the host filesystem bind-mounted at `/host`. Certificate paths that Tetragon reports are host-namespace paths (e.g. `/etc/ssl/certs/ca.pem`). To open those files from inside the container, the analyzer must prepend `/host`. On bare metal the process and the filesystem are in the same namespace, so the prefix is empty.

**Does CertSight also run as a DaemonSet?**
Yes — `kubernetes/deployment.yaml` deploys it as a DaemonSet so every node is covered. It needs access to the Tetragon socket and the host filesystem mount but does not itself load eBPF programs — that's Tetragon's job.

**How does pod/namespace enrichment work and what RBAC does it require?**
Tetragon embeds pod name, namespace, workload kind/name, and labels directly in the `process_kprobe` event proto — no API call needed for those. cert-analyzer then makes a secondary Kubernetes API call to add `container_name` and `container_image`, which requires `get`/`list` on `pods` in the relevant namespaces.

**Tetragon reports the container namespace path — how does cert-analyzer open it via `/host`?**
This is a known limitation. The container-namespace path (e.g. `/test-certs/cert.pem`) doesn't map to a predictable host path via the `/host` bind mount. The periodic scanner isn't affected because it reads `/host/...` paths directly. For Tetragon-driven detection with full pod context, the recommended workaround is a separate pod that reads the cert files — those read events carry the reader pod's workload identity.

**What about ephemeral containers or short-lived Jobs that load certs and exit before CertSight processes the event?**
If the process exits before cert-analyzer processes the event from the gRPC stream, the cert data is still in the Tetragon event — Tetragon buffers events in its ring buffer and streams them. The process context (pid, binary) will be in the event even if the process is already gone. There's no explicit replay mechanism for missed events if cert-analyzer itself was down.

**Can this run on EKS/GKE managed clusters?**
Tetragon requires privileged DaemonSet pods and kernel BTF support (kernel ≥ 5.8 with `CONFIG_DEBUG_INFO_BTF`). EKS with AL2/AL2023 nodes and GKE with Container-Optimized OS both satisfy this, but the node pool must allow privileged pods and `hostPath` mounts for `/sys/kernel/debug`. Fully managed Autopilot-style clusters that lock down privileged workloads would block deployment.

---

## Scale & Performance

**LRU eviction — what happens to a rotated cert?**
When the LRU evicts an entry and the same path reappears with a new serial number, cert-analyzer re-analyzes it as a fresh discovery. A `tls_certificate_rotations_total` counter tracking serial changes at the same path is on the roadmap but not yet implemented — so today rotation is visible as a re-detection, not an explicit rotation event.

**The outbound connect probe dedup — what's the lifetime of that entry?**
It's O(1) dedup with no TTL — each unique `host:port` is probed at most once per cert-analyzer process lifetime. This means a remote server rotating its certificate would not trigger a re-probe unless cert-analyzer restarts. This is the right trade-off for a high-connection-rate host (avoids probe storms) but is a gap for tracking remote cert rotation.

**On a node with thousands of outbound TLS connections, what's the per-event overhead from the eBPF hooks?**
The `perf_tests/` directory contains `cert_agent_hook_overhead.py` and a companion Java perf test (`CertAgentPerfTest`) that measure hook overhead. Refer to `perf_tests/README.md` for benchmark methodology and results.

---

## Security & Compliance

**FIPS compliance checking — what about the TLS handshake cipher suite itself?**
The current FIPS check is cert-centric: key type, minimum key size, approved curves (P-256, P-384, P-521), and signature hash. The cipher suite negotiated during the handshake is not inspected — that would require hooking the handshake itself rather than the certificate load. It's a meaningful gap: a FIPS-compliant cert can be served over a non-FIPS cipher suite and CertSight won't flag it.

**JKS/PKCS12 passwords in a plaintext config file — what's the threat model?**
The config file at `/etc/cert-analyzer/cert-analyzer.conf` is owned by root and preserved across upgrades. The threat model assumes the host is not already compromised — the passwords are needed to open keystores to read certificate metadata, not to use the private key. If the host is compromised, the attacker already has access to the keystore file itself.

**Rogue CA detection is on the roadmap — how would you build the baseline?**
The roadmap describes it as a per-CN/SAN issuer history — tracking which issuers have historically signed certs for a given identity and alerting when a new issuer appears. The natural storage location would be the existing LRU cache (extended with issuer history per path/CN) or an external store for fleet-wide correlation. Not yet implemented.

---

## Roadmap / Competitive Positioning

**OCSP revocation checking — what's the blocker?**
Latency and reliability. OCSP responders are external services with variable availability; a synchronous check on every cert discovery event would add latency and introduce a hard external dependency. The design would need async checks with aggressive caching and a configurable timeout — doable but non-trivial to make robust. It's described as the most significant functional gap and a genuine differentiator if solved.

**How does this compare to cert-manager or Vault PKI?**
Those tools manage certificate issuance — they know about certs they issued. CertSight observes runtime execution: it sees certs loaded by applications that cert-manager never touched, certs imported from external PKIs, certs bundled inside JARs, and certs that were supposed to have been rotated but weren't. The two are complementary, not competing.

**What's the migration path from scheduled `openssl s_client` sweeps?**
The port probe (`bind_probe_enabled`) is a direct replacement — it triggers a TLS handshake against bound ports without any port sweep, giving the same served-cert visibility. The key addition is that CertSight also sees certs that are never served on a network port (file-backed, in-memory, Java keystore), which sweeps miss entirely.

---

## Java JCA/JNI Hooking

### The Big Picture

**Why do you need a Java agent at all? Can't you just uprobe a JVM method directly?**
Java methods are JIT-compiled at runtime — their addresses aren't stable, and they don't exist at a fixed symbol in a shared library until the JIT decides to compile them. There's no static symbol to attach a uprobe to. The Java agent bypasses this by instrumenting the JCA method at the bytecode level and routing cert bytes through a native stub function (`java_cert_agent_write` in `libcert_agent_stub.so`) which does have a stable, resolved symbol that Tetragon can uprobe.

**What is the end-to-end chain from Java cert operation to Prometheus metric?**
1. `KeyStore.setCertificateEntry` is called by the application
2. ASM bytecode instrumentation inserted at method entry calls `NativeBridge.reportCertificate(cert)`
3. `NativeBridge` calls `cert.getEncoded()` to get DER bytes, then passes them to the native JNI method `writeCertificateBytes(byte[])`
4. The C JNI function copies the DER bytes into a thread-local native buffer and calls `java_cert_agent_write(buf, len)`
5. Tetragon's uprobe fires at the entry of `java_cert_agent_write` and reads `buf[0..len-1]` as a `char_buf`
6. `cert_analyzer._handle_uprobe_in_memory_cert()` parses the DER and emits Prometheus metrics — the same handler used for OpenSSL's `SSL_CTX_use_certificate_ASN1`

**Why `KeyStore.setCertificateEntry` specifically? What does it miss?**
It's the canonical JCA call for explicitly storing a certificate — it fires for both file-backed keystores and in-memory operations. It misses certificates that are only read from a keystore (via `getCertificate`) without being explicitly stored, and certificates that bypass `KeyStore` entirely (e.g. raw `CertificateFactory.generateCertificate` results used directly without storing). In practice the vast majority of cert lifecycle operations go through `setCertificateEntry`.

---

### Bytecode Instrumentation (ASM)

**Why ASM rather than a higher-level instrumentation library like ByteBuddy?**
ASM is the lower-level choice and is appropriate here because the target (`java.security.KeyStore`) is a bootstrap class — it's loaded by the bootstrap classloader before the application classloader exists. Higher-level libraries often rely on class resolution mechanisms that fail at the bootstrap boundary. ASM gives direct control over bytecode without those assumptions. The agent bundles ASM directly into `cert-agent.jar` as a fat JAR to avoid version conflicts with any ASM the target application might already bundle.

**Why `COMPUTE_MAXS` and not `COMPUTE_FRAMES`?**
`COMPUTE_FRAMES` causes ASM to call `getCommonSuperClass` to compute stack-map frames, which internally uses `Class.forName`. Under Java 11's module system, resolving types across named/unnamed module boundaries during dynamic retransformation fails because the bootstrap `ClassWriter` can't resolve types that live in the application's module graph. `COMPUTE_MAXS` avoids this entirely — it only recomputes max-stack and max-locals while preserving the existing stack-map frames from the `ClassReader`. Inserting a single `invokestatic` call at method entry doesn't invalidate any existing frames, so this is sufficient.

**Why does the transformer call `inst.retransformClasses(KeyStore.class)`?**
When the agent is injected dynamically via `jattach`, `KeyStore` is already loaded. Without retransformation the instrumentation only applies to classes loaded after the agent attaches. Calling `retransformClasses` forces the JVM to re-run the transformer against the already-loaded `KeyStore` bytecode so the hook is active immediately, not just for future class loads.

---

### Classloader Split

**What was the classloader split bug, and why does it matter?**
`KeyStore` is a bootstrap class. The instrumented bytecode inserts an `invokestatic` call to `NativeBridge.reportCertificate`. For that call to resolve, `NativeBridge` must be visible from the bootstrap classloader — but by default the agent's JAR is only on the agent classloader. The fix is `Instrumentation.appendToBootstrapClassLoaderSearch(agentJar)`, which adds the JAR to the bootstrap classpath so `NativeBridge` is resolvable from the context where `KeyStore` lives.

**Why can't `NativeBridge.loadLibrary()` be called from `CertAgent.setup()`?**
The JVM only allows a native library to be associated with one classloader. If `CertAgent.setup()` (running in the agent classloader) calls `System.load(libPath)`, then when the bootstrap classloader later initialises `NativeBridge` (triggered by the first `setCertificateEntry` call), its attempt to load the same library fails with "already loaded in another classloader" — leaving `loaded = false` in the bootstrap copy. The fix is to not load the library in the agent classloader at all. Instead, `CertAgent.setup()` writes the path into the system property `com.security.certagent.lib`, and `NativeBridge`'s static initialiser (which runs in the bootstrap context) reads the property and calls `System.load` — so the library is owned exclusively by the bootstrap classloader.

---

### The Native Stub

**Why does the native stub exist at all? Why not have NativeBridge call a JNI method that Tetragon probes?**
Tetragon resolves uprobe targets by symbol name in a shared library. A JNI method like `Java_com_security_certagent_NativeBridge_writeCertificateBytes` is a valid symbol, but the `char_buf` uprobe argument capture mechanism requires the DER pointer and length to be in registers `RDI` and `RSI` at function entry (x86-64 ABI). The JNI signature passes `JNIEnv*` and `jclass` first, shifting the cert pointer to `RDX`, which breaks the `char_buf` read. The dedicated `java_cert_agent_write(const char *buf, int len)` stub has exactly the right signature for `char_buf` capture with no offset correction needed.

**What was the `retq` stub bug?**
GCC optimised the semantically-empty stub body to a single `retq` instruction. The Linux uprobe infrastructure replaces the first instruction byte with `int3`. With `retq` as the first instruction, the CPU hits the breakpoint with an ambiguous register state — the arguments haven't been loaded into registers yet. Tetragon reads zero or garbage for the `char_buf`. The fix is the `volatile int _len = len` write and an inline `asm` constraint `"r"(buf), "r"(len)`, which forces GCC to emit a proper function prologue (stack frame, argument loads) before the asm site, giving the uprobe a stable attach point where `RDI=buf` and `RSI=len` as the ABI requires.

**Why a thread-local buffer instead of passing the Java `byte[]` directly?**
Java heap arrays can be moved by the GC at any time. The `GetByteArrayRegion` JNI call copies the DER bytes into native memory that the GC cannot move. Using `__thread` (thread-local storage) avoids allocation overhead on every cert event and ensures the buffer is not shared between concurrent threads — important on busy JVMs handling multiple connections simultaneously. The pointer passed to `java_cert_agent_write` is therefore stable at the uprobe site.

**Is there a maximum cert size?**
Yes — the JNI function caps at 65536 bytes (`if (len <= 0 || len > 65536) return`). DER-encoded X.509 certificates are comfortably below 64 KiB in practice, so this is not a real constraint.

---

### FIPS vs Non-FIPS

**Why does FIPS mode change the hooking strategy entirely?**
In non-FIPS mode, Java's JSSE uses pure-Java crypto — no native library calls occur at the certificate loading level, so there's nothing to uprobe in any shared library. In FIPS mode, Red Hat's JDK redirects all crypto operations through `libsoftokn3.so` (NSS) via the `SunPKCS11-NSS-FIPS` provider. That native path does have stable hookable symbols: `NSC_CreateObject` (certificate storage) and `NSC_FindObjectsInit` (certificate enumeration).

**Why can't the FIPS path use `char_buf` like the non-FIPS path?**
The cert DER bytes are not a direct argument to `NSC_CreateObject`. They're nested inside a `CK_ATTRIBUTE[]` array: the function receives a `CK_ATTRIBUTE_PTR pTemplate` pointer → which points to an array of structs → each struct has a `pValue` pointer → which points to the actual data. Tetragon's eBPF policy cannot chain two `bpf_probe_read_user` calls, so it captures the template pointer and count as `uint64` values. `cert_analyzer` then walks this two-hop indirection via `/proc/<pid>/mem` in Python — which requires `CAP_SYS_PTRACE` or root.

**What does `NSC_FindObjectsInit` tell you vs `NSC_CreateObject`?**
`NSC_FindObjectsInit` fires when Java enumerates objects in the NSS token (e.g. during `KeyStore.load(null, null)`). It provides process-level attribution — who is reading the cert store and when — but doesn't yield cert bytes directly. `NSC_CreateObject` fires when a certificate is actually stored into the NSS token (e.g. `KeyStore.setCertificateEntry`), and is where the DER bytes can be extracted via the template walk.

**The FIPS policy requires `nss-softokn` debuginfo — why?**
The symbols `NSC_CreateObject` and `NSC_FindObjectsInit` are not exported in the stripped RHEL package. Tetragon resolves them via build-ID debuginfo lookup. Without the debuginfo package installed the uprobe fails to attach silently and no events are emitted.

---

### Dynamic vs Static Injection

**How does dynamic injection work mechanically?**
The deployer scans `/proc` every 30 seconds, identifying JVM processes by resolving `/proc/<pid>/exe` and checking the binary name against a known set (`java`, `java11`, `java17`, `java21`). For each newly-seen PID it runs:

```
jattach <pid> load instrument false /opt/cert-agent/cert-agent.jar=/opt/cert-agent/libcert_agent_stub.so
```

`jattach` implements the JVM Attach API protocol: it writes a trigger file into the JVM's attach socket directory, signals the JVM to open its attach listener socket in `/tmp`, connects to that socket, and sends a `load` command. The JVM's attach listener invokes `Instrumentation` via the `agentmain` entry point — the same path as `premain` for static agents, just entered at runtime.

**When does static injection apply and how do you use it?**
Static injection is required when:
- The JVM was started with `-XX:+DisableAttachMechanism`, which prevents any runtime attach
- Java 21+ with `-XX:-EnableDynamicAgentLoading` (the default on JDK 21 is a warning; future versions may enforce it)
- The JVM process owner cannot be matched by the deployer (e.g. a heavily sandboxed container)
- Short-lived JVM processes that may not survive the 30-second scan window

Add the flag to the JVM startup command:

```bash
java -javaagent:/opt/cert-agent/cert-agent.jar=/opt/cert-agent/libcert_agent_stub.so \
     -jar yourapp.jar
```

The `premain` entry point runs before `main`, so `KeyStore` is instrumented before any application code executes — there is no coverage gap.

**How does the deployer surface the static flag when dynamic attach fails?**
When `jattach` returns a non-zero exit code, the deployer reads `/proc/<pid>/cmdline` to reconstruct the original command line and logs:

```
Could not dynamically attach to PID <pid> (<original cmdline>).
  Add this flag to the JVM command line on next restart:
    -javaagent:/opt/cert-agent/cert-agent.jar=/opt/cert-agent/libcert_agent_stub.so
```

This surfaces in `journalctl -u cert-agent-deployer` so operators know which services need a one-time restart to pick up static injection.

**What happens if the deployer injects into the same JVM twice?**
The deployer maintains an in-memory `seen_pids` set and only attempts injection for PIDs not already in it, preventing re-injection within a single deployer lifetime. On deployer restart that set is lost. A second `agentmain` invocation would register a second transformer, resulting in duplicate cert events for that JVM until it restarts. The native library itself is not double-loaded due to the `if (loaded) return` guard in `NativeBridge`.

**The uprobe is on the `.so` inode — what does that mean for deployment ordering?**
Tetragon installs the uprobe on the `libcert_agent_stub.so` file inode when the policy is loaded. Any JVM that subsequently loads the library — whether via the deployer or via `-javaagent:` at startup — triggers the hook automatically. There is no ordering constraint between the Tetragon policy load and either injection method.

**Does static injection require any changes to the Tetragon policy or cert-analyzer?**
No. Whether the library was loaded by dynamic injection or by static `-javaagent:` at JVM startup, the same inode is mapped into the JVM process and the same uprobe fires. `cert_analyzer` handles the event identically in both cases via `_handle_uprobe_in_memory_cert`.

**Can the agent be used without the deployer service at all?**
Yes. The deployer is a convenience for fleets where you don't control JVM startup flags. If you can modify JVM startup (e.g. via a systemd unit, container `CMD`, or application server config), static `-javaagent:` is simpler, has no coverage gap, and avoids the `ptrace` capability requirement entirely. The deployer is primarily useful for brownfield environments where restarting every JVM service to add a flag is not immediately practical.
