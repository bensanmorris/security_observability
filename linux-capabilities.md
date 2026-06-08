# cert-analyzer: Required Linux Capabilities

This document lists the minimum Linux capabilities required by each component.

---

## Component Summary

| Capability | cert-analyzer | cert-agent-deployer | cert-agent-jni | Tetragon |
|---|:---:|:---:|:---:|:---:|
| `CAP_SYS_PTRACE` | ✓ | ✓ | — | ✓ |
| `CAP_DAC_READ_SEARCH` | — | ✓ | — | — |
| `CAP_KILL` | — | ✓ | — | — |
| `CAP_SETUID` | — | ✓ | — | — |
| `CAP_SETGID` | — | ✓ | — | — |
| `CAP_BPF` | — | — | — | ✓ |
| `CAP_PERFMON` | — | — | — | ✓ |
| `CAP_NET_ADMIN` | — | — | — | ✓ |
| `CAP_SYS_ADMIN` | — | — | — | ✓ |
| `CAP_SYS_RESOURCE` | — | — | — | ✓ |
| `CAP_IPC_LOCK` | — | — | — | ✓ |

---

## Per-Component Detail

### cert-analyzer
Runs as the dedicated non-privileged `cert-analyzer` system user.

| Capability | Reason |
|---|---|
| `CAP_SYS_PTRACE` | Resolves truncated binary paths reported by Tetragon via `/proc/{pid}/exe` for JVM processes owned by other users. |

### cert-agent-deployer
Runs as `root`. jattach requires elevated privileges to attach to JVMs owned by arbitrary users.

| Capability | Reason |
|---|---|
| `CAP_SYS_PTRACE` | Reads `/proc/{pid}/exe` to identify JVM processes owned by users other than root. |
| `CAP_DAC_READ_SEARCH` | Opens `/proc/{pid}/cmdline` for processes owned by any UID to log attach failures with full context. |
| `CAP_KILL` | Sends `SIGQUIT` to the target JVM to wake its attach listener. Without this cap, `kill(2)` returns `EPERM` when the JVM runs as a different UID, even for UID 0 once the cap is dropped from the bounding set. |
| `CAP_SETUID` | jattach calls `setresuid()` to switch credentials to match the target JVM before connecting to its attach socket. Required even for UID 0 when absent from the capability bounding set. |
| `CAP_SETGID` | As above, for `setresgid()` to switch the group credential. |

### cert-agent-jni
Runs as a Java instrumentation agent loaded inside the target JVM process. It has no independent process identity and requires no additional capabilities beyond those already held by the JVM.

### Tetragon
Runs as `root` with no `CapabilityBoundingSet` restriction in its service unit (i.e. full capabilities). The capabilities it exercises for eBPF-based observability are:

| Capability | Reason |
|---|---|
| `CAP_BPF` | Load and manage eBPF programs and maps (Linux 5.8+; falls back to `CAP_SYS_ADMIN` on older kernels). |
| `CAP_PERFMON` | Attach to perf events used by eBPF programs (Linux 5.8+; falls back to `CAP_SYS_ADMIN`). |
| `CAP_NET_ADMIN` | Attach TC and XDP eBPF programs for network observability. |
| `CAP_SYS_ADMIN` | Required for cgroup access, BPF token operations, and as a fallback on kernels < 5.8. |
| `CAP_SYS_PTRACE` | Read process information from `/proc` and attach uprobes to arbitrary processes. |
| `CAP_SYS_RESOURCE` | Raise `RLIMIT_MEMLOCK` to allow locking BPF maps in memory. |
| `CAP_IPC_LOCK` | Lock BPF map memory to prevent it from being swapped out. |
