"""
Registry of certificate-detection test use cases for the test HTTP server.

Each use case performs a real action against this host (a real file read,
eventually a real TLS handshake, etc.) so that a locally running Tetragon +
cert-analyzer pick it up exactly as they would in production -- there is
nothing test-server-specific inside cert-analyzer's own detection path.

To add a use case: append a UseCase to USE_CASES with a run() callable that
performs the action and returns a UseCaseResult. Nothing else needs to
change -- server.py and the frontend both read this list at request time.
"""
import ctypes
import queue
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, List, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@dataclass
class UseCaseResult:
    ok: bool
    detail: str


@dataclass
class UseCaseParam:
    name: str                # key in the JSON body POSTed to /api/run/<id>
    label: str                # shown next to the <select> in the UI
    options: List[str]        # values shown and sent as-is; run() is responsible for validating
    default: str


@dataclass
class UseCase:
    id: str
    label: str
    description: str
    run: Callable[[dict], UseCaseResult]
    pipeline: List[str] = None  # ordered steps from click to Kafka event, shown as a disclosure in the UI
    params: List[UseCaseParam] = None  # rendered as <select> controls; run() receives the chosen values as a dict


# cert-analyzer's known-certs dedup key is "path:index:serial" (see
# agent/analyzer.py) -- a cert written to a never-before-seen path is
# therefore always a first-time discovery, regardless of anything already
# cached from earlier test runs. Generated certs accumulate here; cert-
# analyzer never needs them again once processed, so it's safe to delete
# the directory's contents by hand at any time.
#
# Deliberately /dev/shm, not /tmp: cert-analyzer's systemd unit runs with
# PrivateTmp=true, which gives it its own private /tmp and /var/tmp mount
# namespace -- a file this script writes to the host's /tmp is invisible to
# cert-analyzer's process, so Path(cert_path).is_file() fails there and it
# silently skips the cert ("Skipping non-regular-file cert path" in its
# logs). /dev/shm isn't remapped by PrivateTmp and isn't hidden by
# ProtectHome=true (which only covers /home, /root, /run/user) or
# ProtectSystem=strict (which leaves /dev alone), so it's visible to both
# this script and cert-analyzer, and world-writable like /tmp.
_GENERATED_CERT_DIR = Path("/dev/shm/certsight-test-server")

# CertSight's FIPS compliance checker (agent/fips_compliance_checker.py)
# flags RSA keys under 2048 bits, so 1024 reliably triggers a
# fips_compliant=false Kafka event; 2048+ stays compliant. Server-side
# allowlist rather than trusting the raw client-supplied value: this
# endpoint is reachable over the network with no authentication (see
# TEST-SERVER-README.md), so an arbitrary key_size could be used to force
# an expensive RSA keygen (mild CPU-DoS) or simply fail oddly.
_ALLOWED_KEY_SIZES = ["1024", "2048", "3072", "4096"]
_DEFAULT_KEY_SIZE = "2048"


def _generate_self_signed_cert(cn: str, key_size: int) -> Tuple[bytes, bytes]:
    """Returns (cert_pem, key_pem) for a fresh self-signed cert, 1yr validity, SAN=cn."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _generate_and_read_fresh_cert(params: dict) -> UseCaseResult:
    key_size_str = params.get("key_size", _DEFAULT_KEY_SIZE)
    if key_size_str not in _ALLOWED_KEY_SIZES:
        return UseCaseResult(
            ok=False,
            detail=f"invalid key_size '{key_size_str}' -- must be one of {_ALLOWED_KEY_SIZES}",
        )
    key_size = int(key_size_str)

    token = uuid.uuid4().hex[:12]
    cn = f"certsight-test-{token}.local"
    path = _GENERATED_CERT_DIR / f"generated-{token}.crt"

    # On a host with FIPS mode actually enforced at the OpenSSL provider
    # level, generating a sub-2048 RSA key can itself be refused (NIST SP
    # 800-131A disallows RSA keygen below 2048 bits under FIPS) -- which is
    # a legitimate, informative outcome for a FIPS-focused test tool, not a
    # bug, so surface it as a normal use-case failure rather than a 500.
    try:
        cert_pem, _key_pem = _generate_self_signed_cert(cn, key_size)
    except Exception as e:
        return UseCaseResult(
            ok=False,
            detail=f"{key_size}-bit RSA key generation failed on this host ({e}) -- "
            "if FIPS mode is enforced here, sub-2048-bit RSA keygen is likely blocked "
            "at the OpenSSL provider level",
        )

    # cert-analyzer runs as its own unprivileged 'cert-analyzer' user (see
    # cert-analyzer.service), not as whoever runs this script -- it needs
    # "other" read/execute on the dir and "other" read on the file to open
    # them at all. mkdir/write_bytes alone would leave that to the caller's
    # umask, which is fine under the common 022 default but silently breaks
    # detection under a stricter one (e.g. 077), so set the bits explicitly
    # rather than trust the environment.
    _GENERATED_CERT_DIR.mkdir(parents=True, exist_ok=True)
    _GENERATED_CERT_DIR.chmod(0o755)
    path.write_bytes(cert_pem)
    path.chmod(0o644)

    try:
        proc = subprocess.run(["cat", str(path)], capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return UseCaseResult(ok=False, detail=f"cat {path} timed out")

    if proc.returncode != 0:
        return UseCaseResult(ok=False, detail=f"cat {path} exited {proc.returncode}: {proc.stderr.strip()}")

    fips_note = (
        " -- undersized key, expect CertSight to flag this as FIPS non-compliant"
        if key_size < 2048
        else ""
    )
    return UseCaseResult(
        ok=True,
        detail=(
            f"generated a fresh self-signed cert (CN={cn}, {key_size}-bit RSA) at "
            f"{path} and cat'd it{fips_note} -- unique path and serial number "
            "guarantee CertSight treats this as a first-time discovery, so a new "
            "Kafka event should always appear"
        ),
    )


# tls_probe_helper.py runs as its own OS process (not a thread here) so that
# Tetragon's security_socket_bind hook attributes the bind() call to a PID
# that's independently visible and verifiable, rather than this test
# server's own PID. Capped concurrency since, unlike the file-access use
# case, this spins up a real listening socket + child process per click on
# an endpoint that may have no authentication (see TEST-SERVER-README.md).
_HELPER_SCRIPT = Path(__file__).resolve().parent / "tls_probe_helper.py"
_MAX_CONCURRENT_TLS_PROBES = 2
_TLS_PROBE_LIFETIME_SECONDS = 12.0
_TLS_PROBE_READY_TIMEOUT_SECONDS = 5.0
_active_tls_probe_lock = threading.Lock()
_active_tls_probe_count = 0


def _bind_tls_service_for_discovery(params: dict) -> UseCaseResult:
    global _active_tls_probe_count
    with _active_tls_probe_lock:
        if _active_tls_probe_count >= _MAX_CONCURRENT_TLS_PROBES:
            return UseCaseResult(
                ok=False,
                detail=f"{_MAX_CONCURRENT_TLS_PROBES} TLS probe listener(s) are already "
                "running -- wait a few seconds for one to finish and try again",
            )
        _active_tls_probe_count += 1

    def _release():
        global _active_tls_probe_count
        with _active_tls_probe_lock:
            _active_tls_probe_count -= 1

    token = uuid.uuid4().hex[:12]
    cn = f"certsight-test-bind-{token}.local"
    cert_path = _GENERATED_CERT_DIR / f"bind-probe-{token}.crt"
    key_path = _GENERATED_CERT_DIR / f"bind-probe-{token}.key"

    cert_pem, key_pem = _generate_self_signed_cert(cn, key_size=2048)

    _GENERATED_CERT_DIR.mkdir(parents=True, exist_ok=True)
    _GENERATED_CERT_DIR.chmod(0o755)
    cert_path.write_bytes(cert_pem)
    cert_path.chmod(0o644)
    # The private key never leaves this host and is only ever read by the
    # sibling helper process spawned below (same user) -- 0600 keeps it out
    # of reach of anyone else who can list /dev/shm.
    key_path.write_bytes(key_pem)
    key_path.chmod(0o600)

    try:
        proc = subprocess.Popen(
            [sys.executable, str(_HELPER_SCRIPT), str(cert_path), str(key_path), str(_TLS_PROBE_LIFETIME_SECONDS)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError as e:
        _release()
        return UseCaseResult(ok=False, detail=f"failed to spawn TLS probe helper: {e}")

    # Read the helper's first line of stdout (its readiness signal) off the
    # main thread via a background reader + queue, so a helper that never
    # reports readiness (e.g. hangs) can't block this HTTP request forever.
    ready_q: queue.Queue = queue.Queue()
    threading.Thread(target=lambda: ready_q.put(proc.stdout.readline()), daemon=True).start()

    try:
        first_line = ready_q.get(timeout=_TLS_PROBE_READY_TIMEOUT_SECONDS).strip()
    except queue.Empty:
        proc.kill()
        _release()
        return UseCaseResult(ok=False, detail="TLS probe helper didn't report readiness in time")

    if not first_line.startswith("PORT "):
        proc.kill()
        _release()
        return UseCaseResult(ok=False, detail=f"TLS probe helper failed to start: {first_line or '(no output)'}")

    port = first_line.split(" ", 1)[1]

    # Reap the helper in the background once its lifetime elapses so the
    # concurrency slot frees itself and no zombie process is left behind.
    def _reap():
        proc.wait()
        _release()

    threading.Thread(target=_reap, daemon=True).start()

    return UseCaseResult(
        ok=True,
        detail=(
            f"spawned PID {proc.pid}, listening for a TLS handshake on 127.0.0.1:{port} "
            f"for up to {int(_TLS_PROBE_LIFETIME_SECONDS)}s (CN={cn}) -- if cert-analyzer "
            "has [port_probe] bind_probe_enabled = true and the tls-service-tracking.yaml "
            "TracingPolicy loaded, it should connect within ~2s and pull this cert; check "
            f"the Kafka pane for a tls-probe://127.0.0.1:{port} event and confirm its "
            f"'pid' field reads {proc.pid} -- the same process that bound the socket"
        ),
    )


# Hardcoded to the literal path openssl3-cert-load.yaml / openssl3-cert-
# load-rhel8.yaml hook (both RHEL8 and RHEL9 use this same soname). Tetragon
# uprobes attach to a specific file, not to "whatever the dynamic linker
# resolves libssl to" -- ctypes.util.find_library("ssl") can return a
# different path/symlink depending on the host's OpenSSL packaging, which
# would make the call below succeed while the uprobe silently never fires.
_LIBSSL_PATH = "/usr/lib64/libssl.so.3"

_libssl_lock = threading.Lock()
_libssl = None  # lazily loaded and cached -- see _load_libssl()


def _load_libssl():
    """Loads libssl.so.3 and binds the handful of symbols this use case
    needs, once. Done lazily (not at import time) so a host without this
    exact path -- e.g. a dev machine with a different OpenSSL layout --
    doesn't take down the whole test server at startup; it just makes this
    one use case fail with a clear error the first time it's clicked."""
    global _libssl
    with _libssl_lock:
        if _libssl is not None:
            return _libssl
        lib = ctypes.CDLL(_LIBSSL_PATH)
        lib.TLS_client_method.restype = ctypes.c_void_p
        lib.SSL_CTX_new.argtypes = [ctypes.c_void_p]
        lib.SSL_CTX_new.restype = ctypes.c_void_p
        lib.SSL_CTX_use_certificate_ASN1.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]
        lib.SSL_CTX_use_certificate_ASN1.restype = ctypes.c_int
        lib.SSL_CTX_free.argtypes = [ctypes.c_void_p]
        _libssl = lib
        return lib


def _load_in_memory_cert_via_libssl(params: dict) -> UseCaseResult:
    token = uuid.uuid4().hex[:12]
    cn = f"certsight-test-asn1-{token}.local"
    cert_pem, _key_pem = _generate_self_signed_cert(cn, key_size=2048)
    cert = x509.load_pem_x509_certificate(cert_pem)
    der_bytes = cert.public_bytes(serialization.Encoding.DER)

    try:
        lib = _load_libssl()
    except OSError as e:
        return UseCaseResult(
            ok=False,
            detail=f"could not load {_LIBSSL_PATH}: {e} -- this use case calls straight into "
            "the system libssl that openssl3-cert-load.yaml hooks, so it only works on a host "
            "with that exact library present (RHEL8/9-style layout)",
        )

    method = lib.TLS_client_method()
    if not method:
        return UseCaseResult(ok=False, detail="TLS_client_method() returned NULL")

    ctx = lib.SSL_CTX_new(method)
    if not ctx:
        return UseCaseResult(ok=False, detail="SSL_CTX_new() returned NULL")

    # DER bytes never touch disk -- this simulates an application that ships
    # a certificate baked into its own binary (e.g. a pinned CA or bundled
    # service identity cert) rather than reading one from the filesystem.
    try:
        rc = lib.SSL_CTX_use_certificate_ASN1(ctx, len(der_bytes), der_bytes)
    finally:
        lib.SSL_CTX_free(ctx)

    if rc != 1:
        return UseCaseResult(ok=False, detail=f"SSL_CTX_use_certificate_ASN1() returned {rc} (expected 1)")

    return UseCaseResult(
        ok=True,
        detail=(
            f"called SSL_CTX_use_certificate_ASN1() directly against {_LIBSSL_PATH} with a "
            f"fresh in-memory DER cert (CN={cn}, serial={cert.serial_number}) -- no file was "
            "ever written to disk -- unique serial guarantees CertSight treats this as a "
            "first-time discovery, so a new Kafka event should always appear"
        ),
    )


USE_CASES: List[UseCase] = [
    UseCase(
        id="fresh-test-cert",
        label="generate + read a fresh test certificate",
        description=(
            "Generates a new self-signed certificate at a unique path under "
            "/dev/shm and cat's it. Guaranteed to be a first-time discovery "
            "every click, so a new Kafka event always appears. Pick a key size "
            "below 2048 bits to trigger a FIPS non-compliance finding."
        ),
        run=_generate_and_read_fresh_cert,
        params=[
            UseCaseParam(
                name="key_size",
                label="RSA key size",
                options=_ALLOWED_KEY_SIZES,
                default=_DEFAULT_KEY_SIZE,
            ),
        ],
        pipeline=[
            "This server generates a self-signed X.509 certificate in memory "
            "and writes it to a brand-new path under /dev/shm/certsight-test-server/.",

            "This server then runs 'cat <path>' as a real subprocess -- a real "
            "process performing a real open()/read() of that file, no different "
            "from an admin or application reading a cert off disk.",

            "When the kernel services that open(), it calls fd_install() to "
            "attach the new file descriptor to the cat process. Tetragon has a "
            "kprobe on fd_install, loaded system-wide via the "
            "CertSight certificate-file-access.yaml TracingPolicy.",

            "That policy's selector matches the opened file's path against a "
            "list of certificate-like extensions (.crt, .pem, .jks, .p12, ...). "
            "The generated file ends in .crt, so the kprobe's selector matches "
            "and Tetragon emits a process/kprobe event over its gRPC stream.",

            "CertSight's Tetragon gRPC client -- already subscribed to that "
            "stream -- receives the event and extracts the file path and the "
            "process that opened it (/usr/bin/cat), logging "
            "'🔍 Detected certificate access'.",

            "CertSight independently opens and reads that same file itself "
            "(a second, separate real file read, from its own process) to parse "
            "the X.509 structure: subject, issuer, SAN, validity dates, key "
            "algorithm/size, FIPS compliance, etc. Its FIPS checker "
            "(agent/fips_compliance_checker.py) flags any RSA key under 2048 "
            "bits, so picking a smaller key size above sets fips_compliant=false "
            "and a fips_violations list on the resulting event.",

            "Because this exact path has never been seen before, CertSight's "
            "known-certs cache treats it as a first-time discovery: it records "
            "the cert, updates Prometheus metrics, and -- since [kafka] enabled "
            "= true -- publishes a 'certificate_discovered' JSON event to the "
            "cert-analyzer-events Kafka topic.",

            "This test server's own background Kafka consumer thread, "
            "subscribed to that same topic, receives the message and pushes it "
            "to every connected browser over the Server-Sent Events stream, "
            "where it lands in the right-hand pane.",
        ],
    ),
    UseCase(
        id="tls-bind-probe",
        label="bind a TLS service and let CertSight discover it",
        description=(
            "Spawns a separate process that generates a fresh self-signed "
            "cert and binds a real TLS listener on 127.0.0.1 (a random high "
            "port). Requires CertSight's [port_probe] bind_probe_enabled = "
            "true and the tls-service-tracking.yaml TracingPolicy -- see "
            "TEST-SERVER-README.md."
        ),
        run=_bind_tls_service_for_discovery,
        pipeline=[
            "This server generates a fresh self-signed X.509 cert + private "
            "key in memory and writes both to /dev/shm/certsight-test-server/.",

            "This server spawns tls_probe_helper.py as a separate OS "
            "process (not a thread) specifically so the bind() call below "
            "happens in a process with its own distinct PID, which this "
            "use case then shows you so you can cross-check it against the "
            "resulting Kafka event.",

            "That helper process itself picks a random high port and binds "
            "to it explicitly -- not 0/OS-assigned, since CertSight can "
            "only see the literal port passed into bind() itself:\n"
            "```python\n"
            "candidate = random.randint(49152, 65535)\n"
            "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "sock.bind((\"127.0.0.1\", candidate))\n"
            "sock.listen(4)\n"
            "```\n"
            "(retried on collision) then listens for incoming TLS "
            "connections using the generated cert/key -- full source: "
            "[tls_probe_helper.py](/source/tls_probe_helper.py)",

            "Tetragon has a kprobe on the security_socket_bind LSM hook, "
            "loaded via the tls-service-tracking.yaml TracingPolicy, which "
            "fires on that bind() call and emits a process/kprobe event.",

            "CertSight's Tetragon gRPC client receives the event. If "
            "[port_probe] bind_probe_enabled = true, it waits "
            "connect_delay_seconds (default 2s) and then connects to "
            "127.0.0.1:<port> itself, performing a real TLS handshake "
            "with certificate verification intentionally disabled -- the "
            "goal is certificate inventory, not trust validation.",

            "The helper process's TLS handshake hands CertSight the "
            "certificate as a normal part of the handshake; CertSight "
            "parses it exactly like a file-discovered cert (subject, "
            "issuer, SAN, key algorithm/size, FIPS compliance, etc).",

            "Because the synthetic path 'tls-probe://127.0.0.1:<port>' "
            "combined with this cert's serial number has never been seen "
            "before, CertSight treats it as a first-time discovery and -- "
            "since [kafka] enabled = true -- publishes a "
            "'certificate_discovered' event to the cert-analyzer-events "
            "Kafka topic, with a 'pid' field set to the helper process's "
            "PID (from Tetragon's own report of who called bind()).",

            "This test server's own background Kafka consumer thread "
            "pushes that event to every connected browser over the "
            "Server-Sent Events stream, where it lands in the right-hand "
            "pane -- compare its 'pid' field against the PID shown in the "
            "status line above.",
        ],
    ),
    UseCase(
        id="in-memory-asn1-cert",
        label="load a certificate straight into memory (no file)",
        description=(
            "Generates a fresh self-signed certificate as raw DER bytes and "
            "hands them straight to libssl's SSL_CTX_use_certificate_ASN1() "
            "via ctypes -- no file is ever written. Simulates an application "
            "that ships a certificate baked into its own binary (e.g. a "
            "pinned CA). Requires the openssl3-cert-load.yaml TracingPolicy "
            "-- see TEST-SERVER-README.md."
        ),
        run=_load_in_memory_cert_via_libssl,
        pipeline=[
            "This server generates a fresh self-signed X.509 cert in "
            "memory and encodes it straight to DER bytes -- at no point "
            "does a certificate file exist on disk.",

            "This server then calls into the real system "
            "`/usr/lib64/libssl.so.3` via Python's `ctypes` -- the exact "
            "same libssl entry point a C/C++ application calls to load a "
            "certificate that's embedded at compile time rather than "
            "read from a file:\n"
            "```python\n"
            "lib.SSL_CTX_use_certificate_ASN1.argtypes = [\n"
            "    ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]\n"
            "lib.SSL_CTX_use_certificate_ASN1.restype = ctypes.c_int\n"
            "...\n"
            "ctx = lib.SSL_CTX_new(method)\n"
            "rc = lib.SSL_CTX_use_certificate_ASN1(ctx, len(der_bytes), der_bytes)\n"
            "```\n"
            "full source: [use_cases.py](/source/use_cases.py) "
            "(`_load_in_memory_cert_via_libssl`)",

            "Tetragon has a uprobe on that symbol, loaded via the "
            "openssl3-cert-load.yaml TracingPolicy, which fires on entry "
            "and reads the DER bytes directly out of this process's "
            "memory via bpf_probe_read_user (arg 2, sized by arg 1) -- "
            "before the real function body even runs.",

            "CertSight's Tetragon gRPC client receives the resulting "
            "process_uprobe event. Its bytes_arg field holds the raw DER "
            "bytes, which CertSight parses with "
            "load_der_x509_certificate() (agent/analyzer.py's "
            "_handle_uprobe_in_memory_cert) exactly like a file-discovered "
            "cert: subject, issuer, SAN, validity dates, key algorithm/"
            "size, FIPS compliance, etc.",

            "Because there's no real file path at all, CertSight builds a "
            "synthetic one out of the uprobe symbol, this process's PID, "
            "and the cert's serial number: "
            "`uprobe://SSL_CTX_use_certificate_ASN1/<pid>/<serial>`. The "
            "serial is fresh and random every click, so this is always a "
            "first-time discovery in CertSight's known-certs cache.",

            "CertSight records the cert, updates Prometheus metrics, and "
            "-- since [kafka] enabled = true -- publishes a "
            "'certificate_discovered' event to the cert-analyzer-events "
            "Kafka topic.",

            "This test server's own background Kafka consumer thread "
            "pushes that event to every connected browser over the "
            "Server-Sent Events stream, where it lands in the right-hand "
            "pane -- with no file path anywhere in it, only the synthetic "
            "uprobe:// one.",
        ],
    ),
]

USE_CASES_BY_ID = {uc.id: uc for uc in USE_CASES}
