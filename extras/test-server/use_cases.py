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
import os
import queue
import re
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, List, Optional, Tuple

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
    name: str                 # key in the JSON body POSTed to /api/run/<id>
    label: str                 # shown next to the control in the UI
    default: str
    type: str = "select"       # "select" | "checkbox" | "number" -- which control the UI renders
    options: List[str] = None  # values shown/sent as-is for type="select"; run() is responsible for validating
    min: str = None            # type="number": HTML min hint only, run() still validates server-side
    max: str = None            # type="number": HTML max hint only, run() still validates server-side


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
#
# This reasoning only holds when test-server and cert-analyzer share a
# kernel/mount namespace (the standalone host deployment). Under OpenShift
# (extras/openshift/test-server-pod.yaml), /dev/shm is a private per-container
# tmpfs -- invisible to cert-analyzer's own /host bind mount no matter what's
# written there. TEST_SERVER_CERT_DIR overrides this for that deployment,
# pointed at a hostPath-backed directory instead; see the Kafka reachability
# section of extras/OPENSHIFT-DEPLOYMENT-README.md.
_GENERATED_CERT_DIR = Path(os.environ.get("TEST_SERVER_CERT_DIR", "/dev/shm/certsight-test-server"))

# CertSight's FIPS compliance checker (agent/fips_compliance_checker.py)
# flags RSA keys under 2048 bits, so 1024 reliably triggers a
# fips_compliant=false Kafka event; 2048+ stays compliant. Server-side
# allowlist rather than trusting the raw client-supplied value: this
# endpoint is reachable over the network with no authentication (see
# TEST-SERVER-README.md), so an arbitrary key_size could be used to force
# an expensive RSA keygen (mild CPU-DoS) or simply fail oddly.
_ALLOWED_KEY_SIZES = ["1024", "2048", "3072", "4096"]
_DEFAULT_KEY_SIZE = "2048"

_DEFAULT_EXPIRED = "false"
_DEFAULT_EXPIRED_DAYS = "30"
# Bounds an unauthenticated, client-supplied integer (same rationale as
# _ALLOWED_KEY_SIZES above) -- 10 years is more than enough range for testing
# either a barely-expired or a long-expired cert.
_MIN_EXPIRED_DAYS = 1
_MAX_EXPIRED_DAYS = 3650

# The chain-with-missing-intermediates use case always builds a fixed 5-tier
# chain (root -> intermediate-1 -> intermediate-2 -> intermediate-3 -> leaf)
# and then omits some number of the 3 intermediates from the written bundle.
# Server-side allowlist for the same reason as _ALLOWED_KEY_SIZES above --
# this endpoint is unauthenticated.
_CHAIN_INTERMEDIATE_COUNT = 3
_ALLOWED_MISSING_INTERMEDIATE_COUNTS = ["1", "2", "3"]
_DEFAULT_MISSING_INTERMEDIATE_COUNT = "1"


def _generate_self_signed_cert(cn: str, key_size: int, expired_days: int = 0) -> Tuple[bytes, bytes]:
    """Returns (cert_pem, key_pem) for a self-signed cert, SAN=cn.

    With expired_days=0 (default), the cert is valid for 1yr starting now, as
    before. With expired_days=N>0, the cert instead covers the 1yr window
    ending N days ago, so it's already expired.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    not_valid_after = now - timedelta(days=expired_days) if expired_days else now + timedelta(days=365)
    not_valid_before = not_valid_after - timedelta(days=365)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
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

    expired_days = 0
    if params.get("expired", _DEFAULT_EXPIRED) == "true":
        expired_days_str = params.get("expired_days", _DEFAULT_EXPIRED_DAYS)
        try:
            expired_days = int(expired_days_str)
        except (TypeError, ValueError):
            return UseCaseResult(ok=False, detail=f"invalid expired_days '{expired_days_str}' -- must be an integer")
        if not (_MIN_EXPIRED_DAYS <= expired_days <= _MAX_EXPIRED_DAYS):
            return UseCaseResult(
                ok=False,
                detail=f"expired_days must be between {_MIN_EXPIRED_DAYS} and {_MAX_EXPIRED_DAYS}",
            )

    token = uuid.uuid4().hex[:12]
    cn = f"certsight-test-{token}.local"
    path = _GENERATED_CERT_DIR / f"generated-{token}.crt"

    # On a host with FIPS mode actually enforced at the OpenSSL provider
    # level, generating a sub-2048 RSA key can itself be refused (NIST SP
    # 800-131A disallows RSA keygen below 2048 bits under FIPS) -- which is
    # a legitimate, informative outcome for a FIPS-focused test tool, not a
    # bug, so surface it as a normal use-case failure rather than a 500.
    try:
        cert_pem, _key_pem = _generate_self_signed_cert(cn, key_size, expired_days)
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
    expiry_note = (
        f" -- expired {expired_days}d ago, expect CertSight to flag this in the Kafka event"
        if expired_days
        else ""
    )
    return UseCaseResult(
        ok=True,
        detail=(
            f"generated a fresh self-signed cert (CN={cn}, {key_size}-bit RSA) at "
            f"{path} and cat'd it{fips_note}{expiry_note} -- unique path and serial number "
            "guarantee CertSight treats this as a first-time discovery, so a new "
            "Kafka event should always appear"
        ),
    )


def _make_ca_cert(
    cn: str,
    issuer_key: Optional[rsa.RSAPrivateKey],
    issuer_subject: Optional[x509.Name],
    path_length: Optional[int],
):
    """Builds one CA cert. issuer_key/issuer_subject=None means self-signed
    (i.e. this is the root)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_subject if issuer_subject is not None else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .sign(issuer_key if issuer_key is not None else key, hashes.SHA256())
    )
    return key, subject, cert


def _build_5_tier_chain(token: str):
    """Builds root -> intermediate-1 -> intermediate-2 -> intermediate-3 ->
    leaf, each tier signed by the one before it. path_length counts down so
    each intermediate is only ever asserted to be allowed to sign the CAs
    actually beneath it in this chain. Returns (root_cert, intermediates,
    leaf_cn, leaf_cert) -- intermediates is [(subject, cert), ...] in
    root-to-leaf order. Shared by both chain use cases below so the two
    stay structurally identical except for how the result gets written out."""
    root_key, root_subject, root_cert = _make_ca_cert(
        f"certsight-test-chain-root-{token}.local", None, None, None,
    )

    intermediates = []
    signing_key, signing_subject = root_key, root_subject
    for i in range(1, _CHAIN_INTERMEDIATE_COUNT + 1):
        cn = f"certsight-test-chain-int{i}-{token}.local"
        new_key, new_subject, new_cert = _make_ca_cert(
            cn, signing_key, signing_subject, _CHAIN_INTERMEDIATE_COUNT - i,
        )
        intermediates.append((new_subject, new_cert))
        signing_key, signing_subject = new_key, new_subject

    leaf_cn = f"certsight-test-chain-leaf-{token}.local"
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, leaf_cn)])
    now = datetime.now(timezone.utc)
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject)
        .issuer_name(signing_subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(leaf_cn)]), critical=False)
        .sign(signing_key, hashes.SHA256())
    )
    return root_cert, intermediates, leaf_cn, leaf_cert


def _validate_missing_intermediates_param(params: dict):
    """Returns (missing_count, None) or (None, error_result)."""
    missing_str = params.get("missing_intermediates", _DEFAULT_MISSING_INTERMEDIATE_COUNT)
    if missing_str not in _ALLOWED_MISSING_INTERMEDIATE_COUNTS:
        return None, UseCaseResult(
            ok=False,
            detail=f"invalid missing_intermediates '{missing_str}' -- must be one of "
            f"{_ALLOWED_MISSING_INTERMEDIATE_COUNTS}",
        )
    return int(missing_str), None


def _generate_chain_with_missing_intermediates(params: dict) -> UseCaseResult:
    missing_count, error = _validate_missing_intermediates_param(params)
    if error:
        return error

    token = uuid.uuid4().hex[:12]
    root_cert, intermediates, leaf_cn, leaf_cert = _build_5_tier_chain(token)

    # Always drop the N intermediates closest to the root -- this produces
    # exactly one gap in the chain (between whichever intermediate is left
    # closest to the leaf, or the leaf itself if all 3 are dropped, and the
    # root) instead of scattering multiple gaps through the middle.
    kept_intermediates = intermediates[missing_count:]

    token_suffix = f"chain-missing-{missing_count}-{token}"
    path = _GENERATED_CERT_DIR / f"{token_suffix}.crt"
    _GENERATED_CERT_DIR.mkdir(parents=True, exist_ok=True)
    _GENERATED_CERT_DIR.chmod(0o755)

    # Bundle order matches how a real misconfigured server presents a chain
    # (leaf first, then whatever's left, root last) -- same convention as
    # test_analyzer.py's generate_broken_chain().
    with path.open("wb") as f:
        f.write(leaf_cert.public_bytes(serialization.Encoding.PEM))
        for _subject, cert in kept_intermediates:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        f.write(root_cert.public_bytes(serialization.Encoding.PEM))
    path.chmod(0o644)

    try:
        proc = subprocess.run(["cat", str(path)], capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return UseCaseResult(ok=False, detail=f"cat {path} timed out")

    if proc.returncode != 0:
        return UseCaseResult(ok=False, detail=f"cat {path} exited {proc.returncode}: {proc.stderr.strip()}")

    gap_note = (
        "the leaf" if missing_count == _CHAIN_INTERMEDIATE_COUNT
        else "the remaining intermediate closest to the leaf"
    )
    return UseCaseResult(
        ok=True,
        detail=(
            f"generated a 5-certificate chain (root -> 3 intermediates -> leaf, CN={leaf_cn}), "
            f"dropped {missing_count} of the 3 intermediates (closest to the root) from the "
            f"bundle, wrote the remaining {len(kept_intermediates) + 2} certs to {path}, and "
            f"cat'd it -- expect the chain-explorer view to show a MISSING gap between "
            f"{gap_note} and the root"
        ),
    )


def _generate_chain_across_multiple_files(params: dict) -> UseCaseResult:
    missing_count, error = _validate_missing_intermediates_param(params)
    if error:
        return error

    token = uuid.uuid4().hex[:12]
    root_cert, intermediates, leaf_cn, leaf_cert = _build_5_tier_chain(token)

    # Same drop rule as the single-bundle use case above -- drop the N
    # intermediates closest to the root. The difference here is that every
    # *surviving* cert gets written to and cat'd from its own separate
    # file, so cert-analyzer discovers each as an independent cert_path --
    # reassembling the chain requires chain-explorer's cross-file subject/
    # issuer matching, not just cert_index ordering within one bundle.
    kept_intermediates = intermediates[missing_count:]

    _GENERATED_CERT_DIR.mkdir(parents=True, exist_ok=True)
    _GENERATED_CERT_DIR.chmod(0o755)

    written_paths = []
    try:
        for name, cert in (
            [("leaf", leaf_cert)]
            # Named by original tier number (missing_count + position), not
            # sequential kept-position, so the file name matches the CN
            # actually baked into the cert -- e.g. if intermediate-1 was
            # dropped, the first surviving file is named "int2", not "int1".
            + [
                (f"int{missing_count + i}", cert)
                for i, (_subject, cert) in enumerate(kept_intermediates, start=1)
            ]
            + [("root", root_cert)]
        ):
            path = _GENERATED_CERT_DIR / f"chain-multifile-{name}-{token}.crt"
            path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            path.chmod(0o644)
            proc = subprocess.run(["cat", str(path)], capture_output=True, text=True, timeout=10)
            if proc.returncode != 0:
                return UseCaseResult(ok=False, detail=f"cat {path} exited {proc.returncode}: {proc.stderr.strip()}")
            written_paths.append(path)
    except subprocess.TimeoutExpired as e:
        return UseCaseResult(ok=False, detail=f"cat timed out: {e}")

    # A single-cert file is never flagged MISSING by chain-explorer's design
    # (see _find_chain_gaps's docstring in chain_explorer.py) -- only cross-
    # file *resolution* is ever shown for these, regardless of how many
    # intermediates were dropped, so this use case can't demonstrate the
    # MISSING state itself; use the single-bundle use case above for that.
    return UseCaseResult(
        ok=True,
        detail=(
            f"generated the same 5-certificate chain (root -> 3 intermediates -> leaf, "
            f"CN={leaf_cn}) as the single-bundle use case above, dropped {missing_count} of "
            f"the 3 intermediates (closest to the root), but wrote each of the remaining "
            f"{len(written_paths)} certs to its own separate file and cat'd it individually -- "
            f"expect the chain-explorer view to link them together via FOUND ELSEWHERE boxes "
            f"across files rather than cert_index ordering within one file. Note: because each "
            f"surviving cert lives in its own single-cert file here, none of them will show as "
            f"MISSING even with intermediates dropped -- single-cert bundles are never flagged "
            f"missing, to avoid flagging every ordinary standalone leaf cert on the host"
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
            f"the Kafka pane for a tls-bind-probe://127.0.0.1:{port} event and confirm its "
            f"'pid' field reads {proc.pid} -- the same process that bound the socket"
        ),
    )


# tcp_connect_probe_helper.py runs as its own OS process for the same PID-
# attribution reason as the bind-probe helper above. Its candidate ports are
# a fixed subset of tcp-connect-tls.yaml's DPort filter (see that helper's
# module docstring for which, and why); cert-analyzer's outbound probe dedup
# (agent/analyzer.py's _probed_endpoints, keyed 'connect:host:port') never
# expires, so cycling across several candidate ports -- rather than always
# dialing the same one -- keeps this use case producing fresh discoveries
# across more than a single click. This dedup is scoped to the connect
# mechanism only (as of the 'bind'/'connect' key-prefix fix in
# agent/analyzer.py), so it no longer competes with the bind-probe use
# case's own discoveries of the same host:port.
_CONNECT_HELPER_SCRIPT = Path(__file__).resolve().parent / "tcp_connect_probe_helper.py"
_MAX_CONCURRENT_CONNECT_PROBES = 2
_CONNECT_PROBE_LIFETIME_SECONDS = 12.0
_CONNECT_PROBE_READY_TIMEOUT_SECONDS = 5.0
_active_connect_probe_lock = threading.Lock()
_active_connect_probe_count = 0


def _dial_outbound_tls_port(params: dict) -> UseCaseResult:
    global _active_connect_probe_count
    with _active_connect_probe_lock:
        if _active_connect_probe_count >= _MAX_CONCURRENT_CONNECT_PROBES:
            return UseCaseResult(
                ok=False,
                detail=f"{_MAX_CONCURRENT_CONNECT_PROBES} outbound connect probe(s) are "
                "already running -- wait a few seconds for one to finish and try again",
            )
        _active_connect_probe_count += 1

    def _release():
        global _active_connect_probe_count
        with _active_connect_probe_lock:
            _active_connect_probe_count -= 1

    token = uuid.uuid4().hex[:12]
    cn = f"certsight-test-connect-{token}.local"
    cert_path = _GENERATED_CERT_DIR / f"connect-probe-{token}.crt"
    key_path = _GENERATED_CERT_DIR / f"connect-probe-{token}.key"

    cert_pem, key_pem = _generate_self_signed_cert(cn, key_size=2048)

    _GENERATED_CERT_DIR.mkdir(parents=True, exist_ok=True)
    _GENERATED_CERT_DIR.chmod(0o755)
    cert_path.write_bytes(cert_pem)
    cert_path.chmod(0o644)
    # Never leaves this host, only read by the sibling helper process
    # spawned below (same user) -- see the matching comment on the
    # bind-probe use case above.
    key_path.write_bytes(key_pem)
    key_path.chmod(0o600)

    try:
        proc = subprocess.Popen(
            [
                sys.executable, str(_CONNECT_HELPER_SCRIPT),
                str(cert_path), str(key_path), str(_CONNECT_PROBE_LIFETIME_SECONDS),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError as e:
        _release()
        return UseCaseResult(ok=False, detail=f"failed to spawn tcp_connect probe helper: {e}")

    # Same background reader + queue pattern as the bind-probe use case:
    # the helper's readiness line only arrives after its own outbound
    # connect() has already happened, so a helper that hangs before that
    # point can't block this HTTP request forever.
    ready_q: queue.Queue = queue.Queue()
    threading.Thread(target=lambda: ready_q.put(proc.stdout.readline()), daemon=True).start()

    try:
        first_line = ready_q.get(timeout=_CONNECT_PROBE_READY_TIMEOUT_SECONDS).strip()
    except queue.Empty:
        proc.kill()
        _release()
        return UseCaseResult(
            ok=False, detail="tcp_connect probe helper didn't report its outbound connect in time",
        )

    if not first_line.startswith("PORT "):
        proc.kill()
        _release()
        return UseCaseResult(ok=False, detail=f"tcp_connect probe helper failed to start: {first_line or '(no output)'}")

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
            f"PID {proc.pid} made a real outbound connect() to 127.0.0.1:{port} (CN={cn}), "
            f"a port tcp-connect-tls.yaml treats as TLS, then started serving TLS on that "
            f"same port for up to {int(_CONNECT_PROBE_LIFETIME_SECONDS)}s -- if cert-analyzer "
            "has [port_probe] connect_probe_enabled = true and the tcp-connect-tls.yaml "
            "TracingPolicy loaded, it should probe that endpoint immediately; check the "
            f"Kafka pane for a tls-connect-probe://127.0.0.1:{port} event and confirm its "
            f"'pid' field reads {proc.pid} -- the same process that made the connect() call. "
            "Note: cert-analyzer probes each destination host:port at most once ever per "
            "mechanism (no cache expiry), so if this exact port was already dialed by an "
            "earlier click of this same use case since cert-analyzer's last restart, this "
            "click's connect() still fires the kprobe but the probe itself is silently "
            "skipped -- the helper cycles across 7 candidate ports, so expect roughly that "
            "many fresh events before you need to restart cert-analyzer to reset its dedup "
            "cache. This is independent of the bind-probe use case's own dedup, even against "
            "the identical 127.0.0.1:<port> -- each mechanism now tracks its own discoveries."
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


# CertAgentTest.java runs as its own OS process (not a thread) for the same
# PID-attribution reason as the bind-probe/connect-probe helpers above.
# Unlike those, the "cert-agent" side isn't cert-analyzer reaching back in --
# it's a separate JVM bytecode-instrumentation agent (probe_tests/java/
# cert-agent/) that has to be jattach'd into this specific JVM before its
# KeyStore.setCertificateEntry() calls fire the java_cert_agent_write uprobe
# (java-non-fips-cert.yaml). That uprobe attaches to the agent .so's file
# inode, not to a running process, so -- unlike the FIPS/NSS uprobe case --
# load order between the Tetragon policy and jattach doesn't matter here.
#
# Candidate paths cover both a production install (cert-agent-jni /
# cert-agent-deployer RPMs, per their systemd units) and a bare dev checkout
# that's only run probe_tests/java/cert-agent/build.sh locally.
_CERT_AGENT_JAR_CANDIDATES = [
    Path("/opt/cert-agent/cert-agent.jar"),
    Path(__file__).resolve().parents[2] / "probe_tests" / "java" / "cert-agent" / "cert-agent.jar",
]
_CERT_AGENT_NATIVE_LIB_CANDIDATES = [
    Path("/opt/cert-agent/libcert_agent_stub.so"),
    Path(__file__).resolve().parents[2] / "probe_tests" / "java" / "cert-agent" / "native" / "libcert_agent_stub.so",
]
_JATTACH_CANDIDATES = [
    Path("/opt/cert-agent-deployer/jattach"),
    Path(__file__).resolve().parents[2] / "probe_tests" / "java" / "cert-agent" / "jattach-linux-x64" / "jattach",
]

_JAVA_TEST_DIR = Path(__file__).resolve().parent
_JAVA_TEST_SRC = _JAVA_TEST_DIR / "CertAgentTest.java"
_JAVA_TEST_CLASS = _JAVA_TEST_DIR / "CertAgentTest.class"
_JAVA_KEYSTORE_LOOP_INTERVAL_MS = 3_000
_JAVA_KEYSTORE_LIFETIME_SECONDS = 15.0
_JAVA_KEYSTORE_READY_TIMEOUT_SECONDS = 10.0
_MAX_CONCURRENT_JAVA_KEYSTORE_PROBES = 2
_active_java_keystore_probe_lock = threading.Lock()
_active_java_keystore_probe_count = 0


def _first_existing(paths: List[Path]) -> Optional[Path]:
    for p in paths:
        if p.exists():
            return p
    return None


def _ensure_cert_agent_test_compiled() -> None:
    """Compiles the vendored CertAgentTest.java if its .class is missing or
    stale. The RPM (%build) pre-compiles this so production installs never
    hit this path -- it exists so a plain git checkout works with no
    separate build step, like every other use case here."""
    if _JAVA_TEST_CLASS.exists() and _JAVA_TEST_CLASS.stat().st_mtime >= _JAVA_TEST_SRC.stat().st_mtime:
        return
    subprocess.run(
        ["javac", "-source", "11", "-target", "11", "-encoding", "UTF-8", "-d", str(_JAVA_TEST_DIR), str(_JAVA_TEST_SRC)],
        check=True, capture_output=True, text=True, timeout=60,
    )


def _read_java_test_pid(proc: subprocess.Popen) -> Optional[int]:
    # CertAgentTest's PID line is its second line of output (after a
    # "=== CertAgentTest ===" banner), so this reads a few lines rather than
    # just the first, unlike the single-readiness-line helpers above.
    for _ in range(20):
        line = proc.stdout.readline()
        if not line:
            return None
        m = re.match(r"PID\s*:\s*(\d+)", line.strip())
        if m:
            return int(m.group(1))
    return None


def _run_java_keystore_cert(params: dict) -> UseCaseResult:
    global _active_java_keystore_probe_count

    jar = _first_existing(_CERT_AGENT_JAR_CANDIDATES)
    native_lib = _first_existing(_CERT_AGENT_NATIVE_LIB_CANDIDATES)
    jattach = _first_existing(_JATTACH_CANDIDATES)
    if jar is None or native_lib is None:
        return UseCaseResult(
            ok=False,
            detail="cert-agent.jar / libcert_agent_stub.so not found -- install the "
            "cert-agent-jni package (or run probe_tests/java/cert-agent/build.sh) first",
        )
    if jattach is None:
        return UseCaseResult(
            ok=False,
            detail="jattach binary not found -- install the cert-agent-deployer package "
            "(or build probe_tests/java/cert-agent/jattach-linux-x64) first",
        )

    with _active_java_keystore_probe_lock:
        if _active_java_keystore_probe_count >= _MAX_CONCURRENT_JAVA_KEYSTORE_PROBES:
            return UseCaseResult(
                ok=False,
                detail=f"{_MAX_CONCURRENT_JAVA_KEYSTORE_PROBES} JVM(s) are already running for "
                "this use case -- wait a few seconds for one to finish and try again",
            )
        _active_java_keystore_probe_count += 1

    def _release():
        global _active_java_keystore_probe_count
        with _active_java_keystore_probe_lock:
            _active_java_keystore_probe_count -= 1

    try:
        _ensure_cert_agent_test_compiled()
    except subprocess.CalledProcessError as e:
        _release()
        return UseCaseResult(ok=False, detail=f"failed to compile CertAgentTest.java: {e.stderr.strip()}")

    token = uuid.uuid4().hex[:12]
    cn = f"certsight-test-jca-{token}.local"
    cert_pem, _key_pem = _generate_self_signed_cert(cn, key_size=2048)

    # Named with a non-cert-like extension (".seed", not .crt/.pem/...) so
    # this file's own open() by the JVM below doesn't also match
    # certificate-file-access.yaml's Postfix selector -- this use case is
    # meant to exercise only the in-memory JCA uprobe path, not produce an
    # incidental second file-access event for the seed input.
    _GENERATED_CERT_DIR.mkdir(parents=True, exist_ok=True)
    _GENERATED_CERT_DIR.chmod(0o755)
    seed_path = _GENERATED_CERT_DIR / f"java-seed-{token}.seed"
    seed_path.write_bytes(cert_pem)
    seed_path.chmod(0o644)

    try:
        proc = subprocess.Popen(
            ["java", "-cp", str(_JAVA_TEST_DIR), "CertAgentTest", str(seed_path), str(_JAVA_KEYSTORE_LOOP_INTERVAL_MS)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError as e:
        _release()
        seed_path.unlink(missing_ok=True)
        return UseCaseResult(ok=False, detail=f"failed to spawn CertAgentTest JVM: {e}")

    # Same background reader + queue pattern as the bind-probe/connect-probe
    # use cases: a JVM that never prints its PID line (e.g. java missing,
    # bad classpath) can't block this HTTP request forever.
    pid_q: queue.Queue = queue.Queue()
    threading.Thread(target=lambda: pid_q.put(_read_java_test_pid(proc)), daemon=True).start()

    try:
        pid = pid_q.get(timeout=_JAVA_KEYSTORE_READY_TIMEOUT_SECONDS)
    except queue.Empty:
        proc.kill()
        _release()
        seed_path.unlink(missing_ok=True)
        return UseCaseResult(ok=False, detail="CertAgentTest didn't report its PID in time")

    if pid is None:
        proc.kill()
        _release()
        seed_path.unlink(missing_ok=True)
        return UseCaseResult(
            ok=False,
            detail="CertAgentTest exited before reporting its PID -- check 'java' is on PATH",
        )

    jattach_result = subprocess.run(
        [str(jattach), str(pid), "load", "instrument", "false", f"{jar}={native_lib}"],
        capture_output=True, text=True, timeout=10,
    )
    if jattach_result.returncode != 0:
        proc.kill()
        _release()
        seed_path.unlink(missing_ok=True)
        detail = (jattach_result.stderr or jattach_result.stdout).strip()
        return UseCaseResult(ok=False, detail=f"jattach into PID {pid} failed (exit {jattach_result.returncode}): {detail}")

    # Reap the JVM in the background once its lifetime elapses (comfortably
    # more than one more loop iteration past the jattach above) so the
    # concurrency slot frees itself and no stray JVM or seed file lingers.
    def _reap():
        try:
            proc.wait(timeout=_JAVA_KEYSTORE_LIFETIME_SECONDS)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        finally:
            seed_path.unlink(missing_ok=True)
            _release()

    threading.Thread(target=_reap, daemon=True).start()

    return UseCaseResult(
        ok=True,
        detail=(
            f"spawned PID {pid}, jattached the cert-agent, and it's now calling "
            f"KeyStore.setCertificateEntry() every {_JAVA_KEYSTORE_LOOP_INTERVAL_MS}ms on a "
            f"fresh in-memory cert (CN={cn}) -- watch the Kafka pane for a "
            f"uprobe://java_cert_agent_write/{pid}/<serial> event within the next "
            f"~{int(_JAVA_KEYSTORE_LOOP_INTERVAL_MS / 1000) + 1}s; unique PID+serial guarantees "
            "a first-time discovery"
        ),
    )


USE_CASES: List[UseCase] = [
    UseCase(
        id="fresh-test-cert",
        label="generate + read a fresh test certificate",
        description=(
            f"Generates a new self-signed certificate at a unique path under "
            f"{_GENERATED_CERT_DIR} and cat's it. Guaranteed to be a first-time "
            "discovery every click, so a new Kafka event always appears. Pick a "
            "key size below 2048 bits to trigger a FIPS non-compliance finding, "
            "or check 'expired' to generate a cert that's already past its "
            "validity window and verify CertSight flags that in the Kafka event."
        ),
        run=_generate_and_read_fresh_cert,
        params=[
            UseCaseParam(
                name="key_size",
                label="RSA key size",
                type="select",
                options=_ALLOWED_KEY_SIZES,
                default=_DEFAULT_KEY_SIZE,
            ),
            UseCaseParam(
                name="expired",
                label="expired",
                type="checkbox",
                default=_DEFAULT_EXPIRED,
            ),
            UseCaseParam(
                name="expired_days",
                label="days ago",
                type="number",
                default=_DEFAULT_EXPIRED_DAYS,
                min=str(_MIN_EXPIRED_DAYS),
                max=str(_MAX_EXPIRED_DAYS),
            ),
        ],
        pipeline=[
            "This server generates a self-signed X.509 certificate in memory "
            f"and writes it to a brand-new path under {_GENERATED_CERT_DIR}/.",

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
            f"key in memory and writes both to {_GENERATED_CERT_DIR}/.",

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

            "Because the synthetic path 'tls-bind-probe://127.0.0.1:<port>' "
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
        id="tcp-connect-probe",
        label="dial out to a TLS port and let CertSight discover it",
        description=(
            "Spawns a separate process that binds a real TLS listener on one "
            "of tcp-connect-tls.yaml's TLS ports, then makes a real outbound "
            "connect() back to itself -- that connect() is the trigger, not "
            "the bind(). Requires CertSight's [port_probe] "
            "connect_probe_enabled = true and the tcp-connect-tls.yaml "
            "TracingPolicy -- see TEST-SERVER-README.md."
        ),
        run=_dial_outbound_tls_port,
        pipeline=[
            "This server generates a fresh self-signed X.509 cert + private "
            f"key in memory and writes both to {_GENERATED_CERT_DIR}/.",

            "This server spawns tcp_connect_probe_helper.py as a separate OS "
            "process (not a thread) specifically so the connect() call below "
            "happens in a process with its own distinct PID, which this use "
            "case then shows you so you can cross-check it against the "
            "resulting Kafka event.",

            "That helper process binds a real TLS listener on 127.0.0.1, "
            "picking one of a handful of ports that tcp-connect-tls.yaml's "
            "DPort filter treats as TLS (8443, 6380, 8883, 5671, 5672, "
            "9093, 9094 -- a subset that doesn't need root to bind), "
            "retrying on collision, then immediately dials out to that same "
            "port itself:\n"
            "```python\n"
            "sock.bind((\"127.0.0.1\", candidate))\n"
            "sock.listen(4)\n"
            "...\n"
            "with socket.create_connection((\"127.0.0.1\", port), timeout=3):\n"
            "    pass\n"
            "```\n"
            "(no TLS handshake needed on this side -- the kprobe fires on "
            "connect() entry, before any bytes are exchanged) -- full "
            "source: [tcp_connect_probe_helper.py](/source/tcp_connect_probe_helper.py)",

            "Tetragon has a kprobe on the tcp_connect kernel function, "
            "loaded via the tcp-connect-tls.yaml TracingPolicy, which fires "
            "on that connect() call. The policy's DPort selector matches "
            "the destination port against a fixed list of common TLS ports, "
            "so it only fires for connections that look like outbound TLS.",

            "CertSight's Tetragon gRPC client receives the event. If "
            "[port_probe] connect_probe_enabled = true, it immediately "
            "connects to that same 127.0.0.1:<port> itself -- no startup "
            "delay is needed here, unlike the bind-probe case, since the "
            "remote side is already running by the time the connect fires "
            "-- and performs a real TLS handshake with certificate "
            "verification intentionally disabled, exactly like the "
            "bind-probe use case.",

            "The helper process's TLS server hands CertSight the "
            "certificate as a normal part of that handshake; CertSight "
            "parses it exactly like a file- or bind-discovered cert "
            "(subject, issuer, SAN, key algorithm/size, FIPS compliance, "
            "etc).",

            "CertSight builds its own synthetic path for this mechanism, "
            "'tls-connect-probe://127.0.0.1:<port>' -- distinct from the "
            "bind-probe case's 'tls-bind-probe://127.0.0.1:<port>' even "
            "for the identical address, because agent/analyzer.py's probe "
            "endpoint dedup cache is keyed on 'connect:host:port' /  "
            "'bind:host:port' separately, so this use case's own discovery "
            "never gets silently swallowed by the bind-probe use case (or "
            "vice versa) even when both fire for the same 127.0.0.1:<port>. "
            "Within this mechanism alone the dedup still applies with no "
            "expiry, so a port this specific use case has already dialed "
            "since cert-analyzer's last restart is silently skipped on a "
            "later click. Since the port is fresh here, this is a "
            "first-time discovery and -- since [kafka] enabled = true -- "
            "CertSight publishes a 'certificate_discovered' event to the "
            "cert-analyzer-events Kafka topic, with a 'pid' field set to "
            "the helper process's PID (from Tetragon's own report of who "
            "called connect()).",

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
    UseCase(
        id="java-jca-keystore",
        label="load a certificate into a Java KeyStore (JCA)",
        description=(
            "Spawns a real JVM running CertAgentTest, jattaches CertSight's "
            "cert-agent Java instrumentation into it, then watches it call "
            "KeyStore.setCertificateEntry() on a fresh in-memory cert every "
            "few seconds. No file is ever read by cert-analyzer -- the cert "
            "bytes are captured straight off the JCA call itself. Requires "
            "the cert-agent-jni and cert-agent-deployer packages (or a "
            "local probe_tests/java/cert-agent/build.sh build) -- see "
            "TEST-SERVER-README.md."
        ),
        run=_run_java_keystore_cert,
        pipeline=[
            "This server generates a fresh self-signed X.509 cert and "
            "writes it to a throwaway path under "
            f"{_GENERATED_CERT_DIR}/ -- only as seed input for the "
            "JVM below to load once at startup, not as something "
            "cert-analyzer is meant to detect itself (its extension is "
            "deliberately not one of certificate-file-access.yaml's "
            "matched suffixes).",

            "This server spawns "
            "[CertAgentTest.java](/source/CertAgentTest.java) as a separate "
            "OS process (not a thread), for the same PID-attribution reason "
            "as the bind-probe/connect-probe use cases. It loads that seed "
            "cert once, then loops forever calling "
            "`KeyStore.setCertificateEntry()` on a fresh in-memory `JKS` "
            "KeyStore every few seconds.",

            "This server then runs `jattach <pid> load instrument false "
            "cert-agent.jar=libcert_agent_stub.so` against that JVM's PID -- "
            "the same dynamic-attach command documented in "
            "probe_tests/README.md's manual test procedure. This loads "
            "CertSight's cert-agent Java agent, which uses ASM to "
            "bytecode-instrument `KeyStore.setCertificateEntry` in-place, "
            "so every call from that point on serialises the certificate "
            "to DER and passes it across a JNI boundary to a small native "
            "stub function, `java_cert_agent_write`.",

            "Tetragon has a uprobe on that native symbol, loaded via the "
            "java-non-fips-cert.yaml TracingPolicy, which fires on entry "
            "and reads the DER bytes directly out of the JVM process's "
            "memory (arg 2, sized by arg 3) -- the uprobe attaches to the "
            "agent .so's file inode, so it's already armed regardless of "
            "whether the jattach above happened before or after the "
            "policy was loaded.",

            "CertSight's Tetragon gRPC client receives the resulting "
            "process_uprobe event and parses the DER bytes with "
            "load_der_x509_certificate() (agent/analyzer.py's "
            "_handle_uprobe_in_memory_cert) -- the same handler used by "
            "the in-memory ASN1 use case above.",

            "CertSight builds a synthetic path out of the uprobe symbol, "
            "this JVM's PID, and the cert's serial number: "
            "`uprobe://java_cert_agent_write/<pid>/<serial>`. Both the PID "
            "(a brand-new JVM every click) and the serial (a fresh cert "
            "every click) are unique, so this is always a first-time "
            "discovery in CertSight's known-certs cache.",

            "CertSight records the cert, updates Prometheus metrics, and "
            "-- since [kafka] enabled = true -- publishes a "
            "'certificate_discovered' event to the cert-analyzer-events "
            "Kafka topic.",

            "This test server's own background Kafka consumer thread "
            "pushes that event to every connected browser over the "
            "Server-Sent Events stream, where it lands in the right-hand "
            "pane. This server kills the JVM a few seconds later, once "
            "its lifetime elapses, so no stray process is left running.",
        ],
    ),
    UseCase(
        id="cert-chain-missing-intermediates",
        label="generate a 5-cert chain with missing intermediates",
        description=(
            "Builds a full 5-certificate chain (root CA -> 3 intermediate CAs "
            "-> leaf) and writes only some of it to a single PEM bundle, "
            "omitting 1, 2, or 3 intermediates (closest to the root) before "
            "cat'ing it. Exercises the same broken-chain scenario as "
            "extras/test_analyzer.py's generate_broken_chain() fixture, but "
            "clickable and with a configurable number of missing links -- "
            "check the chain-explorer view afterwards for a MISSING gap."
        ),
        run=_generate_chain_with_missing_intermediates,
        params=[
            UseCaseParam(
                name="missing_intermediates",
                label="missing intermediates",
                type="select",
                options=_ALLOWED_MISSING_INTERMEDIATE_COUNTS,
                default=_DEFAULT_MISSING_INTERMEDIATE_COUNT,
            ),
        ],
        pipeline=[
            "This server builds a full 5-tier certificate chain in memory: "
            "a self-signed root CA, 3 intermediate CAs each signed by the "
            "one before it, and a leaf certificate signed by the last "
            "intermediate -- a real, validly-signed chain, just like a CA "
            "would issue.",

            "This server then writes only a subset of that chain to a "
            "single PEM bundle: the leaf, then whichever intermediates "
            "weren't dropped, then the root -- always dropping the "
            "intermediate(s) closest to the root first, so the bundle has "
            "exactly one gap in it rather than several scattered ones.",

            "This server runs 'cat <path>' as a real subprocess against "
            "that bundle -- the same real open()/read() every other "
            "file-based use case here triggers.",

            "Tetragon's kprobe on fd_install (certificate-file-access.yaml) "
            "fires for the .crt extension and CertSight reads the same "
            "file itself, parsing every certificate in the bundle -- "
            "cert-analyzer already supports multi-cert PEM files, indexing "
            "each cert by its position (cert_index).",

            "CertSight records each cert as its own discovery (unique path "
            "+ index + serial), updates Prometheus metrics per cert-index, "
            "and -- since [kafka] enabled = true -- publishes a "
            "'certificate_discovered' event per cert to the "
            "cert-analyzer-events Kafka topic.",

            "This test server's own background Kafka consumer thread pushes "
            "each of those events to every connected browser over the "
            "Server-Sent Events stream, where they land in the right-hand "
            "pane.",

            "Open the [chain explorer](/chain-explorer) afterwards: it reads "
            "the same Prometheus metrics back out, groups certs by file "
            "path, and checks every non-self-signed cert's issuer against "
            "every bundle it currently knows about -- not just this one -- "
            "before rendering a dashed red MISSING box; since the dropped "
            "intermediate(s) were never written anywhere at all, they stay "
            "genuinely unresolvable and show as MISSING here.",
        ],
    ),
    UseCase(
        id="cert-chain-across-multiple-files",
        label="generate a 5-cert chain split across several files",
        description=(
            "Same 5-certificate chain and same missing-intermediates drop "
            "rule as the use case above, but instead of writing the "
            "surviving certs to one PEM bundle, each gets its own separate "
            "file, cat'd individually. Exercises chain-explorer's "
            "cross-file chain reconstruction: reassembling the chain now "
            "requires matching issuer/subject across bundles, not just "
            "cert_index ordering within one file -- check the chain-"
            "explorer view afterwards for FOUND ELSEWHERE links between "
            "the separate files."
        ),
        run=_generate_chain_across_multiple_files,
        params=[
            UseCaseParam(
                name="missing_intermediates",
                label="missing intermediates",
                type="select",
                options=_ALLOWED_MISSING_INTERMEDIATE_COUNTS,
                default=_DEFAULT_MISSING_INTERMEDIATE_COUNT,
            ),
        ],
        pipeline=[
            "This server builds the same full 5-tier certificate chain in "
            "memory as the single-bundle use case above -- a self-signed "
            "root CA, 3 intermediate CAs each signed by the one before it, "
            "and a leaf signed by the last intermediate.",

            "This server drops the same N intermediates closest to the "
            "root, but writes each *surviving* cert (leaf, remaining "
            "intermediates, root) to its own separate file under "
            f"{_GENERATED_CERT_DIR}/, running 'cat <path>' "
            "against each one individually -- so this is several real "
            "open()/read() calls, not one.",

            "Tetragon's kprobe on fd_install fires once per file, and "
            "CertSight discovers each as its own independent cert_path -- "
            "unlike the single-bundle use case, there's no cert_index "
            "grouping to lean on; every file here is its own single-cert "
            "bundle from cert-analyzer's point of view.",

            "CertSight records each cert as its own first-time discovery "
            "(unique path + serial) and -- since [kafka] enabled = true -- "
            "publishes a 'certificate_discovered' event per file to the "
            "cert-analyzer-events Kafka topic, pushed to the browser the "
            "same way as every other use case here.",

            "Open the [chain explorer](/chain-explorer) afterwards: for "
            "each single-cert bundle, it looks up that cert's issuer "
            "against every *other* bundle it knows about and, on a match, "
            "renders a clickable FOUND ELSEWHERE box linking straight to "
            "the bundle that actually has it -- reconstructing the chain "
            "across files instead of leaving each file looking like an "
            "unremarkable, unrelated lone leaf cert.",

            "Note: single-cert bundles are never flagged MISSING (to avoid "
            "flagging every ordinary standalone leaf cert on the host), so "
            "even with intermediates dropped here, this use case only ever "
            "demonstrates the FOUND ELSEWHERE state, not MISSING -- use the "
            "single-bundle use case above for that.",
        ],
    ),
]

USE_CASES_BY_ID = {uc.id: uc for uc in USE_CASES}
