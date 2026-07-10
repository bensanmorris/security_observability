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
import subprocess
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, List

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
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    except Exception as e:
        return UseCaseResult(
            ok=False,
            detail=f"{key_size}-bit RSA key generation failed on this host ({e}) -- "
            "if FIPS mode is enforced here, sub-2048-bit RSA keygen is likely blocked "
            "at the OpenSSL provider level",
        )

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

    # cert-analyzer runs as its own unprivileged 'cert-analyzer' user (see
    # cert-analyzer.service), not as whoever runs this script -- it needs
    # "other" read/execute on the dir and "other" read on the file to open
    # them at all. mkdir/write_bytes alone would leave that to the caller's
    # umask, which is fine under the common 022 default but silently breaks
    # detection under a stricter one (e.g. 077), so set the bits explicitly
    # rather than trust the environment.
    _GENERATED_CERT_DIR.mkdir(parents=True, exist_ok=True)
    _GENERATED_CERT_DIR.chmod(0o755)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
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
            "certificate-file-access.yaml TracingPolicy.",

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
]

USE_CASES_BY_ID = {uc.id: uc for uc in USE_CASES}
