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
class UseCase:
    id: str
    label: str
    description: str
    run: Callable[[], UseCaseResult]


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


def _generate_and_read_fresh_cert() -> UseCaseResult:
    token = uuid.uuid4().hex[:12]
    cn = f"certsight-test-{token}.local"
    path = _GENERATED_CERT_DIR / f"generated-{token}.crt"

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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

    _GENERATED_CERT_DIR.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    try:
        proc = subprocess.run(["cat", str(path)], capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return UseCaseResult(ok=False, detail=f"cat {path} timed out")

    if proc.returncode != 0:
        return UseCaseResult(ok=False, detail=f"cat {path} exited {proc.returncode}: {proc.stderr.strip()}")
    return UseCaseResult(
        ok=True,
        detail=(
            f"generated a fresh self-signed cert (CN={cn}) at {path} and cat'd it -- "
            "unique path and serial number guarantee cert-analyzer treats this as a "
            "first-time discovery, so a new Kafka event should always appear"
        ),
    )


USE_CASES: List[UseCase] = [
    UseCase(
        id="fresh-test-cert",
        label="generate + read a fresh test certificate",
        description=(
            "Generates a new self-signed certificate at a unique path under "
            "/dev/shm and cat's it. Triggers cert-analyzer's file-access "
            "detection via the certificate-file-access.yaml Tetragon policy "
            "(fd_install kprobe), guaranteed to be a first-time discovery "
            "every click, so a new Kafka event always appears."
        ),
        run=_generate_and_read_fresh_cert,
    ),
]

USE_CASES_BY_ID = {uc.id: uc for uc in USE_CASES}
