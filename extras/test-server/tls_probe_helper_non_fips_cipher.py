#!/usr/bin/env python3
"""
Standalone helper spawned by use_cases.py's "bind a non-FIPS-cipher TLS
service" use case.

Identical to tls_probe_helper.py (same module docstring rationale applies
for running as a separate process, binding the wildcard address, and picking
an explicit nonzero port) except for one thing: the SSLContext below is
deliberately pinned to TLS 1.2 and a single cipher --
ECDHE-RSA-CHACHA20-POLY1305 -- which is NOT in fleet_fips_rollout.py's
_APPROVED_TLS12_CIPHERS allowlist (NIST SP 800-52 Rev. 2 approves
AES-GCM/AES-CBC combinations for TLS 1.2, not ChaCha20-Poly1305, regardless
of TLS version). The certificate served here is otherwise unremarkable and
individually FIPS-compliant -- the point is to demonstrate the "cipher
drift" case the FIPS rollout explorer flags: a compliant certificate on a
node whose live TLS session still negotiates a non-approved cipher.

Usage:
    tls_probe_helper_non_fips_cipher.py <certfile> <keyfile> <lifetime_seconds>
"""
import random
import socket
import ssl
import sys
import time

_PORT_RANGE = (49152, 65535)
_BIND_ATTEMPTS = 10
_NON_FIPS_CIPHER = "ECDHE-RSA-CHACHA20-POLY1305"


def main() -> int:
    if len(sys.argv) != 4:
        print(f"ERROR usage: {sys.argv[0]} <certfile> <keyfile> <lifetime_seconds>", flush=True)
        return 2
    certfile, keyfile, lifetime_str = sys.argv[1:4]
    lifetime = float(lifetime_str)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    except Exception as e:
        print(f"ERROR failed to load cert/key: {e}", flush=True)
        return 1

    # set_ciphers() only governs TLS <=1.2 suite selection -- TLS 1.3
    # ciphersuites aren't controllable through it, and a client capable of
    # 1.3 would otherwise prefer it over anything offered here regardless of
    # this cipher list. Capping maximum_version forces negotiation down to
    # 1.2, where this single-entry cipher list actually takes effect.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(_NON_FIPS_CIPHER)

    sock = None
    last_err = None
    for _ in range(_BIND_ATTEMPTS):
        candidate = random.randint(*_PORT_RANGE)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("0.0.0.0", candidate))  # nosec B104 - see tls_probe_helper.py's docstring for why wildcard, not loopback
            s.listen(4)
            sock = s
            break
        except OSError as e:
            last_err = e
            s.close()
    if sock is None:
        print(f"ERROR bind/listen failed after {_BIND_ATTEMPTS} attempts: {last_err}", flush=True)
        return 1

    port = sock.getsockname()[1]
    print(f"PORT {port}", flush=True)

    deadline = time.monotonic() + lifetime
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(remaining)
        try:
            conn, _addr = sock.accept()
        except socket.timeout:
            break
        try:
            with context.wrap_socket(conn, server_side=True):
                pass
        except (ssl.SSLError, OSError):
            conn.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
