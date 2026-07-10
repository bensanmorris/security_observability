#!/usr/bin/env python3
"""
Standalone helper spawned by use_cases.py's TLS bind-probe use case.

Binds a TCP socket to 127.0.0.1:0 (OS-assigned ephemeral port) itself --
deliberately a separate process rather than a thread inside the main test
server, so that Tetragon's security_socket_bind hook attributes the bind
to *this* process's own PID. use_cases.py surfaces that PID in the UI so
it can be cross-checked against the "pid" field of the resulting Kafka
event.

Prints "PORT <port>" to stdout the instant the socket is bound and
listening, then serves TLS handshakes (using the cert/key passed on the
command line) against incoming connections for up to <lifetime_seconds>
before exiting on its own -- long enough to cover cert-analyzer's
[port_probe] connect_delay_seconds (default 2s) plus margin, without
lingering forever if nothing ever connects.

Usage:
    tls_probe_helper.py <certfile> <keyfile> <lifetime_seconds>
"""
import socket
import ssl
import sys
import time


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

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # The bind() call below is the entire point of this process existing
        # separately from its parent -- Tetragon's security_socket_bind kprobe
        # fires right here, tagged with this process's own PID.
        sock.bind(("127.0.0.1", 0))
        sock.listen(4)
    except OSError as e:
        print(f"ERROR bind/listen failed: {e}", flush=True)
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
            # do_handshake_on_connect defaults to True, so the handshake --
            # the only part that matters here, since it's what hands the
            # peer our certificate -- completes inside wrap_socket() itself.
            with context.wrap_socket(conn, server_side=True):
                pass
        except (ssl.SSLError, OSError):
            # A failed/aborted handshake (e.g. a stray non-TLS connection) --
            # keep serving for whatever lifetime remains rather than dying.
            conn.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
