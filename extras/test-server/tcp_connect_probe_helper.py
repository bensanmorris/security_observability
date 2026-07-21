#!/usr/bin/env python3
"""
Standalone helper spawned by use_cases.py's outbound tcp_connect probe use case.

Plays both roles in a single process, mirroring this repo's own reference
test for the same detection path (probe_tests/test_tcp_connect_probe.py):
binds a local TLS server on one of tcp-connect-tls.yaml's DPort-filtered
ports, then immediately makes an outbound connect() back to itself. That
connect() -- not the earlier bind() -- is the actual trigger: Tetragon's
kprobe is on tcp_connect, which fires on any outbound connection attempt
whose destination port matches the policy's DPort filter, tagged with the
connecting process's own PID. The client side doesn't need to complete a
TLS handshake itself (the kprobe fires on connect() entry, before any TLS
bytes are exchanged) -- only cert-analyzer's own follow-up probe needs this
process to actually speak TLS, which is why the server role stays up after
the client's connect() returns.

A separate process (not a thread inside the main test server), for the same
reason as tls_probe_helper.py: so Tetragon attributes the connect() to a PID
that's independently visible and verifiable in the UI, rather than the test
server's own.

Restricted to the DPort values in tcp-connect-tls.yaml that don't require
root to bind (443 and 636 are in that policy too, but binding a *listener*
on either needs CAP_NET_BIND_SERVICE, which this helper deliberately avoids
needing -- it only ever binds, never assumes privilege). Retries across that
list on a bind collision, same approach as tls_probe_helper.py's random-port
retry loop. IMPORTANT: keep this list in sync with
tetragon-policies/tcp-connect-tls.yaml's DPort values and cert-analyzer.conf's
tls_outbound_ports.

Prints "PORT <port>" to stdout once the outbound connect() has actually
happened -- i.e. once the interesting kernel event has already fired -- then
keeps the TLS server up for up to <lifetime_seconds> so cert-analyzer's own
follow-up probe (which reconnects to the same host:port independently, the
same way it does for the bind-probe use case) has time to complete its
handshake and pull the certificate.

Usage:
    tcp_connect_probe_helper.py <certfile> <keyfile> <lifetime_seconds>
"""
import random
import socket
import ssl
import sys
import threading
import time

_CANDIDATE_PORTS = [8443, 5671, 5672, 6380, 8883, 9093, 9094, 2376, 4443, 5986, 6443, 8140, 9443]


def _serve(sock: socket.socket, context: ssl.SSLContext, deadline: float, stop: threading.Event) -> None:
    while not stop.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        sock.settimeout(min(remaining, 1.0))
        try:
            conn, _addr = sock.accept()
        except socket.timeout:
            continue
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

    candidates = list(_CANDIDATE_PORTS)
    random.shuffle(candidates)
    sock = None
    last_err = None
    for candidate in candidates:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", candidate))
            s.listen(4)
            sock = s
            break
        except OSError as e:
            last_err = e
            s.close()
    if sock is None:
        print(f"ERROR bind/listen failed on every candidate port {candidates}: {last_err}", flush=True)
        return 1

    port = sock.getsockname()[1]
    deadline = time.monotonic() + lifetime
    stop = threading.Event()

    server_thread = threading.Thread(target=_serve, args=(sock, context, deadline, stop), daemon=True)
    server_thread.start()

    # The connect() below is the entire point of this helper existing --
    # Tetragon's tcp_connect kprobe fires right here, tagged with this
    # process's own PID and the real, explicit destination port -- exactly
    # like probe_tests/test_tcp_connect_probe.py's reference trigger for
    # this same detection path. A bare TCP connect is enough; no TLS is
    # negotiated on this side.
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3):
            pass
    except OSError as e:
        print(f"ERROR outbound connect to 127.0.0.1:{port} failed: {e}", flush=True)
        stop.set()
        return 1

    print(f"PORT {port}", flush=True)

    remaining = deadline - time.monotonic()
    if remaining > 0:
        server_thread.join(timeout=remaining)
    stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
