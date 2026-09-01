#!/usr/bin/env python3
"""
Standalone helper spawned by use_cases.py's connect-probe SNI-capture use
case -- verifies the SSL_ctrl uprobe added on branch connect_probe_sni_capture
(see agent/analyzer.py's _handle_ssl_ctrl_sni_capture and
extras/PRESENTATION-QA.md's "SNI-multiplexed CDN edge" entry) actually makes
cert-analyzer's connect-probe use the real SNI hostname instead of the raw
destination IP.

Plays two roles in one process, both needed for cert-analyzer's own
follow-up probe (a separate, independent connection -- same as every other
connect-probe/bind-probe use case here) to have something to distinguish:

1. A TLS server on one of tcp-connect-tls.yaml's DPort-filtered ports,
   standing in for an SNI-multiplexed CDN edge: an SNI callback serves one
   of *two* different certificates depending on the SNI hostname actually
   received on each connection -- the "real" cert for the exact hostname
   this helper's own client role below sends, and a "fallback" cert
   (standing in for a CDN edge's generic default vhost) for anything else,
   including a bare IP address or no SNI at all.

2. A client that connects to that same port with a real TLS ClientHello,
   presenting the real hostname as SNI via server_hostname= -- exactly what
   CPython's ssl module does for any ordinary HTTPS client. The connect()
   is what fires Tetragon's tcp_connect kprobe (tagged with this process's
   own PID); wrapping it with server_hostname= is what fires the
   SSL_ctrl(cmd==SSL_CTRL_SET_TLSEXT_HOSTNAME) uprobe, tagged with the same
   PID -- the two events cert-analyzer's [port_probe] sni_capture_enabled
   correlates to decide what hostname to send when it re-dials.

With sni_capture_enabled left at its default false, cert-analyzer's probe
has no captured hostname to use, dials with the raw destination IP as SNI
(same as before this fix), and gets served the fallback cert. With it
enabled and a fresh capture, cert-analyzer dials with the real captured
hostname instead and gets served the real cert. Compare the CN in the
resulting Kafka event against the two CNs use_cases.py reports back to see
which happened.

Restricted to the same non-privileged DPort subset as
tcp_connect_probe_helper.py, kept in sync with it by hand -- see that
file's own comment. IMPORTANT: keep this list in sync with
tetragon-policies/tcp-connect-tls.yaml's DPort values and
cert-analyzer.conf's tls_outbound_ports.

Prints "PORT <port> REAL_SNI <hostname>" once the outbound connect() and its
SNI-bearing handshake have both actually happened, then keeps the TLS
server up for up to <lifetime_seconds> so cert-analyzer's own follow-up
probe has time to complete its (independent) handshake.

Usage:
    tcp_connect_sni_probe_helper.py <real_certfile> <real_keyfile> \
        <fallback_certfile> <fallback_keyfile> <real_hostname> <lifetime_seconds>
"""
import random
import socket
import ssl
import sys
import threading
import time

_CANDIDATE_PORTS = [8443, 5671, 5672, 6380, 8883, 9093, 9094, 2376, 4443, 5986, 6443, 8140, 9443]


def _serve(sock: socket.socket, fallback_ctx: ssl.SSLContext, real_ctx: ssl.SSLContext,
           real_hostname: str, deadline: float, stop: threading.Event) -> None:
    def _sni_callback(sslsock, servername, sslctx):
        if servername == real_hostname:
            sslsock.context = real_ctx
        # else: leave sslsock.context as fallback_ctx (already the default on
        # accept) -- matches an SNI-multiplexed edge falling back to its
        # generic vhost for an unrecognized/absent/IP-literal SNI value.

    fallback_ctx.sni_callback = _sni_callback

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
            # peer whichever certificate the SNI callback above picked --
            # completes inside wrap_socket() itself.
            with fallback_ctx.wrap_socket(conn, server_side=True):
                pass
        except (ssl.SSLError, OSError):
            # A failed/aborted handshake (e.g. a stray non-TLS connection) --
            # keep serving for whatever lifetime remains rather than dying.
            conn.close()


def main() -> int:
    if len(sys.argv) != 7:
        print(
            f"ERROR usage: {sys.argv[0]} <real_certfile> <real_keyfile> "
            "<fallback_certfile> <fallback_keyfile> <real_hostname> <lifetime_seconds>",
            flush=True,
        )
        return 2
    real_certfile, real_keyfile, fallback_certfile, fallback_keyfile, real_hostname, lifetime_str = sys.argv[1:7]
    lifetime = float(lifetime_str)

    real_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    fallback_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        real_ctx.load_cert_chain(certfile=real_certfile, keyfile=real_keyfile)
        fallback_ctx.load_cert_chain(certfile=fallback_certfile, keyfile=fallback_keyfile)
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

    server_thread = threading.Thread(
        target=_serve, args=(sock, fallback_ctx, real_ctx, real_hostname, deadline, stop), daemon=True,
    )
    server_thread.start()

    # The connect() below fires Tetragon's tcp_connect kprobe, tagged with
    # this process's own PID -- same as tcp_connect_probe_helper.py. Unlike
    # that helper, this client role goes on to complete a real TLS handshake
    # of its own, presenting the real hostname as SNI via server_hostname= --
    # CPython's ssl module calls SSL_set_tlsext_host_name (which compiles
    # down to SSL_ctrl(cmd==55), no exported symbol of its own) for that,
    # from this same PID, which is the second half of what cert-analyzer's
    # SSL_ctrl uprobe needs in order to have something to correlate.
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as raw_sock:
            with client_ctx.wrap_socket(raw_sock, server_hostname=real_hostname):
                pass
    except OSError as e:
        print(f"ERROR outbound TLS connect to 127.0.0.1:{port} failed: {e}", flush=True)
        stop.set()
        return 1

    print(f"PORT {port} REAL_SNI {real_hostname}", flush=True)

    remaining = deadline - time.monotonic()
    if remaining > 0:
        server_thread.join(timeout=remaining)
    stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
