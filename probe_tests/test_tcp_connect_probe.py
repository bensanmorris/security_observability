#!/usr/bin/env python3
"""
test_tcp_connect_probe.py

Exercises the tcp-connect-tls kprobe + cert_analyzer outbound port-probe pipeline:

  1. Binds a local TLS server on port 9093 (a port in the policy's DPort filter).
  2. Makes an outbound TCP connect to that server — the connect syscall fires the
     tcp_connect kprobe in Tetragon (tcp-connect-tls.yaml policy, loaded separately).
  3. cert_analyzer receives the Tetragon event with the destination address and port,
     immediately probes that endpoint, completes a TLS handshake, and extracts the
     leaf certificate — making remote server certificate expiry visible without any
     per-service configuration.

This test plays both roles (server + client) in a single script because the trigger
is the outbound connect rather than the bind.  The server serves the cert; the
client-side connect fires the kprobe.

Burst mode (--count > 1) fires many near-simultaneous connects to distinct
loopback IPs on the same port — one port, many destination IPs, the same shape
as a package manager retrying a mirror list — to reproduce a suspected CPU
spike from a burst of connect-probes competing for cert_analyzer's
max_concurrent_background_threads cap (default 20; see agent/analyzer.py).

Usage:
  python3 test_tcp_connect_probe.py                      # default cert, port 9093
  python3 test_tcp_connect_probe.py --port 8443          # any port in TLS_OUTBOUND_PORTS
  python3 test_tcp_connect_probe.py --pause              # hold server open after wait
  python3 test_tcp_connect_probe.py --cert /path/to.crt --key /path/to.key
  python3 test_tcp_connect_probe.py --count 30           # burst: 30 near-simultaneous
                                                          # connects, one loopback IP each,
                                                          # same port

Requires:
  - Tetragon running with tetragon-policies/tcp-connect-tls.yaml loaded
  - cert_analyzer running with [port_probe] enabled = true
"""

import argparse
import os
import socket
import signal
import ssl
import sys
import threading
import time

_SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CERT = os.path.join(_SCRIPT_DIR, '..', 'test-certs', 'valid.crt')
DEFAULT_KEY  = os.path.join(_SCRIPT_DIR, '..', 'test-certs', 'valid.key')
DEFAULT_PORT = 9093   # Kafka TLS — in tcp-connect-tls.yaml DPort filter; no root required
DEFAULT_COUNT = 1
_PROBE_WAIT       = 5   # seconds to allow cert_analyzer to process a single connect event
_BURST_PROBE_WAIT = 10  # longer settle window for a burst, before scaling for large counts


def _serve(cert_path: str, key_path: str, bind_ip: str, port: int,
           ready: threading.Event, stop: threading.Event) -> None:
    """Accept TLS connections on bind_ip:port until stop is set."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_path, key_path)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind((bind_ip, port))
        raw.listen(10)
        raw.settimeout(1.0)
        ready.set()

        while not stop.is_set():
            try:
                conn, _ = raw.accept()
                try:
                    with ctx.wrap_socket(conn, server_side=True) as tls:
                        tls.recv(1)
                except ssl.SSLError:
                    pass
                except Exception:
                    pass
            except socket.timeout:
                pass


def _connect(host: str, port: int, barrier: threading.Barrier = None) -> None:
    """Open a TCP connection to host:port and close it. Fires the tcp_connect kprobe."""
    if barrier is not None:
        barrier.wait()
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            pass
    except Exception as e:
        print(f'[client] connect to {host}:{port} failed: {e}', file=sys.stderr)
        print('[client] The kprobe fires on connect() entry — cert_analyzer may still',
              file=sys.stderr)
        print('[client] receive the event even if the connection is refused.',
              file=sys.stderr)


def _loopback_ip(index: int) -> str:
    """
    Distinct loopback address for server #index (0-based). 127.0.0.0/8 is
    entirely loopback on Linux, so 127.0.0.2, 127.0.0.3, ... route to `lo`
    with no extra interface config — this is what lets burst mode fire N
    distinct *destination IPs* on one port, matching the real-world shape
    (e.g. dnf retrying several mirror IPs on port 443) instead of N connects
    to the same address.
    """
    return f'127.0.0.{index + 2}'


def _run_single(cert_path: str, key_path: str, port: int, pause: bool) -> None:
    """Original single-connection behavior: one server, one client, on 127.0.0.1."""
    stop  = threading.Event()
    ready = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    server = threading.Thread(
        target=_serve, args=(cert_path, key_path, '127.0.0.1', port, ready, stop), daemon=True
    )
    server.start()

    if not ready.wait(timeout=3):
        print('ERROR: TLS server did not start within 3 seconds', file=sys.stderr)
        sys.exit(1)

    print(f'[server] TLS server listening on 127.0.0.1:{port}  (PID {os.getpid()})')
    print(f'[server] cert: {cert_path}')
    print()

    print(f'[client] Connecting to 127.0.0.1:{port} — fires tcp_connect kprobe...')
    _connect('127.0.0.1', port)
    print('[client] Connect complete — Tetragon should have delivered the event to cert_analyzer')
    print()

    print(f'[test] Waiting {_PROBE_WAIT}s for cert_analyzer to process the event and probe...')
    print()
    print('Expected cert_analyzer log output:')
    print(f'  🔍 TLS probe: discovered cert at 127.0.0.1:{port} '
          f'CN=valid.example.com process=...')
    print(f'  ✅ OK: tls-connect-probe://127.0.0.1:{port} '
          f'(process=... CN=valid.example.com) valid for ...')
    print()
    print('Expected Prometheus metric (check on port 9090):')
    print('  tls_port_probes_total{status="success"} 1')
    print()

    stop.wait(_PROBE_WAIT)

    if not stop.is_set() and pause:
        print(f'[test] --pause: server still running on port {port} — Ctrl+C to exit')
        stop.wait()
    elif not stop.is_set():
        stop.set()


def _run_burst(cert_path: str, key_path: str, port: int, count: int, pause: bool) -> None:
    """
    Fire `count` near-simultaneous outbound connects, one per loopback IP, all
    to the same port. Each connect fires its own tcp_connect kprobe event;
    cert_analyzer dispatches each to its own background thread, bounded by
    max_concurrent_background_threads (default 20). Counts above that cap are
    the interesting case: watch cert_analyzer's logs for
    "Background thread cap (20) reached, skipping ..." to see probes drop
    under load instead of queuing.
    """
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    ips = [_loopback_ip(i) for i in range(count)]

    servers = []
    ready_events = []
    for ip in ips:
        ready = threading.Event()
        t = threading.Thread(
            target=_serve, args=(cert_path, key_path, ip, port, ready, stop), daemon=True
        )
        t.start()
        servers.append(t)
        ready_events.append(ready)

    for ip, ready in zip(ips, ready_events):
        if not ready.wait(timeout=3):
            print(f'ERROR: TLS server on {ip}:{port} did not start within 3 seconds',
                  file=sys.stderr)
            sys.exit(1)

    print(f'[server] {count} TLS servers listening on {ips[0]}:{port} .. {ips[-1]}:{port}')
    print(f'[server] cert: {cert_path}')
    print()

    barrier = threading.Barrier(count)
    clients = [
        threading.Thread(target=_connect, args=(ip, port, barrier), daemon=True)
        for ip in ips
    ]

    print(f'[client] Firing {count} near-simultaneous connects to port {port} '
          f'across {count} distinct destination IPs...')
    fire_start = time.monotonic()
    for c in clients:
        c.start()
    for c in clients:
        c.join()
    fire_elapsed = time.monotonic() - fire_start
    print(f'[client] Burst complete in {fire_elapsed:.3f}s — Tetragon should have delivered '
          f'{count} tcp_connect events to cert_analyzer')
    print()

    wait_s = _BURST_PROBE_WAIT if count <= 20 else _BURST_PROBE_WAIT + (count - 20) * 0.5
    print(f'[test] Waiting {wait_s:.1f}s for cert_analyzer to process the burst...')
    print()
    print('Watch for, on the cert_analyzer host:')
    print(f'  - up to {count} x "🔍 TLS probe: discovered cert at 127.0.0.x:{port} ..." / '
          f'"✅ OK: ..." lines')
    print('  - any "Background thread cap (20) reached, skipping tls-connect-probe-..." '
          'warnings (expected once count exceeds max_concurrent_background_threads)')
    print('  - CPU usage on the cert_analyzer process/pod during the burst')
    print()
    print('Expected Prometheus metrics (check on port 9090):')
    print(f'  tls_tcp_connect_events_total          incremented by {count}')
    print('  tls_port_probes_total{status="success"} incremented by up to '
          'max_concurrent_background_threads, the rest dropped if count exceeds the cap')
    print()

    stop.wait(wait_s)

    if not stop.is_set() and pause:
        print(f'[test] --pause: {count} servers still running on port {port} — Ctrl+C to exit')
        stop.wait()
    elif not stop.is_set():
        stop.set()


def main() -> None:
    parser = argparse.ArgumentParser(
        description='TCP outbound connect + port-probe integration test for cert_analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                        help=f'TCP port to connect to (default: {DEFAULT_PORT}). '
                             f'Must be in tcp-connect-tls.yaml DPort filter: '
                             f'443, 636, 2376, 4443, 5671, 5672, 5986, 6380, 6443, '
                             f'8140, 8443, 8883, 9093, 9094, 9443')
    parser.add_argument('--cert', default=DEFAULT_CERT,
                        help='PEM certificate file served by the local TLS server')
    parser.add_argument('--key',  default=DEFAULT_KEY,
                        help='PEM private key matching --cert')
    parser.add_argument('--count', type=int, default=DEFAULT_COUNT,
                        help='Number of near-simultaneous connects to fire, one per '
                             'loopback IP on the same port (default: 1 — the original '
                             'single-connect behavior). Use a value above '
                             "max_concurrent_background_threads (default 20) to "
                             "reproduce a burst that exceeds cert_analyzer's "
                             'concurrent-probe cap.')
    parser.add_argument('--pause', action='store_true',
                        help='Keep TLS server(s) running after the wait period (Ctrl+C to exit)')
    args = parser.parse_args()

    cert_path = os.path.abspath(args.cert)
    key_path  = os.path.abspath(args.key)

    for label, path in [('certificate', cert_path), ('key', key_path)]:
        if not os.path.exists(path):
            print(f'ERROR: {label} file not found: {path}', file=sys.stderr)
            sys.exit(1)

    if args.count < 1:
        print('ERROR: --count must be >= 1', file=sys.stderr)
        sys.exit(1)

    print('=== tcp-connect-tls / outbound port-probe test ===')
    print()
    print('Prerequisites:')
    print('  1. Tetragon running with tcp-connect-tls.yaml policy loaded:')
    print('       sudo tetra tracingpolicy add \\')
    print('         tetragon-policies/tcp-connect-tls.yaml')
    print('  2. cert_analyzer running with port probe enabled:')
    print('       [port_probe]')
    print('       enabled = true')
    print()

    if args.count == 1:
        _run_single(cert_path, key_path, args.port, args.pause)
    else:
        _run_burst(cert_path, key_path, args.port, args.count, args.pause)

    print()
    print('=== done ===')


if __name__ == '__main__':
    main()
