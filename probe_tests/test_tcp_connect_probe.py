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

Usage:
  python3 test_tcp_connect_probe.py                      # default cert, port 9093
  python3 test_tcp_connect_probe.py --port 8443          # any port in TLS_OUTBOUND_PORTS
  python3 test_tcp_connect_probe.py --pause              # hold server open after wait
  python3 test_tcp_connect_probe.py --cert /path/to.crt --key /path/to.key

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
_PROBE_WAIT  = 5      # seconds to allow cert_analyzer to process the connect event and probe


def _serve(cert_path: str, key_path: str, port: int, ready: threading.Event,
           stop: threading.Event) -> None:
    """Accept TLS connections on port until stop is set."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind(('127.0.0.1', port))
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


def _connect(host: str, port: int) -> None:
    """Open a TCP connection to host:port and close it. Fires the tcp_connect kprobe."""
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            pass
    except Exception as e:
        print(f'[client] connect to {host}:{port} failed: {e}', file=sys.stderr)
        print('[client] The kprobe fires on connect() entry — cert_analyzer may still',
              file=sys.stderr)
        print('[client] receive the event even if the connection is refused.',
              file=sys.stderr)


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
    parser.add_argument('--pause', action='store_true',
                        help='Keep TLS server running after the wait period (Ctrl+C to exit)')
    args = parser.parse_args()

    cert_path = os.path.abspath(args.cert)
    key_path  = os.path.abspath(args.key)

    for label, path in [('certificate', cert_path), ('key', key_path)]:
        if not os.path.exists(path):
            print(f'ERROR: {label} file not found: {path}', file=sys.stderr)
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

    stop  = threading.Event()
    ready = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    server = threading.Thread(
        target=_serve, args=(cert_path, key_path, args.port, ready, stop), daemon=True
    )
    server.start()

    if not ready.wait(timeout=3):
        print('ERROR: TLS server did not start within 3 seconds', file=sys.stderr)
        sys.exit(1)

    print(f'[server] TLS server listening on 127.0.0.1:{args.port}  (PID {os.getpid()})')
    print(f'[server] cert: {cert_path}')
    print()

    print(f'[client] Connecting to 127.0.0.1:{args.port} — fires tcp_connect kprobe...')
    _connect('127.0.0.1', args.port)
    print('[client] Connect complete — Tetragon should have delivered the event to cert_analyzer')
    print()

    print(f'[test] Waiting {_PROBE_WAIT}s for cert_analyzer to process the event and probe...')
    print()
    print('Expected cert_analyzer log output:')
    print(f'  🔍 TLS probe: discovered cert at 127.0.0.1:{args.port} '
          f'CN=valid.example.com process=...')
    print(f'  ✅ OK: tls-connect-probe://127.0.0.1:{args.port} '
          f'(process=... CN=valid.example.com) valid for ...')
    print()
    print('Expected Prometheus metric (check on port 9090):')
    print('  tls_port_probes_total{status="success"} 1')
    print()

    stop.wait(_PROBE_WAIT)

    if not stop.is_set() and args.pause:
        print(f'[test] --pause: server still running on port {args.port} — Ctrl+C to exit')
        stop.wait()
    elif not stop.is_set():
        stop.set()

    print()
    print('=== done ===')


if __name__ == '__main__':
    main()
