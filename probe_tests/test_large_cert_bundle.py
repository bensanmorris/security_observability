#!/usr/bin/env python3
"""
test_large_cert_bundle.py

Exercises the large-file background-parsing path in cert_analyzer
(agent/analyzer.py: _count_pem_certs / _process_certificate_file_async):

  1. Generates a PEM bundle with more certificates than the configured
     large_file_cert_threshold (default 20) and opens it, firing the
     fd_install kprobe in certificate-file-access.yaml.
  2. Immediately opens a single-cert "canary" file, firing a second
     fd_install event for a small file.
  3. Because the bundle is parsed on a background thread, cert_analyzer's
     Tetragon event-consumer loop should keep draining events and process
     the canary promptly — its log line should not be delayed behind the
     hundreds-of-certs bundle.

Usage:
  python3 test_large_cert_bundle.py                  # default: 30 certs
  python3 test_large_cert_bundle.py --count 50
  python3 test_large_cert_bundle.py --out-dir /etc/pki/tls/certs
  python3 test_large_cert_bundle.py --keep            # don't delete generated files

  # Also verify the re-access cardinality cap (agent/analyzer.py process_event's
  # cache-hit branch, agent/metrics.py record_cert_process_access): once the
  # bundle is cached, spawn N distinct processes that each independently open
  # it, simulating e.g. a shared system CA bundle being read by many unrelated
  # binaries. Prometheus's tls_certificate_process_info series for the bundle
  # should stay bounded (~large_file_cert_threshold per process), not grow as
  # N * cert-count.
  python3 test_large_cert_bundle.py --parallel-processes 25

Requires:
  - Tetragon running with tetragon-policies/certificate-file-access.yaml loaded
  - cert_analyzer running
  - --out-dir must be a path cert_analyzer can read. cert_analyzer runs with
    ProtectHome=true and PrivateTmp=true, so /home and /tmp are not visible to
    it — /etc/pki/tls/certs/ is in the service's ReadOnlyPaths and is the
    default here. Writing there typically requires sudo.
"""

import argparse
import configparser
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT_DIR = '/etc/pki/tls/certs'
DEFAULT_COUNT = 30
CONFIG_FILE_PATH = '/etc/cert-analyzer/cert-analyzer.conf'
_SETTLE_WAIT = 3  # seconds to let cert_analyzer log the canary before we exit


def _effective_threshold() -> int:
    """Best-effort read of the configured large_file_cert_threshold, for the reminder printed below."""
    default = int(os.getenv('LARGE_FILE_CERT_THRESHOLD', '20'))
    cp = configparser.ConfigParser()
    try:
        if os.access(CONFIG_FILE_PATH, os.R_OK):
            cp.read(CONFIG_FILE_PATH)
            if cp.has_option('certificates', 'large_file_cert_threshold'):
                return int(cp.get('certificates', 'large_file_cert_threshold'))
    except (OSError, configparser.Error, ValueError):
        pass
    return default


def _make_self_signed_cert(common_name: str) -> bytes:
    """Generate a throwaway EC self-signed cert (fast — avoids RSA keygen cost for bulk generation)."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(encoding=serialization.Encoding.PEM)


def _write_file(path: str, data: bytes) -> None:
    try:
        with open(path, 'wb') as f:
            f.write(data)
        os.chmod(path, 0o644)
    except PermissionError:
        print(f'ERROR: permission denied writing {path}', file=sys.stderr)
        print('Re-run with sudo, or pass --out-dir pointing to a location', file=sys.stderr)
        print('cert_analyzer can read (see probe_tests/README.md).', file=sys.stderr)
        sys.exit(1)


_REACCESS_STAGGER_SECONDS = 0.05


def _reaccess_from_parallel_processes(target_path: str, count: int, run_id: str) -> None:
    """
    Open `target_path` from `count` distinct processes, launched a few
    milliseconds apart rather than all at once.

    Each accessor is its own copy of /bin/cat under a unique name, so Tetragon
    (which identifies the accessing process by its resolved binary path)
    reports a distinct process.binary per copy — same as N unrelated real
    binaries (pingsender, curl, some init script, ...) independently opening a
    shared file like a system CA bundle. A single re-used binary would collapse
    back to one process identity and defeat the point of the test.

    The opener temp dir must NOT have "cert-analyzer" or "cert_analyzer"
    anywhere in its path: process_event()'s filter_self_events check skips any
    event whose process path contains those substrings (meant to stop
    cert-analyzer from tracing its own file accesses). An earlier version of
    this helper used prefix='cert-analyzer-probe-openers-', which silently
    self-filtered every single re-access event — Tetragon captured and
    delivered them correctly, cert-analyzer just discarded them all by design.
    Confirmed via DEBUG-level logging: "Skipping self-generated event from
    /tmp/cert-analyzer-probe-openers-.../bundle-opener-...".

    The small stagger between launches is a smaller, separate precaution —
    launching all N via back-to-back subprocess.Popen() with no delay at all
    means many execs/opens/exits within a handful of milliseconds, which is
    unrepresentative of the real-world scenario (many distinct binaries
    reading a shared bundle over seconds, not milliseconds) even if Tetragon
    handles the burst fine.
    """
    opener_dir = tempfile.mkdtemp(prefix='cert-bundle-reaccess-probe-')
    opener_paths = []
    try:
        for i in range(count):
            opener_path = os.path.join(opener_dir, f'bundle-opener-{run_id}-{i}')
            shutil.copy('/bin/cat', opener_path)
            os.chmod(opener_path, 0o755)
            opener_paths.append(opener_path)

        print(f'[test] Launching {count} processes to re-access the bundle '
              f'({_REACCESS_STAGGER_SECONDS * 1000:.0f}ms apart)...')
        t0 = time.time()
        procs = []
        for opener_path in opener_paths:
            procs.append(
                subprocess.Popen([opener_path, target_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            )
            time.sleep(_REACCESS_STAGGER_SECONDS)
        for p in procs:
            p.wait()
        print(f'[test]   {count} processes finished at t=+{time.time() - t0:.3f}s')
    finally:
        shutil.rmtree(opener_dir, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Large multi-cert bundle background-parsing test for cert_analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('--count', type=int, default=DEFAULT_COUNT,
                        help=f'number of certs in the bundle (default: {DEFAULT_COUNT})')
    parser.add_argument('--out-dir', default=DEFAULT_OUT_DIR,
                        help=f'directory to write test files to (default: {DEFAULT_OUT_DIR})')
    parser.add_argument('--keep', action='store_true',
                        help='keep the generated bundle/canary files instead of printing an rm command')
    parser.add_argument('--parallel-processes', type=int, default=0,
                        help='after the bundle is cached, re-access it from this many distinct, '
                             'concurrently-running processes to verify the cert_process_info '
                             're-access cardinality cap (default: 0 = skip this check)')
    args = parser.parse_args()

    threshold = _effective_threshold()
    if args.count <= threshold:
        print(f'WARNING: --count {args.count} does not exceed the configured '
              f'large_file_cert_threshold ({threshold}) — the bundle will be '
              f'processed synchronously, not on a background thread.', file=sys.stderr)
        print('Increase --count or lower large_file_cert_threshold in cert-analyzer.conf.\n',
              file=sys.stderr)

    # A unique suffix per run is required: cert_analyzer's known_certs cache is
    # keyed by path only (agent/analyzer.py process_event's "already known" check
    # is `key.startswith(cert_path + ":")`), so re-using the same path across runs
    # would hit that fast path and skip re-analysis of the new file content.
    run_id = f'{os.getpid()}-{int(time.time())}'
    bundle_path = os.path.join(args.out_dir, f'cert-analyzer-large-bundle-test-{run_id}.pem')
    canary_path = os.path.join(args.out_dir, f'cert-analyzer-canary-test-{run_id}.pem')

    print(f'=== large-cert-bundle background-parsing test ({args.count} certs) ===')
    print()
    print('Prerequisites:')
    print('  Tetragon running with certificate-file-access.yaml policy loaded:')
    print('    sudo tetra tracingpolicy add tetragon-policies/certificate-file-access.yaml')
    print()
    print(f'Configured large_file_cert_threshold: {threshold}')
    print()

    print(f'[test] Generating {args.count} self-signed certs -> {bundle_path}')
    bundle_data = b''.join(
        _make_self_signed_cert(f'bundle-test-{i}.example.com') for i in range(args.count)
    )
    _write_file(bundle_path, bundle_data)

    print(f'[test] Generating 1 canary cert -> {canary_path}')
    _write_file(canary_path, _make_self_signed_cert('canary.example.com'))
    print()

    print('[test] Opening the bundle — this fires fd_install and should be picked up')
    print('       by cert_analyzer as a large file and handed to a background thread.')
    t0 = time.time()
    with open(bundle_path, 'rb') as f:
        f.read()
    print(f'[test]   bundle opened at t=+{time.time() - t0:.3f}s')

    print('[test] Immediately opening the canary — proves the event-consumer thread')
    print('       is still free to process new events while the bundle parses.')
    with open(canary_path, 'rb') as f:
        f.read()
    print(f'[test]   canary opened at t=+{time.time() - t0:.3f}s')
    print()

    print(f'[test] Waiting {_SETTLE_WAIT}s for cert_analyzer to log both...')
    time.sleep(_SETTLE_WAIT)
    print()

    if args.parallel_processes > 0:
        # Only meaningful once the bundle is actually cached — re-accessing it
        # while the background parse is still in flight would just pile onto
        # the initial-parse path (already capped in _finish_new_certificate_file)
        # instead of exercising process_event's cache-hit re-access cap.
        _reaccess_from_parallel_processes(bundle_path, args.parallel_processes, run_id)
        print(f'[test] Waiting {_SETTLE_WAIT}s for cert_analyzer to process the re-accesses...')
        time.sleep(_SETTLE_WAIT)
        print()

    print('=== Verify ===')
    print()
    print('journalctl -u cert-analyzer --since "-1 min" | grep -E "bundle-test|canary"')
    print()
    print('Expected (canary lines should NOT be delayed behind the bundle):')
    print(f'  🔍 Detected certificate access: {bundle_path} ...')
    print(f'  🔍 Detected certificate access: {canary_path} ...')
    print(f'  ✅ OK: {canary_path} [cert #1] ... CN=canary.example.com ...')
    print(f'  Found {args.count} certificate(s) in {bundle_path} (parsed in background — large file)')
    print()
    print('If the canary\'s "Detected certificate access" / "OK" lines appear within')
    print('a second or two of being triggered — even though the bundle line above may')
    print('land later — the background thread is doing its job and the event loop was')
    print('not blocked by the large file.')
    print()
    print(f'curl -s http://localhost:9090/metrics | grep -c \'CN="bundle-test\'')
    print(f'# Expect {args.count} once the background parse finishes')
    print()

    if args.parallel_processes > 0:
        cap = threshold
        print('--- Re-access cardinality cap ---')
        print()
        print(f'{args.parallel_processes} distinct processes each re-opened the already-cached')
        print(f'bundle. Each re-access is capped to large_file_cert_threshold '
              f'({cap}) tracked certs (agent/analyzer.py process_event, cache-hit branch),')
        print(f'instead of one tls_certificate_process_info series per (cached cert, process) pair:')
        print()
        print(f'curl -s http://localhost:9090/metrics | grep \'^tls_certificate_process_info\' '
              f'| grep -cF \'cert_path="{bundle_path}"\'')
        print(f'# Before the fix: up to {args.parallel_processes + 1} * {args.count} = '
              f'{(args.parallel_processes + 1) * args.count} series (N processes x every cached cert)')
        print(f'# After the fix:  at most {args.parallel_processes + 1} * {cap} = '
              f'{(args.parallel_processes + 1) * cap} series (capped per event to large_file_cert_threshold)')
        print()

    if not args.keep:
        rm_prefix = 'sudo ' if not os.access(args.out_dir, os.W_OK) else ''
        print('=== Cleanup ===')
        print(f'{rm_prefix}rm {bundle_path} {canary_path}')


if __name__ == '__main__':
    main()
