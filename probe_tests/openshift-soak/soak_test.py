#!/usr/bin/env python3
"""
soak_test.py — OpenShift/container variant of probe_tests/test_large_cert_bundle.py

Same large-file background-parsing and re-access-cardinality-cap scenario as the
bare-metal script, adapted to run *inside* a Job pod on the same node as the
cert-analyzer DaemonSet instead of being driven from an external host:

  - --out-dir writes into a hostPath-mounted directory (see job.yaml) so the
    write is a genuine host-level file operation, visible to both Tetragon's
    real-time fd_install kprobe and cert-analyzer's own periodic scan of
    /host/etc/pki — exactly like the bare-metal version, just via a container
    mount instead of a local filesystem write.
  - The parallel-process re-access burst still spawns real distinct processes
    (copies of /bin/cat) from *within this container* — no need to shell out
    via `oc debug node` per accessor, which would be far too slow to produce a
    realistic near-simultaneous burst.
  - No /etc/cert-analyzer/cert-analyzer.conf to read (that's a bare-metal RPM
    artifact) — large_file_cert_threshold / large_file_metrics_cap are passed
    explicitly via --threshold/--metrics-cap, defaulting to the same values as
    extras/openshift/daemonset.yaml.
  - --duration lets a soak run exit cleanly after N seconds instead of relying
    on Ctrl-C, which nobody is there to send to an unattended Job.

Usage:
  python3 soak_test.py                              # single burst, defaults
  python3 soak_test.py --count 50 --parallel-processes 25

  # Soak: repeat every --loop-interval seconds for up to --duration seconds
  # (omit --duration to run until the Job's own activeDeadlineSeconds/pod
  # eviction ends it):
  python3 soak_test.py --parallel-processes 25 --loop-interval 300 --duration 14400

Requires (see job.yaml):
  - Tetragon running with tetragon-policies/certificate-file-access.yaml loaded
  - cert-analyzer DaemonSet running on the same node
  - A hostPath volume mounted at --out-dir, on a path cert-analyzer's
    CERT_SCAN_PATHS covers (default /etc/pki/tls/certs, under /host/etc/pki)
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

DEFAULT_OUT_DIR = '/etc/pki/tls/certs'
DEFAULT_COUNT = 30
DEFAULT_THRESHOLD = 20    # must match extras/openshift/daemonset.yaml's LARGE_FILE_CERT_THRESHOLD
DEFAULT_METRICS_CAP = 300 # must match extras/openshift/daemonset.yaml's LARGE_FILE_METRICS_CAP
_SETTLE_WAIT = 3  # seconds to let cert-analyzer log the canary before we exit


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
        print('Check job.yaml\'s hostPath volume is mounted read-write at --out-dir.', file=sys.stderr)
        sys.exit(1)


_REACCESS_STAGGER_SECONDS = 0.05


def _reaccess_from_parallel_processes(target_path: str, count: int, run_id: str) -> None:
    """
    Open `target_path` from `count` distinct processes, launched a few
    milliseconds apart rather than all at once.

    Each accessor is its own copy of /bin/cat under a unique name, so Tetragon
    reports a distinct process.binary per copy — same technique as the
    bare-metal script. Note this alone is enough to produce distinct
    tls_certificate_process_info series even though every accessor shares the
    same pod/namespace/container_name (this soak Job's own): `process` is one
    component of the metric's fan-out key, so varying it is sufficient without
    needing N separate pods.

    The opener temp dir must NOT have "cert-analyzer" or "cert_analyzer"
    anywhere in its path — process_event()'s filter_self_events check skips
    any event whose process path contains those substrings.
    """
    opener_dir = tempfile.mkdtemp(prefix='soak-reaccess-probe-')
    opener_paths = []
    try:
        for i in range(count):
            opener_path = os.path.join(opener_dir, f'bundle-opener-{run_id}-{i}')
            shutil.copy('/bin/cat', opener_path)
            os.chmod(opener_path, 0o755)
            opener_paths.append(opener_path)

        print(f'[soak] Launching {count} processes to re-access the bundle '
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
        print(f'[soak]   {count} processes finished at t=+{time.time() - t0:.3f}s')
    finally:
        shutil.rmtree(opener_dir, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description='OpenShift/container soak test for cert-analyzer\'s large-bundle and '
                    're-access-cardinality-cap paths',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('--count', type=int, default=DEFAULT_COUNT,
                        help=f'number of certs in the bundle (default: {DEFAULT_COUNT})')
    parser.add_argument('--out-dir', default=DEFAULT_OUT_DIR,
                        help=f'hostPath-mounted directory to write test files to (default: {DEFAULT_OUT_DIR})')
    parser.add_argument('--threshold', type=int, default=DEFAULT_THRESHOLD,
                        help=f'expected large_file_cert_threshold, for the printed reminders only '
                             f'(default: {DEFAULT_THRESHOLD})')
    parser.add_argument('--metrics-cap', type=int, default=DEFAULT_METRICS_CAP,
                        help=f'expected large_file_metrics_cap, for the printed reminders only '
                             f'(default: {DEFAULT_METRICS_CAP})')
    parser.add_argument('--keep', action='store_true',
                        help='keep the generated bundle/canary files instead of deleting them')
    parser.add_argument('--parallel-processes', type=int, default=0,
                        help='after the bundle is cached, re-access it from this many distinct, '
                             'concurrently-running processes to verify the cert_process_info '
                             're-access cardinality cap (default: 0 = skip this check)')
    parser.add_argument('--loop-interval', type=float, default=0,
                        help='if set, repeat the entire test every N seconds instead of running once '
                             '(default: 0 = run once)')
    parser.add_argument('--duration', type=float, default=0,
                        help='if set with --loop-interval, stop looping after this many seconds and '
                             'exit cleanly (Job-friendly — nothing is there to send Ctrl-C to an '
                             'unattended soak run). Ignored without --loop-interval. '
                             '(default: 0 = loop until the pod is terminated externally)')
    args = parser.parse_args()

    if args.loop_interval > 0:
        _run_loop(args)
    else:
        _run_once(args)


def _run_loop(args: argparse.Namespace) -> None:
    """Repeat _run_once every args.loop_interval seconds, up to args.duration seconds total."""
    start = time.time()
    iteration = 0
    while True:
        iteration += 1
        print(f'########## iteration {iteration} '
              f'({datetime.utcnow().isoformat()}Z, t=+{time.time() - start:.0f}s) ##########')
        _run_once(args, iteration=iteration)

        elapsed = time.time() - start
        if args.duration > 0 and elapsed >= args.duration:
            print(f'[soak] Reached --duration {args.duration}s after {iteration} iteration(s). Exiting.')
            return
        if args.duration > 0:
            remaining = args.duration - elapsed
            sleep_for = min(args.loop_interval, remaining)
        else:
            sleep_for = args.loop_interval
        print(f'[soak] Sleeping {sleep_for:.0f}s before next iteration...')
        print()
        time.sleep(sleep_for)


def _run_once(args: argparse.Namespace, iteration: Optional[int] = None) -> None:
    """Run a single instance of the bundle/canary/re-access scenario."""
    if args.count <= args.threshold:
        print(f'WARNING: --count {args.count} does not exceed --threshold ({args.threshold}) — '
              f'the bundle will be processed synchronously, not on a background thread.',
              file=sys.stderr)

    # A unique suffix per run: cert-analyzer's known_certs cache is keyed by path,
    # so re-using the same path across runs would skip re-analysis of new content.
    run_id = f'{os.getpid()}-{int(time.time())}'
    bundle_path = os.path.join(args.out_dir, f'soak-large-bundle-{run_id}.pem')
    canary_path = os.path.join(args.out_dir, f'soak-canary-{run_id}.pem')

    try:
        print(f'=== large-cert-bundle soak scenario ({args.count} certs) ===')
        print(f'Expected large_file_cert_threshold: {args.threshold}')
        print(f'Expected large_file_metrics_cap:    {args.metrics_cap}')
        print()

        print(f'[soak] Generating {args.count} self-signed certs -> {bundle_path}')
        bundle_data = b''.join(
            _make_self_signed_cert(f'soak-bundle-{run_id}-{i}.example.com') for i in range(args.count)
        )
        _write_file(bundle_path, bundle_data)

        print(f'[soak] Generating 1 canary cert -> {canary_path}')
        _write_file(canary_path, _make_self_signed_cert(f'soak-canary-{run_id}.example.com'))
        print()

        print('[soak] Opening the bundle — fires fd_install, should be routed to a background thread.')
        t0 = time.time()
        with open(bundle_path, 'rb') as f:
            f.read()
        print(f'[soak]   bundle opened at t=+{time.time() - t0:.3f}s')

        print('[soak] Immediately opening the canary — the event-consumer thread should stay free.')
        with open(canary_path, 'rb') as f:
            f.read()
        print(f'[soak]   canary opened at t=+{time.time() - t0:.3f}s')
        print()

        print(f'[soak] Waiting {_SETTLE_WAIT}s for cert-analyzer to process both...')
        time.sleep(_SETTLE_WAIT)
        print()

        if args.parallel_processes > 0:
            _reaccess_from_parallel_processes(bundle_path, args.parallel_processes, run_id)
            print(f'[soak] Waiting {_SETTLE_WAIT}s for cert-analyzer to process the re-accesses...')
            time.sleep(_SETTLE_WAIT)
            print()

        print('=== Verify (run from outside the cluster) ===')
        print()
        print(f'oc logs -n certsight -l app=cert-expiry-monitor --since=1m | grep -E '
              f'"soak-bundle-{run_id}|soak-canary-{run_id}"')
        print()
        print('curl -s http://cert-expiry-monitor-certsight.apps-<cluster-domain>/metrics '
              f'| grep -c \'CN="soak-bundle-{run_id}\'')
        print(f'# Expect {args.count} once the background parse finishes')
        print()

        if args.parallel_processes > 0:
            print('--- Re-access cardinality cap ---')
            print(f'curl -s http://cert-expiry-monitor-certsight.apps-<cluster-domain>/metrics '
                  f'| grep \'^tls_certificate_process_info\' | grep -cF \'cert_path="{bundle_path}"\'')
            print(f'# At most {args.parallel_processes + 1} * {args.metrics_cap} = '
                  f'{(args.parallel_processes + 1) * args.metrics_cap} series '
                  f'(capped per event to --metrics-cap)')
            print()
    finally:
        if not args.keep:
            for path in (bundle_path, canary_path):
                if os.path.exists(path):
                    try:
                        os.remove(path)
                    except OSError as e:
                        print(f'[soak] WARNING: could not remove {path}: {e}', file=sys.stderr)


if __name__ == '__main__':
    main()
