#!/usr/bin/env python3
"""
test_new_cert_rate_limit.py

Exercises the new-certificate rate limiter and its retry queue
(agent/analyzer.py: _TokenBucket / new_cert_events_per_second, gated in
_analyze_and_finish_new_certificate_file(); _enqueue_rate_limited_retry /
_start_retry_queue_drainer for throttled files):

  1. Generates --count unique self-signed certs and writes them all into
     --out-dir in one burst, firing --count fd_install events
     (certificate-file-access.yaml) almost simultaneously.
  2. Only the first ~new_cert_events_per_second get analyzed immediately
     (token bucket burst capacity) -- the rest are throttled and queued for
     replay by the retry-queue drainer thread, which shares the same token
     budget as fresh events rather than having one of its own.
  3. With --wait, polls cert_analyzer's own /metrics until every burst cert
     has surfaced in tls_certificate_expiry_days (or a timeout trips),
     reporting a timeline of retry_queue_depth draining over the run.

This is a load/regression test for the fix that closed a real gap found
2026-07-14: the rate limiter's "throttled but not lost" guarantee only held
if periodic_scan happened to cover the file's directory. A burst written
outside scan_paths plateaued partway through and never recovered, before the
retry queue existed to give every throttled file a guaranteed replay path
independent of scan_paths coverage.

Usage:
  python3 test_new_cert_rate_limit.py                       # default: 500 certs, print verify commands
  python3 test_new_cert_rate_limit.py --count 2000
  python3 test_new_cert_rate_limit.py --count 5000 --wait   # burst + poll until 100% surfaced or timeout
  python3 test_new_cert_rate_limit.py --wait --timeout 120
  python3 test_new_cert_rate_limit.py --out-dir /etc/pki/tls/certs/rate-limit-probe

Notes on scale -- two separate caps can each stop a large --wait run from
reaching 100%, neither of which is a rate-limiter bug:

  - retry_queue_max_size (default 2000) bounds the retry queue itself -- a
    burst larger than that overflows it and permanently drops the *oldest*
    queued entries (see cert_analysis_errors{error_type="retry_queue_dropped"}),
    not just delays them. Keep --count at or under whatever
    retry_queue_max_size is currently configured to for --wait to reach 100%.

  - known_certs is separately LRU-capped at CACHE_MAX_SIZE (default 10,000),
    shared with every other cert cert_analyzer already knows about on this
    host. A burst that pushes the total past that cap evicts older entries
    (including earlier members of this same burst) to make room --
    cert_analyzer_cache_known_certs_size / cert_analyzer_cache_max_size in
    /metrics show the current occupancy/cap. Leave headroom under the cap
    (accounting for the host's pre-existing known cert count) for --wait to
    cleanly reach 100%.

Requires:
  - Tetragon running with tetragon-policies/certificate-file-access.yaml loaded
  - cert_analyzer running
  - --out-dir must be a path cert_analyzer can read. cert_analyzer runs with
    ProtectHome=true and PrivateTmp=true, so /home and /tmp are not visible to
    it -- /etc/pki/tls/certs/ is in the service's ReadOnlyPaths and is the
    default here. Writing there typically requires sudo.
"""

import argparse
import configparser
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

DEFAULT_OUT_DIR = '/etc/pki/tls/certs'
DEFAULT_COUNT = 500
DEFAULT_METRICS_URL = 'http://localhost:9090/metrics'
CONFIG_FILE_PATH = '/etc/cert-analyzer/cert-analyzer.conf'


def _effective_config_value(option: str, env_var: str, default: str, cast) -> object:
    """Best-effort read of a [certificates] option, for the reminders printed below."""
    fallback = cast(os.getenv(env_var, default))
    cp = configparser.ConfigParser()
    try:
        if os.access(CONFIG_FILE_PATH, os.R_OK):
            cp.read(CONFIG_FILE_PATH)
            if cp.has_option('certificates', option):
                return cast(cp.get('certificates', option))
    except (OSError, configparser.Error, ValueError):
        pass
    return fallback


def _effective_rate() -> float:
    return _effective_config_value('new_cert_events_per_second', 'NEW_CERT_EVENTS_PER_SECOND', '50', float)


def _effective_retry_queue_max_size() -> int:
    return _effective_config_value('retry_queue_max_size', 'RETRY_QUEUE_MAX_SIZE', '2000', int)


def _make_self_signed_cert(common_name: str) -> bytes:
    """Generate a throwaway EC self-signed cert (fast -- avoids RSA keygen cost for bulk generation)."""
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


def _fetch_metrics_text(metrics_url: str) -> str:
    with urllib.request.urlopen(metrics_url, timeout=5) as resp:
        return resp.read().decode('utf-8', errors='replace')


def _count_surfaced(metrics_text: str, cn_prefix: str) -> int:
    """Distinct cert_path values for this run's certs that have made it into
    tls_certificate_expiry_days -- i.e. fully analyzed, not just written to disk."""
    pattern = re.compile(r'cert_path="([^"]*' + re.escape(cn_prefix) + r'[^"]*)"')
    return len(set(pattern.findall(metrics_text)))


def _wait_for_convergence(cn_prefix: str, total: int, metrics_url: str,
                           poll_interval: float, timeout: float) -> None:
    print(f'[test] Polling every {poll_interval:.0f}s until all {total} have surfaced '
          f'(timeout: {timeout / 60:.1f}m)...')
    start = time.monotonic()
    last_count = -1
    history = []

    while True:
        elapsed = time.monotonic() - start
        try:
            text = _fetch_metrics_text(metrics_url)
            count = _count_surfaced(text, cn_prefix)
        except Exception as e:
            print(f'  [{elapsed:7.1f}s] metrics fetch failed: {e!r}')
            time.sleep(poll_interval)
            continue

        if count != last_count:
            history.append((elapsed, count))
            print(f'  [{elapsed:7.1f}s] surfaced: {count}/{total} ({count / total * 100:5.1f}%)')
            last_count = count

        if count >= total:
            print(f'\n[test] SUCCESS: all {total} certs surfaced after {elapsed:.1f}s.')
            break
        if elapsed >= timeout:
            print(f'\n[test] TIMEOUT after {elapsed:.1f}s: {count}/{total} surfaced '
                  f'({total - count} still missing). See the "Notes on scale" section in this '
                  f'script\'s docstring -- check cert_analysis_errors{{error_type="retry_queue_dropped"}} '
                  f'and cert_analyzer_cache_known_certs_size vs cert_analyzer_cache_max_size.')
            break
        time.sleep(poll_interval)

    print('\nTimeline (elapsed_seconds -> cumulative_surfaced):')
    for elapsed, count in history:
        print(f'  {elapsed:8.1f}s  ->  {count}')


def main() -> None:
    parser = argparse.ArgumentParser(
        description='New-certificate rate limiter / retry queue burst test for cert_analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('--count', type=int, default=DEFAULT_COUNT,
                        help=f'number of unique certs to burst-write (default: {DEFAULT_COUNT})')
    parser.add_argument('--out-dir', default=DEFAULT_OUT_DIR,
                        help=f'directory to write test files to (default: {DEFAULT_OUT_DIR})')
    parser.add_argument('--wait', action='store_true',
                        help='poll cert_analyzer\'s /metrics until every cert has surfaced (or '
                             '--timeout trips) instead of just printing verify commands and exiting')
    parser.add_argument('--poll-interval', type=float, default=5.0,
                        help='seconds between polls when --wait is given (default: 5)')
    parser.add_argument('--timeout', type=float, default=600.0,
                        help='seconds to wait for full convergence when --wait is given (default: 600)')
    parser.add_argument('--metrics-url', default=DEFAULT_METRICS_URL,
                        help=f'cert_analyzer /metrics URL (default: {DEFAULT_METRICS_URL})')
    parser.add_argument('--keep', action='store_true',
                        help='keep the generated cert files instead of deleting them at the end')
    args = parser.parse_args()

    rate = _effective_rate()
    retry_cap = _effective_retry_queue_max_size()

    run_id = f'{os.getpid()}-{int(time.time())}'
    cn_prefix = f'rate-limit-test-{run_id}-'

    if args.count > retry_cap:
        print(f'WARNING: --count {args.count} exceeds the configured retry_queue_max_size '
              f'({retry_cap}) -- expect {args.count - retry_cap}+ entries to be permanently '
              f'dropped from the retry queue rather than delayed. Lower --count or raise '
              f'retry_queue_max_size for a run that can reach 100%.\n', file=sys.stderr)

    print(f'=== new-cert rate limiter / retry queue test ({args.count} certs) ===\n')
    print('Prerequisites:')
    print('  Tetragon running with certificate-file-access.yaml policy loaded:')
    print('    sudo tetra tracingpolicy add tetragon-policies/certificate-file-access.yaml\n')
    print(f'Configured new_cert_events_per_second: {rate}')
    print(f'Configured retry_queue_max_size:       {retry_cap}\n')

    paths = []
    try:
        print(f'[test] Pre-generating {args.count} unique certs (untimed -- keygen cost must not '
              f'dilute the burst)...')
        t0 = time.perf_counter()
        for i in range(args.count):
            cn = f'{cn_prefix}{i}.example.com'
            path = os.path.join(args.out_dir, f'{cn_prefix}{i}.pem')
            _write_file(path, _make_self_signed_cert(cn))
            paths.append(path)
        print(f'  done in {time.perf_counter() - t0:.1f}s\n')

        print(f'[test] All {args.count} files already written above by open()/write() -- each one '
              f'fired its own fd_install event as it was created, so the burst already happened '
              f'during generation. No separate "open" pass needed.\n')

        if args.wait:
            _wait_for_convergence(cn_prefix, args.count, args.metrics_url,
                                   args.poll_interval, args.timeout)
            print()
        else:
            print('=== Verify ===\n')
            print(f'curl -s {args.metrics_url} | grep -c \'cert_path="[^"]*{cn_prefix}\'')
            print(f'# Expect {args.count} once the retry queue finishes draining -- at '
                  f'{rate}/sec that\'s roughly {max(0, args.count - rate) / max(rate, 1):.0f}s '
                  f'after the burst\n')
            print('curl -s ' + args.metrics_url + ' | grep cert_analyzer_retry_queue_depth')
            print('# Should climb immediately after the burst, then drain to 0\n')
            print('curl -s ' + args.metrics_url + ' | grep tls_certificate_analysis_errors_total')
            print('# retry_queue_dropped should stay at 0 for a --count under retry_queue_max_size\n')
            print('Or re-run with --wait to have this script poll until convergence itself.\n')
    finally:
        if not args.keep:
            print(f'[test] Cleaning up {len(paths)} generated file(s)...')
            for path in paths:
                if os.path.exists(path):
                    try:
                        os.remove(path)
                    except OSError as e:
                        print(f'[test] WARNING: could not remove {path}: {e}', file=sys.stderr)
        else:
            print(f'=== Cleanup (not run automatically -- --keep was given) ===')
            rm_prefix = 'sudo ' if not os.access(args.out_dir, os.W_OK) else ''
            print(f'{rm_prefix}rm {args.out_dir}/{cn_prefix}*.pem')


if __name__ == '__main__':
    main()
