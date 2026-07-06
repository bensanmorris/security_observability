#!/usr/bin/env python3
"""
Groups cert-analyzer's Kafka discovery events by certificate path and
reports the chain length (leaf + intermediates + root) found at each path.

cert-analyzer publishes one `certificate_discovered` event per certificate
in a bundle, with `cert_index` numbering position within that file/bundle
(0 = leaf). This script reads whatever's on the topic, groups by `path`,
and prints each chain ordered by `cert_index` with subject/issuer so you
can see how deep a given trust chain is.

Note: Kafka only receives *first-time* discoveries (see KAFKA-README.md),
so a chain whose intermediates were already known before Kafka was enabled
will show up here as incomplete (a gap in cert_index) -- this script flags
that rather than guessing at the missing entries.

Separately, this also flags a real chain-of-trust problem: any non-root
cert in a bundle whose issuer doesn't match any other cert's subject in
that same bundle -- i.e. the file itself is missing an intermediate,
regardless of what Kafka has or hasn't seen before. This is the "server
forgot to include its intermediate CA" misconfiguration.

Usage: python3 list_cert_chains.py [--host HOST] [--port PORT] [--topic TOPIC]
"""
import argparse
import json
import sys
from collections import defaultdict

try:
    from kafka import KafkaConsumer
    from kafka.errors import KafkaError
except ImportError:
    print("ERROR: kafka-python is not installed. Install it with:", file=sys.stderr)
    print("       pip install kafka-python", file=sys.stderr)
    sys.exit(1)

IDLE_TIMEOUT_MS = 5000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="localhost", help="Kafka broker IP/hostname (default: localhost)")
    parser.add_argument("--port", type=int, default=9092, help="Kafka broker port (default: 9092)")
    parser.add_argument("--topic", default="cert-analyzer-events", help="Topic to consume (default: cert-analyzer-events)")
    return parser.parse_args()


def describe(entry: dict) -> str:
    cn = entry.get("common_name") or entry.get("subject") or "(no subject)"
    if entry.get("is_self_signed"):
        role = "root (self-signed)"
    elif entry.get("is_ca"):
        role = "intermediate CA"
    else:
        role = "leaf"
    return f"{cn}  [{role}, issuer={entry.get('issuer') or '(none)'}]"


def find_missing_intermediates(by_index: dict) -> list:
    """
    Returns [(cert_index, entry, missing_issuer_subject), ...] for every
    non-self-signed cert in this bundle whose issuer doesn't match any
    other cert's subject in the same bundle -- i.e. its issuing CA cert
    is absent from the file.

    Only meaningful for bundles that already contain more than one cert --
    a lone leaf cert (a single TLS probe capture, a standalone entitlement
    cert, etc.) never embeds its own issuer by design, so checking those
    would just flag every single-cert file in existence.
    """
    if len(by_index) <= 1:
        return []
    subjects = {entry.get("subject") for entry in by_index.values()}
    missing = []
    for idx in sorted(by_index):
        entry = by_index[idx]
        if entry.get("is_self_signed"):
            continue
        issuer = entry.get("issuer")
        if issuer and issuer not in subjects:
            missing.append((idx, entry, issuer))
    return missing


def main() -> None:
    args = parse_args()
    bootstrap_servers = f"{args.host}:{args.port}"

    print(f"Connecting to {bootstrap_servers}, topic '{args.topic}'...")
    print(f"Reading available messages (stops after {IDLE_TIMEOUT_MS // 1000}s of no new ones, or Ctrl-C).\n")

    try:
        consumer = KafkaConsumer(
            args.topic,
            bootstrap_servers=bootstrap_servers,
            auto_offset_reset='earliest',
            enable_auto_commit=False,
            consumer_timeout_ms=IDLE_TIMEOUT_MS,
        )
    except KafkaError as e:
        print(f"ERROR: could not connect to {bootstrap_servers}: {e}", file=sys.stderr)
        sys.exit(1)

    chains = defaultdict(dict)  # path -> {cert_index: event}
    count = 0
    try:
        for message in consumer:
            count += 1
            try:
                payload = json.loads(message.value.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            path = payload.get("path")
            if not path:
                continue
            chains[path][payload.get("cert_index", 0)] = payload
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        consumer.close()

    print(f"{count} message(s) read, {len(chains)} distinct path(s).\n")

    if not chains:
        return

    paths_with_missing_intermediates = []

    for path in sorted(chains):
        by_index = chains[path]
        indices = sorted(by_index)
        chain_len = indices[-1] + 1
        seen_len = len(indices)
        gap_note = ""
        if seen_len != chain_len:
            gap_note = f"  (only {seen_len} of {chain_len} positions seen on topic -- some certs were already known before discovery)"

        missing_intermediates = find_missing_intermediates(by_index)
        if missing_intermediates:
            paths_with_missing_intermediates.append(path)

        print(f"── {path} ──")
        print(f"chain length: {chain_len}{gap_note}")
        for idx in indices:
            print(f"  [{idx}] {describe(by_index[idx])}")
        for idx, entry, issuer in missing_intermediates:
            cn = entry.get("common_name") or entry.get("subject") or "(no subject)"
            print(f"  ⚠ missing intermediate: cert [{idx}] '{cn}' is issued by '{issuer}', which is not present in this bundle")
        print()

    if paths_with_missing_intermediates:
        print(f"── Summary: {len(paths_with_missing_intermediates)} path(s) with a missing intermediate ──")
        for path in paths_with_missing_intermediates:
            print(f"  {path}")
        print()


if __name__ == '__main__':
    main()
