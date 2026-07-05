#!/usr/bin/env python3
"""
Dumps every message on a Kafka topic pretty-printed like `jq .` -- a quick
way to eyeball cert-analyzer's published events without the console
consumer's raw single-line JSON, and without a browser (see Kafdrop in
KAFKA-README.md for that).

Usage: python3 view_kafka_messages.py [--host HOST] [--port PORT] [--topic TOPIC]
"""
import argparse
import json
import sys

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

    count = 0
    try:
        for message in consumer:
            count += 1
            print(f"── offset {message.offset}  partition {message.partition} ──")
            try:
                payload = json.loads(message.value.decode('utf-8'))
                print(json.dumps(payload, indent=2))
            except (json.JSONDecodeError, UnicodeDecodeError):
                print(f"(not valid JSON) {message.value!r}")
            print()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        consumer.close()

    print(f"{count} message(s) shown.")


if __name__ == '__main__':
    main()
