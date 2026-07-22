# cert-analyzer — Consuming Kafka Events (Python)

A guide for developers writing a service that consumes cert-analyzer's Kafka
event streams — as opposed to [KAFKA-README.md](KAFKA-README.md), which
covers standing up a broker to test *cert-analyzer's own* publishing path.

Examples here use Python and [`kafka-python`](https://kafka-python.readthedocs.io/),
the same library cert-analyzer itself uses to publish (see `agent/kafka.py`).
Anything using a JSON-over-Kafka client in another language applies the same
concepts — this doc just doesn't have code samples for them yet.

---

## The two topics

| Topic (default name) | Config key | Default | Fires |
|---|---|---|---|
| `cert-analyzer-events` | `[kafka] topic` | always, when `[kafka] enabled = true` | once per certificate, the first time it's seen |
| `cert-analyzer-access-events` | `[kafka] access_topic` | only when `[kafka] access_enabled = true` (off by default) | once per distinct process/pod that subsequently re-accesses an already-known certificate |

Full field-by-field schemas, with example payloads, live in the
[surfaced fields reference](../FIELDS-README.md):

- [`certificate_discovered` schema](../FIELDS-README.md#kafka-event-schema)
- [`certificate_accessed` schema](../FIELDS-README.md#kafka-event-schema-certificate_accessed)

Read those before writing a consumer — this doc covers the client mechanics,
not the field meanings.

Both topics carry the same partition key, `cert_unique_key`
(`path:cert_index:serial_number` — spelled `cert_info.unique_key` in the
schema fields above), so a consumer joining the two streams can correlate an
access event back to the certificate that discovered it.

---

## Prerequisites

```bash
pip install kafka-python
```

---

## Minimal consumer

Reads `certificate_discovered` events and prints anything expiring soon.

```python
#!/usr/bin/env python3
import json
from kafka import KafkaConsumer

consumer = KafkaConsumer(
    'cert-analyzer-events',
    bootstrap_servers='localhost:9092',
    group_id='expiry-watcher',          # consumer group — see "Consumer groups" below
    auto_offset_reset='earliest',       # 'latest' to skip history and only see new events
    enable_auto_commit=True,
    value_deserializer=lambda v: json.loads(v.decode('utf-8')),
    key_deserializer=lambda k: k.decode('utf-8') if k else None,
)

for message in consumer:
    event = message.value
    if event.get('schema_version') != 1:
        # See "Handling schema_version" below before assuming the shape.
        continue

    if event['days_until_expiry'] < 14:
        print(
            f"⚠ {event['common_name'] or event['path']} expires in "
            f"{event['days_until_expiry']:.1f} days "
            f"(pod={event.get('pod_name') or 'n/a'}, node={event.get('node_name')})"
        )
```

---

## Consuming both topics and joining on `cert_unique_key`

`certificate_accessed` events deliberately omit certificate metadata
(subject, SANs, FIPS status, ...) — see
[why](../FIELDS-README.md#kafka-event-schema-certificate_accessed) — so a
consumer that wants to report "who accessed *this* certificate" needs to
join against `certificate_discovered`. A single consumer subscribed to both
topics, keeping a local dict of certs seen so far, is the simplest way:

```python
#!/usr/bin/env python3
import json
from kafka import KafkaConsumer

DISCOVERY_TOPIC = 'cert-analyzer-events'
ACCESS_TOPIC    = 'cert-analyzer-access-events'   # requires [kafka] access_enabled = true

consumer = KafkaConsumer(
    DISCOVERY_TOPIC, ACCESS_TOPIC,
    bootstrap_servers='localhost:9092',
    group_id='access-auditor',
    auto_offset_reset='earliest',
    enable_auto_commit=True,
    value_deserializer=lambda v: json.loads(v.decode('utf-8')),
)

# cert_unique_key -> last-known certificate_discovered event.
# In a real service, back this with a proper store (Redis, a DB, ...) so it
# survives restarts and isn't rebuilt by replaying the whole topic history.
known_certs = {}

for message in consumer:
    event = message.value
    event_type = event.get('event_type')

    if event_type == 'certificate_discovered':
        known_certs[event['path'] + ':' + str(event['cert_index']) + ':' + event['serial_number']] = event

    elif event_type == 'certificate_accessed':
        cert = known_certs.get(event['cert_unique_key'])
        cert_desc = cert['common_name'] if cert else event['path']
        print(
            f"{event['process']} (pid={event['pid']}) in pod "
            f"{event.get('pod_name') or 'n/a'} accessed {cert_desc} "
            f"at {event['accessed_at']}"
        )
```

If a `certificate_accessed` event arrives for a cert this consumer hasn't
seen `certificate_discovered` for yet (e.g. it joined the consumer group
after the discovery event aged out, or started with `auto_offset_reset =
latest`), `known_certs.get(...)` returns `None` — handle that rather than
assuming every access event has a matching discovery in your local state.

---

## Consumer groups

Both topics are keyed by `cert_unique_key`, so all events for a given
certificate (its discovery, and every subsequent access) land on the same
partition and are delivered in order *within that partition* — but ordering
across different certificates, or between the two topics, isn't guaranteed.

Give each independent consumer application its own `group_id`. Two
processes sharing a `group_id` split the partitions between them (useful for
scaling one logical consumer horizontally); two processes that both want the
full stream need distinct group IDs.

`auto_offset_reset='earliest'` replays everything currently retained on the
topic the first time a given `group_id` connects (or after its committed
offset has expired); `'latest'` starts from new messages only. After the
first connect, a consumer group resumes from its last committed offset
either way.

---

## Handling `schema_version`

`schema_version` is only bumped on breaking changes (a field renamed,
removed, or changed type) — not on every cert-analyzer release. New
non-breaking fields can appear on either topic at the same `schema_version`,
so:

- Don't assume a message has *only* the fields shown in the example payloads
  — treat unrecognized fields as forward-compatible additions, not errors.
- Do check `schema_version` before relying on a field's presence or type,
  and decide explicitly how to handle a version your consumer doesn't yet
  know about (skip, log, or fail loudly, depending on how strict your
  consumer needs to be).

---

## Connecting to a secured broker

If `[kafka] security_protocol` is set to anything other than `PLAINTEXT` on
the producer side, configure the consumer to match:

```python
consumer = KafkaConsumer(
    'cert-analyzer-events',
    bootstrap_servers='broker1:9093,broker2:9093',
    security_protocol='SASL_SSL',
    sasl_mechanism='PLAIN',
    sasl_plain_username='your-username',
    sasl_plain_password='your-password',
    group_id='expiry-watcher',
    value_deserializer=lambda v: json.loads(v.decode('utf-8')),
)
```

---

## Reference scripts in this repo

- [`view_kafka_messages.py`](view_kafka_messages.py) — dumps every message
  on a topic pretty-printed, no consumer-group bookkeeping. Good starting
  point to see real payloads before writing a consumer.
- [`list_cert_chains.py`](list_cert_chains.py) — a fuller example of
  processing `certificate_discovered` events into an aggregate view
  (certificate chains grouped by path).
