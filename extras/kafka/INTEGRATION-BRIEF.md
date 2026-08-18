# cert-analyzer — Platform Kafka Integration Brief

cert-analyzer has been publishing certificate-lifecycle events to a
single-node pilot broker (see [KAFKA-README.md](KAFKA-README.md)). This
document covers what's involved in pointing it at a shared internal Kafka
instead, and what we need to confirm with whichever team owns that broker
before doing so.

If you're writing a consumer rather than standing up the broker side, see
[CONSUMER-README.md](CONSUMER-README.md) instead — this doc is aimed at the
handoff conversation, not client code (though a minimal example is included
below for reference).

---

## Topics

| Topic (default name) | Config key | Fires |
|---|---|---|
| `cert-analyzer-events` | `[kafka] topic` / `KAFKA_TOPIC` | once per certificate, the first time it's seen — subject, issuer, SANs, key/crypto detail, FIPS status, K8s enrichment |
| `cert-analyzer-access-events` | `[kafka] access_topic` / `KAFKA_ACCESS_TOPIC` | once per distinct process/pod that subsequently re-accesses an already-known certificate (opt-in, off by default) |

Topic names are set via config file / env var only today — the Helm chart
doesn't expose them as values, so pointing at a differently-namespaced topic
means a small chart change (`values.yaml` + `templates/daemonset.yaml`), not
just a config toggle.

## Key & ordering

The partition key on both topics is `cert_unique_key`
(`path:cert_index:serial_number`, spelled `cert_info.unique_key` in code) —
it identifies the **certificate**, not its source. Node and pod ride along
in the *payload* (the schema includes both) but aren't in the key: there's
no partition affinity by host, and no ordering promised across different
certs or across the two topics.

A cert deployed identically on many nodes funnels every node's discovery
event into one partition. That's fine for correctness — Kafka is an
append-only log, so a shared key never causes events to be lost or
overwritten, only co-located in publish order — but it does mean
partitioning won't give you per-node consumer sharding or even load spread
by host.

## Message format

Plain JSON, no Avro, no schema registry. Payloads carry an in-payload
`schema_version` (currently `1`) that's only bumped on breaking changes; new
non-breaking fields can appear at the same version. Two event shapes:
`certificate_discovered` and `certificate_accessed`. Full field-by-field
schema with example payloads: [FIELDS-README.md](../FIELDS-README.md).

## Producer durability

- `acks=all`, 3 retries at 200 ms backoff
- No compression or batching tuning applied
- Publish is async / fire-and-forget with a 30s reconnect cooldown — a
  broker outage never blocks cert-analyzer, it just drops back to
  Prometheus-only and logs warnings until the broker comes back

## Auth & transport

The pilot broker is `PLAINTEXT`, unauthenticated — a throwaway test box.
The producer already supports `SSL`, `SASL_PLAINTEXT`, and `SASL_SSL` with
username/password (`[kafka] security_protocol`, `sasl_mechanism`,
`sasl_username`, `sasl_password`). Whatever the shared broker requires is a
config change on our side, not new code.

Bootstrap servers (`[kafka] bootstrap_servers` / `KAFKA_BOOTSTRAP_SERVERS`)
is a plain comma-separated string, split in code — adding another broker
alongside the pilot is a one-line change. One constraint: the DaemonSet runs
with `hostNetwork: true`, so the address needs to be reachable directly from
every node's IP, not a ClusterIP Service.

## Partitions & replication

The pilot topics are created with `--partitions 1 --replication-factor 1`
(`install-kafka.sh`) — a testing artifact, not a requirement. The producer
asserts nothing about partition count or RF; the owning team can size these
however they want. We just need topic creation confirmed (or auto-create
left on) before pointing at it.

---

## Choosing a key per use case

cert-analyzer's three primary consumer use cases each want a different
grouping, and none of them fully match the producer's own key. Rather than
overload one Kafka key for all three, each is better served as its own
consumer-side materialized view, keyed on the field that actually matches
its query.

| Use case | Needs | Where `path:cert_index:serial_number` falls short | Group by instead |
|---|---|---|---|
| **Blast radius** | Cross-node, cross-path grouping by the certificate/key itself — "where does this cert or key live, fleet-wide?" | `path` fragments one physical cert deployed on 500 hosts into 500 different keys — no partition locality to lean on. | `spki_hash` (already computed, built for key-reuse detection) or `issuer` + `serial_number`. |
| **Expiry** | A per-deployment-slot timeline — a renewal at one path shouldn't erase history elsewhere. | `serial_number` in the key means a renewal silently starts a brand-new key; the old slot's history is orphaned. | `path:cert_index` (drop serial) — the slot is the entity, renewal is just the next event in its stream. |
| **Missing intermediates** | Every cert in one bundle — leaf, intermediates, root — co-located to assemble the chain. | `cert_index` is baked into the key, so a leaf and its own intermediates can land on different partitions. | `path` alone — `cert_index` becomes a payload field, not key material. |

The one legitimate use of log compaction here is a *derived* index topic
built for one of these views (e.g. a compacted, `spki_hash`-keyed "current
deployments of this key" topic) — never the raw event topics, per the
compaction confirm-item below.

---

## Open questions for the platform team

1. **Bootstrap address:** our DaemonSet runs with `hostNetwork: true`, so it
   needs a broker address reachable directly from every node's IP — a
   ClusterIP Service won't resolve. What's the right host:port (or LB) for
   that?
2. **Topic naming:** is there a namespace/prefix convention we should adopt
   for `cert-analyzer-events` and `cert-analyzer-access-events`, or are the
   current names fine?
3. **Security protocol:** is PLAINTEXT acceptable on your cluster, or do you
   require `SASL_SSL`? If SASL, what mechanism, and where do credentials
   come from?
4. **Partitions / RF / who creates the topics:** do you want to pre-create
   them with your own sizing, or should we rely on auto-create?
5. **Schema expectations:** is plain JSON + an in-payload `schema_version`
   workable, or does your org require registry-managed schemas
   (Avro/Protobuf)?
6. **Partition affinity by node/pod:** the key is cert-identity only — node
   and pod are payload fields, not part of the key. If you need per-node
   routing or sharded consumers, that's a key-strategy change on our side,
   not something you can get from partitioning alone today. Do you need it?
7. **Confirm `cleanup.policy=delete`, not compact:** since the key doesn't
   include node/pod, log compaction would collapse the log down to the
   latest record per key — i.e. every node's discovery event for a
   widely-deployed cert except the last one written would disappear. We
   need standard retention-based cleanup, not compaction, on these topics.

---

## Minimal consumer example

```python
from kafka import KafkaConsumer
import json

consumer = KafkaConsumer(
    'cert-analyzer-events',
    bootstrap_servers='localhost:9092',
    group_id='expiry-watcher',
    auto_offset_reset='earliest',
    enable_auto_commit=True,
    value_deserializer=lambda v: json.loads(v.decode('utf-8')),
)

for message in consumer:
    event = message.value
    if event.get('schema_version') != 1:
        continue
    if event['days_until_expiry'] < 14:
        print(event['common_name'], event['days_until_expiry'])
```

kafka-python, Python 3 — any JSON-capable client works the same way. Dual-topic
join and secured-broker variants are in
[CONSUMER-README.md](CONSUMER-README.md).

## Guides in this repo

- [`CONSUMER-README.md`](CONSUMER-README.md) — consumer guide: minimal +
  dual-topic join, consumer-group semantics, `schema_version` handling,
  secured-broker config.
- [`../FIELDS-README.md`](../FIELDS-README.md) — field-by-field schema for
  both event types, with example payloads.
- [`KAFKA-README.md`](KAFKA-README.md) — stand up/inspect the pilot broker
  (console consumer, Python viewer, Kafdrop).
- [`view_kafka_messages.py`](view_kafka_messages.py) &
  [`list_cert_chains.py`](list_cert_chains.py) — runnable reference
  scripts: raw message dump, and cert-chain aggregation.
- top-level [`README.md`](../../README.md) — the `[kafka]` config table
  (every setting and default).
