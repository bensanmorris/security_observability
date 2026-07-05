# cert-analyzer — Local Kafka Testing

cert-analyzer can optionally publish a JSON event to Kafka each time a
certificate is discovered for the first time (`KAFKA_ENABLED=true` /
`[kafka] enabled = true`). This document covers standing up a throwaway,
single-node Kafka broker on RHEL 9 to test that path locally, and how to
verify and view the data it produces.

---

## Prerequisites

- RHEL 9 (or similar), `sudo` access
- Java 11+ on `PATH` (e.g. `java-11-openjdk-headless`) — required by the Kafka broker itself, not by cert-analyzer

---

## Install

```bash
./extras/kafka/install-kafka.sh
```

This installs a single-node Apache Kafka broker in **KRaft mode** (no
ZooKeeper) as a native systemd service:

- Downloads Kafka 3.9.0 to `/opt/kafka`
- Writes a minimal combined broker+controller config to `/etc/kafka/server.properties`
- Formats KRaft storage under `/var/lib/kafka/data` (once, on first install)
- Installs and starts `kafka.service`
- Waits for the broker to actually accept Kafka-protocol connections (not just for the process to start — see [Troubleshooting](#troubleshooting))
- Creates the `cert-analyzer-events` topic

It's plaintext/unauthenticated by design — matches cert-analyzer's own
`PLAINTEXT` default `security_protocol`, and is not meant for anything
beyond local testing.

The script is idempotent: re-running it skips the download/format/systemd
steps if `kafka.service` is already active, and just re-verifies the
broker and topic.

To use a different topic name:

```bash
CERT_ANALYZER_TOPIC=my-test-topic ./extras/kafka/install-kafka.sh
```

---

## Configure cert-analyzer to publish to it

Add to `/etc/cert-analyzer/cert-analyzer.conf` (or set the equivalent env vars):

```ini
[kafka]
enabled = true
bootstrap_servers = localhost:9092
topic = cert-analyzer-events
```

Then restart cert-analyzer for the config to take effect.

---

## Verify Kafka is running

```bash
systemctl status kafka --no-pager
journalctl -u kafka -n 40 --no-pager
```

Confirm the broker actually accepts connections (this is a stronger check
than `systemctl is-active`, which flips as soon as the JVM process starts):

```bash
/opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server localhost:9092
```

List topics:

```bash
/opt/kafka/bin/kafka-topics.sh --list --bootstrap-server localhost:9092
```

---

## View the data

```bash
/opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic cert-analyzer-events \
  --from-beginning
```

- Drop `--from-beginning` to only see new events from now on.
- Pipe through `jq .` to pretty-print (`sudo dnf install jq` if not already present).
- Each message is a JSON object (`event_type: "certificate_discovered"`,
  plus subject/issuer/expiry/FIPS/Kubernetes-pod fields). The full schema
  is documented in the `KafkaPublisher` docstring in `agent/kafka.py`.

**cert-analyzer only publishes on first-time discovery** of a certificate
— re-detections of already-known certs are Prometheus-only, by design (see
`agent/kafka.py`). If the topic looks empty, either wait for a genuinely
new certificate access, or clear cert-analyzer's `known_certs` cache
(restart it) so the next access is treated as a fresh discovery.

---

## View the data in a browser (Kafdrop)

The console consumer works, but for a columnar/tree view of topics,
partitions, offsets, and each message's JSON, run
[Kafdrop](https://github.com/obsidiandynamics/kafdrop) as a container:

```bash
podman run -d --name kafdrop --network=host \
  -e KAFKA_BROKERCONNECT=localhost:9092 \
  docker.io/obsidiandynamics/kafdrop
```

`--network=host` is required — the broker's listener is bound to
`localhost:9092`, which is only reachable from inside a container if it
shares the host's network namespace. Without it, Kafdrop would be looking
at its own loopback instead of the host's.

Open **http://localhost:9000** — it lists topics, and clicking into
`cert-analyzer-events` shows partitions/offsets in a table, with each
message expandable as a JSON tree.

Manage the container:

```bash
podman stop kafdrop   # stop
podman start kafdrop  # restart
podman rm -f kafdrop  # remove entirely
```

---

## Troubleshooting

**`kafka.service` crash-loops with `Failed to locate executable
/opt/kafka/bin/kafka-server-start.sh: Permission denied`**

This is `Permission denied`, not `No such file` — the script's own `mv`
into `/opt` (across filesystems, from a temp dir) can leave files with a
stripped execute bit or a stale SELinux context (e.g. inherited from
`/tmp`) that a systemd-launched process isn't permitted to execute, even
though the bits look fine to a manual `ls -l`. `install-kafka.sh` already
runs `chmod +x` and `restorecon -R` on `/opt/kafka` after the move to
guard against both; if you still hit this after re-running the script,
check:

```bash
getenforce
ls -lZ /opt/kafka/bin/kafka-server-start.sh
```

**Topic creation fails with `TimeoutException: Timed out waiting for a
node assignment`**

The broker was still replaying its metadata log when the topic-create
call ran — `systemctl is-active` reports "active" as soon as the JVM
process starts, well before the broker is actually ready. Re-run
`install-kafka.sh`; the readiness wait (`kafka-broker-api-versions.sh`
polling loop) should let it settle before creating the topic.

**Downloading the tarball fails with a TLS error (e.g.
`SSL_ERROR_ZERO_RETURN`)**

Run the script as your normal user (`./extras/kafka/install-kafka.sh`), not
via `sudo ./install-kafka.sh` — it only elevates the specific steps that
need root. Running the whole script under `sudo` resets your environment,
which can drop proxy/CA settings your shell relies on for outbound HTTPS.

---

## Uninstall

```bash
sudo systemctl disable --now kafka
sudo rm -f /etc/systemd/system/kafka.service
sudo systemctl daemon-reload
sudo rm -rf /opt/kafka /opt/kafka_2.13-3.9.0 /etc/kafka /var/lib/kafka
```
