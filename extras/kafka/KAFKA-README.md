# cert-analyzer — Local Kafka Testing

cert-analyzer can optionally publish a JSON event to Kafka each time a
certificate is discovered for the first time (`KAFKA_ENABLED=true` /
`[kafka] enabled = true`), and optionally a further event each time an
already-known certificate is re-accessed by a new process/pod
(`[kafka] access_enabled = true`). This document covers standing up a
throwaway, single-node Kafka broker on RHEL 9 to test that path locally, and
how to verify and view the data it produces.

Writing an actual consumer against these topics? See
[CONSUMER-README.md](CONSUMER-README.md) for client code examples and links
to the full event schemas.

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

- Downloads Kafka 3.9.0 to `/opt/kafka` — or reuses `kafka_2.13-3.9.0.tgz`
  if it's already sitting next to the script in `extras/kafka/`, skipping
  the download entirely (useful offline, or to avoid re-fetching on repeat runs)
- Writes a minimal combined broker+controller config to `/etc/kafka/server.properties`
- Formats KRaft storage under `/var/lib/kafka/data` (once, on first install)
- Installs and starts `kafka.service`
- Waits for the broker to actually accept Kafka-protocol connections (not just for the process to start — see [Troubleshooting](#troubleshooting))
- Creates the `cert-analyzer-events` and `cert-analyzer-access-events` topics
  (the latter created unconditionally, even though `[kafka] access_enabled`
  defaults to `false` — cheap to have it exist and idle rather than fail
  later if you turn access events on after already running this script)

It's plaintext/unauthenticated by design — matches cert-analyzer's own
`PLAINTEXT` default `security_protocol`, and is not meant for anything
beyond local testing.

The script is idempotent: re-running it skips the download/format/systemd
steps if `kafka.service` is already active, and just re-verifies the
broker and both topics.

To use different topic names:

```bash
CERT_ANALYZER_TOPIC=my-test-topic CERT_ANALYZER_ACCESS_TOPIC=my-test-access-topic ./extras/kafka/install-kafka.sh
```

---

## Configure cert-analyzer to publish to it

Add to `/etc/cert-analyzer/cert-analyzer.conf` (or set the equivalent env vars):

```ini
[kafka]
enabled = true
bootstrap_servers = localhost:9092
topic = cert-analyzer-events

# Optional -- off by default. See CONSUMER-README.md for the
# certificate_accessed schema.
access_enabled = true
access_topic = cert-analyzer-access-events
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

### Quick Python viewer

`view_kafka_messages.py` takes the broker host/port and topic as
arguments, then dumps every available message pretty-printed like `jq .`
— no `jq` install or remembering consumer flags required. Useful for a
quick verification pass, including against a broker on a different host
(e.g. if you moved the `[kafka] bootstrap_servers` off `localhost`).

```bash
pip install kafka-python  # if not already installed

# All arguments are optional -- default to localhost:9092 / cert-analyzer-events
python3 extras/kafka/view_kafka_messages.py --host localhost --port 9092 --topic cert-analyzer-events
```

It reads whatever's already on the topic and exits after 5s of no new
messages (or Ctrl-C to stop early).

### Certificate chain lengths

`list_cert_chains.py` groups discovery events by `path` and reports how
many certificates were found at each path (leaf, intermediates, root),
ordered by `cert_index`:

```bash
python3 extras/kafka/list_cert_chains.py --host localhost --port 9092 --topic cert-analyzer-events
```

Since Kafka only receives *first-time* discoveries, a chain whose
intermediates were already known before Kafka was enabled will show up as
incomplete — the script flags this with a gap note rather than guessing.

Separately, the script also flags a real chain-of-trust problem: any
non-root cert in a bundle whose issuer doesn't match any other cert's
subject in that same bundle, i.e. the file itself — not just the Kafka
topic — is missing an intermediate. This is the "server forgot to include
its intermediate CA" misconfiguration, and shows up per-path as a `⚠
missing intermediate` line plus a summary at the end.

To generate a test case for it:

```bash
python3 extras/test_analyzer.py   # also (re)generates broken-chain-missing-intermediate.crt
sudo cp test-certs/broken-chain-missing-intermediate.crt /etc/pki/tls/certs/
cat /etc/pki/tls/certs/broken-chain-missing-intermediate.crt > /dev/null  # trigger detection
```

`generate_broken_chain()` in `test_analyzer.py` builds a real root ->
intermediate -> leaf chain, signs the leaf with the intermediate, then
writes out only the leaf and root — discarding the intermediate — so the
bundle looks like a server that forgot to ship it.

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
