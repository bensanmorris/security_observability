# CertSight detection test console

A small local HTTP server for manually exercising CertSight's certificate
detections one at a time and watching the resulting Kafka event show up
live, without needing a second terminal for `kafka-console-consumer.sh` or
juggling `cat`/`openssl` commands by hand.

**Left pane:** a list of test use cases (e.g. "generate + read a fresh test
certificate"). Clicking one runs the underlying action for real on this
host -- a real file read, eventually a real TLS handshake, etc. -- so
Tetragon and cert-analyzer pick it up exactly as they would in production.

**Right pane:** every message cert-analyzer publishes to its Kafka topic,
streamed live via Server-Sent Events as it arrives.

---

## Prerequisites

- Tetragon + cert-analyzer already installed, running, and configured with
  the certificate-file-access policy applied (see the main
  [README](../../README.md#installation))
- cert-analyzer configured with `[kafka] enabled = true` and pointed at a
  reachable broker -- see [extras/kafka/KAFKA-README.md](../kafka/KAFKA-README.md)
  to stand up a throwaway local broker
- Python 3.9+ with `python3-venv` (or equivalent) available
- Run this **on the same host** cert-analyzer is monitoring -- use cases
  shell out to real local commands (e.g. `cat`), so running it from a
  different machine won't trigger anything

## Set up a virtualenv

```bash
cd extras/test-server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` pins the same `cryptography`/`kafka-python` versions as
the main [requirements.txt](../../requirements.txt), so if you're already
running cert-analyzer's own virtualenv on this host, that one already
satisfies both and you can skip creating a separate one -- just `source`
that venv's `activate` instead.

## Run

```bash
source .venv/bin/activate   # if not already active
python3 server.py --kafka-host localhost --kafka-port 9092
```

(Adjust the path to `server.py` if running from the repo root instead of
`extras/test-server/`.)

Then open http://localhost:8090.

`--kafka-host`/`--kafka-port` are required (no baked-in default) since the
broker is whatever you configured cert-analyzer's `[kafka] bootstrap_servers`
to point at. `--topic` defaults to `cert-analyzer-events` (cert-analyzer's
own default); pass `--port` to change this server's own listen port
(default `8090`), and `--bind` to change its listen address (default
`127.0.0.1`).

**Do not** bind this beyond localhost or a trusted lab network: every use
case executes a real, hardcoded action against this host on request from
any browser that can reach it.

## Use cases

| Use case | Action | Detection exercised |
|---|---|---|
| generate + read a fresh test certificate | Generates a new self-signed cert at a unique path under `/dev/shm`, then `cat`s it | File-access detection via the `certificate-file-access.yaml` Tetragon policy (`fd_install` kprobe) |

Every click generates a brand-new cert at a brand-new path, so it's always
a first-time discovery from cert-analyzer's point of view (its known-certs
dedup key is `path:index:serial` -- see `agent/analyzer.py`) and always
produces a fresh Kafka event, unlike re-`cat`ing a real system file cert-
analyzer has already seen (Prometheus-only by design -- see
[extras/kafka/KAFKA-README.md](../kafka/KAFKA-README.md)).

Generated certs pile up under `/dev/shm/certsight-test-server/` -- cert-
analyzer never needs them again once processed, so it's safe to delete that
directory's contents by hand at any time. `/dev/shm` is used deliberately
instead of `/tmp`: cert-analyzer's systemd unit runs with `PrivateTmp=true`,
which gives it its own private `/tmp`/`/var/tmp` mount namespace that can't
see files written to the host's `/tmp`.

### Permissions on the generated cert directory

No manual setup is required -- this all happens automatically -- but it's
worth knowing why it works: `/dev/shm` itself is world-writable with the
sticky bit set (`drwxrwxrwt`, same model as `/tmp`), so any user can create
`certsight-test-server/` under it without `sudo`. cert-analyzer, however,
runs as its own unprivileged `cert-analyzer` system user (see `User=` /
`Group=` in `cert-analyzer.service`), not as whoever runs this test server,
so it needs "other" read+execute on that directory and "other" read on
each generated cert file to open them at all. `use_cases.py` sets those
bits explicitly (`0o755` / `0o644`) after creating them rather than relying
on the calling user's umask, since a stricter umask (e.g. `077`, common on
hardened hosts) would otherwise silently produce files cert-analyzer can't
read -- Tetragon would still report the file access (its `fd_install`
kprobe doesn't care about DAC permissions), but cert-analyzer's own
follow-up read of the file content would fail, and no event would reach
Kafka.

More use cases (JKS/PKCS12 keystores, in-memory OpenSSL/NSS certs, TLS
service binds, outbound `tcp_connect` probes, Java cert-agent operations)
are intended to be added to `use_cases.py` over time -- see [What CertSight
detects](../../README.md#what-certsight-detects) for the full list this
console is meant to eventually cover.

## Adding a new use case

Add an entry to `USE_CASES` in `use_cases.py`: an `id`, a human-readable
`label` and `description` for the left pane, and a `run()` callable that
performs the real action and returns a `UseCaseResult(ok, detail)`. No
other file needs to change -- the server and frontend both read the list
from `use_cases.py` at request time.
