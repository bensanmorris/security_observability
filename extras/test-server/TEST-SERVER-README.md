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
- Python 3.9+ (a virtualenv install) or `python3.11` (an RPM install) on
  the target host -- see "Install" below for which
- Run this **on the same host** cert-analyzer is monitoring -- use cases
  shell out to real local commands (e.g. `cat`), so running it from a
  different machine won't trigger anything

## Install

Two ways to get `cryptography`/`kafka-python` in place, depending on
whether the target host has pip/internet access.

### Option A: virtualenv (target host has pip/internet access)

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

### Option B: RPM (target host has no pip/internet access)

CI builds this RPM already, for both el8 and el9, with `cryptography` and
`kafka-python` bundled into a relocatable virtualenv at
`/opt/certsight-test-server/venv` -- no need to build it yourself. Grab
`certsight-test-server-*.el8*.rpm` / `*.el9*.rpm` from a tagged
[Release](../../releases) page, or -- for an untagged branch/PR -- from
the `build-test-server-rpm` job's artifacts on its
[Actions run](../../actions/workflows/build.yml) (also triggerable
on-demand via `workflow_dispatch`). Copy it to the
target host and install it with zero pip/internet access required there:

```bash
sudo dnf install ./certsight-test-server-<version>-<release>.el9.*.rpm
```

Only build it locally (`./build-rpm.sh --version 0.1.0 --release 1`) if
you need a change that hasn't been through CI yet. Run that on any machine
with normal pip/PyPI access -- it doesn't need to be the target host --
and it produces the same RPM under
`~/rpmbuild/RPMS/$(uname -m)/certsight-test-server-<version>-<release>.*.rpm`,
following the same pattern as `cert-analyzer.spec` (see there for why the
debuginfo/build-id suppression macros at the top of the spec are needed).

This installs a `certsight-test-server` wrapper onto `$PATH` that runs
`server.py` with the bundled venv's interpreter -- see "Run" below, just
without the `source .venv/bin/activate` step and using `certsight-test-server`
instead of `python3 server.py`. It also installs a
`certsight-test-server.service` systemd unit and a dedicated
`certsight-test-server` system user, so it can be left running across
reboots instead of started by hand every time -- see "Running under
systemd" below.

## Run

```bash
source .venv/bin/activate   # only if you used Option A; skip for the RPM install
python3 server.py --kafka-host localhost --kafka-port 9092   # or: certsight-test-server --kafka-host ... (RPM install)
```

(Adjust the path to `server.py` if running from the repo root instead of
`extras/test-server/`.)

Then open http://localhost:8090.

`--kafka-host`/`--kafka-port` are required (no baked-in default) since the
broker is whatever you configured cert-analyzer's `[kafka] bootstrap_servers`
to point at. `--topic` defaults to `cert-analyzer-events` (cert-analyzer's
own default); pass `--port` to change this server's own listen port
(default `8090`).

By default this only listens on `127.0.0.1`, so it's only reachable from a
browser on the same host. If the target host is headless and you're
browsing from elsewhere on a trusted lab network, pass `--bind 0.0.0.0` to
listen on all interfaces, then open `http://<target-host>:8090` instead of
`localhost`.

**Do not** bind this beyond localhost or a trusted lab network: every use
case executes a real, hardcoded action against this host on request from
any browser that can reach it.

## Running under systemd (RPM install only)

The RPM installs `certsight-test-server.service`, enabled on install so it
starts on every boot, running as a dedicated unprivileged
`certsight-test-server` system user. Unlike the manual CLI (`--bind`
defaults to `127.0.0.1`), the unit binds `0.0.0.0` by default, since a
systemd-managed instance is typically left running on a headless lab host
that you browse to from elsewhere -- **only do this on a trusted lab
network behind a firewall**, per the warning above.

It has no working default for `--kafka-host`/`--kafka-port`, so it won't
actually come up until you configure it:

```bash
sudo vi /etc/certsight-test-server/test-server.conf   # set TEST_SERVER_KAFKA_HOST / TEST_SERVER_KAFKA_PORT
sudo systemctl start certsight-test-server
```

Until then it sits enabled-but-failed (`Restart=on-failure`, giving up
after 5 attempts in 300s) -- `journalctl -u certsight-test-server` will
show it exiting with the same "--kafka-host/--kafka-port are required"
error `server.py` gives on the CLI. Check status/logs, or stop it, the
usual way:

```bash
systemctl status certsight-test-server
journalctl -u certsight-test-server -f
sudo systemctl stop certsight-test-server      # sudo systemctl disable ... to also stop it starting on boot
```

`test-server.conf` is a systemd `EnvironmentFile` (shell `KEY=VALUE`), not
the same format as `cert-analyzer.conf` -- see the commented-out options
in the shipped file for the full list (`TEST_SERVER_KAFKA_HOST`,
`TEST_SERVER_KAFKA_PORT`, `TEST_SERVER_TOPIC`, `TEST_SERVER_PORT`,
`TEST_SERVER_BIND`). It's marked `%config(noreplace)` in the spec, so an
RPM upgrade won't overwrite edits you've made to it.

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

### What actually happens when you click it

The same step-by-step breakdown is shown in the UI itself, under each use
case's "How this works" disclosure -- reproduced here for reference:

1. This server generates a self-signed X.509 certificate in memory and
   writes it to a brand-new path under `/dev/shm/certsight-test-server/`.
2. This server runs `cat <path>` as a real subprocess -- a real process
   performing a real `open()`/`read()` of that file, no different from an
   admin or application reading a cert off disk.
3. When the kernel services that `open()`, it calls `fd_install()` to
   attach the new file descriptor to the `cat` process. Tetragon has a
   kprobe on `fd_install`, loaded system-wide via the
   `certificate-file-access.yaml` TracingPolicy.
4. That policy's selector matches the opened file's path against a list of
   certificate-like extensions (`.crt`, `.pem`, `.jks`, `.p12`, ...). The
   generated file ends in `.crt`, so the kprobe's selector matches and
   Tetragon emits a process/kprobe event over its gRPC stream.
5. cert-analyzer's Tetragon gRPC client -- already subscribed to that
   stream -- receives the event and extracts the file path and the process
   that opened it (`/usr/bin/cat`), logging `🔍 Detected certificate
   access`.
6. cert-analyzer independently opens and reads that same file itself (a
   second, separate real file read, from its own process) to parse the
   X.509 structure: subject, issuer, SAN, validity dates, key
   algorithm/size, FIPS compliance, etc.
7. Because this exact path has never been seen before, cert-analyzer's
   known-certs cache treats it as a first-time discovery: it records the
   cert, updates Prometheus metrics, and -- since `[kafka] enabled = true`
   -- publishes a `certificate_discovered` JSON event to the
   `cert-analyzer-events` Kafka topic.
8. This test server's own background Kafka consumer thread, subscribed to
   that same topic, receives the message and pushes it to every connected
   browser over the Server-Sent Events stream, where it lands in the
   right-hand pane.

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
