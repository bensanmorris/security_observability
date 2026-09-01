# CertSight AWS demo

Stands up a single EC2 instance running the full CertSight stack for demoing
the Grafana dashboard and the [test console](../test-server/TEST-SERVER-README.md)
over public URLs, without touching any existing infrastructure.

What gets installed on the instance:

- Tetragon (standalone systemd install) + CertSight's Tetragon policies
- CertSight cert-analyzer + the CertSight Java cert-agent (JNI + deployer), so all five
  [test console use cases](../test-server/TEST-SERVER-README.md#use-cases)
  work, including the JCA/Java one
- A throwaway single-node Kafka broker (KRaft mode) feeding the test
  console's live event pane
- Prometheus + Grafana, with the CertSight dashboard auto-imported
- `certsight-test-server` (the test console), bound to `127.0.0.1:8091`
  behind an nginx reverse proxy on `0.0.0.0:8090` that rate-limits requests
  (see [Rate limiting](#rate-limiting) below)

---

## Before you run this

**The dashboard and test console are opened to the entire internet with no
authentication**, by design, so you can share a link. Be aware of what that
means:

- Grafana is in anonymous-Viewer mode -- read-only, fine to expose.
- The test console has **no authentication and executes real actions on the
  host** on request from any browser that can reach it (generates certs,
  binds TLS listeners, dials out, spawns a JVM). The project's own docs are
  explicit that this should normally stay on `localhost` or a trusted lab
  network. Here it's deliberately public for demo purposes -- don't leave it
  running longer than you need it, and tear it down afterwards.
- SSH (port 22) is restricted to your current public IP at deploy time, not
  opened to the internet.

### Rate limiting

nginx sits in front of the test console on port 8090 (the test console
itself only listens on `127.0.0.1:8091`) and rate-limits per client IP:

| Path | Limit | Why |
|---|---|---|
| `/api/run/*` (the actual action endpoints -- spawn JVM, generate cert, bind port, etc.) | 12/min, burst 6, capped at 3 concurrent connections/IP | These are the expensive ones (real subprocess/JVM/crypto work); this is the main cost/load control |
| `/api/events` (the SSE live-event stream) | not request-rate-limited, capped at 5 concurrent connections/IP | It's one long-lived connection per page load, not a request to throttle |
| everything else (static assets, `/api/use-cases`) | 10 req/s, burst 20 | Generous -- just guards against a naive scraper/bot loop |

`/api/run/*` and `/api/events` use *separate* connection-count zones even
though both are per-IP -- they used to share one, which meant a client with
several tabs open (each holding its own long-lived `/api/events` stream)
could exhaust the shared counter on SSE connections alone and then have
every `/api/run` click rejected with a `429` that had nothing to do with
request rate. If `/api/run` clicks are failing with plenty of time between
them, check concurrent connections/tabs before assuming the rate limit
itself is too tight.

Exceeding a limit gets a `429`, not a dropped connection. This bounds load
per client but doesn't prevent many *different* IPs hammering it
simultaneously (e.g. a link going viral) -- combined with `CpuCredits=standard`
(see [Cost](#cost)) that degrades to "the demo gets slow" rather than
"surprise bill," which is the actual goal here.

If you'd rather restrict the dashboard/console to specific IPs instead of
the whole internet, edit the `authorize-security-group-ingress` call in
`deploy-demo.sh` before running it (swap `0.0.0.0/0` for your CIDR(s)).

---

## Prerequisites

- AWS CLI v2, configured (`aws configure` or equivalent) with credentials
  that can create EC2/VPC resources in the target region
- A default VPC in that region (most accounts have one; if not, you'll need
  to adapt the script to pass a specific subnet)
- `curl`

No Terraform, no CloudFormation -- just the AWS CLI.

## Cost

`t3.medium` on-demand is roughly $0.04/hr (region-dependent) plus a 20 GB
gp3 EBS volume (~$0.002/hr). An Elastic IP is allocated for a stable link
(see below) -- free while attached to a running instance, but note that if
you ever stop (not terminate) the instance, the EIP starts billing hourly
until either the instance is running again or the address is released.
Tear the instance down when you're done demoing -- `teardown-demo.sh`
removes everything the deploy script created, including releasing the EIP.

The instance launches with `CpuCredits=standard` rather than the t3 default
of `unlimited` -- with the dashboard/test console open to the internet,
`unlimited` would bill per vCPU-hour for any sustained load beyond the
baseline (e.g. a traffic spike after sharing the link publicly) instead of
throttling. `standard` caps the cost risk: under heavy load the instance
just gets slower rather than racking up a surprise charge. A billing
alert/budget in your AWS account is still worth setting up as a backstop.

---

## Deploy

```bash
cd extras/aws-demo
./deploy-demo.sh
```

Takes about 2 minutes to launch the instance, then the script polls until
the dashboard and test console respond -- typically 5-8 minutes total for
the full stack install (Tetragon, cert-analyzer, Kafka, Prometheus,
Grafana, test console) to finish via cloud-init. On success it prints:

```
Dashboard:     http://certsight-demo.com:3000/d/certsight-v1
Test console:  http://certsight-demo.com:8090
```

The instance gets an Elastic IP (stays fixed for the life of the instance,
unlike a plain EC2 public IP which changes on stop/start), and the script
also points `certsight-demo.com` at it via Route 53 -- a hosted zone for
that domain already exists in this account. `teardown-demo.sh` removes the
DNS record before releasing the IP, so it never dangles pointing at an
address AWS could later hand to someone else. Set `DOMAIN_NAME=""` to skip
DNS entirely and just use the raw IP, or point at a different domain (must
already have a hosted zone in this account) via `DOMAIN_NAME=other.com`.

Useful overrides (env vars):

| Var | Default | Notes |
|---|---|---|
| `AWS_REGION` | `us-east-1` | |
| `INSTANCE_TYPE` | `t3.medium` | `t3.small` (2 GB RAM) is too tight for Tetragon + cert-analyzer + Kafka + Prometheus + Grafana + test console running together |
| `DOMAIN_NAME` | `certsight-demo.com` | Route 53 hosted zone must already exist for this domain; set empty to skip DNS |
| `CERTSIGHT_VERSION` | `v0.73` | Must be a tagged [release](../../releases) with RPM assets |
| `TETRAGON_VERSION` | `1.7.0` | Any [Tetragon release](https://github.com/cilium/tetragon/releases) with a `tetragon-vX.Y.Z-amd64.tar.gz` asset |
| `KEY_NAME` | `certsight-demo` | Reused across runs if it already exists in AWS |
| `SSH_CIDR` | auto-detected | Set to `x.x.x.x/32` to override |

Install progress/errors on the instance itself:

```bash
ssh -i certsight-demo.pem rocky@<public-ip>
sudo tail -f /var/log/certsight-demo-install.log
```

**SSH times out?** `SSH_CIDR` auto-detects the IP of the machine *running
`deploy-demo.sh`*, not necessarily the machine you'll SSH in from -- if
those differ (e.g. you ran the script from an agent sandbox or a jump host,
but want to SSH from your own laptop), the security group will allow the
wrong IP. Fix it any time:

```bash
./update-ssh-ip.sh                # re-detects and allows the IP of whatever
                                   # machine runs this command
./update-ssh-ip.sh 203.0.113.7    # or set one explicitly
```

## Tear down

```bash
./teardown-demo.sh              # terminates instance + deletes security group
./teardown-demo.sh --delete-key # also deletes the SSH key pair (local .pem + AWS)
```

---

## How it works

`deploy-demo.sh` does the AWS-side orchestration (AMI lookup, security
group, key pair, launch) and passes `user-data.sh` as EC2 user-data.
`user-data.sh` runs as root via cloud-init on first boot and does the actual
install, following the same steps as the main [README](../../README.md) and
[DASHBOARDS.md](../DASHBOARDS.md) -- nothing here is a special "demo-only"
install path.

State from a deploy (instance ID, security group ID, region, key name) is
kept in `.certsight-demo-state` (gitignored) so `teardown-demo.sh` knows
what to remove. Only one demo stack can be tracked at a time this way -- run
`teardown-demo.sh` before starting another.

## Troubleshooting

- **AMI lookup fails / "Could not find a Rocky Linux 9 AMI"**: the script
  looks for AMIs owned by Rocky Linux's publisher account (`792107900819`)
  named `Rocky-9-EC2-Base-9*`. If your region has none, check
  [rockylinux.org/cloud-images](https://rockylinux.org/cloud-images/) and
  set `AMI_ID` manually in the script.
- **Dashboard/console never come up**: SSH in and check
  `/var/log/certsight-demo-install.log` -- it's the full `set -x` trace of
  every install step, in order.
- **One Tetragon policy fails to apply**: expected for
  `experimental/java-fips-nss-cert.yaml`, which needs the `nss-softokn`
  debuginfo package installed to resolve its uprobe symbols (see the main
  [README](../../README.md#installation)) -- not installed here to keep the
  image lean. Everything else should apply cleanly.
- **"load a certificate into a Java KeyStore (JCA)" test console use case
  produces no Kafka event**: `user-data.sh` works around a known
  policy-load-timing issue (the `java-non-fips-cert.yaml` uprobe only
  attaches if `libcert_agent_stub.so` is already mapped into some process
  when the policy loads, which can't be true on a cold box) by jattaching a
  throwaway JVM and restarting Tetragon while it's still attached. If that
  warm-up step itself failed (check the install log for "WARNING: jattach
  into the warm-up JVM ... failed"), the fix is the same one it performs
  automatically: `sudo systemctl restart tetragon` on the instance, run
  while *some* process on the box has `libcert_agent_stub.so` mapped
  (e.g. click the JCA use case once first, then restart Tetragon within
  its ~15s lifetime) -- restarting Tetragon on a box with no such process
  running yet doesn't help, since nothing is mapped for the policy reload
  to bind against.
