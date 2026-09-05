# CertSight on AWS Marketplace (in progress)

Two independently provisionable products, in place of `extras/aws-demo/`'s
single all-in-one box:

- **CertSight Analyzer** — Tetragon + cert-analyzer + the Java cert-agent.
  No Kafka, no test console. Scale this one out across your fleet.
- **CertSight Dashboard** — Prometheus + Grafana + `certsight-test-server`
  running in `--mode explorer` (read-only fleet explorers only — no
  unauthenticated action endpoints, no Kafka). One per fleet; it discovers
  every Analyzer instance automatically.

**This is adjacent to `extras/aws-demo/`, not a replacement for it.** The
existing single-box demo (`deploy-demo.sh`/`teardown-demo.sh`/`user-data.sh`)
is untouched and keeps working exactly as it does today — it's a different,
simpler thing (one box, Kafka-backed live event stream, the full
unauthenticated test console) aimed at a quick public demo link, not a
product a customer runs long-term.

## Why no Kafka on this path

The demo's live "Kafka event stream" pane and the "run a use case" action
buttons are explicitly out of scope for v1 of this product (see the plan
below) — they're an unauthenticated code-execution surface on the demo box,
acceptable there only because the operator tears it down afterwards. Cutting
Kafka out entirely means the Dashboard AMI has one fewer moving part (no
broker to run or secure) and the fleet-wide explorer pages (blast radius,
chain explorer, FIPS rollout) work over Prometheus alone.

## How fleet discovery works

Prometheus on the Dashboard instance uses native `ec2_sd_configs` — it asks
the EC2 API (via an IAM instance profile granting read-only
`ec2:DescribeInstances`) for every instance tagged `certsight-role=analyzer`
in its region, and scrapes each one's private IP on `:9090`. A new Analyzer
instance appears on the dashboard within one scrape interval, with zero
target-list maintenance. See `dashboard-user-data.sh`'s `prometheus.yml`
generation and `cloudformation.yaml`'s `DashboardRole`/`AnalyzerLaunchTemplate`
tag.

`ec2:DescribeInstances` has no resource-level condition in AWS IAM, so this
permission is account/region-wide read access to instance metadata — not
scopable to just CertSight-tagged instances. Documented limitation, not an
oversight.

## Files here

- `analyzer-user-data.sh` — Analyzer AMI install steps (cloud-init or Packer).
- `dashboard-user-data.sh` — Dashboard AMI install steps, including the
  `ec2_sd_configs` Prometheus config, hardened Grafana (real login required,
  no anonymous-viewer mode, admin password echoed to the instance's console
  log as well as `/root/.grafana-admin-credentials`), and
  `certsight-test-server` in explorer mode.
- `cloudformation.yaml` — quick-launch template: both security groups
  (SG-to-SG referenced, not CIDR-based), the Dashboard's IAM role, one
  Dashboard instance, and an Auto Scaling Group of Analyzer instances sized
  by the `AnalyzerCount` parameter (raise it later with a plain stack update
  to scale the fleet — no template change needed).

No Packer templates yet (see Status below) — until those exist, both
`AnalyzerAMIId` and `DashboardAMIId` can simply be a stock Rocky Linux 9 AMI
ID; the CloudFormation template's own `UserData` fetches and runs the
real, version-pinned install script at boot either way.

## Testing this today

```bash
aws cloudformation validate-template \
  --template-body file://cloudformation.yaml --region us-east-1
```

This is free and non-mutating — it only checks the template's syntax/schema,
no resources are created. Confirmed passing as of this writing.

To actually launch a throwaway stack (**this costs real money and creates
real EC2/IAM resources in your account** — confirm the region/instance types
below before running, and tear it down when done):

```bash
aws cloudformation create-stack \
  --stack-name certsight-test \
  --template-body file://cloudformation.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters \
    ParameterKey=AnalyzerAMIId,ParameterValue=<rocky-9-ami-id> \
    ParameterKey=DashboardAMIId,ParameterValue=<rocky-9-ami-id> \
    ParameterKey=KeyName,ParameterValue=<your-key-pair> \
    ParameterKey=VpcId,ParameterValue=<vpc-id> \
    ParameterKey=SubnetId,ParameterValue=<subnet-id> \
    ParameterKey=SSHCidr,ParameterValue=<your-ip>/32 \
    ParameterKey=DashboardCidr,ParameterValue=<your-ip>/32

# tear down when done:
aws cloudformation delete-stack --stack-name certsight-test
```

`CAPABILITY_NAMED_IAM` is required because the template names the Dashboard's
IAM role explicitly (`${AWS::StackName}-certsight-dashboard-role`).

## Status

Part of a larger plan — see the AWS Marketplace project memory / the
originally-approved plan file for full context (product decisions, explicit
v1 non-goals, sequencing). Current state:

- **Phase 1 (done)**: `certsight-test-server`'s explorer-only mode, dashboard
  node-filter fix.
- **Phase 2 (this directory, done)**: split user-data scripts,
  `ec2_sd_configs` Prometheus config, security-group model, CFN quick-launch
  template. Validated with `aws cloudformation validate-template`; not yet
  launched end-to-end against real EC2 instances.
- **Phase 3 (not started)**: Packer templates to pre-bake both AMIs, wired
  into `.github/workflows/build.yml` as a per-tag CI job.
- **Phase 4 (not started, outside this repo's scope)**: actual AWS
  Marketplace seller registration and listing creation.

## Known limitations (v1, by design)

- No Kafka-backed live event stream or "run a use case" console anywhere in
  this product — see "Why no Kafka" above.
- Grafana uses generated local admin credentials, no SSO/OIDC.
- Assumes the Dashboard and every Analyzer instance share one region and one
  VPC (or peered VPCs) so `ec2_sd_configs` can see them — no cross-account or
  cross-region fleet support.
- On a cold-booted Analyzer instance, Tetragon's `java-non-fips-cert` uprobe
  (Java cert-agent detection) may not attach until *some* real JVM has
  loaded the cert-agent native library and Tetragon is restarted while that
  JVM is still running — `extras/aws-demo/`'s synthetic warm-up JVM trick
  can't be reused here (it depends on a class file that ships only with
  `certsight-test-server`, which isn't installed on the Analyzer AMI). See
  the comment at the bottom of `analyzer-user-data.sh`.
