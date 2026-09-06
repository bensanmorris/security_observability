# CertSight for AWS

Two independently provisionable products, in place of `extras/aws-demo/`'s
single all-in-one box:

- **CertSight Analyzer** — Tetragon + cert-analyzer + the Java cert-agent.
  Scale this one out across your fleet, one instance per host (or per group
  of hosts).
- **CertSight Dashboard** — Prometheus + Grafana + the read-only fleet
  explorers (blast radius, chain explorer, FIPS rollout). One per fleet; it
  discovers every Analyzer instance automatically.

This is a separate, leaner deployment path alongside `extras/aws-demo/`,
which remains a good option for a quick single-box demo. Use this path when
you want to run CertSight across a real fleet with a dedicated dashboard.

## How fleet discovery works

Prometheus on the Dashboard instance uses native `ec2_sd_configs` — it asks
the EC2 API for every instance tagged `certsight-role=analyzer` in its
region, and scrapes each one's private IP on `:9090`. A new Analyzer
instance appears on the dashboard within one scrape interval, with no
target-list maintenance required.

The Dashboard's IAM role is granted read-only `ec2:DescribeInstances` to
make this possible — an account/region-wide read permission, since AWS
doesn't support scoping `Describe*` actions to specific tagged instances.

## What's included

- `analyzer-user-data.sh` — installs Tetragon, cert-analyzer, and the Java
  cert-agent on the Analyzer instance.
- `dashboard-install.sh` / `dashboard-firstboot.sh` — install Prometheus,
  Grafana, and the fleet explorers on the Dashboard instance.
  `dashboard-firstboot.sh` generates a fresh Grafana admin password and
  writes the region-specific Prometheus configuration on first boot, so
  each instance gets its own unique credentials rather than a shared one
  baked into an image.
- `cloudformation.yaml` — a quick-launch template that provisions both
  security groups, the Dashboard's IAM role, one Dashboard instance, and an
  Auto Scaling Group of Analyzer instances sized by the `AnalyzerCount`
  parameter (raise it later with a stack update to scale the fleet).
- `packer/analyzer.pkr.hcl` / `packer/dashboard.pkr.hcl` — Packer templates
  for building your own AMIs from a Rocky Linux 9 base image.

Pre-built AMIs are available in `us-east-1`:

| Product | AMI ID |
|---|---|
| CertSight Analyzer | `ami-0a13dd8bd71f5e2a4` |
| CertSight Dashboard | `ami-051cc74348b46bf48` |

These are `cloudformation.yaml`'s default `AnalyzerAMIId`/`DashboardAMIId`
values. AMI IDs are region-specific — to deploy in another region, build
your own with Packer (see below) or copy an existing AMI with `aws ec2
copy-image`, then pass the new AMI ID as a parameter.

## Deploying

```bash
aws cloudformation create-stack \
  --stack-name certsight \
  --template-body file://cloudformation.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters \
    ParameterKey=KeyName,ParameterValue=<your-key-pair> \
    ParameterKey=VpcId,ParameterValue=<vpc-id> \
    ParameterKey=SubnetId,ParameterValue=<subnet-id> \
    ParameterKey=SSHCidr,ParameterValue=<your-ip>/32 \
    ParameterKey=DashboardCidr,ParameterValue=<your-ip>/32
```

`AnalyzerAMIId`/`DashboardAMIId` can be omitted to use the pre-built AMIs
above, or set explicitly to target a different region or a custom build.
Add `ParameterKey=AnalyzerCount,ParameterValue=<n>` to launch more than one
Analyzer instance.

`CAPABILITY_NAMED_IAM` is required because the template names the
Dashboard's IAM role explicitly.

### What you get

- One or more **CertSight Analyzer** instances, each already running
  Tetragon and cert-analyzer, reporting metrics on `:9090`.
- One **CertSight Dashboard** instance running:
  - Grafana, at `http://<dashboard-public-ip>:3000/d/certsight-v1` —
    retrieve the generated admin password from its EC2 console log
    (**Instance → Actions → Monitor and troubleshoot → Get system log**).
  - The read-only fleet explorers, at `http://<dashboard-public-ip>:8090`
    (blast radius, fleet blast radius, chain explorer, fleet chain
    explorer, FIPS rollout). There's no interactive test console or action
    buttons here — see "Known limitations" below.

### Verifying it works

The Dashboard starts empty until an Analyzer instance actually observes
some certificate activity. To see it working end to end, SSH into an
Analyzer instance and generate a bit of real traffic:

```bash
ssh -i <your-key>.pem rocky@<analyzer-public-ip>

# read the system CA trust bundle, and make a couple of outbound TLS connections
sudo cat /etc/pki/tls/certs/ca-bundle.crt > /dev/null
curl -s -o /dev/null https://example.com
curl -s -o /dev/null https://github.com
```

Within about a minute (Prometheus's scrape interval), you should see:
- Certificate data appear on the Grafana dashboard.
- The explorer pages at `:8090` populate with real chains and hosts
  (`/blast-radius`, `/chain-explorer`, `/fleet-fips-rollout`, etc.)
  instead of showing no data.

Tear down with:

```bash
aws cloudformation delete-stack --stack-name certsight
```

## Building your own AMI

```bash
cd packer
packer init analyzer.pkr.hcl      # or dashboard.pkr.hcl
packer build -var "certsight_version=v0.97" -var "aws_region=<region>" analyzer.pkr.hcl
```

Each template's own header comment has full usage details.

## Known limitations

- No live Kafka-backed event stream and no interactive "run a use case"
  console — the Dashboard ships the read-only fleet explorers only.
- Grafana uses a generated local admin password; no SSO/OIDC integration.
- The Dashboard and every Analyzer instance need to share a region and VPC
  (or peered VPCs) for fleet discovery to work — no cross-account or
  cross-region fleets.
- On a freshly launched Analyzer instance, Java KeyStore certificate
  detection may not activate until a real JVM using the cert-agent has
  started and Tetragon has been restarted once while it's running.
