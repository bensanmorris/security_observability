# Packer template for the CertSight Dashboard AMI.
#
# Bakes only ../dashboard-install.sh (packages: Prometheus, Grafana,
# certsight-test-server + the Java cert-agent packages it hard-depends on).
# Deliberately does NOT run dashboard-firstboot.sh -- that script generates
# the Grafana admin password and writes the region-dependent
# ec2_sd_configs, both of which must happen once per real instance, not
# once here at bake time (see dashboard-install.sh's header for why: baking
# a generated secret into a golden image means every instance launched from
# it shares that same, extractable password).
#
# Every instance launched from the resulting AMI still needs
# dashboard-firstboot.sh run via EC2 user-data at boot -- see
# ../cloudformation.yaml's DashboardInstance, which does this automatically.
#
# Usage:
#   cd extras/aws-marketplace/packer
#   packer init dashboard.pkr.hcl
#   packer build \
#     -var "certsight_version=v0.97" \
#     -var "aws_region=us-east-1" \
#     dashboard.pkr.hcl
#
# Requires AWS credentials in the environment (same as the AWS CLI) with
# permission to launch/terminate a build instance and register an AMI.

packer {
  required_plugins {
    amazon = {
      version = ">= 1.2.8"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "certsight_version" {
  type        = string
  default     = "v0.97"
  description = "Tagged CertSight release to bake in (must have RPM release assets)."
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "instance_type" {
  type    = string
  default = "t3.medium"
}

source "amazon-ebs" "dashboard" {
  region        = var.aws_region
  instance_type = var.instance_type
  ssh_username  = "rocky"
  ami_name      = "certsight-dashboard-${var.certsight_version}-{{timestamp}}"
  ami_description = "CertSight Dashboard: Prometheus (EC2 fleet discovery) + Grafana + certsight-test-server (explorer mode). See extras/aws-marketplace/README.md in bensanmorris/security_observability."

  source_ami_filter {
    filters = {
      name                = "Rocky-9-EC2-Base-9*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
      architecture        = "x86_64"
    }
    owners      = ["792107900819"]
    most_recent = true
  }

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  tags = {
    Name             = "certsight-dashboard"
    CertSightVersion = var.certsight_version
  }
}

build {
  name    = "certsight-dashboard"
  sources = ["source.amazon-ebs.dashboard"]

  provisioner "shell" {
    environment_vars = [
      "CERTSIGHT_VERSION=${var.certsight_version}",
    ]
    script          = "${path.root}/../dashboard-install.sh"
    execute_command = "sudo -E bash '{{ .Path }}'"
  }

  # Written so CI can pull the resulting AMI ID back out without scraping
  # Packer's console log -- see .github/workflows/build.yml's
  # build-dashboard-ami job.
  post-processor "manifest" {
    output     = "dashboard-manifest.json"
    strip_path = true
  }
}
