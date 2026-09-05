# Packer template for the CertSight Analyzer AMI.
#
# Bakes ../analyzer-user-data.sh's install steps (Tetragon + cert-analyzer +
# Java cert-agent) into a Rocky Linux 9 base image. Nothing in that script
# generates per-instance secrets, so unlike the Dashboard template it's safe
# to run the whole thing at bake time -- no first-boot half needed here.
#
# Usage:
#   cd extras/aws-marketplace/packer
#   packer init analyzer.pkr.hcl
#   packer build \
#     -var "certsight_version=v0.96" \
#     -var "aws_region=us-east-1" \
#     analyzer.pkr.hcl
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
  default     = "v0.96"
  description = "Tagged CertSight release to bake in (must have RPM/Tetragon-policy release assets)."
}

variable "tetragon_version" {
  type    = string
  default = "1.7.0"
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "instance_type" {
  type    = string
  default = "t3.small"
}

# Same Rocky Linux 9 publisher account extras/aws-demo/deploy-demo.sh already
# looks up AMIs from -- reusing a known-working source rather than picking a
# new one.
source "amazon-ebs" "analyzer" {
  region        = var.aws_region
  instance_type = var.instance_type
  ssh_username  = "rocky"
  ami_name      = "certsight-analyzer-${var.certsight_version}-{{timestamp}}"
  ami_description = "CertSight Analyzer: Tetragon + cert-analyzer + Java cert-agent. See extras/aws-marketplace/README.md in bensanmorris/security_observability."

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

  # Matches the hardening deploy-demo.sh applies at launch time -- an AMI
  # baked without this would still be launched with it enforced by whoever
  # launches it (cloudformation.yaml sets MetadataOptions too), but setting
  # it here as well means a plain `aws ec2 run-instances` against this AMI
  # with no explicit override still gets IMDSv2-only.
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  tags = {
    Name             = "certsight-analyzer"
    CertSightVersion = var.certsight_version
  }
}

build {
  name    = "certsight-analyzer"
  sources = ["source.amazon-ebs.analyzer"]

  provisioner "shell" {
    environment_vars = [
      "CERTSIGHT_VERSION=${var.certsight_version}",
      "TETRAGON_VERSION=${var.tetragon_version}",
    ]
    script          = "${path.root}/../analyzer-user-data.sh"
    execute_command = "sudo -E bash '{{ .Path }}'"
  }

  # Written so CI can pull the resulting AMI ID back out without scraping
  # Packer's console log -- see .github/workflows/build.yml's
  # build-analyzer-ami job.
  post-processor "manifest" {
    output     = "analyzer-manifest.json"
    strip_path = true
  }
}
