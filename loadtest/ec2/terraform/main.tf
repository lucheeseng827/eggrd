# Isolated EdgeGuard benchmark, as IaC: an ephemeral key pair, a security group (SSH from your IP +
# all-TCP within the group so loadgen->proxy works on private IPs), and two instances (proxy +
# loadgen) sharing one subnet. The two hosts boot the SAME userdata scripts the CLI harness uses
# (../userdata-*.sh), so this is just the declarative twin of provision.sh. Tear down with
# `terraform destroy` (the CLI path uses ./teardown.sh). See README.md.

# --- network: default to the account's default VPC + its first subnet, override via vars ---
data "aws_vpc" "default" {
  count   = var.vpc_id == "" ? 1 : 0
  default = true
}

locals {
  vpc_id = var.vpc_id != "" ? var.vpc_id : data.aws_vpc.default[0].id
}

data "aws_subnets" "in_vpc" {
  count = var.subnet_id == "" ? 1 : 0
  filter {
    name   = "vpc-id"
    values = [local.vpc_id]
  }
}

# --- AMI: latest Amazon Linux 2023 x86_64 unless pinned ---
data "aws_ami" "al2023" {
  count       = var.ami_id == "" ? 1 : 0
  owners      = ["amazon"]
  most_recent = true
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
  filter {
    name   = "state"
    values = ["available"]
  }
}

# --- this machine's public IP, for the SSH ingress rule (unless overridden) ---
data "http" "myip" {
  count = var.ssh_cidr == "" ? 1 : 0
  url   = "https://checkip.amazonaws.com"
}

locals {
  subnet_id = var.subnet_id != "" ? var.subnet_id : data.aws_subnets.in_vpc[0].ids[0]
  ami_id    = var.ami_id != "" ? var.ami_id : data.aws_ami.al2023[0].id
  ssh_cidr  = var.ssh_cidr != "" ? var.ssh_cidr : "${chomp(data.http.myip[0].response_body)}/32"

  hosts = {
    proxy   = { userdata = "${path.module}/../userdata-proxy.sh" }
    loadgen = { userdata = "${path.module}/../userdata-loadgen.sh" }
  }

  tags = { Project = var.project_tag }
}

# --- ephemeral key pair; private key written locally (gitignored) ---
resource "tls_private_key" "bench" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "bench" {
  key_name   = var.key_name
  public_key = tls_private_key.bench.public_key_openssh
  tags       = local.tags
}

resource "local_sensitive_file" "pem" {
  content         = tls_private_key.bench.private_key_pem
  filename        = "${path.module}/${var.key_name}.pem"
  file_permission = "0400"
}

# --- security group: SSH from your IP; all TCP within the group (loadgen <-> proxy private) ---
resource "aws_security_group" "bench" {
  name        = "${var.project_tag}-tf-sg"
  description = "EdgeGuard isolated benchmark (terraform)"
  vpc_id      = local.vpc_id
  tags        = local.tags

  ingress {
    description = "SSH from the provisioning machine"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [local.ssh_cidr]
  }

  ingress {
    description = "All TCP within the group: loadgen -> proxy on 8080-8085 over private IPs"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- the two hosts ---
resource "aws_instance" "host" {
  for_each = local.hosts

  ami                    = local.ami_id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.bench.key_name
  subnet_id              = local.subnet_id
  vpc_security_group_ids = [aws_security_group.bench.id]
  user_data              = file(each.value.userdata)

  # Require IMDSv2 (token-backed) so the instance metadata service can't be
  # reached via SSRF / unauthenticated requests.
  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
  }

  tags = merge(local.tags, {
    Name = "${var.project_tag}-${each.key}"
    Role = each.key
  })
}
