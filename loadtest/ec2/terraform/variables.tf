variable "region" {
  description = "AWS region for the benchmark hosts."
  type        = string
  default     = "ap-southeast-1"
}

variable "instance_type" {
  description = "Instance type for BOTH the proxy and the load generator (compute-optimized = clean perf numbers)."
  type        = string
  default     = "c7i.2xlarge" # 8 vCPU
}

variable "vpc_id" {
  description = "VPC to launch into. Empty = the account's default VPC in this region."
  type        = string
  default     = ""
}

variable "subnet_id" {
  description = "Subnet (both hosts share it, so loadgen->proxy stays on one AZ's private NIC). Empty = first subnet of the chosen VPC."
  type        = string
  default     = ""
}

variable "ami_id" {
  description = "AMI. Empty = latest Amazon Linux 2023 x86_64 (looked up)."
  type        = string
  default     = ""
}

variable "ssh_cidr" {
  description = "CIDR allowed to SSH (port 22). Empty = this machine's public IP /32 (auto-detected)."
  type        = string
  default     = ""
}

variable "key_name" {
  description = "EC2 key pair name to create. The private key is written to ./<key_name>.pem (gitignored)."
  type        = string
  default     = "edgeguard-bench-tf"
}

variable "project_tag" {
  description = "Value for the Project tag on every resource."
  type        = string
  default     = "edgeguard-bench"
}

variable "root_volume_gb" {
  description = "Root gp3 volume size (GiB)."
  type        = number
  default     = 20
}
