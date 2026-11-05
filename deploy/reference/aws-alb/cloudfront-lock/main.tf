# Lock an ALB to CloudFront, for eggrd with forwarded_hops = 2 (CloudFront -> ALB -> eggrd).
#
# With two hops counted from the right, a client that reaches the ALB directly is believed: the
# ALB appends the client's address where CloudFront's would be, and the client's own
# X-Forwarded-For entry becomes "the client". So the ALB must accept only CloudFront, and only
# YOUR distribution:
#   1. its security group admits only CloudFront's origin-facing prefix list;
#   2. CloudFront adds a secret header, and the ALB forwards only requests that carry it (the
#      prefix list admits every CloudFront distribution, anyone's).
#
# Validated with `terraform validate` (smoke.sh); not applied here. With the AWS Load Balancer
# Controller, attach the security group with the Ingress annotation
# alb.ingress.kubernetes.io/security-groups and express the header rule as
# alb.ingress.kubernetes.io/conditions.eggrd (README.md) instead of the listener rule below.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

variable "vpc_id" {
  type        = string
  description = "The ALB's VPC."
}

variable "https_listener_arn" {
  type        = string
  description = "The ALB's HTTPS listener. Set its default action to a fixed 403."
}

variable "target_group_arn" {
  type        = string
  description = "The target group of eggrd's pods (or instances)."
}

variable "origin_secret" {
  type        = string
  sensitive   = true
  description = "A long random value CloudFront sends as X-Origin-Verify. Rotate it like a password."
}

data "aws_ec2_managed_prefix_list" "cloudfront" {
  name = "com.amazonaws.global.cloudfront.origin-facing"
}

resource "aws_security_group" "alb_from_cloudfront" {
  name_prefix = "alb-from-cloudfront-"
  description = "HTTPS to the ALB from CloudFront's origin-facing ranges only"
  vpc_id      = var.vpc_id

  ingress {
    description     = "CloudFront origin-facing"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.cloudfront.id]
  }

  egress {
    description = "to the targets"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle { create_before_destroy = true }
}

# Forward only requests carrying CloudFront's secret header; everything else falls through to the
# listener's default action (a fixed 403).
resource "aws_lb_listener_rule" "from_cloudfront_only" {
  listener_arn = var.https_listener_arn
  priority     = 1

  action {
    type             = "forward"
    target_group_arn = var.target_group_arn
  }

  condition {
    http_header {
      http_header_name = "X-Origin-Verify"
      values           = [var.origin_secret]
    }
  }
}

# On the CloudFront side (aws_cloudfront_distribution), the origin pointing at the ALB:
#   origin {
#     domain_name = "<the ALB's DNS name>"
#     origin_id   = "alb"
#     custom_header { name = "X-Origin-Verify"  value = var.origin_secret }
#     custom_origin_config { origin_protocol_policy = "https-only" ... }
#   }
# and an origin request policy that forwards the viewer's Host header (eggrd's Host rule and the
# app see the name the viewer asked for, not the ALB's).

output "alb_security_group_id" {
  value = aws_security_group.alb_from_cloudfront.id
}
