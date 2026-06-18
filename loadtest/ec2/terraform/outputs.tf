output "proxy_public_ip" {
  description = "SSH/scp target for the proxy host."
  value       = aws_instance.host["proxy"].public_ip
}

output "proxy_private_ip" {
  description = "Address the load generator hits over the private NIC (http://<this>:8080..8085)."
  value       = aws_instance.host["proxy"].private_ip
}

output "loadgen_public_ip" {
  description = "SSH target for the k6 load-generator host."
  value       = aws_instance.host["loadgen"].public_ip
}

output "pem_path" {
  description = "Local private key for SSH."
  value       = local_sensitive_file.pem.filename
}

output "instances_env" {
  description = "Paste into ../instances.env to drive run-saturation.sh against this TF-managed rig."
  value = join("\n", [
    "PROXY_ID=${aws_instance.host["proxy"].id}",
    "LOADGEN_ID=${aws_instance.host["loadgen"].id}",
    "SG_ID=${aws_security_group.bench.id}",
    "PROXY_PUB=${aws_instance.host["proxy"].public_ip}",
    "PROXY_PRIV=${aws_instance.host["proxy"].private_ip}",
    "LOADGEN_PUB=${aws_instance.host["loadgen"].public_ip}",
  ])
}

output "ssh_proxy" {
  value = "ssh -i ${local_sensitive_file.pem.filename} ec2-user@${aws_instance.host["proxy"].public_ip}"
}

output "ssh_loadgen" {
  value = "ssh -i ${local_sensitive_file.pem.filename} ec2-user@${aws_instance.host["loadgen"].public_ip}"
}
