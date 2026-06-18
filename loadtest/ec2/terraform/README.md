# Terraform: isolated benchmark hosts

Declarative twin of `../provision.sh` — stands up the same two-host rig (proxy + load generator in
one subnet, SSH locked to your IP) as Terraform. Both hosts boot the **same** `../userdata-proxy.sh`
/ `../userdata-loadgen.sh`, so the load-test orchestration (`../run-saturation.sh`) is unchanged.

Use this when you want the rig as code (review, repeatability, state) instead of the imperative CLI
script. Use either path, not both — they create overlapping resources.

## Apply

```bash
cd loadtest/ec2/terraform
terraform init
terraform apply                 # creates key pair, SG, 2x c7i.2xlarge; writes <key_name>.pem here

# wire the existing orchestrator to these hosts, then run the sweep:
terraform output -raw instances_env > ../instances.env
cd ..
PEM_PATH="$(terraform -chdir=terraform output -raw pem_path)" ./run-saturation.sh
./summarize-ec2.sh
```

> The simplest end-to-end stays the CLI: `../provision.sh && ../run-saturation.sh`. This module is for
> when the infra must live in Terraform. To point `run-saturation.sh` at TF hosts, just make
> `../instances.env` + the pem match (the two commands above).

## Destroy (stop charges)

```bash
terraform destroy
```

## Notes
- Defaults: `ap-southeast-1`, default VPC + its first subnet, latest AL2023 x86_64, `c7i.2xlarge` ×2
  (~$0.84/hr total). Override with `-var` or a `*.tfvars`.
- SSH ingress defaults to **your current public IP /32** (auto-detected via `checkip.amazonaws.com`);
  set `-var ssh_cidr=...` to pin it.
- **State holds the private key** — `.gitignore` excludes `*.tfstate*` and `*.pem`. Use a remote
  backend with encryption for anything shared.
