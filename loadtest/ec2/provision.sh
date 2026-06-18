#!/usr/bin/env bash
# Provision the isolated benchmark: an ephemeral key pair, a security group (SSH from your IP +
# all-TCP within the group so loadgen->proxy works on private IPs), and two instances (proxy +
# loadgen) in the same subnet/AZ. Writes instances.env with the IPs. Idempotent-ish: reuses an
# existing key/SG by name. Tear down with ./teardown.sh.
set -euo pipefail
cd "$(dirname "$0")"
source ./config.env

MY_IP="$(curl -fsS https://checkip.amazonaws.com)"
echo ">> region=$REGION subnet=$SUBNET_ID type=$INSTANCE_TYPE ssh-from=${MY_IP}/32"

# --- key pair (save the private key locally; gitignored) ---
CREATED_KEY_PAIR=false
if ! aws ec2 describe-key-pairs --region "$REGION" --key-names "$KEY_NAME" >/dev/null 2>&1; then
  echo ">> creating key pair $KEY_NAME -> $PEM_PATH"
  aws ec2 create-key-pair --region "$REGION" --key-name "$KEY_NAME" \
    --query 'KeyMaterial' --output text > "$PEM_PATH"
  chmod 400 "$PEM_PATH"
  CREATED_KEY_PAIR=true
else
  echo ">> key pair $KEY_NAME already exists (expecting $PEM_PATH locally)"
  if [[ ! -f "$PEM_PATH" ]]; then
    echo "Missing local PEM at $PEM_PATH for existing key pair $KEY_NAME" >&2
    echo "Either restore the PEM, change KEY_NAME, or delete/recreate the key pair." >&2
    exit 1
  fi
  chmod 400 "$PEM_PATH"
fi

# --- security group ---
CREATED_SG=false
SG_ID="$(aws ec2 describe-security-groups --region "$REGION" \
  --filters "Name=group-name,Values=$SG_NAME" "Name=vpc-id,Values=$VPC_ID" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)"
if [[ -z "$SG_ID" || "$SG_ID" == "None" ]]; then
  echo ">> creating security group $SG_NAME"
  SG_ID="$(aws ec2 create-security-group --region "$REGION" --group-name "$SG_NAME" \
    --description "EdgeGuard isolated benchmark" --vpc-id "$VPC_ID" \
    --query 'GroupId' --output text)"
  CREATED_SG=true
fi
# Ensure the required ingress rules exist even when the SG is reused — the caller's
# IP may have changed since creation, or rules may have been edited. authorize is
# idempotent, so a DuplicatePermission error on re-run is expected and ignored.
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 22 --cidr "${MY_IP}/32" >/dev/null 2>&1 || true
# All TCP between members of this SG (loadgen -> proxy on 8080-8085, private IPs).
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 0-65535 --source-group "$SG_ID" >/dev/null 2>&1 || true
echo ">> security group: $SG_ID"

launch() { # role userdata-file
  local role="$1" ud="$2"
  aws ec2 run-instances --region "$REGION" \
    --image-id "$AMI_ID" --instance-type "$INSTANCE_TYPE" --key-name "$KEY_NAME" \
    --subnet-id "$SUBNET_ID" --security-group-ids "$SG_ID" \
    --user-data "file://${ud}" \
    --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=20,VolumeType=gp3}' \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${PROJECT_TAG}-${role}},{Key=Project,Value=${PROJECT_TAG}},{Key=Role,Value=${role}}]" \
    --query 'Instances[0].InstanceId' --output text
}

echo ">> launching proxy + loadgen ($INSTANCE_TYPE)"
PROXY_ID="$(launch proxy userdata-proxy.sh)"
LOADGEN_ID="$(launch loadgen userdata-loadgen.sh)"
echo ">> proxy=$PROXY_ID loadgen=$LOADGEN_ID — waiting for running state"
aws ec2 wait instance-running --region "$REGION" --instance-ids "$PROXY_ID" "$LOADGEN_ID"

ip() { aws ec2 describe-instances --region "$REGION" --instance-ids "$1" --query "$2" --output text; }
PROXY_PUB="$(ip "$PROXY_ID" 'Reservations[0].Instances[0].PublicIpAddress')"
PROXY_PRIV="$(ip "$PROXY_ID" 'Reservations[0].Instances[0].PrivateIpAddress')"
LOADGEN_PUB="$(ip "$LOADGEN_ID" 'Reservations[0].Instances[0].PublicIpAddress')"

cat > "$INSTANCES_ENV" <<EOF
PROXY_ID=$PROXY_ID
LOADGEN_ID=$LOADGEN_ID
SG_ID=$SG_ID
CREATED_SG=$CREATED_SG
CREATED_KEY_PAIR=$CREATED_KEY_PAIR
PROXY_PUB=$PROXY_PUB
PROXY_PRIV=$PROXY_PRIV
LOADGEN_PUB=$LOADGEN_PUB
EOF
echo ">> wrote $INSTANCES_ENV:"; cat "$INSTANCES_ENV"
echo ">> next: ./run-saturation.sh  (waits for bootstrap, copies harness, runs k6 over the private NIC)"
