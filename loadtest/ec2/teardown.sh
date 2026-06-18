#!/usr/bin/env bash
# Terminate the benchmark instances and remove the security group + key pair. Safe to re-run.
set -euo pipefail
cd "$(dirname "$0")"
source ./config.env
[[ -f "$INSTANCES_ENV" ]] && source "$INSTANCES_ENV" || true

if [[ -n "${PROXY_ID:-}" || -n "${LOADGEN_ID:-}" ]]; then
  echo ">> terminating ${PROXY_ID:-} ${LOADGEN_ID:-}"
  aws ec2 terminate-instances --region "$REGION" --instance-ids ${PROXY_ID:-} ${LOADGEN_ID:-} >/dev/null || true
  aws ec2 wait instance-terminated --region "$REGION" --instance-ids ${PROXY_ID:-} ${LOADGEN_ID:-} || true
fi

# SG can only be deleted once its instances are gone.
SG_ID="${SG_ID:-$(aws ec2 describe-security-groups --region "$REGION" \
  --filters "Name=group-name,Values=$SG_NAME" "Name=vpc-id,Values=$VPC_ID" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)}"
# Only delete shared AWS resources this harness actually created (the flags are
# written to instances.env by provision.sh); a reused SG/key pair predated us.
if [[ "${CREATED_SG:-false}" == "true" && -n "$SG_ID" && "$SG_ID" != "None" ]]; then
  echo ">> deleting security group $SG_ID"
  deleted=false
  for _ in $(seq 1 12); do
    if aws ec2 delete-security-group --region "$REGION" --group-id "$SG_ID" 2>/dev/null; then
      deleted=true
      break
    fi
    sleep 5
  done
  if [[ "$deleted" != "true" ]]; then
    echo "ERROR: failed to delete security group $SG_ID after retries" >&2
    exit 1
  fi
elif [[ -n "$SG_ID" && "$SG_ID" != "None" ]]; then
  echo ">> skipping security group deletion (not created by this harness): $SG_ID"
fi

if [[ "${CREATED_KEY_PAIR:-false}" == "true" ]]; then
  echo ">> deleting key pair $KEY_NAME"
  aws ec2 delete-key-pair --region "$REGION" --key-name "$KEY_NAME" >/dev/null 2>&1 || true
else
  echo ">> skipping key pair deletion (not created by this harness): $KEY_NAME"
fi
rm -f "$PEM_PATH" "$INSTANCES_ENV"
echo ">> torn down."
