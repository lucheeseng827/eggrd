#!/usr/bin/env bash
# kubeconform.sh <kustomize dir>: render with kubectl kustomize and validate every object against
# the Kubernetes 1.31 schemas, and CRDs (PrometheusRule, Ingress annotations are free-form) against
# the community CRD catalog. Strict: unknown fields fail. Runs kubeconform from its image.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/smoke-lib.sh"
dir="${1:?usage: $0 <kustomize dir>}"
command -v kubectl >/dev/null || die "need kubectl (for kubectl kustomize)"
out="$(kubectl kustomize "$(hostpath "$dir")" | "$(engine)" run --rm -i ghcr.io/yannh/kubeconform:v0.6.7 \
  -strict -summary -kubernetes-version 1.31.0 \
  -schema-location default \
  -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' \
  - 2>&1)" && rc=0 || rc=$?
printf '%s\n' "$out" | sed 's/^/    /'
exit "$rc"
