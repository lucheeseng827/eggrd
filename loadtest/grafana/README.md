# Grafana for the EdgeGuard load-test harness

Two copies of the **"EdgeGuard — proxy overview"** dashboard, for two different ways of loading it.

| File | Use |
|---|---|
| `provisioning/dashboards/eggrd-overview.json` | **Auto-provisioned** by the compose stack (file provider + the pinned `prometheus` datasource uid). Don't import this one by hand — it uses a concrete datasource uid and the importer rejects it as "old format". |
| `eggrd-overview.import.json` | **Manual UI import** into any Grafana. Export/share format (`__inputs` + `__requires`, templated `${DS_PROMETHEUS}` datasource). |

## Auto (compose)
`docker compose --profile observability up` mounts `provisioning/` and the dashboard loads itself at
http://localhost:3000/d/eggrd-overview — nothing to import.

## Manual import (the fix for "Old dashboard JSON format")
That error means the **bare** dashboard model was uploaded; the import UI wants the share format.
Use `eggrd-overview.import.json` instead:

1. Grafana → **Dashboards → New → Import**.
2. **Upload JSON file** → `eggrd-overview.import.json` (or paste its contents).
3. When prompted, pick your **Prometheus** datasource for the `DS_PROMETHEUS` input → **Import**.

Panels query the `edgeguard_*` series (request rate by outcome, p50/p95/p99 from
`edgeguard_request_duration_seconds_bucket`, rate-limit hits by scope, WAF hits by rule), so any
Prometheus scraping EdgeGuard's `/__edgeguard/metrics` works.
