# Isolated EC2 benchmark (saturation + clean numbers)

The local `loadtest/` harness co-locates k6 with the proxy (loopback) — fine for relative deltas,
but the generator competes with the proxy for CPU, so absolute throughput and the saturation ceiling
are unreliable. This rig fixes that: **two EC2 instances in one subnet** — a proxy host running all
six proxies, and a separate load-gen host running k6 over the **private NIC**. No loopback, no
generator-vs-proxy contention.

```text
  loadgen EC2 (native k6) ──private NIC──▶ proxy EC2 (docker compose: 6 proxies) ──▶ upstream (in-compose nginx)
```

## Usage

```bash
cd loadtest/ec2
./provision.sh            # key pair + SG + 2x c7i.2xlarge in ap-southeast-1; writes instances.env
./run-saturation.sh       # ships harness, builds EdgeGuard, runs k6 saturation per proxy
./summarize-ec2.sh        # results/sat-*.json + .stats -> Markdown table
./teardown.sh             # terminate instances, delete SG + key  (DO THIS WHEN DONE — charges accrue hourly)

# baseline (non-saturating) profile on the isolated rig, for clean absolute latency:
./run-saturation.sh baseline && ./summarize-ec2.sh baseline
```

`config.env` holds the resolved AWS coordinates (region/VPC/subnet/AMI/instance type) — override via
env to retarget. Artifacts (`*.pem`, `instances.env`, `results/`) are gitignored.

## What it measures

- **Saturation:** k6 ramps offered load 10k→60k RPS (past the knee). Achieved RPS while `Error %`
  (shed) climbs ≈ the sustained **throughput ceiling**; the latency curve + shed rate show whether the
  proxy **degrades gracefully** (sheds 503/timeout) or falls over. Proxy-side peak CPU%/RSS captured.
- **Isolation:** all six proxies run side by side; only one is loaded at a time (the idle five cost
  ~nothing), so each is measured on the same warm host with the same upstream.

## Cost & safety

- 2× `c7i.2xlarge` on-demand in ap-southeast-1 ≈ **$0.84/hr total**. A full sweep is well under an hour.
- **`./teardown.sh` when finished** — instances bill until terminated. The SG allows SSH only from the
  provisioning machine's public IP and all-TCP only within the group (loadgen↔proxy private).
- Sizing the ceiling: if a fast C proxy (nginx/HAProxy) never sheds at 60k, it didn't knee on 8 vCPU —
  bump `INSTANCE_TYPE` down (smaller proxy) or raise the k6 target to find it; EdgeGuard/Go proxies
  knee within range. Run from a bigger loadgen if k6 itself caps out before the proxy does.
