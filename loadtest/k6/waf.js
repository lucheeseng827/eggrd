// WAF scenario: throughput cost + block correctness under load.
//
// ~90% benign traffic, ~10% attack-shaped, all screened by the built-in SQLi/XSS/path-traversal
// rulesets (waf-block.toml). We assert two things at throughput:
//   * benign requests pass (200) — no false positives on the realistic corpus, and
//   * every attack-shaped request is blocked (403) — no false negatives on the known payloads.
// The latency/RPS delta vs. baseline is the "WAF tax"; pair it with benches/waf.rs for the
// per-request regex cost. Run the same script against a `mode = "report"` config to measure the
// report-only path (attacks then return 200 but are still counted in edgeguard_waf_hits_total).

import http from "k6/http";
import { check } from "k6";
import { Rate } from "k6/metrics";
import exec from "k6/execution";
import { BASE_URL, BENIGN_PATHS, ATTACK_PATHS, pick } from "./lib.js";

const falseNeg = new Rate("eg_waf_false_negative"); // attack NOT blocked in block mode
const falsePos = new Rate("eg_waf_false_positive"); // benign WAS blocked

export const options = {
  scenarios: {
    ramp: {
      executor: "ramping-arrival-rate",
      startRate: 500,
      timeUnit: "1s",
      preAllocatedVUs: 200,
      maxVUs: 2000,
      stages: [
        { target: 2000, duration: "30s" },
        { target: 6000, duration: "30s" },
        { target: 8000, duration: "30s" },
      ],
    },
  },
  thresholds: {
    eg_waf_false_negative: ["rate<0.001"],
    eg_waf_false_positive: ["rate<0.001"],
    http_req_duration: ["p(99)<50"],
  },
};

export default function () {
  // ~1 in 10 requests is an attack payload. Use the test-global iteration counter
  // (exec.scenario.iterationInTest) rather than the per-VU __ITER, so both the attack mix
  // and the path spread stay even across VUs and stage transitions.
  const i = exec.scenario.iterationInTest;
  const isAttack = i % 10 === 0;
  if (isAttack) {
    const res = http.get(`${BASE_URL}${pick(ATTACK_PATHS, i)}`);
    falseNeg.add(res.status !== 403);
    check(res, { "attack blocked (403)": (r) => r.status === 403 });
  } else {
    const res = http.get(`${BASE_URL}${pick(BENIGN_PATHS, i)}`);
    falsePos.add(res.status === 403);
    check(res, { "benign passed (200)": (r) => r.status === 200 });
  }
}
