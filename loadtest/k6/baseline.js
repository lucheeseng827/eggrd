// BASELINE scenario: pure passthrough overhead.
//
// Offers a climbing request rate against the proxy (auth/limit/WAF all off) and records latency
// percentiles + achieved throughput. Run the SAME profile straight at the nginx stub (see
// run.sh `--direct`) to get the "proxy tax": the latency added and the max-RPS lost by putting
// EdgeGuard in front. This is the foundational number the white paper builds on.

import http from "k6/http";
import { check } from "k6";
import { BASE_URL, BENIGN_PATHS, pick, FAST_THRESHOLDS } from "./lib.js";

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
        { target: 10000, duration: "30s" },
        { target: 10000, duration: "30s" }, // hold at the top to read steady-state latency
      ],
    },
  },
  thresholds: FAST_THRESHOLDS,
};

export default function () {
  // Spread paths across VUs (not just per-VU __ITER) so route distribution isn't phase-locked.
  const path = pick(BENIGN_PATHS, __VU * 1000000 + __ITER);
  const res = http.get(`${BASE_URL}${path}`);
  check(res, { "status is 200": (r) => r.status === 200 });
}
