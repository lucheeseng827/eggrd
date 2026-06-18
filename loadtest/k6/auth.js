// AUTH scenario: cost of the API-key gate at throughput.
//
// Identical load profile to baseline.js, but every request carries `X-API-Key` and the proxy
// runs auth=apikey. The latency/RPS delta vs. baseline is the gate's end-to-end tax; compare it
// with benches/auth.rs (`apikey`) to confirm the macro number matches the isolated per-call cost.
// A `wrong-key -> 401` spot check guards against accidentally measuring an open proxy.

import http from "k6/http";
import { check, fail } from "k6";
import { BASE_URL, BENIGN_PATHS, authHeaders, pick, FAST_THRESHOLDS } from "./lib.js";

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
        { target: 10000, duration: "30s" },
      ],
    },
  },
  thresholds: {
    ...FAST_THRESHOLDS,
    checks: ["rate>0.99"],
  },
};

export function setup() {
  // Sanity: an unauthenticated request must be rejected — otherwise the run is meaningless.
  const unauth = http.get(`${BASE_URL}/`);
  const ok = check(unauth, { "rejects missing key (401)": (r) => r.status === 401 });
  // Hard-abort: benchmarking an open proxy would publish a meaningless "auth cost".
  if (!ok) fail("auth scenario invalid: unauthenticated request was not rejected with 401");
}

export default function () {
  // Spread paths across VUs (not just per-VU __ITER) so route distribution isn't phase-locked.
  const path = pick(BENIGN_PATHS, __VU * 1000000 + __ITER);
  const res = http.get(`${BASE_URL}${path}`, { headers: authHeaders() });
  check(res, { "authorized 200": (r) => r.status === 200 });
}
