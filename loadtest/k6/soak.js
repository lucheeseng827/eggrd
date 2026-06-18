// SOAK / endurance scenario: steady moderate load for a long duration.
//
// Holds a comfortable, below-the-knee rate for a long time (default 30m; override with
// K6_SOAK_DURATION) to surface slow problems the short scenarios miss: memory growth, file-
// descriptor / connection leaks, latency drift. Capture RSS and FD count over the run (e.g.
// `docker stats` sampled to a file, or the process metrics) — flat == healthy.
//
// This is also the scenario to drive a CONFIG HOT-RELOAD under: while it runs, edit the mounted
// scenario TOML (e.g. flip the WAF mode, change a rate) and confirm there is no error blip and no
// dropped connections in the k6 output — exercising the arc-swap reload on the live request path.

import http from "k6/http";
import { check } from "k6";
import { authHeaders, BASE_URL, BENIGN_PATHS, pick } from "./lib.js";

const DURATION = __ENV.K6_SOAK_DURATION || "30m";

export const options = {
  scenarios: {
    soak: {
      executor: "constant-arrival-rate",
      rate: 3000, // well under the knee, so this measures stability not capacity
      timeUnit: "1s",
      duration: DURATION,
      preAllocatedVUs: 300,
      maxVUs: 1000,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.001"],   // essentially zero errors over the whole soak
    http_req_duration: ["p(99)<50", "p(99.9)<150"], // latency must not drift up over time
  },
};

export default function () {
  const res = http.get(`${BASE_URL}${pick(BENIGN_PATHS, __ITER)}`, {
    headers: authHeaders(),
  });
  check(res, { "2xx": (r) => r.status >= 200 && r.status < 300 });
}
