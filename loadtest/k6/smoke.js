// SMOKE scenario: a short, fixed-rate passthrough run for CI.
//
// Not a capacity test — `baseline.js` finds the knee. This offers a steady, modest rate for a
// short window so a CI runner can read p99 latency and the proxy's memory on every change, and
// notice when either moves. Run it at the proxy and straight at the stub upstream: the
// difference is the proxy's share, which is what to compare across runs on a shared runner.
//
// RATE (req/s, default 300) and DURATION (default "30s") come from the environment.
// No thresholds: the CI job is advisory, and decides what to warn about from the summary.

import http from "k6/http";
import { check } from "k6";
import { BASE_URL, BENIGN_PATHS, pick } from "./lib.js";

const RATE = parseInt(__ENV.RATE || "300", 10);
const DURATION = __ENV.DURATION || "30s";

export const options = {
  scenarios: {
    smoke: {
      executor: "constant-arrival-rate",
      rate: RATE,
      timeUnit: "1s",
      duration: DURATION,
      preAllocatedVUs: 50,
      maxVUs: 200,
    },
  },
  summaryTrendStats: ["avg", "med", "p(90)", "p(99)", "max"],
};

export default function () {
  const path = pick(BENIGN_PATHS, __VU * 1000000 + __ITER);
  const res = http.get(`${BASE_URL}${path}`);
  check(res, { "status is 200": (r) => r.status === 200 });
}
