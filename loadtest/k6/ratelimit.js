// RATE-LIMIT scenario: validate the GCRA limiter under sustained overload.
//
// Works for BOTH limiter backends — run it against ratelimit-local.toml and ratelimit-redis.toml
// and compare. It offers a steady rate well ABOVE the configured cap (5000/sec) from a single
// source IP, so the per-IP limiter should admit ~the cap as 200 and shed the rest as 429. We
// assert the proxy never 5xx's under overload (shedding stays cheap) and that a meaningful share
// is actually shed (the limiter is doing its job, not silently passing everything).
//
// Note: 429 is the CORRECT response here, so we do NOT use http_req_failed (which counts 4xx as
// failures). We track admitted/shed/error rates explicitly.

import http from "k6/http";
import { Rate } from "k6/metrics";
import { BASE_URL, BENIGN_PATHS, pick } from "./lib.js";

const admitted = new Rate("eg_admitted_200");
const shed = new Rate("eg_shed_429");
const errored = new Rate("eg_errored_5xx");

export const options = {
  scenarios: {
    overload: {
      executor: "constant-arrival-rate",
      rate: 10000, // ~2x the 5000/sec cap
      timeUnit: "1s",
      duration: "60s",
      preAllocatedVUs: 500,
      maxVUs: 3000,
    },
  },
  thresholds: {
    // Under overload the limiter must shed cleanly: no server errors, and a real fraction shed.
    eg_errored_5xx: ["rate<0.001"],
    eg_shed_429: ["rate>0.2"],
    "http_req_duration{status:429}": ["p(99)<25"], // rejection is cheap
  },
};

export default function () {
  const path = pick(BENIGN_PATHS, __ITER);
  const res = http.get(`${BASE_URL}${path}`);
  admitted.add(res.status === 200);
  shed.add(res.status === 429);
  errored.add(res.status >= 500);
}
