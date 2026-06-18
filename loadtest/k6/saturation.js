// SATURATION scenario: find the knee and confirm graceful degradation past it.
//
// Pushes the offered rate well beyond what one EdgeGuard instance can serve, to locate the
// throughput ceiling and — more importantly — to confirm that PAST the ceiling the proxy
// degrades gracefully (latency rises, excess sheds as 503/timeout) instead of crashing,
// deadlocking, or leaking. Watch RSS/FD in `docker stats` and the request-outcome metric in
// Prometheus alongside this run. Scenario-agnostic: use it on baseline.toml for the raw ceiling
// or full.toml for the realistic one.
//
// Carries the API key so it also works against auth-enabled configs; auth=none ignores it.

import http from "k6/http";
import { authHeaders, BASE_URL, BENIGN_PATHS, pick } from "./lib.js";

export const options = {
  scenarios: {
    push: {
      executor: "ramping-arrival-rate",
      startRate: 2000,
      timeUnit: "1s",
      preAllocatedVUs: 1000,
      maxVUs: 8000,
      stages: [
        { target: 10000, duration: "30s" },
        { target: 20000, duration: "30s" },
        { target: 40000, duration: "30s" },
        { target: 60000, duration: "30s" }, // deliberately past the ceiling
      ],
    },
  },
  // No hard thresholds: the goal is to OBSERVE the degradation curve, not pass/fail. The report
  // (and the Prometheus scrape) tell the story.
};

export default function () {
  const res = http.get(`${BASE_URL}${pick(BENIGN_PATHS, __ITER)}`, {
    headers: authHeaders(),
  });
  // Touch the body so we measure full request completion, not just headers.
  void res.body;
}
