// Shared helpers for the EdgeGuard k6 scenarios.
//
// All scripts read BASE_URL (the proxy's public port) and API_KEY from the environment, set by
// docker-compose.yml. Keeping the request construction and the realistic-path corpus here means
// every scenario hits the proxy the same way and only the *policy under test* (and the k6
// `options`) differ between scripts.

export const BASE_URL = __ENV.BASE_URL || "http://localhost:8080";
export const API_KEY = __ENV.API_KEY || "sk_loadtest_key";

// A spread of benign, realistic request paths — varied so per-IP/route limiters and the WAF see
// representative traffic rather than one cached path.
export const BENIGN_PATHS = [
  "/",
  "/index.html",
  "/api/v1/users/42/profile?fields=name,email",
  "/api/v1/orders?status=open&page=2&sort=desc",
  "/static/app.js",
  "/search?q=hello%20world&page=1",
  "/health",
];

// Attack-shaped paths the WAF built-ins should catch (used by the waf scenario). Each should be
// blocked (403) in block mode; in report mode they pass (200) but are counted.
export const ATTACK_PATHS = [
  "/items?id=1%20OR%201=1",                              // SQLi
  "/items?id=1%20UNION%20SELECT%20password%20FROM%20users", // SQLi
  "/p?c=%3Cscript%3Ealert(1)%3C%2Fscript%3E",           // XSS
  "/static/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",    // path traversal (encoded)
];

// Headers carrying the API key, for the auth/full scenarios. The baseline/ratelimit/waf
// scenarios run auth=none and can pass `{}`.
export function authHeaders() {
  return { "X-API-Key": API_KEY };
}

// Pick a deterministic-ish element by VU/iteration so load spreads across the corpus.
export function pick(arr, i) {
  return arr[i % arr.length];
}

// Thresholds shared by the "should be fast and clean" scenarios. Individual scripts tighten or
// relax these; a breached threshold makes `k6 run` exit non-zero so CI/run.sh can gate on it.
export const FAST_THRESHOLDS = {
  http_req_failed: ["rate<0.01"],         // <1% transport/5xx errors
  http_req_duration: ["p(99)<50"],        // p99 under 50ms against the local stub upstream
};
