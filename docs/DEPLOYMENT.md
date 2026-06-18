# Deployment & integration strategy

**Decision:** ship the non-k8s deploy story first, k8s sidecar later. The target user is
the vibe-coder without devops, and that user isn't on Kubernetes — they're on a PaaS or a
small VPS. K8s is a v3 concern for the teams/agencies tier.

## Where these users actually deploy (2026)

Deployment in 2026 is effectively a three-box decision: frontend on an edge/CDN host,
backend on a container PaaS, and state on a managed DB. That split dictates where an edge
proxy can even run:

| Category | Typical targets | Can a front proxy run here? | EdgeGuard fit |
| --- | --- | --- | --- |
| Full-stack container PaaS | Railway, Render, Fly.io, Northflank, DO App Platform | Yes — long-running container/process | ✅ Primary v0 target |
| Self-host / VPS | DigitalOcean droplet, Hetzner, Coolify | Yes — native binary or compose | ✅ v0 target |
| All-in-one vibe platforms | Lovable Cloud, Replit, Hostinger Horizons | Sometimes (only if custom Dockerfile/container allowed) | ⚠️ Conditional |
| Static / edge hosts | Vercel, Netlify, Cloudflare Pages | No — serverless/edge, no persistent front process | ❌ Different surface (see below) |

Full-stack PaaS (Railway/Render/Fly/Northflank) is where AI apps with a real backend live
and where a proxy can actually sit in front. Static/edge hosts (Vercel/Netlify/CF Pages)
are great for frontend-only apps but won't run a long-lived proxy process — so they need a
different delivery model, not the binary.

## Core interface patterns

The invariant in every non-k8s mode: **the app binds to an internal port; EdgeGuard
becomes the public listener and forwards to it.** Four ways to wire that:

1. **Co-process entrypoint (default, simplest).** EdgeGuard is the container `ENTRYPOINT`,
   binds the platform-injected `$PORT`, spawns the user's app on `127.0.0.1:<internal>`,
   and proxies to it. One deployable unit, one service to pay for — ideal for a non-devops
   user. Ship a ready Dockerfile template that wraps a Node/Python app
   (see [`../examples/`](../examples)).
2. **Separate public/private service (cleaner separation).** EdgeGuard runs as the public
   service; the app runs as a private/internal service reachable over the platform's
   private network. Two services, better isolation — the path teams graduate to.
3. **Native binary on a VPS.** A systemd unit (or `docker compose` with EdgeGuard as the
   front container); the app listens on localhost. Full feature set, fully owned.
4. **Edge-function build for static hosts (implemented — Phase 5).** For Vercel/Netlify/CF
   Pages, the response-hardening half (headers/CSP/cookies) plus lightweight edge auth ship as
   either *generated platform config* (`edgeguard generate` → a `_headers` file / `vercel.json` /
   edge-middleware snippet) or a **Rust→WASM Cloudflare Worker** (`../worker/`). This is a
   separate product surface, not the proxy binary. (Rate limiting stays proxy-only — it needs
   shared state.)

## Target rollout order

| Phase | Targets | Interface delivered |
| --- | --- | --- |
| v0 | Railway, Render, Fly.io • generic Docker/VPS | Co-process entrypoint + Dockerfile template; native binary + systemd example |
| v1 | Northflank, DO App Platform; separate public/private service mode | Two-service pattern, internal networking docs, one-click templates |
| v2 | Static/edge hosts (Vercel/Netlify/CF Pages) | Config generator + Rust→WASM Worker for the response-hardening + edge-auth subset |
| v3 | Kubernetes | Sidecar container + Helm chart / operator |

## Implications for the build

- **Config from env first.** Read `PORT` (public, platform-injected) and `APP_PORT` /
  `UPSTREAM` for the internal app, so EdgeGuard drops into any PaaS that injects `$PORT`
  with zero edits. The TOML file layers on top for richer policy. *(Implemented.)*
- **Process supervision.** In co-process mode EdgeGuard launches and supervises the child
  app process (restart on crash, forward signals, propagate exit) — a tiny init for the
  container. *(Implemented for Unix; Windows uses a best-effort child kill — see
  [ROADMAP.md](./ROADMAP.md).)*
- **Stack auto-detect (nice-to-have).** A `--wrap "<start command>"` flag plus detection of
  `package.json` / `requirements.txt` lets the template work for most apps without the user
  thinking about ports. *(`--wrap` implemented; auto-detect is future.)*
- **Distribution artifacts:** (1) a single static binary, (2) a base Docker image to
  `FROM`, (3) per-platform deploy templates (Railway/Render/Fly) so "add EdgeGuard" is
  copy-paste.

## Platform notes

- **Railway** — deploy the repo; set `APP_PORT=3000`. Railway injects `$PORT`; EdgeGuard
  binds it.
- **Render** — see [`../examples/render.yaml`](../examples/render.yaml); health check
  `/__edgeguard/health`.
- **Fly.io** — see [`../examples/fly.toml`](../examples/fly.toml).
- **VPS / Coolify** — run the binary under systemd, or `docker compose` with EdgeGuard as
  the front container.

> Health vs readiness: `/__edgeguard/health` is liveness (is EdgeGuard itself up);
> `/__edgeguard/ready` probes the upstream and reports ready only once it's reachable. Point
> a platform's *health* check at the former and its *readiness*/rolling-deploy gate at the
> latter.
>
> Static/edge hosts (Vercel, Netlify, Cloudflare Pages) can't run a long-lived proxy
> process; those are a separate surface — now implemented in Phase 5 as `edgeguard generate`
> (config generation) and the Rust→WASM Worker (`../worker/`), not this binary.
