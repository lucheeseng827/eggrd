# eggrd (EdgeGuard) — developer Makefile.
#
# The published crate is `eggrd`; the binary/library it builds is `edgeguard` (see Cargo.toml).
# Run every target from this directory, the crate root.
#
# Sections: Build · Run/CLI · Quality (CI parity) · Docker · Monitoring compose ·
# Front-door example compose · Load-test compose · API smoke checks · Docs ·
# Release hygiene · Cloudflare Worker · Enterprise/control-plane [PRIVATE] ·
# LLM-bench [PRIVATE] · Housekeeping.
#
# [PRIVATE] targets operate on ee/ and llm-bench/ — internal-only workspaces (see their own
# READMEs) that are never mirrored into the public eggrd crate or repo. Everything else here is
# part of the OSS surface documented in README.md / docs/.
#
# Every *-up / *-down / *-logs target drives Podman or Docker Compose through $(ENGINE), which
# auto-detects `docker` then falls back to `podman`. Override per-invocation, e.g.:
#   make monitor-up ENGINE=podman
#
# Usage: make <target> [VAR=value ...]   (see `make help` for the full list)

SHELL := /usr/bin/env bash

# ── Shared variables (override on the command line) ────────────────────────────────────────────
ENGINE         ?= $(shell command -v docker >/dev/null 2>&1 && echo docker || echo podman)
COMPOSE        := $(ENGINE) compose

BIN            := edgeguard
CONFIG         ?= edgeguard.toml

# `run` / API smoke checks
HOST           ?= localhost
PORT           ?= 8080
ADMIN_PORT     ?= 9090

# `docker-build` / `docker-run`
DOCKER_IMAGE   ?= eggrd
DOCKER_TAG     ?= dev
UPSTREAM       ?= http://host.docker.internal:3000

# `cert`
DAYS           ?= 90
CERT_OUT       ?= ./tls/cert.pem
KEY_OUT        ?= ./tls/key.pem

# `generate`
GEN_TARGET     ?= _headers

# `loadtest-*`
SCENARIO       ?= baseline
SCRIPT         ?= baseline
COMPARE_TARGET ?= edgeguard

# `ossync-check` — MUST be outside this repo checkout (cargo refuses a nested workspace)
STAGE_DIR      ?= /tmp/eggrd-ossync-stage

.DEFAULT_GOAL := help

.PHONY: help \
	build build-release build-ner install \
	run init init-force doctor hash cert generate version \
	fmt fmt-fix lint test test-verbose cli-test integration-test deps test-all bench whitepaper-check \
	docker-build docker-build-multiarch docker-run docker-inspect \
	monitor-up monitor-down monitor-logs \
	example-up example-down example-logs \
	loadtest-up loadtest-down loadtest-run loadtest-compare loadtest-observability \
	api-health api-ready api-metrics api-csp-report \
	docs docs-open config-reference \
	ossync-check ossync-scan \
	worker-build worker-dev worker-deploy \
	ee-run ee-poc-up ee-poc-down ee-demo-up ee-demo-down ee-demo-llm-up ee-demo-llm-down ee-demo-local-up ee-demo-local-down \
	llmbench-preflight-up llmbench-preflight-down \
	clean clean-compose

## === Help ===

help: ## Show this help
	@echo "eggrd (EdgeGuard) — developer Makefile. Run targets from this directory (the crate root)."
	@echo "Container engine: $(ENGINE) (override with ENGINE=podman or ENGINE=docker)."
	@echo "[PRIVATE] targets touch ee/ and llm-bench/ — internal-only workspaces, never part of the published eggrd crate."
	@awk 'BEGIN{FS = ":.*?## "} \
	  /^## === .* ===$$/ {gsub(/^## === | ===$$/,""); printf "\n\033[1m%s\033[0m\n", $$0; next} \
	  /^[a-zA-Z0-9_.-]+:.*?## / {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

## === Build ===

build: ## Build the edgeguard binary (debug)
	cargo build --bin $(BIN)

build-release: ## Build the edgeguard binary (release, optimized)
	cargo build --release --bin $(BIN)

build-ner: ## Build the release binary with the optional ONNX NER edge-DLP feature
	cargo build --release --bin $(BIN) --features ner

install: ## Install the edgeguard binary via `cargo install --path .` (FORCE=1 to overwrite)
	cargo install --path . --bin $(BIN) $(if $(FORCE),--force)

## === Run / CLI ===
# Mirrors every subcommand in src/main.rs. All read CONFIG (default: edgeguard.toml).

run: ## Run edgeguard against CONFIG (serve mode); WRAP="cmd" to co-process an app
	cargo run --bin $(BIN) -- --config $(CONFIG) $(if $(WRAP),--wrap "$(WRAP)")

init: ## Scaffold edgeguard.toml + Dockerfile.edgeguard in the current directory
	cargo run --bin $(BIN) -- init

init-force: ## Re-scaffold, overwriting an existing edgeguard.toml/Dockerfile.edgeguard
	cargo run --bin $(BIN) -- init --force

doctor: ## Validate CONFIG and print advisory warnings (non-zero exit on a hard error)
	cargo run --bin $(BIN) -- doctor --config $(CONFIG)

hash: ## Hash a password from stdin into an argon2id PHC string: echo -n 'pw' | make hash
	cargo run --bin $(BIN) -- --hash

cert: ## Write a self-signed TLS cert+key (HOSTS="a,b" DAYS=90 CERT_OUT=.. KEY_OUT=.. FORCE=1)
	cargo run --bin $(BIN) -- cert $(if $(HOSTS),--host "$(HOSTS)") --days $(DAYS) --cert-out $(CERT_OUT) --key-out $(KEY_OUT) $(if $(FORCE),--force)

generate: ## Emit static-host/edge header config (GEN_TARGET=_headers|vercel|vercel-middleware|netlify-edge, OUT=path)
	cargo run --bin $(BIN) -- generate --config $(CONFIG) --target $(GEN_TARGET) $(if $(OUT),--out $(OUT))

version: ## Print the edgeguard binary version
	cargo run --bin $(BIN) -- --version

## === Quality (CI parity) ===

fmt: ## Check formatting (CI parity)
	cargo fmt --all -- --check

fmt-fix: ## Auto-format the workspace
	cargo fmt --all

lint: ## Clippy with warnings denied (CI parity)
	cargo clippy --all-targets -- -D warnings

test: ## Unit + integration tests
	cargo test --all-targets

test-verbose: ## Unit + integration tests, showing stdout/stderr
	cargo test --all-targets -- --nocapture

cli-test: ## CLI surface tests only (tests/cli.rs — runs the real binary)
	cargo test --test cli

integration-test: ## Integration tests only (tests/integration.rs)
	cargo test --test integration

deps: ## Fail if the aws-lc crypto stack re-enters the graph (ring must be the only provider)
	bash scripts/check-crypto-provider.sh

test-all: fmt lint test deps ## Everything CI runs on the crate

bench: ## Run the criterion micro-benchmarks (auth / waf / response)
	cargo bench

whitepaper-check: ## Sanity: the docs the white paper references exist
	@missing=0; \
	for f in docs/TESTPLAN.md docs/WHITEPAPER.md loadtest/README.md; do \
	  if test -f $$f; then echo "ok   $$f"; else echo "MISSING $$f"; missing=1; fi; \
	done; \
	test $$missing -eq 0

## === Docker (single image) ===

docker-build: ## Build the release image (static musl on distroless); DOCKER_IMAGE/DOCKER_TAG override the tag (default eggrd:dev)
	$(ENGINE) build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

docker-build-multiarch: ## Buildx multi-arch build (amd64+arm64), Docker only; PUSH=1 to push, else --load
	docker buildx build --platform linux/amd64,linux/arm64 -t $(DOCKER_IMAGE):$(DOCKER_TAG) $(if $(PUSH),--push,--load) .

docker-run: ## Run the built image standalone; UPSTREAM/PORT override the defaults (host.docker.internal:3000 / 8080)
	$(ENGINE) run --rm -p $(PORT):8080 --add-host host.docker.internal:host-gateway -e UPSTREAM=$(UPSTREAM) $(DOCKER_IMAGE):$(DOCKER_TAG)

docker-inspect: ## Copy the binary out of the image for inspection (it's distroless: no shell to exec into)
	$(ENGINE) create --name eggrd-inspect-tmp $(DOCKER_IMAGE):$(DOCKER_TAG)
	$(ENGINE) cp eggrd-inspect-tmp:/usr/local/bin/edgeguard ./edgeguard.extracted
	$(ENGINE) rm eggrd-inspect-tmp
	@echo "extracted to ./edgeguard.extracted"

## === Monitoring compose (Prometheus + Grafana demo stack) ===

monitor-up: ## Bring up the self-contained Prometheus+Grafana demo stack (monitoring/compose.yaml)
	$(COMPOSE) -f monitoring/compose.yaml up -d
	@echo "Grafana:    http://localhost:3000  (anonymous admin)"
	@echo "Prometheus: http://localhost:9091"
	@echo "EdgeGuard:  http://localhost:8080"

monitor-down: ## Tear down the monitoring stack (drops volumes)
	$(COMPOSE) -f monitoring/compose.yaml down -v

monitor-logs: ## Follow logs from the monitoring stack
	$(COMPOSE) -f monitoring/compose.yaml logs -f

## === Front-door example compose ===
# examples/docker-compose.yml is a TEMPLATE for your own app repo: it needs its own
# examples/edgeguard.toml and examples/secrets/jwt_secret.txt before it will start.

example-up: ## Bring up the front-door example (customize examples/edgeguard.toml + secrets first)
	@test -f examples/edgeguard.toml || { echo "missing examples/edgeguard.toml — start from the crate's annotated config: cp edgeguard.toml examples/edgeguard.toml (then set a real auth.users hash)"; exit 1; }
	@test -f examples/secrets/jwt_secret.txt || { echo "missing examples/secrets/jwt_secret.txt — create one: mkdir -p examples/secrets && openssl rand -hex 32 > examples/secrets/jwt_secret.txt"; exit 1; }
	$(COMPOSE) -f examples/docker-compose.yml up -d

example-down: ## Tear down the front-door example
	$(COMPOSE) -f examples/docker-compose.yml down -v

example-logs: ## Follow logs from the front-door example
	$(COMPOSE) -f examples/docker-compose.yml logs -f

## === Load-test compose ===
# loadtest-run/-compare shell out to loadtest's own scripts. run.sh always drives plain `docker
# compose` (not ENGINE-aware); run-compare.sh honors COMPOSE_BIN, wired to $(ENGINE) below.

loadtest-up: ## Bring up the load-test stack (SCENARIO=baseline|auth-apikey|ratelimit-local|ratelimit-redis|waf-block|full)
	cd loadtest && EG_SCENARIO=$(SCENARIO) $(COMPOSE) up -d --build edgeguard upstream redis prometheus

loadtest-down: ## Tear down the load-test stack
	cd loadtest && $(COMPOSE) down -v

loadtest-run: ## Run one k6 scenario end to end (SCENARIO=baseline SCRIPT=baseline DIRECT=1); writes loadtest/results/
	cd loadtest && bash run.sh $(SCENARIO) $(SCRIPT) $(if $(DIRECT),--direct)

loadtest-compare: ## Head-to-head vs a competitor proxy (COMPARE_TARGET=edgeguard|nginx|haproxy|caddy|traefik|envoy SCRIPT=baseline)
	cd loadtest && COMPOSE_BIN=$(ENGINE) bash run-compare.sh $(COMPARE_TARGET) $(SCRIPT)

loadtest-observability: ## Start Grafana against an already-running load-test stack
	cd loadtest && $(COMPOSE) --profile observability up -d grafana

## === API smoke checks (against a running instance) ===
# The reserved /__edgeguard/* namespace — see docs/API.md. Exempt from auth/rate-limit/WAF.

api-health: ## GET /__edgeguard/health on HOST:PORT — liveness, always 200
	curl -fsS -i http://$(HOST):$(PORT)/__edgeguard/health

api-ready: ## GET /__edgeguard/ready — 200 only once the upstream is reachable (ADMIN=1 for ADMIN_PORT)
	curl -fsS -i http://$(HOST):$(if $(ADMIN),$(ADMIN_PORT),$(PORT))/__edgeguard/ready

api-metrics: ## GET /__edgeguard/metrics — Prometheus exposition (ADMIN=1 for ADMIN_PORT)
	curl -fsS http://$(HOST):$(if $(ADMIN),$(ADMIN_PORT),$(PORT))/__edgeguard/metrics

api-csp-report: ## POST a sample CSP violation report to /__edgeguard/csp-report
	curl -fsS -i -X POST http://$(HOST):$(PORT)/__edgeguard/csp-report \
	  -H 'Content-Type: application/csp-report' \
	  -d '{"csp-report":{"document-uri":"https://example.com","violated-directive":"script-src"}}'

## === Docs ===

docs: ## Generate rustdoc for the library
	cargo doc --no-deps

docs-open: ## Generate and open rustdoc in a browser
	cargo doc --no-deps --open

config-reference: ## Regenerate site/docs/config.html from the doc comments in src/config.rs
	python3 scripts/build-config-reference.py

## === Release hygiene (OSS mirror) ===

ossync-check: ## Stage the public OSS cut per .ossync.yaml and scan it (STAGE_DIR must be OUTSIDE this repo)
	bash scripts/ossync-check.sh $(STAGE_DIR)

ossync-scan: ## Stage a fresh cut internally and run the forbidden-marker/forbidden-path scan
	bash scripts/ossync-scan.sh

## === Cloudflare Worker (edge build) ===
# Needs `cargo install worker-build` and `npm install -g wrangler` once; see worker/README.md.

worker-build: ## Compile the Worker to wasm (worker-build --release)
	cd worker && worker-build --release

worker-dev: ## Run the Worker locally against its configured origin (wrangler dev)
	cd worker && wrangler dev

worker-deploy: ## Deploy the Worker to Cloudflare (wrangler deploy; builds first)
	cd worker && wrangler deploy

## === Enterprise / control plane [PRIVATE — ee/, never mirrored] ===
# ee/ is its own Cargo workspace with its own Makefile (build, test, db-migrate, docker, the
# operator, the dashboard, Helm, Terraform — `cd ee && make help` for the full set). The targets
# below just delegate the handful of commands useful from this directory; they are not a copy.

ee-run: ## [PRIVATE] Run the control plane in-memory on :8088 (needs EDGEGUARD_CP_OPERATOR_TOKEN)
	$(MAKE) -C ee run

ee-poc-up: ## [PRIVATE] One-command POC: control plane + dashboard (ee/compose.yaml)
	$(MAKE) -C ee poc-up ENGINE=$(ENGINE)

ee-poc-down: ## [PRIVATE] Tear down the control-plane POC
	$(MAKE) -C ee poc-down ENGINE=$(ENGINE)

ee-demo-up: ## [PRIVATE] Full video-demo stack: certs -> compose -> bootstrap -> seed (own-CA TLS)
	$(MAKE) -C ee demo-up ENGINE=$(ENGINE)

ee-demo-down: ## [PRIVATE] Tear down the video-demo stack
	$(MAKE) -C ee demo-down ENGINE=$(ENGINE)

ee-demo-llm-up: ## [PRIVATE] LLM-gateway demo variant (mock OpenAI-compatible upstream + [llm] metering)
	$(MAKE) -C ee demo-llm-up ENGINE=$(ENGINE)

ee-demo-llm-down: ## [PRIVATE] Tear down the LLM-gateway demo variant
	$(MAKE) -C ee demo-llm-down ENGINE=$(ENGINE)

ee-demo-local-up: ## [PRIVATE] Built-from-source + Postgres demo variant (for unreleased changes)
	$(MAKE) -C ee demo-local-up ENGINE=$(ENGINE)

ee-demo-local-down: ## [PRIVATE] Tear down the built-from-source + Postgres demo variant
	$(MAKE) -C ee demo-local-down ENGINE=$(ENGINE)

## === LLM-bench [PRIVATE — never mirrored] ===

llmbench-preflight-up: ## [PRIVATE] Local pre-flight rig: mock backend + eggrd + nginx (no GPU needed)
	$(COMPOSE) -f llm-bench/compose.preflight.yaml up --build -d

llmbench-preflight-down: ## [PRIVATE] Tear down the pre-flight rig
	$(COMPOSE) -f llm-bench/compose.preflight.yaml down -v

## === Housekeeping ===

clean: ## Remove Rust build artifacts (cargo clean)
	cargo clean

clean-compose: ## Best-effort teardown of every compose stack this Makefile (and ee/'s) can bring up
	-$(COMPOSE) -f monitoring/compose.yaml down -v
	-$(COMPOSE) -f examples/docker-compose.yml down -v
	-cd loadtest && $(COMPOSE) down -v
	-$(COMPOSE) -f llm-bench/compose.preflight.yaml down -v
	-$(MAKE) -C ee poc-down ENGINE=$(ENGINE)
	-$(MAKE) -C ee demo-down ENGINE=$(ENGINE)
	-$(MAKE) -C ee demo-llm-down ENGINE=$(ENGINE)
	-$(MAKE) -C ee demo-local-down ENGINE=$(ENGINE)
