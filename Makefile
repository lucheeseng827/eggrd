# EdgeGuard developer/CI entry points. The load-test harness has its own driver
# (loadtest/run.sh); these targets cover the in-crate checks plus convenient shortcuts.
#
# Usage: make <target>   (run from the crate root, rust_modules/lab/module_52)

.PHONY: help fmt lint test test-all bench loadtest-up loadtest-down whitepaper-check

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  %-18s %s\n", $$1, $$2}'

fmt: ## Check formatting (CI parity)
	cargo fmt --all -- --check

lint: ## Clippy with warnings denied (CI parity)
	cargo clippy --all-targets -- -D warnings

test: ## Unit + integration tests
	cargo test --all-targets

test-all: fmt lint test ## Everything CI runs on the crate

bench: ## Run the criterion micro-benchmarks (auth / waf / response)
	cargo bench

loadtest-up: ## Bring up the load-test stack for the baseline scenario (see loadtest/README.md)
	cd loadtest && EG_SCENARIO=baseline docker compose up -d --build edgeguard upstream redis prometheus

loadtest-down: ## Tear the load-test stack down
	cd loadtest && docker compose down -v

whitepaper-check: ## Sanity: the docs the white paper references exist
	@missing=0; \
	for f in docs/TESTPLAN.md docs/WHITEPAPER.md loadtest/README.md; do \
	  if test -f $$f; then echo "ok   $$f"; else echo "MISSING $$f"; missing=1; fi; \
	done; \
	test $$missing -eq 0
