# Makefile — MAINTAINERS ONLY
#
# Users do NOT need Make. Install via:
#   cargo install schema-risk           ← Rust users
#   curl -fsSL .../install.sh | bash    ← everyone else

.PHONY: build test lint fmt check release clean smoke demo

# ── Development ──────────────────────────────────────────────────────────────

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

test-verbose:
	cargo test -- --nocapture

lint:
	cargo clippy -- -D warnings

fmt:
	cargo fmt --check

fmt-fix:
	cargo fmt

# ── Smoke tests (requires the binary in PATH or target/debug) ────────────────

BIN := ./target/debug/schema-risk

smoke: build
	@echo "=== safe.sql (expect exit 0) ==="
	$(BIN) analyze examples/safe.sql
	@echo "\n=== risky.sql (expect exit 1) ==="
	-$(BIN) analyze examples/risky.sql
	@echo "\n=== critical.sql --fail-on critical (expect exit 2) ==="
	-$(BIN) analyze examples/critical.sql --fail-on critical
	@echo "\n=== guard --dry-run critical.sql (expect exit 2) ==="
	-$(BIN) guard --dry-run examples/critical.sql
	@echo "\n=== fix risky.sql --dry-run (expect diff) ==="
	$(BIN) fix examples/risky.sql --dry-run
	@echo "\n=== ci-report complex.sql ==="
	$(BIN) ci-report examples/complex.sql --format github-comment
	@echo "\n=== init --force ==="
	$(BIN) init --force && rm -f schema-risk.yml
	@echo "\n✅ Smoke tests passed"

demo: build
	@echo "╔═══════════════════════════════════════╗"
	@echo "║       SchemaRisk Live Demo             ║"
	@echo "╚═══════════════════════════════════════╝"
	$(BIN) analyze examples/critical.sql --verbose

# ── Quality gate (run before pushing / tagging) ──────────────────────────────

check: fmt lint test smoke
	@echo "✅ All checks passed"

# ── Cross-compile release artifacts for GitHub Actions ───────────────────────

dist:
	cargo build --release --target x86_64-unknown-linux-musl
	cargo build --release --target x86_64-apple-darwin
	cargo build --release --target aarch64-apple-darwin
	cargo build --release --target x86_64-pc-windows-gnu

clean:
	cargo clean

# ── crates.io publish ────────────────────────────────────────────────────────

publish: check
	cargo publish
