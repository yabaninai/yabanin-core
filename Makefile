.PHONY: all lint-design docs-verify docs-lang docs-mdx lint-helm build gateway loggerd admin migrate unified audit-dist release-artifacts run-gateway run-loggerd run-admin run-mcp run-subscription-bridge dev-opencode opencode-remote-wire test test-short test-integration test-subscription-bridge lint analyze analyze-fast analyze-security analyze-tests install-analysis-tools security-tools-install security-db-update security-db-status security-start security-status security-stop security-scan security-runtime security-release quality-fast quality-static quality-security quality-security-code quality-security-runtime quality-security-release quality-tests quality-web quality-sdk quality-full quality-changed docker-build-all docker-up docker-down demo demo-down docker-clean migrate-up migrate-region tidy measure-savings train-classifier yb evaluate-routing evaluate-guards policies-reconcile policies-reconcile-apply spend-reconcile deploy release helm-install helm-upgrade helm-rollback profile backup licenses-report help clean bench bench-cache bench-cache-live pricing-refresh pricing-pack pricing-verify load-test-chat load-test-cache load-test-mixed helm-lint build-migrate licenses-image

MODULE := github.com/reireirei/yabanin
GO_SCOPE := python3 scripts/quality/go_scope.py

help: ## Show targets with descriptions
	@awk 'BEGIN { FS = ":.*## "; printf "usage: make <target>\n" } /^[a-zA-Z_0-9 %-]+:.*## / { printf "  %-32s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

all: build ## Build all service binaries (gateway, loggerd, admin, migrate, unified)

# --- Build ---
build: gateway loggerd admin migrate unified ## Build all service binaries

# VendorPublicKey can be injected at build time via YABANIN_LICENSE_VENDOR_PUBKEY (base64 32-byte key).
LDFLAGS := $(or $(YABANIN_LDFLAGS),)

# Build marker (BMARK1, incident 2026-11-01): stamp the gateway build identity
# into pkg/gateway.buildVersion, surfaced on GET /healthz (the "build" field +
# X-Yabanin-Build header) and the "gateway starting" log line. Commit-only by
# design: deterministic for a given source tree, so reproducible-build
# properties hold (no timestamps; an fp-schema tag joins once the fingerprint
# script emits a build-time stamp). Unstamped/tarball builds report "dev".
# Override with YABANIN_BUILD_VERSION for explicit release stamping.
BUILD_VERSION ?= $(or $(YABANIN_BUILD_VERSION),$(shell git rev-parse --short HEAD 2>/dev/null || echo dev))
GATEWAY_MARKER_LDFLAGS := -X $(MODULE)/pkg/gateway.buildVersion=$(BUILD_VERSION)

gateway: ## Build yabanin-gateway
	go build -ldflags "$(LDFLAGS) $(GATEWAY_MARKER_LDFLAGS)" -o yabanin-gateway ./services/gateway/cmd/...

loggerd: ## Build yabanin-loggerd
	go build -ldflags "$(LDFLAGS)" -o yabanin-loggerd ./services/loggerd/cmd/...

admin: ## Build yabanin-admin
	go build -ldflags "$(LDFLAGS)" -o yabanin-admin ./services/admin/cmd/...

migrate: ## Build yabanin-migrate
	go build -ldflags "$(LDFLAGS)" -o yabanin-migrate ./cmd/yabanin-migrate/...

unified: ## Build the yabanin multi-command binary
	go build -ldflags "$(LDFLAGS) $(GATEWAY_MARKER_LDFLAGS)" -o yabanin ./cmd/yabanin/...

# The `yb` CLI (pkg/trcli) — keys/spend/doctor/audit/evaluate subcommands
# (BR-02: renamed from `tr`; the project is Yabanin).
yb: ## Build the yb CLI (pkg/trcli)
	go build -ldflags "$(LDFLAGS)" -o yb ./cmd/yb

# --- Release binaries for the offline analyzer (yb audit) ---
# Body lives in scripts/release/audit-dist.sh; AUDIT_DIST_PLATFORMS is the knob.
# dist/ is gitignored; the binaries are an artifact, not source.
AUDIT_DIST_PLATFORMS ?= darwin/arm64 darwin/amd64 linux/amd64 linux/arm64
audit-dist: ## Cross-compile the yb audit binary for release platforms into dist/ (+ SHA256SUMS)
	@AUDIT_DIST_PLATFORMS="$(AUDIT_DIST_PLATFORMS)" bash scripts/release/audit-dist.sh

# --- Astra design gate (ASTR-01) ---
# Forbids hardcoded #hex / rgb() color literals in web/dashboard/src outside
# the canonical tokens (design/astra-tokens.css). Pre-gate occurrences are
# pinned in design/lint-design-baseline.txt and retire screen-by-screen in the
# ASTR-12x migrations.
# restore post-beta: docs_freshness.py (needs docs/strategy/capability-evidence.md)
# and scripts/quality/registry.py (needs docs/plans/tasks.yaml) are disabled —
# the registries behind them were deleted in the beta cleanup (ba9ba9a).
# Re-add both lines below when the registries come back.
docs-verify: ## Verify docs links (freshness/plan-registry checks disabled, restore post-beta)
	python3 scripts/docs_verify.py

docs-lang: ## Docs language gate: no Cyrillic in the public docs (allowlist: scripts/docs_lang_allowlist.txt)
	python3 scripts/docs_lang_check.py

docs-mdx: ## Docs MDX parse sweep: micromark-faithful parse hazards in docs/** (allowlist: scripts/quality/mdx_sweep_allowlist.txt)
	python3 scripts/quality/mdx_parse_sweep.py

lint-helm: ## Lint Helm charts (scripts/lint_helm.sh)
	bash scripts/lint_helm.sh

lint-design: ## Astra design gate: no hardcoded colors outside tokens
	@bash design/lint-design.sh

tidy: ## go mod tidy
	go mod tidy

# --- S08: release artifacts (supply-chain safety) ---
# Body lives in scripts/release/release-artifacts.sh; RELEASE_DIR is the only knob.
RELEASE_DIR ?= dist/release

release-artifacts: ## Reproducible release binaries + SHA256SUMS + SBOM (+ cosign when COSIGN_KEY) into $(RELEASE_DIR)
	@RELEASE_DIR="$(RELEASE_DIR)" bash scripts/release/release-artifacts.sh

release: release-artifacts ## Alias for release-artifacts

# --- Backup (B1: local git bundle, no remote) ---
backup: ## Local git bundle backup (no remote)
	@bash scripts/backup-bundle.sh

# --- Test ---
test: ## Go tests (race, -short) via the quality scope
	$(GO_SCOPE) go test -race -count=1 -short

# Fast deterministic feedback for humans, agents and CI. The full race/shuffle
# suite remains in analyze-tests because it is intentionally more expensive.
test-short: ## Fast Go tests (no race)
	$(GO_SCOPE) go test -count=1 -short

test-integration: ## Gateway integration tests (needs Docker)
	go test -race -count=1 -tags=integration ./services/gateway/integration/...

test-subscription-bridge: ## subscription-bridge contract tests (node)
	node --test --experimental-strip-types services/subscription-bridge/src/contract.test.ts services/subscription-bridge/src/listen.test.ts services/subscription-bridge/src/runners.test.ts

bench: ## Go benchmarks
	go test -bench=./... -benchmem -run=^$ ./...

bench-cache: ## Cache benchmarks (exact + semantic + embed)
	@echo "=== Exact cache benchmarks ==="
	go test -bench=BenchmarkExactCache -benchmem -benchtime=3s ./pkg/cache/...
	@echo "=== Semantic cache benchmarks ==="
	go test -bench=BenchmarkSemanticNormalize -benchmem -benchtime=3s ./pkg/cache/...
	go test -bench=BenchmarkCosineDistance -benchmem -benchtime=3s ./pkg/cache/...
	@echo "=== Embed benchmarks (mock) ==="
	go test -bench=BenchmarkNoopClient -benchmem -benchtime=3s ./pkg/embeddings/...
	@echo "=== End-to-end gateway benchmarks ==="
	go test -bench=BenchmarkNormalizeMessagesJSON_HotPath -benchmem -benchtime=3s ./pkg/gateway/...

bench-cache-live: ## Live embed benchmarks (requires bge-embedder running)
	@echo "=== Live embed benchmarks (requires bge-embedder running) ==="
	go test -tags=livebench -bench=. -benchmem -benchtime=3s ./pkg/embeddings/...

# --- Lint ---
GO_BIN := $(shell go env GOPATH)/bin
# Coverage instrumentation differs between Go toolchain versions (go1.27
# vs go1.26: per-package ~2-6pp lower, merged totals higher on identical
# code). Pin coverage-measuring runs to the module's declared version so
# local evidence matches CI
# (GO_VERSION 1.27.x) and scripts/quality/coverage-baseline.json stays
# comparable. The pin auto-tracks go.mod; re-baseline deliberately on bump.
MODULE_GO_VERSION := $(shell awk '/^go /{print "go" $$2; exit}' go.mod)
GOLANGCI_BIN := $(GO_BIN)/golangci-lint
GOVULNCHECK_BIN := $(GO_BIN)/govulncheck
GOLANGCI_VERSION := v2.14.0
GOVULNCHECK_VERSION := v1.6.0

install-analysis-tools: ## Install pinned golangci-lint and govulncheck
	@if ! $(GOLANGCI_BIN) version 2>/dev/null | grep -q "2.14.0"; then \
		echo "Installing golangci-lint $(GOLANGCI_VERSION)..."; \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION); \
	fi
	@if ! $(GOVULNCHECK_BIN) -version 2>/dev/null | grep -q "v1.6.0"; then \
		echo "Installing govulncheck $(GOVULNCHECK_VERSION)..."; \
		go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION); \
	fi

lint: install-analysis-tools ## Full lint: format + vet + golangci-lint
	$(GO_SCOPE) format
	$(GO_SCOPE) go vet
	$(GO_SCOPE) $(GOLANGCI_BIN) run --timeout=5m

# Quick feedback loop after editing Go files.
analyze-fast: install-analysis-tools ## Quick loop: format + vet + golangci-lint --fast-only
	$(GO_SCOPE) format
	$(GO_SCOPE) go vet
	$(GO_SCOPE) $(GOLANGCI_BIN) run --fast-only --timeout=3m

# Dependency and reachable-code vulnerability analysis.
analyze-security: install-analysis-tools ## go mod verify + govulncheck
	go mod verify
	python3 scripts/security/local_security.py db-status
	$(GO_SCOPE) $(GOVULNCHECK_BIN) -db "file://$(YABANIN_SECURITY_CACHE)/govuln"

TRIVY_VERSION := 0.75.0
GITLEAKS_VERSION := 8.30.1
SECURITY_CACHE ?= $(HOME)/.cache/yabanin-security
YABANIN_SECURITY_CACHE ?= $(SECURITY_CACHE)
export YABANIN_SECURITY_CACHE

security-tools-install: ## Install pinned local Trivy and Gitleaks scanners
	python3 scripts/security/install_scanners.py --bin-dir "$(GO_BIN)"

security-db-update: ## Update local Go and Trivy vulnerability databases
	TRIVY="$(GO_BIN)/trivy" python3 scripts/security/local_security.py db-update

security-db-status: ## Check local vulnerability database freshness
	python3 scripts/security/local_security.py db-status --go-only

security-start: ## Watch the current branch and scan its latest committed SHA in background
	python3 scripts/security/security_worker.py start

security-status: ## Show local security worker status and latest result
	python3 scripts/security/security_worker.py status

security-stop: ## Stop the local background security worker
	python3 scripts/security/security_worker.py stop

security-scan: ## Scan a committed SHA in an isolated worktree
	python3 scripts/security/security_worker.py scan --head "$(or $(SECURITY_HEAD),HEAD)" $(if $(SECURITY_BASE),--base "$(SECURITY_BASE)")

security-runtime: ## Run Docker-backed security scenarios for a committed SHA
	python3 scripts/security/security_worker.py runtime --head "$(or $(SECURITY_HEAD),HEAD)"

security-release: ## Run release gates against a locally built image
	@test -n "$(SECURITY_IMAGE)" || (echo "SECURITY_IMAGE must name a locally built image" >&2; exit 2)
	python3 scripts/security/security_worker.py release --head "$(or $(SECURITY_HEAD),HEAD)" --image "$(SECURITY_IMAGE)"

# License audit inventory (NOT a distribution attribution bundle).
# Use the separate --release check before shipping; see standards/license-compliance.md.
licenses-report: ## Third-party license inventory into artifacts/licenses
	python3 scripts/quality/license_check.py --report artifacts/licenses/inventory.txt --json-report artifacts/licenses/audit.json

# R002-D1 (2026-10-12): the shipped Python surface is the Dockerfile-built
# classifier image, inventoried from the built image and bound to its env
# label via --python-env (constraints file: deploy/python-constraints.txt).
licenses-image: ## License inventory of the classifier image env (requires built deploy-classifier:latest)
	mkdir -p artifacts/licenses
	docker run --rm --entrypoint python deploy-classifier:latest -m pip inspect > artifacts/licenses/pip-inspect-classifier-image.json
	python3 scripts/quality/license_check.py --report artifacts/licenses/inventory.txt --json-report artifacts/licenses/audit.json --python-env classifier-image=artifacts/licenses/pip-inspect-classifier-image.json

# Dynamic correctness checks that complement static analysis.
COVERAGE_FILE ?= coverage.out
analyze-tests: ## Full test suite: race + shuffle + coverage profile
	GOTOOLCHAIN=$(MODULE_GO_VERSION) $(GO_SCOPE) go test -json -race -shuffle=on -count=1 -coverprofile="$(COVERAGE_FILE)"
	go tool cover -func="$(COVERAGE_FILE)" | awk '/^total:/ { print }'

# EV1: routing regression suite. Classifies the golden prompt set with the
# in-process rule-tier classifier and checks it against the committed snapshot
# baseline (any class mismatch fails). No network/DB.
evaluate-routing: ## EV1: routing regression vs golden baseline (eval datasets not in public export)
	@echo "evaluate-routing: eval datasets are not part of the public export"; exit 77

# EV2: guard-hook detection eval. Runs the deterministic detectors over the
# labeled corpus and gates on precision/recall. No network/DB.
evaluate-guards: ## EV2: guard detectors precision/recall gate (eval datasets not in public export)
	@echo "evaluate-guards: eval datasets are not part of the public export"; exit 77

# OP-10 config-as-code: git declarations (deploy/policies) -> policystore.
# Dry-run prints the human-readable plan (add/update/activate/enable/
# disable/attachments/delete + DRIFT report) and writes nothing; -apply
# converges the database onto git (git wins + drift report). Reads
# YABANIN_PG_URI (dev default below; needs a reachable Postgres).
YABANIN_POLICIES_PG_URI ?= $(or $(YABANIN_PG_URI),postgres://yabanin:yabanin@localhost/yabanin?sslmode=disable)

policies-reconcile: yb ## OP-10: plan git policy declarations -> policystore (dry-run)
	./yb policies reconcile --pg-uri "$(YABANIN_POLICIES_PG_URI)" --dir deploy/policies

policies-reconcile-apply: yb ## OP-10: apply the reconcile plan (git wins; add --prune via YABANIN_POLICIES_FLAGS)
	./yb policies reconcile --pg-uri "$(YABANIN_POLICIES_PG_URI)" --dir deploy/policies --apply $(YABANIN_POLICIES_FLAGS)

# OP-17: compare a provider invoice CSV with captured request_logs spend.
# RECONCILE_ORG (uuid) and YABANIN_PG_URI are required; see the command help
# for the CSV format. Example:
#   make spend-reconcile RECONCILE_ORG=<uuid> RECONCILE_CSV=invoice.csv RECONCILE_ARGS="--fail-over 20"
RECONCILE_ORG ?=
RECONCILE_CSV ?= scripts/pricing/fixtures/invoice_openai_2026-10.csv
RECONCILE_ARGS ?=
spend-reconcile: yb ## OP-17: invoice vs request_logs spend capture-rate report
	test -n "$(RECONCILE_ORG)"
	./yb spend-reconcile --pg-uri "$(YABANIN_PG_URI)" --org "$(RECONCILE_ORG)" \
		--provider openai --period $$(date -u +%Y-%m) --csv "$(RECONCILE_CSV)" $(RECONCILE_ARGS)

# Full local quality gate used before completing a task.
analyze: lint analyze-security analyze-tests ## lint + analyze-security + analyze-tests

# --- Tool-agnostic quality gates ---
# These are the stable public interface for local development, coding agents
# and any future CI provider. scripts/quality/run.sh adds per-gate logs and a
# machine-readable manifest; the underlying targets remain directly usable.
QUALITY_BASE ?=
QUALITY_EXECUTE ?= 0
# NEXT-14 concurrent lanes: light gates run up to QUALITY_JOBS at once;
# heavy Go toolchain gates never overlap. 1 = sequential reference.
QUALITY_JOBS ?= 1
SDK_PYTHON ?= python3
export QUALITY_BASE QUALITY_EXECUTE

.PHONY: quality quality-help quality-eval quality-integration quality-self quality-prune quality-plan _quality-plan quality-preflight
quality: quality-changed ## Quality gate inferred from the working-tree diff

quality-help: ## Show scripts/quality quality.py help
	@python3 scripts/quality/quality.py run --help

# Battery-dispatch preflight: internal fleet tooling (bound to the private
# delivery-program registry), not part of the public export.
QUALITY_PREFLIGHT_ARGS ?=
quality-preflight: ## Battery-dispatch preflight (not in public export)
	@echo "quality-preflight: fleet battery preflight is not part of the public export"; exit 77

# Prune old artifacts/quality runs. The private-lane pruning helper is not
# part of the public export; remove artifacts/quality/<run-id> manually.
QUALITY_PRUNE_ARGS ?=
quality-prune: ## Prune old artifacts/quality runs (helper not in public export)
	@echo "quality-prune: pruning helper is not part of the public export; remove artifacts/quality/<run-id> manually"; exit 77

quality-fast quality-static quality-security quality-security-code quality-security-runtime quality-security-release quality-tests quality-web quality-sdk quality-full quality-eval quality-integration quality-self quality-licenses quality-plan: ## Quality gate profile via scripts/quality (see make quality-help)
	@python3 scripts/quality/quality.py run $(patsubst quality-%,%,$@) --jobs "$(QUALITY_JOBS)"

.PHONY: _quality-self _quality-fast _quality-static _quality-security _quality-tests _quality-dashboard _quality-site _quality-design _quality-browser _quality-node-sdk _quality-python-sdk _quality-bridge _quality-routing _quality-guards _quality-integration _quality-docs _quality-go-sdk _quality-nested-go _quality-int-modules _quality-secrets _quality-commit-secrets _quality-history-secrets _quality-image-scan _quality-deps _quality-licenses _quality-policy _quality-package _quality-alerts _quality-dr _quality-claims _quality-package
_quality-self:
	bash -n scripts/quality/run.sh scripts/quality/changed.sh scripts/ci/run-with-report.sh scripts/security/govulncheck-classify.sh
	@echo "public export: private harness checks are not part of the public tree (export-gate syntax check, commentlint, TP-11 verifier, quality self-tests)"

_quality-fast:
	$(GO_SCOPE) go build
	$(MAKE) analyze-fast
	$(MAKE) test-short

_quality-static:
	$(MAKE) analyze-fast
	$(MAKE) lint
	bash scripts/lint_helm.sh

_quality-security:
	$(MAKE) analyze-security

# NEXT-16 local security leaves: secrets (working diff; history is an
# explicit separate mode), dependency audit, container/config policy.
# Scanner error exits 2 and is NEVER a pass; findings need live exceptions
# (owner/reason/expiry) in scripts/quality/security-exceptions.yaml.
_quality-secrets:
	python3 scripts/quality/secret_scan.py diff

_quality-commit-secrets:
	@if [ -n "$${SECURITY_BASE:-}" ]; then \
		$(GO_BIN)/gitleaks version >/dev/null && \
		GITLEAKS="$(GO_BIN)/gitleaks" python3 scripts/security/secret_audit.py range --base "$${SECURITY_BASE}" --head "$${SECURITY_HEAD:-HEAD}"; \
	else \
		$(GO_BIN)/gitleaks version >/dev/null && \
		GITLEAKS="$(GO_BIN)/gitleaks" python3 scripts/security/secret_audit.py history; \
	fi

_quality-history-secrets:
	GITLEAKS="$(GO_BIN)/gitleaks" python3 scripts/security/secret_audit.py history

_quality-image-scan:
	TRIVY="$(GO_BIN)/trivy" python3 scripts/security/image_audit.py

_quality-deps:
	python3 scripts/quality/dep_audit.py --skip-root

# License compliance leaf: permissive-only policy for third-party
# dependencies (Go modules via the local module cache + npm lockfiles).
# Copyleft/source-available EULAs and unrecognized texts are findings;
# scanner error exits 2 and is NEVER a pass, mirroring deps/secrets.
_quality-licenses:
	python3 scripts/quality/license_check.py

_quality-policy:
	python3 scripts/quality/container_policy.py

# NEXT-24: packaging verification — image build (no push), non-root,
# subcommand matrix, live healthz, SBOM-lite inventory. Docker absent =
# explicit skip (77), never a pass.
_quality-package:
	bash scripts/quality/package_verify.sh

# NEXT-22: alert hygiene — expr metrics declared, runbook anchors exist,
# SLO surface (latency/error/queue) present.
_quality-alerts:
	python3 scripts/quality/alert_check.py

# NEXT-01A: claims registry structural check.
# Re-enabled 2026-10-24 (config-level only; the checker script is untouched):
# the registry (docs/strategy/positioning/claims.md) was restored with a
# fresh inventory of the current public claims (README/docs vs reality);
# structural violations fail the gate. If the registry file is ever absent,
# the checker fails the gate (exit 2) — a deleted registry is a red gate,
# never a silent pass.
_quality-claims:
	@echo "quality-claims: the claims registry is internal and not part of the public export"; exit 77

# NEXT-23: recurring DR/upgrade drill on disposable infrastructure
# (up→down→up cycle test + pg_dump/pg_restore parity).
_quality-dr:
	bash scripts/quality/dr_drill.sh

_quality-tests:
	$(MAKE) analyze-tests

# The build wipes the dir; re-stamp the NEXT-06 source fingerprint so a browser
# gate later in the same run verifies the build we just produced.
_quality-dashboard:
	npm --prefix web/dashboard run lint
	npm --prefix web/dashboard run test
	npm --prefix web/dashboard run build
	node scripts/quality/rules-parity.mjs
	bash scripts/quality/browser-build.sh stamp-dashboard

_quality-site:
	npm --prefix web/site run typecheck
	npm --prefix web/site run build
	bash scripts/quality/browser-build.sh stamp-site

_quality-design:
	$(MAKE) lint-design

# NEXT-06: trusted browser gate. Serves fingerprint-verified static builds on
# dedicated ports, never reusing a foreign listener; skips explicitly (exit 77)
# when the browser runtime is absent. Artifacts land in the run dir.
_quality-browser:
	bash scripts/quality/browser.sh

_quality-node-sdk:
	npm --prefix sdks/node run build
	npm --prefix sdks/node test

_quality-python-sdk:
	cd sdks/python && "$(SDK_PYTHON)" -m pytest -q

_quality-bridge:
	$(MAKE) test-subscription-bridge

_quality-docs:
	$(MAKE) docs-verify
	$(MAKE) docs-lang
	$(MAKE) docs-mdx

# Private release planning runs against an internal plans archive that is
# not part of the public export. Explicit skip (exit 77), never a silent pass.
_quality-plan:
	@echo "quality-plan: private planning-data validation is not part of the public export"; exit 77

_quality-go-sdk:
	cd sdks/go && go build ./... && go test -count=1 ./...

_quality-nested-go:
	cd deploy/mock-provider && go build ./... && go vet ./...
	cd deploy/mock-embedder && go build ./... && go vet ./...
	cd scripts/loadtest/http && go build ./... && go vet ./...

_quality-routing:
	$(MAKE) evaluate-routing

_quality-guards:
	$(MAKE) evaluate-guards

_quality-integration:
	docker info > /dev/null
	$(MAKE) test-integration

# NEXT-05: the remaining integration-tagged suites, one leaf per ownership
# boundary. All disposable/env-gated.
_quality-int-modules:
	go test -json -race -count=1 -tags=integration -p=2 ./pkg/migrate/... ./pkg/lineage/... ./pkg/adminstore/... ./pkg/credits/... ./pkg/budget/... ./pkg/policystore/... ./pkg/rulestore/... ./pkg/mcpagg/... ./pkg/a2aagg/... ./pkg/toolpolicy/... ./pkg/auditlog/... ./pkg/policy/asia_packs/... ./tests/integration/dr/... ./tests/integration/multiregion/... ./services/loggerd/integration/...

# Usage: make quality-changed [QUALITY_BASE=<git-ref>] [QUALITY_EXECUTE=1] [QUALITY_JOBS=N]
# Without QUALITY_EXECUTE this prints the required gates without running them.
quality-changed: ## Infer required gates from the working-tree diff (add QUALITY_EXECUTE=1 to run)
	@set --; \
	if [ -n "$$QUALITY_BASE" ]; then set -- "$$@" --base "$$QUALITY_BASE"; fi; \
	if [ "$$QUALITY_EXECUTE" = "1" ]; then set -- "$$@" --execute; fi; \
	set -- "$$@" --jobs "$(QUALITY_JOBS)"; \
	python3 scripts/quality/quality.py changed "$$@"

# --- Run services (foreground) ---
run-gateway: build ## Run yabanin gateway in the foreground
	./yabanin gateway

run-loggerd: build ## Run yabanin loggerd in the foreground
	./yabanin loggerd

run-admin: build ## Run yabanin admin in the foreground
	./yabanin admin

run-mcp: unified ## Run the yabanin mcp command in the foreground
	./yabanin mcp

run-subscription-bridge: ## Run the subscription bridge on loopback (fake mode by default)
	YABANIN_BRIDGE_FAKE=$${YABANIN_BRIDGE_FAKE:-1} YABANIN_BRIDGE_HOST=127.0.0.1 YABANIN_BRIDGE_PORT=$${YABANIN_BRIDGE_PORT:-8091} \
		node --experimental-strip-types services/subscription-bridge/src/index.ts

# OpenCode wiring helpers live on the internal stand lane and are not part
# of the public export: the generated agent-config prompts embed internal
# routing policy. See docs/opencode-integration.md for the gateway API.
dev-opencode: ## One-command OpenCode local loop (not in public export)
	@echo "dev-opencode: OpenCode wiring helpers are not part of the public export"; exit 77

opencode-remote-wire: ## Wire OpenCode agents to the public yabanin.ai stand (not in public export)
	@echo "opencode-remote-wire: OpenCode wiring helpers are not part of the public export"; exit 77

# --- Docker ---
# Every image carries all binaries (the Dockerfile has no SERVICE arg); the
# compose files pick the subcommand via `command:`.
# The Dockerfile fails the build loudly without an integer SOURCE_DATE_EPOCH
# (reproducible image recipe, same pattern as scripts/security/scan_images.sh):
# default to the last commit time, let an explicit caller value win.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct 2>/dev/null)

docker-build-all: ## Build all service Docker images (reproducible: SOURCE_DATE_EPOCH defaults to commit time)
	DOCKER_BUILDKIT=1 docker build --build-arg "SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH)" -t yabanin -f Dockerfile .
	DOCKER_BUILDKIT=1 docker build --build-arg "SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH)" -t yabanin-gateway -f Dockerfile .
	DOCKER_BUILDKIT=1 docker build --build-arg "SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH)" -t yabanin-admin -f Dockerfile .
	DOCKER_BUILDKIT=1 docker build --build-arg "SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH)" -t yabanin-loggerd -f Dockerfile .
	DOCKER_BUILDKIT=1 docker build --build-arg "SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH)" -t yabanin-mcp -f Dockerfile .

docker-up: ## docker compose up -d (loads .env when present)
	@if [ -f .env ]; then \
		echo "Loading .env file..."; \
		set -a; . ./.env; set +a; \
	fi
	docker compose -f deploy/docker-compose.yml up -d

docker-down: ## docker compose down
	docker compose -f deploy/docker-compose.yml down

docker-clean: docker-down ## docker compose down with images + volumes + orphans
	docker compose -f deploy/docker-compose.yml down --rmi local --volumes --remove-orphans

# --- Demo (one command to a populated dashboard) ---
demo: ## One command to a populated dashboard (scripts/demo/run_demo.sh)
	@bash scripts/demo/run_demo.sh

demo-down: ## docker compose down with volumes + orphans
	docker compose -f deploy/docker-compose.yml down --volumes --remove-orphans

# Pricing imports require an explicit operator-supplied file and provenance.
# This guidance-only target does not download or modify pricing data.
pricing-refresh: ## Explain how to import an operator-supplied price file
	@echo 'Pricing imports require an operator-supplied file. Use yb pricing import-litellm or import-litellm-units with explicit --in, --out, --source and --date; see docs/compat/litellm-migration.md.' >&2
	@exit 2

# CORE-REF-03 offline reference-pack tooling. Both targets are hermetic:
# local files only, no network. pricing-pack re-wraps the committed sealed
# genesis catalog into snapshots/reference-pack-v1.json (byte-identical
# regeneration is enforced by TestBundledRefSnapshotPins); pricing-verify
# re-checks the committed envelope offline (schema + both digests).
pricing-pack: ## Regenerate the reference pack envelope from the committed genesis catalog (offline)
	go run ./cmd/yb pricing pack --catalog pkg/pricing/catalogs/reference-catalog-v1.json \
	  --out pkg/pricing/snapshots/reference-pack-v1.json

pricing-verify: ## Verify the committed reference pack offline (schema + catalog + envelope digests)
	go run ./cmd/yb pricing verify --pack pkg/pricing/snapshots/reference-pack-v1.json

# --- Quickstart (one process: gateway + loggerd + admin) ---
.PHONY: quickstart-up quickstart-seed quickstart-smoke quickstart-down
QUICKSTART_COMPOSE = docker compose -f deploy/quickstart/docker-compose.yml --profile mock

quickstart-up: ## Quickstart: init env + compose up --build --wait (mock profile)
	bash scripts/quickstart/init-env.sh
	$(QUICKSTART_COMPOSE) up -d --build --wait

quickstart-seed: ## Quickstart: seed demo data
	bash scripts/quickstart/seed.sh

quickstart-smoke: ## Quickstart: smoke check (usage: make quickstart-smoke KEY=...)
	@if [ -z "$(KEY)" ]; then echo "usage: make quickstart-smoke KEY=..."; exit 1; fi
	bash scripts/quickstart/smoke.sh "$(KEY)"

quickstart-down: ## Quickstart: compose down --remove-orphans
	$(QUICKSTART_COMPOSE) down --remove-orphans

# --- Migrations ---
migrate-up: ## Apply migrations via psql (or docker compose fallback)
	@if command -v psql &>/dev/null; then \
		echo "Running migrations via psql..."; \
		for f in migrations/*.sql; do case "$$f" in *.down.sql) continue;; esac; psql $(YABANIN_PG_URI) -f "$$f"; done; \
	else \
		echo "psql not found, running migrations via docker compose..."; \
		docker compose -f deploy/docker-compose.yml run --rm gateway /app/yabanin migrate; \
	fi

# PB2: region-aware migration runner (sets app.region GUC before each migration).
migrate-region: build-migrate ## Region-aware migration runner (usage: make migrate-region REGION=sg)
	@if [ -z "$(REGION)" ]; then echo "error: REGION is required (e.g. make migrate-region REGION=sg)"; exit 1; fi
	YABANIN_PG_URI="$(or $(YABANIN_PG_URI),postgres://yabanin:yabanin@localhost/yabanin?sslmode=disable)" \
	YABANIN_REGION="$(REGION)" \
	./yabanin-migrate migrations

build-migrate: ## Build yabanin-migrate (no ldflags)
	go build -o yabanin-migrate ./cmd/yabanin-migrate/...

# --- P5 Savings Measurement ---
measure-savings: ## P5 kill criterion: savings measurement
	@echo "=== P5 Kill Criterion: Savings Measurement ==="
	@DATABASE_URL="$${YABANIN_PG_URI:-$${DATABASE_URL}}" python3 scripts/measure_savings.py $$MEASURE_FLAGS

# --- ML Classifier Training (P5.8) ---
# Not part of the public export: training needs the internal datasets/ corpus
# (see the ML-scripts exclusion note in the export allowlist).
train-classifier: ## P5.8: train the ML classifier (requires internal datasets; not in public export)
	@echo "train-classifier: ML training datasets are not part of the public export"; exit 77

# --- Load Testing (P7.1) ---
load-test-chat: ## k6 load test: chat completions
	@echo "=== k6 Chat Completions Load Test ==="
	k6 run --env TOKENROUTER_BASE_URL=$(or $(TOKENROUTER_BASE_URL),http://localhost:8082) \
	   --env TOKENROUTER_API_KEY=$(or $(TOKENROUTER_API_KEY),yabanin-dev-key) \
	   tests/load/k6_chat.js

load-test-cache: ## k6 load test: cache hit rate
	@echo "=== k6 Cache Hit Rate Test ==="
	k6 run --env TOKENROUTER_BASE_URL=$(or $(TOKENROUTER_BASE_URL),http://localhost:8082) \
	   --env TOKENROUTER_API_KEY=$(or $(TOKENROUTER_API_KEY),yabanin-dev-key) \
	   tests/load/k6_cache_hit.js

load-test-mixed: ## k6 load test: mixed models
	@echo "=== k6 Mixed Models Load Test ==="
	k6 run --env TOKENROUTER_BASE_URL=$(or $(TOKENROUTER_BASE_URL),http://localhost:8082) \
	   --env TOKENROUTER_API_KEY=$(or $(TOKENROUTER_API_KEY),yabanin-dev-key) \
	   tests/load/k6_mixed_models.js

# --- Internal benchmark stand (OP-23) ---
# The internal benchmark stand (bench compose project, runner script and
# compose overrides) is internal tooling and is not part of the public
# export. Numbers are machine-dependent and owner-gated for publication.
bench-stand: ## OP-23: run the internal benchmark stand (not in public export)
	@echo "bench-stand: the internal benchmark stand is not part of the public export"; exit 77

bench-stand-down: ## OP-23: force-remove the bench compose project (not in public export)
	@echo "bench-stand-down: the internal benchmark stand is not part of the public export"; exit 77

# --- Deploy (Helm wrappers) ---
# Usage: make deploy REGION=sg NAMESPACE=yabanin-staging VERSION=v0.1.0
REGISTRY      ?= ghcr.io
IMAGE_REPO    ?= $(shell grep '^MODULE' go.mod | sed 's/MODULE := //')
REGION        ?= sg
NAMESPACE     ?= yabanin
VERSION       ?= latest

deploy: helm-upgrade ## Deploy via Helm (usage: make deploy REGION=sg NAMESPACE=yabanin-staging VERSION=v0.1.0)
	@echo "=== Deployed ${VERSION} to ${REGION}/${NAMESPACE} ==="

helm-install: ## helm upgrade --install yabanin (VERSION required)
	@if [ -z "$(VERSION)" ]; then echo "error: VERSION is required (e.g. make helm-install VERSION=v0.1.0)"; exit 1; fi
	helm upgrade --install yabanin deploy/helm/yabanin/ \
		--set gateway.image.tag=$(VERSION) \
		--set loggerd.image.tag=$(VERSION) \
		--set admin.image.tag=$(VERSION) \
		--namespace $(NAMESPACE) \
		--create-namespace \
		--wait

helm-upgrade: helm-install ## Alias of helm-install
	@echo "=== Upgraded to ${VERSION} ==="

helm-rollback: ## helm rollback (usage: make helm-rollback REVISION=3)
	@if [ -z "$(REVISION)" ]; then echo "error: REVISION is required (e.g. make helm-rollback REVISION=3)"; exit 1; fi
	helm rollback yabanin $(REVISION) --namespace $(NAMESPACE)
	@echo "=== Rolled back to revision $(REVISION) ==="

# --- Profile (P7.2) ---
profile: ## Performance profiling (scripts/profile_run.sh [SERVICE] [DURATION])
	@echo "=== Performance Profiling ==="
	./scripts/profile_run.sh $(or $(SERVICE),all) $(or $(DURATION),60)

# --- Helm validation ---
helm-lint: ## helm lint + template validation of the yabanin chart
	@echo "=== Helm lint yabanin chart ==="
	helm lint deploy/helm/yabanin/
	helm template test-release deploy/helm/yabanin/ > /dev/null

# --- Clean ---
clean: ## Remove root binaries, coverage.out, nohup.out, test-results/, dist/
	rm -f yabanin yabanin-gateway yabanin-loggerd yabanin-admin yabanin-mcp yabanin-migrate yb
	rm -f coverage.out nohup.out
	rm -rf test-results dist
