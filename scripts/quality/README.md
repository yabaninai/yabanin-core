# Local quality checks

Run commands from the repository root. The public Core checks use repository
source, synthetic evaluation data and disposable test infrastructure. They do
not require private plans or agent reports.

## Prerequisites

Use the Go version declared in `go.mod`, Node.js with npm, Python 3, make, Git,
Docker Engine with Compose v2, Bash, curl, OpenSSL and Helm. Docker must be
reachable for integration, packaging and recovery checks. Allow disk space for
container images and temporary databases. Install Python's PyYAML in your active
Python environment; the dependency checker uses it.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install pyyaml -e 'sdks/python[test]'
npm ci --prefix web/dashboard
npm ci --prefix web/site
npm ci --prefix sdks/node
make install-analysis-tools
make security-tools-install
make security-db-update
```

Security tools are version-pinned. Database updates need network access; scans
use the local database cache. Go and Trivy metadata must be no older than 24
hours. `YABANIN_SECURITY_CACHE` selects metadata and Go database storage;
`TRIVY_CACHE_DIR` selects Trivy's database storage. Use the same overrides for
updates and scans. Go-only analysis does not require the Trivy database.

Builds may download Go modules, npm packages and container base images. The
Node bridge has no npm dependencies. Python SDK tests require its `test` extras,
including pytest and respx; the install command above supplies them.
Use an isolated worktree and avoid concurrent heavy checks on the same Docker
daemon or Go caches.

## Select and execute

Capture the task's original base before editing. Include it after committing,
otherwise a clean working tree alone will not describe the task's changes.

```bash
TASK_BASE=$(git rev-parse HEAD)
# Make your changes, then inspect and execute the selected checks.
make quality-changed QUALITY_BASE="$TASK_BASE"
make quality-changed QUALITY_BASE="$TASK_BASE" QUALITY_EXECUTE=1
```

For a full product check:

```bash
make quality-full QUALITY_BASE="$TASK_BASE"
```

The full profile covers static analysis, Go tests with race detection, public
routing/guard evaluations, dashboard and site builds, SDK tests, module
integration, secrets, dependencies, licenses, container policy, packaging,
monitoring configuration and database recovery. Changed Go files additionally
run the changed-complexity gate (`go-complexity`, differential analyzer in
`complexity/go/`), and changed files under `web/dashboard/` run the frontend
complexity gate (`ts-complexity`, differential analyzer in `complexity/ts/`;
thresholds and receipt policy in each README). Evaluation
corpora are synthetic regression samples, not production accuracy benchmarks.
Private program claims and planning ledgers are outside the product profile.

The full profile does not include `make quality-integration` (gateway integration)
or browser acceptance. Run those when required by the changed behavior. Verify
the actual [Compose quickstart](../../docs/quickstart.md) and its authenticated
UI when changing installation or user workflows. A synthetic API browser test
alone does not verify the running backend.

## Read evidence

Each run writes commands, logs and `manifest.json` under a unique
`artifacts/quality/<run-id>/` directory. Validate evidence against the current
source and original base:

```bash
python3 scripts/quality/quality.py evidence artifacts/quality/<run-id>/manifest.json \
  --require changed --base "$TASK_BASE"
```

A full run can cover the changed profile when its source and gates match. A
failed, interrupted or stale run is not acceptance. Inspect the first meaningful
failure, classify its cause, fix it, and rerun affected checks. Do not delete
assertions, substitute a successful placeholder, or import private security
waivers to obtain a passing result.

License metadata exceptions are versioned, scoped and expire. They do not waive
vulnerabilities or grant release clearance. Preserve complete upstream notices
and follow the separate release review process before distributing artifacts.
The exceptions registry is shared across scanners: every entry names its
scanner, and each gate reads only its own entries.

## Go policy and critical behavior

Install `make install-analysis-tools install-critical-tools`. Changed Go work and
the full profile include `go-policy` and `critical-go`; see the
[scope, budgets and negative controls](go_policy/README.md). Preserve the original
task base for local execution and candidate evidence. Untouched analyzer debt is
reported separately. A missing tool or missing relevant critical coverage blocks.
