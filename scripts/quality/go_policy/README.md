# Go policy and critical behavior gates

Use Python 3.12 or later, the product Go toolchain, pinned golangci-lint 2.15.0
and Gremlins 0.6.0. Install via
`make install-analysis-tools install-critical-tools`. Run from the product root:

```bash
make analyze-go-policy QUALITY_BASE=<original-task-base>
make analyze-critical-go QUALITY_BASE=<original-task-base>
```

Both are selected by changed Go work and included in the full quality profile.
Selection without `QUALITY_EXECUTE=1` is not executed evidence. Existing lint,
security, race tests and differential complexity remain required. Tools run
locally and use the same commands in CI; no coordination repository is needed.

## Static policy

The additional pinned configuration is `linters.yml`. Error wrapping/comparison,
package dependency boundaries, process exits in libraries and designated enum
switches are blocking rules. `gocritic`'s appendAssign, badCall, dupBranchBody and
exitAfterDefer checks are advisory during calibration. Command entrypoints and
test files are exempt only from the process-exit rule. SQL remains permitted in
storage adapters; only the named pure-domain packages deny SQL imports.

The runner analyzes the current tree and original base with the SAME candidate
configuration and tool, then compares findings against canonical Go declaration
identities. An existing finding in a changed declaration blocks even if its own
line did not change. A content-identical move can retain old debt; copies cannot
claim the same old finding more than once. A new enum member can create a new
finding in an otherwise unchanged switch and still blocks. Untouched findings
are retained in `legacy_debt`, never silently deleted or auto-fixed.

Imports and package declarations are units too. Formatting/comments do not reset
identity; literal content does. New suppression/generated-code directives need
independent policy review and are rejected by this runner, not accepted as a fix.
Missing tools, parse/load errors, invalid output and timeouts are operational
failures, not a clean scan. Reports include base, source/config hashes, tool
version, blocking findings and advisory/debt inventories. Use a fresh output path
for every invocation to preserve failed evidence.

## Critical behavior

`critical.json` lists the critical package paths and build modes. A production
function change selects that function; test or domain-declaration changes select
its package's production functions. Pure formatting/comment edits do not invent
new executable behavior. Deletions with no remaining package are not fuzz targets.
A declaration-only change with no executable consumer bound is blocked for an
explicit coverage decision. Dependency-only edits still run policy/security and
normal product tests; this runner does not pretend that unchanged functions were
modified or that their missing historic fuzz tests are new-code violations.

Each affected package has at most 300 seconds per check kind (unit suite,
fuzzing, mutation), including subprocess startup and its supported build modes.
Missing coverage, timeout or an unfinished run blocks. Extended campaigns
belong in separate runs; never raise this budget secretly or interpret an
exhausted budget as success.

Applicability is per package and build mode, decided from real evidence and
versioned in `critical.json` (schema 2):

- Fuzzing applies only where the package actually has fuzz targets in that
  build mode (detected via `go test -list=^Fuzz`). Where targets exist, the
  strict requirement is unchanged: seed inputs must cover every statement
  block of the selected functions and actual fuzz executions must complete.
  A package without fuzz targets in a mode reports
  `skipped: no fuzz targets (N/A)` for that mode — visibly in the console
  output and in `report.json`; it is never counted as fuzz coverage.
- Mutation applies only to packages listed in `mutation_qualified_packages`
  — a gremlins-qualified unit mode, meaning a test suite that can actually
  kill the relevant mutants of each selected function within the approved
  budget. The list is explicit and versioned; it is empty until a package
  genuinely qualifies. Unlisted packages report
  `skipped: no gremlins-qualified unit mode (N/A)` explicitly.
- Where fuzz targets are absent but the package has unit tests, the gate
  requires that unit suite to pass in each configured build mode — the real
  requirement that exists there. A package with no tests at all reports
  `skipped: no unit tests in package (N/A)` and enforces nothing else here;
  normal build, vet, lint and test gates still apply outside this runner.

Not-applicable entries are printed with their reasons and stored in
`report.json`; they never fabricate fuzz executions, mutation kills or
coverage, and strictness is unchanged where the infrastructure exists. The
engine warms its instrumented binary inside the same fuzz budget before
spending the remaining time on input generation. Build modes share the
budget, and only functions compiled in that mode are tested; a selected file
absent from every configured mode blocks. A passing unrelated fuzz target or
an empty test suite is insufficient.

For qualified packages, mutation runs use real Gremlins in an isolated source
copy. Every selected function must have tested mutations; relevant mutations
must be KILLED. The underlying Go invocations are independently captured as
JSON events; a kill requires an actual failing named test. Compilation/CLI
errors, incomplete child processes and mismatched kill totals block, even
when the mutator claims success. LIVED,
NOT COVERED, NOT VIABLE, skipped, timed-out and unknown outcomes do not
certify correctness. A nonviable mutation or an equivalent survivor requires
diagnosis and a separately reviewed, source-bound exception decision; this
initial gate has no automatic waiver path. Never weaken tests or hide the
mutation to pass. The mutation gate is additional evidence, not a proof of
all business invariants.

Logs, mutation reports, seed coverage and fuzz execution counts are retained under
ignored `artifacts/quality/`; failing fuzz corpora are copied from the isolated
source. Neither tool may mutate the developer's product worktree. The enclosing
quality manifest binds command exits/logs and current source; gate output includes
its report hash. Failures remain blockers until fixed or independently reviewed.

## Gate self-tests

The quality self suite includes real-linter controls for legacy debt, errors in a
changed body, renamed imports, SQL boundaries and enum evolution, plus output and
coverage negative controls. A missing analyzer fails these controls. Known-bad
programs must produce the expected named rule; a build failure is not a successful
negative control. Critical engine qualification also runs a small real Go program
through both mutation and fuzzing; its raw evidence must be recorded separately
from product acceptance. A synthetic control is never a production behavior claim.
