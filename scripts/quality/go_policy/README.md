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

Selection runs through the qualified conservative selector by default: changed
declarations bind their real consumers — including baseline, relocated and
cross-package test consumers — and unresolved mapping widens the selection
instead of running too little. Every selected row carries a `seed` flag in
`report.json`: literally-changed bodies, consumers bound to changed
declarations or rewritten tests, and every production function of a widened
package all carry fuzz-seed demands — widening is the conservative fallback
and keeps the historical demand instead of dropping it. Seed flags are
demands, not self-executing guarantees: they are enforced only in build modes
where the package actually has fuzz targets (`report.json` records the scope
as `selector.seed_demand_scope`); in a fuzz-less package the selected
critical function relies on the unit-suite gate passing in every configured
build mode — a deliberate contract, not an oversight. A rewritten test (same
name, new body) does not keep its baseline coverage selected on text alone:
after binding, the gate re-runs the package's unit suite per build mode
under a real coverage profile, both at the base revision and in the current
tree, and the proof is block-level — a consumer whose base-revision body is
identical must still execute every base-executed block (shift- and
move-aligned through base-side spans, so relocating a function in the
current tree cannot make its lost coverage vacuous) and blocks with
`lost_block_coverage` naming file and block otherwise, while a consumer the
whole suite no longer exercises at all blocks with `lost_unit_coverage`.
A changed body cannot map its base blocks, so it must execute every block
it now has. The rest re-baseline silently and are recorded as `rebaselined`
selector evidence. Test units pair with their baseline twins by name and
body hash together, never by name alone: Go allows duplicate test names in
mutually exclusive files (build tags, GOOS), and an unchanged twin must not
spend or replace a rewritten sibling's baseline. Baseline helpers reachable
from a lost unit resolve across every same-named twin — the closure unions
all (name, body) helpers, so a rewrite cannot redirect its baseline through
a name-collapsed helper while a platform twin still carries it. A moved
production counterpart sharing its name with twins resolves only by body
hash with a unique build-mode footprint; when no counterpart resolves at
all — an ambiguous twin whose body also changed — each applicable mode must
execute every current block, and an unexecuted one blocks with
`lost_block_coverage` instead of re-baselining on an unmappable baseline. Bare names the base never
covered (for example stdlib `Set`/`WriteHeader` calls that collide with
production method names) are vacuous and never block, and vacuous means no
applicable base build mode ever executed the like-named consumer — a
consumer one mode covered is a real baseline even when another mode never
did; a consumer that cannot be matched to any
base-revision function is not vacuous — it re-baselines with evidence while
covered and blocks while uncovered. The blank identifier is not package
state, so `var _ Iface = ...` compile assertions never widen.
`CRITICAL_SCOPE_SELECTOR=legacy` selects the pre-qualification selector as an
explicit emergency override; any other value fails the gate closed instead
of guessing a mode.

Each affected package runs on the approved versioned budget block in
`critical.json` (`budget.schema_version` 1): 300 seconds per package for the
unit suite, 420 seconds for fuzzing and 300 seconds for mutation, including
subprocess startup and shared across the package's supported build modes.
Baseline-coverage verification runs draw down the same per-package unit
budget as the normal unit phase — one wall-clock budget per package, never a
fresh one per verification subprocess — and a suite that outlives it is
killed as a whole process group and reported as an exhausted unit budget.
The runner rejects any other budget instead of silently guessing; a legacy
flat `seconds_per_package_and_kind` field is an error, not a fallback.
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
  requirement that exists there. A package whose fuzz or unit-test targets
  disappear from a build mode (renamed or constraint-tagged out) blocks the
  gate loudly instead of turning every check not-applicable; a package with no
  tests at all reports `skipped: no unit tests in package (N/A)` and enforces
  nothing else here; normal build, vet, lint and test gates still apply
  outside this runner.

Not-applicable entries are printed with their reasons and stored in
`report.json`; they never fabricate fuzz executions, mutation kills or
coverage, and strictness is unchanged where the infrastructure exists. There
is no separate warm invocation: each fuzz budget first replays the seed
corpus for coverage, then goes directly to bounded real `-fuzz` attempts that
build and warm the instrumented binary themselves. Seed replay and generated
executions remain mandatory: an attempt that only gathered seed baseline
coverage earns one evidence-bounded retry and stays red if it still confirms
no executions. Build modes share the
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
