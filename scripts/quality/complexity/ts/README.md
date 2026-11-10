# TS/JS complexity differential analyzer

`analyze.mjs` measures added/changed/moved TypeScript and JavaScript function
bodies between a base revision and the current working tree, and reports
untouched legacy debt separately. It is the measurement core for the frontend
complexity gate (QG-C02); wiring it into `make quality-changed`, receipt
validation and stricter moved-code debt rules land in later children.

This analyzer is self-contained Node.js (no npm dependencies of its own). It
parses with the dashboard's pinned TypeScript compiler.

## Usage

```bash
node scripts/quality/complexity/ts/analyze.mjs \
  --base "$TASK_BASE" [--scope web/dashboard/] [--receipt ID] \
  [--json-out FILE] [--repo PATH] [--quiet]
```

- `--base` — base ref; resolved to a commit, then `git merge-base <commit>
  HEAD` (same semantics as `scripts/quality/quality.py`). Without `--base`,
  the diff is the working tree against `HEAD`.
- `--scope` — repeatable path prefix filter; defaults to `web/dashboard/`.
  Files with extensions `.ts .tsx .js .jsx .mjs .cjs` are measured.
- `--receipt` — recorded verbatim in the report; review-band functions are
  marked `receipt-recorded` instead of `required`. Validation of the receipt
  (identity, base, hash binding, model capability) is QG-C02-02.
- `--repo` — target repository (default: the checkout holding this script;
  `TS_COMPLEXITY_REPO_ROOT` overrides that default, used by the fixture
  runner for analyzer copies in temp directories).

JSON goes to stdout (deterministic: no timestamps, sorted entries); the human
summary and `BLOCK ...` offender lines go to stderr. Exit codes: `0` clean,
`1` at least one changed body is over the block limit, `2` tool error (bad
base, missing merge base, parse failure, TypeScript pin drift).

## Parser pinning

The parser is the `typescript` package installed under
`web/dashboard/node_modules`, and its installed version is verified against
`web/dashboard/package-lock.json` (`packages["node_modules/typescript"]`) on
every run. Drift is a hard error, and both versions plus `pin_matches` are
recorded in the report. Parse diagnostics in any in-scope file fail the run
(exit 2) naming the file — a parser failure is never silently skipped.

## Metric rules

Cognitive complexity, Sonar-style, with explicit counting rules:

- `+1 x (1 + nesting)` for each `if` (not counting its `else`), each loop
  (`for`, `for-of`, `for-in`, `while`, `do-while`), each `switch` `case`
  clause, each `catch` clause, and each ternary (`? :`).
- `+1` flat for `else` and for each `else if` link in a chain.
- `+1` flat for each logical operator token `&&`, `||`, `??` (a run of n
  same-kind operators scores n, which is Sonar's sequence rule reduced to
  per-operator counting).
- `+1` flat for `break`/`continue` with a label.
- Nesting increases by one inside: `if` bodies, loop bodies, `switch` case
  bodies, `catch` bodies, and ternary branches.
- Deviation from Sonar, deliberate: nested function-likes (closures, arrow
  functions, callbacks) add nothing to the enclosing score and are measured
  as their own bodies — this gate treats every closure as a function body,
  so attribution must not double-count.
- Not counted (documented limits): recursion, `goto`-style jumps other than
  labeled break/continue.

Classification (per the maintainability standard): `<=10` ok, `11-15`
review (stronger-model review receipt required — recorded only at this
stage), `>15` block. Only `added` and `changed` bodies can fail the run
(exit 1, offender named on stderr); `moved` bodies and untouched legacy debt
are reported, never re-flagged here.

## Body extraction and identity

Measured bodies: function declarations, class methods, constructors, getters
and setters, function expressions, arrow functions (including arrow-valued
variables/properties) and every closure nested inside another body.
Overloads and body-less declarations are skipped. `role` is a naming
heuristic (`useX` → hook, `X...` → component), not a semantic claim.

A body fingerprint is the SHA-256 of the function body printed by the
TypeScript printer with comments removed and whitespace collapsed, so
formatting-only and comment-only edits keep the fingerprint stable. Match
order per changed file:

1. identical fingerprint → unchanged (same qualified name) or renamed/moved
   within the file (different name) — status `moved`, never re-flagged;
2. same own name and kind → `changed` (old/new complexity and delta);
3. otherwise, a fingerprint found in the pool of base-side bodies that
   vanished from other changed files → `moved` across files;
4. else `added`. Base-side bodies consumed by nobody are `deleted` (counted
   in the summary only, per the fixture contract).

Known limitation: renaming a function *and* editing its body in the same
change classifies as `added`, losing the old baseline; a rename that also
renames parameters breaks fingerprint identity the same way. Stricter
rename handling that preserves baseline debt is QG-C02-02 scope.

## Report schema (`ts-complexity-diff/1`)

- `analyzer` — name/version/metric + threshold limits.
- `parser` — typescript version, lockfile pin, `pin_matches`.
- `run` — repository root, scopes, base ref/commit, merge base, head
  commit, file counts, and content digests binding the report to the exact
  head source (`source_digest`) and base tree (`base_source_digest`, git
  blob IDs from `ls-tree`).
- `receipt` — the `--receipt` value or null.
- `changed_functions[]` — `file, name (qualified with `::`), kind, role,
  line, fingerprint, status (added/changed/moved), moved_from, old/new
  complexity, delta, classification, review`.
- `summary` — added/changed/moved/deleted counts, review and blocking.
- `untouched_debt` — counts of untouched functions by classification plus
  the ten highest scores (a full inventory belongs in CI artifacts).
- `failures[]` — blocking offenders, `file: name (cognitive complexity N > 15)`.

## Fixtures

`scripts/quality/tests/complexity/ts_fixture_runner.mjs` builds a throwaway
git repository from `ts_fixtures/` (base and head states), asserts exit codes
and report contents for all six control classes, checks byte-determinism of
two consecutive runs, and re-runs deliberately mutated analyzer copies to
prove each control fails on its intended assertion. The fixture templates
intentionally contain high-complexity bodies; they are test inputs, not
shipped logic, and are excluded from the analyzer's self-check scope.
