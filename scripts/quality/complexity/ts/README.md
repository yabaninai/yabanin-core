# TS/JS complexity differential analyzer

`analyze.mjs` measures added/changed/moved TypeScript and JavaScript function
bodies between a base revision and the current working tree, reports
untouched legacy debt separately (including debt carried by renames and
relocations — a rename never resets debt), and enforces the review band
(11-15) through validated stronger-model review receipts. It is the
measurement core for the frontend complexity gate (QG-C02).

This analyzer is self-contained Node.js (no npm dependencies of its own). It
parses with the dashboard's pinned TypeScript compiler.

## Usage

```bash
node scripts/quality/complexity/ts/analyze.mjs \
  --base "$TASK_BASE" [--scope web/dashboard/] [--receipt FILE] \
  [--model-order weakest,...,strongest] [--debt-out FILE] \
  [--json-out FILE] [--repo PATH] [--quiet]
```

Through the quality framework (what CI and `make quality-changed` run):

```bash
make _quality-ts-complexity                    # base defaults to HEAD
QUALITY_BASE="$TASK_BASE" make _quality-ts-complexity
```

The gate recipe analyzes `web/dashboard/` (the default scope) and forwards
an optional receipt through the `TS_COMPLEXITY_RECEIPT` environment
variable (path to the receipt JSON; keep receipts outside the tracked
source tree — `artifacts/` is ignored). The gate never writes files into
the working tree.

- `--base` — base ref; resolved to a commit, then `git merge-base <commit>
  HEAD` (same semantics as `scripts/quality/quality.py`). Without `--base`,
  the diff is the working tree against `HEAD`.
- `--scope` — repeatable path prefix filter; defaults to `web/dashboard/`.
  Files with extensions `.ts .tsx .js .jsx .mjs .cjs` are measured.
- `--receipt` — **path to a review receipt JSON file** (breaking change from
  1.0, which recorded the value verbatim). See *Review receipts*. A provided
  receipt is validated in full; an invalid receipt blocks exactly like a
  missing one.
- `--model-order` — comma-separated model identifiers ordered weakest to
  strongest (for example `--model-order impl-lite,impl-strong`). When given,
  both receipt models must appear in the ordering and the reviewer must rank
  strictly above the implementer. Without it, only reviewer ≠ implementer is
  enforced (the inequality is always required).
- `--debt-out` — write the full untouched-debt ledger (schema
  `ts-complexity-debt/1`, see *Debt ledger*) to this file. Never blocks.
- `--repo` — target repository (default: the checkout holding this script —
  never environment-steered, so a gate copy always measures its own tree).
  `TS_COMPLEXITY_REPO_ROOT` instead pins where the parser's TypeScript
  checkout is looked up (used by the fixture runner for analyzer copies in
  temp directories).

JSON goes to stdout (deterministic: no timestamps, sorted entries); the human
summary, `BLOCK ...`, `RECEIPT INVALID ...` and `NEEDS REVIEW RECEIPT ...`
lines go to stderr. Exit codes: `0` clean; `1` a changed body is over the
block limit, the review band lacks a receipt, or a provided receipt is
invalid; `2` tool error (bad base, missing merge base, parse failure,
TypeScript pin drift, unreadable source file).

## Parser pinning

The parser is the `typescript` package installed under
`web/dashboard/node_modules`, and its installed version is verified against
`web/dashboard/package-lock.json` (`packages["node_modules/typescript"]`) on
every run. Drift is a hard error, and both versions plus `pin_matches` are
recorded in the report. Parse diagnostics in any in-scope file fail the run
(exit 2) naming the file — a parser failure is never silently skipped.

The same holds for source reads: a file absent from the working tree is
treated as deleted, but any other read failure (permissions, I/O) is a tool
error that exits 2 naming the file.

## Metric rules

Cognitive complexity, Sonar-style, with explicit counting rules:

- `+1 x (1 + nesting)` for each `if` (not counting its `else`), each loop
  (`for`, `for-of`, `for-in`, `while`, `do-while`), each `switch` `case`
  clause, each `catch` clause, and each ternary (`? :`).
- `+1` flat for `else` and for each `else if` link in a chain.
- `+1` flat for each logical operator token `&&`, `||`, `??` (a run of n
  same-kind operators scores n, which is Sonar's sequence rule reduced to
  per-operator counting).
- `+1` flat for each `break`/`continue` with a label.
- Nesting increases by one inside: `if` bodies, loop bodies, `switch` case
  bodies, `catch` bodies, and ternary branches.
- Deviation from Sonar, deliberate: nested function-likes (closures, arrow
  functions, callbacks) add nothing to the enclosing score and are measured
  as their own bodies — this gate treats every closure as a function body,
  so attribution must not double-count.
- Not counted (documented limits): recursion, `goto`-style jumps other than
  labeled break/continue.

Classification (per the maintainability standard): `<=10` ok, `11-15`
review, `>15` block. Every `added`/`changed` body over 15 fails the run
(exit 1, offender named on stderr). Every `added`/`changed` body in the
11-15 review band needs a valid receipt: `review` is `required` (no receipt
given), `receipt-invalid` (receipt given but failed validation) or
`receipt-recorded`. `moved` bodies are exempt from the review band — they
carry their base measurement, delta 0 — but they stay visible as carried
debt in the debt ledger.

## Review receipts (`ts-complexity-review-receipt/1`)

A receipt is a JSON object binding one independent review to the exact
analyzed commits, the review-band functions and both model identities:

```json
{
  "schema": "ts-complexity-review-receipt/1",
  "source_commit": "<analyzed head commit>",
  "base_commit": "<analyzed merge base>",
  "implementer_model": "impl-lite",
  "reviewer_model": "impl-strong",
  "verdict": "approve",
  "reviewed_at": "2026-11-10T09:00:00.000Z",
  "functions": ["web/dashboard/src/lib/band.ts:borderlineTwelve"]
}
```

Valid means all of the following; each failed check yields its own precise
error, listed in `report.receipt.errors` and on stderr as
`RECEIPT INVALID ...` lines:

- `schema` is exactly `ts-complexity-review-receipt/1`; every field is
  present and non-empty (`functions` a non-empty list of `file:name`
  strings).
- `source_commit`/`base_commit` equal the analyzed head commit and merge
  base — a receipt for any other change is refused.
- `reviewer_model` differs from `implementer_model` (always), and with
  `--model-order` both appear in the ordering with the reviewer strictly
  stronger.
- `verdict` is one of `approve`, `reject`, `require_refactoring` and only
  `approve` clears the band.
- `reviewed_at` parses as ISO-8601, is no more than 30 days old (mirroring
  the bounded-exception expiry in the maintainability standard) and at most
  24h in the future (clock-skew tolerance).
- every review-band function of the run is bound as exact `file:name` in
  `functions` (extra entries are allowed).

One invalid receipt blocks the run (exit 1) with all of its errors; a valid
receipt is echoed in `report.receipt` with `valid: true`. Regardless of any
receipt, bodies over 15 always block.

Relationship to the Go gate (`scripts/quality/complexity/go`): the
discipline is shared and the placeholder fields `reviewer_model`,
`verdict` and `functions` mirror the Go schema. Deliberate divergences:
Go's single `base_sha` becomes `source_commit` + `base_commit` here; this
schema adds `implementer_model`, `reviewed_at` and `schema`; Go's
`functions` entries are bare names while this gate binds exact
`file:name` pairs, because the TS/JS diff can contain same-named functions
in different files.

## Body extraction and identity

Measured bodies: function declarations, class methods, constructors, getters
and setters, function expressions, arrow functions (including arrow-valued
variables/properties) and every closure nested inside another body.
Overloads and body-less declarations are skipped. `role` is a naming
heuristic (`useX` → hook, `X...` → component), not a semantic claim.

A body fingerprint is the SHA-256 of the function body printed by the
TypeScript printer with comments removed and whitespace collapsed, so
formatting-only and comment-only edits keep the fingerprint stable. Matching
per changed file runs in three survivor-first passes:

1. **Survivors** — a base body that still exists at head under its own
   qualified name with an identical fingerprint is unchanged; it is never
   re-measured and can never back a rename or move. Pairing survivors first
   makes the result independent of file order: a duplicate copy appearing
   earlier in the file cannot steal the original's identity.
2. **In-file renames** — identical fingerprint, different name (any
   syntactic form: declaration → function expression, default export →
   renamed arrow). Each vanished original backs at most one rename; later
   identical copies fall through to duplicate handling.
3. **Changed** — same own name and kind, different content → `changed` with
   old/new complexity and delta.

Bodies still unmatched after the three passes are resolved globally:

- an identical fingerprint in the pool of base bodies that vanished from
  *other* changed files → `moved` (cross-file), `moved_from` names the
  origin;
- otherwise, if the fingerprint exists anywhere at base, the body is a
  **duplicate**: status `added` with `duplicate_of` naming the original,
  and it is measured as new code — an identical copy of a blocking body
  blocks, and a copy of a function whose original still exists cannot
  escape measurement as a fake "move". A cross-file duplicate whose
  original lives in an unchanged file is a plain `added` (the unchanged
  file is not part of the diff, so `duplicate_of` cannot point at it);
- else plain `added`. Base-side bodies consumed by nobody are `deleted`
  (counted in the summary only, per the fixture contract).

Known limitation: renaming a function *and* editing its body in the same
change classifies as `added`, losing the old baseline; a rename that also
renames parameters breaks fingerprint identity the same way.

## Report schema (`ts-complexity-diff/2`)

- `analyzer` — name/version/metric + threshold limits.
- `parser` — typescript version, lockfile pin, `pin_matches`.
- `run` — repository root, scopes, base ref/commit, merge base, head
  commit, file counts, and content digests binding the report to the exact
  head source (`source_digest`) and base tree (`base_source_digest`, git
  blob IDs from `ls-tree`).
- `receipt` — null, or the validated receipt object: `path`, `valid`,
  `errors[]`, and the echoed document fields. The full validation verdict,
  not a verbatim echo.
- `changed_functions[]` — `file, name (qualified with `::`), kind, role,
  line, fingerprint, status (added/changed/moved), moved_from,
  duplicate_of, old/new complexity, delta, classification, review`.
- `summary` — added/changed/moved/deleted counts, review and blocking,
  plus `review_unreceipted` (band entries with no receipt at all) and
  `receipt_errors` (count of receipt validation failures). The run exits 1
  when `blocking + review_unreceipted + receipt_errors > 0`.
- `untouched_debt` — counts of untouched functions by classification plus
  the ten highest scores (a full inventory belongs in CI artifacts).
- `failures[]` — blocking complexity offenders only,
  `file: name (cognitive complexity N > 15)`; receipt problems are surfaced
  via `receipt.errors`, `RECEIPT INVALID` and `NEEDS REVIEW RECEIPT` lines.

## Debt ledger (`ts-complexity-debt/1`, `--debt-out`)

The ledger is the untruncated inventory behind `untouched_debt`: every
function above the ok limit that this change did not touch (`kind
"untouched"`) plus debt carried by renamed or relocated bodies (`kind
"moved"`, matching the Go gate's `debt_summary` semantics). Entries are
`{file, function, complexity, kind, function_kind}` sorted by file, then
function; split into `functions_gt15` and `functions_11_to_15` with counts
in `summary` (`untouched_*`/`moved_*` per band, plus totals). The ledger
records debt; it never blocks, and unlike the report it carries a
`generated_at` timestamp.

## Fixtures

`scripts/quality/tests/complexity/ts_fixture_runner.mjs` builds throwaway
git repositories from `ts_fixtures/` (base/head, receipt and rename
scenarios, plus gate-wiring repos embedding an analyzer copy) and asserts
54 checks (42 controls + 12 mutants):

- the main repo (base/head) pins the changed-function control classes
  C1–C13: changed/added/moved/deleted bodies, nested-closure attribution,
  untouched debt, and pinned metric paths with exact scores — `switch`
  case-clause counting, `catch`-clause counting, class getter/setter/method
  bodies, async function and async arrow bodies; fingerprint stability
  under a whitespace/comment-only reformat; byte-determinism of two
  consecutive runs (C7);
- the receipt repo (`ts_fixtures/receipt/`) pins receipt enforcement: C8 —
  a valid stronger-model receipt clears the single review-band function
  (exit 0, `review: receipt-recorded`); R1–R10 — receipts failing exactly
  one validation class each (wrong source commit, wrong base commit,
  reviewer = implementer, weaker reviewer per `--model-order`, stale,
  unbound function, `reject` verdict, unknown verdict, malformed JSON,
  missing file) are all rejected with their precise error; R11 — without a
  receipt the band blocks (exit 1) with a `NEEDS REVIEW RECEIPT` line and
  `failures` stays complexity-only;
- the rename repo (`ts_fixtures/rename/`) pins rename/duplicate handling:
  C14 — a byte-identical copy (`heavyCopy`) of a surviving original
  (`heavyOriginal`) is `added` with `duplicate_of` and blocks at 16 > 15;
  C15 — `--debt-out` lists the untouched `heavyOriginal` and the renamed
  `legacyHeavyRenamed` (reformatted body, status moved) untruncated with
  per-kind counts; C16 — a function declaration renamed into a const
  function expression and a default export renamed into a re-exported
  arrow both stay moves; C17 — an unreadable changed file exits 2 naming
  the file (requires a non-root user, since root ignores file modes);
- mutation guards: every guarded control has a mutant (M1a–M6,
  M-switch/M-catch/M-class/M-async, plus M-receipt bound to R1 and M-dup
  bound to C14) that disables exactly one counting, extraction, receipt or
  duplicate path via a single exact-string replacement (target uniqueness
  asserted, crashed mutants rejected), and the battery passes only when the
  target control fails on that mutant — a disabled path cannot keep the
  battery green;
- gate-wiring controls (QG-C02-03) commit an analyzer copy at the base of
  each gate repo and drive the recipe extracted live from the product
  `Makefile` through `make`: an over-15 change without a receipt fails
  (W1–W2), a same-model receipt over 15 still fails (W3), the review band
  without a receipt fails (W4), a receipt bound to a different head commit
  is rejected (W5), a valid receipt passes via `TS_COMPLEXITY_RECEIPT`
  (W6), untouched debt passes with a changed ok body (W7), and a docs-only
  diff measures zero bodies (W8); routing checks (W9–W14) verify
  `quality.py` selects the gate for measured extensions under
  `web/dashboard/`, keeps it with the dashboard lane, excludes manifests
  and out-of-scope trees, includes it in the full profile, and never
  selects it for docs-only diffs. `test_ts_complexity_gate.py` binds the
  same invariants as a self-gate unit test.

Fixture coupling: C13 pins `files_changed_in_scope === 7` for the main repo;
the rename and receipt scenarios deliberately live in separate fixture
repositories so the main repo's changed-file census (and every existing
control) stays stable.

The fixture templates intentionally contain high-complexity bodies; they are
test inputs, not shipped logic, and are excluded from the analyzer's
self-check scope.
