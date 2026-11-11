# Go complexity differential analyzer

`go_complexity.py` measures added/changed/moved Go function bodies between a
base commit and the current working tree (head = committed + uncommitted +
untracked), scores each body with gocyclo-style cyclomatic complexity (the
classification metric; cognitive complexity is reported as informational),
and summarizes untouched legacy debt separately. It is the measurement core
for the Go complexity gate (QG-C01); wiring into `make quality-changed`
lands in QG-C01-03.

Python 3.9+ standard library plus the Go toolchain (used only to parse and
measure via `go_funcscan.go`; the product is never built).

## Usage

```bash
python3 scripts/quality/complexity/go/go_complexity.py \
  --base "$TASK_BASE" [--receipt receipt.json] [--report PATH|-] [--root DIR]
```

Exit codes: `0` all changed bodies within policy; `1` gate failure — a
changed body >15, an 11–15 body without an accepted receipt, or a rejected
receipt; `2` operational error (missing Go toolchain, git failure, head file
that cannot be parsed). A missing metric tool is a blocker, never a pass.

## Threshold decision (QG-C01-02)

| Band (cyclomatic) | New/changed body | Action |
| --- | --- | --- |
| ≤10 | ok | none |
| 11–15 | needs_review | passes only with an accepted review receipt |
| >15 | blocks | refactor, or a recorded bounded exception; a receipt alone never unblocks |

Thresholds live in the script (`CYCLOMATIC_OK_MAX = 10`,
`CYCLOMATIC_REVIEW_MAX = 15`) per the maintainability standard's 2026-11-10
owner decision.

## Review receipts

A receipt is the machine-checkable record of the independent
stronger-model review required for the 11–15 band. Schema
`go-complexity-review-receipt/1`:

```json
{
  "schema": "go-complexity-review-receipt/1",
  "source_commit": "<full 40-hex SHA of the analyzed head commit>",
  "base_commit": "<full 40-hex SHA of the analyzed base commit>",
  "implementer_model": "yabanin/glm-5.3",
  "reviewer_model": "<a strictly stronger model>",
  "review_date": "2026-11-10",
  "verdict": "approve-exception",
  "functions": ["path/to/file.go:FunctionName", "other.go:Recv.Method"]
}
```

Validation rejects any receipt with a precise, named reason (exit 1):

- unreadable file, invalid JSON, or not an object;
- `schema` other than `go-complexity-review-receipt/1`;
- `implementer_model`/`reviewer_model` missing or empty;
- `verdict` not one of `approve-exception`, `require-refactor`;
- `source_commit`/`base_commit` not a full 40-hex SHA, or not exactly the
  analyzed head/base commits (`source_commit mismatch: …`, `base_commit
  mismatch: …`);
- `review_date` not ISO `YYYY-MM-DD`;
- stale receipt: `review_date` strictly earlier than the source commit's
  committer date (same-day review is fresh; the receipt must not predate
  the reviewed source);
- `reviewer_model` equal to `implementer_model` (self-review), either model
  absent from the configured strength ordering, or the reviewer not
  strictly stronger than the implementer;
- `functions` entries that are not `file.go:Function` bindings.

A structurally valid receipt approves an 11–15 body only when its verdict
is `approve-exception` **and** its `functions` list binds that exact
`file:function`; otherwise the body still fails with the precise reason
(`receipt does not bind …` / `receipt verdict is 'require-refactor' …`).
For >15 bodies a valid approving receipt is recorded on the entry
(`exception_receipt_recorded`) and in the report for the bounded-exception
ledger — the run still blocks.

### Model strength ordering

The reviewer must rank strictly above the implementer in an ordered
allowlist. The script default lists the known coordination model only;
deployments widen it via `GO_COMPLEXITY_MODEL_ORDER` (comma-separated,
strongest first), which the report echoes as `model_strength_order`. A
model absent from the ordering can neither implement nor review, because
relative capability is then unproven.

## Moved, duplicate and carry policy

Function identity is the SHA-256 over the canonical AST print of receiver +
signature-without-name + body (see `go_funcscan.go`): formatting-,
comment- and blank-line-independent, because every position is printed
against a synthetic single-line file set — no extra blank-line
normalization is needed. A rename keeps identity; any signature, receiver
or body change does not.

- **Moved (original gone at head):** carries pre-existing debt without
  re-measurement (`classification: ok_moved_unchanged`, `from_file`/
  `from_function` recorded) and is listed in the `untouched_debt` ledger
  with `kind: "moved"` — reported, never blocking. At most one head
  function may claim a given base original as its move origin.
- **Moved + reformatted:** still recognized as moved (canonical hash is
  gofmt-stable; fixtures prove it).
- **Duplicate (QG-C01-02 loophole fix):** a hash match whose base original
  still exists at head with identical content is a free duplicate — it is
  measured as `added` (or `changed` when it replaced an existing slot)
  under the full thresholds, with `duplicate_of` naming the surviving
  original. Duplicate resolution is scoped to the changed head files the
  analyzer measures: a >15 copy whose original also lives in a changed
  file is always measured under the full thresholds; a copy whose
  original resides in an unchanged file is not resolvable as a duplicate
  and classifies as `moved`, landing in the `untouched_debt` ledger —
  non-blocking (`exit 0`), the debt still reported and visible.
- **Body changed during a move:** classified as regular content
  (`added`/`changed`) and fully measured.
- **Formatting-only edits:** produce no changed-function entries; they must
  not suppress existing findings either (debt summaries still run).

Known limitation: whole-tree duplicate detection — resolving duplicate
originals that live in unchanged head files — is deferred to the
gate-wiring follow-up (QG-C01-03); today such copies remain in the
untouched-debt ledger as visible, non-blocking moved debt.

## Report schema (`go-complexity-diff/2`)

- `analyzer` — name/version, go version, helper source hash, metric rules,
  moved/duplicate policy text, model strength ordering, receipt validation
  description.
- `run` — requested base, resolved `base_sha`, `head_sha`,
  `head_commit_date`, dirty flag, measured files, content digest
  (`measured_source_sha256`), base parse failures. No wall-clock fields:
  identical inputs and toolchain produce identical bytes.
- `receipt` — `null`, or the validated state: `rejected` with `reason`, or
  `accepted`/`valid_not_approving` with the bound fields echoed.
- `changed_functions[]` — `file, function, line, kind
  (added/changed/moved), old/new cyclomatic + cognitive, delta,
  classification (ok/needs_review/blocks/ok_moved_unchanged), and where
  relevant `receipt`, `receipt_reason`, `exception_receipt_recorded`,
  `duplicate_of`, `from_file`, `from_function`.
- `untouched_debt` — legacy and carried debt: counts plus the >15 list
  (capped), never blocking.

## Fixtures

`scripts/quality/tests/complexity/go_test_complexity.sh` builds throwaway
git repositories from `go_fixtures/*.go.tmpl` and asserts, with hand-counted
oracle values independent of the analyzer's own computation:

- clean pass, >15 blocking, receipt band and boundary 10, determinism
  (byte-identical reports), modified-move-measured-as-added (QG-C01-01);
- receipt validation (QG-C01-02): valid receipt passes 11–15; wrong
  source/base SHA, same model, weaker reviewer, stale date, unknown
  verdict, missing implementer model, unbound function and
  require-refactor verdict each block with a distinct precise error;
- duplicate-of-over-15 blocks as added content (`duplicate_of` recorded,
  original stays untouched debt); a valid receipt on it is ledger-only and
  still blocks;
- rename + reformat of a >15 function with the original removed is a move
  that carries into the debt ledger without blocking;
- same-file gofmt/blank-line-only change yields zero changed functions.

The fixture templates intentionally contain high-complexity bodies; they
are test inputs, not shipped logic, and are `.go.tmpl` so the module never
compiles them at rest.
