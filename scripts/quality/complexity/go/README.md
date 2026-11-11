# Go complexity differential analyzer

`go_complexity.py` measures added/changed/moved Go function bodies between a
base commit and the current working tree (head = committed + uncommitted +
untracked), scores each body with gocyclo-style cyclomatic complexity (the
classification metric; cognitive complexity is reported as informational),
and summarizes untouched legacy debt separately. It is the measurement core
of the `go-complexity` gate (QG-C01), wired into `make quality-changed` since
QG-C01-03: any changed `.go` file (root or nested module) selects the gate.

Python 3.9+ standard library plus the Go toolchain (used only to parse and
measure via `go_funcscan.go`; the product is never built).

## Usage

```bash
python3 scripts/quality/complexity/go/go_complexity.py \
  --base "$TASK_BASE" [--receipt receipt.json] [--report PATH|-] [--root DIR]
```

Through the quality framework (what CI and `make quality-changed` run):

```bash
make _quality-go-complexity                    # base defaults to HEAD
QUALITY_BASE="$TASK_BASE" make _quality-go-complexity
```

The gate recipe writes the JSON report to stdout (`--report -`) and the
human summary to stderr, and forwards an optional receipt through the
`GO_COMPLEXITY_RECEIPT` environment variable (path to the receipt JSON;
keep receipts outside the tracked source tree — `artifacts/` is ignored).
The gate never writes files into the working tree.

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
`go-complexity-review-receipt/2` binds every approval to the exact
function bodies reviewed and to the active gate configuration, so a
receipt cannot survive a body edit, a rename-with-rewrite, or a threshold
change under the same function name:

```json
{
  "schema": "go-complexity-review-receipt/2",
  "source_commit": "<full 40-hex SHA of the analyzed head commit>",
  "base_commit": "<full 40-hex SHA of the analyzed base commit>",
  "implementer_model": "yabanin/glm-5.3",
  "reviewer_model": "<a strictly stronger model>",
  "review_date": "2026-11-10",
  "verdict": "approve-exception",
  "gate_config_sha256": "<64-hex digest of the decision-relevant gate config>",
  "bindings": [
    {
      "function": "path/to/file.go:FunctionName",
      "body_sha256": "<64-hex body hash from the gate report>"
    }
  ]
}
```

`gate_config_sha256` is `sha256` over the canonical JSON of the schema id,
both cyclomatic thresholds, and the body-identity scheme
(`body_sha256@signature-without-name+body`); the analyzer recomputes it on
every run and refuses receipts minted under a different configuration.
`body_sha256` values come from the gate report's `changed_functions[]`
entries, so receipts are minted from the same measurement they approve.

Validation rejects any receipt with a precise, named reason (exit 1):

- unreadable file, invalid JSON, or not an object;
- `schema` other than `go-complexity-review-receipt/2`;
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
- `gate_config_sha256` not equal to the digest of the active gate
  configuration (`receipt gate_config_sha256 does not match …`);
- `bindings` entries that are not objects with exactly `function`
  (`file.go:Function`) and `body_sha256` (64-hex).

A structurally valid receipt approves an 11–15 body only when its verdict
is `approve-exception` **and** one of its `bindings` matches that exact
`file:function` **and** its `body_sha256` equals the hash of the function
body being measured; otherwise the body still fails with the precise
reason (`receipt does not bind …` / `receipt body hash … does not match
the current function body; re-review required` / `receipt verdict is
'require-refactor' …`).
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
  original. Since QG-C01-03 duplicate resolution is whole-tree: the
  original counts as surviving when it lives anywhere in the head tree —
  its own file changed or untouched — so a >15 copy cannot escape
  measurement as a "move" by leaving its original's file out of the
  changed set.
- **Body changed during a move:** classified as regular content
  (`added`/`changed`) and fully measured.
- **Formatting-only edits:** produce no changed-function entries; they must
  not suppress existing findings either (debt summaries still run).

Unchanged files' own legacy debt (functions in files outside the changed
set) is not part of this diff's `untouched_debt` ledger — that ledger covers
untouched functions in changed files plus carried moves; whole-tree
baseline debt tracking is QG-C02 scope.

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
  (added/changed/moved), `body_sha256`, old/new cyclomatic + cognitive,
  delta, classification (ok/needs_review/blocks/ok_moved_unchanged), and
  where relevant `receipt`, `receipt_reason`,
  `exception_receipt_recorded`, `duplicate_of`, `from_file`,
  `from_function`.
- `untouched_debt` — legacy and carried debt: counts plus the >15 list
  (capped), never blocking.

## Fixtures

`scripts/quality/tests/complexity/go_test_complexity.sh` builds throwaway
git repositories from `go_fixtures/*.go.frag` and asserts, with hand-counted
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
- whole-tree duplicate resolution (QG-C01-03): a >15 copy whose original
  lives untouched in an unchanged file still blocks as added content
  (`duplicate_of` recorded), instead of escaping as a move;
- same-file gofmt/blank-line-only change yields zero changed functions.

Gate-wiring controls (QG-C01-03) drive the recipe extracted live from the
product `Makefile` through `make` in fixture repos: >15 without receipt
fails, invalid receipts fail (same-model over 15, stale over 11–15),
untouched debt passes, a valid 11–15 receipt passes via
`GO_COMPLEXITY_RECEIPT`, a docs-only diff measures zero bodies, and
`quality.py` routing selects the gate for `.go` diffs (root and nested)
and never for docs-only diffs. `test_go_complexity_gate.py` binds the same
invariants as a self-gate unit test.

The fixture templates intentionally contain high-complexity bodies; they
are test inputs, not shipped logic, and are `.go.frag` so the module never
compiles them at rest.
