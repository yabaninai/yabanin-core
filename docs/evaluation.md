# Offline evaluation

The `yb` CLI can evaluate the rule-tier classifier and guard detectors against
local labeled data. These flows do not start a gateway or call a model. They
help detect specific regressions; they do not measure full production routing,
model quality, or protection against every sensitive-data pattern.

Core includes a synthetic regression corpus in `datasets/eval/`. Run
`make evaluate-routing` and `make evaluate-guards` to check the committed
classifier baseline and guard precision/recall thresholds. These checks require
no private datasets, gateway, or provider account. See the
[dataset scope](../datasets/eval/README.md) before interpreting their results.
You can also evaluate your own local inputs with the CLI, as below.

## Build and create a workspace

Use the Go version in `go.mod` and Python 3. From the repository root:

```bash
go build -o bin/yb ./cmd/yb
EVAL_DIR="$(mktemp -d)"
```

Building can download Go modules; evaluating the resulting local fixtures is
offline. The examples are deliberately small and synthetic. A passing result
validates the workflow, not a representative quality claim.

## Rule-tier classifier regression

Each JSONL row requires a unique non-empty `id`, a non-empty `prompt`, and
`expect_class` set to `easy`, `medium`, or `hard`.

```bash
cat > "$EVAL_DIR/routing.jsonl" <<'JSONL'
{"id":"easy-1","prompt":"What is a cache?","expect_class":"easy"}
{"id":"medium-1","prompt":"Hello there","expect_class":"medium"}
{"id":"hard-1","prompt":"Debug this failing program","expect_class":"hard"}
JSONL

bin/yb evaluate routing --golden "$EVAL_DIR/routing.jsonl"   --save "$EVAL_DIR/routing-baseline.json"
bin/yb evaluate routing --golden "$EVAL_DIR/routing.jsonl"   --against "$EVAL_DIR/routing-baseline.json" --max-mismatch 0
```

Expected output includes `OK: all 3 golden rows match their expected class`.
`--save` requires a **file path** and records the classifier's actual output;
it is not a boolean flag. Review the recorded classes before accepting a
baseline. The evaluator runs `rule_tier` in process; it does not resolve real
model IDs, execute organization routing policies, or compare model responses.

**Exit behavior matters:** expected-label disagreement is printed but does not
by itself cause a nonzero exit in this preview. `--max-mismatch` enforces a
failure only when `--against` supplies a saved baseline. New rows missing from
that baseline count as mismatches. Removed rows are not counted by that
comparison; review changes to the dataset itself.

To demonstrate a failing regression against the saved baseline:

```bash
python3 - "$EVAL_DIR/routing.jsonl" "$EVAL_DIR/routing-changed.jsonl" <<'PYTHON'
import json
import sys
from pathlib import Path
rows = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
rows[0]["prompt"] = "Debug this failing program"
Path(sys.argv[2]).write_text("".join(json.dumps(row) + "\n" for row in rows))
PYTHON

if bin/yb evaluate routing --golden "$EVAL_DIR/routing-changed.jsonl"   --against "$EVAL_DIR/routing-baseline.json" --max-mismatch 0; then
  echo 'Unexpected success: inspect the classifier and baseline.' >&2
  exit 1
else
  echo 'Expected nonzero result: inspect the routing regression message above.'
fi
```

The message should identify one class mismatch against the baseline. Other
errors, such as an unreadable input, also exit nonzero; inspect the diagnostic
rather than treating any failure as proof of regression detection.

## Guard detection with a pinned revision

Guard evaluation scans each sample and compares any detection with its
`detect` or `clean` label. It reports true positives, false positives, false
negatives, precision, and recall, with a breakdown by the supplied `type`.
It does not prove the detector selected the right sensitive-data category.

Generate a synthetic two-sample revision. The marker below is constructed
locally and is not a real credential:

```bash
python3 - "$EVAL_DIR/guards-revision.json" <<'PYTHON'
import json
import sys
from pathlib import Path
revision = {
    "schema_version": 1,
    "dataset_id": "demo-guards",
    "samples": [
        {"id": "detect-1", "payload": {
            "text": "synthetic marker " + "sk-" + "abcdefghijklmnop12345678",
            "type": "secret", "expect": "detect"}},
        {"id": "clean-1", "payload": {
            "text": "ordinary synthetic text", "type": "clean", "expect": "clean"}},
    ],
}
Path(sys.argv[1]).write_text(json.dumps(revision, indent=2) + "\n")
PYTHON

bin/yb evaluate guards --revision "$EVAL_DIR/guards-revision.json"   --min-precision 0.98 --min-recall 0.90
```

Expected result: one true positive, no false positives or false negatives,
precision and recall of 1, and exit code 0. This tiny fixture is a smoke check;
build a representative corpus before using those thresholds as policy.
Misclassified rows can include text excerpts in the report. Use synthetic or
properly reviewed data and inspect output before sharing it.

The report includes the dataset ID and a lowercase SHA-256 `revision_id` of
the exact bytes evaluated. Preserve the revision file and record its hash with
the source commit and metrics. A content hash identifies input; it does not
certify the quality or provenance of its labels.

The revision format accepts at most 8 MiB and 10,000 samples. It requires
schema version `1`, non-empty dataset/sample IDs, unique sample IDs, and an
object `payload` with non-empty `text` and `expect` set to `detect` or `clean`.
Unknown fields, duplicate JSON keys, malformed/trailing JSON, and duplicate
sample IDs are rejected before metrics are printed. The CLI hashes and
evaluates the same in-memory snapshot.

For a plain JSONL corpus instead, each row has `text`, `type`, and `expect`:

```bash
# Replace this path with your reviewed local corpus.
bin/yb evaluate guards --corpus /path/to/guards.jsonl   --min-precision 0.98 --min-recall 0.90
```

Choose either `--corpus` or `--revision`; supplying both is an error. Precision
below its threshold or recall below its threshold fails the command. A zero
denominator is reported as zero, so an all-clean fixture alone cannot produce
a passing recall result with the default threshold.

## Use in CI

Keep reviewed datasets and routing baselines in your own repository. Build
`yb` from the selected source revision, then run the explicit `--golden`,
`--against`, and `--revision` commands above with those committed paths.
Preserve exit codes and archive outputs, dataset hashes, and the source commit.
Dependency installation during the build can need network access even though
the evaluation itself is offline.

Review a baseline change as a behavior change; regenerating it after every
failure removes its value as a regression check. Include positive, negative,
and boundary samples. Keep operational tests for routing, authorization, and
real-provider behavior separate from these narrow local evaluations.

The CLI also exposes `yb evaluate FILE` for comparing structured model-output
pairs. That is a separate evaluator with its own input format; inspect
`bin/yb evaluate --help` before using it. The fixtures on this page apply only
to the `routing` and `guards` subcommands.
