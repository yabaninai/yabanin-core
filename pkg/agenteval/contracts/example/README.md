# Example agent-eval run directory

This directory is a synthetic fixture for the version 1 agent-eval journal
contract. It demonstrates record shapes and relationships; it is not evidence
of a real provider call, a successful deployment, or a security evaluation.
The contract's [Go types](../contracts.go), [validator](../validate.go), and
[JSON schemas](../schema/) define the corresponding public interfaces.

## Files

| File | Records | Purpose | JSON Schema |
| --- | --- | --- | --- |
| [manifest.json](manifest.json) | One JSON document | Run identity, smoke profile, model arm, limits, price snapshot, and spend authorization fields | [Manifest](../schema/manifest.schema.json) |
| [episodes.jsonl](episodes.jsonl) | One | Completed episode with incomplete observed cost information | [Episode](../schema/episode.schema.json) |
| [calls.jsonl](calls.jsonl) | Two | One call with observed cost and one with unknown observed cost | [Call](../schema/call.schema.json) |
| [tools.jsonl](tools.jsonl) | Two | An executed read and a denied mutation | [Tool event](../schema/tool.schema.json) |
| [verdicts.jsonl](verdicts.jsonl) | One | The verdict identified by the episode's `verdict_ref` | [Verdict](../schema/verdict.schema.json) |

Each nonempty JSONL line is one JSON object. The manifest is a single JSON
object rather than a JSONL stream.

## Reading the example

The second call has `observed_usd: null` and `uncertain: true`. Unknown cost
must not be interpreted as zero. The episode records an estimated total of
`0.0105`, an unknown observed total, and `coverage: 0.5`. The validator requires
an uncertain flag for a successful call with unknown observed cost. Its cost
sum check compares an episode estimate with the sum of observed call costs
only when the estimate exists and no call has unknown observed cost.

The denied `run_shell` event includes `deny_reason: "not_in_allowlist"`.
Tool records use `args_digest` rather than raw arguments. A digest is a
reference to argument bytes, not encryption or proof that an operation ran.
The example's one executed tool and one denied tool event are distinct from
its `tool_calls: 1` episode usage counter.

`spend.authorized` is `false` and the spend limit is zero. Reading or validating
these files makes no provider calls and grants no permission to spend. The
model names, historical price snapshot, example endpoint, commit value, and
placeholder hashes illustrate the format; they must not be used as current
pricing or verified provenance. Referenced dataset selection and catalog files
are not included here, so this directory is not a runnable evaluation dataset.

## Validation

From the repository root, run the existing fixture checks:

```bash
go test ./pkg/agenteval/contracts -run '^(TestValidateHappyPathAndExampleFixtures|TestSchemasValidateExample)$' -count=1
```

For another run directory, call `contracts.Validate(dir)` from Go using the
package `github.com/reireirei/yabanin/pkg/agenteval/contracts`. It reads the
journal and checks the implemented cross-record constraints, including unique
record IDs, call/tool/verdict references to episodes, tool references to calls,
required reasons for denied tools, and the cost conditions described above.
See [validate.go](../validate.go) for the exact checks.

Also validate the manifest and every JSONL record against their corresponding
JSON Schema Draft 2020-12 schemas. Schema validation checks individual record
shapes; it does not replace the cross-file checks in `Validate`. The two tests
in the command above exercise these checks separately on this fixture.

Neither validation step executes a task or establishes that a recorded success
or safety verdict is true. `Validate` does not authenticate external source
commits, fetch referenced datasets, verify their hashes, or reconcile prices
with a provider. Use the records as an interchange example, with independent
evidence required for operational conclusions.
