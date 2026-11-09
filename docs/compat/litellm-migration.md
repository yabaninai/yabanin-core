# LiteLLM proxy-config migration

`yb migrate-litellm` moves model routing configuration from a
[LiteLLM](https://docs.litellm.ai/) proxy config into a Yabanin catalog
document. The flow is review-first: a dry-run produces a report, a human
reviews it, and only that reviewed report can be applied. Raw LiteLLM
configuration is never applied directly. Recognized credential fields and
credential patterns are redacted; this does not detect every possible
secret. Review reports and outputs for sensitive content before sharing them.

## Pricing data

The public release does not bundle LiteLLM's price corpus or prices derived
from it. Routing configuration migration remains available and does not
install a price catalog. Missing prices mean **unknown cost**, not free
inference.

To convert a price file you have obtained and reviewed yourself, use the
local import commands. They read the specified file; they do not download
prices or activate the resulting file:

```bash
yb pricing import-litellm --in /path/to/model_prices.json \
  --out /path/to/operator-token-prices.json \
  --source 'operator-reviewed source and revision' --date 2026-11-09
yb pricing import-litellm-units --in /path/to/model_prices.json \
  --out /path/to/operator-unit-prices.json \
  --source 'operator-reviewed source and revision' --date 2026-11-09
```

Replace the paths, source and date with those of your actual reviewed input.
Keep generated files outside the source checkout and preserve applicable
upstream notices. Review the conversion report before using the output;
unsupported modes and tiers are not silently treated as supported prices.
The former `make pricing-refresh` target now refuses to repopulate the
release's bundled data.

## Commands

### 1. Dry-run (read-only)

```bash
yb migrate-litellm dry-run --config litellm_config.yaml --out report.json
```

Analyzes the proxy config and writes a migration report: what transfers
(model deployments → catalog rows), what differs semantically, what
conflicts, what is unsupported, which secret locations were redacted, and a
derived transfer plan. Nothing is written except the report file. The stats
line goes to stderr; use `--format text` for a human-readable report.

### 2. Apply (preview by default)

```bash
# preview: prints exactly what the apply would do, writes nothing
yb migrate-litellm apply --report report.json --catalog catalog.json

# execute the reviewed plan
yb migrate-litellm apply --report report.json --catalog catalog.json --yes
```

The apply gate re-verifies the whole report before touching anything. It
refuses — with every problem listed and nothing written — when the report
schema or source format is unexpected, summary counts disagree with the
finding lists, a plan entry cites a source that is conflicted, unsupported,
or not a verified transfer, an alias collides or shadows a model name, a
capability or limit is outside the catalog vocabulary, or the current
catalog or ledger file does not parse. A report with zero plan entries is a
refusal, never a silent success.

Apply semantics per plan row:

- Rows are matched by `(provider, model)`. Missing rows are inserted;
  existing rows are updated **only** in the fields the report carries
  (capabilities, `max_tpm`/`max_rpm`/`max_output_tokens`); aliases are
  unioned. Price, context window, deprecation and all other vendor data are
  preserved. Nothing is ever deleted or unset.
- Re-applying the same report is a byte-stable no-op: identical outputs, no
  duplicate ledger entries, no writes at all.

### 3. Rollback

```bash
yb migrate-litellm rollback --catalog catalog.json
```

Restores the exact pre-apply bytes of both touched files (catalog and
ledger), including the "did not exist" state. Backups are kept after a
successful apply precisely so this rollback is always available; they are
removed only after a verified restore.

## Files

| Path | Purpose |
|------|---------|
| `catalog.json` | Target catalog document (created if absent) |
| `catalog.litellm-apply-ledger.json` | Apply ledger — every applied plan row with content digests (default path; override with `--ledger`) |
| `catalog.json.litellm-backup` | Pre-apply catalog bytes (zero-length = file did not exist) |
| `catalog.litellm-apply-ledger.json.litellm-backup` | Pre-apply ledger bytes |

If a write fails after the catalog has changed, the command attempts to
restore its pre-apply state and reports the failure. Restoration can also
fail; in that case, inspect both target files and the retained backups
named in the error before attempting recovery. Available backups are kept.
While a backup set exists, the next `apply` refuses loudly — run `rollback`
or remove the backups explicitly after inspecting them. A rollback refuses
to touch anything when the backup set is inconsistent (exactly one backup
present).

## Guarantees

- **Review gate**: only verified, conflict-free plan entries from a reviewed
  dry-run report can ever reach the catalog.
- **Redaction**: recognized credential fields are redacted at dry-run time;
  source values included in findings are also scrubbed for supported
  credential patterns. Values outside those rules may remain visible, so
  review reports and outputs for sensitive content before sharing them.
- **Determinism**: the same report applied to the same state produces
  byte-identical outputs and previews; no timestamps are embedded anywhere.
- **Reversibility**: rollback restores byte-identical pre-state, verified by
  re-read.

## Negative contract (cause → expected result)

These scenarios are pinned by `pkg/clientconfig/litellm_negative_test.go`;
each pairs a source state with the behavior an operator must observe.

- **Newer LiteLLM adds unknown fields** (limit- or route-shaped names under
  `router_settings`, `litellm_settings`, `model_info`, `litellm_params` or
  deployment level) → every such field is reported as an `unsupported`
  finding with its exact source path and a refusal naming the pinned
  compatibility matrix section. It never silently disappears, never enters
  the plan, and is never cited by a plan entry — so an apply of that report
  cannot carry it. Both the text and JSON renderers list every unsupported
  path.
- **Limit value would silently change meaning** (`tpm`/`rpm` of `0` reads as
  *block all traffic* in LiteLLM but *unset/unlimited* in a catalog;
  negative bounds are invalid on both sides; non-integer values cannot
  transfer) → each is a `conflict` finding at the exact path, the finding
  explains the inversion, and the deployment is excluded from the plan. A
  deployment whose only problem is a zero `model_info.max_output_tokens`
  still transfers its verified identity row, but never the bound itself
  (catalog absence of the field is semantically identical to the source
  zero).
- **Operator asks what happens to users, logs or spend** → every report —
  clean or adversarial — carries an explicit scope statement: model rows,
  model-group names and per-model limits migrate; user accounts/teams/proxy
  keys, request and usage logs, and spend tracking/financial history are
  listed as NOT migrated with a reason. The plan DTO has a closed field
  vocabulary (action/provider/model/aliases/capabilities/limits/
  source_paths), so no user, log or financial entity can ride along.
- **Config contains nothing verified to transfer** → the dry-run still
  produces a full report (status is never a false success), the plan is
  empty, and `apply` refuses with `report carries no plan entries` —
  creating nothing on disk.
- **Credential-shaped field under an unknown name** (connection strings,
  `*_secret`, `*_api_key`, bearer-style tokens, in any section) → the field
  is treated as a secret: it enters the redaction ledger by path and field
  name, its refusal finding carries the `[REDACTED]` marker instead of the
  value, and no renderer — text or JSON — emits the raw value.

## Consumer contract

Pinned by `pkg/trcli/litellm_integration_test.go`: the operator-facing
surface (CLI) and the data-facing surface (catalog document) agree with the
report DTO.

- **Report before apply**: the dry-run writes the reviewed report file
  before any apply is attempted; a preview-only `apply` writes nothing
  anywhere in the working directory; an `apply --yes` prints the preview
  before the result, so the executed plan is always visible in the output.
- **Verified semantics or explicit refusal**: every catalog entity the
  apply writes is traceable to a verified transfer in the reviewed report —
  provider/model identity, aliases (client-facing group names plus resolved
  `router_settings.model_group_alias` entries), capability flags from the
  pinned `mode` mapping, and limit values verbatim. Refused
  (router-owned features, credentials), unsupported (unknown fields) and
  redacted sources never appear in the catalog bytes — not as keys, not as
  values.
- **DTO agreement**: the text and JSON renderers carry the same summary,
  scope and finding paths; the on-disk JSON report round-trips into the
  typed DTO the apply consumes; JSON apply output is two documents
  (preview, then result) whose entries match the plan and each other.
- **Exit codes**: `0` on success (dry-run, preview no-op, applied apply,
  idempotent re-apply, rollback); `1` on every refusal and usage error,
  with all problems listed on the error output and nothing written.
