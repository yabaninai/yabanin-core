import useBaseUrl from '@docusaurus/useBaseUrl';

# Offline spend audit (`yb audit`)

Analyze a local LLM request log without starting a gateway, database, or model
provider. `yb audit` estimates spend from logged usage and its available prices, then
simulates exact-cache reuse and cheaper tier routing. These are conditional
projections, not measured invoice savings or evidence of equivalent answers.

The supported CLI modes (`exact` and `off`) make no network calls. Building the
binary can download Go modules. Semantic simulation exists in the library but
is not wired into the CLI; starting an embedder does not enable it.

## Quickstart: a synthetic report

Install the Go version from the root `go.mod` (currently 1.27.3). From the
repository root, build the **operator CLI**, which contains `audit`:

```bash
go build -o bin/yb ./cmd/yb
```

Create a temporary directory and a tiny synthetic request log. The repeated
prompt illustrates exact reuse; the unknown model illustrates incomplete
pricing coverage. No credentials or customer data are used.

```bash
AUDIT_DIR="$(mktemp -d)"
cat > "$AUDIT_DIR/traffic.jsonl" <<'JSONL'
{"model":"claude-3-5-sonnet-latest","messages":[{"role":"user","content":"What is a cache?"}],"usage":{"prompt_tokens":20,"completion_tokens":12},"timestamp":"2026-01-01T10:00:00Z","status_code":200,"duration_ms":100}
{"model":"claude-3-5-sonnet-latest","messages":[{"role":"user","content":"What is a cache?"}],"usage":{"prompt_tokens":20,"completion_tokens":12},"timestamp":"2026-01-01T10:01:00Z","status_code":200,"duration_ms":80}
{"model":"synthetic-unpriced-model","messages":[{"role":"user","content":"Hello"}],"usage":{"prompt_tokens":5,"completion_tokens":4},"timestamp":"2026-01-01T10:02:00Z","status_code":200,"duration_ms":90}
JSONL

bin/yb audit "$AUDIT_DIR/traffic.jsonl"   --cache-mode exact --format html --no-prompts   --output "$AUDIT_DIR/report.html"
printf 'Open this local file in a browser: %s/report.html\n' "$AUDIT_DIR"
```

Expected result: a self-contained HTML report with **3 parsed requests**,
a single unpriced request, and an **insufficient sample** warning. That warning is expected
for this tiny fixture; its figures do not support a workload savings claim.
The unknown model is excluded from dollar totals rather than treated as free.

To inspect machine-readable output from the same input:

```bash
bin/yb audit "$AUDIT_DIR/traffic.jsonl" --cache-mode exact --format json --no-prompts
```

For your own data, replace the input path with an export you have reviewed.
The public source export does not include the private `datasets/audit/` fixture.
The <a href={useBaseUrl('/examples/audit-sample.html')}>historical synthetic
sample report</a> is a separate illustration; it is not the output of the
three-row example above, and its original dataset is not bundled publicly.

## Usage

```bash
# Markdown report (default) to stdout
yb audit path/to/traffic.jsonl

# JSON
yb audit path/to/traffic.jsonl --format json

# Self-contained HTML (no CDN, no JS) to a file
yb audit path/to/traffic.jsonl --format html --output report.html

# Exact mode is the supported offline default.
# Semantic simulation is a library capability; the CLI has no embedder wiring.

# Drop raw prompts from the report; inspect other identifying fields before sharing
yb audit path/to/traffic.jsonl --no-prompts

# Read from stdin
cat traffic.jsonl | yb audit -
```

Flags:

| Flag | Default | Meaning |
|---|---|---|
| `--format`, `-f` | `md` | `md`, `json`, or `html` |
| `--cache-mode` | `exact` | `exact` or `off`; `semantic` is recognized but rejected by this CLI |
| `--output`, `-o` | *(stdout)* | write the report to this file |
| `--max-records` | `5,000,000` | cap on ingested records |
| `--no-prompts` | `false` | drop raw prompt text after hashing |
| `--provider` | *(inferred)* | override provider inference for the whole file |

An invalid `--format` or `--cache-mode` is rejected, never silently defaulted.

## Input formats

The ingest auto-detects the format, or you can rely on the sniffing:

- **OpenAI-style JSONL** — one JSON object per line, in either the flat shape
  (`model`, `usage.prompt_tokens`, `usage.completion_tokens`, `messages`,
  optional `timestamp`, `status_code`, `duration_ms`) or the wrapped shape
  (`{"request": {...}, "response": {...}}`).
- **CSV** — header-driven; column names are matched to fields.
- **This gateway's format** — the JSONL/CSV emitted by Yabanin's own logger.

Malformed lines are counted and skipped; the command fails if no valid rows
remain. A symlinked input is followed and reported as such in data quality. When token counts are absent they are estimated
from text length at a fixed 4 chars/token, and the report discloses the share of
rows whose counts were estimated.

## The six sections

1. **Summary** — request count, total cost (input/output split), unpriced
   requests (excluded from all dollar totals, never priced at $0), the window,
   top models, top providers.
2. **What we found** — the measured findings: spend concentration
   (p50/p90/p99 + top-1%/10% share), repeated-prefix bloat, top prompt clusters,
   retry storms, error waste, max_tokens over-provision, tail latency,
   model-mix drift. Only findings above threshold are listed; none is padded with
   adjectives.
3. **Cache simulation** — hit rate, tokens avoided, dollars avoided, per-model
   hit rates. Exact reuse is still a projection, not a check that a cached
   answer would satisfy a new request.
4. **Routing simulation** — the class distribution (easy/medium/hard) from the
   in-process rule-tier classifier, routing-only savings, routing-on-misses
   savings, and the combined figure with the overlap stated explicitly.
5. **Data quality** — parsed/skipped counts, share with real token counts,
   share with timestamps, unpriced request count, and the unpriced model names.
6. **Recommendations** — every rule that fired, verbatim, anchored to the number
   that triggered it. No recommendation is printed unless its finding is in the
   data.

## Cache and routing: production order, no double-counting

The combined savings figure applies the two optimizations in the same order the
gateway applies them in production: **cache first, routing to cache-misses
only.** The report states three numbers so a reader cannot double-count:

- **Cache-only** — dollars the cache alone would have avoided.
- **Routing-only** — dollars tier-routing would have saved if *every* request
  were routed.
- **Combined** — cache-only + routing-on-misses. The **overlap**
  (routing-only − routing-on-misses) is the amount that would be double-counted
  if you naively added cache + routing, and it is stated explicitly.

A request never contributes a routing saving when its target model has no known
price (it is dropped and counted), when the target equals the original model, or
when the target is not cheaper. Unknown models are never silently priced at $0.

## Cache modes

- **`exact`** (default) — keys on the production prompt hash. No dependencies,
  fully offline, no network.
- **`semantic`** — the library simulator requires an injected `EmbedFunc`. The CLI does not wire an embedder and rejects this mode explicitly; starting an embedder service alone does not enable it.
- **`off`** — skip the simulation; routing-on-misses then equals routing-all.

## Determinism

For the same binary, pricing data, input, and mode, figures and ordering are
intended to remain stable. The `generated` timestamp changes between runs.
Record the source revision and pricing fingerprint alongside any archived
report so a later run can identify changes in code or pricing.

## Insufficient sample

The report carries a hard **insufficient sample** banner when the input has fewer
than 50 requests, or a window shorter than 24 hours (or no window at all). The
banner is a fact about the sample, not a suggestion: the figures are still shown,
but the report flags that they are not statistically reliable.

## Pricing and privacy limits

The release excludes LiteLLM pricing data. The default reference catalog contains
independently verified Nebius entries subject to their validity and review dates;
a small historical Anthropic fallback remains. This is limited coverage, not a
current market-wide price list. The example above uses that historical fallback
only to demonstrate reporting; its rates are not current provider quotes.

The report identifies its pricing source and SHA-256 fingerprint.
An unknown upstream verification date remains unknown. Usage-based list-price
estimates do not reconcile provider invoices, negotiated rates, service tiers,
or provider-specific cached-input discounts. Review price coverage and the
age of the data before interpreting a result.

`--no-prompts` drops raw prompt text after hashing. It does not anonymize model
names, source paths, timestamps, or derived findings. It can also reduce the
information available to prompt-based classification. Inspect the entire
report before sharing and explain that limitation when quoting routing
projections.

## Failures and troubleshooting

| Result | Meaning and next action |
| --- | --- |
| `unknown command "audit"` | Use the `yb` executable built from `cmd/yb`, not the `yabanin` server binary. |
| Input file cannot be opened | Check the path and read permissions. The examples preserve the temporary path in `AUDIT_DIR`. |
| No valid records | Correct the input shape; a file containing only invalid rows fails. |
| Some skipped rows | Inspect Data quality before treating totals as coverage of your export. |
| Unknown model price | Supply a supported model identifier where appropriate; never reinterpret missing price as zero. |
| Semantic audit unavailable | Use `--cache-mode exact` or `off`. There is no CLI embedder setting in this preview. |
| Insufficient sample | Gather a representative longer request window; a small example can still validate the file-to-report workflow. |

The analyzer does not modify its input, call a model to compare answers, or
establish that a proposed cheaper model meets your quality requirements.
