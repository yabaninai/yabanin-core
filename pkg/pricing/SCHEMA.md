# Reference pricing schema (CORE-REF-01)

Status: implemented. The built-in serving projection uses the committed
primary-source reference pack, subject to verification and freshness gates.

This document is the normative prose for `pkg/pricing/schema.go`. Where the
two disagree, fix one of them in the same commit — the intent is that an
operator can validate a snapshot by reading either.

## Purpose

Yabanin needs its own reference snapshot of model prices and metering units:
independently assembled from primary provider sources and verified
contractual rates, never invented, and never a rename of a third-party
aggregator's catalog.
The committed reference pack contains independently verified Nebius records;
operators may import their own snapshots with their original attribution.


The schema describes **public list prices only**. Client actuals (quotes,
ledger, `QuoteRecord`) and contractual overrides (`reseller_pricing`,
markup) are separate data planes and deliberately have no fields here.

## Vocabulary

- `Catalog` — one immutable reference snapshot. Header fields:
  `schema_version` (must be `RefSchemaVersion` = 1 for this consumer),
  `version` (operator-assigned revision), `generated_at`, `source` (how it
  was assembled), `reviewer`, `review_sla_days`, `supersedes` (digest of the
  replaced snapshot; empty for genesis), `digest` (SHA256 over the canonical
  form, see below), and `models`.
- `RefModel` — one entry: a `(provider, model)` identity plus optional
  scoping fields `region`, `tier`, `context_band` ("" = default). Identity
  has two planes; see [Model identity](#model-identity) below.
- `RefModel.aliases` — alternative names resolving to the entry. Aliases
  never carry their own rates. Exact names always win resolution
  (`ResolveModel`); the validator rejects an alias equal to any model name
  in the same provider and vice versa. Aliases resolve by exact string
  match, so an alias with leading or trailing whitespace is a validation
  error (never silently trimmed): what validates is exactly what resolves.
- `RefModel.currency` — ISO-4217; **v1 accepts USD only** (the runtime
  accounting is USD; multi-currency is a later, explicit change).
- `RefRate` — one priced axis: `axis` (closed vocabulary), `unit` (must be
  the axis's paired unit), `amount` (*float64), `evidence`.
- `RefEvidence` — one source's observation: `ref` (must match one of the
  entry's sources), `amount`, `at`.
- `RefSource` — primary source: `kind` (`url` or `internal_evidence`),
  `ref`, `verified_at`, `note`.
- `RefConflict` — resolution of a source disagreement: `axis`, `ref` (the
  chosen source), `reason`.

## Model identity

Two planes, pinned by `schema_identity_test.go`:

- **Validation identity** is exactly the two-part `(provider, model)` pair,
  compared as written — no trimming, no scoping fields. `ValidateCatalog`
  rejects a second entry with the same pair as
  `models[1]: duplicate entry for openai:gpt-4 (first at models[0])` even
  when it differs from the first only in `region`, `tier` or
  `context_band`. A valid v1 catalog therefore cannot carry per-region
  (or per-tier, per-band) variants of one pair.
- Provider and model spellings are not trimmed and padding is not a
  finding for them (unlike aliases, which reject padding): `" openai"` +
  `"gpt-4"` and `"openai"` + `"gpt-4"` are two distinct validation
  identities, and a catalog holding only one of them validates.
- **Merge/canonical identity** is the full five-part key
  `(provider, model, region, tier, context_band)`: `MergeCatalogs` unions
  entries by it and `CanonicalCatalogJSON` sorts by it. A merge hence
  appends a scoping variant of an existing pair instead of merging it —
  and the merged snapshot then fails `ValidateCatalog` on the two-part
  key above.

The runtime model-catalog document (`pkg/upstream`) is a separate schema
with its own rule: its identity is the trimmed two-part `(provider, model)`
pair, and whitespace-padded spellings are rejected at load.

### Axes and units (closed sets)

| axis | unit | meaning |
|---|---|---|
| `input` | `per_1m_tokens` | prompt tokens |
| `output` | `per_1m_tokens` | completion tokens |
| `cache_write` | `per_1m_tokens` | prompt-cache write tokens |
| `cache_read` | `per_1m_tokens` | prompt-cache read tokens |
| `audio_second` | `per_second_audio` | input audio seconds (transcription) |
| `character` | `per_character` | input characters (text-to-speech) |
| `image` | `per_image` | generated images |

An unknown axis is a validation error, never silently dropped — a silently
ignored axis would price a billable dimension at zero. At most one rate per
axis per entry.

## The three states of a rate

1. **Absent** — the entry has no rate for the axis: the entry does not
   price this dimension at all.
2. **Explicitly unpriced** — the axis is present with `amount: null`: the
   dimension is known but no verified price exists. Consumers must treat
   this as *unknown*, never as free.
3. **Number** — `amount: 0.0` is a legitimate explicit free. Any other
   value must be finite and non-negative.

No conversion or adapter may collapse 2 into 3. The legacy formats cannot
distinguish "free" from "no price" (see §Conversion).

## Lifecycle, windows, review

- `status`: `draft` (never serveable), `active` (serveable inside its
  window), `retired` (never serveable, even with an open window —
  deactivation dominates the window).
- Effective window is half-open `[effective_from, effective_to)`; empty
  bound = open on that side. `effective_to` must be strictly after
  `effective_from`.
- Active entries require at least one primary source and a
  `verified_at` instant. Draft entries do not (that is what review is for).
- `review_sla_days` on the catalog: entries whose `verified_at` is older
  are reported by `StaleModels` as an operational signal. Staleness is not
  a validation failure — a stale price is still the best known price.

## Conflicts

If a rate's evidence contains two observations with different amounts
(compared at 1e-12 storage precision — sub-picodollar rounding noise
agrees), the conflict must be resolved: `amount` set to one observed value
(exactly) and a `RefConflict` recording the chosen source ref and a
non-empty human reason. The validator rejects unresolved conflicts; it does
not pick a winner silently.

## Digest and rollback chain

- `CanonicalCatalogJSON` renders the snapshot with all orderings normalized
  (models sorted by provider/model/region/tier/context band; rates in
  canonical axis order; aliases, sources, evidence, conflicts sorted). The
  `digest` field itself is excluded from the input.
- `CatalogDigest` = SHA256 over that canonical form. Loaders must verify a
  snapshot's `digest` against its content instead of trusting the field.
- `ValidateCatalogChain(prev, next)` requires `next.supersedes ==
  CatalogDigest(prev)` — the rollback chain cannot silently rewrite
  history.

## Pack envelope (reference-pack-v1)

`refpack.go` wraps a sealed snapshot in a verifiable offline envelope. The
committed pack is `snapshots/reference-pack-v1.json`, regenerated by
`make pricing-pack` and verified by `make pricing-verify`; both are
hermetic — local files only, no network. `pricing-refresh` explicitly refuses
to restore excluded data; operators import their own files with recorded provenance.

Envelope fields, in fixed struct order (no maps on the output path):

- `pack_schema_version` — `1` (`RefPackSchemaVersion`);
- `catalog` — the sealed snapshot body, lifted **verbatim** from the
  committed genesis (compact canonical form, `digest` included);
- `catalog_digest` — the snapshot's own sealed digest, pinned into the
  envelope;
- `pack_sha256` — SHA256 over the envelope bytes with this field present
  and empty;
- `notices` — sorted, deduplicated build notice refs (e.g. in-tree NOTICE
  paths).

Contract, fail-closed everywhere:

- `BuildRefPack` refuses an unsealed input (empty `digest`) — packing is
  the last step, sealing comes first;
- `LoadRefPack` re-checks all three layers independently and reports
  expected-vs-actual on mismatch: schema version, `catalog_digest` over
  the body, `pack_sha256` over the envelope; a stripped `pack_sha256`
  field is refused outright, never treated as "no digest yet";
- `VerifyRefPackChain(prevPack, nextPack)` is the catalog chain check
  over pack envelopes — a successor that names a digest its predecessor
  does not have is refused, in both load and rollback directions. Rolling
  back is legitimate only as a **new** snapshot restoring prior content
  with `supersedes` naming the digest it undoes;
- `MarshalRefPack` is deterministic and wall-clock-free: identical
  content produces byte-identical envelopes regardless of input slice
  order (canonicalization covers model, alias and axis ordering);
- `RefDiff(oldCatalog, newCatalog)` renders the promotion diff in
  canonical identity order with a stable `summary:` line. Its refusal
  gate covers draft→active promotions only: a draft promoted to active
  without a reviewer, or without at least one primary source, is
  refused. An active→active rate change with no reviewer is rendered,
  not refused — such edits are caught at review, not gated by the diff
  (an active entry without a primary source remains refused at load, by
  `ValidateCatalog`; the diff is the promotion gate a reviewer reads).

Offline tooling: `yb pricing pack --catalog <sealed.json> --out <pack>`
(notice refs repeatable via `--notice`), `yb pricing verify --pack
<pack>`, `yb pricing diff --old <pack> --new <pack>`, `yb pricing chain
--prev <pack> --next <pack>`. The `verify` stdout is the provenance label
form: `catalog: yabanin-catalog@<version> <generated_at> sha256:<digest>`.

## Validation

`ValidateCatalog` reports every problem at once (`CatalogError.Problems`,
located by path). A snapshot with any problem is rejected as a whole — no
partial acceptance. Validation is deterministic and wall-clock-free: review
staleness is `StaleModels`' job, not the validator's.

## Conversion from the legacy formats

`CatalogFromPriceFile` / `CatalogFromUnitFile` / `MergeCatalogs`
(`schema_convert.go`) map `PriceFile` / `UnitFile` onto this schema. The
lossy contract, in force since CORE-REF-01:

- legacy zero on `input`/`output` → explicitly unpriced (`amount: null`,
  never free); a genuinely free legacy model must be re-verified from the
  primary provider during review;
- legacy zero on cache axes → axis absent (in the legacy format zero
  uniformly means "not offered" for caches);
- the legacy files carry no per-source evidence, so converted rates have
  none; provenance is entry-level (one internal source record naming the
  legacy snapshot);
- converted entries are `draft` with the legacy snapshot date as
  `verified_at` — conversion output is never auto-serveable; review is the
  gate.

`MergeCatalogs` unions by full identity, merging aliases/sources and
per-axis rates; two different amounts on the same axis are an error for
the operator to resolve in the source data, never a silent pick. The one
documented resolution is `null` vs a number: the verified number wins,
because an explicitly-unpriced axis is unknown, not contradictory — and
`null` vs `null` stays `null`. Converted catalogs are `draft`, so this
resolution is always reviewable before any entry serves.

## Serving flip (CORE-REF-04)

Since the defaults flip, the process default pricer
(`pricing.DefaultFilePricer`) serves the reference catalog projection
(`refserve.go`, embedded committed pack), not the legacy bundled corpus:

- Projection is serveability-gated (PRECEDENCE §5): ACTIVE entries only,
  with a verified source, inside the effective window, and non-stale
  (entry-level `verified_at` + `review_sla_days`, same boundary as
  `StaleModels`). Draft and retired entries never serve.
- An active serveable entry must price input AND output; a missing token
  price refuses the projection (fail closed) — an unknown price never
  projects as free. Cache axes absent from the entry project as 0, which
  the legacy file semantics read as "not offered".
- The pricer cites `yabanin-catalog@<version>` with the generation date and
  the sealed catalog digest (`FilePricer.Provenance`), and carries the
  structured citation (`FilePricer.CatalogProvenance`) that admin report
  payloads expose as `pricing_catalog` (`pkg/adminstore/savings.go`).
  Surfaces render the collapsed node `catalog:<version> digest:<prefix>`.
- Time-dependent gates are evaluated once at load; the embedded pack bytes
  stay deterministic. Historical quotes, usage, invoices and ledger entries
  are never re-evaluated: their stored costs and provenance are immutable,
  and tenant overrides (`SetDefaultPricer`, `SetDefaultFilePricer`) keep
  precedence above the default.
- `LoadBundled` is a compatibility alias for the primary catalog projection.
  The offline external-source seam also serves this projection. No built-in
  non-token rates ship: `DefaultUnitPricer` returns unknown until explicitly
  replaced with a validated operator snapshot.
- Automatic historical fallback is limited to the five independently authored
  Anthropic identities in `lookupHistoricalPrimary`; removing third-party
  drafts never enables the old OpenAI table prices. An absent rate is unknown,
  not free. Explicit operator pricers and provider-alias precedence remain.


## Data-plane boundaries

- **Reference (this schema)**: public list prices, provenance, review.
- **Actuals**: quotes/settlement (`pkg/pricing/quote_report.go`), cost
  analytics, events. Reads reference data; never writes it.
- **Contractual**: `reseller_pricing` markups, fixed org rates
  (`pkg/pricing/markup.go`, `pkg/adminstore/resale_pricing.go`). Overrides
  reference rates per org; never mutates them.

## Consumer inventory

The complete pinned inventory of current consumers lives in
`artifacts/internal-delivery-program/CORE-REF/inventory.md` and is enforced by
`pkg/pricing/consumers_test.go` (every row pinned by file + symbol; the
markdown must mention every ID).
