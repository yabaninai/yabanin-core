# Precedence: reference pricing catalog vs models registry (CORE-REF-02)

Normative for every consumer that touches both `pkg/pricing` catalog data
and the models registry. The ownership split below is the R1 answer to
"whose field wins" — recorded here because the split is load-bearing for
the preview flip (CORE-REF-04) and must survive refactors.

## Authority split

The reference pricing catalog is the **rate authority**: what a token,
character, image or audio second costs. The models registry is the
**routing-config and identity authority**: which models exist, which one
serves a request, and what they can do.

1. **Rates.** The pricing catalog wins for every priced axis. The registry
   must not carry rates; if a registry row seems to, it is stale or
   out-of-scope data and the catalog value is the one that bills.
2. **Routing.** The models registry wins for which model serves a request.
   The catalog is not a routing table: presence in the catalog never makes
   a model routable, and absence never blocks a routed model (it prices as
   unpriced, which is "unknown", never free).
3. **Identity and capabilities.** The models registry wins for context
   windows, modalities, precision and every other capability fact. Catalog
   v1 deliberately has no such fields; console capability notes stay in the
   evidence record, not in rate entries.
4. **Alias resolution.** An alias resolves to its target entry's identity
   and that entry's rates. An identical model name never inherits a price
   through another entry's alias (`ResolveModel` semantics, CORE-REF-01).
5. **Serving defaults in preview.** Only entries that are simultaneously
   `status=active`, inside their effective window, provenance
   `verified-primary` and not review-stale may price production traffic.
   Draft and retired entries are never serveable, regardless of rates or
   windows. No third-party corpus is included in the shipped pack. Explicit
   operator rates and the five historical primary Anthropic fallback identities
   remain separate compatibility paths (`pricing.lookupHistoricalPrimary`).
6. **Rate disputes.** Disagreements between sources about an amount are
   resolved inside the catalog (per-axis evidence + recorded conflict
   resolution) or in the source data — never silently at the consumer.
   Disputes about identity (which model is which) belong to the registry.

## Consumer contract

- Load catalog bytes through `catalogs.LoadCatalog` (digest verified
  fail-closed). Never trust a sealed file's digest field without
  recomputation. Bytes whose digest field is missing or empty are refused
  outright: verification is fail-closed, so stripping the digest field is
  not a bypass.
- Wrap snapshot switches in `catalogs.VerifyChain(prev, next)`; a chain
  break is a stop, not a warning.
- Cite the artifact with `catalogs.ProvenanceLabel` (the REF-04 preview
  label contract). The label is a source citation, not a freshness claim.
- Treat `amount: null` and absent axes as "unpriced: unknown" — there is
  no zero-priced axis in a correctly built catalog (the builder refuses
  them; `RateAmount` reports `priced=false`).

## Change flow

Corpus or record changes regenerate the pin through the golden flow
(`go test ./pkg/pricing/catalogs/ -run TestCommittedReferenceCatalog
-update`) and commit the regenerated `reference-catalog-v1.json` together
with the change that caused the drift. The next catalog revision declares
`Supersedes = <digest of this pin>`; rollback is a new snapshot restoring
prior content, never a pointer shuffle.
