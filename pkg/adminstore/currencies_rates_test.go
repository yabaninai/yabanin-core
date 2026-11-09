package adminstore

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

// Rates surfaces. Invariants under guard:
//
//   - the committed pack is the only promotion predecessor (chain verify);
//   - refusals are structured data and never mutate the default pricer;
//   - the review-needed flag fires on ADDED/CHANGED active entries recorded
//     without a reviewer — including active→active changes the upstream
//     RefDiff gate does not refuse;
//   - report counters are parsed from RefDiff's own summary line, so the
//     rendered diff and the structured report cannot disagree;
//   - the promotion re-seats a pricer whose citation equals the next pack.

// ratesActiveModel builds a serveable active entry: reviewed, sourced,
// in-window, pricing input and output per 1M tokens.
func ratesActiveModel(provider, model string, in, out float64, reviewer string) pricing.RefModel {
	amtIn, amtOut := in, out
	return pricing.RefModel{
		Provider:      provider,
		Model:         model,
		Currency:      "USD",
		Status:        pricing.RefStatusActive,
		EffectiveFrom: "2026-11-01",
		VerifiedAt:    "2026-11-02",
		Rates: []pricing.RefRate{
			{Axis: pricing.AxisInput, Unit: pricing.RefUnitPer1MTokens, Amount: &amtIn},
			{Axis: pricing.AxisOutput, Unit: pricing.RefUnitPer1MTokens, Amount: &amtOut},
		},
		Sources: []pricing.RefSource{{
			Kind:       pricing.RefSourceURL,
			Ref:        "https://pricing.example.test/" + provider + "/" + model,
			VerifiedAt: "2026-11-02",
		}},
		Reviewer: reviewer,
	}
}

// ratesDraftModel builds a draft entry (no sources required at draft).
func ratesDraftModel(provider, model string, reviewer string) pricing.RefModel {
	amt := 1.5
	return pricing.RefModel{
		Provider:      provider,
		Model:         model,
		Currency:      "USD",
		Status:        pricing.RefStatusDraft,
		EffectiveFrom: "2026-11-01",
		VerifiedAt:    "2026-11-02",
		Rates: []pricing.RefRate{
			{Axis: pricing.AxisInput, Unit: pricing.RefUnitPer1MTokens, Amount: &amt},
		},
		Reviewer: reviewer,
	}
}

// ratesTestCatalog assembles a fixture snapshot (no SLA so verification
// dates never go stale inside the test).
func ratesTestCatalog(version, supersedes string, models []pricing.RefModel) pricing.Catalog {
	c := pricing.Catalog{
		SchemaVersion: pricing.RefSchemaVersion,
		Version:       version,
		GeneratedAt:   "2026-11-02",
		Source:        "rates store test assembly (deterministic fixture)",
		Models:        models,
	}
	if supersedes != "" {
		c.Supersedes = supersedes
	}
	return c
}

// ratesSealedPack seals, packs and marshals a fixture snapshot.
func ratesSealedPack(t *testing.T, c pricing.Catalog) []byte {
	t.Helper()
	sealed, err := pricing.SealCatalog(c)
	if err != nil {
		t.Fatalf("seal fixture catalog: %v", err)
	}
	b, err := json.Marshal(sealed)
	if err != nil {
		t.Fatalf("marshal fixture catalog: %v", err)
	}
	pack, err := pricing.BuildRefPack(b, nil)
	if err != nil {
		t.Fatalf("build fixture pack: %v", err)
	}
	out, err := pricing.MarshalRefPack(pack)
	if err != nil {
		t.Fatalf("marshal fixture pack: %v", err)
	}
	return out
}

// ratesChainedPack returns a pack for c with Supersedes pinned to the actual
// digest of the catalog inside prevPackJSON.
func ratesChainedPack(t *testing.T, prevPackJSON []byte, c pricing.Catalog) []byte {
	t.Helper()
	_, prevCat, err := pricing.LoadRefPack(prevPackJSON)
	if err != nil {
		t.Fatalf("load previous fixture pack: %v", err)
	}
	c.Supersedes = prevCat.Digest
	return ratesSealedPack(t, c)
}

// ratesTamperedPack breaks the envelope digest of an otherwise valid pack.
func ratesTamperedPack(t *testing.T, packJSON []byte) []byte {
	t.Helper()
	var env map[string]any
	if err := json.Unmarshal(packJSON, &env); err != nil {
		t.Fatalf("unmarshal pack: %v", err)
	}
	env["pack_sha256"] = strings.Repeat("ab", 32)
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("remarshal pack: %v", err)
	}
	return out
}

// TestRatesCatalog_CurrentCommittedPack pins that the committed reference
// pack surfaces with a coherent citation: the provenance label is the
// composed catalog label, the body digests to the cited digest, and the body
// passes full schema validation.
func TestRatesCatalog_CurrentCommittedPack(t *testing.T) {
	rc, err := CurrentRefRatesCatalog()
	if err != nil {
		t.Fatalf("CurrentRefRatesCatalog: %v", err)
	}
	ref := rc.Ref
	if ref.Version == "" || ref.Digest == "" || ref.GeneratedAt == "" {
		t.Fatalf("citation incomplete: %+v", ref)
	}
	if ref.Digest != rc.Catalog.Digest {
		t.Fatalf("ref digest %s does not match catalog body digest %s", ref.Digest, rc.Catalog.Digest)
	}
	if want := CatalogProvenanceLabel(ref.Version, ref.Digest); ref.Provenance != want {
		t.Fatalf("provenance %q, want composed label %q", ref.Provenance, want)
	}
	if len(ref.PackDigest) != 64 {
		t.Fatalf("pack digest not sealed: %q", ref.PackDigest)
	}
	if err := pricing.ValidateCatalog(rc.Catalog); err != nil {
		t.Fatalf("committed catalog body must validate: %v", err)
	}
	if len(rc.Catalog.Models) == 0 {
		t.Fatal("committed catalog has no entries")
	}
}

// TestRatesCatalog_FromPackAndTamper pins the load path: valid packs load,
// tampered envelopes are refused as errors (not reports).
func TestRatesCatalog_FromPackAndTamper(t *testing.T) {
	prev := ratesSealedPack(t, ratesTestCatalog("0.1.0-rates-a", "", []pricing.RefModel{
		ratesActiveModel("aprov", "alpha", 3.0, 9.0, "r1"),
	}))

	rc, err := RefRatesCatalogFromPack(prev)
	if err != nil {
		t.Fatalf("RefRatesCatalogFromPack: %v", err)
	}
	if rc.Ref.Version != "0.1.0-rates-a" {
		t.Fatalf("version %q", rc.Ref.Version)
	}

	if _, err := RefRatesCatalogFromPack([]byte("not a pack")); err == nil {
		t.Fatal("garbage bytes must error")
	}
	if _, err := RefRatesCatalogFromPack(ratesTamperedPack(t, prev)); err == nil {
		t.Fatal("tampered envelope must error")
	}
}

// TestRatesDiff_CountersAndRendered pins the happy diff: counters parsed
// from RefDiff's own summary line, rendered output verbatim, no flags when
// every touched entry carries a reviewer.
func TestRatesDiff_CountersAndRendered(t *testing.T) {
	prev := ratesSealedPack(t, ratesTestCatalog("0.1.0-rates-b", "", []pricing.RefModel{
		ratesActiveModel("aprov", "alpha", 3.0, 9.0, "r1"),
	}))
	next := ratesChainedPack(t, prev, ratesTestCatalog("0.2.0-rates-b", "", []pricing.RefModel{
		ratesActiveModel("aprov", "alpha", 4.0, 9.0, "r1"), // changed input rate
		ratesActiveModel("bprov", "beta", 2.0, 8.0, "r2"),  // added, reviewed
	}))

	report, err := DiffRefRatesCatalogs(prev, next)
	if err != nil {
		t.Fatalf("DiffRefRatesCatalogs: %v", err)
	}
	if report.Refused {
		t.Fatalf("unexpected refusal: %s", report.RefusalReason)
	}
	if report.Added != 1 || report.Removed != 0 || report.Changed != 1 {
		t.Fatalf("counters added=%d removed=%d changed=%d, want 1/0/1", report.Added, report.Removed, report.Changed)
	}
	if report.ReviewNeeded {
		t.Fatalf("reviewed diff must not flag: %+v", report.Flags)
	}
	if len(report.Flags) != 0 {
		t.Fatalf("flags must be empty, got %+v", report.Flags)
	}
	if !strings.Contains(report.Rendered, "CHANGED aprov/alpha") ||
		!strings.Contains(report.Rendered, "ADDED bprov/beta") ||
		!strings.Contains(report.Rendered, "summary: added=1 removed=0 changed=1") {
		t.Fatalf("rendered diff missing expected lines:\n%s", report.Rendered)
	}
	if report.From.Version != "0.1.0-rates-b" || report.To.Version != "0.2.0-rates-b" {
		t.Fatalf("ref versions from=%q to=%q", report.From.Version, report.To.Version)
	}
}

// TestRatesDiff_ReviewNeededFiresWithoutReviewer pins the advisory flag on
// an active→active rate change recorded without a reviewer — a case the
// upstream RefDiff gate deliberately does not refuse (it only gates
// draft→active), so this flag is the only review tooth for it.
func TestRatesDiff_ReviewNeededFiresWithoutReviewer(t *testing.T) {
	prev := ratesSealedPack(t, ratesTestCatalog("0.1.0-rates-c", "", []pricing.RefModel{
		ratesActiveModel("aprov", "alpha", 3.0, 9.0, "r1"),
	}))
	next := ratesChainedPack(t, prev, ratesTestCatalog("0.2.0-rates-c", "", []pricing.RefModel{
		ratesActiveModel("aprov", "alpha", 5.0, 9.0, ""), // changed, reviewer dropped
		ratesActiveModel("cprov", "gamma", 7.0, 1.0, ""), // added, unreviewed
	}))

	report, err := DiffRefRatesCatalogs(prev, next)
	if err != nil {
		t.Fatalf("DiffRefRatesCatalogs: %v", err)
	}
	if report.Refused {
		t.Fatalf("active→active changes must render, not refuse: %s", report.RefusalReason)
	}
	if !report.ReviewNeeded {
		t.Fatal("review_needed must fire")
	}
	kinds := map[string]string{}
	for _, f := range report.Flags {
		kinds[f.Kind] = f.Entry
	}
	if kinds["active_changed_without_reviewer"] != "aprov/alpha" {
		t.Fatalf("missing/incorrect changed flag: %+v", report.Flags)
	}
	if kinds["active_added_without_reviewer"] != "cprov/gamma" {
		t.Fatalf("missing/incorrect added flag: %+v", report.Flags)
	}
}

// TestRatesDiff_RefusedDraftPromotion pins the structured refusal: a
// draft→active promotion without a recorded reviewer refuses with
// Refused=true and a reason (data, not a Go error).
func TestRatesDiff_RefusedDraftPromotion(t *testing.T) {
	prev := ratesSealedPack(t, ratesTestCatalog("0.1.0-rates-d", "", []pricing.RefModel{
		ratesDraftModel("dprov", "delta", "r1"),
	}))
	promoted := ratesDraftModel("dprov", "delta", "")
	promoted.Status = pricing.RefStatusActive
	promoted.Sources = []pricing.RefSource{{
		Kind:       pricing.RefSourceURL,
		Ref:        "https://pricing.example.test/dprov/delta",
		VerifiedAt: "2026-11-02",
	}}
	next := ratesChainedPack(t, prev, ratesTestCatalog("0.2.0-rates-d", "", []pricing.RefModel{promoted}))

	report, err := DiffRefRatesCatalogs(prev, next)
	if err != nil {
		t.Fatalf("refusal must be data, not error: %v", err)
	}
	if !report.Refused {
		t.Fatal("diff must refuse")
	}
	if !strings.Contains(report.RefusalReason, "no reviewer recorded") {
		t.Fatalf("refusal reason %q", report.RefusalReason)
	}
	if report.Rendered != "" {
		t.Fatalf("refused diff must not render: %q", report.Rendered)
	}
}

// TestRatesDiff_InvalidPackIsError pins that invalid pack bytes surface as
// errors (not silent refusal reports).
func TestRatesDiff_InvalidPackIsError(t *testing.T) {
	prev := ratesSealedPack(t, ratesTestCatalog("0.1.0-rates-e", "", []pricing.RefModel{
		ratesActiveModel("aprov", "alpha", 3.0, 9.0, "r1"),
	}))
	if _, err := DiffRefRatesCatalogs(ratesTamperedPack(t, prev), prev); err == nil {
		t.Fatal("tampered previous pack must error")
	}
	if _, err := DiffRefRatesCatalogs(prev, []byte("{}")); err == nil {
		t.Fatal("garbage next pack must error")
	}
}

// TestParseRatesSummary pins the counter parser against the deterministic
// upstream format and its failure mode.
func TestParseRatesSummary(t *testing.T) {
	added, removed, changed, err := parseRatesSummary(
		"ref-diff: a (x) -> b (y)\nADDED p/m\nsummary: added=1 removed=2 changed=3 unchanged=4\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if added != 1 || removed != 2 || changed != 3 {
		t.Fatalf("got %d/%d/%d, want 1/2/3", added, removed, changed)
	}
	if _, _, _, err := parseRatesSummary("no summary here\n"); err == nil {
		t.Fatal("missing summary must error")
	}
}

// TestRatesPromotion_HappyPath pins the promotion: chain verified against
// the committed pack, diff rendered, pricer re-seated with the next pack's
// citation. The original pricer is restored afterwards.
func TestRatesPromotion_HappyPath(t *testing.T) {
	original := pricing.DefaultFilePricer()
	t.Cleanup(func() { pricing.SetDefaultFilePricer(original) })

	_, committedCat, err := pricing.LoadRefPack(pricing.BundledRefPackJSON())
	if err != nil {
		t.Fatalf("committed pack: %v", err)
	}
	nextCat := committedCat // mutate the freshly-loaded instance
	nextCat.Version = "999.0.0-rates-promote"
	nextCat.GeneratedAt = "2026-11-02"
	nextCat.Supersedes = committedCat.Digest
	tweaked := false
	for i := range nextCat.Models {
		if nextCat.Models[i].Status != pricing.RefStatusActive || tweaked {
			continue
		}
		for k := range nextCat.Models[i].Rates {
			if nextCat.Models[i].Rates[k].Axis == pricing.AxisInput && nextCat.Models[i].Rates[k].Amount != nil {
				v := *nextCat.Models[i].Rates[k].Amount + 0.25
				nextCat.Models[i].Rates[k].Amount = &v
				tweaked = true
				break
			}
		}
	}
	if !tweaked {
		t.Fatal("fixture could not tweak any active input rate")
	}
	next := ratesSealedPack(t, nextCat)

	prom, err := PromoteRefCatalog(next)
	if err != nil {
		t.Fatalf("PromoteRefCatalog: %v", err)
	}
	if !prom.Applied {
		t.Fatal("promotion must be applied")
	}
	if prom.Before.Version != committedCat.Version || prom.After.Version != "999.0.0-rates-promote" {
		t.Fatalf("before=%q after=%q", prom.Before.Version, prom.After.Version)
	}
	if prom.Diff == nil || prom.Diff.Refused || prom.Diff.Changed != 1 {
		t.Fatalf("promotion diff: %+v", prom.Diff)
	}
	serving := pricing.DefaultFilePricer()
	got, ok := serving.CatalogProvenance()
	if !ok {
		t.Fatal("re-seated pricer lost its catalog citation")
	}
	if got.Version != "999.0.0-rates-promote" || got.Digest != prom.After.Digest {
		t.Fatalf("serving citation %+v, want version 999.0.0-rates-promote digest %s", got, prom.After.Digest)
	}
}

// TestRatesPromotion_RefusedLeavesPricerUntouched pins that a refused
// durable promotion returns a typed *RatesRefusal carrying the structured
// report. Its synthetic draft predecessor does not depend on shipped prices.
func TestRatesPromotion_RefusedLeavesPricerUntouched(t *testing.T) {
	original := pricing.DefaultFilePricer()
	t.Cleanup(func() { pricing.SetDefaultFilePricer(original) })

	active := ratesActiveModel("synthetic-refusal", "reviewed", 17, 29, "fixture-reviewer")
	draft := ratesActiveModel("synthetic-refusal", "unreviewed", 31, 43, "")
	draft.Status = pricing.RefStatusDraft
	previous := ratesSealedPack(t, ratesTestCatalog("synthetic-draft-anchor", "", []pricing.RefModel{active, draft}))
	prevPack, prevCat, err := pricing.LoadRefPack(previous)
	require.NoError(t, err)
	pool := testdb.Postgres(t)
	_, err = pool.Exec(t.Context(), `INSERT INTO rates_catalog_state
		(id, catalog_version, catalog_digest, pack_sha256, pack_json, activated_by)
		VALUES (1, $1, $2, $3, $4, 'synthetic-refusal-fixture')`, prevCat.Version, prevCat.Digest, prevPack.PackSHA256, previous)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, cleanupErr := pool.Exec(ctx, `DELETE FROM rates_catalog_state WHERE id = 1 AND activated_by = 'synthetic-refusal-fixture'`)
		require.NoError(t, cleanupErr)
	})
	store := New(pool, slog.Default(), nil)
	draft.Status = pricing.RefStatusActive // Deliberately no reviewer.
	nextCat := ratesTestCatalog("synthetic-unreviewed-activation", prevCat.Digest, []pricing.RefModel{active, draft})
	next := ratesSealedPack(t, nextCat)

	before := pricing.DefaultFilePricer()
	prom, err := store.PromoteRefCatalogDurable(t.Context(), next, "synthetic-refusal-fixture")
	if prom != nil {
		t.Fatalf("refused promotion must return no promotion: %+v", prom)
	}
	var refusal *RatesRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("want *RatesRefusal, got %T: %v", err, refusal)
	}
	if refusal.Report == nil || !refusal.Report.Refused {
		t.Fatalf("refusal report: %+v", refusal.Report)
	}
	if !strings.Contains(refusal.Error(), "no reviewer recorded") {
		t.Fatalf("refusal error %q", refusal.Error())
	}
	if pricing.DefaultFilePricer() != before {
		t.Fatal("refused promotion must not re-seat the pricer")
	}
	after, found, err := store.DurableRatesCatalogPackJSON(t.Context())
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, previous, after, "refusal must preserve the durable predecessor")
}

// TestRatesPromotion_ChainBreakIsError pins that a pack not chained to the
// committed snapshot is a plain error (history cannot be rewritten), and the
// pricer is untouched.
func TestRatesPromotion_ChainBreakIsError(t *testing.T) {
	original := pricing.DefaultFilePricer()
	t.Cleanup(func() { pricing.SetDefaultFilePricer(original) })

	_, committedCat, err := pricing.LoadRefPack(pricing.BundledRefPackJSON())
	if err != nil {
		t.Fatalf("committed pack: %v", err)
	}
	nextCat := committedCat
	nextCat.Version = "0.2.0-rates-unchained"
	nextCat.GeneratedAt = "2026-11-02"
	nextCat.Supersedes = "" // genesis claim: not the committed pack
	next := ratesSealedPack(t, nextCat)

	before := pricing.DefaultFilePricer()
	if _, err := PromoteRefCatalog(next); err == nil {
		t.Fatal("unchained promotion must error")
	} else {
		var refusal *RatesRefusal
		if errors.As(err, &refusal) {
			t.Fatalf("chain break is not a diff refusal: %v", err)
		}
	}
	if pricing.DefaultFilePricer() != before {
		t.Fatal("failed promotion must not re-seat the pricer")
	}
}

// TestRatesPromotion_UnserveableNextIsError pins the serveability tooth at
// promotion time: an active entry without output pricing loads and diffs
// fine but must never seat a pricer that prices output as free.
func TestRatesPromotion_UnserveableNextIsError(t *testing.T) {
	original := pricing.DefaultFilePricer()
	t.Cleanup(func() { pricing.SetDefaultFilePricer(original) })

	_, committedCat, err := pricing.LoadRefPack(pricing.BundledRefPackJSON())
	if err != nil {
		t.Fatalf("committed pack: %v", err)
	}
	nextCat := committedCat
	nextCat.Version = "0.2.0-rates-unserveable"
	nextCat.GeneratedAt = "2026-11-02"
	nextCat.Supersedes = committedCat.Digest
	// Strip the output axis from one active entry (input-only entry).
	stripped := false
	for i := range nextCat.Models {
		if nextCat.Models[i].Status != pricing.RefStatusActive || stripped {
			continue
		}
		rates := nextCat.Models[i].Rates[:0]
		for _, r := range nextCat.Models[i].Rates {
			if r.Axis != pricing.AxisOutput {
				rates = append(rates, r)
			}
		}
		nextCat.Models[i].Rates = rates
		stripped = true
	}
	if !stripped {
		t.Fatal("fixture could not strip any active output axis")
	}
	next := ratesSealedPack(t, nextCat)

	before := pricing.DefaultFilePricer()
	if _, err := PromoteRefCatalog(next); err == nil {
		t.Fatal("unserveable promotion must error")
	}
	if pricing.DefaultFilePricer() != before {
		t.Fatal("failed promotion must not re-seat the pricer")
	}
}

// TestRatesDiffReport_WireShape pins the refusal serialization the handler
// will forward on 422: refused=true plus the reason string.
func TestRatesDiffReport_WireShape(t *testing.T) {
	prev := ratesSealedPack(t, ratesTestCatalog("0.1.0-rates-w", "", []pricing.RefModel{
		ratesDraftModel("gprov", "eta", "r1"),
	}))
	promoted := ratesDraftModel("gprov", "eta", "")
	promoted.Status = pricing.RefStatusActive
	promoted.Sources = []pricing.RefSource{{
		Kind:       pricing.RefSourceURL,
		Ref:        "https://pricing.example.test/gprov/eta",
		VerifiedAt: "2026-11-02",
	}}
	next := ratesChainedPack(t, prev, ratesTestCatalog("0.2.0-rates-w", "", []pricing.RefModel{promoted}))

	report, err := DiffRefRatesCatalogs(prev, next)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	b, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if wire["refused"] != true {
		t.Fatalf("wire refused=%v", wire["refused"])
	}
	if s, _ := wire["refusal_reason"].(string); !strings.Contains(s, "no reviewer recorded") {
		t.Fatalf("wire refusal_reason=%v", wire["refusal_reason"])
	}
}
