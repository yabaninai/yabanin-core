package pricing

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AUD-PRICE-02 (pkg/pricing audit): reference-pack review diff, envelope
// round-trip, serveability SLA boundaries, alias serving, provenance
// citations and tenant-seat precedence. Each test pins one contract from
// pkg/pricing/catalogs/PRECEDENCE.md §4/§5 and the CORE-REF-03/04 cards.

// audit02Time is the fixed "now" for every projection in the package's
// audit/serving-flip pins (this file, audit_price01_test.go and the fresh
// default rebuild in refserve_test.go): the genesis catalog generation
// date. All gates are driven with this instant so the pins never go
// SLA-stale (the embedded catalog's verified_at 2026-09-08 + 90d SLA
// expires 2026-12-07; the real expiry boundary is pinned explicitly in
// TestAuditPRICE02_ShippedCatalogExpiryBoundary below).
var audit02Time = time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)

// audit02Catalog assembles a minimal sealed-catalog fixture.
func audit02Catalog(models []RefModel) Catalog {
	return Catalog{
		SchemaVersion: RefSchemaVersion,
		Version:       "audit02",
		GeneratedAt:   "2026-11-02",
		Source:        "audit-price02 fixture",
		ReviewSLADays: 30,
		Models:        models,
	}
}

// audit02Entry is one active verified in-window entry with input+output
// priced — the minimal serveable shape, with configurable aliases.
func audit02Entry(provider, model string, aliases []string) RefModel {
	in := 0.14
	out := 0.28
	return RefModel{
		Provider: provider, Model: model, Aliases: aliases,
		Currency: "USD", Status: RefStatusActive,
		EffectiveFrom: "2026-07-01", VerifiedAt: "2026-10-20",
		Rates: []RefRate{
			{Axis: AxisInput, Unit: RefUnitPer1MTokens, Amount: &in},
			{Axis: AxisOutput, Unit: RefUnitPer1MTokens, Amount: &out},
		},
		Sources: []RefSource{{
			Kind: RefSourceInternalEvidence, Ref: "ev-1", VerifiedAt: "2026-10-20",
		}},
		Reviewer: "audit02-reviewer",
	}
}

// TestAuditPRICE02_RefDiffSurfacesReviewFacts: the review diff must surface
// every operator-visible review fact of an entry — the entry-level
// verified_at, the alias set, and the primary-source ref set. A change that
// the diff does not render is a change reviewers cannot gate on; a
// same-count source swap (replace one URL with another) must be as visible
// as an added one.
func TestAuditPRICE02_RefDiffSurfacesReviewFacts(t *testing.T) {
	base := audit02Entry("aprov", "alpha-model", []string{"alpha-alias"})

	mutants := []struct {
		name   string
		mutate func(*RefModel)
		want   string
	}{
		{
			name:   "verified_at change is rendered",
			mutate: func(m *RefModel) { m.VerifiedAt = "2026-10-21" },
			want:   "verified_at: 2026-10-20 -> 2026-10-21",
		},
		{
			name:   "alias set change is rendered",
			mutate: func(m *RefModel) { m.Aliases = append(m.Aliases, "alpha-alias-2") },
			want:   "aliases: alpha-alias -> alpha-alias,alpha-alias-2",
		},
		{
			name: "same-count source swap is rendered",
			mutate: func(m *RefModel) {
				m.Sources = []RefSource{{Kind: RefSourceInternalEvidence, Ref: "ev-2", VerifiedAt: "2026-10-20"}}
			},
			want: "sources: ev-1 -> ev-2",
		},
	}

	for _, tc := range mutants {
		t.Run(tc.name, func(t *testing.T) {
			oldJSON := sealedCatalogJSON(t, audit02Catalog([]RefModel{base}))
			nm := base
			tc.mutate(&nm)
			newJSON := sealedCatalogJSON(t, audit02Catalog([]RefModel{nm}))

			diff, err := RefDiff(oldJSON, newJSON)
			require.NoError(t, err)
			assert.Contains(t, diff, tc.want, "review diff must surface the change")
			assert.Contains(t, diff, "CHANGED aprov/alpha-model", "the changed entry must be marked CHANGED, not silently unchanged")
			// Deterministic render for identical inputs.
			again, err := RefDiff(oldJSON, newJSON)
			require.NoError(t, err)
			assert.Equal(t, diff, again)
		})
	}
}

// TestAuditPRICE02_MarshalLoadUnsortedNotices: MarshalRefPack must emit the
// normalized pack it digested. The digest is computed over the open envelope
// with sorted, deduplicated notices — the sealed bytes must carry exactly
// that normalized form, or LoadRefPack rejects the marshaler's own output
// for any caller that hands in unsorted notices (every loader in the fleet
// verifies, so a self-rejecting marshaler is a hard fault).
func TestAuditPRICE02_MarshalLoadUnsortedNotices(t *testing.T) {
	catJSON := sealedCatalogJSON(t, audit02Catalog([]RefModel{audit02Entry("aprov", "alpha-model", nil)}))
	var c Catalog
	require.NoError(t, json.Unmarshal(catJSON, &c))

	mk := func(notices []string) *RefPack {
		return &RefPack{
			PackSchemaVersion: RefPackSchemaVersion,
			Catalog:           append(json.RawMessage(nil), catJSON...),
			CatalogDigest:     c.Digest,
			Notices:           notices,
		}
	}
	unsorted := mk([]string{"z-notices.txt", "a-notices.txt", "z-notices.txt", "  ", "m-notices.txt"})
	sorted := mk([]string{"m-notices.txt", "a-notices.txt", "z-notices.txt"})

	b1, err := MarshalRefPack(unsorted)
	require.NoError(t, err)
	_, _, err = LoadRefPack(b1)
	require.NoError(t, err, "MarshalRefPack output must round-trip through LoadRefPack (unsorted input notices)")

	b2, err := MarshalRefPack(sorted)
	require.NoError(t, err)
	assert.Equal(t, b1, b2, "notice order must not leak into the envelope bytes")

	var rp RefPack
	require.NoError(t, json.Unmarshal(b1, &rp))
	assert.Equal(t, []string{"a-notices.txt", "m-notices.txt", "z-notices.txt"}, rp.Notices,
		"sealed bytes carry the normalized notice list")
}

// TestAuditPRICE02_AliasesServeThroughProjection: an active entry's aliases
// serve under the entry's exact projection — an alias lookup resolves to the
// target entry's identity, never to a different price. The canonical name
// keeps exact-key precedence: an alias must never shadow another entry's
// canonical name.
func TestAuditPRICE02_AliasesServeThroughProjection(t *testing.T) {
	t.Run("alias rows carry the target projection", func(t *testing.T) {
		cat := audit02Catalog([]RefModel{audit02Entry("gprov", "gate-model", []string{"gate-alias-b", "gate-alias-a"})})
		pf, err := projectServeable(cat, audit02Time)
		require.NoError(t, err)

		names := map[string]PriceFileModel{}
		for _, m := range pf.Models {
			names[m.Provider+":"+m.Model] = m
		}
		canon, ok := names["gprov:gate-model"]
		require.True(t, ok, "canonical name must project")
		for _, alias := range []string{"gate-alias-a", "gate-alias-b"} {
			am, ok := names["gprov:"+alias]
			require.True(t, ok, "alias %q must project (got %v)", alias, names)
			assert.InDelta(t, canon.Input, am.Input, 0)
			assert.InDelta(t, canon.Output, am.Output, 0)
		}
		// Exactly one row per name — aliases collapse, canonical stays single.
		assert.Len(t, pf.Models, 3)

		pf.Source, pf.Date = "audit02", "2026-11-02"
		p, err := NewFilePricer(pf, "sha256:audit02")
		require.NoError(t, err)
		for _, name := range []string{"gate-model", "gate-alias-a", "gate-alias-b"} {
			pr, ok := p.Lookup("gprov", name)
			require.True(t, ok, "Lookup(%s) must serve through the projection", name)
			assert.InDelta(t, 0.14, pr.InputPerM, 0)
			assert.InDelta(t, 0.28, pr.OutputPerM, 0)
		}
	})

	t.Run("canonical name is never shadowed by an alias", func(t *testing.T) {
		a := audit02Entry("gprov", "gate-model", []string{"gate-alias-a"})
		b := audit02Entry("gprov", "gate-alias-a", nil)
		b.Rates[0].Amount = ptrFloat(9.0)
		b.Rates[1].Amount = ptrFloat(19.0)
		pf, err := projectServeable(audit02Catalog([]RefModel{a, b}), audit02Time)
		require.NoError(t, err)

		byName := map[string]PriceFileModel{}
		for _, m := range pf.Models {
			byName[m.Provider+":"+m.Model] = m
		}
		claim, ok := byName["gprov:gate-alias-a"]
		require.True(t, ok)
		assert.InDelta(t, 9.0, claim.Input, 0, "the canonical entry keeps the name; the alias of another entry must not shadow it")
		assert.Len(t, pf.Models, 2, "gate-model, gate-alias-a (canonical) — the shadowing alias collapses into it")
	})
}

// TestAuditPRICE02_SLABoundaryFreshVsStale: the review SLA boundary is
// inclusive — an entry verified exactly ReviewSLADays ago still serves; one
// nanosecond past the boundary does not. A pricer built while fresh is a
// frozen snapshot: it keeps serving identical prices after the catalog
// goes stale (quotes are never re-evaluated), and a construction attempt
// after the whole catalog went stale refuses rather than serving a stale
// projection.
func TestAuditPRICE02_SLABoundaryFreshVsStale(t *testing.T) {
	cat := audit02Catalog([]RefModel{audit02Entry("gprov", "gate-model", nil)})
	// VerifiedAt 2026-10-20 + SLA 30d = 2026-11-19 — drive the boundary from
	// the entry's own verification instant so the pins are exact.
	v, err := parseRefTime("2026-10-20")
	require.NoError(t, err)
	boundary := v.AddDate(0, 0, 30)

	countAt := func(now time.Time) int {
		t.Helper()
		pf, err := projectServeable(cat, now)
		require.NoError(t, err)
		return len(pf.Models)
	}
	assert.Equal(t, 1, countAt(boundary.Add(-time.Nanosecond)), "one nanosecond inside the SLA serves")
	assert.Equal(t, 1, countAt(boundary), "the SLA boundary itself is inclusive")
	assert.Equal(t, 0, countAt(boundary.Add(time.Nanosecond)), "past the boundary the entry drops out")

	// Long-lived process: build while fresh, serve forever after.
	pf, err := projectServeable(cat, boundary)
	require.NoError(t, err)
	pf.Source, pf.Date = "audit02", "2026-11-02"
	p, err := NewFilePricer(pf, "sha256:audit02")
	require.NoError(t, err)
	pr, ok := p.Lookup("gprov", "gate-model")
	require.True(t, ok)
	assert.InDelta(t, 0.14, pr.InputPerM, 0, "the frozen snapshot keeps serving after the catalog went stale")

	// A construction attempt once the whole catalog is stale refuses —
	// an empty projection must not become a pricer (fail closed).
	pfStale, err := projectServeable(cat, boundary.Add(time.Nanosecond))
	require.NoError(t, err)
	assert.Empty(t, pfStale.Models)
	pfStale.Source, pfStale.Date = "audit02", "2026-11-02"
	_, err = NewFilePricer(pfStale, "sha256:audit02")
	assert.Error(t, err, "an empty projection must not validate into a pricer")
}

// TestAuditPRICE02_ShippedCatalogExpiryBoundary: the wall-clock serving
// routes (LoadBundledRefServe, ExternalLoader offline, fresh
// DefaultFilePricer legs) are pinned at fixed instants elsewhere, so this
// test owns the REAL clock contract of the shipped catalog: it serves at
// ReviewSLADays past its newest verified_at and fails closed from the first
// instant after. Deriving the boundary from the pack keeps the test honest,
// and the pinned instant below is the deliberate tripwire: a catalog
// refresh that moves verified_at breaks this assert and forces the refresh,
// the wall-clock pins and the delivery-record operational handoff (§5) to
// move together in one conscious change.
func TestAuditPRICE02_ShippedCatalogExpiryBoundary(t *testing.T) {
	_, cat, err := LoadRefPack(bundledRefPackBytes)
	require.NoError(t, err)
	require.Positive(t, cat.ReviewSLADays, "the shipped catalog must pin a review SLA")

	// Newest verified_at among the ACTIVE entries drives the expiry
	// (retired entries never project regardless of age).
	var newest time.Time
	active := 0
	for i := range cat.Models {
		m := &cat.Models[i]
		if m.Status != RefStatusActive {
			continue
		}
		active++
		v, err := parseRefTime(m.VerifiedAt)
		require.NoError(t, err)
		if newest.IsZero() || v.After(newest) {
			newest = v
		}
	}
	require.Equal(t, 3, active, "the shipped pack pins 3 active entries")
	boundary := newest.AddDate(0, 0, cat.ReviewSLADays)

	// The intentional pin: all shipped entries were verified 2026-09-08
	// with a 90-day SLA, so the catalog serves through 2026-12-07T00:00:00Z
	// (inclusive) and fails closed from 2026-12-08T00:00Z onwards. If this
	// assert fires, the catalog was refreshed — re-derive the boundary,
	// update the audit02Time/route pins if the served set changed, and
	// refresh the delivery-record operational handoff in the same change.
	assert.True(t, boundary.Equal(time.Date(2026, 12, 7, 0, 0, 0, 0, time.UTC)),
		"shipped-catalog expiry boundary moved (newest verified_at %s + SLA %dd = %s): a catalog refresh must land together with the wall-clock pins and the §5 operational handoff",
		newest.Format(time.RFC3339), cat.ReviewSLADays, boundary.Format(time.RFC3339))

	// At the boundary instant the shipped catalog still serves (inclusive).
	p, err := loadBundledRefServeAt(boundary)
	require.NoError(t, err, "serving at the SLA boundary must succeed (inclusive)")
	assert.Len(t, p.File().Models, 6, "3 canonical rows + 3 alias rows at the boundary")
	assert.Equal(t, refGenesisLabel, p.Provenance().Source)

	// From the first instant past it, construction fails closed: no
	// pricer, no stale projection, ever.
	_, err = loadBundledRefServeAt(boundary.Add(time.Nanosecond))
	require.Error(t, err, "past the boundary the shipped catalog must fail closed")
	_, err = loadBundledRefServeAt(time.Date(2026, 12, 8, 0, 0, 0, 0, time.UTC))
	require.Error(t, err, "2026-12-08T00:00Z must fail closed against the shipped catalog")
}

// TestAuditPRICE02_GenesisProjectionDeterministic: the shipped catalog's
// projection facts are pinned at a fixed now — provenance citation, catalog
// info coherence, model rows (canonical names and their aliases) and exact
// cents. Deterministic: none of these pins expire with the review SLA.
func TestAuditPRICE02_GenesisProjectionDeterministic(t *testing.T) {
	p, err := loadBundledRefServeAt(audit02Time)
	require.NoError(t, err)

	prov := p.Provenance()
	assert.Equal(t, refGenesisLabel, prov.Source)
	assert.Equal(t, "2026-11-02", prov.Date)
	assert.True(t, strings.HasPrefix(prov.SHA256, "sha256:"), "provenance must cite a sha256 fingerprint, got %q", prov.SHA256)

	info, ok := p.CatalogProvenance()
	require.True(t, ok, "reference-backed pricer carries the structured catalog citation")
	assert.Equal(t, "0.1.0", info.Version)
	assert.Equal(t, refGenesisDigest, info.Digest)
	assert.Equal(t, "sha256:"+info.Digest, prov.SHA256, "the file provenance cites the sealed catalog digest")
	assert.Len(t, info.Digest, 64)

	// Three active arms, each serving its canonical name and its one alias.
	pf := p.File()
	assert.Len(t, pf.Models, 6, "3 canonical rows + 3 alias rows")
	assert.Equal(t, 6, prov.ModelCnt)
	names := map[string]PriceFileModel{}
	for _, m := range pf.Models {
		names[m.Provider+":"+m.Model] = m
	}
	for _, want := range []string{
		"nebius-token-factory:deepseek-ai/DeepSeek-V4-Flash-0731",
		"nebius-token-factory:DeepSeek-V4-Flash",
		"nebius-token-factory:zai-org/GLM-5.2",
		"nebius-token-factory:GLM-5.2",
		"nebius-token-factory:zai-org/GLM-5.3-Flash",
		"nebius-token-factory:GLM-5.3 Flash",
	} {
		assert.Contains(t, names, want)
	}
	// The retired sibling refuses under its exact spelling — unknown, not free.
	pr, ok := p.Lookup("nebius-token-factory", "deepseek-ai/DeepSeek-V4-Flash")
	assert.False(t, ok, "retired canonical name must not serve")
	assert.Equal(t, Price{}, pr)

	// Alias and canonical serve the same verified cents (0.14/0.28, R2).
	canon, ok := p.Lookup("nebius-token-factory", "deepseek-ai/DeepSeek-V4-Flash-0731")
	require.True(t, ok)
	alias, ok := p.Lookup("nebius-token-factory", "DeepSeek-V4-Flash")
	require.True(t, ok)
	assert.Equal(t, canon, alias, "the alias resolves to the target entry's identity")
}

// TestAuditPRICE02_PricerSeatPrecedence: a pricer seated via
// SetDefaultPricer keeps precedence above the catalog-backed default for
// names nothing else knows — the seat is rung 1 of the global-default
// chain (the file-pricer seat is pinned by
// TestRefServe_DefaultFlipsAndOverridesWin; this pins the pricer seat).
func TestAuditPRICE02_PricerSeatPrecedence(t *testing.T) {
	SetDefaultPricer(staticPricer{})
	defer SetDefaultPricer(staticPricer{})

	seat := audit02StubPricer{price: Price{InputPerM: 5.0, OutputPerM: 7.0}}
	SetDefaultPricer(seat)

	got, ok := DefaultLookup("tenant-only", "seat-model")
	require.True(t, ok, "the seated pricer serves its names")
	assert.InDelta(t, 5.0, got.InputPerM, 0)
	assert.InDelta(t, 7.0, got.OutputPerM, 0)

	// The seated pricer answers even where the legacy table and the catalog
	// are both silent: the seat is consulted first.
	if _, ok := (staticPricer{}).Lookup("tenant-only", "seat-model"); ok {
		t.Fatal("fixture drift: the name must be absent from the legacy table")
	}
	assert.False(t, catalogRefused("tenant-only", "seat-model"), "the name must be catalog-unknown")
}

// audit02StubPricer answers every lookup with one price.
type audit02StubPricer struct{ price Price }

func (s audit02StubPricer) Lookup(_, _ string) (Price, bool) { return s.price, true }
