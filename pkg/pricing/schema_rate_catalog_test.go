package pricing

import (
	"errors"
	"math"
	"strings"
	"testing"
)

// Pins validation semantics of the rate body (validateRate) and the catalog
// header (ValidateCatalog) that the other suites only probe one defect at a
// time: full ordered problem aggregation, the 1e-12 storage grid, and
// conflict resolution on unpriced rates. Fixtures are independent of
// schema_test.go and schema_semantic_test.go.

// rcCatalog wraps models in the smallest valid snapshot header.
func rcCatalog(models ...RefModel) Catalog {
	return Catalog{
		SchemaVersion: RefSchemaVersion,
		Version:       "rc-1",
		GeneratedAt:   "2026-11-12",
		Source:        "rate-catalog-contract-suite",
		Models:        models,
	}
}

// rcDraftModel is the smallest legal entry: draft status exempts it from
// window, review and source requirements, so rate findings surface alone.
func rcDraftModel() RefModel {
	return RefModel{
		Provider: "openai",
		Model:    "gpt-rc",
		Currency: "USD",
		Status:   RefStatusDraft,
	}
}

func rcPtr(v float64) *float64 { return &v }

func TestSameRefAmountStorageGrid(t *testing.T) {
	// Oracle values are hand-counted on the rounding grid: amounts agree
	// iff round(x*1e12) is equal; all pairs below sit clear of half-step
	// ties, so the expected results do not depend on tie-breaking.
	cases := []struct {
		name string
		a, b float64
		want bool
	}{
		{name: "identical amounts agree", a: 3, b: 3, want: true},
		{name: "sub-grid noise below one grid step agrees", a: 3, b: 3 + 4e-13, want: true},
		{name: "agreement is symmetric", a: 3 + 4e-13, b: 3, want: true},
		{name: "one full grid step disagrees", a: 3, b: 3 + 1e-12, want: false},
		{name: "grid cell zero includes sub-grid amounts", a: 0, b: 1e-13, want: true},
		{name: "adjacent cell from zero disagrees", a: 0, b: 1e-12, want: false},
		{name: "adjacency from zero is symmetric", a: 1e-12, b: 0, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameRefAmount(tc.a, tc.b); got != tc.want {
				t.Fatalf("sameRefAmount(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestConflictResolutionMatchesAmountOnStorageGrid(t *testing.T) {
	// A resolution is valid only when the chosen observation lands on the
	// same 1e-12 grid cell as the published Amount, so a resolution citing
	// sub-grid-different evidence still resolves the conflict.
	m := rcDraftModel()
	m.Sources = []RefSource{
		{Kind: RefSourceURL, Ref: "a", VerifiedAt: "2026-11-01"},
		{Kind: RefSourceURL, Ref: "b", VerifiedAt: "2026-11-01"},
	}
	m.Rates = []RefRate{{
		Axis:   AxisInput,
		Unit:   RefUnitPer1MTokens,
		Amount: rcPtr(4),
		Evidence: []RefEvidence{
			{Ref: "a", Amount: 3, At: "2026-11-01"},
			{Ref: "b", Amount: 4 + 4e-13, At: "2026-11-01"},
		},
	}}

	resolved := m
	resolved.Conflicts = []RefConflict{{Axis: AxisInput, Ref: "b", Reason: "b is authoritative"}}
	if err := ValidateCatalog(rcCatalog(resolved)); err != nil {
		t.Fatalf("resolution choosing a same-grid observation must resolve the conflict: %v", err)
	}

	offGrid := m
	offGrid.Conflicts = []RefConflict{{Axis: AxisInput, Ref: "a", Reason: "a is one grid step from Amount"}}
	err := ValidateCatalog(rcCatalog(offGrid))
	if err == nil || !strings.Contains(err.Error(), "conflicting evidence on axis \"input\" without a resolution") {
		t.Fatalf("resolution choosing an off-grid observation must not resolve the conflict, got %v", err)
	}
}

func TestUnpricedRateWithConflictingEvidenceIsUnresolvable(t *testing.T) {
	// Amount=nil keeps the axis explicitly unpriced; no resolution can
	// choose an observed amount for a rate that publishes none.
	m := rcDraftModel()
	m.Sources = []RefSource{{Kind: RefSourceURL, Ref: "b", VerifiedAt: "2026-11-01"}}
	m.Rates = []RefRate{{
		Axis:   AxisInput,
		Unit:   RefUnitPer1MTokens,
		Amount: nil,
		Evidence: []RefEvidence{
			{Ref: "a", Amount: 3, At: "2026-11-01"},
			{Ref: "b", Amount: 4, At: "2026-11-01"},
		},
	}}
	m.Conflicts = []RefConflict{{Axis: AxisInput, Ref: "b", Reason: "declared but the rate is unpriced"}}

	err := ValidateCatalog(rcCatalog(m))
	if err == nil || !strings.Contains(err.Error(), "conflicting evidence on axis \"input\" without a resolution") {
		t.Fatalf("conflicting evidence on an unpriced rate must stay unresolved, got %v", err)
	}
}

func TestEvidenceAmountFiniteAndNonNegative(t *testing.T) {
	cases := []struct {
		name    string
		amount  float64
		wantErr string
	}{
		{name: "zero evidence amount is a free observation", amount: 0},
		{name: "NaN evidence amount", amount: math.NaN(), wantErr: "evidence[0].amount: not a finite number"},
		{name: "infinite evidence amount", amount: math.Inf(1), wantErr: "evidence[0].amount: not a finite number"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := rcDraftModel()
			m.Rates = []RefRate{{
				Axis:     AxisInput,
				Unit:     RefUnitPer1MTokens,
				Amount:   rcPtr(3),
				Evidence: []RefEvidence{{Ref: "a", Amount: tc.amount, At: "2026-11-01"}},
			}}
			err := ValidateCatalog(rcCatalog(m))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected rejection: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected finding %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// rcProblemPairs returns the (path, message fragment) sequence of every
// finding, in order, so tests can assert exact declaration-order output.
func rcProblemPairs(t *testing.T, err error) [][2]string {
	t.Helper()
	var catalogErr *CatalogError
	if !errors.As(err, &catalogErr) {
		t.Fatalf("ValidateCatalog must return *CatalogError, got %T (%v)", err, err)
	}
	pairs := make([][2]string, 0, len(catalogErr.Problems))
	for _, p := range catalogErr.Problems {
		pairs = append(pairs, [2]string{p.Path, p.Message})
	}
	return pairs
}

func rcWantProblems(t *testing.T, got [][2]string, want [][2]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d:\ngot  %v\nwant %v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i][0] != want[i][0] || !strings.Contains(got[i][1], want[i][1]) {
			t.Fatalf("finding %d = (%s, %q), want (%s, containing %q)", i, got[i][0], got[i][1], want[i][0], want[i][1])
		}
	}
}

func TestRateFindingsReportedInDeclarationOrder(t *testing.T) {
	// One model whose two rates carry simultaneous defects: the report
	// must list every finding, per rate in field order (axis, unit,
	// amount, then evidence fields in evidence order), with the unit
	// check skipped for an unknown axis and duplicate-axis registration
	// applying to unknown axes too.
	m := rcDraftModel()
	m.Rates = []RefRate{
		{
			Axis:     "bogus",
			Unit:     RefUnitPerImage,
			Amount:   rcPtr(-1),
			Evidence: []RefEvidence{{Ref: " ", Amount: math.NaN(), At: "soon"}},
		},
		{Axis: "bogus", Unit: RefUnitPerImage, Amount: rcPtr(math.NaN())},
	}

	got := rcProblemPairs(t, ValidateCatalog(rcCatalog(m)))
	want := [][2]string{
		{"models[0].rates[0].axis", `unknown axis "bogus"`},
		{"models[0].rates[0].amount", "negative price"},
		{"models[0].rates[0].evidence[0].ref", "evidence ref is required"},
		{"models[0].rates[0].evidence[0].amount", "not a finite number"},
		{"models[0].rates[0].evidence[0].at", "not an RFC 3339 instant or YYYY-MM-DD date"},
		{"models[0].rates[1].axis", `unknown axis "bogus"`},
		{"models[0].rates[1].axis", `duplicate rate for axis "bogus" (first at rates[0])`},
		{"models[0].rates[1].amount", "not a finite number"},
	}
	rcWantProblems(t, got, want)
}

func TestHeaderFindingsReportedInDeclarationOrder(t *testing.T) {
	// Every header field broken at once: findings appear in field order
	// (schema_version, version, source, generated_at, supersedes, digest,
	// review_sla_days) before any model finding, and a non-hex Digest
	// reports both the format and the content mismatch.
	m := rcDraftModel()
	m.Status = "live"
	c := rcCatalog(m)
	c.SchemaVersion = 99
	c.Version = ""
	c.Source = ""
	c.GeneratedAt = "now"
	c.Supersedes = "nothex"
	c.Digest = "alsonothex"
	c.ReviewSLADays = -1

	got := rcProblemPairs(t, ValidateCatalog(c))
	want := [][2]string{
		{"schema_version", "must be 1, got 99"},
		{"version", "catalog version is required"},
		{"source", "assembly source is required"},
		{"generated_at", "not an RFC 3339 instant or YYYY-MM-DD date"},
		{"supersedes", "must be a 64-hex digest"},
		{"digest", "must be a 64-hex digest"},
		{"digest", "does not match content"},
		{"review_sla_days", "must not be negative (-1)"},
		{"models[0].status", `must be draft, active or retired, got "live"`},
	}
	rcWantProblems(t, got, want)
}

func TestValidateCatalogDoesNotCheckChain(t *testing.T) {
	// ValidateCatalog only checks that Supersedes is well-formed hex; the
	// predecessor binding is ValidateCatalogChain's contract.
	prev, err := SealCatalog(rcCatalog(rcDraftModel()))
	if err != nil {
		t.Fatalf("seal prev: %v", err)
	}
	other, err := SealCatalog(rcCatalog(rcDraftModel()))
	if err != nil {
		t.Fatalf("seal other: %v", err)
	}
	other.Version = "rc-2"
	resealed, err := SealCatalog(other)
	if err != nil {
		t.Fatalf("reseal other: %v", err)
	}

	next := prev
	next.Supersedes = resealed.Digest
	next, err = SealCatalog(next)
	if err != nil {
		t.Fatalf("seal next: %v", err)
	}
	if err := ValidateCatalog(next); err != nil {
		t.Fatalf("well-formed Supersedes must pass ValidateCatalog even when it names the wrong predecessor: %v", err)
	}
	if err := ValidateCatalogChain(prev, next); err == nil {
		t.Fatal("the wrong predecessor must fail ValidateCatalogChain")
	}

	chained := prev
	chained.Supersedes = prev.Digest
	if sealed, err := SealCatalog(chained); err != nil {
		t.Fatalf("seal chained: %v", err)
	} else if err := ValidateCatalogChain(prev, sealed); err != nil {
		t.Fatalf("the actual predecessor digest must pass the chain check: %v", err)
	}
}
