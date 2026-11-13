package upstream

import (
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
)

// deprecationPhaseDocument is the single-row v2 fixture for the deprecation
// phase pin: window 2022-01-01..2025-01-01, deprecated from 2023-01-01.
func deprecationPhaseDocument() CatalogDocument {
	return CatalogDocument{
		SchemaVersion: CatalogSchemaV2,
		Version:       "dep-rev",
		Source:        "unit-test",
		Models: []CatalogModelEntry{{
			Provider:      "demo",
			Model:         "m1",
			EffectiveFrom: "2022-01-01",
			EffectiveTo:   "2025-01-01",
			DeprecatedAt:  "2023-01-01",
		}},
	}
}

type deprecationPhaseCase struct {
	name       string
	at         time.Time
	status     provider.ModelStatus
	available  bool
	deprecated bool
	state      provider.ModelLifecycle
}

// TestLifecycleReportDeprecationPhases pins the deprecation flag against the
// sell-window phases: it appears exactly from the deprecation instant while
// the model is still sellable, and never on a pending or retired row.
func TestLifecycleReportDeprecationPhases(t *testing.T) {
	c, err := BuildModelCatalog(deprecationPhaseDocument())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	depInstant := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []deprecationPhaseCase{
		{"pending before the window opens", time.Date(2021, 7, 1, 0, 0, 0, 0, time.UTC),
			provider.StatusPending, false, false, provider.LifecycleUnavailable},
		{"active before the deprecation instant", time.Date(2022, 7, 1, 0, 0, 0, 0, time.UTC),
			provider.StatusActive, true, false, provider.LifecycleDiscovered},
		{"deprecated exactly at the instant", depInstant,
			provider.StatusActive, true, true, provider.LifecycleDiscovered},
		{"deprecated inside the phase", time.Date(2023, 7, 1, 0, 0, 0, 0, time.UTC),
			provider.StatusActive, true, true, provider.LifecycleDiscovered},
		{"retired after the window closes", time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC),
			provider.StatusRetired, false, false, provider.LifecycleUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := BuildLifecycleReport(c, nil, tt.at)
			if len(report.Rows) != 1 {
				t.Fatalf("rows = %d, want 1: %+v", len(report.Rows), report.Rows)
			}
			r := report.Rows[0]
			if r.Provider != "demo" || r.Model != "m1" || !r.Discovered {
				t.Fatalf("row identity = %s:%s discovered=%v", r.Provider, r.Model, r.Discovered)
			}
			checkDeprecationPhaseRow(t, tt, r, depInstant)
		})
	}
}

// checkDeprecationPhaseRow asserts one phase row's catalog opinion against
// its case: availability, the deprecation flag with its instant, and the
// derived state.
func checkDeprecationPhaseRow(t *testing.T, tt deprecationPhaseCase, r ModelLifecycleRow, depInstant time.Time) {
	t.Helper()
	if r.CatalogStatus != tt.status {
		t.Fatalf("catalog status = %v, want %v", r.CatalogStatus, tt.status)
	}
	if r.Available != tt.available {
		t.Fatalf("available = %v, want %v", r.Available, tt.available)
	}
	if r.Deprecated != tt.deprecated {
		t.Fatalf("deprecated = %v, want %v", r.Deprecated, tt.deprecated)
	}
	if r.DeprecatedAt.IsZero() == tt.deprecated {
		t.Fatalf("deprecated_at = %v, want zero iff not deprecated", r.DeprecatedAt)
	}
	if tt.deprecated && !r.DeprecatedAt.Equal(depInstant) {
		t.Fatalf("deprecated_at = %v, want %v", r.DeprecatedAt, depInstant)
	}
	if r.State != tt.state {
		t.Fatalf("state = %v, want %v", r.State, tt.state)
	}
}

// wrongProviderFactReport builds the report for the identity pin: a
// configured fact naming another provider's model.
func wrongProviderFactReport(t *testing.T) LifecycleReport {
	t.Helper()
	c, err := BuildModelCatalog(sampleDocument())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	facts := []LifecycleFact{{Provider: "anthropic", Model: "gpt-doc", Configured: true}}
	return BuildLifecycleReport(c, facts, u2022)
}

// TestLifecycleReportWrongProviderFactRowSet pins that identity is the
// (provider, model) pair: the fact neither folds into openai:gpt-doc nor
// disturbs its row, and opens its own facts-only row instead.
func TestLifecycleReportWrongProviderFactRowSet(t *testing.T) {
	report := wrongProviderFactReport(t)
	wantKeys := []string{"anthropic:claude-doc", "anthropic:gpt-doc", "openai:gpt-doc"}
	if len(report.Rows) != len(wantKeys) {
		t.Fatalf("rows = %d, want %d: %+v", len(report.Rows), len(wantKeys), report.Rows)
	}
	for i, key := range wantKeys {
		if got := report.Rows[i].Provider + ":" + report.Rows[i].Model; got != key {
			t.Fatalf("row %d = %q, want %q", i, got, key)
		}
	}
}

func TestLifecycleReportWrongProviderFactRows(t *testing.T) {
	report := wrongProviderFactReport(t)
	drift := report.Rows[1]
	if drift.Discovered || !drift.Configured || drift.Tested {
		t.Fatalf("facts-only row = %+v", drift)
	}
	if drift.CatalogStatus != provider.StatusUnknown || !drift.Available {
		t.Fatalf("facts-only row must carry no catalog opinion but its provider stays admitted: %+v", drift)
	}
	vendor := report.Rows[2]
	if !vendor.Discovered || vendor.Configured || vendor.State != provider.LifecycleDiscovered {
		t.Fatalf("vendor row must stay fact-free: %+v", vendor)
	}
}

// TestLifecycleReportAliasAndCanonicalFactsMerge pins that facts naming the
// alias and the canonical spelling union into the single canonical row.
func TestLifecycleReportAliasAndCanonicalFactsMerge(t *testing.T) {
	c, err := BuildModelCatalog(sampleDocument())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	facts := []LifecycleFact{
		{Provider: "openai", Model: "gpt-doc-short", Configured: true},
		{Provider: "openai", Model: "gpt-doc", Tested: true},
	}
	report := BuildLifecycleReport(c, facts, u2022)
	if len(report.Rows) != 2 {
		t.Fatalf("rows = %d, want 2 (no alias fork): %+v", len(report.Rows), report.Rows)
	}
	gpt := report.Rows[1]
	if gpt.Model != "gpt-doc" || !gpt.Configured || !gpt.Tested {
		t.Fatalf("merged row = %+v", gpt)
	}
	if gpt.State != provider.LifecycleTested {
		t.Fatalf("state = %v, want tested", gpt.State)
	}
	want := LifecycleSummary{Discovered: 1, Tested: 1}
	if report.Summary != want {
		t.Fatalf("summary = %+v, want %+v", report.Summary, want)
	}
}

// TestLifecycleReportOrderingAndEntryOrder pins both orders: Entries()
// preserves document order, while report rows sort by (provider, model)
// with facts-only rows interleaved by the same key.
func TestLifecycleReportOrderingAndEntryOrder(t *testing.T) {
	doc := CatalogDocument{
		SchemaVersion: CatalogSchemaV1,
		Version:       "order-rev",
		Source:        "unit-test",
		Models: []CatalogModelEntry{
			{Provider: "zeta", Model: "b"},
			{Provider: "alpha", Model: "y"},
			{Provider: "alpha", Model: "x"},
			{Provider: "mid", Model: "a"},
		},
	}
	c, err := BuildModelCatalog(doc)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	wantDocOrder := []string{"zeta:b", "alpha:y", "alpha:x", "mid:a"}
	entries := c.Entries()
	for i, key := range wantDocOrder {
		if got := entries[i].Provider + ":" + entries[i].Model; got != key {
			t.Fatalf("entry %d = %q, want %q (document order)", i, got, key)
		}
	}
	report := BuildLifecycleReport(c, []LifecycleFact{{Provider: "beta", Model: "zz", Configured: true}}, u2022)
	wantSorted := []string{"alpha:x", "alpha:y", "beta:zz", "mid:a", "zeta:b"}
	for i, key := range wantSorted {
		if got := report.Rows[i].Provider + ":" + report.Rows[i].Model; got != key {
			t.Fatalf("row %d = %q, want %q", i, got, key)
		}
	}
}

// TestLifecycleReportAliasesArePrivateSortedCopies pins that each report
// sorts its own alias copy: the stored entry keeps document order and a
// mutated report slice never leaks into the next build.
func TestLifecycleReportAliasesArePrivateSortedCopies(t *testing.T) {
	doc := sampleDocument()
	doc.Models[0].Aliases = []string{"zz-alias", "aa-alias", "gpt-doc-short"}
	c, err := BuildModelCatalog(doc)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	report := BuildLifecycleReport(c, nil, u2022)
	got := report.Rows[1].Aliases // rows sorted: anthropic:claude-doc first
	wantSorted := []string{"aa-alias", "gpt-doc-short", "zz-alias"}
	if strings.Join(got, ",") != strings.Join(wantSorted, ",") {
		t.Fatalf("report aliases = %v, want %v", got, wantSorted)
	}
	e, ok := c.Entry("openai", "gpt-doc")
	if !ok || strings.Join(e.Aliases, ",") != "zz-alias,aa-alias,gpt-doc-short" {
		t.Fatalf("entry aliases = %v, want document order", e.Aliases)
	}
	report.Rows[1].Aliases[0] = "tampered"
	again := BuildLifecycleReport(c, nil, u2022)
	if again.Rows[1].Aliases[0] != "aa-alias" {
		t.Fatalf("rebuild leaked the mutated slice: %v", again.Rows[1].Aliases)
	}
}

// builtSampleEntries materializes the sample document's entries once for
// the per-row mapping pins.
func builtSampleEntries(t *testing.T) []provider.ModelCatalogEntry {
	t.Helper()
	c, err := BuildModelCatalog(sampleDocument())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	entries := c.Entries()
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	return entries
}

func TestBuildModelCatalogSnapshotMetadata(t *testing.T) {
	c, err := BuildModelCatalog(sampleDocument())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if c.Version() != "doc-rev-1" || c.SchemaVersion() != CatalogSchemaV1 || c.Source() != "unit-test" {
		t.Fatalf("metadata = (%q, v%d, %q)", c.Version(), c.SchemaVersion(), c.Source())
	}
	if !c.AsOf().Equal(u2022) {
		t.Fatalf("as_of = %v, want %v", c.AsOf(), u2022)
	}
}

func TestBuildModelCatalogGptDocEntryMapping(t *testing.T) {
	gpt := builtSampleEntries(t)[0]
	if gpt.Provider != "openai" || gpt.Model != "gpt-doc" {
		t.Fatalf("first entry = %s:%s, want openai:gpt-doc", gpt.Provider, gpt.Model)
	}
	wantCaps := provider.ModelCapabilities{Chat: true, Streaming: true, Tools: true, VisionInput: true}
	if gpt.Capabilities != wantCaps {
		t.Fatalf("gpt-doc capabilities = %+v, want %+v", gpt.Capabilities, wantCaps)
	}
	wantLimits := provider.ModelLimits{ContextWindowTokens: 200000, MaxOutputTokens: 8192, MaxTPM: 30000}
	if gpt.Limits != wantLimits {
		t.Fatalf("gpt-doc limits = %+v, want %+v", gpt.Limits, wantLimits)
	}
	wantPrice := pricing.Price{InputPerM: 2.5, OutputPerM: 10, CacheReadPerM: 1.25}
	if !gpt.PriceListed || gpt.Price != wantPrice {
		t.Fatalf("gpt-doc price = (%+v, listed=%v), want (%+v, true)", gpt.Price, gpt.PriceListed, wantPrice)
	}
	if strings.Join(gpt.Aliases, ",") != "gpt-doc-short" {
		t.Fatalf("gpt-doc aliases = %v", gpt.Aliases)
	}
}

func TestBuildModelCatalogGptDocWindow(t *testing.T) {
	gpt := builtSampleEntries(t)[0]
	if !gpt.EffectiveTo.Equal(u2024) || !gpt.EffectiveFrom.IsZero() {
		t.Fatalf("gpt-doc window = (%v, %v), want (zero, %v)", gpt.EffectiveFrom, gpt.EffectiveTo, u2024)
	}
	if !gpt.DeprecatedAt.IsZero() || gpt.Custom {
		t.Fatalf("gpt-doc deprecated_at/custom = (%v, %v), want (zero, false)", gpt.DeprecatedAt, gpt.Custom)
	}
}

func TestBuildModelCatalogClaudeDocEntryMapping(t *testing.T) {
	claude := builtSampleEntries(t)[1]
	if claude.Provider != "anthropic" || claude.Model != "claude-doc" {
		t.Fatalf("second entry = %s:%s, want anthropic:claude-doc", claude.Provider, claude.Model)
	}
	wantClaudeCaps := provider.ModelCapabilities{Chat: true, PDFInput: true}
	if claude.Capabilities != wantClaudeCaps {
		t.Fatalf("claude-doc capabilities = %+v, want %+v", claude.Capabilities, wantClaudeCaps)
	}
	if claude.Limits != (provider.ModelLimits{}) || claude.PriceListed || claude.Price != (pricing.Price{}) {
		t.Fatalf("claude-doc must carry no limits and no listing: %+v listed=%v", claude.Limits, claude.PriceListed)
	}
}

// TestBuildModelCatalogWithdrawalAdmissionIsHalfOpen pins the materialized
// withdrawal boundary: admitted strictly before WithdrawnAt, never at or
// after it, and providers without a row are always admitted.
func TestBuildModelCatalogWithdrawalAdmissionIsHalfOpen(t *testing.T) {
	c, err := BuildModelCatalog(sampleDocument())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !c.ProviderAdmitted("vendor-doc-gone", u2024.Add(-time.Nanosecond)) {
		t.Fatal("must be admitted before the withdrawal instant")
	}
	if c.ProviderAdmitted("vendor-doc-gone", u2024) {
		t.Fatal("must not be admitted at the withdrawal instant")
	}
	if c.ProviderAdmitted("vendor-doc-gone", u2030) {
		t.Fatal("must not be admitted after the withdrawal instant")
	}
	if !c.ProviderAdmitted("openai", u2030) {
		t.Fatal("a provider without a withdrawal row stays admitted")
	}
}

// TestBuildModelCatalogRejectsInvalidDocuments pins the defensive recheck:
// the builder returns the document validator's findings, not a partial
// snapshot.
func TestBuildModelCatalogRejectsInvalidDocuments(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(d *CatalogDocument)
		wantSub string
	}{
		{"missing version", func(d *CatalogDocument) { d.Version = "" }, "version is required"},
		{"negative price", func(d *CatalogDocument) {
			d.Models[0].Price = &CatalogPrice{Input: -1}
		}, "price.input must not be negative (-1)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := sampleDocument()
			tt.mutate(&doc)
			_, err := BuildModelCatalog(doc)
			if err == nil || !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantSub)
			}
		})
	}
}
