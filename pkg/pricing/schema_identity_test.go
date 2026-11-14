package pricing

import (
	"errors"
	"testing"
)

// Collision tests for the two identity planes documented in SCHEMA.md
// "Model identity": ValidateCatalog deduplicates on the exact two-part
// (provider, model) pair as written, while MergeCatalogs and the canonical
// order use the full five-part key. Every case asserts the implemented
// behavior; the historical "full identity is the 5-tuple" prose this suite
// accompanies was corrected to match it.

// wantOneProblem asserts the catalog is rejected with exactly one finding
// whose message is want.
func wantOneProblem(t *testing.T, c Catalog, want string) {
	t.Helper()
	err := ValidateCatalog(c)
	if err == nil {
		t.Fatalf("catalog must be rejected with %q, got nil", want)
	}
	var ce *CatalogError
	if !errors.As(err, &ce) {
		t.Fatalf("error must be *CatalogError, got %T: %v", err, err)
	}
	if len(ce.Problems) != 1 || ce.Problems[0].Message != want {
		t.Fatalf("problems differ:\nwant exactly [%s]\ngot  %v", want, ce.Problems)
	}
}

// TestValidationIdentityIgnoresScopingDimensions pins that the duplicate
// key is exactly (provider, model): an entry differing from an earlier one
// only in a scoping dimension still collides. The region variant is also
// pinned in schema_semantic_test.go; tier and context_band complete the trio.
func TestValidationIdentityIgnoresScopingDimensions(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(m *RefModel)
	}{
		{"region", func(m *RefModel) { m.Region = "eu" }},
		{"tier", func(m *RefModel) { m.Tier = "pro" }},
		{"context_band", func(m *RefModel) { m.ContextBand = "128k" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			variant := semanticActiveModel()
			tc.mutate(&variant)
			wantOneProblem(t, semanticCatalog(semanticActiveModel(), variant),
				"duplicate entry for openai:gpt-sem (first at models[0])")
		})
	}
}

// TestValidationIdentityComparesNamesAsWritten pins that provider and model
// spellings are compared exactly: no trimming and no padding finding (the
// alias rules reject padding; the identity rules do not). A padded spelling
// is therefore a distinct identity, not a collision.
func TestValidationIdentityComparesNamesAsWritten(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(m *RefModel)
	}{
		{"padded provider", func(m *RefModel) { m.Provider = " openai" }},
		{"padded model", func(m *RefModel) { m.Model = " gpt-sem" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			padded := semanticActiveModel()
			tc.mutate(&padded)
			if err := ValidateCatalog(semanticCatalog(semanticActiveModel(), padded)); err != nil {
				t.Fatalf("distinct raw spellings must not collide and must not be a finding: %v", err)
			}
		})
	}
}

// TestMergeKeyIncludesScopingDimensions pins the split between the planes:
// MergeCatalogs unions by the full five-part key, so a scoping variant is
// appended rather than merged — and the merged snapshot then fails
// ValidateCatalog on the two-part validation identity.
func TestMergeKeyIncludesScopingDimensions(t *testing.T) {
	variant := semanticActiveModel()
	variant.Region = "eu"
	merged, err := MergeCatalogs(semanticCatalog(semanticActiveModel()), semanticCatalog(variant))
	if err != nil {
		t.Fatalf("merge must keep five-part identities distinct: %v", err)
	}
	if len(merged.Models) != 2 {
		t.Fatalf("merge output must carry both variants, got %d entries", len(merged.Models))
	}
	wantOneProblem(t, merged, "duplicate entry for openai:gpt-sem (first at models[0])")
}
