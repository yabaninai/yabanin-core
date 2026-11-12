package upstream

// Independent semantic pin of ValidateCatalogDocument for the complexity
// refactor: identity rules, finding order and per-section violations are
// asserted as exact problem-list oracles, so the decomposition cannot
// reorder, drop or merge findings. Written against the documented contract
// and pinned on the unmodified implementation.

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

// semDoc is a minimal valid schema-v2 document; each test mutates from it.
func semDoc() CatalogDocument {
	return CatalogDocument{
		SchemaVersion: CatalogSchemaV2,
		Version:       "sem-rev",
		Source:        "semantics-pin",
		AsOf:          "2024-06-01T12:00:00+02:00",
		Models: []CatalogModelEntry{
			{Provider: "p", Model: "m", Capabilities: map[string]bool{"chat": true}},
		},
	}
}

// semProblems asserts the document is rejected and returns the exact
// problem list for order-sensitive comparison.
func semProblems(t *testing.T, doc CatalogDocument) []string {
	t.Helper()
	err := ValidateCatalogDocument(doc)
	if err == nil {
		t.Fatalf("document must be rejected:\n%+v", doc)
	}
	var docErr *CatalogDocumentError
	if !errors.As(err, &docErr) {
		t.Fatalf("error must be *CatalogDocumentError, got %T: %v", err, err)
	}
	return docErr.Problems
}

// semWant fails with a side-by-side diff of the wanted vs actual problems.
func semWant(t *testing.T, doc CatalogDocument, want []string) {
	t.Helper()
	got := semProblems(t, doc)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("problems differ:\nwant:\n  %s\ngot:\n  %s",
			strings.Join(want, "\n  "), strings.Join(got, "\n  "))
	}
}

// TestCatalogHeaderFindingsOrder pins the header section: one finding per
// broken header field, emitted in document order before any row finding.
func TestCatalogHeaderFindingsOrder(t *testing.T) {
	doc := semDoc()
	doc.SchemaVersion = 7
	doc.Version = " "
	doc.Source = ""
	doc.AsOf = "junk"
	doc.Models = nil
	semWant(t, doc, []string{
		"unsupported schema_version 7 (this parser understands 1 and 2)",
		"version is required",
		"source is required",
		`as_of: not an RFC 3339 or YYYY-MM-DD instant ("junk")`,
	})
}

// TestCatalogModelRowFindingOrder pins the within-row order of one
// maximally broken model row: names, aliases in listed order, capabilities,
// limits in pinned field order, prices in pinned field order, window parse
// errors (which suppress the inversion check), then the deprecated_at
// schema guard before its parse error.
func TestCatalogModelRowFindingOrder(t *testing.T) {
	doc := semDoc()
	doc.SchemaVersion = CatalogSchemaV1
	doc.Models = []CatalogModelEntry{{
		Provider:      " p",
		Model:         "m ",
		Aliases:       []string{"", " ", " dup", "m", "x", "x"},
		Capabilities:  map[string]bool{"chat": true, "bogus": true},
		Limits:        &CatalogLimits{ContextWindowTokens: -1, MaxOutputTokens: -2, MaxTPM: -3, MaxRPM: -4},
		Price:         &CatalogPrice{Input: math.NaN(), Output: -1},
		EffectiveFrom: "bad1",
		EffectiveTo:   "bad2",
		DeprecatedAt:  "bad3",
	}}
	semWant(t, doc, []string{
		`models[0] (p:m): whitespace-padded provider name " p"`,
		`models[0] (p:m): whitespace-padded model name "m "`,
		`models[0] (p:m): empty alias`,
		`models[0] (p:m): empty alias`,
		`models[0] (p:m): whitespace-padded alias name " dup"`,
		`models[0] (p:m): alias "m" shadows the model name`,
		`models[0] (p:m): duplicate alias "x"`,
		"models[0] (p:m): unknown capability keys: bogus",
		"models[0] (p:m): limits.context_window_tokens must not be negative (-1)",
		"models[0] (p:m): limits.max_output_tokens must not be negative (-2)",
		"models[0] (p:m): limits.max_tpm must not be negative (-3)",
		"models[0] (p:m): limits.max_rpm must not be negative (-4)",
		"models[0] (p:m): price.input must be a finite number (NaN)",
		"models[0] (p:m): price.output must not be negative (-1)",
		`models[0].effective_from: not an RFC 3339 or YYYY-MM-DD instant ("bad1")`,
		`models[0].effective_to: not an RFC 3339 or YYYY-MM-DD instant ("bad2")`,
		"models[0] (p:m): deprecated_at requires schema_version 2",
		`models[0].deprecated_at: not an RFC 3339 or YYYY-MM-DD instant ("bad3")`,
	})
}

// TestCatalogCrossSectionFindingOrder pins the order across sections: row
// findings, then the deferred alias-vs-model-name pass over all rows, then
// customization rows, then the v1 customizations guard, then withdrawals.
func TestCatalogCrossSectionFindingOrder(t *testing.T) {
	doc := semDoc()
	doc.SchemaVersion = CatalogSchemaV1
	doc.Models = []CatalogModelEntry{
		{Provider: "p", Model: "a", Aliases: []string{"zed"}, Capabilities: map[string]bool{"bogus": true}},
		{Provider: "p", Model: "zed"},
	}
	doc.Customizations = []CatalogOverride{{Provider: "", Model: ""}}
	doc.WithdrawnProviders = []CatalogWithdrawal{{Provider: "", WithdrawnAt: ""}}
	semWant(t, doc, []string{
		"models[0] (p:a): unknown capability keys: bogus",
		`models (p:a): alias "zed" collides with an existing model name`,
		"customizations[0]: provider and model are required",
		"customizations require schema_version 2",
		"withdrawn_providers[0]: provider is required",
		"withdrawn_providers[0]: withdrawn_at is required",
	})
}

// TestCatalogIdentityIsProviderAndModel pins the entry identity rule the
// implementation enforces: the dedup key is exactly the trimmed
// (provider, model) pair — the catalog document has no scoping dimensions,
// unlike the pricing snapshot's 5-tuple identity (provider, model, region,
// tier, context_band) documented in pkg/pricing/SCHEMA.md.
func TestCatalogIdentityIsProviderAndModel(t *testing.T) {
	t.Run("two rows differing in every other attribute still collide", func(t *testing.T) {
		doc := semDoc()
		rich := doc.Models[0]
		rich.Aliases = []string{"x"}
		rich.Limits = &CatalogLimits{ContextWindowTokens: 8}
		rich.Price = &CatalogPrice{Input: 1}
		rich.EffectiveFrom, rich.EffectiveTo, rich.DeprecatedAt = "2020-01-01", "2021-01-01", "2020-06-01"
		doc.Models = append(doc.Models, CatalogModelEntry{Provider: "p", Model: "m"})
		semWant(t, doc, []string{"models[1]: duplicate entry for p:m"})
	})

	t.Run("the same model name under two providers is not a duplicate", func(t *testing.T) {
		doc := semDoc()
		doc.Models = append(doc.Models, CatalogModelEntry{Provider: "q", Model: "m"})
		if err := ValidateCatalogDocument(doc); err != nil {
			t.Fatalf("provider-scoped identity must allow the same model name: %v", err)
		}
	})

	t.Run("identity compares trimmed spellings", func(t *testing.T) {
		doc := semDoc()
		doc.Models[0].Provider = " p"
		doc.Models = append(doc.Models, CatalogModelEntry{Provider: "p", Model: " m"})
		semWant(t, doc, []string{
			`models[0] (p:m): whitespace-padded provider name " p"`,
			`models[1] (p:m): whitespace-padded model name " m"`,
			"models[1]: duplicate entry for p:m",
		})
	})

	t.Run("an alias never collides with another provider's model name", func(t *testing.T) {
		doc := semDoc()
		doc.Models[0].Aliases = []string{"shared"}
		doc.Models = append(doc.Models, CatalogModelEntry{Provider: "q", Model: "shared"})
		if err := ValidateCatalogDocument(doc); err != nil {
			t.Fatalf("alias/model collision check must be provider-scoped: %v", err)
		}
	})

	t.Run("an override restating a vendor pair is the override mechanism, not a duplicate", func(t *testing.T) {
		doc := semDoc()
		doc.Customizations = []CatalogOverride{{Provider: "p", Model: "m", Aliases: []string{"x"}}}
		if err := ValidateCatalogDocument(doc); err != nil {
			t.Fatalf("customizing a vendor row must not trip the model-row dedup: %v", err)
		}
	})

	t.Run("one pair customized at most once", func(t *testing.T) {
		doc := semDoc()
		doc.Customizations = []CatalogOverride{
			{Provider: "p", Model: "m"},
			{Provider: "p", Model: "m"},
		}
		semWant(t, doc, []string{"customizations[1]: duplicate override for p:m"})
	})

	t.Run("withdrawal identity is the provider alone", func(t *testing.T) {
		doc := semDoc()
		doc.WithdrawnProviders = []CatalogWithdrawal{
			{Provider: "p", WithdrawnAt: "2024-01-01"},
			{Provider: "p", WithdrawnAt: "2030-01-01"},
		}
		semWant(t, doc, []string{"withdrawn_providers[1]: duplicate withdrawal for provider p"})
	})
}

// TestCatalogWindowParseErrorSuppressesInversion pins that a window whose
// endpoints do not parse yields only the parse findings: the inversion
// check needs both instants and never fabricates a comparison on zeros.
func TestCatalogWindowParseErrorSuppressesInversion(t *testing.T) {
	doc := semDoc()
	doc.Models[0].EffectiveFrom = "junk"
	doc.Models[0].EffectiveTo = "2020-01-01"
	semWant(t, doc, []string{
		`models[0].effective_from: not an RFC 3339 or YYYY-MM-DD instant ("junk")`,
	})
}

// TestCatalogPriceFiniteAndNegative pins the two price guards field by
// field: non-finite values (reachable through the struct API; JSON cannot
// spell them) are rejected as non-finite, never as negative.
func TestCatalogPriceFiniteAndNegative(t *testing.T) {
	tests := []struct {
		name string
		set  func(*CatalogPrice)
		want string
	}{
		{"NaN input", func(p *CatalogPrice) { p.Input = math.NaN() },
			"price.input must be a finite number (NaN)"},
		{"positive infinity output", func(p *CatalogPrice) { p.Output = math.Inf(1) },
			"price.output must be a finite number (+Inf)"},
		{"negative infinity cache_w", func(p *CatalogPrice) { p.CacheW = math.Inf(-1) },
			"price.cache_w must be a finite number (-Inf)"},
		{"negative cache_r", func(p *CatalogPrice) { p.CacheR = -0.5 },
			"price.cache_r must not be negative (-0.5)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := semDoc()
			doc.Models[0].Price = &CatalogPrice{}
			tt.set(doc.Models[0].Price)
			semWant(t, doc, []string{"models[0] (p:m): " + tt.want})
		})
	}
}

// TestCatalogOverrideWindowAndDeprecationFindings pins the customization
// tail: the override-window inversion message, the v1 guard without the row
// key, and the deprecation window problem carried with it.
func TestCatalogOverrideWindowAndDeprecationFindings(t *testing.T) {
	t.Run("v1 guard fires per row and without the key", func(t *testing.T) {
		doc := semDoc()
		doc.SchemaVersion = CatalogSchemaV1
		doc.Customizations = []CatalogOverride{{Provider: "p", Model: "m", DeprecatedAt: "junk"}}
		semWant(t, doc, []string{
			"customizations[0]: deprecated_at requires schema_version 2",
			`customizations[0].deprecated_at: not an RFC 3339 or YYYY-MM-DD instant ("junk")`,
			"customizations require schema_version 2",
		})
	})

	t.Run("inverted override window", func(t *testing.T) {
		doc := semDoc()
		doc.Customizations = []CatalogOverride{{
			Provider: "p", Model: "m", EffectiveFrom: "2024-01-01", EffectiveTo: "2022-06-01",
		}}
		semWant(t, doc, []string{"customizations[0] (p:m): override window closes before it opens"})
	})

	t.Run("deprecation outside the override window", func(t *testing.T) {
		doc := semDoc()
		doc.Customizations = []CatalogOverride{{
			Provider: "p", Model: "m", EffectiveFrom: "2022-06-01", EffectiveTo: "2023-06-01",
			DeprecatedAt: "2023-06-01",
		}}
		semWant(t, doc, []string{
			"customizations[0] (p:m): deprecated_at 2023-06-01T00:00:00Z is not before the sell window closing 2023-06-01T00:00:00Z",
		})
	})
}
