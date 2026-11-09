package upstream

// Boundary corpus for the catalog document: the exact instants where a sell
// window opens and closes, the extreme price field values a JSON document
// can carry, and the name forms that reach the namespace. Every case pins
// either a loud observable rejection or the previous behavior — a boundary
// that silently moves is the drift this packet exists to catch.

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/provider"
)

// boundaryDoc is the minimal valid document carrying one model row with the
// given overrides applied.
func boundaryDoc(mutate func(*CatalogModelEntry)) CatalogDocument {
	row := CatalogModelEntry{
		Provider:     "openai",
		Model:        "gpt-boundary",
		Capabilities: map[string]bool{"chat": true},
	}
	if mutate != nil {
		mutate(&row)
	}
	return CatalogDocument{
		SchemaVersion: CatalogSchemaV2,
		Version:       "boundary-rev",
		Source:        "boundary-walk",
		AsOf:          "2024-06-01",
		Models:        []CatalogModelEntry{row},
	}
}

// TestBoundaryWindowInstantValidation pins the document-level sell-window
// and deprecation-instant edges: the window must not close strictly before
// it opens (closing exactly at the opening instant is a legal zero-width
// window), and a deprecation instant must fall in the half-open phase
// [from, to) — equal to the opening is the first observable instant, equal
// to the closing is outside the observable range and is rejected. The
// comparisons run on parsed instants, so equivalent spellings in different
// UTC offsets collide exactly like their UTC forms.
func TestBoundaryWindowInstantValidation(t *testing.T) {
	cases := []struct {
		name    string
		from    string
		to      string
		dep     string
		wantErr string // empty = must validate clean
	}{
		{
			name: "window closing one microsecond before it opens",
			from: "2023-06-01T00:00:00Z", to: "2023-05-31T23:59:59.999999Z",
			wantErr: "sell window closes before it opens",
		},
		{
			name: "zero-width window closes exactly when it opens",
			from: "2023-06-01T00:00:00Z", to: "2023-06-01T00:00:00Z",
			wantErr: "",
		},
		{
			name: "deprecation exactly at the window opening",
			from: "2023-06-01T00:00:00Z", to: "2025-06-01T00:00:00Z", dep: "2023-06-01T00:00:00Z",
			wantErr: "",
		},
		{
			name: "deprecation one microsecond before the opening",
			from: "2023-06-01T00:00:00Z", to: "2025-06-01T00:00:00Z", dep: "2023-05-31T23:59:59.999999Z",
			wantErr: "deprecated_at 2023-05-31T23:59:59Z precedes the sell window opening",
		},
		{
			name: "deprecation exactly at the window closing",
			from: "2023-06-01T00:00:00Z", to: "2025-06-01T00:00:00Z", dep: "2025-06-01T00:00:00Z",
			wantErr: "deprecated_at 2025-06-01T00:00:00Z is not before the sell window closing",
		},
		{
			name: "deprecation one microsecond before the closing",
			from: "2023-06-01T00:00:00Z", to: "2025-06-01T00:00:00Z", dep: "2025-05-31T23:59:59.999999Z",
			wantErr: "",
		},
		{
			name: "deprecation equal to the closing instant in another UTC offset",
			from: "2023-06-01T00:00:00Z", to: "2025-06-01T02:00:00+02:00", dep: "2025-06-01T00:00:00Z",
			wantErr: "is not before the sell window closing",
		},
		{
			name: "deprecation strictly inside spelled in another UTC offset",
			from: "2023-06-01T00:00:00Z", to: "2025-06-01T00:00:00Z", dep: "2024-06-01T02:00:00+02:00",
			wantErr: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := boundaryDoc(func(e *CatalogModelEntry) {
				e.EffectiveFrom = tc.from
				e.EffectiveTo = tc.to
				e.DeprecatedAt = tc.dep
			})
			err := ValidateCatalogDocument(doc)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("boundary form must validate clean, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("boundary form must be rejected, want %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("rejection must name the boundary precisely: %v", err)
			}
		})
	}
}

// TestBoundaryPriceFieldValues drives the extreme price values a JSON
// document can carry through the real byte path: zero is a legal listed
// price (a free model), negative is rejected with the named field, an
// out-of-range number is a decode error before validation ever sees it, and
// the largest finite float passes validation — the catalog keeps no upper
// price bound because the billing-side price store stays authoritative.
func TestBoundaryPriceFieldValues(t *testing.T) {
	t.Run("zero price is listed and serves", func(t *testing.T) {
		cat, _ := jointBuild(t, jointDocBytes(t, boundaryDoc(func(e *CatalogModelEntry) {
			e.Price = &CatalogPrice{Input: 0, Output: 0}
		})))
		entry, st := cat.Lookup("openai", "gpt-boundary", jOpened)
		if st != provider.StatusActive {
			t.Fatalf("zero-priced model must be active at mid-window, got %v", st)
		}
		if !entry.PriceListed {
			t.Fatal("an explicit zero price must stay listed")
		}
		if entry.Price.InputPerM != 0 || entry.Price.OutputPerM != 0 {
			t.Fatalf("zero price must survive the build: %+v", entry.Price)
		}
	})
	t.Run("negative price names the field", func(t *testing.T) {
		doc := boundaryDoc(nil)
		raw := strings.Replace(string(jointDocBytes(t, doc)),
			`"gpt-boundary"`, `"gpt-boundary","price":{"input":-0.5,"output":2}`, 1)
		// Validation rides inside the parse: the finding surfaces on the
		// byte path, before any snapshot could exist.
		_, _, err := ParseCatalogDocument(bytes.NewReader([]byte(raw)))
		if err == nil {
			t.Fatal("negative price must fail the parse loudly")
		}
		if !strings.Contains(err.Error(), "price.input must not be negative") {
			t.Fatalf("rejection must name the field precisely: %v", err)
		}
	})
	t.Run("out-of-range number is a decode error", func(t *testing.T) {
		doc := boundaryDoc(nil)
		raw := strings.Replace(string(jointDocBytes(t, doc)),
			`"gpt-boundary"`, `"gpt-boundary","price":{"input":1e999,"output":2}`, 1)
		if _, _, err := ParseCatalogDocument(bytes.NewReader([]byte(raw))); err == nil {
			t.Fatal("1e999 must fail the decode (out of float64 range), not validation")
		}
	})
	t.Run("largest finite float validates and stays listed", func(t *testing.T) {
		cat, _ := jointBuild(t, jointDocBytes(t, boundaryDoc(func(e *CatalogModelEntry) {
			e.Price = &CatalogPrice{Input: math.MaxFloat64, Output: 2}
		})))
		entry, _ := cat.Lookup("openai", "gpt-boundary", jOpened)
		if !entry.PriceListed || entry.Price.InputPerM != math.MaxFloat64 {
			t.Fatalf("largest finite price must survive listed: %+v listed=%v", entry.Price, entry.PriceListed)
		}
	})
	t.Run("absent price is not listed", func(t *testing.T) {
		cat, _ := jointBuild(t, jointDocBytes(t, boundaryDoc(nil)))
		entry, _ := cat.Lookup("openai", "gpt-boundary", jOpened)
		if entry.PriceListed {
			t.Fatal("a row without a price must not be listed")
		}
	})
}

// TestBoundaryNamePaddingRejected pins the namespace boundary for invisible
// characters: validation compares trimmed names and the runtime snapshot
// layers trim again before installing, so a padded provider, model or alias
// that passed validation would be silently repaired into an identity other
// than the one the document wrote — contrary to the contract that nothing
// in a catalog document is silently repaired. The finding must be loud and
// name the padded field. Internal whitespace stays legal: names are opaque
// strings.
func TestBoundaryNamePaddingRejected(t *testing.T) {
	cases := []struct {
		name     string
		provider string
		model    string
		alias    string
		want     string
	}{
		{
			name: "provider padded with spaces", provider: "\topenai ", model: "gpt-boundary",
			want: "whitespace-padded provider name",
		},
		{
			name: "model padded with spaces", provider: "openai", model: "gpt-boundary ",
			want: "whitespace-padded model name",
		},
		{
			name: "alias padded with spaces", provider: "openai", model: "gpt-boundary", alias: " mini",
			want: "whitespace-padded alias",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := boundaryDoc(func(e *CatalogModelEntry) {
				e.Provider, e.Model = tc.provider, tc.model
				if tc.alias != "" {
					e.Aliases = []string{tc.alias}
				}
			})
			err := ValidateCatalogDocument(doc)
			if err == nil {
				t.Fatalf("padded name must be rejected with %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("rejection must name the padded field: %v", err)
			}
			// The strict rejection must hold through the build path too:
			// a padded row can never reach the namespace.
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			parsed, _, err := ParseCatalogDocument(bytes.NewReader(raw))
			if err == nil {
				if _, buildErr := BuildModelCatalog(parsed); buildErr == nil {
					t.Fatal("padded name must fail the build as well")
				}
			}
		})
	}
	t.Run("internal whitespace stays legal", func(t *testing.T) {
		cat, _ := jointBuild(t, jointDocBytes(t, boundaryDoc(func(e *CatalogModelEntry) {
			e.Model = "gpt-boundary turbo"
		})))
		if _, st := cat.Lookup("openai", "gpt-boundary turbo", jOpened); st != provider.StatusActive {
			t.Fatalf("internal whitespace is part of the name and must resolve, got %v", st)
		}
	})
	t.Run("padded override provider is a loud finding", func(t *testing.T) {
		doc := boundaryDoc(nil)
		doc.Customizations = []CatalogOverride{{Provider: "\topenai ", Model: "gpt-boundary"}}
		err := ValidateCatalogDocument(doc)
		if err == nil || !strings.Contains(err.Error(), "whitespace-padded provider name") {
			t.Fatalf("padded override provider must be rejected loudly: %v", err)
		}
	})
	t.Run("padded override model is a loud finding", func(t *testing.T) {
		doc := boundaryDoc(nil)
		doc.Customizations = []CatalogOverride{{Provider: "openai", Model: "gpt-boundary\t"}}
		err := ValidateCatalogDocument(doc)
		if err == nil || !strings.Contains(err.Error(), "whitespace-padded model name") {
			t.Fatalf("padded override model must be rejected loudly: %v", err)
		}
	})
	t.Run("padded withdrawal provider is a loud finding", func(t *testing.T) {
		doc := boundaryDoc(nil)
		doc.WithdrawnProviders = []CatalogWithdrawal{{Provider: " openai\t", WithdrawnAt: "2025-01-01"}}
		err := ValidateCatalogDocument(doc)
		if err == nil || !strings.Contains(err.Error(), `whitespace-padded provider name " openai\t"`) {
			t.Fatalf("padded withdrawal provider must be rejected loudly: %v", err)
		}
	})
}

// TestBoundaryNameNamespaceEdges pins the alias and model-name namespace
// edges: self-aliasing and alias-shadows-model are loud findings inside one
// provider, while the same alias or the same model name under two different
// providers are legal and independently resolvable; name length and Unicode
// are opaque to the namespace.
func TestBoundaryNameNamespaceEdges(t *testing.T) {
	t.Run("alias shadows its own model name", func(t *testing.T) {
		err := ValidateCatalogDocument(boundaryDoc(func(e *CatalogModelEntry) {
			e.Aliases = []string{"gpt-boundary"}
		}))
		if err == nil || !strings.Contains(err.Error(), `alias "gpt-boundary" shadows the model name`) {
			t.Fatalf("self-alias must be a loud finding: %v", err)
		}
	})
	t.Run("alias collides with a later row's model name", func(t *testing.T) {
		doc := boundaryDoc(func(e *CatalogModelEntry) { e.Aliases = []string{"gpt-later"} })
		doc.Models = append(doc.Models, CatalogModelEntry{
			Provider: "openai", Model: "gpt-later", Capabilities: map[string]bool{"chat": true},
		})
		err := ValidateCatalogDocument(doc)
		if err == nil || !strings.Contains(err.Error(), `alias "gpt-later" collides with an existing model name`) {
			t.Fatalf("cross-row shadow must be a loud finding: %v", err)
		}
	})
	t.Run("same alias under two providers resolves independently", func(t *testing.T) {
		doc := boundaryDoc(nil)
		doc.Models[0].Aliases = []string{"fast"}
		doc.Models = append(doc.Models, CatalogModelEntry{
			Provider: "anthropic", Model: "claude-boundary", Aliases: []string{"fast"},
			Capabilities: map[string]bool{"chat": true},
		})
		cat, _ := jointBuild(t, jointDocBytes(t, doc))
		for _, probe := range []struct{ provider, model string }{
			{"openai", "fast"}, {"anthropic", "fast"},
			{"openai", "gpt-boundary"}, {"anthropic", "claude-boundary"},
		} {
			if _, st := cat.Lookup(probe.provider, probe.model, jOpened); st != provider.StatusActive {
				t.Fatalf("provider-scoped name %s:%s must resolve active, got %v", probe.provider, probe.model, st)
			}
		}
	})
	t.Run("one-byte and unicode model names resolve", func(t *testing.T) {
		long := strings.Repeat("m", 129)
		doc := boundaryDoc(nil)
		doc.Models[0].Model = "a"
		doc.Models = append(doc.Models,
			CatalogModelEntry{Provider: "openai", Model: long, Capabilities: map[string]bool{"chat": true}},
			CatalogModelEntry{Provider: "openai", Model: "модель-тест", Capabilities: map[string]bool{"chat": true}},
		)
		cat, _ := jointBuild(t, jointDocBytes(t, doc))
		for _, name := range []string{"a", long, "модель-тест"} {
			if _, st := cat.Lookup("openai", name, jOpened); st != provider.StatusActive {
				t.Fatalf("opaque name %q must resolve active, got %v", name, st)
			}
		}
	})
}
