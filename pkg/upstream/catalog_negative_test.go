package upstream

// Negative-scenario corpus for N08-P06-T05: malformed, torn and hostile
// catalog documents must fail loudly. Every test here pins an observable
// rejection — an old or hostile document can never be silently repaired,
// defaulted or half-accepted (the drift the packet exists to kill).
//
// Test-only file: no production behavior is defined here; these tests
// constrain the failure surface the packet delivered.

import (
	"errors"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
)

// validV2Raw is a complete, valid schema-v2 document as one raw JSON string
// with no trailing whitespace: every proper byte prefix of it is therefore a
// torn document (never valid JSON itself), which the torn-corpus test relies
// on.
const validV2Raw = `{"schema_version":2,"version":"neg-rev-1","source":"negative-corpus","as_of":"2022-06-01","models":[{"provider":"openai","model":"gpt-doc","aliases":["gpt-doc-short"],"capabilities":{"chat":true,"tools":true},"limits":{"context_window_tokens":200000,"max_output_tokens":8192},"price":{"input":2.5,"output":10},"effective_from":"2022-01-01","effective_to":"2024-01-01","deprecated_at":"2023-01-01"}],"withdrawn_providers":[{"provider":"vendor-gone","withdrawn_at":"2024-01-01"}],"customizations":[{"provider":"openai","model":"gpt-doc","capabilities":{"chat":true},"effective_to":"2023-06-01"}]}`

func mustRejectRaw(t *testing.T, raw string, wantSub string) {
	t.Helper()
	_, _, err := ParseCatalogDocument(strings.NewReader(raw))
	if err == nil {
		t.Fatalf("hostile document must be rejected, got a valid parse:\n%s", raw)
	}
	if wantSub != "" && !strings.Contains(err.Error(), wantSub) {
		t.Fatalf("error %q does not mention %q", err, wantSub)
	}
}

// TestParseCatalogDocumentTorn pins that every torn copy of a valid document
// — each proper byte prefix, arbitrary truncations and appended garbage —
// fails loudly. A truncated document can never parse into a half-snapshot.
func TestParseCatalogDocumentTorn(t *testing.T) {
	t.Run("every proper byte prefix is rejected", func(t *testing.T) {
		for cut := 0; cut < len(validV2Raw); cut++ {
			torn := validV2Raw[:cut]
			if _, _, err := ParseCatalogDocument(strings.NewReader(torn)); err == nil {
				t.Fatalf("torn prefix of length %d parsed successfully — truncation must fail loudly:\n%s", cut, torn)
			}
		}
	})

	t.Run("truncations at structural boundaries are rejected", func(t *testing.T) {
		cuts := []string{
			`{"schema_version":2,`,
			`{"schema_version":2,"version":"v"`,
			`{"schema_version":2,"models":[`,
			`{"schema_version":2,"models":[{"provider":"openai"`,
			`{"schema_version":2,"models":[{"provider":"openai","capabilities":{"chat"`,
			`{"schema_version":2,"customizations":[{"provider":"openai","model":"gpt-doc"`,
		}
		for _, torn := range cuts {
			if _, _, err := ParseCatalogDocument(strings.NewReader(torn)); err == nil {
				t.Fatalf("torn document parsed successfully:\n%s", torn)
			}
		}
	})

	t.Run("trailing garbage after a valid document is rejected", func(t *testing.T) {
		for _, tail := range []string{"x", " {}", "[]", "null", "2"} {
			mustRejectRaw(t, validV2Raw+tail, "")
		}
	})

	t.Run("a trailing newline is still accepted", func(t *testing.T) {
		// Whitespace after the top-level value is legal JSON: the corpus
		// rejects torn bytes, not trailing formatting.
		if _, _, err := ParseCatalogDocument(strings.NewReader(validV2Raw + "\n")); err != nil {
			t.Fatalf("valid document with trailing newline must parse: %v", err)
		}
	})
}

// TestParseCatalogDocumentMalformed pins the rejection of inputs that are not
// catalog documents at all: empty input, JSON non-objects, a byte-order mark,
// and an empty object (which must fail with all three required-field findings
// aggregated in one loud error).
func TestParseCatalogDocumentMalformed(t *testing.T) {
	t.Run("empty and whitespace-only input", func(t *testing.T) {
		for _, raw := range []string{"", " ", "\n\t "} {
			if _, _, err := ParseCatalogDocument(strings.NewReader(raw)); err == nil {
				t.Fatalf("input %q must be rejected", raw)
			}
		}
	})

	t.Run("non-object JSON roots", func(t *testing.T) {
		for _, raw := range []string{`[]`, `"catalog"`, `42`, `null`, `true`, `-1.5`} {
			if _, _, err := ParseCatalogDocument(strings.NewReader(raw)); err == nil {
				t.Fatalf("JSON root %s must be rejected", raw)
			}
		}
	})

	t.Run("UTF-8 byte-order mark is rejected", func(t *testing.T) {
		mustRejectRaw(t, "\uFEFF"+validV2Raw, "")
	})

	t.Run("empty object aggregates every required-field finding", func(t *testing.T) {
		_, _, err := ParseCatalogDocument(strings.NewReader(`{}`))
		if err == nil {
			t.Fatal("empty document must be rejected")
		}
		var docErr *CatalogDocumentError
		if !errors.As(err, &docErr) {
			t.Fatalf("error must be *CatalogDocumentError, got %T", err)
		}
		for _, want := range []string{"schema_version is required", "version is required", "source is required"} {
			found := false
			for _, p := range docErr.Problems {
				if strings.Contains(p, want) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("aggregated problems %v miss %q", docErr.Problems, want)
			}
		}
	})
}

// TestParseCatalogDocumentHostileTypes pins that JSON members with the wrong
// type are decode errors, never silent defaults: every hostile member below
// must fail the parse.
func TestParseCatalogDocumentHostileTypes(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"schema_version as string", `{"schema_version":"2","version":"v","source":"s"}`},
		{"schema_version as bool", `{"schema_version":true,"version":"v","source":"s"}`},
		{"version as number", `{"schema_version":2,"version":7,"source":"s"}`},
		{"as_of as number", `{"schema_version":2,"version":"v","source":"s","as_of":20220101}`},
		{"models as string", `{"schema_version":2,"version":"v","source":"s","models":"gpt-doc"}`},
		{"models as object", `{"schema_version":2,"version":"v","source":"s","models":{"provider":"openai"}}`},
		{"model entry as number", `{"schema_version":2,"version":"v","source":"s","models":[7]}`},
		{"model aliases as string", `{"schema_version":2,"version":"v","source":"s","models":[{"provider":"openai","model":"m","aliases":"m-short"}]}`},
		{"model capabilities as array", `{"schema_version":2,"version":"v","source":"s","models":[{"provider":"openai","model":"m","capabilities":["chat"]}]}`},
		{"model capabilities member as string", `{"schema_version":2,"version":"v","source":"s","models":[{"provider":"openai","model":"m","capabilities":{"chat":"yes"}}]}`},
		{"model limits as number", `{"schema_version":2,"version":"v","source":"s","models":[{"provider":"openai","model":"m","limits":5}]}`},
		{"model price as string", `{"schema_version":2,"version":"v","source":"s","models":[{"provider":"openai","model":"m","price":"free"}]}`},
		{"model effective_to as number", `{"schema_version":2,"version":"v","source":"s","models":[{"provider":"openai","model":"m","effective_to":20240101}]}`},
		{"withdrawn_providers as string", `{"schema_version":2,"version":"v","source":"s","withdrawn_providers":"openai"}`},
		{"withdrawn_at as bool", `{"schema_version":2,"version":"v","source":"s","withdrawn_providers":[{"provider":"p","withdrawn_at":true}]}`},
		{"customizations as number", `{"schema_version":2,"version":"v","source":"s","customizations":7}`},
		{"customization entry as array", `{"schema_version":2,"version":"v","source":"s","customizations":[["openai","m"]]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mustRejectRaw(t, tt.raw, "")
		})
	}
}

// TestV1DocumentCarryingV2DataRejects pins the schema-drift guard at the
// full parse/build boundary: a v1 document that carries v2 vocabulary
// (deprecated_at, customizations) must fail with the precise bump-schema
// error — never a silent drop of the data an old parser does not
// understand.
func TestV1DocumentCarryingV2DataRejects(t *testing.T) {
	buildDoc := func(modelDep, depInCustom, customSection bool) string {
		var b strings.Builder
		b.WriteString(`{"schema_version":1,"version":"drift-doc","source":"negative-corpus"`)
		if modelDep {
			b.WriteString(`,"models":[{"provider":"openai","model":"gpt-doc","deprecated_at":"2023-01-01"}]`)
		}
		if customSection || depInCustom {
			b.WriteString(`,"customizations":[{"provider":"openai","model":"gpt-doc"`)
			if depInCustom {
				b.WriteString(`,"deprecated_at":"2023-01-01"`)
			}
			b.WriteString(`}]`)
		}
		b.WriteString(`}`)
		return b.String()
	}

	t.Run("deprecated_at on a model row is rejected precisely", func(t *testing.T) {
		_, _, err := ParseCatalogDocument(strings.NewReader(buildDoc(true, false, false)))
		if err == nil {
			t.Fatal("v1 model row with deprecated_at must be rejected")
		}
		if !strings.Contains(err.Error(), "deprecated_at requires schema_version 2") {
			t.Fatalf("error must name the schema bump precisely, got: %v", err)
		}
	})

	t.Run("deprecated_at inside a customization is rejected precisely", func(t *testing.T) {
		_, _, err := ParseCatalogDocument(strings.NewReader(buildDoc(false, true, true)))
		if err == nil {
			t.Fatal("v1 customization with deprecated_at must be rejected")
		}
		if !strings.Contains(err.Error(), "deprecated_at requires schema_version 2") {
			t.Fatalf("error must name the schema bump precisely, got: %v", err)
		}
		if !strings.Contains(err.Error(), "customizations require schema_version 2") {
			t.Fatalf("the customization section itself must also be flagged, got: %v", err)
		}
	})

	t.Run("customizations section alone is rejected precisely", func(t *testing.T) {
		_, _, err := ParseCatalogDocument(strings.NewReader(buildDoc(false, false, true)))
		if err == nil {
			t.Fatal("v1 document with a customizations section must be rejected")
		}
		if !strings.Contains(err.Error(), "customizations require schema_version 2") {
			t.Fatalf("error must name the schema bump precisely, got: %v", err)
		}
	})

	t.Run("no v1 document is accepted while it carries v2 data", func(t *testing.T) {
		for _, raw := range []string{
			buildDoc(true, false, false),
			buildDoc(false, true, true),
			buildDoc(false, false, true),
			buildDoc(true, true, true),
		} {
			// The rejection must happen before any snapshot exists: the
			// parse returns no document and no fingerprint to install.
			_, sum, err := ParseCatalogDocument(strings.NewReader(raw))
			if err == nil || sum != "" {
				t.Fatalf("v1-with-v2-data must yield no snapshot fingerprint, got sum=%q err=%v", sum, err)
			}
		}
	})
}

// TestDeprecatedAtWindowEdgesRejects pins the half-open window edges of the
// deprecation phase at the document level: an instant at or after the sell
// window close, or before the open, is dead data and must be named by the
// validation error.
func TestDeprecatedAtWindowEdgesRejects(t *testing.T) {
	tests := []struct {
		name    string
		dep     string
		wantSub string
	}{
		{"at the window close is outside the half-open window", "2024-01-01", "is not before the sell window closing"},
		{"after the window close is dead data", "2030-01-01", "is not before the sell window closing"},
		{"before the window open is a born-deprecated row", "2021-01-01", "precedes the sell window opening"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := sampleV2Document()
			doc.Models[0].EffectiveFrom = "2022-01-01"
			doc.Models[0].EffectiveTo = "2024-01-01"
			doc.Models[0].DeprecatedAt = tt.dep
			err := ValidateCatalogDocument(doc)
			if err == nil {
				t.Fatalf("deprecated_at %s must be rejected", tt.dep)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("error %q does not mention %q", err, tt.wantSub)
			}
		})
	}

	t.Run("one nanosecond before the close is the last valid instant", func(t *testing.T) {
		doc := sampleV2Document()
		doc.Models[0].EffectiveFrom = "2022-01-01"
		doc.Models[0].EffectiveTo = "2024-01-01T00:00:00Z"
		doc.Models[0].DeprecatedAt = "2023-12-31T23:59:59.999999999Z"
		if err := ValidateCatalogDocument(doc); err != nil {
			t.Fatalf("last instant inside the window must be accepted: %v", err)
		}
	})
}

// TestBuildModelCatalogMergeRevalidationFailures pins the snapshot
// re-validation layer: a customization may pass document-level validation —
// override aliases are deliberately not checked against the vendor name
// space there, because an override may restate the alias of the row it
// replaces — but the merged snapshot must still be built with full
// NewModelCatalog strictness. Every collision below must fail the build
// loudly: the merged name space can never contain an ambiguous name.
func TestBuildModelCatalogMergeRevalidationFailures(t *testing.T) {
	assertMergeFails := func(t *testing.T, doc CatalogDocument, wantSubs ...string) {
		t.Helper()
		if err := ValidateCatalogDocument(doc); err != nil {
			t.Fatalf("precondition: document must pass document-level validation: %v", err)
		}
		_, err := BuildModelCatalog(doc)
		if err == nil {
			t.Fatalf("merge must fail loudly for customization %#v", doc.Customizations)
		}
		for _, want := range wantSubs {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not mention %q", err, want)
			}
		}
	}

	t.Run("override alias collides with a vendor model name", func(t *testing.T) {
		doc := sampleV2Document()
		doc.Customizations = []CatalogOverride{{
			Provider: "openai", Model: "claude-doc",
			Aliases: []string{"gpt-doc"}, // vendor model of the same provider
		}}
		assertMergeFails(t, doc, "merged catalog with 1 override(s)", "collides with an existing model name")
	})

	t.Run("override alias collides with a vendor alias of another row", func(t *testing.T) {
		doc := sampleV2Document()
		doc.Customizations = []CatalogOverride{{
			Provider: "anthropic", Model: "claude-doc",
			Aliases: []string{"gpt-doc-short"}, // vendor alias bound to openai:gpt-doc
		}}
		// Cross-provider names do not collide: use the same provider.
		doc.Customizations[0].Provider = "openai"
		doc.Customizations[0].Model = "zz-other"
		doc.Models = append(doc.Models, CatalogModelEntry{Provider: "openai", Model: "zz-other"})
		assertMergeFails(t, doc, "duplicate alias")
	})

	t.Run("custom model named like a vendor alias is a fork attempt", func(t *testing.T) {
		// (openai, gpt-doc-short) is vendor-unknown as a pair — the alias
		// belongs to openai:gpt-doc — so the customization would introduce
		// a custom model occupying the vendor alias's name. The merged
		// name space must reject the ambiguity.
		doc := sampleV2Document()
		doc.Customizations = []CatalogOverride{{
			Provider: "openai", Model: "gpt-doc-short",
			Capabilities: map[string]bool{"chat": true},
		}}
		assertMergeFails(t, doc, "merged catalog with 1 override(s)", "collides with an existing model name")
	})

	t.Run("custom model name shadows another override alias", func(t *testing.T) {
		doc := sampleV2Document()
		doc.Customizations = []CatalogOverride{
			{ // introduces llama as a custom model with alias local-llama
				Provider: "selfhosted", Model: "llama",
				Aliases: []string{"local-llama"},
			},
			{ // second override aliases the same name in the same provider
				Provider: "selfhosted", Model: "vendor-proxy",
				Aliases: []string{"local-llama"},
			},
		}
		// The document-level override-alias map catches direct duplicates,
		// so route this corpus through the runtime merge instead, where the
		// alias collides with the custom MODEL name of the first override.
		if err := ValidateCatalogDocument(doc); err == nil {
			t.Fatal("precondition: duplicate override alias must fail document validation")
		}
		// Rename the second alias to collide only with the first custom
		// model's name — document validation allows it (custom names are
		// not model rows), the merge must not.
		doc.Customizations[1].Aliases = []string{"llama"}
		assertMergeFails(t, doc, "merged catalog with 2 override(s)")
	})

	t.Run("alias equals another override's custom model name", func(t *testing.T) {
		doc := sampleV2Document()
		doc.Customizations = []CatalogOverride{
			{Provider: "selfhosted", Model: "llama-local"},
			{Provider: "selfhosted", Model: "router", Aliases: []string{"llama-local"}},
		}
		assertMergeFails(t, doc, "merged catalog with 2 override(s)")
	})

	t.Run("override alias collides with a custom model introduced later in the same set", func(t *testing.T) {
		doc := sampleV2Document()
		doc.Customizations = []CatalogOverride{
			{Provider: "openai", Model: "gpt-doc", Aliases: []string{"new-name"}},
			{Provider: "openai", Model: "new-name"}, // custom model named like the alias above
		}
		// Direct name-vs-alias order in the merged namespace: the second
		// row is a vendor-unknown pair, so it introduces a custom model
		// whose name the first override's alias already occupies.
		assertMergeFails(t, doc, "merged catalog with 2 override(s)")
	})
}

// TestPricingTamperViaOverrideRejected pins the pricing authority rule with
// hostile input: a customization that smuggles a price member into the
// document must not move the merged pricing — the billing-side price store
// and the vendor row stay authoritative, and no custom row can mint a price.
//
// The document decoder has no price field on an override row (the runtime
// ModelOverride cannot even represent one), so the tamper is unrepresentable
// in the merge; the assertions below pin the observable outcome: identical
// vendor pricing before and after, and never a listed price on a custom row.
func TestPricingTamperViaOverrideRejected(t *testing.T) {
	t.Run("smuggled price member on an override never takes effect", func(t *testing.T) {
		raw := `{
		  "schema_version": 2, "version": "tamper-1", "source": "negative-corpus",
		  "models": [
		    {"provider": "openai", "model": "gpt-doc", "price": {"input": 2.5, "output": 10, "cache_w": 1.25, "cache_r": 0.1},
		     "capabilities": {"chat": true}, "effective_from": "2022-01-01", "effective_to": "2024-01-01"}
		  ],
		  "customizations": [
		    {"provider": "openai", "model": "gpt-doc", "capabilities": {"chat": true},
		     "price": {"input": 0, "output": 0, "cache_w": 0, "cache_r": 0}}
		  ]
		}`
		doc, _, err := ParseCatalogDocument(strings.NewReader(raw))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		merged, err := BuildModelCatalog(doc)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		e, st := merged.Lookup("openai", "gpt-doc", u2022)
		if st != provider.StatusActive {
			t.Fatalf("status = %v", st)
		}
		if !e.PriceListed ||
			e.Price.InputPerM != 2.5 || e.Price.OutputPerM != 10 ||
			e.Price.CacheWritePerM != 1.25 || e.Price.CacheReadPerM != 0.1 {
			t.Fatalf("override tampered the vendor pricing: listed=%v price=%+v", e.PriceListed, e.Price)
		}
	})

	t.Run("custom row can never mint a price", func(t *testing.T) {
		raw := `{
		  "schema_version": 2, "version": "tamper-2", "source": "negative-corpus",
		  "models": [],
		  "customizations": [
		    {"provider": "selfhosted", "model": "free-tier",
		     "capabilities": {"chat": true}, "price": {"input": 0}}
		  ]
		}`
		doc, _, err := ParseCatalogDocument(strings.NewReader(raw))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		merged, err := BuildModelCatalog(doc)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		e, st := merged.Lookup("selfhosted", "free-tier", u2022)
		if st != provider.StatusActive || !e.Custom {
			t.Fatalf("custom row = (status %v, custom %v)", st, e.Custom)
		}
		if e.PriceListed || (e.Price != (pricing.Price{})) {
			t.Fatalf("custom row minted a price: listed=%v price=%+v", e.PriceListed, e.Price)
		}
	})

	t.Run("an attribute-replacing override still leaves pricing untouched", func(t *testing.T) {
		doc := sampleV2Document()
		// The override replaces every attribute the merge allows it to
		// replace; pricing is not part of that set.
		doc.Customizations = []CatalogOverride{{
			Provider: "openai", Model: "gpt-doc",
			Capabilities:  map[string]bool{"embeddings": true},
			Limits:        &CatalogLimits{ContextWindowTokens: 1},
			Aliases:       []string{"x"},
			EffectiveFrom: "2022-06-01", EffectiveTo: "2022-06-02",
			DeprecatedAt: "2022-06-01T12:00:00Z",
		}}
		merged, err := BuildModelCatalog(doc)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		e, _ := merged.Entry("openai", "gpt-doc")
		if !e.PriceListed || e.Price.InputPerM != 2.5 || e.Price.OutputPerM != 10 || e.Price.CacheWritePerM != 0 || e.Price.CacheReadPerM != 1.25 {
			t.Fatalf("full-attribute override moved the vendor pricing: listed=%v price=%+v", e.PriceListed, e.Price)
		}
	})
}
