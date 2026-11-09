package upstream

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/provider"
)

var (
	u2022 = time.Date(2022, 6, 1, 0, 0, 0, 0, time.UTC)
	u2024 = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	u2030 = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
)

func sampleDocument() CatalogDocument {
	return CatalogDocument{
		SchemaVersion: CatalogSchemaV1,
		Version:       "doc-rev-1",
		Source:        "unit-test",
		AsOf:          "2022-06-01",
		Models: []CatalogModelEntry{
			{
				Provider: "openai",
				Model:    "gpt-doc",
				Aliases:  []string{"gpt-doc-short"},
				Capabilities: map[string]bool{
					"chat": true, "streaming": true, "tools": true, "vision_input": true,
				},
				Limits:      &CatalogLimits{ContextWindowTokens: 200000, MaxOutputTokens: 8192, MaxTPM: 30000},
				Price:       &CatalogPrice{Input: 2.5, Output: 10, CacheR: 1.25},
				EffectiveTo: "2024-01-01",
			},
			{
				Provider:     "anthropic",
				Model:        "claude-doc",
				Capabilities: map[string]bool{"chat": true, "pdf_input": true, "speech_synthesis": false},
			},
		},
		WithdrawnProviders: []CatalogWithdrawal{
			{Provider: "vendor-doc-gone", WithdrawnAt: "2024-01-01"},
		},
	}
}

func TestValidateCatalogDocument(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(d *CatalogDocument)
		wantErrSub string
	}{
		{"missing schema version", func(d *CatalogDocument) { d.SchemaVersion = 0 }, "schema_version is required"},
		{"unsupported schema version", func(d *CatalogDocument) { d.SchemaVersion = 99 }, "unsupported schema_version 99"},
		{"missing version", func(d *CatalogDocument) { d.Version = "" }, "version is required"},
		{"missing source", func(d *CatalogDocument) { d.Source = "  " }, "source is required"},
		{"unparseable as_of", func(d *CatalogDocument) { d.AsOf = "not-a-date" }, "as_of"},
		{"empty model name", func(d *CatalogDocument) { d.Models[0].Model = "" }, "provider and model are required"},
		{"empty provider name", func(d *CatalogDocument) { d.Models[0].Provider = "" }, "provider and model are required"},
		{"duplicate model", func(d *CatalogDocument) {
			dup := d.Models[0]
			dup.Aliases = nil
			d.Models = append(d.Models, dup)
		}, "duplicate entry"},
		{"duplicate alias within provider", func(d *CatalogDocument) {
			d.Models = append(d.Models, CatalogModelEntry{Provider: "openai", Model: "another", Aliases: []string{"gpt-doc-short"}})
		}, "already used in this provider"},
		{"model name shadows an alias declared earlier", func(d *CatalogDocument) {
			d.Models = append(d.Models, CatalogModelEntry{Provider: "openai", Model: "gpt-doc-short"})
		}, "collides with an existing model name"},
		{"alias equals its own model", func(d *CatalogDocument) {
			d.Models[0].Aliases = []string{"gpt-doc"}
		}, "shadows the model name"},
		{"unknown capability key", func(d *CatalogDocument) {
			d.Models[0].Capabilities["realtime_audio"] = true
		}, "unknown capability keys: realtime_audio"},
		{"negative limit", func(d *CatalogDocument) { d.Models[0].Limits.MaxRPM = -5 }, "max_rpm must not be negative"},
		{"negative price", func(d *CatalogDocument) { d.Models[0].Price.Input = -1 }, "price.input must not be negative"},
		{"inverted sell window", func(d *CatalogDocument) {
			d.Models[0].EffectiveFrom = "2024-01-01"
			d.Models[0].EffectiveTo = "2022-06-01"
		}, "closes before it opens"},
		{"unparseable effective_from", func(d *CatalogDocument) { d.Models[0].EffectiveFrom = "junk" }, "effective_from"},
		{"withdrawal without provider", func(d *CatalogDocument) {
			d.WithdrawnProviders[0].Provider = ""
		}, "provider is required"},
		{"withdrawal without instant", func(d *CatalogDocument) {
			d.WithdrawnProviders[0].WithdrawnAt = ""
		}, "withdrawn_at is required"},
		{"unparseable withdrawal instant", func(d *CatalogDocument) {
			d.WithdrawnProviders[0].WithdrawnAt = "31/12/2026"
		}, "withdrawn_at"},
		{"duplicate withdrawal for one provider", func(d *CatalogDocument) {
			d.WithdrawnProviders = append(d.WithdrawnProviders,
				CatalogWithdrawal{Provider: "vendor-doc-gone", WithdrawnAt: "2030-01-01"})
		}, "duplicate withdrawal for provider vendor-doc-gone"},
		{"multiple negative limits listed in field order", func(d *CatalogDocument) {
			d.Models[0].Limits.MaxRPM = -5
			d.Models[0].Limits.ContextWindowTokens = -1
		}, "limits.context_window_tokens must not be negative (-1); models[0] (openai:gpt-doc): limits.max_rpm must not be negative (-5)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := sampleDocument()
			tt.mutate(&doc)
			err := ValidateCatalogDocument(doc)
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErrSub)
			}
			if !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Fatalf("error %q does not mention %q", err, tt.wantErrSub)
			}
		})
	}
}

func TestValidateCatalogDocumentAccepts(t *testing.T) {
	t.Run("sample document is valid", func(t *testing.T) {
		if err := ValidateCatalogDocument(sampleDocument()); err != nil {
			t.Fatalf("sample document must validate: %v", err)
		}
	})
	t.Run("withdrawal-only document without models is valid", func(t *testing.T) {
		doc := CatalogDocument{
			SchemaVersion:      CatalogSchemaV1,
			Version:            "retire-only",
			Source:             "unit-test",
			WithdrawnProviders: []CatalogWithdrawal{{Provider: "p", WithdrawnAt: "2024-01-01T00:00:00Z"}},
		}
		if err := ValidateCatalogDocument(doc); err != nil {
			t.Fatalf("withdrawal-only document must validate: %v", err)
		}
	})
	t.Run("validation does not mutate the document", func(t *testing.T) {
		doc := sampleDocument()
		capsBefore := len(doc.Models[0].Capabilities)
		if err := ValidateCatalogDocument(doc); err != nil {
			t.Fatalf("validate: %v", err)
		}
		if len(doc.Models[0].Capabilities) != capsBefore {
			t.Fatalf("validation mutated capabilities map: %v", doc.Models[0].Capabilities)
		}
	})
}

func TestParseCatalogDocument(t *testing.T) {
	t.Run("round trip with stable fingerprint", func(t *testing.T) {
		raw := `{
		  "schema_version": 1,
		  "version": "2026-10-29.1",
		  "source": "operator export",
		  "as_of": "2026-10-29",
		  "models": [
		    {
		      "provider": "openai",
		      "model": "gpt-x",
		      "aliases": ["gpt-x-alias"],
		      "capabilities": {"chat": true, "tools": true},
		      "limits": {"context_window_tokens": 400000},
		      "price": {"input": 1.25, "output": 5},
		      "effective_to": "2027-01-01T00:00:00Z"
		    }
		  ],
		  "withdrawn_providers": [
		    {"provider": "legacy", "withdrawn_at": "2026-01-01"}
		  ]
		}`
		doc1, sum1, err := ParseCatalogDocument(strings.NewReader(raw))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		doc2, sum2, err := ParseCatalogDocument(strings.NewReader(raw))
		if err != nil {
			t.Fatalf("reparse: %v", err)
		}
		if sum1 == "" || sum1 != sum2 {
			t.Fatalf("fingerprint unstable: %q vs %q", sum1, sum2)
		}
		if !reflect.DeepEqual(doc1, doc2) {
			t.Fatalf("reparse differs:\n%+v\nvs\n%+v", doc1, doc2)
		}
		if doc1.Version != "2026-10-29.1" || len(doc1.Models) != 1 || len(doc1.WithdrawnProviders) != 1 {
			t.Fatalf("parsed document incomplete: %+v", doc1)
		}
	})

	t.Run("broken JSON is rejected", func(t *testing.T) {
		if _, _, err := ParseCatalogDocument(strings.NewReader("{not json")); err == nil {
			t.Fatal("malformed JSON must fail")
		}
	})

	t.Run("semantic problems reject the whole document", func(t *testing.T) {
		raw := `{
		  "schema_version": 1, "version": "v", "source": "s",
		  "models": [
		    {"provider": "openai", "model": "a", "capabilities": {"warp_drive": true}},
		    {"provider": "openai", "model": "b", "limits": {"max_tpm": -1}}
		  ]
		}`
		_, _, err := ParseCatalogDocument(strings.NewReader(raw))
		if err == nil {
			t.Fatal("document with unknown capability and negative limit must fail")
		}
		var docErr *CatalogDocumentError
		if !errors.As(err, &docErr) {
			t.Fatalf("error must be *CatalogDocumentError, got %T", err)
		} else if len(docErr.Problems) != 2 {
			t.Fatalf("expected both problems aggregated, got: %v", docErr.Problems)
		}
	})
}

func TestBuildModelCatalog(t *testing.T) {
	doc := sampleDocument()
	c, err := BuildModelCatalog(doc)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if c.Version() != "doc-rev-1" || c.SchemaVersion() != CatalogSchemaV1 || c.EntryCount() != 2 {
		t.Fatalf("snapshot metadata wrong: v=%q schema=%d entries=%d", c.Version(), c.SchemaVersion(), c.EntryCount())
	}
	if !c.AsOf().Equal(u2022) {
		t.Fatalf("as_of = %v, want %v", c.AsOf(), u2022)
	}

	t.Run("attributes transferred", func(t *testing.T) {
		e, st := c.Lookup("openai", "gpt-doc", u2022)
		if st != provider.StatusActive {
			t.Fatalf("status = %v", st)
		}
		if !e.Capabilities.Chat || !e.Capabilities.Tools || !e.Capabilities.VisionInput || e.Capabilities.ImageGeneration {
			t.Fatalf("capabilities = %+v", e.Capabilities)
		}
		if e.Limits.ContextWindowTokens != 200000 || e.Limits.MaxTPM != 30000 {
			t.Fatalf("limits = %+v", e.Limits)
		}
		if !e.PriceListed || e.Price.InputPerM != 2.5 || e.Price.OutputPerM != 10 || e.Price.CacheReadPerM != 1.25 {
			t.Fatalf("price = %+v listed=%v", e.Price, e.PriceListed)
		}
	})

	t.Run("explicit false stays false", func(t *testing.T) {
		e, _ := c.Entry("anthropic", "claude-doc")
		if e.Capabilities.SpeechSynthesis {
			t.Fatal("speech_synthesis: false must not flip to true")
		}
		if !e.Capabilities.PDFInput {
			t.Fatal("pdf_input: true lost")
		}
	})

	t.Run("windows and withdrawals enforced", func(t *testing.T) {
		if st := c.Status("openai", "gpt-doc", u2024); st != provider.StatusRetired {
			t.Fatalf("status after window close = %v", st)
		}
		if c.ProviderAdmitted("vendor-doc-gone", u2024) {
			t.Fatal("withdrawn provider must not be admitted")
		}
		if !c.ProviderAdmitted("openai", u2030) {
			t.Fatal("provider without a withdrawal row must stay admitted")
		}
	})
}

func TestInstallCatalogAndRevert(t *testing.T) {
	prev := provider.CurrentModelCatalog()
	t.Cleanup(func() { provider.SetModelCatalog(prev) })

	doc := sampleDocument()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	installed, sum, err := InstallCatalog(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if installed == nil || sum == "" {
		t.Fatal("install must return the snapshot and fingerprint")
	}
	if got := provider.CurrentModelCatalog(); got != installed {
		t.Fatal("installed snapshot is not the process-wide catalog")
	}

	// The install is visible to the provider-side admission surface.
	if provider.ProviderAdmitted("vendor-doc-gone") {
		t.Fatal("withdrawn provider must be rejected after install")
	}

	provider.SetModelCatalog(nil)
	if got := provider.CurrentModelCatalog(); got != nil {
		t.Fatal("clearing the catalog must restore the no-catalog state")
	}
}

// TestReconcileStaticNamesDelistNegative is the document-level form of the
// card's negative scenario: names in a static surface are classified against
// the catalog, and a withdrawn name comes back retired no matter how green
// the static list claims it is.
func TestReconcileStaticNamesDelistNegative(t *testing.T) {
	c, err := BuildModelCatalog(sampleDocument())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	refs := []StaticModelRef{
		{Provider: "openai", Model: "gpt-doc"},       // active at u2022
		{Provider: "openai", Model: "gpt-doc-short"}, // alias of an entry
		{Provider: "openai", Model: "org-custom"},    // not in the catalog
		{Provider: "anthropic", Model: "claude-doc"}, // active, no window
	}
	got := ReconcileStaticNames(c, refs, u2022)
	want := []provider.ModelStatus{
		provider.StatusActive,
		provider.StatusActive,
		provider.StatusUnknown,
		provider.StatusActive,
	}
	for i, w := range want {
		if got[i].Status != w {
			t.Fatalf("ref %d (%s:%s) = %v, want %v", i, refs[i].Provider, refs[i].Model, got[i].Status, w)
		}
	}

	retired := ReconcileStaticNames(c, refs[:1], u2030)
	if retired[0].Status != provider.StatusRetired {
		t.Fatalf("static list still carries a withdrawn model as %v", retired[0].Status)
	}
}

func TestCapabilityVocabularyIsComplete(t *testing.T) {
	vocabulary := CatalogCapabilityFields()
	want := []string{
		"chat", "streaming", "tools", "vision_input", "pdf_input", "audio_input",
		"image_generation", "speech_transcription", "speech_synthesis", "embeddings",
	}
	if len(vocabulary) != len(want) {
		t.Fatalf("vocabulary size = %d, want %d: %v", len(vocabulary), len(want), vocabulary)
	}
	for _, name := range want {
		if field, ok := vocabulary[name]; !ok || field == "" {
			t.Fatalf("capability %q missing from the pinned vocabulary", name)
		}
	}
}

// lifecycleSampleFacts are the installation facts used by the report tests:
// a fully enabled model named through its alias, a configured-only model, a
// drift row the catalog has no opinion about, and a model under a provider
// the catalog withdrew.
func lifecycleSampleFacts() []LifecycleFact {
	return []LifecycleFact{
		{Provider: "openai", Model: "gpt-doc-short", Configured: true, Tested: true},
		{Provider: "anthropic", Model: "claude-doc", Configured: true},
		{Provider: "openai", Model: "org-custom", Configured: true},
		{Provider: "vendor-doc-gone", Model: "legacy-model", Configured: true, Tested: true},
	}
}

// TestBuildLifecycleReport shows the discovered/configured/tested/unavailable
// states separately. The decisive rows are the negative ones: after the sell
// window closes, the fully configured and tested model reports unavailable
// (its facts stay visible on the row), and the withdrawn provider drags its
// configured models down with it.
func TestBuildLifecycleReport(t *testing.T) {
	c, err := BuildModelCatalog(sampleDocument())
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	report := BuildLifecycleReport(c, lifecycleSampleFacts(), u2022)

	t.Run("rows sorted and complete", func(t *testing.T) {
		wantKeys := []string{
			"anthropic:claude-doc",
			"openai:gpt-doc",
			"openai:org-custom",
			"vendor-doc-gone:legacy-model",
		}
		if len(report.Rows) != len(wantKeys) {
			t.Fatalf("rows = %d, want %d: %+v", len(report.Rows), len(wantKeys), report.Rows)
		}
		for i, key := range wantKeys {
			got := report.Rows[i].Provider + ":" + report.Rows[i].Model
			if got != key {
				t.Fatalf("row %d = %q, want %q", i, got, key)
			}
		}
		if !report.At.Equal(u2022) {
			t.Fatalf("report instant = %v, want %v", report.At, u2022)
		}
	})

	t.Run("each state shows separately", func(t *testing.T) {
		tests := []struct {
			key        string
			discovered bool
			configured bool
			tested     bool
			available  bool
			catalog    provider.ModelStatus
			state      provider.ModelLifecycle
		}{
			{"anthropic:claude-doc", true, true, false, true, provider.StatusActive, provider.LifecycleConfigured},
			{"openai:gpt-doc", true, true, true, true, provider.StatusActive, provider.LifecycleTested},
			{"openai:org-custom", false, true, false, true, provider.StatusUnknown, provider.LifecycleConfigured},
			// The provider withdrawal only starts in 2024: in 2022 the model
			// under it is still fully available.
			{"vendor-doc-gone:legacy-model", false, true, true, true, provider.StatusUnknown, provider.LifecycleTested},
		}
		byKey := make(map[string]ModelLifecycleRow, len(report.Rows))
		for _, r := range report.Rows {
			byKey[r.Provider+":"+r.Model] = r
		}
		for _, tt := range tests {
			t.Run(tt.key, func(t *testing.T) {
				r, ok := byKey[tt.key]
				if !ok {
					t.Fatalf("row %q missing", tt.key)
				}
				if r.Discovered != tt.discovered || r.Configured != tt.configured ||
					r.Tested != tt.tested || r.Available != tt.available {
					t.Fatalf("facts = (discovered=%v configured=%v tested=%v available=%v), want (%v %v %v %v)",
						r.Discovered, r.Configured, r.Tested, r.Available,
						tt.discovered, tt.configured, tt.tested, tt.available)
				}
				if r.CatalogStatus != tt.catalog {
					t.Fatalf("catalog status = %v, want %v", r.CatalogStatus, tt.catalog)
				}
				if r.State != tt.state {
					t.Fatalf("state = %v, want %v", r.State, tt.state)
				}
			})
		}
	})

	t.Run("configured alias folds into the canonical row", func(t *testing.T) {
		for _, r := range report.Rows {
			if r.Model == "gpt-doc-short" {
				t.Fatal("a configured alias must not fork a second row")
			}
			if r.Model == "gpt-doc" {
				if !r.Configured || !r.Tested {
					t.Fatalf("canonical row lost the alias facts: %+v", r)
				}
				if len(r.Aliases) != 1 || r.Aliases[0] != "gpt-doc-short" {
					t.Fatalf("aliases = %v, want [gpt-doc-short]", r.Aliases)
				}
			}
		}
	})

	t.Run("summary counts every row exactly once", func(t *testing.T) {
		want := LifecycleSummary{Discovered: 0, Configured: 2, Tested: 2, Unavailable: 0}
		if report.Summary != want {
			t.Fatalf("summary = %+v, want %+v", report.Summary, want)
		}
		total := want.Discovered + want.Configured + want.Tested + want.Unavailable
		if total != len(report.Rows) {
			t.Fatalf("summary total %d != rows %d", total, len(report.Rows))
		}
	})

	t.Run("delisted model reports unavailable while its facts stay visible", func(t *testing.T) {
		later := BuildLifecycleReport(c, lifecycleSampleFacts(), u2030)
		var gptDoc, legacy *ModelLifecycleRow
		for i := range later.Rows {
			switch later.Rows[i].Model {
			case "gpt-doc":
				gptDoc = &later.Rows[i]
			case "legacy-model":
				legacy = &later.Rows[i]
			}
		}
		if gptDoc == nil || legacy == nil {
			t.Fatalf("expected rows missing: %+v", later.Rows)
		}
		// The static configuration still names the model, the last test
		// passed — and it is still not green: the catalog window closed.
		if gptDoc.State != provider.LifecycleUnavailable || gptDoc.Available {
			t.Fatalf("delisted model = (%v, available=%v), want unavailable", gptDoc.State, gptDoc.Available)
		}
		if !gptDoc.Configured || !gptDoc.Tested || gptDoc.CatalogStatus != provider.StatusRetired {
			t.Fatalf("delisted row must keep its facts visible: %+v", gptDoc)
		}
		// The provider withdrawal makes even unknown-name rows unavailable.
		if legacy.State != provider.LifecycleUnavailable || legacy.Available {
			t.Fatalf("row under a withdrawn provider = (%v, available=%v)", legacy.State, legacy.Available)
		}
		want := LifecycleSummary{Configured: 2, Unavailable: 2}
		if later.Summary != want {
			t.Fatalf("later summary = %+v, want %+v", later.Summary, want)
		}
	})

	t.Run("report is deterministic and self-consistent", func(t *testing.T) {
		again := BuildLifecycleReport(c, lifecycleSampleFacts(), u2022)
		if !reflect.DeepEqual(report, again) {
			t.Fatalf("rebuild differs:\n%+v\nvs\n%+v", report, again)
		}
		for _, r := range report.Rows {
			want := c.Lifecycle(r.Provider, r.Model, u2022, r.Configured, r.Tested)
			if r.State != want {
				t.Fatalf("row %s:%s state %v disagrees with the classifier %v",
					r.Provider, r.Model, r.State, want)
			}
		}
	})

	t.Run("aliases are sorted in the row", func(t *testing.T) {
		doc := sampleDocument()
		doc.Models[0].Aliases = append(doc.Models[0].Aliases, "zz-alias", "aa-alias")
		cc, err := BuildModelCatalog(doc)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		rep := BuildLifecycleReport(cc, nil, u2022)
		var aliases []string
		for _, r := range rep.Rows {
			if r.Model == "gpt-doc" {
				aliases = r.Aliases
			}
		}
		want := []string{"aa-alias", "gpt-doc-short", "zz-alias"}
		if !reflect.DeepEqual(aliases, want) {
			t.Fatalf("aliases = %v, want %v", aliases, want)
		}
	})
}

func TestBuildLifecycleReportEdges(t *testing.T) {
	t.Run("empty inputs yield an honest empty report", func(t *testing.T) {
		report := BuildLifecycleReport(nil, nil, u2022)
		if report.Rows == nil || len(report.Rows) != 0 {
			t.Fatalf("rows = %#v, want empty non-nil", report.Rows)
		}
		if (report.Summary != LifecycleSummary{}) {
			t.Fatalf("summary = %+v, want zero", report.Summary)
		}
	})

	t.Run("no catalog: facts-only report", func(t *testing.T) {
		facts := []LifecycleFact{
			{Provider: "openai", Model: "custom-a", Configured: true, Tested: true},
			{Provider: "openai", Model: "custom-b", Configured: true},
		}
		report := BuildLifecycleReport(nil, facts, u2022)
		if len(report.Rows) != 2 {
			t.Fatalf("rows = %d, want 2", len(report.Rows))
		}
		if report.Rows[0].State != provider.LifecycleTested || report.Rows[1].State != provider.LifecycleConfigured {
			t.Fatalf("states = %v, %v; want tested, configured", report.Rows[0].State, report.Rows[1].State)
		}
		if report.Rows[0].CatalogStatus != provider.StatusUnknown || report.Rows[0].Discovered {
			t.Fatalf("facts-only row must carry no catalog opinion: %+v", report.Rows[0])
		}
	})

	t.Run("factless names and flagless facts are not reported", func(t *testing.T) {
		c, err := BuildModelCatalog(sampleDocument())
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		facts := []LifecycleFact{
			{Provider: "openai", Model: "claude-doc"},     // wrong provider: no facts match
			{Provider: "anthropic", Model: "claude-doc"},  // all flags false: skipped
			{Provider: "anthropic", Model: "another-row"}, // all flags false: skipped
		}
		report := BuildLifecycleReport(c, facts, u2022)
		if len(report.Rows) != 2 { // the two catalog rows, no fact rows
			t.Fatalf("rows = %d, want 2: %+v", len(report.Rows), report.Rows)
		}
		for _, r := range report.Rows {
			if !r.Discovered || r.Configured || r.Tested {
				t.Fatalf("unexpected fact rows: %+v", r)
			}
		}
		if report.Summary.Discovered != 2 {
			t.Fatalf("summary = %+v, want 2 discovered", report.Summary)
		}
	})

	t.Run("duplicate facts merge by union", func(t *testing.T) {
		facts := []LifecycleFact{
			{Provider: "openai", Model: "solo", Configured: true},
			{Provider: "openai", Model: "solo", Tested: true},
		}
		report := BuildLifecycleReport(nil, facts, u2022)
		if len(report.Rows) != 1 {
			t.Fatalf("rows = %d, want 1 merged row", len(report.Rows))
		}
		if !report.Rows[0].Configured || !report.Rows[0].Tested || report.Rows[0].State != provider.LifecycleTested {
			t.Fatalf("merged row = %+v, want configured+tested", report.Rows[0])
		}
	})
}

// sampleV2Document extends the v1 sample with the schema-2 vocabulary: a
// vendor deprecation instant and a customizations section (one vendor-row
// override, one custom model).
func sampleV2Document() CatalogDocument {
	doc := sampleDocument()
	doc.SchemaVersion = CatalogSchemaV2
	doc.Version = "doc-rev-2"
	// gpt-doc: sells until 2024, deprecated (flagged EOL) from 2023.
	doc.Models[0].DeprecatedAt = "2023-01-01"
	doc.Customizations = []CatalogOverride{
		{
			// Vendor-row override: enable pdf_input, retire early.
			Provider: "openai", Model: "gpt-doc",
			Capabilities: map[string]bool{
				"chat": true, "streaming": true, "tools": true,
				"vision_input": true, "pdf_input": true,
			},
			Aliases:     []string{"gpt-doc-short", "gpt-doc-alias"},
			EffectiveTo: "2023-06-01",
		},
		{
			// Custom model: not in the vendor snapshot.
			Provider: "selfhosted", Model: "llama-local",
			Capabilities: map[string]bool{"chat": true},
			Aliases:      []string{"llama"},
		},
	}
	return doc
}

func TestValidateCatalogDocumentV2Features(t *testing.T) {
	t.Run("v1 document must not carry deprecated_at", func(t *testing.T) {
		doc := sampleDocument()
		doc.Models[0].DeprecatedAt = "2023-01-01"
		err := ValidateCatalogDocument(doc)
		if err == nil || !strings.Contains(err.Error(), "deprecated_at requires schema_version 2") {
			t.Fatalf("err = %v, want deprecated_at schema guard", err)
		}
	})

	t.Run("v1 document must not carry customizations", func(t *testing.T) {
		doc := sampleDocument()
		doc.Customizations = []CatalogOverride{{Provider: "openai", Model: "gpt-doc"}}
		err := ValidateCatalogDocument(doc)
		if err == nil || !strings.Contains(err.Error(), "customizations require schema_version 2") {
			t.Fatalf("err = %v, want customizations schema guard", err)
		}
	})

	t.Run("v2 document with both features is accepted", func(t *testing.T) {
		if err := ValidateCatalogDocument(sampleV2Document()); err != nil {
			t.Fatalf("v2 sample rejected: %v", err)
		}
	})

	t.Run("override validation", func(t *testing.T) {
		tests := []struct {
			name    string
			mutate  func(d *CatalogDocument)
			wantSub string
		}{
			{"missing provider", func(d *CatalogDocument) {
				d.Customizations[0].Provider = ""
			}, "customizations[0]: provider and model are required"},
			{"missing model", func(d *CatalogDocument) {
				d.Customizations[0].Model = " "
			}, "customizations[0]: provider and model are required"},
			{"duplicate override", func(d *CatalogDocument) {
				d.Customizations = append(d.Customizations, CatalogOverride{Provider: "openai", Model: "gpt-doc"})
			}, "duplicate override for openai:gpt-doc"},
			{"alias shadows its own model", func(d *CatalogDocument) {
				d.Customizations[0].Aliases = []string{"gpt-doc"}
			}, `alias "gpt-doc" shadows the model name`},
			{"duplicate alias within one override", func(d *CatalogDocument) {
				d.Customizations[0].Aliases = []string{"x", "x"}
			}, `duplicate alias "x"`},
			{"alias used by another override in the provider", func(d *CatalogDocument) {
				d.Customizations = append(d.Customizations, CatalogOverride{
					Provider: "openai", Model: "claude-doc", Aliases: []string{"gpt-doc-alias"},
				})
			}, "is already used by another override in this provider"},
			{"unknown capability key", func(d *CatalogDocument) {
				d.Customizations[1].Capabilities["realtime_audio"] = true
			}, "unknown capability keys: realtime_audio"},
			{"negative limit", func(d *CatalogDocument) {
				d.Customizations[0].Limits = &CatalogLimits{MaxRPM: -5}
			}, "limits.max_rpm must not be negative (-5)"},
			{"inverted override window", func(d *CatalogDocument) {
				d.Customizations[0].EffectiveFrom = "2024-01-01"
				d.Customizations[0].EffectiveTo = "2022-06-01"
			}, "override window closes before it opens"},
			{"deprecation outside the override window", func(d *CatalogDocument) {
				d.Customizations[0].DeprecatedAt = "2024-01-01" // after its 2023-06-01 close
			}, "deprecated_at 2024-01-01T00:00:00Z is not before the sell window closing"},
			{"unparseable deprecated_at", func(d *CatalogDocument) {
				d.Customizations[1].DeprecatedAt = "junk"
			}, "customizations[1].deprecated_at"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				doc := sampleV2Document()
				tt.mutate(&doc)
				err := ValidateCatalogDocument(doc)
				if err == nil {
					t.Fatalf("expected error containing %q", tt.wantSub)
				}
				if !strings.Contains(err.Error(), tt.wantSub) {
					t.Fatalf("error %q does not mention %q", err, tt.wantSub)
				}
			})
		}
	})
}

// TestBuildModelCatalogWithCustomizations pins the merged document flow:
// deprecation rides the vendor rows, overrides replace explicit attributes
// and narrow windows, custom models are introduced, and a vendor retirement
// survives any override claim.
func TestBuildModelCatalogWithCustomizations(t *testing.T) {
	c, err := BuildModelCatalog(sampleV2Document())
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	t.Run("metadata and entry set", func(t *testing.T) {
		if c.Version() != "doc-rev-2" || c.SchemaVersion() != CatalogSchemaV2 {
			t.Fatalf("metadata = (%q, v%d)", c.Version(), c.SchemaVersion())
		}
		if c.EntryCount() != 3 { // two vendor rows + llama-local
			t.Fatalf("entries = %d, want 3", c.EntryCount())
		}
	})

	t.Run("vendor deprecation rides the row", func(t *testing.T) {
		// The override restates gpt-doc-short in its replacement alias
		// set, so the alias still resolves; the vendor deprecation
		// instant is untouched by the attribute replacement.
		e, st := c.Lookup("openai", "gpt-doc-short", u2022)
		if st != provider.StatusActive {
			t.Fatalf("status = %v", st)
		}
		want := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
		if !e.DeprecatedAt.Equal(want) {
			t.Fatalf("deprecated_at = %v, want %v", e.DeprecatedAt, want)
		}
		if !c.Deprecated("openai", "gpt-doc", want) || !c.Deprecated("openai", "gpt-doc-short", want) {
			t.Fatal("deprecation must flag through exact name and alias")
		}
	})

	t.Run("override replaced attributes and narrowed the window", func(t *testing.T) {
		u2023 := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
		e, _ := c.Entry("openai", "gpt-doc")
		if !e.Capabilities.PDFInput {
			t.Fatal("override capability pdf_input lost")
		}
		aliases := map[string]struct{}{}
		for _, a := range e.Aliases {
			aliases[a] = struct{}{}
		}
		if _, ok := aliases["gpt-doc-alias"]; !ok {
			t.Fatalf("override alias set not applied: %v", e.Aliases)
		}
		// Early retirement at 2023-06-01, and the deprecation flag lives
		// only inside the sellable phase (2023-01-01 .. 2023-06-01).
		if st := c.Status("openai", "gpt-doc", u2023.AddDate(0, 7, 0)); st != provider.StatusRetired {
			t.Fatalf("early-retired model = %v, want retired", st)
		}
		if !c.Deprecated("openai", "gpt-doc", u2023) {
			t.Fatal("model must be flagged inside the narrowed window")
		}
		if c.Deprecated("openai", "gpt-doc", u2023.AddDate(0, 7, 0)) {
			t.Fatal("retired model is not deprecated — retirement dominates")
		}
	})

	t.Run("custom model introduced", func(t *testing.T) {
		e, st := c.Lookup("selfhosted", "llama", u2022)
		if st != provider.StatusActive || !e.Custom {
			t.Fatalf("custom model = (status %v, custom %v)", st, e.Custom)
		}
	})

	t.Run("vendor retirement survives an override claim", func(t *testing.T) {
		doc := sampleV2Document()
		// The override claims a life until 2030, past the vendor's own
		// 2024 retirement — the merge must keep the vendor window.
		doc.Customizations[0].EffectiveTo = "2030-01-01"
		merged, err := BuildModelCatalog(doc)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if st := merged.Status("openai", "gpt-doc", u2030); st != provider.StatusRetired {
			t.Fatalf("override resurrected a model the vendor retired: %v at %v", st, u2030)
		}
		if st := merged.Status("openai", "gpt-doc", u2022); st != provider.StatusActive {
			t.Fatalf("healthy period disturbed: %v", st)
		}
	})

	t.Run("lifecycle report shows the deprecation separately", func(t *testing.T) {
		u2023 := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
		facts := []LifecycleFact{
			{Provider: "openai", Model: "gpt-doc", Configured: true, Tested: true},
			{Provider: "selfhosted", Model: "llama-local", Configured: true},
		}
		report := BuildLifecycleReport(c, facts, u2023)
		var gpt *ModelLifecycleRow
		for i := range report.Rows {
			if report.Rows[i].Model == "gpt-doc" {
				gpt = &report.Rows[i]
			}
		}
		if gpt == nil {
			t.Fatalf("gpt-doc row missing: %+v", report.Rows)
		}
		// Deprecated is distinct from unavailable: the model still
		// serves and reports tested, but carries the flag and instant.
		if !gpt.Deprecated || gpt.DeprecatedAt.IsZero() {
			t.Fatalf("deprecated row flag = (%v, %v)", gpt.Deprecated, gpt.DeprecatedAt)
		}
		if gpt.State != provider.LifecycleTested || gpt.State == provider.LifecycleUnavailable {
			t.Fatalf("deprecated sellable model state = %v, want tested", gpt.State)
		}
		if !gpt.Available {
			t.Fatal("deprecated sellable model must stay available")
		}
		// Before the deprecation instant the flag is off.
		before := BuildLifecycleReport(c, facts, u2022)
		for i := range before.Rows {
			if before.Rows[i].Model == "gpt-doc" && (before.Rows[i].Deprecated || !before.Rows[i].DeprecatedAt.IsZero()) {
				t.Fatalf("pre-deprecation row carries the flag: %+v", before.Rows[i])
			}
		}
	})

	t.Run("merged build is deterministic", func(t *testing.T) {
		facts := lifecycleSampleFacts()
		u2023 := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
		first := BuildLifecycleReport(c, facts, u2023)
		again := BuildLifecycleReport(c, facts, u2023)
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("rebuild differs:\n%+v\nvs\n%+v", first, again)
		}
	})
}

// TestParseCatalogDocumentV2Fingerprint pins that the raw-bytes SHA256
// provenance covers v2 documents the same way as v1, including the
// customizations section.
func TestParseCatalogDocumentV2Fingerprint(t *testing.T) {
	raw, err := json.Marshal(sampleV2Document())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	doc, sum, err := ParseCatalogDocument(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if doc.SchemaVersion != CatalogSchemaV2 || len(doc.Customizations) != 2 {
		t.Fatalf("parsed document = (v%d, %d customizations)", doc.SchemaVersion, len(doc.Customizations))
	}
	h := sha256.Sum256(raw)
	if sum != hex.EncodeToString(h[:]) {
		t.Fatal("fingerprint does not match the raw bytes")
	}

	// An old v1 binary's failure mode must be an error, never a silent
	// drop of the v2 vocabulary.
	v1 := sampleV2Document()
	v1.SchemaVersion = CatalogSchemaV1
	raw1, err := json.Marshal(v1)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, _, err := ParseCatalogDocument(strings.NewReader(string(raw1))); err == nil {
		t.Fatal("a v1 document carrying v2 data must be rejected, not silently repaired")
	}
}
