package provider

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// Fixed instants: all window boundaries in the tests are absolute dates far
// from "now" so the assertions are deterministic without clock injection.
var (
	t2020 = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	t2022 = time.Date(2022, 6, 1, 0, 0, 0, 0, time.UTC)
	t2024 = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	t2030 = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
)

func mustCatalog(t *testing.T, spec ModelCatalogSpec) *ModelCatalog {
	t.Helper()
	c, err := NewModelCatalog(spec)
	if err != nil {
		t.Fatalf("NewModelCatalog: unexpected error: %v", err)
	}
	return c
}

func sampleSpec() ModelCatalogSpec {
	return ModelCatalogSpec{
		Version:       "test-rev-1",
		SchemaVersion: 1,
		Source:        "unit-test",
		AsOf:          t2022,
		Entries: []ModelCatalogEntry{
			{
				Provider:     "openai",
				Model:        "gpt-test",
				Aliases:      []string{"gpt-short"},
				Capabilities: ModelCapabilities{Chat: true, Streaming: true, Tools: true},
				Limits:       ModelLimits{ContextWindowTokens: 128000, MaxOutputTokens: 4096},
				Price:        pricing.Price{InputPerM: 1.5, OutputPerM: 2},
				PriceListed:  true,
				EffectiveTo:  t2024,
			},
			{
				Provider:      "openai",
				Model:         "gpt-future",
				Capabilities:  ModelCapabilities{Chat: true},
				EffectiveFrom: t2030,
			},
			{
				Provider:     "anthropic",
				Model:        "claude-test",
				Capabilities: ModelCapabilities{Chat: true, PDFInput: true},
				PriceListed:  true, // all-zero price: a listed free model
			},
		},
		Withdrawals: []Withdrawal{
			{Provider: "vendor-gone", WithdrawnAt: t2024},
		},
	}
}

func TestModelCatalogStatusWindows(t *testing.T) {
	c := mustCatalog(t, sampleSpec())

	tests := []struct {
		name     string
		provider string
		model    string
		at       time.Time
		want     ModelStatus
	}{
		{"active inside window", "openai", "gpt-test", t2022, StatusActive},
		{"active on last instant of half-open window", "openai", "gpt-test", t2024.Add(-time.Nanosecond), StatusActive},
		{"retired at window close (half-open)", "openai", "gpt-test", t2024, StatusRetired},
		{"retired long after", "openai", "gpt-test", t2030, StatusRetired},
		{"pending before window opens", "openai", "gpt-future", t2022, StatusPending},
		{"active once window opens", "openai", "gpt-future", t2030, StatusActive},
		{"no bounds means active", "anthropic", "claude-test", t2020, StatusActive},
		{"no bounds means active far future", "anthropic", "claude-test", t2030, StatusActive},
		{"unknown pair", "openai", "no-such-model", t2022, StatusUnknown},
		{"unknown provider", "nosuch", "gpt-test", t2022, StatusUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := c.Status(tt.provider, tt.model, tt.at); got != tt.want {
				t.Fatalf("Status(%s, %s, %v) = %v, want %v", tt.provider, tt.model, tt.at, got, tt.want)
			}
		})
	}
}

func TestModelCatalogLookupPayload(t *testing.T) {
	c := mustCatalog(t, sampleSpec())

	t.Run("active entry exposes attributes", func(t *testing.T) {
		e, st := c.Lookup("openai", "gpt-test", t2022)
		if st != StatusActive {
			t.Fatalf("status = %v, want active", st)
		}
		if !e.Capabilities.Tools || !e.Capabilities.Streaming {
			t.Fatalf("capabilities = %+v, want chat+streaming+tools", e.Capabilities)
		}
		if e.Limits.ContextWindowTokens != 128000 || e.Limits.MaxOutputTokens != 4096 {
			t.Fatalf("limits = %+v", e.Limits)
		}
		if !e.PriceListed || e.Price.InputPerM != 1.5 || e.Price.OutputPerM != 2 {
			t.Fatalf("price = %+v listed=%v", e.Price, e.PriceListed)
		}
	})

	t.Run("retired entry keeps its data but reports retired", func(t *testing.T) {
		e, st := c.Lookup("openai", "gpt-test", t2030)
		if st != StatusRetired || e.Model != "gpt-test" {
			t.Fatalf("lookup = (%+v, %v), want entry + retired", e, st)
		}
	})

	t.Run("capabilities hidden unless active", func(t *testing.T) {
		if _, ok := c.Capabilities("openai", "gpt-test", t2030); ok {
			t.Fatal("retired model must not expose capabilities")
		}
		if _, ok := c.Capabilities("openai", "gpt-future", t2022); ok {
			t.Fatal("pending model must not expose capabilities")
		}
		if _, ok := c.Capabilities("openai", "missing", t2022); ok {
			t.Fatal("unknown model must not expose capabilities")
		}
	})
}

func TestModelCatalogAliases(t *testing.T) {
	c := mustCatalog(t, sampleSpec())

	t.Run("alias resolves while target is active", func(t *testing.T) {
		got, st := c.ResolveAlias("openai", "gpt-short", t2022)
		if got != "gpt-test" || st != StatusActive {
			t.Fatalf("ResolveAlias = (%q, %v), want (gpt-test, active)", got, st)
		}
		if e, st := c.Lookup("openai", "gpt-short", t2022); st != StatusActive || e.Model != "gpt-test" {
			t.Fatalf("Lookup via alias = (%+v, %v)", e, st)
		}
	})

	t.Run("alias of a retired target is retired, never green", func(t *testing.T) {
		if _, st := c.Lookup("openai", "gpt-short", t2030); st != StatusRetired {
			t.Fatalf("alias after retirement = %v, want retired", st)
		}
		got, st := c.ResolveAlias("openai", "gpt-short", t2030)
		if st != StatusRetired || got != "gpt-test" {
			t.Fatalf("ResolveAlias after retirement = (%q, %v), want (gpt-test, retired)", got, st)
		}
	})

	t.Run("unknown alias is unknown", func(t *testing.T) {
		if got, st := c.ResolveAlias("openai", "nope", t2022); got != "" || st != StatusUnknown {
			t.Fatalf("ResolveAlias(unknown) = (%q, %v), want empty/unknown", got, st)
		}
	})

	t.Run("alias colliding with a model name is rejected, so exact-vs-alias can never be ambiguous", func(t *testing.T) {
		spec := sampleSpec()
		spec.Entries = append(spec.Entries, ModelCatalogEntry{
			Provider: "openai", Model: "gpt-test-alias-target", Aliases: []string{"gpt-test"},
		})
		if _, err := NewModelCatalog(spec); err == nil {
			t.Fatal("alias colliding with an existing model name must be rejected")
		}
	})
}

// TestPickerVisibleDelistNegative is the negative scenario of the card: a
// model withdrawn from the catalog must not stay green because a static list
// still names it — retirement overrides the static/key verdict.
func TestPickerVisibleDelistNegative(t *testing.T) {
	c := mustCatalog(t, sampleSpec())

	tests := []struct {
		name       string
		provider   string
		model      string
		at         time.Time
		keyVisible bool
		want       bool
	}{
		{"retired stays hidden even when static list says visible", "openai", "gpt-test", t2030, true, false},
		{"retired hidden also when key denied", "openai", "gpt-test", t2030, false, false},
		{"active shown when key policy allows", "openai", "gpt-test", t2022, true, true},
		{"active still hidden when key policy denies", "openai", "gpt-test", t2022, false, false},
		{"pending not shown even when key allows", "openai", "gpt-future", t2022, true, false},
		{"unknown defers to key policy allow", "openai", "org-custom-model", t2022, true, true},
		{"unknown defers to key policy deny", "openai", "org-custom-model", t2022, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := c.PickerVisible(tt.provider, tt.model, tt.at, tt.keyVisible); got != tt.want {
				t.Fatalf("PickerVisible(%s, %s, keyVisible=%v) = %v, want %v",
					tt.provider, tt.model, tt.keyVisible, got, tt.want)
			}
		})
	}
}

func TestFilterVisible(t *testing.T) {
	c := mustCatalog(t, sampleSpec())
	rows := []PickerRow{
		{Provider: "openai", Model: "gpt-test", KeyVisible: true},
		{Provider: "openai", Model: "gpt-future", KeyVisible: true},
		{Provider: "anthropic", Model: "claude-test", KeyVisible: false},
		{Provider: "openai", Model: "custom-org", KeyVisible: true},
	}
	got := c.FilterVisible(rows, t2022)
	if len(got) != 2 || got[0].Model != "gpt-test" || got[1].Model != "custom-org" {
		t.Fatalf("FilterVisible = %+v, want [gpt-test custom-org] in input order", got)
	}

	// No catalog installed: the rows pass through unchanged.
	var nilCatalog *ModelCatalog
	if out := nilCatalog.FilterVisible(rows, t2022); len(out) != len(rows) {
		t.Fatalf("nil catalog FilterVisible dropped rows: %d -> %d", len(rows), len(out))
	}
}

func TestPricingKey(t *testing.T) {
	c := mustCatalog(t, sampleSpec())

	if p, m, ok := c.PricingKey("openai", "gpt-short", t2022); !ok || p != "openai" || m != "gpt-test" {
		t.Fatalf("PricingKey via alias = (%q, %q, %v)", p, m, ok)
	}
	if _, _, ok := c.PricingKey("openai", "gpt-test", t2030); ok {
		t.Fatal("retired model must not yield a pricing key")
	}
	if _, _, ok := c.PricingKey("openai", "missing", t2022); ok {
		t.Fatal("unknown model must not yield a pricing key")
	}
}

func TestProviderWithdrawal(t *testing.T) {
	c := mustCatalog(t, sampleSpec())

	tests := []struct {
		name     string
		provider string
		at       time.Time
		want     bool
	}{
		{"admitted before withdrawal", "vendor-gone", t2022, true},
		{"not admitted at withdrawal instant", "vendor-gone", t2024, false},
		{"not admitted after withdrawal", "vendor-gone", t2030, false},
		{"unknown provider stays admitted", "openai", t2030, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := c.ProviderAdmitted(tt.provider, tt.at); got != tt.want {
				t.Fatalf("ProviderAdmitted(%s, %v) = %v, want %v", tt.provider, tt.at, got, tt.want)
			}
		})
	}
}

func TestFactoryRejectsWithdrawnProvider(t *testing.T) {
	SetModelCatalogForTest(t, mustCatalog(t, sampleSpec()))

	if _, err := New("vendor-gone"); err == nil {
		t.Fatal("New must reject a provider the catalog withdrew")
	} else if !strings.Contains(err.Error(), "vendor-gone") {
		t.Fatalf("error must name the withdrawn provider, got: %v", err)
	}
	if _, err := New("openai"); err != nil {
		t.Fatalf("New for an unwithdrawn provider must succeed, got: %v", err)
	}
	if _, err := New(""); err != nil {
		t.Fatalf("default adapter must stay available, got: %v", err)
	}
}

func TestFactoryWithoutCatalogUnchanged(t *testing.T) {
	SetModelCatalog(nil)
	defer SetModelCatalog(nil)

	if got := ProviderAdmitted("anything"); !got {
		t.Fatal("with no catalog installed every provider must stay admitted")
	}
	for _, name := range []string{"", "openai", "anthropic", "vertex", "nonsense-name"} {
		_, err := New(name)
		if name == "nonsense-name" {
			if err == nil {
				t.Fatalf("New(%q) must still fail for unknown names", name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("New(%q) without catalog = %v, want success", name, err)
		}
	}
}

// TestSetModelCatalogConcurrent exercises the atomic snapshot swap: writers
// replace the catalog while readers consult admission and status. Run under
// -race; the final assertion pins the last writer's outcome.
func TestSetModelCatalogConcurrent(t *testing.T) {
	defer SetModelCatalog(nil)

	cA := mustCatalog(t, sampleSpec())
	specB := sampleSpec()
	specB.Version = "test-rev-2"
	specB.Entries = specB.Entries[:1]
	cB := mustCatalog(t, specB)

	const writers = 4
	const readsPerWriter = 200
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(2)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < readsPerWriter; i++ {
				c := CurrentModelCatalog()
				_ = c.ProviderAdmitted("vendor-gone", t2022)
				_, st := c.Lookup("openai", "gpt-test", t2022)
				if st != StatusActive && st != StatusUnknown {
					t.Errorf("impossible status %v from an installed catalog", st)
					return
				}
				_ = ProviderAdmitted("vendor-gone")
			}
		}(w)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < readsPerWriter; i++ {
				if w%2 == 0 {
					SetModelCatalog(cA)
				} else {
					SetModelCatalog(cB)
				}
			}
		}(w)
	}
	wg.Wait()

	SetModelCatalog(cB)
	if c := CurrentModelCatalog(); c == nil || c.Version() != "test-rev-2" {
		t.Fatalf("final snapshot = %v, want test-rev-2", c)
	}
}

func TestNewModelCatalogValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(s *ModelCatalogSpec)
		errPart string
	}{
		{"missing version", func(s *ModelCatalogSpec) { s.Version = " " }, "version is required"},
		{"zero schema", func(s *ModelCatalogSpec) { s.SchemaVersion = 0 }, "schema version"},
		{"negative schema", func(s *ModelCatalogSpec) { s.SchemaVersion = -3 }, "schema version"},
		{"missing source", func(s *ModelCatalogSpec) { s.Source = "" }, "source is required"},
		{"empty provider", func(s *ModelCatalogSpec) { s.Entries[0].Provider = " " }, "provider and model are required"},
		{"empty model", func(s *ModelCatalogSpec) { s.Entries[0].Model = "" }, "provider and model are required"},
		{"duplicate model", func(s *ModelCatalogSpec) {
			s.Entries = append(s.Entries, s.Entries[0])
		}, "duplicate entry"},
		{"duplicate alias", func(s *ModelCatalogSpec) {
			s.Entries = append(s.Entries, ModelCatalogEntry{Provider: "openai", Model: "other", Aliases: []string{"gpt-short"}})
		}, "duplicate alias"},
		{"alias shadows a model name declared later", func(s *ModelCatalogSpec) {
			s.Entries[0].Aliases = append(s.Entries[0].Aliases, "gpt-future")
		}, "collides with an existing model name"},
		{"alias equals its own model", func(s *ModelCatalogSpec) {
			s.Entries[0].Aliases = []string{"gpt-test"}
		}, "shadows the model name"},
		{"empty alias", func(s *ModelCatalogSpec) {
			s.Entries[0].Aliases = []string{"  "}
		}, "empty alias"},
		{"inverted window", func(s *ModelCatalogSpec) {
			s.Entries[0].EffectiveFrom = t2024
			s.Entries[0].EffectiveTo = t2022
		}, "closes before it opens"},
		{"negative limit", func(s *ModelCatalogSpec) {
			s.Entries[0].Limits.ContextWindowTokens = -1
		}, "must not be negative"},
		{"negative price", func(s *ModelCatalogSpec) {
			s.Entries[0].Price.OutputPerM = -0.5
		}, "price"},
		{"withdrawal without provider", func(s *ModelCatalogSpec) {
			s.Withdrawals = append(s.Withdrawals, Withdrawal{WithdrawnAt: t2024})
		}, "provider is required"},
		{"withdrawal without date", func(s *ModelCatalogSpec) {
			s.Withdrawals = append(s.Withdrawals, Withdrawal{Provider: "x"})
		}, "withdrawal date is required"},
		{"duplicate withdrawal for one provider", func(s *ModelCatalogSpec) {
			s.Withdrawals = append(s.Withdrawals,
				Withdrawal{Provider: "vendor-gone", WithdrawnAt: t2030},
				Withdrawal{Provider: " vendor-gone ", WithdrawnAt: t2020},
			)
		}, "duplicate withdrawal for provider vendor-gone"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fresh spec per case: cases mutate nested slices, and sharing
			// the backing array across cases would leak mutations forward.
			spec := sampleSpec()
			tt.mutate(&spec)
			_, err := NewModelCatalog(spec)
			if err == nil {
				t.Fatalf("expected validation error containing %q", tt.errPart)
			}
			if !strings.Contains(err.Error(), tt.errPart) {
				t.Fatalf("error %q does not mention %q", err, tt.errPart)
			}
		})
	}
}

func TestNewModelCatalogAcceptsFreeListedPrice(t *testing.T) {
	spec := sampleSpec()
	if _, err := NewModelCatalog(spec); err != nil {
		t.Fatalf("zero listed price (free model) must be accepted: %v", err)
	}
}

// TestModelCatalogImmutability pins that callers cannot mutate the snapshot
// through the slices they handed in or through the accessors.
func TestModelCatalogImmutability(t *testing.T) {
	spec := sampleSpec()
	aliasesBefore := append([]string(nil), spec.Entries[0].Aliases...)
	c := mustCatalog(t, spec)

	spec.Entries[0].Capabilities = ModelCapabilities{}
	spec.Entries[0].Limits = ModelLimits{}
	spec.Entries[0].Aliases[0] = "tampered"

	if caps, ok := c.Capabilities("openai", "gpt-test", t2022); !ok || !caps.Tools {
		t.Fatalf("catalog capabilities mutated through caller slice: %+v", caps)
	}
	if e, _ := c.Entry("openai", "gpt-test"); e.Aliases[0] != aliasesBefore[0] {
		t.Fatalf("entry aliases mutated: %q", e.Aliases[0])
	}

	entries := c.Entries()
	entries[0].Model = "tampered"
	entries[0].Aliases = nil
	if e, _ := c.Entry("openai", "gpt-test"); e.Model != "gpt-test" || len(e.Aliases) != 1 {
		t.Fatalf("snapshot leaked mutable state: %+v", e)
	}
}

func TestModelStatusStrings(t *testing.T) {
	tests := []struct {
		st   ModelStatus
		want string
	}{
		{StatusUnknown, "unknown"},
		{StatusPending, "pending"},
		{StatusActive, "active"},
		{StatusRetired, "retired"},
	}
	for _, tt := range tests {
		if got := tt.st.String(); got != tt.want {
			t.Fatalf("ModelStatus(%d).String() = %q, want %q", tt.st, got, tt.want)
		}
	}
}

// TestModelCatalogNilReceiver pins the documented nil-receiver contract: a
// nil *ModelCatalog behaves like "no catalog installed" — every lookup
// answers "no opinion" and metadata accessors answer the zero value instead
// of panicking.
func TestModelCatalogNilReceiver(t *testing.T) {
	var c *ModelCatalog

	t.Run("lookups answer no opinion", func(t *testing.T) {
		if st := c.Status("openai", "gpt-test", t2022); st != StatusUnknown {
			t.Fatalf("Status on nil catalog = %v, want unknown", st)
		}
		if e, st := c.Lookup("openai", "gpt-test", t2022); st != StatusUnknown || e.Model != "" {
			t.Fatalf("Lookup on nil catalog = (%+v, %v)", e, st)
		}
		if got, st := c.ResolveAlias("openai", "gpt-short", t2022); got != "" || st != StatusUnknown {
			t.Fatalf("ResolveAlias on nil catalog = (%q, %v)", got, st)
		}
		if _, ok := c.Capabilities("openai", "gpt-test", t2022); ok {
			t.Fatal("Capabilities on nil catalog must report no capabilities")
		}
		if _, _, ok := c.PricingKey("openai", "gpt-test", t2022); ok {
			t.Fatal("PricingKey on nil catalog must yield no key")
		}
		if !c.PickerVisible("openai", "gpt-test", t2022, true) {
			t.Fatal("PickerVisible on nil catalog must defer to the key verdict (true)")
		}
		if c.PickerVisible("openai", "gpt-test", t2022, false) {
			t.Fatal("PickerVisible on nil catalog must defer to the key verdict (false)")
		}
		if !c.ProviderAdmitted("openai", t2022) {
			t.Fatal("ProviderAdmitted on nil catalog must admit")
		}
		if e, ok := c.Entry("openai", "gpt-test"); ok || e.Model != "" {
			t.Fatalf("Entry on nil catalog = (%+v, %v)", e, ok)
		}
	})

	t.Run("metadata accessors answer the zero value", func(t *testing.T) {
		if got := c.Version(); got != "" {
			t.Fatalf("Version on nil catalog = %q, want empty", got)
		}
		if got := c.SchemaVersion(); got != 0 {
			t.Fatalf("SchemaVersion on nil catalog = %d, want 0", got)
		}
		if got := c.Source(); got != "" {
			t.Fatalf("Source on nil catalog = %q, want empty", got)
		}
		if got := c.AsOf(); !got.IsZero() {
			t.Fatalf("AsOf on nil catalog = %v, want zero", got)
		}
		if got := c.EntryCount(); got != 0 {
			t.Fatalf("EntryCount on nil catalog = %d, want 0", got)
		}
		if got := c.Entries(); got != nil {
			t.Fatalf("Entries on nil catalog = %+v, want nil", got)
		}
	})
}

// TestModelLifecycle pins the four-state lifecycle classifier. The negative
// rows are the packet's core scenario: a model the catalog delisted reports
// unavailable even when the installation still configures and tests it —
// withdrawal dominates every installation fact.
func TestModelLifecycle(t *testing.T) {
	c := mustCatalog(t, sampleSpec())

	tests := []struct {
		name       string
		provider   string
		model      string
		at         time.Time
		configured bool
		tested     bool
		want       ModelLifecycle
	}{
		{"active and tested", "openai", "gpt-test", t2022, true, true, LifecycleTested},
		{"active and configured but never tested", "openai", "gpt-test", t2022, true, false, LifecycleConfigured},
		{"active in the catalog only", "anthropic", "claude-test", t2022, false, false, LifecycleDiscovered},
		{"tested without configured is still tested", "openai", "gpt-test", t2022, false, true, LifecycleTested},
		{"retired stays unavailable even configured and tested", "openai", "gpt-test", t2030, true, true, LifecycleUnavailable},
		{"retired without facts", "openai", "gpt-test", t2024, false, false, LifecycleUnavailable},
		{"pending is not sellable yet", "openai", "gpt-future", t2022, true, true, LifecycleUnavailable},
		{"pending becomes testable once the window opens", "openai", "gpt-future", t2030, true, true, LifecycleTested},
		{"provider withdrawal dominates unknown status", "vendor-gone", "any-model", t2024, true, true, LifecycleUnavailable},
		{"provider still admitted before its withdrawal", "vendor-gone", "any-model", t2022, true, true, LifecycleTested},
		{"unknown name keeps installation facts: tested", "openai", "org-custom", t2022, true, true, LifecycleTested},
		{"unknown name keeps installation facts: configured", "openai", "org-custom", t2022, true, false, LifecycleConfigured},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c.Lifecycle(tt.provider, tt.model, tt.at, tt.configured, tt.tested)
			if got != tt.want {
				t.Fatalf("Lifecycle(%s, %s, %v, configured=%v, tested=%v) = %v, want %v",
					tt.provider, tt.model, tt.at, tt.configured, tt.tested, got, tt.want)
			}
		})
	}

	t.Run("without a catalog the facts decide", func(t *testing.T) {
		var nilCatalog *ModelCatalog
		if got := nilCatalog.Lifecycle("openai", "gpt-test", t2022, true, true); got != LifecycleTested {
			t.Fatalf("nil catalog Lifecycle = %v, want tested", got)
		}
		if got := nilCatalog.Lifecycle("openai", "gpt-test", t2022, true, false); got != LifecycleConfigured {
			t.Fatalf("nil catalog Lifecycle = %v, want configured", got)
		}
		if got := nilCatalog.Lifecycle("openai", "gpt-test", t2022, false, false); got != LifecycleDiscovered {
			t.Fatalf("nil catalog Lifecycle = %v, want discovered", got)
		}
	})
}

func TestModelLifecycleStrings(t *testing.T) {
	tests := []struct {
		l    ModelLifecycle
		want string
	}{
		{LifecycleDiscovered, "discovered"},
		{LifecycleConfigured, "configured"},
		{LifecycleTested, "tested"},
		{LifecycleUnavailable, "unavailable"},
		{ModelLifecycle(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.l.String(); got != tt.want {
			t.Fatalf("ModelLifecycle(%d).String() = %q, want %q", tt.l, got, tt.want)
		}
	}
}

// SetModelCatalogForTest installs c for the duration of the test and restores
// the previous snapshot afterwards, so tests never leak global state.
func SetModelCatalogForTest(t *testing.T, c *ModelCatalog) {
	t.Helper()
	prev := CurrentModelCatalog()
	SetModelCatalog(c)
	t.Cleanup(func() { SetModelCatalog(prev) })
}

// deprecationSpec is a catalog where openai:gpt-test is deprecated on
// 2023-01-01 and retires on 2024-01-01: a sellable-but-flagged phase in
// between.
func deprecationSpec() ModelCatalogSpec {
	spec := sampleSpec()
	spec.Entries = spec.Entries[:1]
	spec.Withdrawals = nil
	spec.Entries[0].DeprecatedAt = time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	return spec
}

// TestModelCatalogDeprecation pins the deprecation phase: deprecated is not
// retired. The model stays sellable (StatusActive) through the announced
// end-of-life phase, the flag turns on exactly at the instant, and
// retirement — window close or provider withdrawal — dominates the flag.
func TestModelCatalogDeprecation(t *testing.T) {
	c := mustCatalog(t, deprecationSpec())

	t2023 := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	t2023mid := time.Date(2023, 6, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"before the deprecation instant", t2022, false},
		{"exactly at the deprecation instant", t2023, true},
		{"inside the flagged phase", t2023mid, true},
		{"retired dominates: window closed", t2024, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := c.Deprecated("openai", "gpt-test", tt.at); got != tt.want {
				t.Fatalf("Deprecated at %v = %v, want %v", tt.at, got, tt.want)
			}
		})
	}

	t.Run("deprecated model is still sellable", func(t *testing.T) {
		if st := c.Status("openai", "gpt-test", t2023mid); st != StatusActive {
			t.Fatalf("status in the flagged phase = %v, want active", st)
		}
		// The picker keeps it visible per the key policy — hiding a
		// working model would break clients; the flag is the signal.
		if !c.PickerVisible("openai", "gpt-test", t2023mid, true) {
			t.Fatal("deprecated model must stay picker-visible while sellable")
		}
	})

	t.Run("provider withdrawal dominates the flag", func(t *testing.T) {
		spec := deprecationSpec()
		spec.Withdrawals = []Withdrawal{{Provider: "openai", WithdrawnAt: t2022}}
		w := mustCatalog(t, spec)
		if w.Deprecated("openai", "gpt-test", t2023mid) {
			t.Fatal("a withdrawn provider's model is not merely deprecated")
		}
	})

	t.Run("unknown name and missing flag", func(t *testing.T) {
		if c.Deprecated("openai", "no-such-model", t2023mid) {
			t.Fatal("unknown pair is not deprecated")
		}
		bare := mustCatalog(t, sampleSpec())
		if bare.Deprecated("anthropic", "claude-test", t2022) {
			t.Fatal("entry without a deprecation instant is not deprecated")
		}
	})

	t.Run("nil receiver", func(t *testing.T) {
		var nilCatalog *ModelCatalog
		if nilCatalog.Deprecated("openai", "gpt-test", t2023mid) {
			t.Fatal("nil catalog has no deprecation opinion")
		}
	})

	t.Run("alias reports the target flag", func(t *testing.T) {
		if !c.Deprecated("openai", "gpt-short", t2023mid) {
			t.Fatal("alias must resolve to the deprecated target")
		}
	})

	t.Run("lifecycle keeps fact states during the flagged phase", func(t *testing.T) {
		// Deprecation is a flag, not a lifecycle state: a configured and
		// tested deprecated model still reports tested (it works), with
		// the deprecation carried as data beside the label.
		if got := c.Lifecycle("openai", "gpt-test", t2023mid, true, true); got != LifecycleTested {
			t.Fatalf("deprecated-but-working model = %v, want tested", got)
		}
	})
}

// TestFilterVisibleDeprecatedFlag pins that the picker payload carries the
// deprecation flag on surviving rows and never on filtered-out ones.
func TestFilterVisibleDeprecatedFlag(t *testing.T) {
	c := mustCatalog(t, deprecationSpec())
	t2023mid := time.Date(2023, 6, 15, 0, 0, 0, 0, time.UTC)

	rows := []PickerRow{
		{Provider: "openai", Model: "gpt-test", KeyVisible: true},      // deprecated at t2023mid
		{Provider: "openai", Model: "gpt-test", KeyVisible: false},     // key denies
		{Provider: "openai", Model: "no-such-model", KeyVisible: true}, // unknown pair
	}
	got := c.FilterVisible(rows, t2023mid)
	if len(got) != 2 {
		t.Fatalf("surviving rows = %d, want 2: %+v", len(got), got)
	}
	if !got[0].Deprecated {
		t.Fatal("deprecated sellable row must carry the flag")
	}
	if got[1].Deprecated {
		t.Fatal("flag must not leak onto a different row")
	}

	// After retirement the row disappears entirely — it never survives
	// with or without the flag.
	if got := c.FilterVisible(rows[:1], t2030); len(got) != 0 {
		t.Fatalf("retired model survived the filter: %+v", got)
	}
}

func TestNewModelCatalogDeprecationValidation(t *testing.T) {
	t2023 := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		mutate  func(e *ModelCatalogEntry)
		errPart string
	}{
		{"deprecation before the window opens", func(e *ModelCatalogEntry) {
			e.EffectiveFrom = t2023
			e.EffectiveTo = t2024
			e.DeprecatedAt = t2022
		}, "precedes the sell window opening"},
		{"deprecation at the window close", func(e *ModelCatalogEntry) {
			e.EffectiveFrom = t2022
			e.EffectiveTo = t2024
			e.DeprecatedAt = t2024
		}, "is not before the sell window closing"},
		{"deprecation after the window close", func(e *ModelCatalogEntry) {
			e.EffectiveFrom = t2022
			e.EffectiveTo = t2024
			e.DeprecatedAt = t2030
		}, "is not before the sell window closing"},
		{"deprecation before an open-ended window opening", func(e *ModelCatalogEntry) {
			e.EffectiveFrom = t2024
			e.EffectiveTo = time.Time{}
			e.DeprecatedAt = t2023
		}, "precedes the sell window opening"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := deprecationSpec()
			tt.mutate(&spec.Entries[0])
			_, err := NewModelCatalog(spec)
			if err == nil {
				t.Fatalf("expected validation error containing %q", tt.errPart)
			}
			if !strings.Contains(err.Error(), tt.errPart) {
				t.Fatalf("error %q does not mention %q", err, tt.errPart)
			}
		})
	}

	t.Run("valid phases are accepted", func(t *testing.T) {
		for _, dep := range []time.Time{t2022, t2023} {
			spec := deprecationSpec()
			spec.Entries[0].DeprecatedAt = dep
			if _, err := NewModelCatalog(spec); err != nil {
				t.Fatalf("deprecation at %v must be accepted: %v", dep, err)
			}
		}
		// Open-ended and not-yet-open windows accept an instant on their
		// known side.
		spec := deprecationSpec()
		spec.Entries[0].EffectiveTo = time.Time{}
		if _, err := NewModelCatalog(spec); err != nil {
			t.Fatalf("deprecation in an open-ended window must be accepted: %v", err)
		}
	})
}

// TestApplyOverrides pins the custom-catalog merge: explicit attributes
// replace, windows narrow, and a model the vendor retired stays retired no
// matter what the override claims — the anti-resurrection rule.
func TestApplyOverrides(t *testing.T) {
	base := mustCatalog(t, sampleSpec())
	t2023 := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	t2023half := time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC)

	caps := ModelCapabilities{Chat: true, VisionInput: true}
	limits := ModelLimits{ContextWindowTokens: 32000}
	merged, err := ApplyOverrides(base, []ModelOverride{
		{
			Provider: "openai", Model: "gpt-test",
			Capabilities: &caps, Limits: &limits,
			Aliases: []string{"gpt-alias-new"}, // replaces gpt-short
			// retire early: pull the window in from 2024 to mid-2023
			EffectiveTo:  t2023half,
			DeprecatedAt: t2023,
		},
	})
	if err != nil {
		t.Fatalf("ApplyOverrides: %v", err)
	}

	t.Run("explicit attributes replace the vendor set", func(t *testing.T) {
		e, st := merged.Lookup("openai", "gpt-test", t2022)
		if st != StatusActive {
			t.Fatalf("status = %v", st)
		}
		if e.Capabilities != caps || e.Limits != limits {
			t.Fatalf("merged attributes = %+v / %+v", e.Capabilities, e.Limits)
		}
		if !e.PriceListed || e.Price.InputPerM != 1.5 {
			t.Fatalf("pricing must ride unchanged from the vendor row: %+v listed=%v", e.Price, e.PriceListed)
		}
	})

	t.Run("aliases are replaced and validated as a whole", func(t *testing.T) {
		if _, st := merged.Lookup("openai", "gpt-short", t2022); st != StatusUnknown {
			t.Fatalf("replaced alias still resolves: %v", st)
		}
		if _, st := merged.Lookup("openai", "gpt-alias-new", t2022); st != StatusActive {
			t.Fatalf("new alias does not resolve: %v", st)
		}
	})

	t.Run("window narrowed and deprecation merged", func(t *testing.T) {
		if st := merged.Status("openai", "gpt-test", t2023half); st != StatusRetired {
			t.Fatalf("early-retired model = %v, want retired", st)
		}
		if st := merged.Status("openai", "gpt-test", t2023); st != StatusActive {
			t.Fatalf("model before the pulled-in close = %v, want active", st)
		}
		if !merged.Deprecated("openai", "gpt-test", t2023) {
			t.Fatal("override deprecation must flag from its instant")
		}
	})

	t.Run("custom model introduced", func(t *testing.T) {
		c2, err := ApplyOverrides(base, []ModelOverride{{
			Provider: "selfhosted", Model: "llama-local",
			Capabilities: &caps,
			Aliases:      []string{"llama"},
		}})
		if err != nil {
			t.Fatalf("custom model: %v", err)
		}
		e, st := c2.Lookup("selfhosted", "llama-local", t2022)
		if st != StatusActive || !e.Custom {
			t.Fatalf("custom row = (status %v, custom %v), want (active, true)", st, e.Custom)
		}
		if _, st := c2.Lookup("selfhosted", "llama", t2022); st != StatusActive {
			t.Fatalf("custom alias = %v, want active", st)
		}
		// A custom model under a withdrawn provider is still not admitted.
		c3, err := ApplyOverrides(base, []ModelOverride{{
			Provider: "vendor-gone", Model: "zombie",
		}})
		if err != nil {
			t.Fatalf("override under withdrawn provider: %v", err)
		}
		if c3.ProviderAdmitted("vendor-gone", t2030) {
			t.Fatal("a custom model must not resurrect a withdrawn provider")
		}
		if got := c3.Lifecycle("vendor-gone", "zombie", t2030, true, true); got != LifecycleUnavailable {
			t.Fatalf("custom model under withdrawn provider = %v, want unavailable", got)
		}
	})

	t.Run("base snapshot untouched", func(t *testing.T) {
		if _, st := base.Lookup("openai", "gpt-short", t2022); st != StatusActive {
			t.Fatal("base alias lost after merge")
		}
		if st := base.Status("openai", "gpt-test", t2030); st != StatusRetired {
			t.Fatalf("base window moved: %v", st)
		}
		if base.Deprecated("openai", "gpt-test", t2023) {
			t.Fatal("base deprecation moved by the merge")
		}
		if base.EntryCount() != 3 {
			t.Fatalf("base grew to %d entries", base.EntryCount())
		}
	})

	t.Run("metadata inherited", func(t *testing.T) {
		if merged.Version() != base.Version() || merged.Source() != base.Source() ||
			merged.SchemaVersion() != base.SchemaVersion() || !merged.AsOf().Equal(base.AsOf()) {
			t.Fatal("merged snapshot must inherit the base metadata")
		}
	})
}

// TestApplyOverridesAntiResurrection is the card's negative scenario at the
// merge layer: an override can narrow a vendor window but never widen it.
// A model the vendor delisted stays retired even when a stale or hostile
// custom override still claims a later end of life.
func TestApplyOverridesAntiResurrection(t *testing.T) {
	base := mustCatalog(t, sampleSpec()) // gpt-test retires at t2024

	overrides := []ModelOverride{
		{Provider: "openai", Model: "gpt-test", EffectiveTo: t2030},   // claims a longer life
		{Provider: "openai", Model: "gpt-test", EffectiveFrom: t2020}, // earlier open
		{Provider: "openai", Model: "gpt-test"},                       // attribute-only override of a dead row
	}
	for i, ov := range overrides {
		merged, err := ApplyOverrides(base, []ModelOverride{ov})
		if err != nil {
			t.Fatalf("override %d: %v", i, err)
		}
		if st := merged.Status("openai", "gpt-test", t2030); st != StatusRetired {
			t.Fatalf("override %d resurrected a retired model: %v at %v", i, st, t2030)
		}
		if st := merged.Status("openai", "gpt-test", t2022); st != StatusActive {
			t.Fatalf("override %d changed the healthy-period status: %v", i, st)
		}
	}

	t.Run("pending window cannot open early", func(t *testing.T) {
		merged, err := ApplyOverrides(base, []ModelOverride{
			{Provider: "openai", Model: "gpt-future", EffectiveFrom: t2022},
		})
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		if st := merged.Status("openai", "gpt-future", t2022); st != StatusPending {
			t.Fatalf("override opened a pending window early: %v", st)
		}
		if st := merged.Status("openai", "gpt-future", t2030); st != StatusActive {
			t.Fatalf("vendor window must still open on time: %v", st)
		}
	})

	t.Run("override cannot un-deprecate a model", func(t *testing.T) {
		spec := deprecationSpec() // deprecated from 2023-01-01
		vendor := mustCatalog(t, spec)
		later := time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC)
		merged, err := ApplyOverrides(vendor, []ModelOverride{
			{Provider: "openai", Model: "gpt-test", DeprecatedAt: later}, // claims a later flag
		})
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		if !merged.Deprecated("openai", "gpt-test", spec.Entries[0].DeprecatedAt) {
			t.Fatal("the earlier vendor deprecation must survive the override")
		}
	})
}

func TestApplyOverridesValidation(t *testing.T) {
	base := mustCatalog(t, sampleSpec())
	t2023 := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		base    *ModelCatalog
		ovs     []ModelOverride
		errPart string
	}{
		{"nil base", nil, []ModelOverride{{Provider: "openai", Model: "m"}}, "requires a base catalog"},
		{"missing provider", base, []ModelOverride{{Model: "m"}}, "provider and model are required"},
		{"missing model", base, []ModelOverride{{Provider: "openai"}}, "provider and model are required"},
		{"blank names", base, []ModelOverride{{Provider: " ", Model: " "}}, "provider and model are required"},
		{"duplicate override", base, []ModelOverride{
			{Provider: "openai", Model: "gpt-test"},
			{Provider: "openai", Model: " gpt-test "},
		}, "duplicate override for openai:gpt-test"},
		{"inverted override window", base, []ModelOverride{
			{Provider: "openai", Model: "gpt-test", EffectiveFrom: t2024, EffectiveTo: t2022},
		}, "override window closes before it opens"},
		{"alias shadows its own model", base, []ModelOverride{
			{Provider: "openai", Model: "gpt-test", Aliases: []string{"gpt-test"}},
		}, "shadows the model name"},
		{"alias collides with another vendor model", base, []ModelOverride{
			{Provider: "openai", Model: "gpt-test", Aliases: []string{"gpt-future"}},
		}, "collides with an existing model name"},
		{"alias collides with a vendor alias", base, []ModelOverride{
			{Provider: "openai", Model: "gpt-future", Aliases: []string{"gpt-short"}},
		}, "duplicate alias"},
		{"negative limit", base, []ModelOverride{
			{Provider: "openai", Model: "gpt-test", Limits: &ModelLimits{ContextWindowTokens: -1}},
		}, "must not be negative"},
		{"custom row with inverted window", base, []ModelOverride{
			{Provider: "selfhosted", Model: "m", EffectiveFrom: t2024, EffectiveTo: t2022},
		}, "override window closes before it opens"},
		{"custom row with deprecation outside its window", base, []ModelOverride{
			{Provider: "selfhosted", Model: "m", EffectiveFrom: t2022, EffectiveTo: t2023, DeprecatedAt: t2030},
		}, "deprecation instant"},
		{"merged row deprecation outside the narrowed window", base, []ModelOverride{
			// The vendor row closes at 2024; the override pulls the close
			// to 2023 but claims a deprecation in 2030 — dead data.
			{Provider: "openai", Model: "gpt-test", EffectiveTo: t2023, DeprecatedAt: t2030},
		}, "merged row violates the deprecation window"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ApplyOverrides(tt.base, tt.ovs)
			if err == nil {
				t.Fatalf("expected error containing %q", tt.errPart)
			}
			if !strings.Contains(err.Error(), tt.errPart) {
				t.Fatalf("error %q does not mention %q", err, tt.errPart)
			}
		})
	}
}

// TestMergedCatalogSwapConcurrent pins that deprecation queries and merged
// snapshots are race-free under atomic installation: readers consult the
// process-wide catalog while a writer alternates the vendor snapshot and an
// override-merged one. Run under -race.
func TestMergedCatalogSwapConcurrent(t *testing.T) {
	defer SetModelCatalog(nil)

	base := mustCatalog(t, deprecationSpec())
	caps := ModelCapabilities{Chat: true}
	merged, err := ApplyOverrides(base, []ModelOverride{{
		Provider: "openai", Model: "gpt-test",
		Capabilities: &caps,
	}})
	if err != nil {
		t.Fatalf("ApplyOverrides: %v", err)
	}

	const writers = 4
	const rounds = 150
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				c := CurrentModelCatalog()
				_ = c.Deprecated("openai", "gpt-test", t2022)
				_, st := c.Lookup("openai", "gpt-test", t2022)
				if st != StatusActive && st != StatusUnknown {
					t.Errorf("impossible status %v", st)
					return
				}
			}
		}()
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if w%2 == 0 {
					SetModelCatalog(base)
				} else {
					SetModelCatalog(merged)
				}
			}
		}(w)
	}
	wg.Wait()
	SetModelCatalog(merged)
	if c := CurrentModelCatalog(); c != merged {
		t.Fatal("final snapshot is not the merged catalog")
	}
}
