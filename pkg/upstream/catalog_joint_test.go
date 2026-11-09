package upstream

// The joint user scenario of the model-catalog drift packet: end-to-end
// walks that compose the delivered layers the way an installation
// experiences them — vendor documents are parsed, validated and materialized
// into runtime snapshots, operator overrides are merged on top, and every
// consumer view (static-name reconcile, lifecycle report, per-key picker
// filter, pricing key routing) must agree on the same drift/retirement
// facts.
//
// Real and mock checks are kept explicitly distinct, per the card's stage
// acceptance:
//   - real: the production code paths (byte-level document parse, SHA256
//     provenance, strict snapshot validation, merged-space re-validation,
//     the production price-file parser and immutable price store);
//   - mock: synthetic vendor documents with fixed absolute instants standing
//     in for wall-clock time (deterministic, no network, no sleeps).
//
// Test-only: this file changes no production behavior. It composes the
// pkg/upstream document layer, the pkg/provider runtime layer and the
// pricing store adjacency that T04 delivered; pkg/shadow and pkg/lineage
// have no catalog surface (verified: zero references) and stay regression
// neighbors only, as in the T04 evidence.

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
)

// Fixed absolute instants for the joint timeline (deterministic; no
// time.Now anywhere in the walks).
var (
	jOpened    = time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC)  // healthy selling phase
	jAnnounced = time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)  // inside the announced EOL phase
	jLastCall  = time.Date(2024, 8, 15, 0, 0, 0, 0, time.UTC) // still active under the narrowed window
	jNarrowAt  = time.Date(2024, 9, 1, 0, 0, 0, 0, time.UTC)  // narrowed window close (half-open)
	jZombie    = time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC) // after the close: zombie-check instant
	jWithdrawn = time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)  // after the provider withdrawal instant
	jDepAt     = time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)  // announced end-of-life instant
)

// jointDocBytes marshals a catalog document into the raw JSON bytes an
// installation would receive.
func jointDocBytes(t *testing.T, doc CatalogDocument) []byte {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal catalog document: %v", err)
	}
	return raw
}

// jointBuild walks the real byte-level path: parse, validate, build
// (including the customizations merge). Returns the snapshot and its
// SHA256 provenance fingerprint.
func jointBuild(t *testing.T, raw []byte) (*provider.ModelCatalog, string) {
	t.Helper()
	doc, sum, err := ParseCatalogDocument(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse catalog document: %v", err)
	}
	cat, err := BuildModelCatalog(doc)
	if err != nil {
		t.Fatalf("build model catalog: %v", err)
	}
	return cat, sum
}

// jointInstall swaps the process-wide snapshot and restores the previous
// installation when the test finishes, so -shuffle order can never leak
// catalog state between tests.
func jointInstall(t *testing.T, c *provider.ModelCatalog) {
	t.Helper()
	prev := provider.CurrentModelCatalog()
	provider.SetModelCatalog(c)
	t.Cleanup(func() { provider.SetModelCatalog(prev) })
}

// jointVendorDoc is the mock vendor snapshot for the first walk: one model
// selling 2023-01-01…2025-06-01, optionally carrying the announced
// end-of-life instant (schema v2 data).
func jointVendorDoc(version string, schema int, deprecated bool) CatalogDocument {
	doc := CatalogDocument{
		SchemaVersion: schema,
		Version:       version,
		Source:        "joint-walk-vendor",
		AsOf:          "2024-06-01",
		Models: []CatalogModelEntry{{
			Provider: "openai",
			Model:    "gpt-alpha",
			Aliases:  []string{"gpt-alpha-mini"},
			Capabilities: map[string]bool{
				"chat": true, "streaming": true, "tools": true,
			},
			Limits:        &CatalogLimits{ContextWindowTokens: 128000, MaxOutputTokens: 16384},
			Price:         &CatalogPrice{Input: 2.5, Output: 10, CacheR: 1.25},
			EffectiveFrom: "2023-01-01",
			EffectiveTo:   "2025-06-01",
		}},
	}
	if deprecated {
		doc.Models[0].DeprecatedAt = "2024-03-01"
	}
	return doc
}

// TestJointDeprecationAnnouncementToZombieCheck is the full drift walk:
// vendor announces end-of-life mid-window → catalog rebuild → the picker
// marks the row deprecated but still sellable → the operator narrows the
// window → the model retires → zombie-check: no surface shows the dead
// model green, and a provider-level withdrawal drags the whole namespace
// down while the rows stay inspectable.
func TestJointDeprecationAnnouncementToZombieCheck(t *testing.T) {
	narrow := provider.ModelOverride{
		Provider:     "openai",
		Model:        "gpt-alpha",
		EffectiveTo:  jNarrowAt, // 2025-06-01 → 2024-09-01
		DeprecatedAt: jDepAt,    // restate: the operator ships the announcement with the narrowing
	}

	// Gen 1: healthy vendor snapshot (schema v1, no EOL data).
	gen1, sum1 := jointBuild(t, jointDocBytes(t, jointVendorDoc("vendor-rev-1", CatalogSchemaV1, false)))
	jointInstall(t, gen1)

	if st := gen1.Status("openai", "gpt-alpha", jOpened); st != provider.StatusActive {
		t.Fatalf("gen1 status = %v, want active", st)
	}
	if gen1.Deprecated("openai", "gpt-alpha", jOpened) {
		t.Fatal("gen1 must not flag deprecation before any announcement")
	}
	rows := gen1.FilterVisible([]provider.PickerRow{{Provider: "openai", Model: "gpt-alpha", KeyVisible: true}}, jOpened)
	if len(rows) != 1 || rows[0].Deprecated {
		t.Fatalf("gen1 picker = %+v, want one green row", rows)
	}

	// The vendor announces end-of-life mid-window: a schema-v2 rebuild.
	gen2Raw := jointDocBytes(t, jointVendorDoc("vendor-rev-2", CatalogSchemaV2, true))
	gen2, sum2 := jointBuild(t, gen2Raw)
	if sum1 == sum2 {
		t.Fatal("the announcement must move the document fingerprint")
	}
	if gen2.SchemaVersion() != CatalogSchemaV2 {
		t.Fatalf("gen2 schema = %d, want %d", gen2.SchemaVersion(), CatalogSchemaV2)
	}
	jointInstall(t, gen2)

	// Deprecated but sellable: the flag is observable through the exact
	// name and the alias, while every sell-side surface keeps serving.
	for _, name := range []string{"gpt-alpha", "gpt-alpha-mini"} {
		if !gen2.Deprecated("openai", name, jAnnounced) {
			t.Fatalf("%s must be flagged deprecated at %v", name, jAnnounced)
		}
		if _, ok := gen2.Capabilities("openai", name, jAnnounced); !ok {
			t.Fatalf("%s must still serve capabilities while deprecated", name)
		}
		if p, m, ok := gen2.PricingKey("openai", name, jAnnounced); !ok || p != "openai" || m != "gpt-alpha" {
			t.Fatalf("%s pricing key = (%q,%q,%v) while deprecated", name, p, m, ok)
		}
	}
	rows = gen2.FilterVisible([]provider.PickerRow{{Provider: "openai", Model: "gpt-alpha", KeyVisible: true}}, jAnnounced)
	if len(rows) != 1 || !rows[0].Deprecated {
		t.Fatalf("picker = %+v, want the row kept and flagged (deprecated ≠ hidden)", rows)
	}

	// The lifecycle report renders the announcement instead of a collapsed
	// green: tested, available and deprecated on the same row.
	report := BuildLifecycleReport(gen2, []LifecycleFact{
		{Provider: "openai", Model: "gpt-alpha-mini", Configured: true, Tested: true}, // named through the alias
	}, jAnnounced)
	if len(report.Rows) != 1 {
		t.Fatalf("report rows = %d, want 1: %+v", len(report.Rows), report.Rows)
	}
	row := report.Rows[0]
	if row.Provider+":"+row.Model != "openai:gpt-alpha" || row.Aliases[0] != "gpt-alpha-mini" {
		t.Fatalf("report row = %+v, want the canonical row with the sorted alias", row)
	}
	if row.State != provider.LifecycleTested || !row.Available || !row.Deprecated || !row.DeprecatedAt.Equal(jDepAt) {
		t.Fatalf("deprecated-and-tested row = %+v, want tested/available/deprecated with the instant", row)
	}
	if report.Summary.Tested != 1 {
		t.Fatalf("summary = %+v, want one tested row", report.Summary)
	}

	// The operator narrows the window on top of the announcement.
	merged, err := provider.ApplyOverrides(gen2, []provider.ModelOverride{narrow})
	if err != nil {
		t.Fatalf("narrowing override: %v", err)
	}
	jointInstall(t, merged)

	e, ok := merged.Entry("openai", "gpt-alpha")
	if !ok || !e.EffectiveTo.Equal(jNarrowAt) {
		t.Fatalf("narrowed close = (%v,%v), want %v", e.EffectiveTo, ok, jNarrowAt)
	}
	if st := merged.Status("openai", "gpt-alpha", jAnnounced); st != provider.StatusActive {
		t.Fatalf("status inside the narrowed live phase = %v", st)
	}
	if !merged.Deprecated("openai", "gpt-alpha", jLastCall) {
		t.Fatal("the announcement must survive the narrowing (deprecation only moves earlier)")
	}
	if st := merged.Status("openai", "gpt-alpha", jNarrowAt); st != provider.StatusRetired {
		t.Fatalf("status at the half-open close = %v, want retired", st)
	}

	// Zombie-check (model level): the sell window closed, but the static
	// picker list still names the model and its alias. Every view must
	// agree the model is dead.
	if got := ReconcileStaticNames(merged, []StaticModelRef{
		{Provider: "openai", Model: "gpt-alpha"},
		{Provider: "openai", Model: "gpt-alpha-mini"},
	}, jZombie); got[0].Status != provider.StatusRetired || got[1].Status != provider.StatusRetired {
		t.Fatalf("static reconcile = [%v,%v], want both retired (not green)", got[0].Status, got[1].Status)
	}
	if kept := merged.FilterVisible([]provider.PickerRow{
		{Provider: "openai", Model: "gpt-alpha", KeyVisible: true},
		{Provider: "openai", Model: "gpt-alpha-mini", KeyVisible: true},
	}, jZombie); len(kept) != 0 {
		t.Fatalf("picker kept zombie rows: %+v", kept)
	}
	if merged.Deprecated("openai", "gpt-alpha", jZombie) {
		t.Fatal("a retired model is not deprecated: retirement dominates the flag")
	}
	if _, ok := merged.Capabilities("openai", "gpt-alpha", jZombie); ok {
		t.Fatal("zombie must not serve capabilities")
	}
	if _, _, ok := merged.PricingKey("openai", "gpt-alpha", jZombie); ok {
		t.Fatal("zombie must not route pricing keys")
	}
	if m, st := merged.ResolveAlias("openai", "gpt-alpha-mini", jZombie); m != "gpt-alpha" || st != provider.StatusRetired {
		t.Fatalf("stale alias = (%q,%v), want the retired target (no name resurrection)", m, st)
	}
	// The billing facts stay intact for in-flight requests: retirement
	// hides the model from sale surfaces, it does not erase price history.
	if e, ok := merged.Entry("openai", "gpt-alpha"); !ok || !e.PriceListed || e.Price.InputPerM != 2.5 || e.Price.OutputPerM != 10 {
		t.Fatalf("zombie price history = (%+v, listed=%v, %v)", e.Price, e.PriceListed, ok)
	}

	// Gen 3: the vendor withdraws the whole provider; the operator
	// re-applies the local override on top of the vendor rebuild (the
	// local override set is state the installation carries forward).
	gen3 := jointVendorDoc("vendor-rev-3", CatalogSchemaV2, true)
	gen3.WithdrawnProviders = []CatalogWithdrawal{{Provider: "openai", WithdrawnAt: "2025-01-01"}}
	gen3cat, _ := jointBuild(t, jointDocBytes(t, gen3))
	merged3, err := provider.ApplyOverrides(gen3cat, []provider.ModelOverride{narrow})
	if err != nil {
		t.Fatalf("gen3 merge: %v", err)
	}
	jointInstall(t, merged3)

	if !merged3.ProviderAdmitted("openai", jLastCall) {
		t.Fatal("provider must stay admitted before its withdrawal instant")
	}
	if merged3.ProviderAdmitted("openai", jWithdrawn) {
		t.Fatal("provider must be unadmitted after its withdrawal instant")
	}
	report3 := BuildLifecycleReport(merged3, []LifecycleFact{
		{Provider: "openai", Model: "gpt-alpha", Configured: true, Tested: true},
	}, jWithdrawn)
	if len(report3.Rows) != 1 || report3.Rows[0].State != provider.LifecycleUnavailable {
		t.Fatalf("withdrawn-provider report = %+v, want the row unavailable", report3.Rows)
	}
	if report3.Summary.Unavailable != 1 {
		t.Fatalf("summary = %+v, want one unavailable row", report3.Summary)
	}
	wants := merged3.Withdrawals()
	if len(wants) != 1 || wants[0].Provider != "openai" || !wants[0].WithdrawnAt.Equal(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("withdrawals = %+v, want openai @ 2025-01-01", wants)
	}
	// The rows are not erased: drift stays inspectable.
	if merged3.EntryCount() != 1 {
		t.Fatalf("entry count = %d, want the retired row preserved", merged3.EntryCount())
	}
}

// TestJointDocumentToConsumersConsistentViews is the second walk: a v2
// document is loaded, runtime overrides are applied on the installed
// snapshot (after a hostile set failed the merged-space re-validation
// without touching the installed surface), and the consumers — static-name
// reconcile, lifecycle report, picker filter, pricing key routing — all see
// consistent views, with the operator-supplied price store untouched.
func TestJointDocumentToConsumersConsistentViews(t *testing.T) {
	// REAL component: the production parser and immutable store, with an
	// explicitly synthetic operator price file. No upstream corpus is used.
	pf, digest, err := pricing.ParsePriceFile(strings.NewReader(`{
	  "source":"synthetic joint consumer test", "date":"2024-06-01",
	  "currency":"USD", "units":"per_1m_tokens", "models":[
	    {"provider":"openai", "model":"gpt-4o", "input":7, "output":19, "cache_r":2}
	  ]
	}`))
	if err != nil {
		t.Fatalf("parse synthetic price file: %v", err)
	}
	pricer, err := pricing.NewFilePricer(pf, digest)
	if err != nil {
		t.Fatalf("load operator price store: %v", err)
	}
	realPrice, ok := pricer.Lookup("openai", "gpt-4o")
	if !ok || realPrice.InputPerM != 7 || realPrice.OutputPerM != 19 {
		t.Fatal("operator price store must retain the synthetic rates")
	}

	// MOCK component: a synthetic vendor document with fixed instants.
	doc := CatalogDocument{
		SchemaVersion: CatalogSchemaV2,
		Version:       "joint-rev-1",
		Source:        "joint-walk-mock",
		AsOf:          "2024-06-01",
		Models: []CatalogModelEntry{
			{
				Provider: "openai", Model: "gpt-alpha", Aliases: []string{"gpt-alpha-mini"},
				Capabilities:  map[string]bool{"chat": true, "streaming": true, "tools": true, "vision_input": true},
				Price:         &CatalogPrice{Input: 2.5, Output: 10, CacheR: 1.25},
				EffectiveFrom: "2023-01-01",
				EffectiveTo:   "2025-06-01",
			},
			{
				Provider: "anthropic", Model: "claude-alpha",
				Capabilities: map[string]bool{"chat": true, "pdf_input": true},
			},
			{
				// The catalog carries the synthetic operator price read
				// through the production parser; every consumer must
				// agree with this immutable price store.
				Provider: "openai", Model: "gpt-4o",
				Capabilities: map[string]bool{"chat": true, "vision_input": true},
				Price: &CatalogPrice{
					Input: realPrice.InputPerM, Output: realPrice.OutputPerM, CacheR: realPrice.CacheReadPerM,
				},
			},
		},
	}
	base, sum := jointBuild(t, jointDocBytes(t, doc))
	jointInstall(t, base)
	if sum == "" {
		t.Fatal("every installed document carries its SHA256 fingerprint")
	}
	baseEntries := base.Entries()

	// Hostile runtime override set: the alias collides with a vendor
	// model name in the same provider. The merged-space re-validation
	// must reject it loudly, and the installed snapshot must not move.
	installed := provider.CurrentModelCatalog()
	_, err = provider.ApplyOverrides(base, []provider.ModelOverride{
		{Provider: "openai", Model: "gpt-alpha", Aliases: []string{"gpt-4o"}},
		{Provider: "selfhosted", Model: "llama-local", Capabilities: &provider.ModelCapabilities{Chat: true}},
	})
	if err == nil || !strings.Contains(err.Error(), `alias "gpt-4o" collides with an existing model name`) {
		t.Fatalf("hostile merge err = %v, want the merged-namespace collision", err)
	}
	if !strings.Contains(err.Error(), "merged catalog with 2 override(s)") {
		t.Fatalf("hostile merge err = %v, want the merge provenance", err)
	}
	if provider.CurrentModelCatalog() != installed {
		t.Fatal("a failed merge must never reach the installed snapshot")
	}

	// The good override set: replace the alpha attribute payload, narrow
	// the window with the announced EOL, introduce a custom row.
	merged, err := provider.ApplyOverrides(base, []provider.ModelOverride{
		{
			Provider: "openai", Model: "gpt-alpha",
			Aliases:      []string{"gpt-alpha-mini"}, // restate: replacement sets are authoritative
			Capabilities: &provider.ModelCapabilities{Chat: true, Streaming: true},
			EffectiveTo:  jNarrowAt,
			DeprecatedAt: jDepAt,
		},
		{
			Provider: "selfhosted", Model: "llama-local",
			Aliases:       []string{"llama"},
			Capabilities:  &provider.ModelCapabilities{Chat: true},
			EffectiveFrom: time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC),
		},
	})
	if err != nil {
		t.Fatalf("good merge: %v", err)
	}
	jointInstall(t, merged)

	// The merged snapshot inherits the base metadata…
	if merged.Version() != base.Version() || merged.SchemaVersion() != base.SchemaVersion() ||
		merged.Source() != base.Source() || !merged.AsOf().Equal(base.AsOf()) {
		t.Fatalf("merged metadata drifted: %q v%d %q %v", merged.Version(), merged.SchemaVersion(), merged.Source(), merged.AsOf())
	}
	// …the override replaced the explicit attributes…
	alpha, _ := merged.Entry("openai", "gpt-alpha")
	if alpha.Custom || alpha.Capabilities.Tools || alpha.Capabilities.VisionInput || !alpha.Capabilities.Chat {
		t.Fatalf("overridden capabilities = %+v, want the operator set", alpha.Capabilities)
	}
	// …narrowed the window and kept the announcement…
	if !alpha.EffectiveTo.Equal(jNarrowAt) || !alpha.DeprecatedAt.Equal(jDepAt) {
		t.Fatalf("alpha window/EOL = (%v,%v)", alpha.EffectiveTo, alpha.DeprecatedAt)
	}
	// …and never touched pricing (the price store stays authoritative).
	if !alpha.PriceListed || !reflect.DeepEqual(alpha.Price, baseEntries[0].Price) {
		t.Fatalf("override moved pricing: %+v listed=%v", alpha.Price, alpha.PriceListed)
	}
	llama, ok := merged.Entry("selfhosted", "llama-local")
	if !ok || !llama.Custom || llama.PriceListed {
		t.Fatalf("custom row = (%+v, %v), want Custom and unlisted", llama, llama.PriceListed)
	}
	// The base snapshot itself is untouched by both merges.
	if !reflect.DeepEqual(base.Entries(), baseEntries) {
		t.Fatal("the base snapshot must be immutable across merges")
	}

	// Consumers see one consistent picture at the walk instant.
	at := jAnnounced
	static := ReconcileStaticNames(merged, []StaticModelRef{
		{Provider: "openai", Model: "gpt-alpha-mini"}, // alias
		{Provider: "openai", Model: "gpt-4o"},
		{Provider: "selfhosted", Model: "llama"}, // custom alias
		{Provider: "openai", Model: "no-such-model"},
	}, at)
	for i, want := range []provider.ModelStatus{
		provider.StatusActive, provider.StatusActive, provider.StatusActive, provider.StatusUnknown,
	} {
		if static[i].Status != want {
			t.Fatalf("static[%d] (%s) = %v, want %v", i, static[i].Ref.Model, static[i].Status, want)
		}
	}

	facts := []LifecycleFact{
		{Provider: "openai", Model: "gpt-alpha-mini", Configured: true, Tested: true},
		{Provider: "anthropic", Model: "claude-alpha", Configured: true},
		{Provider: "selfhosted", Model: "llama-local", Configured: true},
	}
	report := BuildLifecycleReport(merged, facts, at)
	wantRows := []struct {
		key   string
		state provider.ModelLifecycle
		dep   bool
	}{
		{"anthropic:claude-alpha", provider.LifecycleConfigured, false},
		{"openai:gpt-4o", provider.LifecycleDiscovered, false}, // no facts: discovered
		{"openai:gpt-alpha", provider.LifecycleTested, true},
		{"selfhosted:llama-local", provider.LifecycleConfigured, false},
	}
	if len(report.Rows) != len(wantRows) {
		t.Fatalf("report rows = %d, want %d: %+v", len(report.Rows), len(wantRows), report.Rows)
	}
	for i, w := range wantRows {
		r := report.Rows[i]
		if r.Provider+":"+r.Model != w.key || r.State != w.state || r.Deprecated != w.dep {
			t.Fatalf("row[%d] = %s:%s state=%v dep=%v, want %s state=%v dep=%v",
				i, r.Provider, r.Model, r.State, r.Deprecated, w.key, w.state, w.dep)
		}
		// The report and the per-name classifier can never disagree.
		if r.State != merged.Lifecycle(r.Provider, r.Model, at, r.Configured, r.Tested) {
			t.Fatalf("row[%d] state %v disagrees with the classifier", i, r.State)
		}
	}
	if report.Summary != (LifecycleSummary{Discovered: 1, Configured: 2, Tested: 1}) {
		t.Fatalf("summary = %+v", report.Summary)
	}

	// The picker view agrees with the report: deprecated-but-sellable is
	// flagged, healthy rows stay green, order is preserved.
	picker := merged.FilterVisible([]provider.PickerRow{
		{Provider: "openai", Model: "gpt-alpha", KeyVisible: true},
		{Provider: "anthropic", Model: "claude-alpha", KeyVisible: true},
		{Provider: "selfhosted", Model: "llama-local", KeyVisible: true},
		{Provider: "openai", Model: "gpt-4o", KeyVisible: true},
	}, at)
	if len(picker) != 4 || !picker[0].Deprecated || picker[1].Deprecated || picker[2].Deprecated || picker[3].Deprecated {
		t.Fatalf("picker = %+v, want only gpt-alpha flagged", picker)
	}

	// Pricing adjacency: the catalog routes the pricing key to the
	// canonical name and the real price store answers it; the merge never
	// reached the store, and the custom row cannot mint a price.
	p, m, ok := merged.PricingKey("openai", "gpt-4o", at)
	if !ok || p != "openai" || m != "gpt-4o" {
		t.Fatalf("pricing key = (%q,%q,%v)", p, m, ok)
	}
	if routed, listed := pricer.Lookup(p, m); !listed || !reflect.DeepEqual(routed, realPrice) {
		t.Fatalf("pricer(%s:%s) = (%+v,%v), want the real listed price", p, m, routed, listed)
	}
	if e4o, _ := merged.Entry("openai", "gpt-4o"); !reflect.DeepEqual(e4o.Price, realPrice) {
		t.Fatalf("catalog list price %+v != real store price %+v", e4o.Price, realPrice)
	}
	if _, _, ok := merged.PricingKey("selfhosted", "llama-local", at); !ok {
		t.Fatal("the custom row is active: its pricing key must resolve")
	}
	if _, listed := pricer.Lookup("selfhosted", "llama-local"); listed {
		t.Fatal("the custom row must not mint a price-store row")
	}
}

// jointOnboardingDoc builds the raw bytes of an onboarding document: one
// vendor row plus the given customization set (empty = none).
func jointOnboardingDoc(version string, customs []CatalogOverride) []byte {
	doc := CatalogDocument{
		SchemaVersion: CatalogSchemaV2,
		Version:       version,
		Source:        "joint-walk-operator",
		AsOf:          "2024-06-01",
		Models: []CatalogModelEntry{{
			Provider:      "openai",
			Model:         "gpt-alpha",
			Aliases:       []string{"gpt-alpha-mini"},
			Capabilities:  map[string]bool{"chat": true, "streaming": true},
			Price:         &CatalogPrice{Input: 2.5, Output: 10},
			EffectiveFrom: "2023-01-01",
			EffectiveTo:   "2025-06-01",
		}},
		Customizations: customs,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		panic(err) // unreachable for a fixed struct
	}
	return raw
}

// TestJointCustomOnboardingFlow walks the operator journey of introducing
// custom rows into a live installation, with alias collisions handled at
// the layer that owns them: a draft whose custom alias collides with a
// vendor model name parses (document level leaves vendor-namespace
// collisions to the merged space) but is rejected by the merge, and the
// failed install leaves the previous snapshot serving; the corrected draft
// installs; a second custom row that wants an already-taken override alias
// is rejected at document level; and a vendor-row override restating its
// own alias coexists with the custom rows.
func TestJointCustomOnboardingFlow(t *testing.T) {
	customLlama := func(alias string) CatalogOverride {
		return CatalogOverride{
			Provider: "openai", Model: "llama-local", // the org's OpenAI-compatible proxy
			Aliases:       []string{alias},
			Capabilities:  map[string]bool{"chat": true},
			EffectiveFrom: "2023-06-01",
		}
	}

	// Baseline: the vendor snapshot is live before any onboarding.
	baseRaw := jointOnboardingDoc("onboarding-rev-0", nil)
	base, baseSum := jointBuild(t, baseRaw)
	jointInstall(t, base)
	if base.EntryCount() != 1 {
		t.Fatalf("baseline entries = %d, want the vendor row", base.EntryCount())
	}

	// Phase 1 — the draft: the custom row wants the vendor model name as
	// its alias. Document validation passes by design (an override may
	// restate vendor names; the merged name space is the arbiter)…
	draft := jointOnboardingDoc("onboarding-rev-1", []CatalogOverride{customLlama("gpt-alpha")})
	draftDoc, draftSum, err := ParseCatalogDocument(bytes.NewReader(draft))
	if err != nil {
		t.Fatalf("draft must pass document validation: %v", err)
	}
	// …but the merged-space re-validation rejects the fork attempt, and a
	// failed install leaves the previous snapshot serving.
	if _, err := BuildModelCatalog(draftDoc); err == nil ||
		!strings.Contains(err.Error(), `alias "gpt-alpha" collides with an existing model name`) ||
		!strings.Contains(err.Error(), "merged catalog with 1 override(s)") {
		t.Fatalf("draft build err = %v, want the merged-namespace collision", err)
	}
	installed := provider.CurrentModelCatalog()
	if _, _, err := InstallCatalog(bytes.NewReader(draft)); err == nil {
		t.Fatal("the colliding draft must not install")
	}
	if provider.CurrentModelCatalog() != installed {
		t.Fatal("a failed install must leave the previous snapshot serving")
	}

	// Phase 2 — the corrected draft installs atomically.
	prev := provider.CurrentModelCatalog()
	correctedRaw := jointOnboardingDoc("onboarding-rev-2", []CatalogOverride{customLlama("llama")})
	llama, sum2, err := InstallCatalog(bytes.NewReader(correctedRaw))
	if err != nil {
		t.Fatalf("corrected install: %v", err)
	}
	t.Cleanup(func() { provider.SetModelCatalog(prev) })
	if provider.CurrentModelCatalog() != llama {
		t.Fatal("the corrected snapshot must be the installed one")
	}
	if sum2 == draftSum || sum2 == baseSum {
		t.Fatal("each accepted revision carries its own fingerprint")
	}
	e, ok := llama.Entry("openai", "llama-local")
	if !ok || !e.Custom || !e.Capabilities.Chat {
		t.Fatalf("custom row = (%+v, %v)", e, ok)
	}
	if m, st := llama.ResolveAlias("openai", "llama", jAnnounced); m != "llama-local" || st != provider.StatusActive {
		t.Fatalf("custom alias = (%q,%v)", m, st)
	}
	if !llama.PickerVisible("openai", "llama-local", jAnnounced, true) {
		t.Fatal("the custom row must be picker-visible under the key policy")
	}
	// A fact named through the custom alias folds into the custom row.
	report := BuildLifecycleReport(llama, []LifecycleFact{
		{Provider: "openai", Model: "llama", Configured: true},
	}, jAnnounced)
	if len(report.Rows) != 2 { // gpt-alpha (discovered) + llama-local (configured)
		t.Fatalf("report rows = %d, want 2: %+v", len(report.Rows), report.Rows)
	}
	if r := report.Rows[1]; r.Provider+":"+r.Model != "openai:llama-local" || r.State != provider.LifecycleConfigured {
		t.Fatalf("custom report row = %+v, want configured llama-local", r)
	}

	// Phase 3 — a second custom row wants the alias the first one took:
	// document-level rejection (cross-override uniqueness), then the
	// corrected second row installs and coexists.
	prev = provider.CurrentModelCatalog()
	clash := jointOnboardingDoc("onboarding-rev-3", []CatalogOverride{
		customLlama("llama"),
		{Provider: "openai", Model: "qwen-local", Aliases: []string{"llama"}, Capabilities: map[string]bool{"chat": true}},
	})
	if _, _, err := InstallCatalog(bytes.NewReader(clash)); err == nil ||
		!strings.Contains(err.Error(), `alias "llama" is already used by another override in this provider`) {
		t.Fatalf("clashing install err = %v, want the cross-override alias rejection", err)
	}
	if provider.CurrentModelCatalog() != prev {
		t.Fatal("the rejected revision must not displace the live snapshot")
	}
	twoCustomRaw := jointOnboardingDoc("onboarding-rev-4", []CatalogOverride{
		customLlama("llama"),
		{Provider: "openai", Model: "qwen-local", Aliases: []string{"qwen"}, Capabilities: map[string]bool{"chat": true}},
	})
	both, _, err := InstallCatalog(bytes.NewReader(twoCustomRaw))
	if err != nil {
		t.Fatalf("two-custom install: %v", err)
	}
	t.Cleanup(func() { provider.SetModelCatalog(prev) })
	if both.EntryCount() != 3 {
		t.Fatalf("entries = %d, want vendor + two custom rows", both.EntryCount())
	}
	for _, pair := range [][2]string{{"llama", "llama-local"}, {"qwen", "qwen-local"}} {
		if m, st := both.ResolveAlias("openai", pair[0], jAnnounced); m != pair[1] || st != provider.StatusActive {
			t.Fatalf("alias %s = (%q,%v), want %s", pair[0], m, st, pair[1])
		}
	}

	// Phase 4 — a vendor-row override restating the vendor alias of the
	// row it replaces is legal and coexists with the custom rows: the
	// replacement alias set is authoritative, the row stays vendor-owned.
	prev = provider.CurrentModelCatalog()
	finalRaw := jointOnboardingDoc("onboarding-rev-5", []CatalogOverride{
		customLlama("llama"),
		{Provider: "openai", Model: "qwen-local", Aliases: []string{"qwen"}, Capabilities: map[string]bool{"chat": true}},
		{
			Provider: "openai", Model: "gpt-alpha",
			Aliases:      []string{"gpt-alpha-mini", "gpt-alpha-short"},
			Capabilities: map[string]bool{"chat": true, "streaming": true, "tools": true},
		},
	})
	final, _, err := InstallCatalog(bytes.NewReader(finalRaw))
	if err != nil {
		t.Fatalf("final install: %v", err)
	}
	t.Cleanup(func() { provider.SetModelCatalog(prev) })
	alpha, ok := final.Entry("openai", "gpt-alpha")
	if !ok || alpha.Custom {
		t.Fatalf("overridden vendor row = (%+v, %v), want Custom=false (vendor identity)", alpha, ok)
	}
	if m, st := final.ResolveAlias("openai", "gpt-alpha-short", jAnnounced); m != "gpt-alpha" || st != provider.StatusActive {
		t.Fatalf("restated alias = (%q,%v)", m, st)
	}
	if _, ok := final.Entry("openai", "llama-local"); !ok {
		t.Fatal("the custom rows must survive the vendor-row override")
	}
	if _, ok := final.Entry("openai", "qwen-local"); !ok {
		t.Fatal("the second custom row must survive the vendor-row override")
	}
}

// jointSchemaDoc builds the raw bytes of the migration-arc document: one
// vendor row selling 2023-01-01…2025-06-01, optionally carrying the
// end-of-life announcement (v2 data) under the requested schema version.
func jointSchemaDoc(version string, schema int, deprecated bool) []byte {
	doc := CatalogDocument{
		SchemaVersion: schema,
		Version:       version,
		Source:        "joint-walk-schema",
		AsOf:          "2024-06-01",
		Models: []CatalogModelEntry{{
			Provider:      "openai",
			Model:         "gpt-alpha",
			Aliases:       []string{"gpt-alpha-mini"},
			Capabilities:  map[string]bool{"chat": true, "streaming": true},
			Price:         &CatalogPrice{Input: 2.5, Output: 10},
			EffectiveFrom: "2023-01-01",
			EffectiveTo:   "2025-06-01",
		}},
	}
	if deprecated {
		doc.Models[0].DeprecatedAt = "2024-03-01"
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		panic(err) // unreachable for a fixed struct
	}
	return raw
}

// TestJointSchemaEvolutionArcs walks the v1→v2 vocabulary migration: a v1
// installation, the announcement arriving in v1 clothing (rejected — an old
// vocabulary can never silently absorb new data), the schema bump that
// makes the announcement legible, the no-op bump that must change no
// behavior, a future schema version the parser refuses to guess forward on,
// and the schema pin riding through a runtime merge.
func TestJointSchemaEvolutionArcs(t *testing.T) {
	t.Run("v1 baseline, v1-carried announcement, the bump", func(t *testing.T) {
		// The v1 installation serves happily and knows nothing of EOL.
		v1, _, err := InstallCatalog(bytes.NewReader(jointSchemaDoc("schema-rev-1", CatalogSchemaV1, false)))
		if err != nil {
			t.Fatalf("v1 install: %v", err)
		}
		if v1.SchemaVersion() != CatalogSchemaV1 {
			t.Fatalf("v1 schema = %d", v1.SchemaVersion())
		}
		if v1.Deprecated("openai", "gpt-alpha", jAnnounced) {
			t.Fatal("v1 must not flag deprecation")
		}

		// Drift arrives: the same data with an announcement, still
		// declared as v1. The old vocabulary cannot absorb it silently —
		// the rejection names the migration, and the v1 snapshot keeps
		// serving.
		drift := jointSchemaDoc("schema-rev-2", CatalogSchemaV1, true)
		if _, _, err := ParseCatalogDocument(bytes.NewReader(drift)); err == nil ||
			!strings.Contains(err.Error(), "deprecated_at requires schema_version 2") {
			t.Fatalf("drift parse err = %v, want the schema-bump demand", err)
		}
		if _, _, err := InstallCatalog(bytes.NewReader(drift)); err == nil {
			t.Fatal("v1-carried v2 data must not install")
		}
		if provider.CurrentModelCatalog() != v1 {
			t.Fatal("the rejected migration must leave the v1 snapshot serving")
		}

		// The operator bumps the schema: the same announcement installs
		// and becomes observable.
		v2, sum, err := InstallCatalog(bytes.NewReader(jointSchemaDoc("schema-rev-2", CatalogSchemaV2, true)))
		if err != nil {
			t.Fatalf("migrated install: %v", err)
		}
		t.Cleanup(func() { provider.SetModelCatalog(nil) })
		if v2.SchemaVersion() != CatalogSchemaV2 || sum == "" {
			t.Fatalf("migrated snapshot = v%d (sum %q)", v2.SchemaVersion(), sum)
		}
		if !v2.Deprecated("openai", "gpt-alpha", jAnnounced) {
			t.Fatal("the announcement must be observable after the bump")
		}
	})

	t.Run("no-op bump changes no behavior", func(t *testing.T) {
		v1, err := BuildModelCatalog(mustParse(t, jointSchemaDoc("schema-rev-1", CatalogSchemaV1, false)))
		if err != nil {
			t.Fatalf("v1 build: %v", err)
		}
		v2, err := BuildModelCatalog(mustParse(t, jointSchemaDoc("schema-rev-1", CatalogSchemaV2, false)))
		if err != nil {
			t.Fatalf("v2 build: %v", err)
		}
		if v1.SchemaVersion() != CatalogSchemaV1 || v2.SchemaVersion() != CatalogSchemaV2 {
			t.Fatalf("schemas = %d/%d", v1.SchemaVersion(), v2.SchemaVersion())
		}
		// Identical rows, identical statuses, identical picker output.
		if !reflect.DeepEqual(v1.Entries(), v2.Entries()) {
			t.Fatal("the no-op bump must not move the row set")
		}
		for _, at := range []time.Time{jOpened, jAnnounced, jZombie} {
			if v1.Status("openai", "gpt-alpha", at) != v2.Status("openai", "gpt-alpha", at) {
				t.Fatalf("status disagree at %v", at)
			}
		}
		rows := []provider.PickerRow{{Provider: "openai", Model: "gpt-alpha", KeyVisible: true}}
		if !reflect.DeepEqual(v1.FilterVisible(rows, jAnnounced), v2.FilterVisible(rows, jAnnounced)) {
			t.Fatal("the no-op bump must not move the picker view")
		}
	})

	t.Run("future schema is refused, not guessed", func(t *testing.T) {
		future := jointSchemaDoc("schema-rev-3", 3, true)
		if _, _, err := ParseCatalogDocument(bytes.NewReader(future)); err == nil ||
			!strings.Contains(err.Error(), "unsupported schema_version 3") {
			t.Fatalf("future parse err = %v, want the version refusal", err)
		}
		// The operator re-declares the same data in the understood
		// vocabulary and the install succeeds.
		installed, _, err := InstallCatalog(bytes.NewReader(jointSchemaDoc("schema-rev-3", CatalogSchemaV2, true)))
		if err != nil {
			t.Fatalf("re-declared install: %v", err)
		}
		t.Cleanup(func() { provider.SetModelCatalog(nil) })
		if installed.SchemaVersion() != CatalogSchemaV2 {
			t.Fatalf("installed schema = %d", installed.SchemaVersion())
		}
	})

	t.Run("schema pin rides the runtime merge", func(t *testing.T) {
		base, err := BuildModelCatalog(mustParse(t, jointSchemaDoc("schema-rev-2", CatalogSchemaV2, true)))
		if err != nil {
			t.Fatalf("base build: %v", err)
		}
		merged, err := provider.ApplyOverrides(base, []provider.ModelOverride{{
			Provider: "selfhosted", Model: "llama-local",
			Capabilities:  &provider.ModelCapabilities{Chat: true},
			EffectiveFrom: time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC),
		}})
		if err != nil {
			t.Fatalf("merge: %v", err)
		}
		if merged.SchemaVersion() != base.SchemaVersion() || merged.Version() != base.Version() ||
			merged.Source() != base.Source() || !merged.AsOf().Equal(base.AsOf()) {
			t.Fatalf("merged metadata = (%q v%d %q %v), want the base pin",
				merged.Version(), merged.SchemaVersion(), merged.Source(), merged.AsOf())
		}
		if e, ok := merged.Entry("selfhosted", "llama-local"); !ok || !e.Custom {
			t.Fatalf("custom row under the inherited pin = (%+v, %v)", e, ok)
		}
	})
}

// mustParse parses raw document bytes or fails the test.
func mustParse(t *testing.T, raw []byte) CatalogDocument {
	t.Helper()
	doc, _, err := ParseCatalogDocument(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse catalog document: %v", err)
	}
	return doc
}

// jointKeyWhitelist is one mock key's whitelist verdicts: the per-key
// visibility the shipping whitelist loader computes for an (apiKey, model)
// pair — explicit allow/deny rows with default-allow for unlisted names. The
// test owns the verdicts; the whitelist store itself is outside the
// catalog's entry paths and is exercised by its own package.
type jointKeyWhitelist map[string]bool

func (w jointKeyWhitelist) visible(model string) bool {
	allowed, listed := w[model]
	if !listed {
		return true // no entry in any scope: default allow
	}
	return allowed
}

// TestJointPerKeyPickerMatchesKeyCapabilities walks the picker the way a
// concrete key experiences it. The static installation list is filtered
// twice — by the key's whitelist verdicts (the KeyVisible input) and by the
// catalog sell windows — and what survives must match the key's real
// capabilities: a sellable model the key may use stays (flagged deprecated
// while still serving), a name the vendor retired never stays green even
// when the static list still names it and the key's whitelist still allows
// it, a key denial is never widened by the catalog, and the capability
// surface agrees with the picker output row by row — sellable rows serve
// their catalog capability set through the exact name and the alias, while
// retired, pending and unknown names serve nothing.
func TestJointPerKeyPickerMatchesKeyCapabilities(t *testing.T) {
	doc := CatalogDocument{
		SchemaVersion: CatalogSchemaV2,
		Version:       "joint-rev-keys",
		Source:        "joint-walk-keys",
		AsOf:          "2024-06-01",
		Models: []CatalogModelEntry{
			{
				Provider: "openai", Model: "gpt-alpha", Aliases: []string{"gpt-alpha-mini"},
				Capabilities:  map[string]bool{"chat": true, "streaming": true, "tools": true},
				Price:         &CatalogPrice{Input: 2.5, Output: 10},
				EffectiveFrom: "2023-01-01",
				EffectiveTo:   "2025-06-01",
				DeprecatedAt:  "2024-03-01",
			},
			{
				// Announced but not yet sellable.
				Provider: "openai", Model: "gpt-beta",
				Capabilities:  map[string]bool{"chat": true},
				EffectiveFrom: "2026-01-01",
			},
			{
				// The vendor retired it 2023-06-01; a stale static list
				// and a stale allowlist row still name it.
				Provider: "openai", Model: "gpt-old",
				Capabilities:  map[string]bool{"chat": true},
				EffectiveFrom: "2022-01-01",
				EffectiveTo:   "2023-06-01",
			},
			{
				Provider: "anthropic", Model: "claude-alpha",
				Capabilities: map[string]bool{"chat": true, "pdf_input": true},
			},
		},
	}
	cat, _ := jointBuild(t, jointDocBytes(t, doc))
	jointInstall(t, cat)

	// The static list the installation renders (config fallback, bundled
	// snapshot): the sellable names, the retired name, the pending name
	// and an org-local name the catalog has no row for.
	staticRefs := []StaticModelRef{
		{Provider: "openai", Model: "gpt-alpha"},
		{Provider: "openai", Model: "gpt-beta"},
		{Provider: "openai", Model: "gpt-old"},
		{Provider: "anthropic", Model: "claude-alpha"},
		{Provider: "selfhosted", Model: "org-local-proxy"},
	}

	// Two concrete keys: a restricted ops key (claude-alpha and gpt-beta
	// explicitly denied, gpt-old still explicitly allowed — a stale
	// allowlist row) and an audit key with no entries (default allow).
	opsKey := jointKeyWhitelist{"claude-alpha": false, "gpt-beta": false, "gpt-old": true}
	auditKey := jointKeyWhitelist{}
	keys := []struct {
		name string
		list jointKeyWhitelist
	}{
		{"ops", opsKey},
		{"audit", auditKey},
	}

	pickerRows := func(list jointKeyWhitelist) []provider.PickerRow {
		out := make([]provider.PickerRow, 0, len(staticRefs))
		for _, r := range staticRefs {
			out = append(out, provider.PickerRow{Provider: r.Provider, Model: r.Model, KeyVisible: list.visible(r.Model)})
		}
		return out
	}

	// The key views at the walk instant: order preserved, only the rows
	// both policies admit survive, and the deprecated row carries the flag
	// instead of a plain green.
	wantKept := map[string][]provider.PickerRow{
		"ops": {
			{Provider: "openai", Model: "gpt-alpha", KeyVisible: true, Deprecated: true},
			{Provider: "selfhosted", Model: "org-local-proxy", KeyVisible: true},
		},
		"audit": {
			{Provider: "openai", Model: "gpt-alpha", KeyVisible: true, Deprecated: true},
			{Provider: "anthropic", Model: "claude-alpha", KeyVisible: true},
			{Provider: "selfhosted", Model: "org-local-proxy", KeyVisible: true},
		},
	}
	for _, k := range keys {
		kept := cat.FilterVisible(pickerRows(k.list), jAnnounced)
		if !reflect.DeepEqual(kept, wantKept[k.name]) {
			t.Fatalf("%s-key picker = %+v, want %+v", k.name, kept, wantKept[k.name])
		}
	}

	// The negative through the key path: gpt-old is named by the static
	// list and its whitelist row says allowed, yet the vendor retired it —
	// neither key may see it green, whatever the key policy claims.
	for _, k := range keys {
		if cat.PickerVisible("openai", "gpt-old", jAnnounced, k.list.visible("gpt-old")) {
			t.Fatalf("%s-key: the retired model must not stay visible through the allowlist row", k.name)
		}
	}
	for i, w := range []provider.ModelStatus{
		provider.StatusActive, provider.StatusPending, provider.StatusRetired,
		provider.StatusActive, provider.StatusUnknown,
	} {
		if got := ReconcileStaticNames(cat, staticRefs[i:i+1], jAnnounced)[0].Status; got != w {
			t.Fatalf("static %s = %v, want %v", staticRefs[i].Model, got, w)
		}
	}

	// A key denial is never widened, even for an active model.
	if cat.PickerVisible("anthropic", "claude-alpha", jAnnounced, opsKey.visible("claude-alpha")) {
		t.Fatal("claude-alpha is denied for the ops key: the catalog must keep it hidden")
	}

	// The capability surface agrees with the picker output row by row.
	wantCaps := map[string]provider.ModelCapabilities{
		"openai:gpt-alpha":       {Chat: true, Streaming: true, Tools: true},
		"anthropic:claude-alpha": {Chat: true, PDFInput: true},
	}
	for _, k := range keys {
		for _, row := range wantKept[k.name] {
			caps, ok := cat.Capabilities(row.Provider, row.Model, jAnnounced)
			if row.Model == "org-local-proxy" {
				if ok {
					t.Fatal("a name without a catalog row must not fabricate capabilities")
				}
				continue // picker-visible per key policy, capability-free by contract
			}
			if !ok || caps != wantCaps[row.Provider+":"+row.Model] {
				t.Fatalf("%s-key %s capabilities = (%+v,%v), want %+v", k.name, row.Model, caps, ok, wantCaps[row.Provider+":"+row.Model])
			}
		}
	}
	// The deprecated model still serves: the flag informs, it does not
	// revoke — through the exact name and the alias alike.
	for _, name := range []string{"gpt-alpha", "gpt-alpha-mini"} {
		if _, ok := cat.Capabilities("openai", name, jAnnounced); !ok {
			t.Fatalf("%s must keep serving capabilities while deprecated", name)
		}
	}
	// Names that are not sellable serve nothing regardless of keys:
	// retired and pending rows expose no capability set at all. (A key
	// denial is a picker-layer fact, pinned above — the catalog capability
	// surface itself stays key-independent.)
	for _, probe := range []struct{ provider, model string }{
		{"openai", "gpt-old"}, {"openai", "gpt-beta"},
	} {
		if _, ok := cat.Capabilities(probe.provider, probe.model, jAnnounced); ok {
			t.Fatalf("%s:%s must not serve capabilities at the walk instant", probe.provider, probe.model)
		}
	}
}
