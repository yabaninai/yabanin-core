package provider

// Negative-scenario corpus for N08-P06-T05: a model past its sell window
// (or a withdrawn provider) never comes back to life through catalog
// customization. Every form below either fails the merge loudly or leaves
// the pair retired with all sell-side capabilities refused — a retired row
// can never regain status, capabilities, pricing or picker visibility.

import (
	"strings"
	"testing"
	"time"
)

// TestVendorRetiredModelNeverResurrects drives every resurrection form
// against openai:gpt-test (sell window [zero, 2024-01-01), so retired from
// t2024 on) and pins the observable outcome: StatusRetired, no capabilities,
// no pricing key, no picker visibility — at t2030, long after the close.
func TestVendorRetiredModelNeverResurrects(t *testing.T) {
	t2023 := time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC)
	allCaps := ModelCapabilities{Chat: true, Streaming: true, Tools: true}
	wideLimits := ModelLimits{ContextWindowTokens: 999999, MaxOutputTokens: 999999}

	forms := []struct {
		name string
		ov   ModelOverride
	}{
		{
			name: "full-attribute override restating everything",
			ov: ModelOverride{
				Provider: "openai", Model: "gpt-test",
				Aliases:      []string{"gpt-short"},
				Capabilities: &allCaps,
				Limits:       &wideLimits,
			},
		},
		{
			name: "window narrowed but still covering t2030",
			ov: ModelOverride{
				Provider: "openai", Model: "gpt-test",
				EffectiveTo: t2030.Add(-time.Hour), // earlier than the vendor close: narrowed
			},
		},
		{
			name: "window opening attempt via a later close is silently narrowed",
			ov: ModelOverride{
				Provider: "openai", Model: "gpt-test",
				EffectiveTo: t2030, // after the vendor close: widening is ignored
			},
		},
		{
			name: "deprecation flag dropped by omission",
			ov: ModelOverride{
				Provider: "openai", Model: "gpt-test",
				Capabilities: &allCaps, // no DeprecatedAt: omission keeps vendor data
			},
		},
		{
			name: "zero-width window",
			ov: ModelOverride{
				Provider: "openai", Model: "gpt-test",
				EffectiveFrom: t2024, EffectiveTo: t2024,
			},
		},
		{
			name: "alias set replaced with a fresh name",
			ov: ModelOverride{
				Provider: "openai", Model: "gpt-test",
				Aliases: []string{"gpt-reborn"},
			},
		},
	}

	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			c, err := ApplyOverrides(mustCatalog(t, sampleSpec()), []ModelOverride{form.ov})
			if err != nil {
				t.Fatalf("merge must succeed for this corpus (the rejection forms are separate): %v", err)
			}

			e, st := c.Lookup("openai", "gpt-test", t2030)
			if st != StatusRetired {
				t.Fatalf("override %+v resurrected the pair: status %v (entry %+v)", form.ov, st, e)
			}
			if _, ok := c.Capabilities("openai", "gpt-test", t2030); ok {
				t.Fatal("retired row must refuse capabilities after the override")
			}
			if _, _, ok := c.PricingKey("openai", "gpt-test", t2030); ok {
				t.Fatal("retired row must refuse its pricing key after the override")
			}
			if c.Deprecated("openai", "gpt-test", t2030) {
				t.Fatal("retired dominates: no deprecation flag past the close")
			}
			if c.PickerVisible("openai", "gpt-test", t2030, true) {
				t.Fatal("retired row must stay out of the picker after the override")
			}

			// Inside the remaining window the row may still work — the
			// corpus only forbids resurrection past the close. Sanity:
			// the mid-window instant must not report retired.
			if st := c.Status("openai", "gpt-test", t2023); st == StatusRetired {
				t.Fatal("sanity: mid-window instant must not be retired")
			}
		})
	}

	t.Run("zero-width window is active at no instant at all", func(t *testing.T) {
		c, err := ApplyOverrides(mustCatalog(t, sampleSpec()), []ModelOverride{{
			Provider: "openai", Model: "gpt-test",
			EffectiveFrom: t2024, EffectiveTo: t2024,
		}})
		if err != nil {
			t.Fatalf("merge: %v", err)
		}
		for _, at := range []time.Time{t2022, t2023, t2024, t2030} {
			if st := c.Status("openai", "gpt-test", at); st == StatusActive {
				t.Fatalf("zero-width window reported active at %v", at)
			}
		}
	})

	t.Run("fresh alias resolves to the same retired row", func(t *testing.T) {
		c, err := ApplyOverrides(mustCatalog(t, sampleSpec()), []ModelOverride{{
			Provider: "openai", Model: "gpt-test",
			Aliases: []string{"gpt-reborn"},
		}})
		if err != nil {
			t.Fatalf("merge: %v", err)
		}
		if _, st := c.Lookup("openai", "gpt-reborn", t2030); st != StatusRetired {
			t.Fatalf("fresh alias on a retired row reports %v, want retired", st)
		}
		if _, st := c.ResolveAlias("openai", "gpt-reborn", t2030); st != StatusRetired {
			t.Fatalf("ResolveAlias through the fresh alias reports %v, want retired", st)
		}
		// The replaced alias is gone entirely: resolving it reports
		// unknown — no second resurrection path through stale names.
		if _, st := c.Lookup("openai", "gpt-short", t2030); st != StatusUnknown {
			t.Fatalf("dropped alias must resolve as unknown, got %v", st)
		}
	})

	t.Run("custom model under another provider does not shadow the retired pair", func(t *testing.T) {
		c, err := ApplyOverrides(mustCatalog(t, sampleSpec()), []ModelOverride{{
			Provider: "anthropic", Model: "gpt-test",
			Capabilities: &allCaps,
		}})
		if err != nil {
			t.Fatalf("merge: %v", err)
		}
		if _, st := c.Lookup("openai", "gpt-test", t2030); st != StatusRetired {
			t.Fatalf("vendor pair resurrected through a same-named custom row: %v", st)
		}
		// The custom row is its own row — but it must not make the vendor
		// pair's namespace ambiguous.
		if _, st := c.Lookup("anthropic", "gpt-test", t2030); st != StatusActive {
			t.Fatalf("custom row itself should be active, got %v", st)
		}
	})

	t.Run("filter drops the restated retired row", func(t *testing.T) {
		c, err := ApplyOverrides(mustCatalog(t, sampleSpec()), []ModelOverride{{
			Provider: "openai", Model: "gpt-test",
			Aliases: []string{"gpt-short"}, Capabilities: &allCaps, Limits: &wideLimits,
		}})
		if err != nil {
			t.Fatalf("merge: %v", err)
		}
		rows := c.FilterVisible([]PickerRow{
			{Provider: "openai", Model: "gpt-test", KeyVisible: true},
			{Provider: "anthropic", Model: "claude-test", KeyVisible: true},
		}, t2030)
		if len(rows) != 1 || rows[0].Model != "claude-test" {
			t.Fatalf("restated retired row survived the filter: %+v", rows)
		}
	})
}

// TestOverrideWideningFormsFailOrNarrow pins the window-widening surface a
// resurrection attempt can take: every form either errors the merge loudly
// (deprecation inversion) or provably narrows — the widened instant is
// never observed.
func TestOverrideWideningFormsFailOrNarrow(t *testing.T) {
	base := mustCatalog(t, sampleSpec())

	t.Run("widened close is ignored, not applied", func(t *testing.T) {
		c, err := ApplyOverrides(base, []ModelOverride{{
			Provider: "openai", Model: "gpt-test", EffectiveTo: t2030,
		}})
		if err != nil {
			t.Fatalf("merge: %v", err)
		}
		if _, st := c.Lookup("openai", "gpt-test", t2030); st != StatusRetired {
			t.Fatalf("widened close resurrected the model: %v", st)
		}
	})

	t.Run("earlier open is ignored, not applied", func(t *testing.T) {
		// gpt-future opens at t2030; an override claiming an earlier open
		// must not make it active now.
		c, err := ApplyOverrides(base, []ModelOverride{{
			Provider: "openai", Model: "gpt-future", EffectiveFrom: t2022,
		}})
		if err != nil {
			t.Fatalf("merge: %v", err)
		}
		if st := c.Status("openai", "gpt-future", t2022); st != StatusPending {
			t.Fatalf("earlier open applied to a pending model: %v", st)
		}
	})

	t.Run("deprecation after the window close fails the merge", func(t *testing.T) {
		// t2030 is outside the vendor window entirely: a row deprecated
		// after its own close is dead data, and the merged snapshot must
		// refuse to exist rather than install it.
		_, err := ApplyOverrides(base, []ModelOverride{{
			Provider: "openai", Model: "gpt-test", DeprecatedAt: t2030,
		}})
		if err == nil {
			t.Fatal("posthumous deprecation must fail the merge")
		}
		if !strings.Contains(err.Error(), "is not before the sell window closing") {
			t.Fatalf("error must name the window rule: %v", err)
		}
	})
}

// TestWithdrawnProviderOverrideStaysDead is the regression half of the
// zombie form: an override on a withdrawn provider's model must not
// reinstate the provider — admission stays refused and the lifecycle
// reports unavailable.
func TestWithdrawnProviderOverrideStaysDead(t *testing.T) {
	spec := sampleSpec()
	spec.Withdrawals = []Withdrawal{{Provider: "openai", WithdrawnAt: t2022}}
	c, err := ApplyOverrides(mustCatalog(t, spec), []ModelOverride{{
		Provider: "openai", Model: "gpt-test",
		Aliases:      []string{"gpt-short"},
		Capabilities: &ModelCapabilities{Chat: true, Streaming: true, Tools: true},
	}})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if c.ProviderAdmitted("openai", t2030) {
		t.Fatal("override reinstated a withdrawn provider")
	}
	if got := c.Lifecycle("openai", "gpt-test", t2030, true, true); got != LifecycleUnavailable {
		t.Fatalf("zombie lifecycle = %v, want unavailable", got)
	}
}

// TestSameCallOverrideCollisions pins the alias/name ambiguity surface that
// only exists at merge time: each override alone passes, but the set
// introduces a name collision (alias vs custom model name, custom name vs
// another override's alias) that NewModelCatalog must refuse loudly. A
// merged snapshot with an ambiguous name can never exist.
func TestSameCallOverrideCollisions(t *testing.T) {
	base := mustCatalog(t, sampleSpec())

	t.Run("alias collides with a custom model introduced in the same call", func(t *testing.T) {
		_, err := ApplyOverrides(base, []ModelOverride{
			{Provider: "anthropic", Model: "claude-test", Aliases: []string{"fast-claude"}},
			{Provider: "anthropic", Model: "fast-claude", Capabilities: &ModelCapabilities{Chat: true}},
		})
		if err == nil {
			t.Fatal("same-call alias/model collision must fail the merge")
		}
		if !strings.Contains(err.Error(), "merged catalog with 2 override(s)") {
			t.Fatalf("error must come from the merged snapshot: %v", err)
		}
	})

	t.Run("reverse order is equally ambiguous", func(t *testing.T) {
		_, err := ApplyOverrides(base, []ModelOverride{
			{Provider: "anthropic", Model: "fast-claude", Capabilities: &ModelCapabilities{Chat: true}},
			{Provider: "anthropic", Model: "claude-test", Aliases: []string{"fast-claude"}},
		})
		if err == nil {
			t.Fatal("collision must fail regardless of override order")
		}
	})

	t.Run("same-provider alias collision across overrides", func(t *testing.T) {
		// Alias names are provider-scoped: the same alias under two
		// providers is legal, the same alias twice under one provider is
		// an ambiguity the merged snapshot must refuse.
		_, err := ApplyOverrides(base, []ModelOverride{
			{Provider: "openai", Model: "gpt-future", Aliases: []string{"shared"}},
			{Provider: "openai", Model: "gpt-test", Aliases: []string{"shared"}},
		})
		if err == nil {
			t.Fatal("same-provider duplicate alias must fail the merge")
		}
		if !strings.Contains(err.Error(), "duplicate alias") {
			t.Fatalf("error must name the duplicate alias: %v", err)
		}
		t.Run("the same alias under two providers is legal", func(t *testing.T) {
			c, err := ApplyOverrides(base, []ModelOverride{
				{Provider: "openai", Model: "gpt-future", Aliases: []string{"shared"}},
				{Provider: "anthropic", Model: "claude-test", Aliases: []string{"shared"}},
			})
			if err != nil {
				t.Fatalf("provider-scoped aliases must not collide: %v", err)
			}
			if m, _ := c.ResolveAlias("openai", "shared", t2030); m != "gpt-future" {
				t.Fatalf("openai:shared resolved to %q", m)
			}
			if m, _ := c.ResolveAlias("anthropic", "shared", t2030); m != "claude-test" {
				t.Fatalf("anthropic:shared resolved to %q", m)
			}
		})
	})

	t.Run("one override's alias colliding with a later custom model name", func(t *testing.T) {
		_, err := ApplyOverrides(base, []ModelOverride{
			{Provider: "selfhosted", Model: "router", Aliases: []string{"local"}},
			{Provider: "selfhosted", Model: "local", Capabilities: &ModelCapabilities{Chat: true}},
		})
		if err == nil {
			t.Fatal("alias vs later custom model name must fail the merge")
		}
	})

	t.Run("the base snapshot is untouched when the merge refuses", func(t *testing.T) {
		_, err := ApplyOverrides(base, []ModelOverride{
			{Provider: "anthropic", Model: "claude-test", Aliases: []string{"fast-claude"}},
			{Provider: "anthropic", Model: "fast-claude"},
		})
		if err == nil {
			t.Fatal("precondition: collision must fail")
		}
		if got := base.EntryCount(); got != 3 {
			t.Fatalf("base entry count = %d after a refused merge, want unchanged 3", got)
		}
		if _, st := base.Lookup("anthropic", "fast-claude", t2022); st != StatusUnknown {
			t.Fatalf("base must not know the refused custom model, got %v", st)
		}
	})
}
