package adminstore

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

// functions, so they are exercised here without a database; the SQL itself
// is covered by the Real-PG int tests (routing_map_int_test.go,
// provider_health_int_test.go).

func timeNowPtr() *time.Time { t := time.Now().UTC(); return &t }

func model(name string, enabled bool, fallback *string, failover ...string) RoutingMapModel {
	if failover == nil {
		failover = []string{}
	}
	return RoutingMapModel{
		ModelName: name, DisplayName: name, Tier: "smart", Provider: "openai-compat",
		Enabled: enabled, FallbackModel: fallback, FailoverModels: failover, TierPool: []string{},
	}
}

func strptr(s string) *string { return &s }

func warningCodes(ws []RoutingMapWarning) map[string]int {
	out := map[string]int{}
	for _, w := range ws {
		out[w.Code]++
	}
	return out
}

func TestComputeRoutingWarnings_ChainTargetMissing(t *testing.T) {
	models := []RoutingMapModel{model("m1", true, nil, "ghost")}
	ws := computeRoutingWarnings(models, nil, nil)
	if got := warningCodes(ws)[WarnChainTargetMissing]; got != 1 {
		t.Fatalf("chain_target_missing count = %d, want 1; warnings %+v", got, ws)
	}
	if ws[0].Scope != "model" || ws[0].Source != "m1" || ws[0].Target != "ghost" {
		t.Errorf("warning identity = %+v", ws[0])
	}
}

func TestComputeRoutingWarnings_ChainTargetDisabled(t *testing.T) {
	models := []RoutingMapModel{model("m1", true, nil, "off"), model("off", false, nil)}
	ws := computeRoutingWarnings(models, nil, nil)
	if got := warningCodes(ws)[WarnChainTargetDisabled]; got != 1 {
		t.Fatalf("chain_target_disabled count = %d, want 1; warnings %+v", got, ws)
	}
}

func TestComputeRoutingWarnings_FallbackModelCountsAsChain(t *testing.T) {
	models := []RoutingMapModel{model("m1", true, strptr("ghost"), "m2"), model("m2", true, nil)}
	ws := computeRoutingWarnings(models, nil, nil)
	if got := warningCodes(ws)[WarnChainTargetMissing]; got != 1 {
		t.Fatalf("fallback target must warn: %+v", ws)
	}
}

func TestComputeRoutingWarnings_ChainCycle(t *testing.T) {
	cases := []struct {
		name   string
		models []RoutingMapModel
	}{
		{"self failover", []RoutingMapModel{model("m1", true, nil, "m1")}},
		{"self fallback", []RoutingMapModel{model("m1", true, strptr("m1"))}},
		{"duplicate entry", []RoutingMapModel{model("m1", true, nil, "m2", "m2"), model("m2", true, nil)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ws := computeRoutingWarnings(tc.models, nil, nil)
			if got := warningCodes(ws)[WarnChainCycle]; got != 1 {
				t.Fatalf("chain_cycle count = %d, want 1; warnings %+v", got, ws)
			}
		})
	}
}

func TestComputeRoutingWarnings_AliasTargets(t *testing.T) {
	models := []RoutingMapModel{model("live", true, nil)}
	aliases := []RoutingMapAlias{
		{Alias: "a-missing", TargetModel: "ghost"},
		{Alias: "a-disabled", TargetModel: "off"},
		{Alias: "a-ok", TargetModel: "live"},
	}
	disabled := model("off", false, nil)
	ws := computeRoutingWarnings(append(models, disabled), aliases, nil)
	codes := warningCodes(ws)
	if codes[WarnAliasTargetMissing] != 1 || codes[WarnAliasTargetDisabled] != 1 {
		t.Fatalf("alias warnings = %+v", ws)
	}
	for _, w := range ws {
		if w.Scope != "alias" {
			t.Errorf("scope = %q, want alias", w.Scope)
		}
	}
}

func TestComputeRoutingWarnings_RuleTargets(t *testing.T) {
	models := []RoutingMapModel{model("live", true, nil), model("off", false, nil)}
	rules := []RoutingMapRule{
		{ID: "r1", TargetModel: "ghost", Enabled: true},
		{ID: "r2", TargetModel: "off", Enabled: true},
		{ID: "r3", TargetModel: "live", Enabled: true},
		// A disabled rule is inert — its target must NOT warn.
		{ID: "r4", TargetModel: "ghost", Enabled: false},
	}
	ws := computeRoutingWarnings(models, nil, rules)
	codes := warningCodes(ws)
	if codes[WarnRuleTargetMissing] != 1 || codes[WarnRuleTargetDisabled] != 1 {
		t.Fatalf("rule warnings = %+v", ws)
	}
	for _, w := range ws {
		if w.Scope != "rule" {
			t.Errorf("scope = %q, want rule", w.Scope)
		}
	}
}

func TestComputeRoutingWarnings_CleanMapHasNoWarnings(t *testing.T) {
	models := []RoutingMapModel{model("m1", true, nil, "m2"), model("m2", true, nil)}
	ws := computeRoutingWarnings(models, []RoutingMapAlias{{Alias: "a", TargetModel: "m1"}}, []RoutingMapRule{{ID: "r", TargetModel: "m2", Enabled: true}})
	if len(ws) != 0 {
		t.Fatalf("clean map produced warnings: %+v", ws)
	}
}

func TestGetRoutingMap_NilDBErrors(t *testing.T) {
	s := newForTest(nil, slog.Default(), nil)
	if _, err := s.GetRoutingMap(context.Background(), "org-1"); err == nil {
		t.Fatal("nil db must error")
	}
}

func TestGroupProviderHealth_GroupsAndSorts(t *testing.T) {
	ts := timeNowPtr()
	rows := []ProviderHealthModelRow{
		{Provider: "b-provider", Model: "b1", Requests: 10, Errors: 1, P50Ms: 100, P95Ms: 200, LastError: "boom", LastErrorA: ts},
		{Provider: "a-provider", Model: "a1", Requests: 30, Errors: 3},
		{Provider: "", Model: "mystery", Requests: 5, Errors: 0},
		{Provider: "a-provider", Model: "a2", Requests: 20, Errors: 0},
	}
	got := groupProviderHealth(rows)
	if len(got) != 3 {
		t.Fatalf("providers = %d, want 3: %+v", len(got), got)
	}
	// Sorted by request volume desc: a-provider (50), b-provider (10), unknown (5).
	if got[0].Provider != "a-provider" || got[1].Provider != "b-provider" || got[2].Provider != "unknown" {
		t.Fatalf("provider order = %s,%s,%s", got[0].Provider, got[1].Provider, got[2].Provider)
	}
	if got[0].Requests != 50 || got[0].Errors != 3 {
		t.Errorf("a-provider aggregate = %d/%d, want 50 req / 3 err", got[0].Requests, got[0].Errors)
	}
	if got[0].ErrorRate != 0.06 {
		t.Errorf("a-provider error rate = %v, want 0.06", got[0].ErrorRate)
	}
	if len(got[0].Models) != 2 || got[0].Models[0].Model != "a1" || got[0].Models[0].ErrorRate != 0.1 {
		t.Errorf("a-provider models = %+v", got[0].Models)
	}
	if got[2].Models[0].Model != "mystery" {
		t.Errorf("unregistered model must land under unknown: %+v", got[2])
	}
}

func TestGroupProviderHealth_EmptyIsHonestEmpty(t *testing.T) {
	got := groupProviderHealth(nil)
	if got == nil || len(got) != 0 {
		t.Fatalf("grouping no rows = %#v, want empty non-nil slice", got)
	}
}
