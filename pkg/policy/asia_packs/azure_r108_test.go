package asiapacks

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/policy"
)

// 2026-10-16: residency = страна, the existing models_registry.region
// country semantics — no new residency mechanism). The gateway passes the
// registry provider string as the pack family (chat.go enforceChatPolicy),
// so the asia packs' family whitelists must admit "azure-openai" for the
// in-country Azure resources their docstrings already name (jp.go: "an
// Azure OpenAI Japan East resource"). Bedrock/Vertex stay OUT of the
// whitelists until adapters exist — unsupported must not be promised.

// TestAsiaPacks_AzureOpenAI_InCountryAllowed: every shipped pack admits an
// azure-openai model registered with an in-pack-region country.
func TestAsiaPacks_AzureOpenAI_InCountryAllowed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pack   policy.Pack
		region policy.Region
	}{
		{NewJapanPack(), "JP"},
		{NewSingaporePack(), "SG"},
		{NewIndonesiaPack(), "ID"},
		{NewIndiaPack(), "IN"},
	}
	for _, tc := range cases {
		d := tc.pack.Evaluate(context.Background(), policy.EvalContext{
			OrgID:          "org-r108",
			ModelRequested: "azure-jp-gpt4o",
			ModelRegion:    tc.region,
			UpstreamFamily: "azure-openai",
		}, nil)
		if !d.Allowed {
			t.Fatalf("%s: in-region azure-openai model must be allowed, denied: %s (violations=%v)",
				tc.pack.ID(), d.Reason, d.Violations)
		}
	}
}

// TestJapanPack_AzureOpenAI_RegionMismatch_Denied: the negative scenario of
// JP-profile org is denied with the NAMED region, before any family
// consideration.
func TestJapanPack_AzureOpenAI_RegionMismatch_Denied(t *testing.T) {
	t.Parallel()
	d := NewJapanPack().Evaluate(context.Background(), policy.EvalContext{
		OrgID:          "org-jp",
		ModelRequested: "azure-us-gpt4o",
		ModelRegion:    "US",
		UpstreamFamily: "azure-openai",
	}, nil)
	if d.Allowed {
		t.Fatal("US-region azure-openai model must be denied for the JP pack")
	}
	found := false
	for _, v := range d.Violations {
		if v == "jurisdiction:US" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected jurisdiction:US violation, got %v", d.Violations)
	}
}

// TestJapanPack_BedrockVertex_StillNotPromised: providers without adapters
// stubs in migration 0005 must not translate into promised support.
func TestJapanPack_BedrockVertex_StillNotPromised(t *testing.T) {
	t.Parallel()
	for _, family := range []string{"bedrock", "vertex"} {
		d := NewJapanPack().Evaluate(context.Background(), policy.EvalContext{
			OrgID:          "org-jp",
			ModelRequested: "future-model",
			ModelRegion:    "JP",
			UpstreamFamily: family,
		}, nil)
		if d.Allowed {
			t.Fatalf("family %q must not be whitelisted before its adapter ships", family)
		}
	}
}

// TestEnforcer_AzureOpenAI_JPOrg_EndToEnd: the full Enforcer path (registry
// + real Japan pack) for contract example 1: org with a JP profile,
// models_registry row (provider='azure-openai', region='JP') → allowed with
// no remap; the same provider registered region='US' → denied.
func TestEnforcer_AzureOpenAI_JPOrg_EndToEnd(t *testing.T) {
	t.Parallel()
	reg := policy.NewRegistry()
	reg.Register(NewJapanPack())
	e := policy.NewEnforcer(reg, func(_ context.Context, _ string) policy.Region { return "JP" }, nil, nil)

	d := e.Enforce(context.Background(), "org-jp", "azure-jp-gpt4o", "JP", "azure-openai")
	if !d.Allowed {
		t.Fatalf("JP azure-openai model must pass the residency gate, denied: %s (violations=%v)",
			d.Reason, d.Violations)
	}
	if d.RemappedModel != "" {
		t.Fatalf("allowed decision must not remap, got %q", d.RemappedModel)
	}

	deny := e.Enforce(context.Background(), "org-jp", "azure-us-gpt4o", "US", "azure-openai")
	if deny.Allowed {
		t.Fatal("US-region azure-openai model must be denied for a JP org")
	}
}
