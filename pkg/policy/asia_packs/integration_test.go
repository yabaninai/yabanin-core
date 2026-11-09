//go:build integration

package asiapacks_test

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/policy"
	asiapacks "github.com/reireirei/yabanin/pkg/policy/asia_packs"
)

// TestIntegration_Residency_AllowDenyMatrix exercises the three packs end-to-end
// through a real Registry (no DB needed for the matrix itself; this gate exists
// to assert the packs compose correctly). Run with: go test -tags=integration ./pkg/policy/asia_packs/
func TestIntegration_Residency_AllowDenyMatrix(t *testing.T) {
	reg := policy.NewRegistry()
	reg.Register(asiapacks.NewSingaporePack())
	reg.Register(asiapacks.NewIndiaPack())
	reg.Register(asiapacks.NewIndonesiaPack())
	reg.Register(asiapacks.NewJapanPack())

	cases := []struct {
		name    string
		region  policy.Region
		model   policy.Region
		family  string
		allowed bool
	}{
		{"SG→SG openai", "SG", "SG", "openai", true},
		{"SG→US openai", "SG", "US", "openai", false},
		{"SG→EU anthropic", "SG", "EU", "anthropic", true},
		{"IN→IN openai", "IN", "IN", "openai", true},
		{"IN→CN blacklist", "IN", "CN", "openai", false},
		{"IN→US denied", "IN", "US", "openai", false},
		{"ID→ID openai", "ID", "ID", "openai", true},
		{"ID→SG openai", "ID", "SG", "openai", true},
		{"ID→US denied", "ID", "US", "openai", false},
		{"JP→JP openai (azure japan-east)", "JP", "JP", "openai", true},
		{"JP→JP sovereign_jp", "JP", "JP", "sovereign_jp", true},
		{"JP→US openai (global endpoint) denied", "JP", "US", "openai", false},
		{"JP→JP cohere family denied", "JP", "JP", "cohere", false},
		{"GLOBAL free-pass", "GLOBAL", "US", "openai", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.region == policy.RegionGlobal {
				e := policy.NewEnforcer(reg,
					func(_ context.Context, _ string) policy.Region { return c.region }, nil, nil)
				d := e.Enforce(context.Background(), "org", "m", c.model, c.family)
				if d.Allowed != c.allowed {
					t.Fatalf("expected allowed=%v, got decision=%+v", c.allowed, d)
				}
				return
			}
			pack := reg.Get(c.region)
			if pack == nil {
				t.Fatalf("no pack for region %s", c.region)
			}
			d := pack.Evaluate(context.Background(), policy.EvalContext{ModelRegion: c.model, UpstreamFamily: c.family}, nil)
			if d.Allowed != c.allowed {
				t.Fatalf("expected allowed=%v, got decision=%+v", c.allowed, d)
			}
		})
	}
}
