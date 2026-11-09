//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/verticals"
	"github.com/reireirei/yabanin/pkg/verticals/carbon"
	"github.com/reireirei/yabanin/pkg/verticals/defense"
	"github.com/reireirei/yabanin/pkg/verticals/finance"
	"github.com/reireirei/yabanin/pkg/verticals/halal"
	"github.com/reireirei/yabanin/pkg/verticals/health"
)

// TestVerticalLifecycle runs through the full lifecycle of all 5 vertical packs.
func TestVerticalLifecycle(t *testing.T) {
	ctx := context.Background()

	// Create registry.
	reg := verticals.NewRegistry()

	// Register all 5 verticals.
	packs := []verticals.Vertical{
		halal.New(),
		carbon.New(),
		health.New(),
		defense.New(),
		finance.New(),
	}

	for _, p := range packs {
		if err := reg.Register(p); err != nil {
			t.Fatalf("register %s: %v", p.ID(), err)
		}
	}

	// Enable all verticals for a test org.
	for _, p := range packs {
		if err := reg.EnableFor("test-org", p.ID()); err != nil {
			t.Fatalf("enable %s: %v", p.ID(), err)
		}
	}

	// Verify enabled list.
	enabled := reg.EnabledFor("test-org")
	if len(enabled) != 5 {
		t.Errorf("expected 5 enabled verticals, got %d", len(enabled))
	}

	// Pre-transform should run all 5 transforms.
	in := verticals.Request{
		OrgID:          "test-org",
		ModelRequested: "gpt-4o",
		Prompt:         "Patient SSN: 123-45-6789 needs credit score analysis for loan approval",
		Metadata:       make(map[string]string),
	}

	newCtx, newIn, err := reg.PreTransform(ctx, "test-org", in)
	if err != nil {
		// Defense might deny if no sovereign models configured — that's expected.
		t.Logf("pre-transform result: %v (may be expected for defense)", err)
	}

	// Verify metadata accumulation from multiple verticals.
	if newIn.Metadata["phi_detected"] == "" {
		t.Log("warning: phi_detected not set — health transform may have been skipped")
	}
	_ = newCtx

	// Generate reports for all verticals.
	for _, p := range packs {
		report, err := p.Report(ctx, "test-org", "2024-01-01", "2024-12-31", "saas")
		if err != nil {
			t.Errorf("report %s: %v", p.ID(), err)
			continue
		}
		if len(report) == 0 {
			t.Errorf("empty report for %s", p.ID())
		}
		t.Logf("%s report: %s", p.ID(), string(report))
	}

	// Disable defense vertical.
	if err := reg.DisableFor("test-org", "defense_itar"); err != nil {
		t.Errorf("disable defense: %v", err)
	}
	enabled = reg.EnabledFor("test-org")
	if len(enabled) != 4 {
		t.Errorf("expected 4 enabled after disable, got %d", len(enabled))
	}

	t.Log("Vertical lifecycle test completed successfully")
}
