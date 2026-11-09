package classifier

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestABAssigner_Deterministic(t *testing.T) {
	ab := NewABAssigner(3600)
	v1 := ab.Assign("org-1", "classifier-ab", 50)
	v2 := ab.Assign("org-1", "classifier-ab", 50)
	assert.Equal(t, v1, v2, "same org should get same variant")
}

func TestABAssigner_ControlWhenZeroTraffic(t *testing.T) {
	ab := NewABAssigner(3600)
	variant := ab.Assign("org-any", "classifier-ab", 0)
	assert.Equal(t, "control", variant)
}

func TestABAssigner_Distribution(t *testing.T) {
	ab := NewABAssigner(3600)

	const trials = 10000
	const trafficPct = 50

	treatmentCount := 0
	for i := 0; i < trials; i++ {
		orgID := fmt.Sprintf("org-%d", i)
		if ab.Assign(orgID, "test-exp", trafficPct) == "treatment" {
			treatmentCount++
		}
	}

	pct := float64(treatmentCount) / float64(trials) * 100
	assert.InDelta(t, float64(trafficPct), pct, 12.0, "distribution should be ~50%% treatment")
}

func TestABAssigner_StickyCache(t *testing.T) {
	ab := NewABAssigner(3600)

	// First call populates cache
	v1 := ab.GetVariant("org-cache-test", "exp", 50)
	// Second call should return same (sticky)
	v2 := ab.GetVariant("org-cache-test", "exp", 50)
	assert.Equal(t, v1, v2)
}
