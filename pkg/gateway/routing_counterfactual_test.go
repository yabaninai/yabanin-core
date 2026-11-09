package cli

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/stretchr/testify/assert"
)

// Regression companion to the routing-savings gap: tier-routed requests
// baselined at the model actually used, so the routing savings percentage
// could only ever read 0%. The baseline for routed requests is the model the
// client originally requested ("what routing changed"); everything else
// baselines at actual spend.

func TestEffectiveCounterfactual_UntieredUsesActual(t *testing.T) {
	gw := &gateway{}
	u := provider.Usage{PromptTokens: 1000}

	got := gw.effectiveCounterfactual(context.Background(), "", "", "", u, 0.5)
	assert.InDelta(t, 0.5, got, 1e-12, "untiered requests baseline at actual spend")

	got = gw.effectiveCounterfactual(context.Background(), "glm-5.3-flash", "", "easy", u, 0.5)
	assert.InDelta(t, 0.5, got, 1e-12, "routing fields incomplete → actual baseline")

	got = gw.effectiveCounterfactual(context.Background(), "glm-5.3-flash", "glm-5.3", "medium", u, 0.5)
	assert.InDelta(t, 0.0, got, 1e-12,
		"routed request baselines at the requested model; unpriced model → honest 0, never actual")
}

func TestRoutingCounterfactualCost_UnknownBaselineModel(t *testing.T) {
	gw := &gateway{}

	_, ok := gw.routingCounterfactualCost(context.Background(), "", provider.Usage{PromptTokens: 10})
	assert.False(t, ok, "empty baseline model must report unknown")
}
