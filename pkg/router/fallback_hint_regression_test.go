package router_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/router"
)

// they pin the OBSERVABLE fallback-executor contract the gateway depends on.
// Only boundary cases not covered by fallback_hint_test.go live here.

// The reorder is stable within both groups: with several candidates on the
// hinted provider the hinted candidates keep their relative order and come
// first; the rest keeps its relative order behind them. No candidate is
// added, removed, or re-sorted beyond the single preference pass.
func TestFallbackWithProviderHint_ReorderStableWithinGroups(t *testing.T) {
	primary := resolver.ModelInfo{
		ModelName:      "primary",
		Provider:       "openai",
		FailoverModels: []string{"a1", "b1", "a2"},
	}
	res := newFakeResolver(map[string]resolver.ModelInfo{
		"a1": {ModelName: "a1", Provider: "anthropic"},
		"b1": {ModelName: "b1", Provider: "meta"},
		"a2": {ModelName: "a2", Provider: "anthropic"},
	})
	fe := router.NewFallbackExecutor(res, 4, nil)

	var calls []string
	_, _, attempts, err := fe.ExecuteWithProviderHint(context.Background(), primary, "anthropic", recordProviders(&calls))

	require.Error(t, err) // every candidate failed; only the order is pinned here
	assert.Equal(t, []string{"anthropic", "anthropic", "openai", "meta"},
		calls, "hinted group first with relative order preserved, remainder unchanged")
	require.Len(t, attempts, 4, "the hint must not remove or add candidates")
}

// A hint naming the primary's provider is already satisfied: the chain order
// stays exactly the declaration order (no shuffling of the remaining
// candidates).
func TestFallbackWithProviderHint_HintOnPrimaryKeepsDeclarationOrder(t *testing.T) {
	primary, res := hintChain()
	fe := router.NewFallbackExecutor(res, 3, nil)

	var calls []string
	_, _, _, _ = fe.ExecuteWithProviderHint(context.Background(), primary, "openai", recordProviders(&calls))

	assert.Equal(t, []string{"openai", "anthropic", "meta"}, calls)
}
