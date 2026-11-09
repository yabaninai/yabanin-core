package router_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/router"
)

// hintChain builds a primary ("openai") with two failover candidates: one on
// the hinted provider ("anthropic") and one on another provider ("meta").
func hintChain() (resolver.ModelInfo, *fakeResolver) {
	primary := resolver.ModelInfo{
		ModelName:      "primary",
		Provider:       "openai",
		FailoverModels: []string{"secondary", "tertiary"},
	}
	res := newFakeResolver(map[string]resolver.ModelInfo{
		"secondary": {ModelName: "secondary", Provider: "anthropic"},
		"tertiary":  {ModelName: "tertiary", Provider: "meta"},
	})
	return primary, res
}

// recordProviders returns an AttemptFunc that always fails (500) and records
// the provider order the chain attempted.
func recordProviders(calls *[]string) router.AttemptFunc {
	return func(_ context.Context, info resolver.ModelInfo) (int, error) {
		*calls = append(*calls, info.Provider)
		return 500, assert.AnError
	}
}

// attempted first, relative order otherwise preserved (all candidates still
// run).
func TestFallbackWithProviderHint_ReordersChain(t *testing.T) {
	primary, res := hintChain()
	fe := router.NewFallbackExecutor(res, 3, nil)

	var calls []string
	_, _, attempts, err := fe.ExecuteWithProviderHint(context.Background(), primary, "anthropic", recordProviders(&calls))

	require.Error(t, err) // every candidate failed; only the order matters here
	assert.Equal(t, []string{"anthropic", "openai", "meta"}, calls)
	require.Len(t, attempts, 3)
}

func TestFallbackWithProviderHint_EmptyHintUnchanged(t *testing.T) {
	primary, res := hintChain()
	fe := router.NewFallbackExecutor(res, 3, nil)

	var calls []string
	_, _, _, _ = fe.ExecuteWithProviderHint(context.Background(), primary, "", recordProviders(&calls))

	assert.Equal(t, []string{"openai", "anthropic", "meta"}, calls)
}

// refuses explicitly BEFORE any candidate is attempted — terminal *PolicyError
// with the 400 route_hint_unsatisfiable envelope, empty attempts, no dial.
func TestFallbackWithProviderHint_UnmatchedHintRefusedBeforeAttempts(t *testing.T) {
	primary, res := hintChain()
	fe := router.NewFallbackExecutor(res, 3, nil)

	var calls []string
	final, status, attempts, err := fe.ExecuteWithProviderHint(context.Background(), primary, "vertex", recordProviders(&calls))

	require.Error(t, err)
	var refusal *router.PolicyError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, http.StatusBadRequest, refusal.Status)
	assert.Equal(t, router.HintUnsatisfiableErrType, refusal.ErrType)
	assert.Equal(t, router.HintUnsatisfiableCode, refusal.ErrCode)
	assert.Contains(t, refusal.Message, "vertex", "the unsatisfiable hint is named for diagnosis")
	assert.Zero(t, final, "a refusal resolves no candidate")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Empty(t, attempts, "a refusal must not produce attempt outcomes")
	assert.Empty(t, calls, "a refusal must not dial any provider")
}

// identically instead of partially succeeding on a retry.
func TestFallbackWithProviderHint_UnmatchedHintRefusalDeterministic(t *testing.T) {
	primary, res := hintChain()
	fe := router.NewFallbackExecutor(res, 3, nil)

	run := func() *router.PolicyError {
		var calls []string
		_, _, _, err := fe.ExecuteWithProviderHint(context.Background(), primary, "vertex", recordProviders(&calls))
		require.Error(t, err)
		var refusal *router.PolicyError
		require.ErrorAs(t, err, &refusal)
		assert.Empty(t, calls)
		return refusal
	}

	first := run()
	second := run()
	assert.Equal(t, first.Status, second.Status)
	assert.Equal(t, first.ErrCode, second.ErrCode)
	assert.Equal(t, first.Message, second.Message)
}

// as a policy refusal (per-attempt gate contract parity).
func TestFallbackWithProviderHint_CanceledContextNotMisreportedAsRefusal(t *testing.T) {
	primary, res := hintChain()
	fe := router.NewFallbackExecutor(res, 3, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var calls []string
	_, _, attempts, err := fe.ExecuteWithProviderHint(ctx, primary, "vertex", recordProviders(&calls))

	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
	var refusal *router.PolicyError
	assert.NotErrorAs(t, err, &refusal, "cancellation must not surface as a policy refusal")
	assert.Empty(t, attempts)
	assert.Empty(t, calls)
}

// matching hint is an order preference, not a refusal.
func TestFallbackWithProviderHint_SingleCandidateMatchedRuns(t *testing.T) {
	primary := resolver.ModelInfo{ModelName: "primary", Provider: "openai"}
	res := newFakeResolver(map[string]resolver.ModelInfo{})
	fe := router.NewFallbackExecutor(res, 3, nil)

	var calls []string
	final, code, attempts, err := fe.ExecuteWithProviderHint(context.Background(), primary, "openai",
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			calls = append(calls, info.Provider)
			return 200, nil
		})

	require.NoError(t, err)
	assert.Equal(t, 200, code)
	assert.Equal(t, "primary", final.ModelName)
	assert.Equal(t, []string{"openai"}, calls)
	require.Len(t, attempts, 1)
	assert.True(t, attempts[0].Success)
}

// still falls through to the rest of the chain.
func TestFallbackWithProviderHint_HintedFirstWinsThenFallsThrough(t *testing.T) {
	primary, res := hintChain()
	fe := router.NewFallbackExecutor(res, 3, nil)

	final, code, attempts, err := fe.ExecuteWithProviderHint(context.Background(), primary, "anthropic",
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			if info.Provider == "anthropic" {
				return 500, assert.AnError
			}
			return 200, nil
		})

	require.NoError(t, err)
	assert.Equal(t, 200, code)
	assert.Equal(t, "primary", final.ModelName)
	require.Len(t, attempts, 2)
	assert.Equal(t, "anthropic", attempts[0].Provider)
	assert.False(t, attempts[0].Success)
	assert.True(t, attempts[1].Success)
}
