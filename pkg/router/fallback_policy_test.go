package router_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/router"
)

// RT-03: a terminal policy outcome (denied candidate / unavailable policy
// check) must end the fallback chain immediately. It is not a transport
// failure the next candidate could satisfy: no retry, no advance.

func TestRT03_PolicyError_StopsChainImmediately(t *testing.T) {
	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary", "tertiary"}}
	res := newFakeResolver(map[string]resolver.ModelInfo{
		"secondary": {ModelName: "secondary"},
		"tertiary":  {ModelName: "tertiary"},
	})
	fe := router.NewFallbackExecutor(res, 5, nil)

	var calls []string
	_, code, attempts, err := fe.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			calls = append(calls, info.ModelName)
			if info.ModelName == "primary" {
				return 503, errors.New("upstream error 503")
			}
			return http.StatusForbidden, &router.PolicyError{
				Status:  http.StatusForbidden,
				ErrType: "permission_denied_error",
				Message: "model not allowed",
			}
		})

	require.Error(t, err)
	var pe *router.PolicyError
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, http.StatusForbidden, pe.Status)
	assert.Equal(t, http.StatusForbidden, code)
	assert.Equal(t, []string{"primary", "secondary"}, calls,
		"tertiary must never be attempted after a policy denial")
	require.Len(t, attempts, 2)
	assert.Equal(t, http.StatusForbidden, attempts[1].StatusCode)
	assert.False(t, attempts[1].Success)
}

func TestRT03_PolicyError_TerminalEvenWithPermissiveClassifier(t *testing.T) {
	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
	res := newFakeResolver(map[string]resolver.ModelInfo{"secondary": {ModelName: "secondary"}})
	fe := router.NewFallbackExecutor(res, 5, nil).
		WithClassifier(func(int, error) bool { return true }) // everything "retryable"

	var calls []string
	_, _, _, err := fe.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			calls = append(calls, info.ModelName)
			return http.StatusForbidden, &router.PolicyError{Status: http.StatusForbidden, Message: "denied"}
		})

	require.Error(t, err)
	assert.Equal(t, []string{"primary"}, calls,
		"a policy outcome is terminal regardless of the retryable classifier")
}

func TestRT03_DefaultRetryable_PolicyErrorNeverRetryable(t *testing.T) {
	assert.False(t, router.DefaultRetryable(0, &router.PolicyError{Status: http.StatusServiceUnavailable, Message: "store down"}),
		"policy-store outage must not be routed around via the next candidate")
	assert.False(t, router.DefaultRetryable(http.StatusForbidden, &router.PolicyError{Status: http.StatusForbidden, Message: "denied"}))
	assert.True(t, router.DefaultRetryable(503, errors.New("upstream error 503")),
		"transport failures stay retryable")
	assert.True(t, router.DefaultRetryable(0, &net.OpError{Op: "dial", Err: errors.New("connect: connection refused")}),
		"a proven pre-send failure keeps the chain advanceable")
	assert.False(t, router.DefaultRetryable(0, errors.New("upstream request timeout")),
		"an unknown upstream outcome must not advance the chain: the request may have executed")
	assert.False(t, router.DefaultRetryable(0, errors.New("connection refused")),
		"an error without non-execution proof is unknown, even when its text mentions a refusal")
}

func TestRT03_ChainCycle_DeduplicatedAndBounded(t *testing.T) {
	// m0 → m1 → m0 → m1: a cycle must not burn hops on already-failed
	// candidates. maxHops stays the hard bound.
	primary := resolver.ModelInfo{ModelName: "m0", FailoverModels: []string{"m1", "m0", "m1"}}
	res := newFakeResolver(map[string]resolver.ModelInfo{"m1": {ModelName: "m1"}})
	fe := router.NewFallbackExecutor(res, 5, nil)

	var calls []string
	_, _, attempts, _ := fe.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			calls = append(calls, info.ModelName)
			return 503, errors.New("upstream error 503")
		})

	assert.Equal(t, []string{"m0", "m1"}, calls, "a repeated candidate is skipped")
	require.Len(t, attempts, 2)
}

func TestRT03_UnknownFailoverEntry_KeptInChainForCallerGate(t *testing.T) {
	// Unknown failover names are not silently dropped by the executor: the
	// resolved candidate (name-only without a resolver) stays in the chain so
	// the caller's per-attempt gate can evaluate it.
	primary := resolver.ModelInfo{ModelName: "m0", FailoverModels: []string{"ghost-x"}}
	fe := router.NewFallbackExecutor(newFakeResolver(nil), 3, nil)

	var calls []string
	_, _, attempts, _ := fe.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			calls = append(calls, info.ModelName)
			return 503, errors.New("upstream error 503")
		})

	assert.Equal(t, []string{"m0", "ghost-x"}, calls)
	require.Len(t, attempts, 2)
}

func TestRT03_UnknownEntries_ResolvingToSameDefault_Deduplicated(t *testing.T) {
	// Two unknown names that both resolve to the shared default model must
	// not call that default twice — the second hop would repeat the first
	// candidate's failure (and, with gating, re-evaluate the same decision).
	primary := resolver.ModelInfo{ModelName: "m0", FailoverModels: []string{"ghost-a", "ghost-b"}}
	res := newFakeResolver(map[string]resolver.ModelInfo{
		"ghost-a": {ModelName: "fb-model", Fallback: true},
		"ghost-b": {ModelName: "fb-model", Fallback: true},
	})
	fe := router.NewFallbackExecutor(res, 5, nil)

	var calls []string
	_, _, _, _ = fe.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			calls = append(calls, info.ModelName)
			return 503, errors.New("upstream error 503")
		})

	assert.Equal(t, []string{"m0", "fb-model"}, calls)
}
