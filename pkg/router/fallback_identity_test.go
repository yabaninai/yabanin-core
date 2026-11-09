package router_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/router"
)

// TestFallback_RequestIdentityPreservedAcrossAttempts pins the card behaviour:
// one client request keeps one identity across every hop of the fallback
// chain. The executor never mints or rewrites identity — every attempt trace
// entry carries the same request id from the request context, and the attempt
// closure observes the same identity on every hop, so provider deduplication
// contracts and per-attempt usage records join on one key.
func TestFallback_RequestIdentityPreservedAcrossAttempts(t *testing.T) {
	t.Parallel()

	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"second", "third"}}
	res := newFakeResolver(map[string]resolver.ModelInfo{
		"second": {ModelName: "second"},
		"third":  {ModelName: "third"},
	})
	fe := router.NewFallbackExecutor(res, 5, nil)

	identity := retry.RequestIdentity{RequestID: "req-fallback-1", IdempotencyKey: "idem-1"}
	ctx := retry.WithRequestIdentity(context.Background(), identity)

	var closureSaw []retry.RequestIdentity
	_, code, attempts, err := fe.Execute(ctx, primary,
		func(ctx context.Context, info resolver.ModelInfo) (int, error) {
			closureSaw = append(closureSaw, retry.RequestIdentityFrom(ctx))
			if info.ModelName == "primary" {
				// Proven pre-send failure: the chain advances on its own evidence.
				return 0, &net.OpError{Op: "dial", Err: errors.New("connect: connection refused")}
			}
			if info.ModelName == "second" {
				return http.StatusServiceUnavailable, errors.New("upstream error 503")
			}
			return http.StatusOK, nil
		})

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	require.Len(t, attempts, 3)
	assert.Equal(t, []retry.RequestIdentity{identity, identity, identity}, closureSaw,
		"every attempt closure must observe the same request identity")
	for i, outcome := range attempts {
		assert.Equal(t, "req-fallback-1", outcome.RequestID,
			"attempt %d must carry the shared request id", i+1)
		assert.Equal(t, i+1, outcome.Attempt, "attempt index must be the 1-based chain position")
	}
}

// TestFallback_IdentityAbsentKeepsZeroRequestID pins backward compatibility:
// without an identity in the context the trace entries keep an empty request
// id (the executor invents none), while the attempt indexing still applies.
func TestFallback_IdentityAbsentKeepsZeroRequestID(t *testing.T) {
	t.Parallel()

	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"second"}}
	res := newFakeResolver(map[string]resolver.ModelInfo{"second": {ModelName: "second"}})
	fe := router.NewFallbackExecutor(res, 5, nil)

	_, _, attempts, err := fe.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			if info.ModelName == "primary" {
				// Retryable known-completed failure: the chain advances once.
				return http.StatusServiceUnavailable, errors.New("upstream error 503")
			}
			return http.StatusOK, nil
		})

	require.NoError(t, err)
	require.Len(t, attempts, 2)
	assert.Empty(t, attempts[0].RequestID)
	assert.Empty(t, attempts[1].RequestID)
	assert.Equal(t, 1, attempts[0].Attempt)
	assert.Equal(t, 2, attempts[1].Attempt)
}

// TestFallback_RefusedRepeatIsExplained pins the UI/API explanation of the
// no-repeat decision: when the chain ends on an unknown-outcome attempt, the
// returned error is the typed refusal (stable machine-readable code, named
// candidate) while the original cause stays reachable via errors.Is. The
// negative criterion stays pinned: the suppressed attempt produces no second
// provider call.
func TestFallback_RefusedRepeatIsExplained(t *testing.T) {
	t.Parallel()

	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
	res := newFakeResolver(map[string]resolver.ModelInfo{"secondary": {ModelName: "secondary"}})
	fe := router.NewFallbackExecutor(res, 5, nil)

	cause := errors.New("upstream request timeout")
	var secondaryCalled, charged int
	identity := retry.RequestIdentity{RequestID: "req-suppressed"}
	ctx := retry.WithRequestIdentity(context.Background(), identity)

	_, code, attempts, err := fe.Execute(ctx, primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			if info.ModelName == "primary" {
				charged++ // the hidden charge happened before the silence
				return 0, cause
			}
			secondaryCalled++
			return http.StatusOK, nil
		})

	assert.Equal(t, 1, charged, "the primary provider is attempted exactly once")
	assert.Zero(t, secondaryCalled, "a refused repeat must never produce a second provider call")
	assert.Equal(t, 0, code)

	var suppressed *retry.SuppressedError
	require.ErrorAs(t, err, &suppressed, "the refusal must be typed and explainable")
	assert.Equal(t, retry.SuppressedUnknownCode, suppressed.Code())
	assert.Equal(t, "primary", suppressed.Model)
	assert.Equal(t, retry.OutcomeUnknown, suppressed.Outcome)
	require.ErrorIs(t, err, cause, "the original cause must stay reachable")

	require.Len(t, attempts, 1)
	assert.Equal(t, "req-suppressed", attempts[0].RequestID,
		"the suppressed attempt is attributed to the same request identity")
	assert.Equal(t, 1, attempts[0].Attempt)
}

// TestFallback_PolicyDenialIsNeverASuppression pins the envelope boundary: a
// policy denial terminates the chain as a *PolicyError exactly as before —
// the refusal-to-repeat type must not shadow it, because the gateway
// translates PolicyError into the wire envelope.
func TestFallback_PolicyDenialIsNeverASuppression(t *testing.T) {
	t.Parallel()

	primary := resolver.ModelInfo{ModelName: "primary"}
	fe := router.NewFallbackExecutor(newFakeResolver(nil), 5, nil)

	policyErr := &router.PolicyError{Status: http.StatusForbidden, ErrType: "permission_denied_error", Message: "model not allowed"}
	_, status, _, err := fe.Execute(context.Background(), primary,
		func(_ context.Context, _ resolver.ModelInfo) (int, error) {
			return http.StatusForbidden, policyErr
		})

	require.ErrorIs(t, err, policyErr)
	assert.Equal(t, http.StatusForbidden, status)
	var suppressed *retry.SuppressedError
	assert.NotErrorAs(t, err, &suppressed, "a policy denial is not a repeat refusal")
}

// TestFallback_DedupAdvanceStampsIdentityOnBothHops pins that the
// contract-permitted advance keeps one identity across both attempts: the
// repeated operation must present the same identity the dedup contract keyed.
func TestFallback_DedupAdvanceStampsIdentityOnBothHops(t *testing.T) {
	t.Parallel()

	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
	res := newFakeResolver(map[string]resolver.ModelInfo{"secondary": {ModelName: "secondary"}})
	fe := router.NewFallbackExecutor(res, 5, nil).WithIdempotencyProof(chainProbeProof{allows: true})

	identity := retry.RequestIdentity{RequestID: "req-dedup", IdempotencyKey: "idem-dedup"}
	ctx := retry.WithRequestIdentity(context.Background(), identity)

	_, _, attempts, err := fe.Execute(ctx, primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			if info.ModelName == "primary" {
				return 0, errors.New("upstream request timeout")
			}
			return http.StatusOK, nil
		})

	require.NoError(t, err, "the verified dedup contract permits the advance")
	require.Len(t, attempts, 2)
	assert.Equal(t, "req-dedup", attempts[0].RequestID)
	assert.Equal(t, "req-dedup", attempts[1].RequestID,
		"the repeated operation carries the identity the contract keyed")
	assert.Equal(t, 1, attempts[0].Attempt)
	assert.Equal(t, 2, attempts[1].Attempt)
}

// TestFallback_ConcurrentRequestsKeepDisjointIdentities pins the race-safety
// of identity stamping: the executor is shared across requests, and identity
// travels in the per-request context, so concurrent executions never observe
// each other's identity. Run under -race.
func TestFallback_ConcurrentRequestsKeepDisjointIdentities(t *testing.T) {
	t.Parallel()

	fe := router.NewFallbackExecutor(newFakeResolver(nil), 5, nil)

	const requests = 16
	var wg sync.WaitGroup
	errs := make(chan error, requests)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()

			want := fmt.Sprintf("req-concurrent-%d", n)
			ctx := retry.WithRequestIdentity(context.Background(), retry.RequestIdentity{RequestID: want})
			_, _, attempts, err := fe.Execute(ctx, resolver.ModelInfo{ModelName: fmt.Sprintf("m-%d", n)},
				func(_ context.Context, _ resolver.ModelInfo) (int, error) {
					return http.StatusOK, nil
				})
			if err != nil {
				errs <- err
				return
			}
			if len(attempts) != 1 || attempts[0].RequestID != want || attempts[0].Attempt != 1 {
				errs <- fmt.Errorf("request %d: identity crossed attempts: %+v", n, attempts[0])
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}
