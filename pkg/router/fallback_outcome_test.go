package router_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/router"
)

// TestOutcome_UnknownResultDoesNotRepeatProviderCall is the hidden-charge
// negative: a provider may execute the request, charge for it or perform an
// external side effect and only then fall silent (timeout, disconnect,
// broken connection). Advancing the fallback chain in that state calls a
// second provider for work that may already have happened. Every unknown
// shape must therefore end the chain on the first attempt.
func TestOutcome_UnknownResultDoesNotRepeatProviderCall(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		code       int
		attemptErr error
	}{
		{name: "timeout after delivery", code: 0, attemptErr: errors.New("upstream request timeout")},
		{name: "context deadline", code: 0, attemptErr: context.DeadlineExceeded},
		{name: "client disconnect", code: 0, attemptErr: context.Canceled},
		{name: "write failure after send", code: 0, attemptErr: &net.OpError{Op: "write", Err: errors.New("broken pipe")}},
		{name: "read failure after headers", code: 0, attemptErr: &net.OpError{Op: "read", Err: errors.New("connection reset by peer")}},
		{name: "unclassified plain error", code: 0, attemptErr: errors.New("connection reset after write")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
			res := newFakeResolver(map[string]resolver.ModelInfo{"secondary": {ModelName: "secondary"}})
			fe := router.NewFallbackExecutor(res, 5, nil)

			var charged, secondaryCalled int
			_, code, attempts, err := fe.Execute(context.Background(), primary,
				func(_ context.Context, info resolver.ModelInfo) (int, error) {
					if info.ModelName == "primary" {
						charged++ // side effect happened upstream before the silence
						return tt.code, tt.attemptErr
					}
					secondaryCalled++
					return http.StatusOK, nil
				})

			assert.Equal(t, 1, charged, "the primary provider is attempted exactly once")
			assert.Zero(t, secondaryCalled, "an unknown upstream outcome must never produce a second provider call")
			require.Error(t, err)
			// The refusal to repeat an unknown outcome is typed and
			// explainable (N09-P01-T04); the original cause stays reachable
			// through errors.Is.
			require.ErrorIs(t, err, tt.attemptErr, "the original unknown-outcome error must stay reachable")
			var suppressed *retry.SuppressedError
			require.ErrorAs(t, err, &suppressed)
			assert.Equal(t, retry.SuppressedUnknownCode, suppressed.Code())
			assert.Equal(t, tt.code, code)
			require.Len(t, attempts, 1)
			assert.Equal(t, "unknown", attempts[0].Outcome)
			assert.False(t, attempts[0].Success)
		})
	}
}

// TestOutcome_ProvenNotStartedStillAdvancesChain pins the opposite boundary:
// a dial failure proves the request never reached the first provider, so the
// chain still advances to the next candidate and the attempt is recorded as
// known-not-started.
func TestOutcome_ProvenNotStartedStillAdvancesChain(t *testing.T) {
	t.Parallel()

	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
	res := newFakeResolver(map[string]resolver.ModelInfo{"secondary": {ModelName: "secondary"}})
	fe := router.NewFallbackExecutor(res, 5, nil)

	var calls []string
	_, code, attempts, err := fe.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			calls = append(calls, info.ModelName)
			if info.ModelName == "primary" {
				return 0, &net.OpError{Op: "dial", Err: errors.New("connect: connection refused")}
			}
			return http.StatusOK, nil
		})

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, []string{"primary", "secondary"}, calls, "proven pre-send failure must keep the chain working")
	require.Len(t, attempts, 2)
	assert.Equal(t, "not_executed", attempts[0].Outcome)
	assert.Equal(t, "executed", attempts[1].Outcome)
}

// TestOutcome_HTTPAnswerAdvancesChain pins the known-completed boundary: an
// upstream that answered with an HTTP status finished the exchange, so the
// ordinary status-based fallback policy decides what happens next (503
// advances) and the attempt is recorded as known-completed, never unknown.
func TestOutcome_HTTPAnswerAdvancesChain(t *testing.T) {
	t.Parallel()

	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
	res := newFakeResolver(map[string]resolver.ModelInfo{"secondary": {ModelName: "secondary"}})
	fe := router.NewFallbackExecutor(res, 5, nil)

	var calls []string
	_, code, attempts, _ := fe.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			calls = append(calls, info.ModelName)
			if info.ModelName == "primary" {
				return http.StatusServiceUnavailable, errors.New("upstream error 503: overloaded")
			}
			return http.StatusOK, nil
		})

	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, []string{"primary", "secondary"}, calls)
	require.Len(t, attempts, 2)
	assert.Equal(t, "executed", attempts[0].Outcome, "an HTTP answer is a known-completed outcome")
}

// TestOutcome_PolicyOutcomeRemainsTerminalWithClassification pins that the
// policy-error terminality is untouched by the outcome classification and
// that a refused attempt is still recorded as known-completed (the upstream
// answered).
func TestOutcome_PolicyOutcomeRemainsTerminalWithClassification(t *testing.T) {
	t.Parallel()

	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary", "tertiary"}}
	res := newFakeResolver(map[string]resolver.ModelInfo{
		"secondary": {ModelName: "secondary"},
		"tertiary":  {ModelName: "tertiary"},
	})
	fe := router.NewFallbackExecutor(res, 5, nil)

	var calls []string
	_, _, attempts, err := fe.Execute(context.Background(), primary,
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
	assert.Equal(t, []string{"primary", "secondary"}, calls, "tertiary must never be attempted after a policy denial")
	require.Len(t, attempts, 2)
	assert.Equal(t, "executed", attempts[1].Outcome)
}

// TestOutcome_ClassifierOverrideOwnsUnknownRepetition documents the default
// boundary: DefaultRetryable stops the chain on unknown outcomes, while an
// explicit WithClassifier override takes that responsibility (and its
// duplicate-call risk) on deliberately.
func TestOutcome_ClassifierOverrideOwnsUnknownRepetition(t *testing.T) {
	t.Parallel()

	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
	res := newFakeResolver(map[string]resolver.ModelInfo{"secondary": {ModelName: "secondary"}})
	fe := router.NewFallbackExecutor(res, 5, nil).
		WithClassifier(func(int, error) bool { return true })

	var calls []string
	_, code, attempts, _ := fe.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			calls = append(calls, info.ModelName)
			if info.ModelName == "primary" {
				return 0, errors.New("upstream request timeout")
			}
			return http.StatusOK, nil
		})

	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, []string{"primary", "secondary"}, calls,
		"an explicit classifier override replaces the default unknown-outcome terminality")
	require.Len(t, attempts, 2)
	assert.Equal(t, "unknown", attempts[0].Outcome,
		"the classification is recorded even when decisions are overridden")
}

// chainProbeProof is a test stand-in for a verified provider/action
// deduplication contract attached to the fallback executor.
type chainProbeProof struct{ allows bool }

func (p chainProbeProof) AllowsRetry() bool { return p.allows }

// TestOutcome_DedupContractGatesSilentAdvance pins the repetition permission
// at the chain level: a verified deduplication contract may advance the chain
// past an attempt that produced no HTTP answer, a declining contract may not,
// proven non-execution advances on its own evidence, and policy denials are
// never overridden. The contract is only consulted for attempts that produced
// no HTTP answer — definitive answers stay governed by the status policy.
func TestOutcome_DedupContractGatesSilentAdvance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		proof           chainProbeProof
		attachProof     bool
		code            int
		attemptErr      error
		wantAttempts    int
		wantSecondaryOK bool
		wantOutcome     string
		// wantSuppressed marks the terminal cases that must surface the typed
		// repeat-refusal explanation (unknown outcome, permission denied by
		// the MayRepeat rule). Policy denials surface the raw PolicyError.
		wantSuppressed bool
	}{
		{
			name:        "silent attempt without contract stays terminal",
			attachProof: false,
			code:        0, attemptErr: errors.New("upstream request timeout"),
			wantAttempts: 1, wantOutcome: "unknown", wantSuppressed: true,
		},
		{
			name:        "silent attempt with declining contract stays terminal",
			attachProof: true, proof: chainProbeProof{allows: false},
			code: 0, attemptErr: errors.New("upstream request timeout"),
			wantAttempts: 1, wantOutcome: "unknown", wantSuppressed: true,
		},
		{
			name:        "silent attempt with verified contract advances",
			attachProof: true, proof: chainProbeProof{allows: true},
			code: 0, attemptErr: errors.New("upstream request timeout"),
			wantAttempts: 2, wantSecondaryOK: true, wantOutcome: "unknown",
		},
		{
			name:        "proven not-started advances even with a declining contract",
			attachProof: true, proof: chainProbeProof{allows: false},
			code: 0, attemptErr: &net.OpError{Op: "dial", Err: errors.New("connect: connection refused")},
			wantAttempts: 2, wantSecondaryOK: true, wantOutcome: "not_executed",
		},
		{
			name:        "policy denial is never overridden by the contract",
			attachProof: true, proof: chainProbeProof{allows: true},
			code:         http.StatusForbidden,
			attemptErr:   &router.PolicyError{Status: http.StatusForbidden, ErrType: "permission_denied_error", Message: "model not allowed"},
			wantAttempts: 1, wantOutcome: "executed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
			res := newFakeResolver(map[string]resolver.ModelInfo{"secondary": {ModelName: "secondary"}})
			fe := router.NewFallbackExecutor(res, 5, nil)
			if tt.attachProof {
				fe = fe.WithIdempotencyProof(tt.proof)
			}

			var secondaryCalled int
			_, code, attempts, err := fe.Execute(context.Background(), primary,
				func(_ context.Context, info resolver.ModelInfo) (int, error) {
					if info.ModelName == "primary" {
						return tt.code, tt.attemptErr
					}
					secondaryCalled++
					return http.StatusOK, nil
				})

			require.Len(t, attempts, tt.wantAttempts)
			assert.Equal(t, tt.wantOutcome, attempts[0].Outcome,
				"the first attempt's recorded classification must match the evidence")
			if tt.wantSecondaryOK {
				require.NoError(t, err)
				assert.Equal(t, 1, secondaryCalled, "the verified contract permits exactly one advance")
				assert.Equal(t, "executed", attempts[1].Outcome)
				assert.Equal(t, http.StatusOK, code)
			} else {
				assert.Zero(t, secondaryCalled, "without permission the chain must not produce a second provider call")
				require.Error(t, err)
				// The original error stays reachable in every terminal case;
				// unknown-outcome refusals additionally surface the typed,
				// machine-readable repeat-refusal explanation (N09-P01-T04),
				// while policy denials keep the raw PolicyError envelope.
				require.ErrorIs(t, err, tt.attemptErr, "the original error must stay reachable")
				var suppressed *retry.SuppressedError
				if tt.wantSuppressed {
					require.ErrorAs(t, err, &suppressed)
					assert.Equal(t, retry.SuppressedUnknownCode, suppressed.Code())
				} else {
					assert.NotErrorAs(t, err, &suppressed)
				}
				assert.Equal(t, tt.code, code)
			}
		})
	}
}

// TestOutcome_TranslateRefusalAdvancesChain (N07-P01-T05): a translate-layer
// refusal is the typed proof the request never left this process — unlike an
// unknown outcome, the chain may advance to a candidate that can actually
// honor the request, and the attempt record must classify it as
// not_executed (proven not started), not "unknown".
func TestOutcome_TranslateRefusalAdvancesChain(t *testing.T) {
	t.Parallel()

	primary := resolver.ModelInfo{ModelName: "bedrock-m", FailoverModels: []string{"openai-m"}}
	res := newFakeResolver(map[string]resolver.ModelInfo{"openai-m": {ModelName: "openai-m"}})
	fe := router.NewFallbackExecutor(res, 5, nil)

	var secondaryCalled int
	_, code, attempts, err := fe.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			if info.ModelName == "bedrock-m" {
				return 0, &retry.RequestNotSentError{Err: fmt.Errorf("translate request: bedrock adapter: reasoning_effort %q is not mapped; rejecting instead of silently dropping (I51)", "high")}
			}
			secondaryCalled++
			return http.StatusOK, nil
		})

	assert.Equal(t, 1, secondaryCalled, "a provably-not-sent refusal must advance the chain to the next candidate")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	require.Len(t, attempts, 2)
	assert.Equal(t, "not_executed", attempts[0].Outcome, "translate refusals are proven not-sent, not unknown")
	assert.False(t, attempts[0].Success)
	assert.True(t, attempts[1].Success)
}

// TestOutcome_TranslateRefusalExhaustionSurfacesTypedReason pins the render
// contract for the other boundary: when every candidate refuses, the
// surfaced error must still unwrap to the typed refusal so the gateway can
// render the exact reason (I51) as a client-side 400 — not a generic
// upstream failure that hides which field was lost.
func TestOutcome_TranslateRefusalExhaustionSurfacesTypedReason(t *testing.T) {
	t.Parallel()

	primary := resolver.ModelInfo{ModelName: "a", FailoverModels: []string{"b"}}
	res := newFakeResolver(map[string]resolver.ModelInfo{"b": {ModelName: "b"}})
	fe := router.NewFallbackExecutor(res, 5, nil)

	_, code, attempts, err := fe.Execute(context.Background(), primary,
		func(_ context.Context, _ resolver.ModelInfo) (int, error) {
			return 0, &retry.RequestNotSentError{Err: fmt.Errorf("translate request: anthropic: reasoning_effort %q is not mapped; rejecting instead of silently dropping (I51)", "high")}
		})

	require.Error(t, err)
	assert.Zero(t, code, "no provider was ever contacted")
	require.Len(t, attempts, 2)
	var ns *retry.RequestNotSentError
	require.ErrorAs(t, err, &ns, "the exhaustion wrap must preserve the typed refusal for the client-facing render")
	assert.Contains(t, err.Error(), "reasoning_effort", "the exact reason must survive the wrap")
	assert.False(t, attempts[0].Success)
}
