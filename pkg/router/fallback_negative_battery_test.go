package router_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/router"
)

// firstByteTimeout is a net.Error-shaped first-byte read deadline: the
// request bytes were written, the upstream stayed silent until the read
// deadline expired. Nothing about that silence proves the request did not
// execute.
type firstByteTimeout struct{}

func (firstByteTimeout) Error() string   { return "first byte deadline exceeded" }
func (firstByteTimeout) Timeout() bool   { return true }
func (firstByteTimeout) Temporary() bool { return true }

// Compile-time check: the stand-in carries the shape real transport
// timeouts have.
var _ net.Error = firstByteTimeout{}

// countingProof is an allowing dedup contract that records every
// consultation, so the battery can pin how often the executor asks for
// permission: exactly once per silent attempt, never for definitive
// answers, never when the evidence arm alone already permits.
type countingProof struct{ consults int }

func (p *countingProof) AllowsRetry() bool { p.consults++; return true }

// silentAttemptErrors lists the transport evidence shapes that cannot prove
// non-execution: before falling silent, the provider may have executed the
// request, billed it and performed external side effects.
var silentAttemptErrors = []struct {
	name string
	err  error
}{
	{name: "timeout after delivery", err: errors.New("upstream request timeout")},
	{name: "context deadline", err: context.DeadlineExceeded},
	{name: "client disconnect", err: context.Canceled},
	{name: "write failure after send", err: &net.OpError{Op: "write", Err: errors.New("broken pipe")}},
	{name: "read failure after headers", err: &net.OpError{Op: "read", Err: errors.New("connection reset by peer")}},
	{name: "client timeout wrapping a first-byte deadline", err: &url.Error{Op: "Post", Err: firstByteTimeout{}}},
	{name: "bare first-byte read deadline", err: firstByteTimeout{}},
	{name: "unclassified mid-flight reset", err: errors.New("connection reset after write")},
}

// TestNegative_HiddenChargeNeverProducesSecondCall is the card headline
// battery: the primary provider bills the request or performs an external
// side effect and only then falls silent (every silent evidence shape). The
// fallback chain must end on that attempt — the hidden spend is never
// repeated on a second provider, the trace keeps exactly the one attempt
// with no successful status, and the refusal is the typed unknown-outcome
// explanation attributed to the same request identity.
func TestNegative_HiddenChargeNeverProducesSecondCall(t *testing.T) {
	t.Parallel()

	for _, tt := range silentAttemptErrors {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary", "tertiary"}}
			res := newFakeResolver(map[string]resolver.ModelInfo{
				"secondary": {ModelName: "secondary"},
				"tertiary":  {ModelName: "tertiary"},
			})
			fe := router.NewFallbackExecutor(res, 5, nil)

			identity := retry.RequestIdentity{RequestID: "req-hidden-charge"}
			ctx := retry.WithRequestIdentity(context.Background(), identity)

			var billable, others int
			_, code, attempts, err := fe.Execute(ctx, primary,
				func(_ context.Context, info resolver.ModelInfo) (int, error) {
					if info.ModelName != "primary" {
						others++
						return http.StatusOK, nil
					}
					billable++ // hidden spend: billed and side-effected upstream before the silence
					return 0, tt.err
				})

			assert.Equal(t, 1, billable, "the primary provider is attempted exactly once")
			assert.Zero(t, others, "the hidden spend must never be repeated on another provider")
			require.Len(t, attempts, 1, "the trace keeps exactly the one silent attempt")
			assert.False(t, attempts[0].Success, "no false successful status")
			assert.Equal(t, 0, attempts[0].StatusCode)
			assert.Equal(t, 0, code)
			assert.Equal(t, "unknown", attempts[0].Outcome,
				"silence is recorded as unknown, never as not_executed")
			assert.Equal(t, "req-hidden-charge", attempts[0].RequestID,
				"the charged attempt is attributed to the client request identity")
			assert.Equal(t, 1, attempts[0].Attempt)

			require.Error(t, err)
			var suppressed *retry.SuppressedError
			require.ErrorAs(t, err, &suppressed, "the refusal to repeat is typed and explainable")
			assert.Equal(t, retry.SuppressedUnknownCode, suppressed.Code())
			assert.Equal(t, "primary", suppressed.Model)
			require.ErrorIs(t, err, tt.err, "the original cause stays reachable")
		})
	}
}

// TestNegative_HintCannotRouteAroundUnknownOutcome pins the suppression on
// the hinted path: a provider hint reorders candidates, but when the first
// attempted candidate goes silently unknown, the hint cannot route the
// request around the refusal — the remaining hinted candidates are never
// dialed.
func TestNegative_HintCannotRouteAroundUnknownOutcome(t *testing.T) {
	t.Parallel()

	primary := resolver.ModelInfo{
		ModelName:      "primary",
		Provider:       "prov-a",
		FailoverModels: []string{"secondary", "tertiary"},
	}
	res := newFakeResolver(map[string]resolver.ModelInfo{
		"secondary": {ModelName: "secondary", Provider: "prov-b"},
		"tertiary":  {ModelName: "tertiary", Provider: "prov-b"},
	})
	fe := router.NewFallbackExecutor(res, 5, nil)

	var dialed []string
	_, code, attempts, err := fe.ExecuteWithProviderHint(context.Background(), primary, "prov-b",
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			dialed = append(dialed, info.ModelName)
			if info.ModelName == "secondary" {
				// The hinted candidate bills the work and falls silent.
				return 0, errors.New("upstream request timeout")
			}
			return http.StatusOK, nil
		})

	assert.Equal(t, []string{"secondary"}, dialed,
		"the silent hinted attempt ends the chain; no candidate is dialed after it")
	assert.Equal(t, 0, code, "no false successful status")
	require.Len(t, attempts, 1)
	assert.False(t, attempts[0].Success)
	require.Error(t, err)
	var suppressed *retry.SuppressedError
	require.ErrorAs(t, err, &suppressed)
	assert.Equal(t, retry.SuppressedUnknownCode, suppressed.Code())
	assert.Equal(t, "secondary", suppressed.Model)
}

// TestNegative_NeverSetIdentityInventsNothing pins the never-set side of the
// identity delta: without an attached identity the executor invents none —
// not on the suppressed trace, not across a contract-permitted advance —
// while attempt indexing stays exact (one 1-based position per attempt, no
// double-attribution on one index) and repeated executions never restamp an
// earlier trace.
func TestNegative_NeverSetIdentityInventsNothing(t *testing.T) {
	t.Parallel()

	t.Run("suppressed trace keeps the empty request id", func(t *testing.T) {
		t.Parallel()

		primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
		fe := router.NewFallbackExecutor(newFakeResolver(nil), 5, nil)

		_, _, attempts, err := fe.Execute(context.Background(), primary,
			func(_ context.Context, _ resolver.ModelInfo) (int, error) {
				return 0, errors.New("upstream request timeout")
			})

		require.Error(t, err)
		require.Len(t, attempts, 1)
		assert.Empty(t, attempts[0].RequestID, "no identity is invented for the charged attempt")
		assert.Equal(t, 1, attempts[0].Attempt)
	})

	t.Run("contract-permitted advance stamps no identity on either hop", func(t *testing.T) {
		t.Parallel()

		primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
		fe := router.NewFallbackExecutor(newFakeResolver(nil), 5, nil).
			WithIdempotencyProof(&countingProof{})

		_, _, attempts, err := fe.Execute(context.Background(), primary,
			func(_ context.Context, info resolver.ModelInfo) (int, error) {
				if info.ModelName == "primary" {
					return 0, errors.New("upstream request timeout")
				}
				return http.StatusOK, nil
			})

		require.NoError(t, err, "the verified contract permits the advance")
		require.Len(t, attempts, 2)
		assert.Empty(t, attempts[0].RequestID)
		assert.Empty(t, attempts[1].RequestID, "no identity is invented for the repeated operation")
		assert.Equal(t, 1, attempts[0].Attempt)
		assert.Equal(t, 2, attempts[1].Attempt, "each hop keeps its own 1-based position")
	})

	t.Run("sequential executions restart attempt numbering", func(t *testing.T) {
		t.Parallel()

		primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"second"}}
		res := newFakeResolver(map[string]resolver.ModelInfo{"second": {ModelName: "second"}})
		fe := router.NewFallbackExecutor(res, 5, nil)
		ctx := retry.WithRequestIdentity(context.Background(), retry.RequestIdentity{RequestID: "req-sequential"})

		attemptFn := func(_ context.Context, info resolver.ModelInfo) (int, error) {
			if info.ModelName == "primary" {
				return http.StatusServiceUnavailable, errors.New("upstream error 503")
			}
			return http.StatusOK, nil
		}

		_, _, first, err := fe.Execute(ctx, primary, attemptFn)
		require.NoError(t, err)
		firstSnapshot := append([]router.AttemptOutcome(nil), first...)

		_, _, second, err := fe.Execute(ctx, primary, attemptFn)
		require.NoError(t, err)

		require.Len(t, first, 2)
		require.Len(t, second, 2)
		for i, outcome := range firstSnapshot {
			assert.Equal(t, outcome, first[i], "the first trace is never restamped by the second execution")
		}
		for _, trace := range [][]router.AttemptOutcome{first, second} {
			assert.Equal(t, "req-sequential", trace[0].RequestID)
			assert.Equal(t, 1, trace[0].Attempt, "each execution numbers its own attempts from 1")
			assert.Equal(t, 2, trace[1].Attempt)
		}
	})
}

// TestNegative_AttemptClosureCannotRewriteChainIdentity is the identity-loss
// adversarial: an attempt closure that mints its own identity (attaching a
// forged child context before calling upstream) cannot rewrite the
// executor's stamping and cannot leak the forgery into later attempts — the
// chain hands every attempt the executor's original context, and every trace
// entry carries the one identity read at Execute time.
func TestNegative_AttemptClosureCannotRewriteChainIdentity(t *testing.T) {
	t.Parallel()

	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"second", "third"}}
	res := newFakeResolver(map[string]resolver.ModelInfo{
		"second": {ModelName: "second"},
		"third":  {ModelName: "third"},
	})
	fe := router.NewFallbackExecutor(res, 5, nil)

	original := retry.RequestIdentity{RequestID: "req-original", IdempotencyKey: "idem-original"}
	forged := retry.RequestIdentity{RequestID: "req-forged-per-attempt", IdempotencyKey: "idem-forged"}
	ctx := retry.WithRequestIdentity(context.Background(), original)

	var entry []retry.RequestIdentity
	_, _, attempts, err := fe.Execute(ctx, primary,
		func(attemptCtx context.Context, info resolver.ModelInfo) (int, error) {
			entry = append(entry, retry.RequestIdentityFrom(attemptCtx))
			_ = retry.WithRequestIdentity(attemptCtx, forged) // per-attempt re-mint upstream
			switch info.ModelName {
			case "primary":
				// Proven not-started: advances on its own evidence.
				return 0, &net.OpError{Op: "dial", Err: errors.New("connect: connection refused")}
			case "second":
				// Known-completed failure: advances on the status policy.
				return http.StatusServiceUnavailable, errors.New("upstream error 503")
			default:
				return http.StatusOK, nil
			}
		})

	require.NoError(t, err)
	require.Len(t, attempts, 3)
	assert.Equal(t, []retry.RequestIdentity{original, original, original}, entry,
		"every attempt still receives the executor's original identity — the forgery does not propagate")
	for i, outcome := range attempts {
		assert.Equal(t, "req-original", outcome.RequestID,
			"attempt %d is stamped with the one identity read at Execute time", i+1)
		assert.Equal(t, i+1, outcome.Attempt)
	}
}

// TestNegative_ContractOnlyConsultedForSilentAttempts pins the permission
// discipline around the dedup contract: definitive HTTP answers are governed
// by the status policy and never consult the contract (the 784e885 De Morgan
// boundary — the contract channel cannot attach its permission to executed
// evidence), a silent attempt consults it exactly once, and evidence-proved
// non-execution advances without consulting it at all.
func TestNegative_ContractOnlyConsultedForSilentAttempts(t *testing.T) {
	t.Parallel()

	t.Run("definitive answers never consult the contract", func(t *testing.T) {
		t.Parallel()

		primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
		res := newFakeResolver(map[string]resolver.ModelInfo{"secondary": {ModelName: "secondary"}})
		proof := &countingProof{}
		fe := router.NewFallbackExecutor(res, 5, nil).WithIdempotencyProof(proof)

		var dialed []string
		_, code, attempts, err := fe.Execute(context.Background(), primary,
			func(_ context.Context, info resolver.ModelInfo) (int, error) {
				dialed = append(dialed, info.ModelName)
				if info.ModelName == "primary" {
					return http.StatusServiceUnavailable, errors.New("upstream error 503")
				}
				return http.StatusTooManyRequests, errors.New("upstream error 429")
			})

		assert.Equal(t, []string{"primary", "secondary"}, dialed,
			"definitive answers advance on the ordinary status policy alone")
		assert.Zero(t, proof.consults,
			"the dedup contract is never consulted for executed evidence — no permission is attributed to it")
		require.Error(t, err, "the chain exhausts with the last failure")
		assert.Equal(t, http.StatusTooManyRequests, code)
		var suppressed *retry.SuppressedError
		assert.NotErrorAs(t, err, &suppressed,
			"a definitive-answer chain exhaustion is not a repeat refusal")
		require.Len(t, attempts, 2)
	})

	t.Run("silent attempt consults the contract exactly once", func(t *testing.T) {
		t.Parallel()

		primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
		res := newFakeResolver(map[string]resolver.ModelInfo{"secondary": {ModelName: "secondary"}})
		proof := &countingProof{}
		fe := router.NewFallbackExecutor(res, 5, nil).WithIdempotencyProof(proof)

		_, _, attempts, err := fe.Execute(context.Background(), primary,
			func(_ context.Context, info resolver.ModelInfo) (int, error) {
				if info.ModelName == "primary" {
					return 0, errors.New("upstream request timeout")
				}
				return http.StatusOK, nil
			})

		require.NoError(t, err)
		require.Len(t, attempts, 2)
		assert.Equal(t, 1, proof.consults,
			"the permission decision happens once per silent attempt — no double consultation")
	})

	t.Run("evidence-proved non-execution advances without the contract", func(t *testing.T) {
		t.Parallel()

		primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
		res := newFakeResolver(map[string]resolver.ModelInfo{"secondary": {ModelName: "secondary"}})
		proof := &countingProof{}
		// The classifier declines every failure: only the evidence arm of the
		// permission rule can advance this chain.
		fe := router.NewFallbackExecutor(res, 5, nil).
			WithIdempotencyProof(proof).
			WithClassifier(func(int, error) bool { return false })

		var dialed []string
		_, code, attempts, err := fe.Execute(context.Background(), primary,
			func(_ context.Context, info resolver.ModelInfo) (int, error) {
				dialed = append(dialed, info.ModelName)
				if info.ModelName == "primary" {
					return 0, &net.OpError{Op: "dial", Err: errors.New("connect: connection refused")}
				}
				return http.StatusOK, nil
			})

		require.NoError(t, err)
		assert.Equal(t, []string{"primary", "secondary"}, dialed,
			"proven non-execution advances on its own evidence")
		assert.Equal(t, http.StatusOK, code)
		assert.Zero(t, proof.consults,
			"the contract is not consulted when the evidence arm already permits — no double permission")
		require.Len(t, attempts, 2)
	})
}

// TestNegative_SilentSuppressionAlwaysCarriesTheUnknownCode pins the
// executor side of the refusal-code channel: whatever classifier declines a
// silent attempt, the produced refusal is the conservative unknown-outcome
// code — the executor never claims an executed outcome it did not observe.
// A declined definitive answer stays the raw error and is never wrapped as a
// repeat refusal (status answers keep their envelope).
func TestNegative_SilentSuppressionAlwaysCarriesTheUnknownCode(t *testing.T) {
	t.Parallel()

	classifiers := []struct {
		name       string
		classifier router.StatusClassifier
	}{
		{name: "default classifier", classifier: nil},
		{name: "classifier declining every failure", classifier: func(int, error) bool { return false }},
	}
	for _, tt := range silentAttemptErrors {
		for _, classifier := range classifiers {
			t.Run(tt.name+" / "+classifier.name, func(t *testing.T) {
				t.Parallel()

				primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
				res := newFakeResolver(map[string]resolver.ModelInfo{"secondary": {ModelName: "secondary"}})
				fe := router.NewFallbackExecutor(res, 5, nil)
				if classifier.classifier != nil {
					fe = fe.WithClassifier(classifier.classifier)
				}

				var secondaryCalled int
				_, _, attempts, err := fe.Execute(context.Background(), primary,
					func(_ context.Context, info resolver.ModelInfo) (int, error) {
						if info.ModelName != "primary" {
							secondaryCalled++
							return http.StatusOK, nil
						}
						return 0, tt.err
					})

				assert.Zero(t, secondaryCalled, "the silent attempt is terminal under every classifier")
				require.Len(t, attempts, 1)
				require.Error(t, err)
				var suppressed *retry.SuppressedError
				require.ErrorAs(t, err, &suppressed)
				assert.Equal(t, retry.SuppressedUnknownCode, suppressed.Code(),
					"the executor never claims an executed outcome it did not observe")
				assert.Equal(t, retry.OutcomeUnknown, suppressed.Outcome)
			})
		}
	}

	t.Run("declined definitive answer is never wrapped", func(t *testing.T) {
		t.Parallel()

		primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
		res := newFakeResolver(map[string]resolver.ModelInfo{"secondary": {ModelName: "secondary"}})
		fe := router.NewFallbackExecutor(res, 5, nil).
			WithClassifier(func(int, error) bool { return false })

		cause := errors.New("upstream error 503: overloaded")
		var secondaryCalled int
		_, code, attempts, err := fe.Execute(context.Background(), primary,
			func(_ context.Context, info resolver.ModelInfo) (int, error) {
				if info.ModelName != "primary" {
					secondaryCalled++
					return http.StatusOK, nil
				}
				return http.StatusServiceUnavailable, cause
			})

		assert.Zero(t, secondaryCalled, "the declined definitive answer is terminal on policy alone")
		assert.Equal(t, http.StatusServiceUnavailable, code)
		require.Len(t, attempts, 1)
		require.ErrorIs(t, err, cause, "the raw status answer surfaces unchanged")
		var suppressed *retry.SuppressedError
		assert.NotErrorAs(t, err, &suppressed,
			"a definitive answer is never reframed as a repeat refusal")
	})
}

// TestNegative_ConcurrentSuppressedChainsDoNotCrossAttribute extends the
// race coverage to the refusal path: many concurrent requests end on the
// typed suppression through one shared executor, and every refusal stays
// attributed to its own request — own identity, own cause, own single
// attempt, no second provider call, no false success. Run under -race.
func TestNegative_ConcurrentSuppressedChainsDoNotCrossAttribute(t *testing.T) {
	t.Parallel()

	fe := router.NewFallbackExecutor(newFakeResolver(nil), 5, nil)

	const requests = 16
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()

			wantID := fmt.Sprintf("req-neg-concurrent-%d", n)
			cause := fmt.Errorf("upstream request timeout %d", n)
			ctx := retry.WithRequestIdentity(context.Background(), retry.RequestIdentity{RequestID: wantID})
			_, code, attempts, err := fe.Execute(ctx,
				resolver.ModelInfo{ModelName: fmt.Sprintf("m-%d", n), FailoverModels: []string{"backup"}},
				func(_ context.Context, info resolver.ModelInfo) (int, error) {
					if info.ModelName == "backup" {
						return http.StatusOK, nil
					}
					return 0, cause
				})

			switch {
			case err == nil:
				t.Errorf("request %d: a silent attempt must not end in success", n)
			case code != 0:
				t.Errorf("request %d: suppression must not carry a successful status, got %d", n, code)
			case len(attempts) != 1:
				t.Errorf("request %d: the suppressed trace keeps exactly one attempt, got %d", n, len(attempts))
			case attempts[0].RequestID != wantID:
				t.Errorf("request %d: identity crossed suppressed chains: %q", n, attempts[0].RequestID)
			case attempts[0].Success:
				t.Errorf("request %d: suppressed attempt recorded as success", n)
			default:
				var suppressed *retry.SuppressedError
				if !errors.As(err, &suppressed) || suppressed.Code() != retry.SuppressedUnknownCode {
					t.Errorf("request %d: refusal is not the typed unknown-outcome explanation: %v", n, err)
				} else if !errors.Is(err, cause) {
					t.Errorf("request %d: the own cause is not reachable: %v", n, err)
				}
			}
		}(i)
	}
	wg.Wait()
}
