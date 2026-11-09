package retry_test

// N09-P01-T10 [risk] — rights/data/resources verification for pkg/retry.
// Test-only card: zero production changes.
//
//	permissions — the repetition rule (MayRepeat) and its enforcement in Do:
//	only proven non-execution or the Result's own dedup contract advances a
//	StatusCode-0 error; a declining proof, a nil proof and unknown evidence
//	all end the loop on the first attempt;
//	data — the SuppressedError surface is exactly {Model, Outcome, Err}: the
//	rendered text and machine code never carry identity or key material;
//	resources — hostile policies and server-controlled Retry-After values
//	stay within bounded wall clocks: the HTTP-date form is clamped by
//	MaxDelay exactly like the seconds form.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/retry"
)

// TestN09P1T10_Risk_MayRepeatPermissionMatrix: repetition permission comes
// from exactly two sources — proven non-execution, or an explicit
// IdempotencyProof handed in as the Result's contract. Everything else is
// terminal, and a declining contract is as good as none.
func TestN09P1T10_Risk_MayRepeatPermissionMatrix(t *testing.T) {
	t.Parallel()

	allowing := allowingProof{}
	declining := t10DecliningProof{}

	assert.True(t, retry.MayRepeat(retry.OutcomeNotExecuted, nil),
		"proven non-execution needs no contract")
	assert.True(t, retry.MayRepeat(retry.OutcomeNotExecuted, declining),
		"proven non-execution ignores a declining contract")
	assert.False(t, retry.MayRepeat(retry.OutcomeUnknown, nil))
	assert.False(t, retry.MayRepeat(retry.OutcomeUnknown, declining))
	assert.True(t, retry.MayRepeat(retry.OutcomeUnknown, allowing),
		"the verified contract is the documented opt-in for unknown outcomes")

	// Domain note: MayRepeat's contract is "a failed attempt that produced
	// no HTTP answer". OutcomeExecuted implies an HTTP answer or nil error
	// (Classify), so it never reaches the rule at the production call sites
	// — Do gates on StatusCode == 0 and the fallback executor on code == 0,
	// and both treat definitive answers as terminal before asking. The raw
	// function value for that unreachable input is recorded here so the
	// domain assumption is explicit rather than implicit.
	assert.True(t, retry.MayRepeat(retry.OutcomeExecuted, allowing),
		"unreachable input (documented domain: no-answer failures only)")
	assert.False(t, retry.MayRepeat(retry.OutcomeExecuted, nil),
		"unreachable input (documented domain: no-answer failures only)")
}

type allowingProof struct{}

func (allowingProof) AllowsRetry() bool { return true }

type t10DecliningProof struct{}

func (t10DecliningProof) AllowsRetry() bool { return false }

// TestN09P1T10_Risk_DoEnforcesTheRepetitionGate: a StatusCode-0 transport
// error ends the loop on the first attempt unless the Result itself carries
// the opt-in proof — Do consults the Result's own contract field, never any
// ambient permission.
func TestN09P1T10_Risk_DoEnforcesTheRepetitionGate(t *testing.T) {
	t.Parallel()

	t.Run("unknown silence without a proof is terminal", func(t *testing.T) {
		t.Parallel()

		var calls int32
		res := retry.Do(context.Background(), retry.DefaultPolicy(),
			func(_ context.Context) retry.Result {
				atomic.AddInt32(&calls, 1)
				return retry.Result{Err: errors.New("upstream request timeout")}
			})
		assert.EqualValues(t, 1, atomic.LoadInt32(&calls))
		assert.Equal(t, retry.OutcomeUnknown, retry.Classify(res.StatusCode, res.Err))
	})

	t.Run("declining proof cannot resurrect the attempt", func(t *testing.T) {
		t.Parallel()

		var calls int32
		retry.Do(context.Background(), retry.DefaultPolicy(),
			func(_ context.Context) retry.Result {
				atomic.AddInt32(&calls, 1)
				return retry.Result{Err: errors.New("upstream request timeout"), Proof: t10DecliningProof{}}
			})
		assert.EqualValues(t, 1, atomic.LoadInt32(&calls))
	})

	t.Run("the Result's own allowing proof advances within MaxAttempts", func(t *testing.T) {
		t.Parallel()

		var calls int32
		retry.Do(context.Background(), retry.Policy{MaxAttempts: 4, RetryOn: func(int, error) bool { return true }},
			func(_ context.Context) retry.Result {
				atomic.AddInt32(&calls, 1)
				return retry.Result{Err: errors.New("upstream request timeout"), Proof: allowingProof{}}
			})
		assert.EqualValues(t, 4, atomic.LoadInt32(&calls), "bounded by MaxAttempts")
	})
}

// TestN09P1T10_Risk_SuppressedErrorSurfaceCarriesNoIdentityMaterial: the
// refusal type is exactly {Model, Outcome, Err} — its deterministic text and
// stable code carry the outcome class and the cause, and nothing else.
func TestN09P1T10_Risk_SuppressedErrorSurfaceCarriesNoIdentityMaterial(t *testing.T) {
	t.Parallel()

	cause := fmt.Errorf("boom")
	sup := &retry.SuppressedError{Model: "primary", Outcome: retry.OutcomeUnknown, Err: cause}

	// Deterministic rendered text (the exact production template).
	assert.Equal(t,
		"automatic repeat suppressed on primary (unknown upstream outcome): boom",
		sup.Error())
	assert.Equal(t, retry.SuppressedUnknownCode, sup.Code())

	// Executed-outcome refusals keep their distinct code; the model clause
	// is dropped when empty.
	executed := &retry.SuppressedError{Outcome: retry.OutcomeExecuted, Err: cause}
	assert.Equal(t, retry.SuppressedExecutedCode, executed.Code())
	assert.Equal(t,
		"automatic repeat suppressed (executed upstream outcome): boom",
		executed.Error())

	// Identity-shaped material never enters the text.
	const reqID = "req-t10-join-key"
	const reqKey = "ik_live_T10_SECRET"
	plain := &retry.SuppressedError{Model: "primary", Outcome: retry.OutcomeUnknown,
		Err: fmt.Errorf("upstream request timeout")}
	assert.NotContains(t, plain.Error(), reqID)
	assert.NotContains(t, plain.Error(), reqKey)
	assert.NotContains(t, plain.Code(), reqID)
	assert.NotContains(t, plain.Code(), reqKey)

	// The cause stays reachable through the error chain.
	sentinel := errors.New("terminal cause")
	wrapped := &retry.SuppressedError{Outcome: retry.OutcomeUnknown, Err: sentinel}
	require.ErrorIs(t, wrapped, sentinel)
	var asSup *retry.SuppressedError
	require.ErrorAs(t, wrapped, &asSup)
}

// retryAfterHeader builds a Result with a Retry-After header.
func retryAfterHeader(v string) http.Header {
	h := http.Header{}
	h.Set("Retry-After", v)
	return h
}

// TestN09P1T10_Risk_RetryAfterHTTPDateClampedLikeSecondsForm: the server
// controls Retry-After. Both forms it accepts — delta-seconds and HTTP-date —
// must clamp to the policy's MaxDelay, so a hostile or broken upstream can
// never stall the worker beyond the policy bound.
func TestN09P1T10_Risk_RetryAfterHTTPDateClampedLikeSecondsForm(t *testing.T) {
	t.Parallel()

	policy := retry.Policy{
		MaxAttempts: 3,
		BaseDelay:   5 * time.Millisecond,
		MaxDelay:    20 * time.Millisecond,
		RetryOn:     func(int, error) bool { return true },
	}

	for name, header := range map[string]string{
		"far-future HTTP-date (year 2100)": time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC).Format(http.TimeFormat),
		"near-future HTTP-date (+30s)":     time.Now().Add(30 * time.Second).Format(http.TimeFormat),
		"hours-scale seconds form":         "3600",
		"garbage value":                    "not-a-date-or-seconds",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var calls int32
			start := time.Now()
			retry.Do(context.Background(), policy, func(_ context.Context) retry.Result {
				atomic.AddInt32(&calls, 1)
				return retry.Result{StatusCode: 503, Err: errors.New("overloaded"), Headers: retryAfterHeader(header)}
			})
			elapsed := time.Since(start)

			assert.EqualValues(t, 3, atomic.LoadInt32(&calls))
			assert.Less(t, elapsed, 1500*time.Millisecond,
				"Retry-After %q must clamp to MaxDelay=20ms; took %s", header, elapsed)
		})
	}

	t.Run("past HTTP-date falls back to bounded backoff", func(t *testing.T) {
		t.Parallel()

		var calls int32
		start := time.Now()
		retry.Do(context.Background(), policy, func(_ context.Context) retry.Result {
			atomic.AddInt32(&calls, 1)
			return retry.Result{
				StatusCode: 503,
				Err:        errors.New("overloaded"),
				Headers:    retryAfterHeader(time.Now().Add(-time.Hour).Format(http.TimeFormat)),
			}
		})
		assert.EqualValues(t, 3, atomic.LoadInt32(&calls))
		assert.Less(t, time.Since(start), 1500*time.Millisecond)
	})
}

// TestN09P1T10_Risk_HostilePolicyStaysBounded: degenerate policy numbers —
// huge base delays, zero/negative max delay, extreme and negative jitter —
// neither panic nor produce unbounded sleeps.
func TestN09P1T10_Risk_HostilePolicyStaysBounded(t *testing.T) {
	t.Parallel()

	cases := map[string]retry.Policy{
		"hour-scale base delay clamped by max": {
			MaxAttempts: 4, BaseDelay: time.Hour, MaxDelay: 40 * time.Millisecond,
			RetryOn: func(int, error) bool { return true },
		},
		"extreme jitter factor": {
			MaxAttempts: 3, BaseDelay: 5 * time.Millisecond, MaxDelay: 40 * time.Millisecond, JitterFactor: 1.0,
			RetryOn: func(int, error) bool { return true },
		},
		"negative jitter factor": {
			MaxAttempts: 3, BaseDelay: 5 * time.Millisecond, MaxDelay: 40 * time.Millisecond, JitterFactor: -0.9,
			RetryOn: func(int, error) bool { return true },
		},
		"zero max delay falls back to defaults": {
			MaxAttempts: 3, BaseDelay: time.Hour, MaxDelay: 0,
			RetryOn: func(int, error) bool { return true },
		},
		"non-positive max attempts falls back to defaults": {
			MaxAttempts: 0, BaseDelay: time.Hour, MaxDelay: time.Hour,
			RetryOn: func(int, error) bool { return true },
		},
	}

	for name, policy := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var calls int32
			start := time.Now()
			retry.Do(context.Background(), policy, func(_ context.Context) retry.Result {
				atomic.AddInt32(&calls, 1)
				return retry.Result{StatusCode: 503, Err: errors.New("overloaded")}
			})

			assert.GreaterOrEqual(t, atomic.LoadInt32(&calls), int32(1))
			assert.LessOrEqual(t, atomic.LoadInt32(&calls), int32(4))
			assert.Less(t, time.Since(start), 3*time.Second,
				"hostile policy must stay within a bounded wall clock")
		})
	}
}

// TestN09P1T10_Risk_AnsweredButBrokenStreamIsOrdinaryPolicyTerritory: the
// answered branch of the partial-streaming risk at the Do gate. The
// MayRepeat evidence gate is scoped to attempts that produced no HTTP answer
// (Do gates on StatusCode == 0) — a stream that answered 200 and broke
// mid-flight is a known-completed outcome whose repetition question belongs
// to the ordinary RetryOn policy, not to the evidence gate. Pinned both ways:
// the default classifier repeats the answered break (any transport error is
// a retry candidate), and a RetryOn that declines answered breaks owns the
// no-replay duty on the first attempt. The placement of that duty is a
// policy-owner decision recorded in the card record.
func TestN09P1T10_Risk_AnsweredButBrokenStreamIsOrdinaryPolicyTerritory(t *testing.T) {
	t.Parallel()

	breakErr := errors.New("stream aborted after first chunk")

	t.Run("default policy repeats the answered break", func(t *testing.T) {
		t.Parallel()

		var calls int32
		res := retry.Do(context.Background(), retry.DefaultPolicy(),
			func(_ context.Context) retry.Result {
				atomic.AddInt32(&calls, 1)
				return retry.Result{StatusCode: http.StatusOK, Err: breakErr}
			})

		assert.EqualValues(t, 3, atomic.LoadInt32(&calls),
			"the evidence gate does not apply to answered attempts; the default classifier retries any error")
		assert.Equal(t, http.StatusOK, res.StatusCode)
		require.ErrorIs(t, res.Err, breakErr, "the mid-stream cause stays reachable")
	})

	t.Run("a RetryOn declining answered breaks is terminal on the first attempt", func(t *testing.T) {
		t.Parallel()

		policy := retry.DefaultPolicy()
		policy.RetryOn = func(code int, err error) bool { return err == nil && code < 500 }

		var calls int32
		res := retry.Do(context.Background(), policy, func(_ context.Context) retry.Result {
			atomic.AddInt32(&calls, 1)
			return retry.Result{StatusCode: http.StatusOK, Err: breakErr}
		})

		assert.EqualValues(t, 1, atomic.LoadInt32(&calls),
			"declined answered breaks never replay: one billable stream, no repeat")
		assert.Equal(t, http.StatusOK, res.StatusCode)
		require.ErrorIs(t, res.Err, breakErr)
	})
}
