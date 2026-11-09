package retry_test

// N09-P01-T07 boundary regression corpus — the retry seam (pkg/retry).
//
// The layer's unit guarantees are pinned by outcome_test.go (classification
// table, MayRepeat matrix, proof-contract table), retry_test.go,
// retry_contract_test.go and the T05 negative battery. This corpus adds the
// regression dimension those tests leave open: the REPEAT BUDGET boundary —
// what a deliberately wide policy (MaxAttempts=5) does for every evidence ×
// contract combination, and the error discipline of the seam itself.
//
// The no-repeat stack's core promise has two sides, and a regression can
// break either:
//   - silence and hidden execution never repeat, no matter how wide the
//     budget (over-repetition would double billable work);
//   - proven non-execution and contract-backed repeats DO exhaust the whole
//     budget (over-suppression would turn one transient network blip into a
//     guaranteed user-visible failure).
// A drift in classification or permission shows up here as a wrong attempt
// count. The corpus also pins that retry.Do returns the refused repeat's
// raw cause: the typed SuppressedError envelope is the chain executor's job
// (T04), never fabricated inside the loop.

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/retry"
)

// TestN09P1T07_Boundary_RepeatBudgetMatrix pins the attempt-count boundary
// for every evidence × contract combination under a wide MaxAttempts=5
// policy. The counts are the regression boundary: exactly one attempt
// wherever repetition is forbidden, exactly the full budget wherever it is
// permitted.
func TestN09P1T07_Boundary_RepeatBudgetMatrix(t *testing.T) {
	t.Parallel()

	dialRefused := &net.OpError{Op: "dial", Err: errors.New("connect: connection refused")}
	silence := errors.New("upstream request timeout")

	// The evidence classes used below are honest: what the caller claims
	// matches what the classification derives from the transport error.
	require.Equal(t, retry.OutcomeNotExecuted, retry.Classify(0, dialRefused))
	require.Equal(t, retry.OutcomeUnknown, retry.Classify(0, silence))

	tests := []struct {
		name      string
		err       error
		safety    retry.OutcomeSafety
		proof     retry.IdempotencyProof
		wantCalls int
	}{
		{
			name: "proven non-execution exhausts the whole budget",
			err:  dialRefused, safety: retry.OutcomeNotExecuted, wantCalls: 5,
		},
		{
			name: "proven non-execution ignores a declining contract",
			err:  dialRefused, safety: retry.OutcomeNotExecuted,
			proof: outcomeProbeProof{allows: false}, wantCalls: 5,
		},
		{
			name: "silence stops after the first attempt",
			err:  silence, safety: retry.OutcomeUnknown, wantCalls: 1,
		},
		{
			name: "silence stops after the first attempt under a declining contract",
			err:  silence, safety: retry.OutcomeUnknown,
			proof: outcomeProbeProof{allows: false}, wantCalls: 1,
		},
		{
			name: "a verified contract repeats silence to the budget",
			err:  silence, safety: retry.OutcomeUnknown,
			proof: outcomeProbeProof{allows: true}, wantCalls: 5,
		},
		{
			name: "hidden execution never repeats at any budget",
			err:  silence, safety: retry.OutcomeExecuted, wantCalls: 1,
		},
		{
			name: "hidden execution repeats only under a verified contract",
			err:  silence, safety: retry.OutcomeExecuted,
			proof: outcomeProbeProof{allows: true}, wantCalls: 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			calls := 0
			policy := retry.Policy{
				MaxAttempts: 5,
				BaseDelay:   time.Nanosecond,
				MaxDelay:    time.Nanosecond,
				RetryOn:     retry.DefaultClassifier,
			}
			res := retry.Do(context.Background(), policy, func(context.Context) retry.Result {
				calls++
				return retry.Result{
					StatusCode: 0,
					Err:        tt.err,
					Safety:     tt.safety,
					Proof:      tt.proof,
				}
			})

			assert.Equal(t, tt.wantCalls, calls,
				"the attempt count is the regression boundary (safety=%s)", tt.safety)
			assert.Equal(t, 0, res.StatusCode, "no false successful status")
			require.ErrorIs(t, res.Err, tt.err, "the raw cause surfaces unchanged")
			var suppressed *retry.SuppressedError
			assert.NotErrorAs(t, res.Err, &suppressed,
				"the retry loop returns raw evidence — the typed refusal envelope is the chain's job")
		})
	}
}

// TestN09P1T07_Boundary_ProvenDialFailureBudgetIsNotSilenced is the
// no-over-suppression control at the transport boundary: a caller that
// proves non-execution through the production evidence channel
// (DefinitelyNotSent → not_executed, exactly what the composed hop closure
// does) keeps its full retry budget. If classification drift ever
// re-silenced dial failures, one refused TCP connection would become a
// guaranteed failed request.
func TestN09P1T07_Boundary_ProvenDialFailureBudgetIsNotSilenced(t *testing.T) {
	t.Parallel()

	dialRefused := &net.OpError{Op: "dial", Err: errors.New("connect: connection refused")}
	require.True(t, retry.DefinitelyNotSent(dialRefused),
		"a dial refusal is proof the exchange never started")
	require.Equal(t, retry.OutcomeNotExecuted, retry.Classify(0, dialRefused))

	calls := 0
	policy := retry.Policy{
		MaxAttempts: 5,
		BaseDelay:   time.Nanosecond,
		MaxDelay:    time.Nanosecond,
		RetryOn:     retry.DefaultClassifier,
	}
	res := retry.Do(context.Background(), policy, func(context.Context) retry.Result {
		calls++
		return retry.Result{Err: dialRefused, Safety: retry.OutcomeNotExecuted}
	})

	assert.Equal(t, 5, calls, "proven pre-send failure keeps the whole retry budget")
	assert.Equal(t, 0, res.StatusCode)
	require.ErrorIs(t, res.Err, dialRefused)
	var suppressed *retry.SuppressedError
	assert.NotErrorAs(t, res.Err, &suppressed)
}
