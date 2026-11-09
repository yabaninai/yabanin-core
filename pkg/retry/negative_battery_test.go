package retry_test

import (
	"context"
	"errors"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/retry"
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

// TestNegative_SilenceIsNeverProofOfNonExecution pins the N09-P01-T05
// acceptance boundary at the classification seam: a timeout or an absent
// first byte is silence, never proof of non-execution. Every silent shape
// must classify unknown (not not_executed) and must therefore stay terminal
// in the repetition-permission rule — without a contract, and with a
// declining contract. If any of these shapes leaked into OutcomeNotExecuted,
// it would earn unconditional repeat permission (MayRepeat's evidence arm)
// and a fallback could repeat hidden spend or side effects.
func TestNegative_SilenceIsNeverProofOfNonExecution(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{name: "client timeout wrapping a first-byte deadline", err: &url.Error{Op: "Post", Err: firstByteTimeout{}}},
		{name: "bare first-byte read deadline", err: firstByteTimeout{}},
		{name: "context deadline", err: context.DeadlineExceeded},
		{name: "context canceled", err: context.Canceled},
		{name: "client disconnect through url.Error", err: &url.Error{Op: "Post", Err: context.Canceled}},
		{name: "write failure after request bytes were sent", err: &net.OpError{Op: "write", Err: errors.New("broken pipe")}},
		{name: "read failure after headers", err: &net.OpError{Op: "read", Err: errors.New("connection reset by peer")}},
		{name: "unclassified mid-flight reset", err: errors.New("connection reset after write")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := retry.Classify(0, tt.err)

			assert.NotEqual(t, retry.OutcomeNotExecuted, got,
				"a timeout or absent first byte is never proof of non-execution")
			assert.Equal(t, retry.OutcomeUnknown, got,
				"silent evidence classifies as the conservative unknown")
			assert.False(t, retry.MayRepeat(got, nil),
				"silence must not earn unconditional repeat permission")
			assert.False(t, retry.MayRepeat(got, outcomeProbeProof{allows: false}),
				"a declining dedup contract must not permit repeating silence")
		})
	}
}

// TestNegative_PartialStreamNeverBecomesSafeReplay is the card's
// partial-streaming negative at the retry gate: an attempt that visibly
// started executing (stream produced bytes, answer arrived but was unusable)
// is reported with the executed evidence class and must stay terminal no
// matter how wide the retry policy is, and a declining dedup contract must
// not change that. The outcome is final: no replayed call, the cause stays
// reachable, no false successful status.
func TestNegative_PartialStreamNeverBecomesSafeReplay(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{name: "stream aborted after first chunk", err: errors.New("stream aborted after first chunk")},
		{name: "answer arrived but was unusable", err: errors.New("response arrived but could not be decoded")},
		{name: "translation failed mid-stream", err: errors.New("adapter translation failed after output started")},
	}
	contracts := []struct {
		name  string
		proof retry.IdempotencyProof
	}{
		{name: "no contract", proof: nil},
		{name: "declining contract", proof: outcomeProbeProof{allows: false}},
	}
	for _, tt := range tests {
		for _, contract := range contracts {
			t.Run(tt.name+" / "+contract.name, func(t *testing.T) {
				t.Parallel()

				calls := 0
				// A deliberately wide policy: if executed evidence were not
				// terminal, five attempts would be made.
				policy := retry.Policy{
					MaxAttempts: 5,
					BaseDelay:   time.Nanosecond,
					MaxDelay:    2 * time.Nanosecond,
					RetryOn:     retry.DefaultClassifier,
				}
				res := retry.Do(context.Background(), policy, func(context.Context) retry.Result {
					calls++
					return retry.Result{Err: tt.err, Safety: retry.OutcomeExecuted, Proof: contract.proof}
				})

				assert.Equal(t, 1, calls, "partial execution must not become a safe replay")
				require.Error(t, res.Err)
				require.ErrorIs(t, res.Err, tt.err, "the terminal cause stays reachable")
				assert.Equal(t, 0, res.StatusCode, "no false successful status")
			})
		}
	}
}

// TestNegative_ContractPermittedRepeatKeepsOneIdentity covers the identity
// seam under the retry loop: when a verified dedup contract permits the
// repeat, the repeated operation must present the same request identity the
// contract was keyed with. The loop hands every attempt the caller's context
// unchanged — a per-attempt re-mint would silently defeat the provider
// deduplication the contract promises.
func TestNegative_ContractPermittedRepeatKeepsOneIdentity(t *testing.T) {
	t.Parallel()

	identity := retry.RequestIdentity{RequestID: "req-neg-dedup", IdempotencyKey: "idem-neg-dedup"}
	ctx := retry.WithRequestIdentity(context.Background(), identity)

	calls := 0
	saw := make([]retry.RequestIdentity, 0, 2)
	policy := retry.Policy{
		MaxAttempts: 3,
		BaseDelay:   time.Nanosecond,
		MaxDelay:    2 * time.Nanosecond,
		RetryOn:     retry.DefaultClassifier,
	}
	res := retry.Do(ctx, policy, func(attemptCtx context.Context) retry.Result {
		calls++
		saw = append(saw, retry.RequestIdentityFrom(attemptCtx))
		if calls == 1 {
			return retry.Result{
				Err:    errors.New("upstream request timeout"),
				Safety: retry.OutcomeUnknown,
				Proof:  outcomeProbeProof{allows: true},
			}
		}
		return retry.Result{StatusCode: 200}
	})

	require.NoError(t, res.Err)
	assert.Equal(t, 2, calls, "the verified contract permits exactly one repeat")
	assert.Equal(t, []retry.RequestIdentity{identity, identity}, saw,
		"every attempt of the repeated operation presents the same identity")
}

// TestNegative_SuppressedRefusalCodeIsStable pins the typed-refusal channel
// adversarially: the machine-readable refusal code is a pure function of the
// evidence class — stable under every unrelated field variation, mutually
// exclusive between the unknown and executed classes, conservative for every
// non-executed classification, and free of double-derivation side effects.
func TestNegative_SuppressedRefusalCodeIsStable(t *testing.T) {
	t.Parallel()

	cause := errors.New("upstream request timeout")

	t.Run("unknown refusal keeps its code under every field variation", func(t *testing.T) {
		t.Parallel()

		for _, model := range []string{"", "primary"} {
			for _, err := range []error{nil, cause} {
				e := &retry.SuppressedError{Model: model, Outcome: retry.OutcomeUnknown, Err: err}
				assert.Equal(t, retry.SuppressedUnknownCode, e.Code(),
					"model=%q err=%v", model, err)
				assert.Equal(t, retry.SuppressedUnknownCode, e.Code(),
					"repeated reads are stable (model=%q err=%v)", model, err)
			}
		}
	})

	t.Run("executed refusal keeps its code under every field variation", func(t *testing.T) {
		t.Parallel()

		streamCause := errors.New("stream aborted after first chunk")
		for _, model := range []string{"", "primary"} {
			e := &retry.SuppressedError{Model: model, Outcome: retry.OutcomeExecuted, Err: streamCause}
			assert.Equal(t, retry.SuppressedExecutedCode, e.Code(), "model=%q", model)
			assert.Equal(t, retry.SuppressedExecutedCode, e.Code(), "repeated reads are stable")
			require.ErrorIs(t, e, streamCause,
				"the partial-stream cause stays reachable under the executed refusal")
		}
	})

	t.Run("every non-executed class reports the conservative unknown code", func(t *testing.T) {
		t.Parallel()

		for _, outcome := range []retry.OutcomeSafety{
			retry.OutcomeUnknown,
			retry.OutcomeNotExecuted,
			retry.OutcomeSafety(99),
			retry.OutcomeSafety(255),
		} {
			e := &retry.SuppressedError{Outcome: outcome, Err: cause}
			assert.Equal(t, retry.SuppressedUnknownCode, e.Code(),
				"only observed execution may claim the executed refusal code (outcome=%s)", outcome)
		}
	})

	t.Run("reading the code does not mutate the classification", func(t *testing.T) {
		t.Parallel()

		e := &retry.SuppressedError{Outcome: retry.OutcomeExecuted, Err: cause}
		first := e.Code()
		assert.Equal(t, first, e.Code())
		assert.Equal(t, retry.SuppressedExecutedCode, first)
		assert.Equal(t, retry.OutcomeExecuted, e.Outcome, "Code is a pure read")
	})
}

// TestNegative_IdentityAttachNeverCorruptsOrInvents covers the identity-loss
// adversarial cases of the context carrier: a middleware stack that attaches
// an identity twice resolves deterministically (innermost wins, nothing is
// merged or corrupted), the outer attachment survives unchanged for outer
// readers, and attaching an empty identity invents nothing.
func TestNegative_IdentityAttachNeverCorruptsOrInvents(t *testing.T) {
	t.Parallel()

	outer := retry.RequestIdentity{RequestID: "req-outer", IdempotencyKey: "idem-outer"}
	inner := retry.RequestIdentity{RequestID: "req-inner", IdempotencyKey: "idem-inner"}

	t.Run("double attachment resolves to the innermost identity", func(t *testing.T) {
		t.Parallel()

		ctx := retry.WithRequestIdentity(retry.WithRequestIdentity(context.Background(), outer), inner)
		got := retry.RequestIdentityFrom(ctx)

		assert.Equal(t, inner, got, "the innermost attachment wins; nothing is merged")
		assert.NotEqual(t, outer, got)
	})

	t.Run("outer attachment survives for outer readers", func(t *testing.T) {
		t.Parallel()

		parent := retry.WithRequestIdentity(context.Background(), outer)
		_ = retry.WithRequestIdentity(parent, inner)

		assert.Equal(t, outer, retry.RequestIdentityFrom(parent),
			"the child attachment never rewrites the parent carrier")
	})

	t.Run("attaching the zero value invents nothing", func(t *testing.T) {
		t.Parallel()

		ctx := retry.WithRequestIdentity(context.Background(), retry.RequestIdentity{})

		assert.Equal(t, retry.RequestIdentity{}, retry.RequestIdentityFrom(ctx))
	})
}
