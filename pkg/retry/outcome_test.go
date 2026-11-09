package retry_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/retry"
)

// TestClassify pins the three-way upstream outcome classification from
// transport evidence: an HTTP answer is a known-completed outcome, a DNS or
// dial failure is known-not-started, and everything else — timeouts,
// cancellations, write and read failures, plain errors with no answer — has
// an unknown outcome. None of the unknown shapes may classify as
// not_executed: silence is never proof that the request did not execute.
func TestClassify(t *testing.T) {
	t.Parallel()

	dialRefused := &net.OpError{Op: "dial", Err: errors.New("connect: connection refused")}
	tests := []struct {
		name string
		code int
		err  error
		want retry.OutcomeSafety
	}{
		{name: "success is known-completed", code: http.StatusOK, err: nil, want: retry.OutcomeExecuted},
		{name: "http 429 answer is known-completed", code: http.StatusTooManyRequests, err: errors.New("upstream error 429: rate limited"), want: retry.OutcomeExecuted},
		{name: "http 503 answer is known-completed", code: http.StatusServiceUnavailable, err: errors.New("upstream error 503"), want: retry.OutcomeExecuted},
		{name: "http 500 answer is known-completed", code: http.StatusInternalServerError, err: errors.New("upstream error 500"), want: retry.OutcomeExecuted},
		{name: "dns resolution failure is known-not-started", code: 0, err: &net.DNSError{Err: "no such host", Name: "api.example.com"}, want: retry.OutcomeNotExecuted},
		{name: "dial refusal is known-not-started", code: 0, err: dialRefused, want: retry.OutcomeNotExecuted},
		{name: "dial refusal behind url.Error unwraps", code: 0, err: &url.Error{Op: "Post", Err: dialRefused}, want: retry.OutcomeNotExecuted},
		{name: "timeout without answer is unknown", code: 0, err: errors.New("upstream request timeout"), want: retry.OutcomeUnknown},
		{name: "context deadline is unknown", code: 0, err: context.DeadlineExceeded, want: retry.OutcomeUnknown},
		{name: "client disconnect is unknown", code: 0, err: context.Canceled, want: retry.OutcomeUnknown},
		{name: "write failure after send is unknown", code: 0, err: &net.OpError{Op: "write", Err: errors.New("broken pipe")}, want: retry.OutcomeUnknown},
		{name: "read failure after headers is unknown", code: 0, err: &net.OpError{Op: "read", Err: errors.New("connection reset by peer")}, want: retry.OutcomeUnknown},
		{name: "plain error without answer is unknown", code: 0, err: errors.New("connection reset after write"), want: retry.OutcomeUnknown},
		{name: "no error reported counts as known-completed", code: 0, err: nil, want: retry.OutcomeExecuted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, retry.Classify(tt.code, tt.err))
		})
	}
}

// TestOutcomeSafetyString pins the stable machine-readable names used in
// events, metrics and logs.
func TestOutcomeSafetyString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "unknown", retry.OutcomeUnknown.String())
	assert.Equal(t, "not_executed", retry.OutcomeNotExecuted.String())
	assert.Equal(t, "executed", retry.OutcomeExecuted.String())
	assert.Equal(t, "unknown", retry.OutcomeSafety(99).String(), "out-of-range values stay conservative")
}

// TestMayRepeat pins the repetition-permission rule for silent attempts: only
// proven non-execution or a verified deduplication contract permits an
// automatic repeat — never an unknown or executed outcome on its own, and a
// declining contract never invents permission.
func TestMayRepeat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		safety retry.OutcomeSafety
		proof  retry.IdempotencyProof
		want   bool
	}{
		{name: "proven non-execution repeats without any contract", safety: retry.OutcomeNotExecuted, want: true},
		{name: "proven non-execution repeats even with a declining contract", safety: retry.OutcomeNotExecuted, proof: outcomeProbeProof{allows: false}, want: true},
		{name: "unknown outcome is terminal without a contract", safety: retry.OutcomeUnknown, want: false},
		{name: "unknown outcome repeats only with an allowing contract", safety: retry.OutcomeUnknown, proof: outcomeProbeProof{allows: true}, want: true},
		{name: "unknown outcome with a declining contract stays terminal", safety: retry.OutcomeUnknown, proof: outcomeProbeProof{allows: false}, want: false},
		{name: "executed outcome is terminal without a contract", safety: retry.OutcomeExecuted, want: false},
		{name: "executed outcome repeats only with an allowing contract", safety: retry.OutcomeExecuted, proof: outcomeProbeProof{allows: true}, want: true},
		{name: "out-of-range value still follows an allowing contract", safety: retry.OutcomeSafety(99), proof: outcomeProbeProof{allows: true}, want: true},
		{name: "out-of-range value is terminal without a contract", safety: retry.OutcomeSafety(99), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, retry.MayRepeat(tt.safety, tt.proof))
		})
	}
}

// outcomeProbeProof is a test stand-in for a verified provider deduplication
// contract. No production provider ships one; the retry gate must honour the
// contract interface exactly as declared.
type outcomeProbeProof struct{ allows bool }

func (p outcomeProbeProof) AllowsRetry() bool { return p.allows }

// TestDoProofContract pins the repetition gate for errored attempts that
// produced no HTTP answer: only proof of non-execution or a verified
// provider deduplication contract may permit an automatic repeat. Unknown
// and executed outcomes are terminal without such evidence — the provider
// may have executed the first attempt, and a repeat would double the work.
func TestDoProofContract(t *testing.T) {
	tests := []struct {
		name       string
		safety     retry.OutcomeSafety
		proof      retry.IdempotencyProof
		wantCalls  int
		wantErr    bool
		wantStatus int
	}{
		{
			name:      "unknown without proof is terminal",
			safety:    retry.OutcomeUnknown,
			wantCalls: 1, wantErr: true,
		},
		{
			name:      "unknown with declining proof is terminal",
			safety:    retry.OutcomeUnknown,
			proof:     outcomeProbeProof{allows: false},
			wantCalls: 1, wantErr: true,
		},
		{
			name:      "unknown with verified dedup contract may repeat",
			safety:    retry.OutcomeUnknown,
			proof:     outcomeProbeProof{allows: true},
			wantCalls: 2, wantStatus: http.StatusOK,
		},
		{
			name:      "known-not-started repeats without proof",
			safety:    retry.OutcomeNotExecuted,
			wantCalls: 2, wantStatus: http.StatusOK,
		},
		{
			name:      "known-completed failure is terminal without proof",
			safety:    retry.OutcomeExecuted,
			wantCalls: 1, wantErr: true,
		},
		{
			name:      "known-completed failure with verified dedup contract may repeat",
			safety:    retry.OutcomeExecuted,
			proof:     outcomeProbeProof{allows: true},
			wantCalls: 2, wantStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			calls := 0
			policy := retry.Policy{
				MaxAttempts: 2,
				BaseDelay:   time.Nanosecond,
				MaxDelay:    2 * time.Nanosecond,
				RetryOn:     retry.DefaultClassifier,
			}
			res := retry.Do(context.Background(), policy, func(context.Context) retry.Result {
				calls++
				if calls == 1 {
					return retry.Result{
						StatusCode: 0,
						Err:        errors.New("upstream request timeout"),
						Safety:     tt.safety,
						Proof:      tt.proof,
					}
				}
				return retry.Result{StatusCode: http.StatusOK}
			})

			assert.Equal(t, tt.wantCalls, calls, "attempt count must match the repetition contract")
			if tt.wantErr {
				require.Error(t, res.Err)
			} else {
				require.NoError(t, res.Err)
				assert.Equal(t, tt.wantStatus, res.StatusCode)
			}
		})
	}
}

// TestDo_ExecutedOutcomeIsNotReplayed is the partial-work negative: an
// attempt that visibly started executing (stream produced bytes, response
// arrived but was unusable) is marked known-completed and must never be
// replayed, even though the caller ended up with an error and no usable
// response.
func TestDo_ExecutedOutcomeIsNotReplayed(t *testing.T) {
	t.Parallel()

	calls := 0
	res := retry.Do(context.Background(), retry.DefaultPolicy(), func(context.Context) retry.Result {
		calls++
		return retry.Result{
			StatusCode: 0,
			Err:        errors.New("stream aborted after first chunk"),
			Safety:     retry.OutcomeExecuted,
		}
	})

	assert.Equal(t, 1, calls, "partial execution must not become a safe replay")
	require.Error(t, res.Err)
	assert.Equal(t, 0, res.StatusCode)
}
