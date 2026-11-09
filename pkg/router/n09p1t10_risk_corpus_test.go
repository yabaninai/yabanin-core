package router_test

// N09-P01-T10 [risk] — rights/data/resources verification for pkg/router.
// Test-only card: zero production changes. The corpus pins three risk
// dimensions of the fallback executor that the negative battery (T07/T08)
// and the compatibility walk (T09) do not cover:
//
//	permissions — repetition permission cannot arrive through the error
//	channel and an allowing contract cannot bypass an enforce-mode hint
//	refusal;
//	data — the executor never copies identity key material into the chain
//	record (the request ID stays the join key by design);
//	resources — adversarial chain shapes stay within maxHops and the
//	suppressed/duplicate paths spawn no goroutines.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/router"
)

// t10ProofError is a caller-controlled error value that carries its own
// "permission": it implements retry.IdempotencyProof and claims repetition
// is deduplicated upstream. The executor must never consult the error
// channel for permission — only the construction-wired contract counts.
type t10ProofError struct{ msg string }

func (e *t10ProofError) Error() string     { return e.msg }
func (e *t10ProofError) AllowsRetry() bool { return true }

// t10WrappingProofError hides an allowing proof behind Unwrap, so an
// errors.As-based permission extraction would find it. Same rule applies:
// the error channel never grants repetition.
type t10WrappingProofError struct{ inner *t10ProofError }

func (e *t10WrappingProofError) Error() string { return "wrapped: " + e.inner.msg }
func (e *t10WrappingProofError) Unwrap() error { return e.inner }

// TestN09P1T10_Risk_PermissionCannotArriveThroughTheErrorChannel: a silent
// attempt whose error value claims (directly or behind Unwrap) that the
// provider deduplicates repeats must still be terminal without a wired
// contract. Permission is a construction-time fact of the executor, not
// something a failed attempt can assert about itself.
func TestN09P1T10_Risk_PermissionCannotArriveThroughTheErrorChannel(t *testing.T) {
	t.Parallel()

	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}

	for name, attemptErr := range map[string]error{
		"direct allowing proof in error":  &t10ProofError{msg: "upstream request timeout"},
		"allowing proof behind unwrap":    &t10WrappingProofError{inner: &t10ProofError{msg: "upstream request timeout"}},
		"plain unknown transport silence": errors.New("upstream request timeout"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for nameWire, proof := range map[string]retry.IdempotencyProof{
				"no wired contract":  nil,
				"declining contract": decliningProof{},
			} {
				t.Run(nameWire, func(t *testing.T) {
					t.Parallel()

					var dials int32
					fe := router.NewFallbackExecutor(newFakeResolver(nil), 3, nil)
					if proof != nil {
						fe = fe.WithIdempotencyProof(proof)
					}

					_, code, attempts, err := fe.Execute(context.Background(), primary,
						func(_ context.Context, _ resolver.ModelInfo) (int, error) {
							atomic.AddInt32(&dials, 1)
							return 0, attemptErr
						})

					var suppressed *retry.SuppressedError
					require.ErrorAs(t, err, &suppressed)
					assert.Equal(t, retry.SuppressedUnknownCode, suppressed.Code())
					assert.Equal(t, 0, code, "no HTTP answer ever arrived")
					require.Len(t, attempts, 1, "the chain must end on the silent attempt")
					assert.False(t, attempts[0].Success)
					assert.EqualValues(t, 1, atomic.LoadInt32(&dials),
						"the failed attempt must never be repeated via second provider")
				})
			}
		})
	}

	// Control: with the contract wired at construction the very same error
	// does advance — proving the suppression above comes from the wiring
	// discipline, not from the error shape.
	t.Run("control: wired allowing contract advances", func(t *testing.T) {
		t.Parallel()

		proof := &countingProof{}
		var dials int32
		fe := router.NewFallbackExecutor(newFakeResolver(nil), 3, nil).WithIdempotencyProof(proof)

		_, code, attempts, err := fe.Execute(context.Background(), primary,
			func(_ context.Context, info resolver.ModelInfo) (int, error) {
				atomic.AddInt32(&dials, 1)
				if info.ModelName == "primary" {
					return 0, &t10ProofError{msg: "upstream request timeout"}
				}
				return 200, nil
			})

		require.NoError(t, err)
		assert.Equal(t, 200, code)
		require.Len(t, attempts, 2)
		assert.EqualValues(t, 2, atomic.LoadInt32(&dials))
		assert.Equal(t, 1, proof.consults, "exactly one consultation for the one silent attempt")
	})
}

// decliningProof is a wired dedup contract that never permits repetition.
type decliningProof struct{}

func (decliningProof) AllowsRetry() bool { return false }

// TestN09P1T10_Risk_AllowingContractCannotBypassHintRefusal: enforce-mode
// hint semantics come before any repetition question. A contract that would
// allow advancing past silent attempts buys nothing against a hint no
// candidate can satisfy: no dial, no trace, no contract consultation.
func TestN09P1T10_Risk_AllowingContractCannotBypassHintRefusal(t *testing.T) {
	t.Parallel()

	proof := &countingProof{}
	fe := router.NewFallbackExecutor(newFakeResolver(nil), 3, nil).WithIdempotencyProof(proof)
	primary := resolver.ModelInfo{
		ModelName:      "primary",
		Provider:       "prov-a",
		FailoverModels: []string{"secondary"},
	}

	var dials int32
	_, code, attempts, err := fe.ExecuteWithProviderHint(context.Background(), primary,
		"provider-no-candidate-has",
		func(_ context.Context, _ resolver.ModelInfo) (int, error) {
			atomic.AddInt32(&dials, 1)
			return 200, nil
		})

	require.Error(t, err)
	var refusal *router.PolicyError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, 400, refusal.Status)
	assert.Equal(t, router.HintUnsatisfiableCode, refusal.ErrCode)
	assert.Equal(t, 400, code)
	assert.Empty(t, attempts, "refusal happens before any candidate is attempted")
	assert.EqualValues(t, 0, atomic.LoadInt32(&dials), "no endpoint may be dialed")
	assert.Equal(t, 0, proof.consults, "the contract is not consulted for a hint refusal")
}

// TestN09P1T10_Risk_HintEchoBoundedInRefusalEnvelope: the refusal envelope
// truncates overlong hint text. The hint is policy-controlled, but the
// envelope must not reflect unbounded input — neither via HintRefusal
// directly nor through the executor's refusal path.
func TestN09P1T10_Risk_HintEchoBoundedInRefusalEnvelope(t *testing.T) {
	t.Parallel()

	huge := strings.Repeat("A", 10_000)

	t.Run("direct refusal constructor", func(t *testing.T) {
		t.Parallel()

		msg := router.HintRefusal(huge, "unit probe").Message
		assert.Contains(t, msg, "…(truncated)", "overlong hints must be marked as truncated")
		assert.NotContains(t, msg, strings.Repeat("A", 65), "at most 64 characters are echoed")
		assert.Less(t, len(msg), 256, "the echoed hint stays bounded: %d chars", len(msg))
	})

	t.Run("end-to-end executor refusal", func(t *testing.T) {
		t.Parallel()

		fe := router.NewFallbackExecutor(newFakeResolver(nil), 3, nil)
		primary := resolver.ModelInfo{ModelName: "primary", Provider: "prov-a"}

		_, _, attempts, err := fe.ExecuteWithProviderHint(context.Background(), primary, huge,
			func(_ context.Context, _ resolver.ModelInfo) (int, error) {
				return 200, nil
			})

		var refusal *router.PolicyError
		require.ErrorAs(t, err, &refusal)
		assert.NotContains(t, refusal.Message, strings.Repeat("A", 65))
		assert.Contains(t, refusal.Message, "…(truncated)")
		assert.Empty(t, attempts)
	})
}

// TestN09P1T10_Risk_IdentityKeyMaterialStaysOutOfChainRecords: the executor
// stamps the request ID on every attempt entry (the join key by design) and
// nothing else from the request identity. The upstream deduplication key is
// attempt-loop material owned by the caller's transport closure — it must
// never surface in the attempt trace, its JSON event shape, or the refusal.
func TestN09P1T10_Risk_IdentityKeyMaterialStaysOutOfChainRecords(t *testing.T) {
	t.Parallel()

	const (
		reqID  = "req-t10-join-key"
		reqKey = "ik_live_T10_SECRET_do_not_journal"
	)
	ctx := retry.WithRequestIdentity(context.Background(),
		retry.RequestIdentity{RequestID: reqID, IdempotencyKey: reqKey})
	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}

	t.Run("suppressed silent attempt", func(t *testing.T) {
		t.Parallel()

		fe := router.NewFallbackExecutor(newFakeResolver(nil), 3, nil)
		_, _, attempts, err := fe.Execute(ctx, primary,
			func(_ context.Context, _ resolver.ModelInfo) (int, error) {
				return 0, errors.New("upstream request timeout")
			})

		var suppressed *retry.SuppressedError
		require.ErrorAs(t, err, &suppressed)
		assert.NotContains(t, suppressed.Error(), reqKey, "refusal text never echoes the dedup key")
		assert.NotContains(t, suppressed.Error(), reqID, "refusal text never echoes the join key either")

		require.Len(t, attempts, 1)
		assert.Equal(t, reqID, attempts[0].RequestID, "request ID is the join key by design")

		raw, mErr := json.Marshal(attempts)
		require.NoError(t, mErr)
		assert.Contains(t, string(raw), reqID, "the event shape carries the join key")
		assert.NotContains(t, string(raw), reqKey, "the event shape never carries the dedup key")
		assert.NotContains(t, string(raw), "idempoten", "no identity key field exists on the trace")
	})

	t.Run("exhausted definitive chain", func(t *testing.T) {
		t.Parallel()

		fe := router.NewFallbackExecutor(newFakeResolver(nil), 3, nil)
		_, _, _, err := fe.Execute(ctx, primary,
			func(_ context.Context, _ resolver.ModelInfo) (int, error) {
				return 503, errors.New("overloaded")
			})

		require.Error(t, err)
		assert.NotContains(t, err.Error(), reqKey)
		assert.NotContains(t, err.Error(), reqID)
	})
}

// TestN09P1T10_Risk_AdversarialChainShapesStayBounded: self-cycles, duplicate
// and empty-resolving failover entries, and oversized failover lists all
// collapse to a chain within maxHops; already-failed candidates are never
// re-dialed within one request.
func TestN09P1T10_Risk_AdversarialChainShapesStayBounded(t *testing.T) {
	t.Parallel()

	type dialLog struct {
		mu    sync.Mutex
		names []string
	}

	record := func(log *dialLog) router.AttemptFunc {
		return func(_ context.Context, info resolver.ModelInfo) (int, error) {
			log.mu.Lock()
			log.names = append(log.names, info.ModelName)
			log.mu.Unlock()
			return 503, errors.New("overloaded")
		}
	}

	t.Run("self-cycle resolves to one candidate", func(t *testing.T) {
		t.Parallel()

		fe := router.NewFallbackExecutor(newFakeResolver(nil), 3, nil)
		primary := resolver.ModelInfo{ModelName: "self", FailoverModels: []string{"self", "self"}}

		var log dialLog
		_, _, attempts, _ := fe.Execute(context.Background(), primary, record(&log))

		assert.Len(t, attempts, 1)
		assert.Equal(t, []string{"self"}, log.names)
	})

	t.Run("10k duplicate failover entries collapse and stay within maxHops", func(t *testing.T) {
		t.Parallel()

		failovers := []string{"b", "c"}
		for i := 0; i < 10_000; i++ {
			failovers = append(failovers, "b")
		}
		res := newFakeResolver(map[string]resolver.ModelInfo{
			"b": {ModelName: "b"},
			"c": {ModelName: "c"},
		})
		fe := router.NewFallbackExecutor(res, 5, nil)
		primary := resolver.ModelInfo{ModelName: "a", FailoverModels: failovers}

		var log dialLog
		_, _, attempts, _ := fe.Execute(context.Background(), primary, record(&log))

		require.LessOrEqual(t, len(attempts), 5, "maxHops is the hard bound")
		seen := map[string]bool{}
		for _, name := range log.names {
			assert.False(t, seen[name], "candidate %q must never be dialed twice", name)
			seen[name] = true
		}
		assert.ElementsMatch(t, []string{"a", "b", "c"}, log.names)
	})

	t.Run("entries resolving to an empty name stay in the chain within maxHops", func(t *testing.T) {
		t.Parallel()

		// Documented contract: unknown failover models are still included —
		// gating them is the caller's per-attempt gate, not the chain
		// builder's. The bound that matters here is maxHops: junk entries
		// cannot grow the chain past it, and the gate still sees every
		// candidate (an empty-name candidate is the gate's refusal call).
		fe := router.NewFallbackExecutor(newFakeResolver(nil), 3, nil)
		primary := resolver.ModelInfo{ModelName: "a", FailoverModels: []string{"", "", "b", "c", "d"}}

		var gateDeniedEmpty int32
		_, _, attempts, _ := fe.Execute(context.Background(), primary,
			func(_ context.Context, info resolver.ModelInfo) (int, error) {
				if info.ModelName == "" {
					atomic.AddInt32(&gateDeniedEmpty, 1)
				}
				return 503, errors.New("overloaded")
			})

		assert.LessOrEqual(t, len(attempts), 3, "junk entries cannot exceed maxHops")
		assert.EqualValues(t, len(attempts)-1, gateDeniedEmpty,
			"every non-primary junk candidate reaches the caller's gate")
	})

	t.Run("maxHops bounds an oversized distinct list", func(t *testing.T) {
		t.Parallel()

		failovers := make([]string, 0, 50)
		entries := map[string]resolver.ModelInfo{}
		for i := 0; i < 50; i++ {
			name := fmt.Sprintf("m%02d", i)
			failovers = append(failovers, name)
			entries[name] = resolver.ModelInfo{ModelName: name}
		}
		fe := router.NewFallbackExecutor(newFakeResolver(entries), 3, nil)
		primary := resolver.ModelInfo{ModelName: "a", FailoverModels: failovers}

		var log dialLog
		_, _, attempts, _ := fe.Execute(context.Background(), primary, record(&log))

		assert.LessOrEqual(t, len(attempts), 3)
	})
}

// TestN09P1T10_Risk_NoGoroutineLeakInSuppressedDuplicatePaths: the suppressed
// and duplicate-heavy execution paths spawn no background work — goroutine
// count returns to its baseline after a burst of adversarial chains.
// Dependency-free on purpose: goleak is not a direct module dependency and a
// test-only card does not add one.
func TestN09P1T10_Risk_NoGoroutineLeakInSuppressedDuplicatePaths(t *testing.T) {
	t.Parallel()

	failovers := make([]string, 0, 64)
	for i := 0; i < 64; i++ {
		failovers = append(failovers, "dup")
	}
	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: failovers}
	silent := func(_ context.Context, _ resolver.ModelInfo) (int, error) {
		return 0, errors.New("upstream request timeout")
	}

	time.Sleep(50 * time.Millisecond) // let prior tests' goroutines wind down
	runtime.GC()
	baseline := runtime.NumGoroutine()

	fe := router.NewFallbackExecutor(newFakeResolver(nil), 3, nil)
	for i := 0; i < 300; i++ {
		_, _, _, _ = fe.Execute(context.Background(), primary, silent)
	}

	assert.Eventually(t, func() bool {
		runtime.GC()
		return runtime.NumGoroutine() <= baseline+32
	}, 5*time.Second, 50*time.Millisecond,
		"goroutines must return to baseline (base %d, now %d)", baseline, runtime.NumGoroutine())
}

// TestN09P1T10_Risk_AnsweredStreamBreakFollowsTheOrdinaryPolicyBranch: the
// answered branch of the partial-streaming risk. A stream that produced HTTP
// answers (headers received, output started) and then broke mid-flight is a
// known-completed outcome by the evidence contract — the executor records it
// as executed and the ordinary status policy, never the unknown-outcome
// suppression, governs what follows. Two consequences are pinned:
//
//  1. under DefaultRetryable the answered break is a retryable transport
//     error, so the fallback completes on the next candidate (a second
//     billable generation — the caller owns the no-replay duty for answered
//     attempts, by reporting them as no-answer silence or overriding the
//     classifier);
//  2. a caller classifier that declines answered breaks ends the chain on
//     the raw mid-stream cause — an answered attempt is never typed as an
//     unknown-outcome suppression in either branch.
//
// The asymmetry is the documented evidence contract (an HTTP answer is
// definitive evidence; silence is not); the double-spend consideration for
// branch 1 is flagged in the card record for the policy-owner lane.
func TestN09P1T10_Risk_AnsweredStreamBreakFollowsTheOrdinaryPolicyBranch(t *testing.T) {
	t.Parallel()

	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
	resolverEntries := map[string]resolver.ModelInfo{"secondary": {ModelName: "secondary"}}
	breakErr := errors.New("stream aborted after first chunk")

	t.Run("default classifier: the answered break advances, recorded as executed", func(t *testing.T) {
		t.Parallel()

		fe := router.NewFallbackExecutor(newFakeResolver(resolverEntries), 5, nil)
		var generations int32
		_, code, attempts, err := fe.Execute(context.Background(), primary,
			func(_ context.Context, info resolver.ModelInfo) (int, error) {
				atomic.AddInt32(&generations, 1) // billable upstream work per dial
				if info.ModelName == "primary" {
					return http.StatusOK, breakErr
				}
				return http.StatusOK, nil
			})

		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, code)
		assert.EqualValues(t, 2, atomic.LoadInt32(&generations),
			"the answered break is ordinary-policy territory: the chain completes on the fallback candidate")
		require.Len(t, attempts, 2)
		assert.Equal(t, "executed", attempts[0].Outcome,
			"an answer followed by a stream break is executed evidence — never unknown, never not_executed")
		assert.False(t, attempts[0].Success, "the broken stream is not a success")
		assert.Equal(t, http.StatusOK, attempts[0].StatusCode)
		assert.Equal(t, "primary", attempts[0].ModelName)
	})

	t.Run("caller-owned no-replay: a classifier declining answered breaks ends the chain", func(t *testing.T) {
		t.Parallel()

		fe := router.NewFallbackExecutor(newFakeResolver(resolverEntries), 5, nil).
			WithClassifier(func(code int, err error) bool { return err == nil && code < 500 })
		var generations int32
		_, code, attempts, err := fe.Execute(context.Background(), primary,
			func(_ context.Context, info resolver.ModelInfo) (int, error) {
				atomic.AddInt32(&generations, 1)
				if info.ModelName == "primary" {
					return http.StatusOK, breakErr
				}
				return http.StatusOK, nil
			})

		assert.EqualValues(t, 1, atomic.LoadInt32(&generations),
			"declining the answered break keeps the fallback quiet: one billable stream, no replay")
		assert.Equal(t, http.StatusOK, code, "the answered status surfaces unchanged")
		require.Len(t, attempts, 1)
		require.ErrorIs(t, err, breakErr, "the raw mid-stream cause surfaces, not a substitution")
		var suppressed *retry.SuppressedError
		assert.NotErrorAs(t, err, &suppressed,
			"an answered attempt is never unknown-suppressed: the suppression gate is for silence")
	})
}
