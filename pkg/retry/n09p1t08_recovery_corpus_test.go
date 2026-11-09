package retry_test

// N09-P01-T08 recovery corpus — the retry seam (pkg/retry).
//
// The loop's stop-on-cancel behaviour is already pinned by retry_test.go
// (TestDo_ContextCancelledStopsImmediately,
// TestDo_ContextCancelledDuringSleepStops). This corpus adds the RECOVERY
// dimension those leave open: what the interrupted RESULT means to whoever
// resumes, and what a fresh loop is entitled to after a restart.
//
// Two properties are pinned here:
//  1. An interrupted loop returns evidence, never a verdict of
//     non-execution. Before the first attempt the returned pair (0,
//     context.Canceled) classifies unknown — a cancellation proves nothing
//     about the upstream. Mid-backoff, the last attempt's HTTP answer
//     survives in StatusCode, Err carries the context error, and the
//     caller-owned Safety channel passes through untouched: the loop never
//     invents or upgrades evidence while unwinding. Neither shape may be
//     repeated automatically without proof of non-execution or a verified
//     deduplication contract.
//  2. A fresh loop after the interruption starts with a FULL attempt
//     budget and presents the same request identity — the restart re-enters
//     the contract at the seam instead of inheriting a spent budget or a
//     re-minted identity.

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/retry"
)

// TestN09P1T08_Recovery_InterruptedLoopReturnsEvidenceNotNonExecution pins
// the evidence semantics of an interrupted loop's result. Where retry_test
// pins THAT the loop stops, this pins WHAT the stopped loop hands back — the
// shape a resuming dispatcher (a restarted process replaying the request, a
// supervisor re-driving the loop) reads to decide what may happen next.
func TestN09P1T08_Recovery_InterruptedLoopReturnsEvidenceNotNonExecution(t *testing.T) {
	t.Run("cancelled before the first attempt", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var calls atomic.Int64
		res := retry.Do(ctx, retry.Policy{MaxAttempts: 3, BaseDelay: time.Millisecond},
			func(context.Context) retry.Result {
				calls.Add(1)
				return retry.Result{StatusCode: http.StatusServiceUnavailable,
					Err: fmt.Errorf("upstream 503")}
			})
		require.ErrorIs(t, res.Err, context.Canceled)
		assert.EqualValues(t, 0, calls.Load(),
			"nothing was sent — the interruption preceded every attempt")

		// The interruption classifies unknown at the boundary: no answer
		// arrived and context.Canceled is not proof the exchange never
		// started (only DNS/dial errors are). A resuming dispatcher must
		// refuse to repeat it automatically.
		assert.Equal(t, 0, res.StatusCode)
		assert.Equal(t, retry.OutcomeUnknown, retry.Classify(res.StatusCode, res.Err),
			"context.Canceled is not non-execution proof")
		assert.False(t, retry.MayRepeat(retry.Classify(res.StatusCode, res.Err), nil),
			"an interrupted attempt without proof stays terminal for the resumer")
	})

	t.Run("cancelled during backoff after an answered attempt", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		var calls atomic.Int64
		res := retry.Do(ctx, retry.Policy{
			MaxAttempts: 4, BaseDelay: 50 * time.Millisecond, MaxDelay: 50 * time.Millisecond,
		}, func(context.Context) retry.Result {
			if calls.Add(1) == 2 {
				cancel() // the process dies during the inter-attempt sleep
			}
			return retry.Result{StatusCode: http.StatusServiceUnavailable,
				Err: fmt.Errorf("upstream 503")}
		})
		require.ErrorIs(t, res.Err, context.Canceled)
		assert.EqualValues(t, 2, calls.Load())

		// Evidence semantics of the interrupted result: the last attempt's
		// HTTP answer survives in StatusCode (the exchange DID reach an
		// answer), Err carries the context error, and the caller-owned
		// Safety channel passes through untouched — the loop never attests
		// execution the caller did not claim, and never erases evidence it
		// did.
		assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode,
			"the answered attempt's status survives the interruption")
		assert.Equal(t, retry.OutcomeUnknown, res.Safety,
			"the loop never invents a Safety class while unwinding")
		assert.Equal(t, retry.OutcomeExecuted, retry.Classify(res.StatusCode, res.Err),
			"the boundary re-derivation sees the real answer, not a forged one")
		assert.False(t, retry.MayRepeat(retry.Classify(res.StatusCode, res.Err), nil),
			"an answered attempt is never auto-repeated after the interruption")
	})
}

// TestN09P1T08_Recovery_FreshLoopAfterInterruptionGetsFullBudget pins the
// resume contract at the seam: a loop interrupted mid-flight hands the
// request to a fresh loop that (a) owns the FULL attempt budget again — the
// restart does not inherit a spent budget — and (b) presents the same
// request identity on every call of both incarnations, so upstream dedup
// contracts and usage records keep joining the two halves as one request.
func TestN09P1T08_Recovery_FreshLoopAfterInterruptionGetsFullBudget(t *testing.T) {
	identity := retry.RequestIdentity{
		RequestID:      "req-n09p1t08-retry",
		IdempotencyKey: "idem-n09p1t08-retry",
	}
	const maxAttempts = 4
	pol := retry.Policy{
		MaxAttempts: maxAttempts,
		BaseDelay:   5 * time.Millisecond,
		MaxDelay:    5 * time.Millisecond,
		RetryOn:     retry.DefaultClassifier,
	}

	var (
		mu     sync.Mutex
		ids    []retry.RequestIdentity
		calls  atomic.Int64
		armed  atomic.Bool // the first loop dies on its second attempt
		cancel context.CancelFunc
	)
	present := func(ctx context.Context) retry.Result {
		n := calls.Add(1)
		mu.Lock()
		ids = append(ids, retry.RequestIdentityFrom(ctx))
		mu.Unlock()
		if armed.Load() && n == 2 {
			cancel() // interrupted during the backoff sleep after attempt 2
		}
		return retry.Result{StatusCode: http.StatusServiceUnavailable,
			Err: fmt.Errorf("upstream 503")}
	}

	// Loop 1 (the interrupted incarnation): stops after two attempts.
	ctx1, cancel1 := context.WithCancel(
		retry.WithRequestIdentity(context.Background(), identity))
	cancel = cancel1
	armed.Store(true)
	res1 := retry.Do(ctx1, pol, present)
	cancel1()
	armed.Store(false)
	require.ErrorIs(t, res1.Err, context.Canceled)
	assert.EqualValues(t, 2, calls.Load(),
		"the interrupted loop stops with its work half-done, budget unspent")

	// Loop 2 (the fresh incarnation after the restart): full budget, same
	// identity, runs to exhaustion.
	ctx2 := retry.WithRequestIdentity(context.Background(), identity)
	res2 := retry.Do(ctx2, pol, present)
	require.Error(t, res2.Err)
	assert.Equal(t, http.StatusServiceUnavailable, res2.StatusCode,
		"the fresh loop runs its full budget to the last answer")
	assert.EqualValues(t, 2+maxAttempts, calls.Load(),
		"the fresh loop owns the full attempt budget again")

	// One identity across the restart boundary: every call of both
	// incarnations presented the unchanged boundary identity.
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, ids, 2+maxAttempts)
	for i, id := range ids {
		assert.Equal(t, identity, id,
			"transport call %d across the restart presents the same identity", i+1)
	}
}
