package router_test

// N09-P01-T08 recovery corpus — the chain executor seam (pkg/router).
//
// The executor's unit guarantees are pinned by fallback_outcome_test.go,
// fallback_identity_test.go, fallback_policy_test.go and the negative
// battery; the composed story by T06 (n09p1t06_joint_scenario_test.go) and
// the chain-scale boundary by T07 (n09p1t07_boundary_corpus_test.go). This
// corpus adds the recovery dimension between those levels: what happens when
// the SAME client request re-enters the chain — a duplicated delivery in the
// same process, or a restarted process that rebuilt every in-memory
// structure and re-presents the unchanged identity.
//
// Three properties are pinned here:
//  1. A duplicated arrival after suppression is safe by construction: the
//     breaker the first arrival tripped refuses the silenced endpoint with a
//     definitive 503 — the attempt is not re-dialed, the dedup contract is
//     NOT consulted a second time (an admission refusal is not silence, so
//     no repetition question arises), the chain advances and the next
//     candidate serves; the refusal records nothing in the books.
//  2. A restarted stack re-enters the contract honestly: a fresh breaker
//     map (closed circuits, zeroed books) and a fresh contract object
//     re-execute the input command from the beginning — one consult for the
//     fresh silent attempt — while the request identity stays the one
//     identity across both incarnations of the stack.
//  3. A partial stream that broke mid-body stays terminal across a restart
//     when no verified contract exists: the caller's executed-evidence
//     stops the intra-hop loop after one attempt, the chain boundary
//     re-derives unknown (no HTTP answer) and refuses the repeat with the
//     typed suppression; the restarted process re-dials once — the stream
//     is never resumed mid-body and never replayed twice per process.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/circuit"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/router"
)

// t08Identity is the T08 restart identity: minted once, re-presented by
// every arrival in every incarnation of the stack.
var t08Identity = retry.RequestIdentity{
	RequestID:      "req-n09p1t08-recovery",
	IdempotencyKey: "idem-n09p1t08-recovery",
}

// t08NewStack builds the T06-shaped composed stack carrying the T08 identity
// instead of the joint story identity: fresh per-endpoint breakers
// (threshold 1), a fast deterministic retry policy, scripted upstreams.
func t08NewStack(a, b, c func(int64) retry.Result) (*context.Context, *jointStack) {
	ctx := retry.WithRequestIdentity(context.Background(), t08Identity)
	stack := &jointStack{
		circuits: circuit.NewMap(circuit.Config{
			Name:             "t08-recovery",
			Enabled:          true,
			FailureThreshold: 1,
			SuccessThreshold: 1,
			OpenTimeout:      time.Minute,
			Window:           time.Minute,
		}, 0, nil),
		policy: retry.Policy{
			MaxAttempts: 2,
			BaseDelay:   time.Millisecond,
			MaxDelay:    time.Millisecond,
			RetryOn:     retry.DefaultClassifier,
		},
		probes: jointProbes(a, b, c),
	}
	return &ctx, stack
}

// TestN09P1T08_Recovery_DupArrivalSameIdentityNoSecondConsult walks the same
// client request through the chain twice in one process. Arrival 1 goes
// silent on the primary and the declining contract suppresses the repeat;
// arrival 2 — the duplicated delivery with the same identity — meets the
// tripped breaker: a definitive 503 that re-dials nothing and re-consults
// nothing, after which B serves the request.
func TestN09P1T08_Recovery_DupArrivalSameIdentityNoSecondConsult(t *testing.T) {
	ctx, stack := t08NewStack(
		func(int64) retry.Result { return retry.Result{Err: firstByteTimeout{}} },
		func(int64) retry.Result { return retry.Result{StatusCode: http.StatusOK} },
		func(int64) retry.Result { return retry.Result{StatusCode: http.StatusOK} },
	)
	proof := &t07DecliningProof{}
	exec := router.NewFallbackExecutor(jointResolver(), 5, nil).
		WithIdempotencyProof(proof)

	// Arrival 1: A goes silent, the verified contract declines — the chain
	// refuses to repeat and stops with the typed suppression.
	_, code1, attempts1, err1 := exec.Execute(*ctx, jointPrimary(), stack.attempt)
	require.Error(t, err1)
	var suppressed *retry.SuppressedError
	require.ErrorAs(t, err1, &suppressed,
		"the refusal is the typed suppression with the cause reachable")
	assert.Equal(t, 0, code1)
	require.Len(t, attempts1, 1)
	assert.Equal(t, 1, proof.consults,
		"exactly one consult for the one silent attempt")
	assert.Equal(t, int64(1), stack.probes["http://ep-a-joint"].count())
	require.Len(t, stack.identityLog, 1)
	assert.Equal(t, t08Identity, stack.identityLog[0])

	// Arrival 2 — same identity, fresh Execute walk (a gateway retry, a
	// duplicated delivery): A's breaker is open, the attempt returns a
	// definitive 503 WITHOUT dialing and WITHOUT consulting the contract
	// again; the chain advances and B serves.
	consultsBefore := int64(proof.consults)
	_, code2, attempts2, err2 := exec.Execute(*ctx, jointPrimary(), stack.attempt)
	require.NoError(t, err2)
	assert.Equal(t, http.StatusOK, code2)
	require.Len(t, attempts2, 2)
	assert.Equal(t, "joint-second", attempts2[1].ModelName,
		"the chain advanced past the refused endpoint and B served")

	assert.Equal(t, int64(1), stack.probes["http://ep-a-joint"].count(),
		"the open circuit refuses re-dialing the silenced endpoint")
	assert.EqualValues(t, consultsBefore, proof.consults,
		"an admission refusal is definitive — the contract is not consulted again")
	assert.Equal(t, int64(1), stack.probes["http://ep-b-joint"].count())
	// The transport log grew by exactly one entry — B's call. A made no
	// transport call on arrival 2, so its identity was never re-presented
	// to the silenced endpoint.
	require.Len(t, stack.identityLog, 2)
	assert.Equal(t, t08Identity, stack.identityLog[1])

	// Books stay honest: arrival 1 recorded its one real failure; the
	// arrival-2 admission refusal recorded nothing.
	a := stack.circuits.Breaker(circuit.EndpointKey("http://ep-a-joint"))
	assert.Equal(t, 1, a.Metrics().FailureCount,
		"the refusal is not booked as another failure")
	assert.Equal(t, circuit.StateOpen, a.State())
}

// TestN09P1T08_Recovery_RestartRebuiltStackReentersWithinContract restarts
// the process between two arrivals: every in-memory structure is rebuilt
// (fresh breaker map, fresh contract object, fresh endpoint state) and the
// client re-presents the SAME identity. The rebuilt stack re-executes the
// input command from the beginning — one consult for the fresh silent
// attempt — and the rebuilt books count only their own incident.
func TestN09P1T08_Recovery_RestartRebuiltStackReentersWithinContract(t *testing.T) {
	silent := func(int64) retry.Result { return retry.Result{Err: firstByteTimeout{}} }
	ok := func(int64) retry.Result { return retry.Result{StatusCode: http.StatusOK} }

	// First process: A silent, the verified contract permits advancing,
	// B serves. A's breaker records the failure and opens.
	ctx1, stack1 := t08NewStack(silent, ok, ok)
	proof1 := &jointProof{}
	exec1 := router.NewFallbackExecutor(jointResolver(), 5, nil).
		WithIdempotencyProof(proof1)
	_, code1, _, err1 := exec1.Execute(*ctx1, jointPrimary(), stack1.attempt)
	require.NoError(t, err1)
	assert.Equal(t, http.StatusOK, code1)
	assert.EqualValues(t, 1, proof1.consults.Load())
	assert.Equal(t, int64(1), stack1.probes["http://ep-a-joint"].count())
	a1 := stack1.circuits.Breaker(circuit.EndpointKey("http://ep-a-joint"))
	assert.Equal(t, 1, a1.Metrics().FailureCount)
	assert.Equal(t, circuit.StateOpen, a1.State())

	// Restart: fresh process, fresh structures, SAME identity. The dedup
	// contract carries the repeat permission for the new silent attempt.
	ctx2, stack2 := t08NewStack(silent, ok, ok)
	proof2 := &jointProof{}
	exec2 := router.NewFallbackExecutor(jointResolver(), 5, nil).
		WithIdempotencyProof(proof2)
	_, code2, attempts2, err2 := exec2.Execute(*ctx2, jointPrimary(), stack2.attempt)
	require.NoError(t, err2)
	assert.Equal(t, http.StatusOK, code2)
	require.Len(t, attempts2, 2)
	assert.EqualValues(t, 1, proof2.consults.Load(),
		"the fresh process consults the contract once for the fresh silent attempt")
	assert.Equal(t, int64(1), stack2.probes["http://ep-a-joint"].count(),
		"the restarted stack re-executes the command once from the beginning")

	// The identity is unchanged across both incarnations — the join key
	// every transport call presented, in both processes.
	require.Len(t, stack1.identityLog, 2)
	require.Len(t, stack2.identityLog, 2)
	both := append(append([]retry.RequestIdentity{}, stack1.identityLog...),
		stack2.identityLog...)
	for i, id := range both {
		assert.Equal(t, t08Identity, id,
			"transport call %d across the restart presents the same identity", i+1)
	}

	// Rebuilt books count only their own incident: the fresh breaker opens
	// on the fresh failure with a clean count — nothing bled across the
	// restart.
	a2 := stack2.circuits.Breaker(circuit.EndpointKey("http://ep-a-joint"))
	assert.Equal(t, 1, a2.Metrics().FailureCount)
	assert.Equal(t, circuit.StateOpen, a2.State())
}

// TestN09P1T08_Recovery_RestartedPartialStreamStaysTerminalWithoutContract
// pins the no-resume property for a stream that produced bytes and then
// broke mid-body, when no verified dedup contract exists: the caller's
// executed-evidence stops the intra-hop loop after the single attempt; the
// chain boundary re-derives the outcome to unknown (no HTTP answer arrived)
// and refuses the automatic repeat with the typed suppression. After a
// restart the fresh process re-dials once — the stream is never resumed
// mid-body and never replayed twice within one process.
func TestN09P1T08_Recovery_RestartedPartialStreamStaysTerminalWithoutContract(t *testing.T) {
	partial := func(int64) retry.Result {
		return retry.Result{
			Err:    jointPartialStreamError{bytes: 128},
			Safety: retry.OutcomeExecuted, // the caller observed the bytes
		}
	}
	ok := func(int64) retry.Result { return retry.Result{StatusCode: http.StatusOK} }

	// First process, NO contract wired: suppression, one call.
	ctx1, stack1 := t08NewStack(partial, ok, ok)
	exec1 := router.NewFallbackExecutor(jointResolver(), 5, nil)
	_, code1, attempts1, err1 := exec1.Execute(*ctx1, jointPrimary(), stack1.attempt)
	require.Error(t, err1)
	var suppressed *retry.SuppressedError
	require.ErrorAs(t, err1, &suppressed)
	assert.Equal(t, retry.OutcomeUnknown, suppressed.Outcome,
		"at the chain boundary the partial stream re-derives to unknown")
	assert.Equal(t, retry.SuppressedUnknownCode, suppressed.Code())
	assert.Equal(t, 0, code1)
	require.Len(t, attempts1, 1)
	var streamErr jointPartialStreamError
	require.ErrorAs(t, err1, &streamErr,
		"the executed-evidence cause stays reachable through the refusal")
	assert.Equal(t, int64(1), stack1.probes["http://ep-a-joint"].count(),
		"executed evidence stops the intra-hop loop after one attempt")
	require.Len(t, stack1.identityLog, 1)
	assert.Equal(t, t08Identity, stack1.identityLog[0])

	// Restart, still no contract: the fresh process re-dials A exactly
	// once — the interrupted stream is never resumed mid-body and never
	// replayed twice within one process.
	ctx2, stack2 := t08NewStack(partial, ok, ok)
	exec2 := router.NewFallbackExecutor(jointResolver(), 5, nil)
	_, _, attempts2, err2 := exec2.Execute(*ctx2, jointPrimary(), stack2.attempt)
	require.ErrorAs(t, err2, &suppressed)
	require.Len(t, attempts2, 1)
	assert.Equal(t, int64(1), stack2.probes["http://ep-a-joint"].count())
	a2 := stack2.circuits.Breaker(circuit.EndpointKey("http://ep-a-joint"))
	assert.Equal(t, 1, a2.Metrics().FailureCount,
		"the rebuilt breaker counts only its own incident")
}
