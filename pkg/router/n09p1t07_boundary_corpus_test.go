package router_test

// N09-P01-T07 boundary regression corpus — the chain executor seam
// (pkg/router).
//
// The executor's unit guarantees are pinned by fallback_outcome_test.go,
// fallback_identity_test.go, fallback_policy_test.go and the negative
// battery; the composed story by T06 (n09p1t06_joint_scenario_test.go).
// This corpus adds the regression dimension between those two levels: the
// CHAIN-SCALE boundary of the counting honesty rules and the terminality of
// wrapped rights refusals.
//
// Three properties are pinned here:
//  1. With a contract that permits every advance, the consult count scales
//     with the number of SILENT attempts (one consult each), the transport
//     call count stays one per candidate, and when the chain exhausts the
//     final error is the executor's exhaustion report for the last
//     candidate — a fallbackError, NOT a SuppressedError (no refusal was
//     ever issued; the typed suppression envelope stays refusal-only).
//     Re-pinned after N07-P01-T05 (commit 8ea0c25): the exhaustion wrap
//     preserves the typed transport cause via Unwrap so downstream layers
//     (the gateway's client-facing render, the journal writer) can still
//     classify it. The original "message-only exhaustion report" pin
//     predated that change and is superseded by it; what remains
//     refusal-only is the SuppressedError envelope, not cause reachability.
//  2. A rights refusal wrapped arbitrarily deep by intermediate layers
//     stays terminal on the first attempt: DefaultRetryable and the
//     executor's terminal gate both resolve the cause through errors.As.
//  3. A declining contract is consulted exactly once (its refusal is its
//     own answer) and then the typed suppression surfaces with the cause
//     reachable — the refusal is never mistaken for silence.

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/circuit"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/router"
)

// TestN09P1T07_Boundary_AllSilentChainScalesCountsHonesty walks the T06
// story's three-candidate chain with EVERY candidate silent and a contract
// that permits every advance. The counts are the regression boundary: three
// transport calls (one per candidate), three contract consults (one per
// silent attempt), one stable identity on every call, one recorded failure
// and an open breaker per dialed endpoint — and no refusal envelope,
// because the contract permitted the whole walk.
func TestN09P1T07_Boundary_AllSilentChainScalesCountsHonesty(t *testing.T) {
	ctx, stack := newJointStack(jointProbes(
		func(int64) retry.Result { return retry.Result{Err: firstByteTimeout{}} },
		func(int64) retry.Result { return retry.Result{Err: firstByteTimeout{}} },
		func(int64) retry.Result { return retry.Result{Err: firstByteTimeout{}} },
	))

	proof := &jointProof{}
	exec := router.NewFallbackExecutor(jointResolver(), 5, nil).
		WithIdempotencyProof(proof)
	_, code, attempts, err := exec.Execute(*ctx, jointPrimary(), stack.attempt)

	// The chain exhausted: the contract permitted every advance, so nothing
	// was refused — the final error is the exhaustion report for the last
	// candidate, not a suppression.
	require.Error(t, err)
	require.ErrorContains(t, err, "joint-third",
		"the exhaustion report names the last candidate")
	assert.Equal(t, 0, code)
	var suppressed *retry.SuppressedError
	assert.NotErrorAs(t, err, &suppressed,
		"a contract-permitted walk to exhaustion issues no refusal envelope")
	var fbt firstByteTimeout
	require.ErrorAs(t, err, &fbt,
		"the exhaustion wrap keeps the typed cause reachable for downstream classification (N07-P01-T05, commit 8ea0c25: the gateway renders the client-facing reason after chain exhaustion)")

	// Count honesty at chain scale: one transport call per candidate, and
	// one consult per silent attempt — three of each.
	require.Len(t, attempts, 3)
	assert.Equal(t, int64(1), stack.probes["http://ep-a-joint"].count())
	assert.Equal(t, int64(1), stack.probes["http://ep-b-joint"].count())
	assert.Equal(t, int64(1), stack.probes["http://ep-c-joint"].count())
	assert.Equal(t, int64(3), proof.consults.Load(),
		"consults scale with silent attempts, never with chain length or retry budget")
	require.Len(t, stack.identityLog, 3)
	for i, id := range stack.identityLog {
		assert.Equal(t, jointStoryIdentity, id,
			"transport call %d must present the unchanged boundary identity", i+1)
	}

	// Evidence honesty: every advanced attempt is unknown-outcome, attempts
	// stay contiguous, and one request identity stamps the whole trace.
	for i, o := range attempts {
		assert.Equal(t, i+1, o.Attempt)
		assert.Equal(t, jointStoryIdentity.RequestID, o.RequestID)
		assert.Equal(t, retry.OutcomeUnknown.String(), o.Outcome,
			"attempt %d stayed honest about its unknown outcome", i+1)
	}

	// Circuit consumer honesty: every dialed endpoint recorded its one real
	// failure and is open (threshold 1); none was spared the record.
	assert.Equal(t, 3, stack.circuits.Len())
	for _, url := range []string{"http://ep-a-joint", "http://ep-b-joint", "http://ep-c-joint"} {
		b := stack.circuits.Breaker(circuit.EndpointKey(url))
		assert.Equal(t, 1, b.Metrics().FailureCount, "%s recorded its failure", url)
		assert.Equal(t, circuit.StateOpen, b.State(), "%s is open after its failure", url)
	}
}

// TestN09P1T07_Boundary_WrappedPolicyErrorStaysChainTerminal pins that a
// rights refusal survives arbitrary wrapping by intermediate layers: the
// executor's terminal gate resolves the cause through errors.As, stops the
// chain on the first attempt, never consults the dedup contract and never
// dials the next candidate — and surfaces the original PolicyError with its
// status and machine-readable code intact. The refusal is handed to the
// executor at the attempt boundary (the chain contract), so this test uses
// a bare attempt closure: the intra-hop retry loop's treatment of
// (status, err) pairs is the retry seam's own corpus, not this boundary.
func TestN09P1T07_Boundary_WrappedPolicyErrorStaysChainTerminal(t *testing.T) {
	denied := &router.PolicyError{
		Status:  http.StatusForbidden,
		ErrType: "permission_denied_error",
		ErrCode: "model_not_allowed",
		Message: "model not allowed for org",
	}
	tests := []struct {
		name string
		wrap func() error
	}{
		{name: "raw policy error", wrap: func() error { return denied }},
		{name: "single wrap", wrap: func() error {
			return fmt.Errorf("hop failed: %w", denied)
		}},
		{name: "double wrap", wrap: func() error {
			return fmt.Errorf("layer one: %w", fmt.Errorf("layer two: %w", denied))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probeErr := tt.wrap()
			probes := jointProbes(
				func(int64) retry.Result {
					return retry.Result{StatusCode: http.StatusForbidden, Err: probeErr}
				},
				func(int64) retry.Result {
					t.Error("the next candidate must never be dialed past a wrapped rights refusal")
					return retry.Result{StatusCode: http.StatusOK}
				},
				func(int64) retry.Result {
					t.Error("the third candidate must never be dialed past a wrapped rights refusal")
					return retry.Result{StatusCode: http.StatusOK}
				},
			)
			// Bare attempt boundary: no retry loop, no breaker — exactly the
			// (status, error) pair the executor's terminal gate consumes.
			attempt := func(ctx context.Context, mi resolver.ModelInfo) (int, error) {
				if err := ctx.Err(); err != nil {
					return 0, err
				}
				probe := probes[mi.UpstreamURL]
				res := probe.result(ctx, mi)
				if res.Err != nil {
					return res.StatusCode, res.Err
				}
				if res.StatusCode >= http.StatusBadRequest {
					return res.StatusCode, fmt.Errorf("upstream error %d", res.StatusCode)
				}
				return res.StatusCode, nil
			}

			proof := &countingProof{}
			exec := router.NewFallbackExecutor(jointResolver(), 5, nil).
				WithIdempotencyProof(proof)
			_, code, attempts, err := exec.Execute(context.Background(), jointPrimary(), attempt)

			require.Error(t, err)
			assert.Equal(t, http.StatusForbidden, code,
				"the refusal's status surfaces unchanged through any wrapping")
			require.Len(t, attempts, 1, "the chain stops on the first attempt")
			var pe *router.PolicyError
			require.ErrorAs(t, err, &pe,
				"the rights refusal stays typed through any wrapping")
			assert.Equal(t, "model_not_allowed", pe.ErrCode)
			assert.Equal(t, http.StatusForbidden, pe.Status)
			var sup *retry.SuppressedError
			assert.NotErrorAs(t, err, &sup,
				"a definitive refusal is a policy verdict, never a suppression")

			assert.Equal(t, 0, proof.consults,
				"a definitive HTTP answer never reaches the dedup contract")
			assert.Equal(t, int64(1), probes["http://ep-a-joint"].count())
			assert.Equal(t, int64(0), probes["http://ep-b-joint"].count(),
				"the fallback candidate is never dialed")
		})
	}
}

// t07DecliningProof is a verified contract whose verified answer is NO: it
// counts consults so the corpus can pin that the refusal was actually
// asked, exactly once.
type t07DecliningProof struct{ consults int }

func (p *t07DecliningProof) AllowsRetry() bool { p.consults++; return false }

// TestN09P1T07_Boundary_DecliningContractIsConsultedThenRefuses pins the
// declining-contract boundary: the contract is consulted exactly once (its
// refusal is its own answer, not an absence of consultation), the advance
// is refused, the typed suppression surfaces with the unknown-outcome code
// and the original cause stays reachable for the journal writer.
func TestN09P1T07_Boundary_DecliningContractIsConsultedThenRefuses(t *testing.T) {
	ctx, stack := newJointStack(jointProbes(
		func(int64) retry.Result { return retry.Result{Err: firstByteTimeout{}} },
		func(int64) retry.Result {
			t.Error("a declining contract must close the chain before the next candidate")
			return retry.Result{StatusCode: http.StatusOK}
		},
		func(int64) retry.Result {
			t.Error("the third candidate must never be dialed past a declined advance")
			return retry.Result{StatusCode: http.StatusOK}
		},
	))

	proof := &t07DecliningProof{}
	exec := router.NewFallbackExecutor(jointResolver(), 5, nil).
		WithIdempotencyProof(proof)
	_, code, attempts, err := exec.Execute(*ctx, jointPrimary(), stack.attempt)

	require.Error(t, err)
	assert.Equal(t, 0, code)
	var sup *retry.SuppressedError
	require.ErrorAs(t, err, &sup, "the refusal is the typed explanation")
	assert.Equal(t, retry.SuppressedUnknownCode, sup.Code())
	assert.Equal(t, "joint-primary", sup.Model,
		"the refusal names exactly the suppressed candidate")
	assert.Equal(t, 1, proof.consults,
		"the declining contract was consulted exactly once — its no is an answer, not silence")
	require.Len(t, attempts, 1)
	var fbt firstByteTimeout
	require.ErrorAs(t, err, &fbt,
		"the suppression keeps the original cause reachable (errors.As discipline)")
	assert.Equal(t, int64(1), stack.probes["http://ep-a-joint"].count())
	assert.Equal(t, int64(0), stack.probes["http://ep-b-joint"].count())
	assert.Equal(t, 1, stack.circuits.Len())
}
