package router_test

// N09-P01-T09 [compatibility] — old/new configuration walk for pkg/router.
//
// The walk drives the real FallbackExecutor over the composed joint stack
// (breaker admission + classified retry + evidence loss, the T06 production
// hop shape) with the historical construction shapes and the new option
// surface side by side:
//
//	legacy construction   NewFallbackExecutor(res, 3, nil), no options —
//	                      unknown outcomes stay suppressed (pre-proof parity)
//	legacy call shape     maxHops 0 / negative — defaulted to 3 candidates
//	nil option tolerance  WithClassifier(nil).WithIdempotencyProof(nil) —
//	                      receiver returned, defaults intact
//	new hint surface      ExecuteWithProviderHint reorder — must not bypass
//	                      the pinned err-rule-dominates chain contract
//
// Reused lane-pinned contracts: StatusCode==0 unknown-outcome suppression
// (T04), maxHops queue bound, err-rule-dominates beside a dedup contract
// (T06). Existing hint-refusal coverage (fallback_hint_test) is not repeated.

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/router"
)

// t09FailIfDialed is a probe behaviour for candidates a legacy walk must
// never reach; any call fails the test loudly.
func t09FailIfDialed(t *testing.T) func(int64) retry.Result {
	t.Helper()
	return func(int64) retry.Result {
		t.Error("candidate was dialed but the chain must have stopped earlier")
		return retry.Result{StatusCode: http.StatusOK}
	}
}

// t09Always503 scripts a retryable upstream overload.
func t09Always503(int64) retry.Result {
	return retry.Result{StatusCode: http.StatusServiceUnavailable}
}

// TestN09P1T09_Compat_LegacyConstructionKeepsUnknownOutcomeSuppressed pins
// the historical construction — no With* options at all — over the joint
// stack: a silent first candidate is terminal, the typed suppression
// surfaces with the unknown-outcome code, the original transport cause stays
// reachable, exactly one attempt is traced and the failover siblings are
// never dialed. Absence of the new options changes nothing for old call sites.
func TestN09P1T09_Compat_LegacyConstructionKeepsUnknownOutcomeSuppressed(t *testing.T) {
	ctx, stack := newJointStack(jointProbes(
		func(int64) retry.Result { return retry.Result{Err: firstByteTimeout{}} },
		t09FailIfDialed(t),
		t09FailIfDialed(t),
	))

	fe := router.NewFallbackExecutor(jointResolver(), 3, nil) // pre-proof call shape
	_, code, attempts, err := fe.Execute(*ctx, jointPrimary(), stack.attempt)

	if code != 0 {
		t.Fatalf("suppressed silent attempt: status %d, want 0", code)
	}
	var suppressed *retry.SuppressedError
	if !errors.As(err, &suppressed) {
		t.Fatalf("legacy construction: want *retry.SuppressedError, got %T (%v)", err, err)
	}
	if suppressed.Code() != retry.SuppressedUnknownCode {
		t.Fatalf("suppression code %q, want %q", suppressed.Code(), retry.SuppressedUnknownCode)
	}
	if suppressed.Outcome != retry.OutcomeUnknown {
		t.Fatalf("suppression outcome %s, want unknown", suppressed.Outcome)
	}
	if !errors.Is(err, firstByteTimeout{}) {
		t.Fatalf("original transport cause not reachable through suppression: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("attempts: got %d, want 1", len(attempts))
	}
	if attempts[0].Outcome != retry.OutcomeUnknown.String() {
		t.Fatalf("attempt outcome %q, want %q", attempts[0].Outcome, retry.OutcomeUnknown.String())
	}
	if attempts[0].RequestID != jointStoryIdentity.RequestID {
		t.Fatalf("attempt identity %q, want %q", attempts[0].RequestID, jointStoryIdentity.RequestID)
	}
	if stack.probes["http://ep-b-joint"].count() != 0 || stack.probes["http://ep-c-joint"].count() != 0 {
		t.Fatal("failover siblings were dialed despite the suppressed unknown outcome")
	}
}

// TestN09P1T09_Compat_UnsetMaxHopsWalksThreeCandidates pins the legacy call
// shape NewFallbackExecutor(res, 0, nil) (and any negative hop budget): the
// bound defaults to three candidates over a four-deep chain — the fourth is
// reachable only when the caller asks for it.
func TestN09P1T09_Compat_UnsetMaxHopsWalksThreeCandidates(t *testing.T) {
	res := newFakeResolver(map[string]resolver.ModelInfo{
		"t09-hop1": {ModelName: "t09-hop1", Provider: "prov-b", UpstreamURL: "http://ep-t09-1", Enabled: true},
		"t09-hop2": {ModelName: "t09-hop2", Provider: "prov-c", UpstreamURL: "http://ep-t09-2", Enabled: true},
		"t09-hop3": {ModelName: "t09-hop3", Provider: "prov-d", UpstreamURL: "http://ep-t09-3", Enabled: true},
	})
	primary := resolver.ModelInfo{
		ModelName:      "t09-hop0",
		Provider:       "prov-a",
		UpstreamURL:    "http://ep-t09-0",
		FailoverModels: []string{"t09-hop1", "t09-hop2", "t09-hop3"},
	}
	newStack := func() (*context.Context, *jointStack) {
		return newJointStack(map[string]*jointEndpoint{
			"http://ep-t09-0": {behave: t09Always503},
			"http://ep-t09-1": {behave: t09Always503},
			"http://ep-t09-2": {behave: t09Always503},
			"http://ep-t09-3": {behave: t09Always503},
		})
	}

	t.Run("maxHops 0 defaults to three", func(t *testing.T) {
		ctx, stack := newStack()
		_, code, attempts, err := router.NewFallbackExecutor(res, 0, nil).Execute(*ctx, primary, stack.attempt)
		if err == nil || code != http.StatusServiceUnavailable {
			t.Fatalf("exhausted chain: code %d err %v, want 503", code, err)
		}
		if len(attempts) != 3 {
			t.Fatalf("maxHops 0: walked %d candidates, want 3", len(attempts))
		}
		if attempts[2].UpstreamURL != "http://ep-t09-2" {
			t.Fatalf("third candidate %q, want http://ep-t09-2", attempts[2].UpstreamURL)
		}
	})

	t.Run("negative maxHops defaults to three", func(t *testing.T) {
		ctx, stack := newStack()
		_, _, attempts, _ := router.NewFallbackExecutor(res, -2, nil).Execute(*ctx, primary, stack.attempt)
		if len(attempts) != 3 {
			t.Fatalf("maxHops -2: walked %d candidates, want 3", len(attempts))
		}
	})

	t.Run("explicit four-hop budget reaches the fourth candidate", func(t *testing.T) {
		ctx, stack := newStack()
		_, _, attempts, _ := router.NewFallbackExecutor(res, 4, nil).Execute(*ctx, primary, stack.attempt)
		if len(attempts) != 4 {
			t.Fatalf("maxHops 4: walked %d candidates, want 4", len(attempts))
		}
	})
}

// TestN09P1T09_Compat_NilOptionsIgnoredKeepsDefaults pins option-call
// tolerance: WithClassifier(nil) and WithIdempotencyProof(nil) return the
// receiver and change nothing — the default classifier still terminates the
// chain on a definitive 4xx answer and the absent proof still suppresses
// unknown outcomes.
func TestN09P1T09_Compat_NilOptionsIgnoredKeepsDefaults(t *testing.T) {
	fe := router.NewFallbackExecutor(newFakeResolver(nil), 3, nil)
	if got := fe.WithClassifier(nil).WithIdempotencyProof(nil); got != fe {
		t.Fatal("nil-option builders must return the receiver, got a new executor")
	}

	t.Run("default classifier still stops on definitive 4xx", func(t *testing.T) {
		calls := 0
		_, code, attempts, err := fe.Execute(context.Background(), resolver.ModelInfo{ModelName: "t09-4xx"},
			func(context.Context, resolver.ModelInfo) (int, error) {
				calls++
				return http.StatusBadRequest, nil
			})
		if err != nil || code != http.StatusBadRequest {
			t.Fatalf("4xx walk: code %d err %v, want 400 and nil error", code, err)
		}
		if calls != 1 || len(attempts) != 1 {
			t.Fatalf("4xx walk: calls %d attempts %d, want 1/1", calls, len(attempts))
		}
	})

	t.Run("nil proof keeps unknown outcomes terminal", func(t *testing.T) {
		calls := 0
		silent := errors.New("silent upstream failure")
		_, code, attempts, err := fe.Execute(context.Background(), resolver.ModelInfo{ModelName: "t09-silent"},
			func(context.Context, resolver.ModelInfo) (int, error) {
				calls++
				return 0, silent
			})
		var suppressed *retry.SuppressedError
		if !errors.As(err, &suppressed) {
			t.Fatalf("nil proof: want suppression, got %T (%v)", err, err)
		}
		if code != 0 || calls != 1 || len(attempts) != 1 {
			t.Fatalf("nil proof: code %d calls %d attempts %d, want 0/1/1", code, calls, len(attempts))
		}
		if !errors.Is(err, silent) {
			t.Fatalf("cause not reachable through suppression: %v", err)
		}
	})
}

// TestN09P1T09_Compat_HintReorderKeepsErrRuleDominates walks the new hint
// surface together with the pinned err-rule-dominates contract: a valid
// provider hint reorders the chain so the denied candidate is attempted
// first, and the 403 policy denial is still chain-terminal — one attempt,
// the policy error surfacing unchanged, siblings never dialed and the dedup
// contract never consulted.
func TestN09P1T09_Compat_HintReorderKeepsErrRuleDominates(t *testing.T) {
	ctx, stack := newJointStack(jointProbes(
		t09FailIfDialed(t), // ep-a — reordered behind the hint, never reached
		t09FailIfDialed(t), // ep-b
		func(int64) retry.Result { // ep-c — hinted first, denied by policy
			return retry.Result{
				StatusCode: http.StatusForbidden,
				Err: &router.PolicyError{
					Status:  http.StatusForbidden,
					ErrType: "invalid_request_error",
					ErrCode: "policy_denied",
					Message: "denied by the per-attempt policy gate",
				},
			}
		},
	))

	proof := &jointProof{}
	exec := router.NewFallbackExecutor(jointResolver(), 5, nil).WithIdempotencyProof(proof)

	final, code, attempts, err := exec.ExecuteWithProviderHint(*ctx, jointPrimary(), "prov-c", stack.attempt)

	if code != http.StatusForbidden {
		t.Fatalf("hinted denial: code %d, want 403", code)
	}
	var policyErr *router.PolicyError
	if !errors.As(err, &policyErr) || policyErr.ErrCode != "policy_denied" {
		t.Fatalf("hinted denial: want PolicyError policy_denied, got %T (%v)", err, err)
	}
	if len(attempts) != 1 {
		t.Fatalf("hinted denial: %d attempts, want 1 (terminal beside the hint reorder)", len(attempts))
	}
	if attempts[0].UpstreamURL != "http://ep-c-joint" {
		t.Fatalf("hint reorder ignored: first attempt hit %q, want the hinted ep-c", attempts[0].UpstreamURL)
	}
	if final.Provider != "prov-c" {
		t.Fatalf("final provider %q, want prov-c", final.Provider)
	}
	if stack.probes["http://ep-a-joint"].count() != 0 || stack.probes["http://ep-b-joint"].count() != 0 {
		t.Fatal("chain advanced past a policy denial under the hint reorder")
	}
	if proof.consults.Load() != 0 {
		t.Fatalf("dedup contract consulted %d times for a policy outcome, want 0", proof.consults.Load())
	}
}
