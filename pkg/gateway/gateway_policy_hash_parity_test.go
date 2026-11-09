package cli

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/pipeline"
)

// N02-P01-T06 acceptance: the gateway runtime, a simulator-style direct
// evaluation and any CLI consumer share one compiled snapshot identity
// (EffectivePolicyHash) and one condition evaluator. Identical policy state
// yields one hash and agreeing verdicts; a policy referencing an unknown
// field fails closed in every consumer with no divergence.

// conditionalDenyYAML returns an enforce policy whose contains-deny step is
// gated by an expr `when` condition (when_engine pinned — three engines are
// registered in the policy engine).
func conditionalDenyYAML(when string) string {
	return "apiVersion: ypp/v1\nkind: Policy\nname: cond-deny\nmode: enforce\nhooks: [pre_upstream]\nsteps:\n" +
		"  - id: gated\n    detector: builtin/contains\n    when: \"" + when + "\"\n    when_engine: expr\n" +
		"    params:\n      words: [\"forbidden-secret\"]\n      action: deny\n"
}

const (
	parityBody  = `{"messages":[{"role":"user","content":"give me the forbidden-secret"}]}`
	parityModel = "m"
)

// TestPolicyRuntimeEffectiveHashParityAcrossConsumers is the normal
// acceptance example: the compiled policy applied at the gateway produces the
// same verdict as a direct evaluation of the same compiled snapshot (the
// simulator path), and the decision record's effective hash equals the hash
// every consumer recomputes from the same (version, policy, pins) state.
func TestPolicyRuntimeEffectiveHashParityAcrossConsumers(t *testing.T) {
	policyYAML := conditionalDenyYAML("Meta.Model == '" + parityModel + "'")
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "cond-1", OrgID: testOrg, Name: "cond-deny", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: policyYAML}, []adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	gw := testHookGateway(rt)

	// Runtime path: the gated deny fires for the matching model.
	body := []byte(parityBody)
	w, r := policyRequest(string(body))
	_, policyEvent, ok := gw.policyPreUpstream(w, r, "chat", parityModel, "openai", body)
	if ok {
		t.Fatalf("runtime must deny the gated match, got pass-through (%s)", w.Body.String())
	}
	decisions := parseDecisions(t, policyEvent)
	if len(decisions) != 1 || decisions[0].Verdict != "deny" {
		t.Fatalf("runtime decisions = %+v, want one deny", decisions)
	}
	if decisions[0].EffectiveHash == "" || len(decisions[0].EffectiveHash) != 64 {
		t.Fatalf("decision effective hash = %q, want a 64-char digest", decisions[0].EffectiveHash)
	}

	// Consumer-side recomputation: parse the same stored YAML and hash the
	// same snapshot state (version 1, no prompt pins — nil map).
	pp, err := pipeline.ParsePolicy([]byte(policyYAML))
	if err != nil {
		t.Fatalf("parse stored policy: %v", err)
	}
	recomputed := pipeline.EffectivePolicyHash(1, pp, nil)
	if recomputed != decisions[0].EffectiveHash {
		t.Fatalf("hash divergence for identical state: runtime %q != consumer %q", decisions[0].EffectiveHash, recomputed)
	}

	// Simulator path: a direct engine run over the same compiled snapshot
	// and the identical payload agrees with the runtime verdict.
	eng, err := newPolicyEngine(nil, testLogger())
	if err != nil {
		t.Fatalf("simulator engine: %v", err)
	}
	compiled, err := eng.CompilePolicy(pp)
	if err != nil {
		t.Fatalf("simulator compile: %v", err)
	}
	payload := policyRequestPayload("chat", body, policyMeta(testOrg, "key-1", parityModel, "openai"))
	res := eng.Run(context.Background(), []pipeline.Compiled{compiled}, payload)
	if string(res.Verdict) != decisions[0].Verdict {
		t.Fatalf("simulator verdict %q diverges from runtime verdict %q", res.Verdict, decisions[0].Verdict)
	}

	// Divergent states never share the identity: another `when` rule and a
	// bumped version both hash differently.
	otherRule, err := pipeline.ParsePolicy([]byte(conditionalDenyYAML("Meta.Model == 'other'")))
	if err != nil {
		t.Fatalf("parse divergent policy: %v", err)
	}
	if got := pipeline.EffectivePolicyHash(1, otherRule, nil); got == decisions[0].EffectiveHash {
		t.Fatal("rule change did not change the effective hash")
	}
	if got := pipeline.EffectivePolicyHash(2, pp, nil); got == decisions[0].EffectiveHash {
		t.Fatal("version change did not change the effective hash")
	}

	// Same compiled snapshot, non-matching condition: the runtime lets the
	// request through and the simulator agrees (verdict parity both ways).
	w2, r2 := policyRequest(string(body))
	body2, _, ok2 := gw.policyPreUpstream(w2, r2, "chat", "other-model", "openai", body)
	if !ok2 {
		t.Fatalf("non-matching condition must pass through, got %d %s", w2.Code, w2.Body.String())
	}
	if string(body2) != string(body) {
		t.Fatal("pass-through must not mutate the payload")
	}
	payload2 := policyRequestPayload("chat", body, policyMeta(testOrg, "key-1", "other-model", "openai"))
	res2 := eng.Run(context.Background(), []pipeline.Compiled{compiled}, payload2)
	if res2.Verdict == pipeline.ActionDeny {
		t.Fatalf("simulator denied the non-matching condition: %+v", res2)
	}
}

// TestPolicyRuntimeNoPoliciesPassthroughStableHash is the empty acceptance
// example: an org with no policies is a pass-through (no decisions, no
// denial, unchanged payload) and the empty snapshot state has one stable
// identity for every consumer.
func TestPolicyRuntimeNoPoliciesPassthroughStableHash(t *testing.T) {
	rt := newTestRuntime(t, newFakePolicyStore(), &fakePolicyVersions{}, PolicyModeEnforce)
	gw := testHookGateway(rt)

	body := []byte(parityBody)
	w, r := policyRequest(string(body))
	got, policyEvent, ok := gw.policyPreUpstream(w, r, "chat", parityModel, "openai", body)
	if !ok {
		t.Fatalf("no policies must pass through, got %d %s", w.Code, w.Body.String())
	}
	if string(got) != string(body) {
		t.Fatal("pass-through must not mutate the payload")
	}
	if decisions := parseDecisions(t, policyEvent); len(decisions) != 0 {
		t.Fatalf("no policies must record no decisions, got %+v", decisions)
	}

	// The empty state hashes identically for independent consumers and stays
	// stable across repeats.
	empty := pipeline.EffectivePolicyHash(0, pipeline.Policy{}, nil)
	if empty == "" || empty != pipeline.EffectivePolicyHash(0, pipeline.Policy{}, map[string]string{}) {
		t.Fatalf("empty-state hash unstable or degenerate: %q", empty)
	}
}

// TestPolicyRuntimeUnknownConditionFieldFailsClosedEverywhere is the
// adversarial acceptance example: a policy whose `when` references an unknown
// field is rejected by every consumer of the shared compiler/evaluator — the
// runtime load fails as a whole, the gateway answers 503 instead of serving
// unprotected, and a simulator/CLI consumer compiling the same YAML hits the
// same rejection. No consumer diverges into fail-open.
func TestPolicyRuntimeUnknownConditionFieldFailsClosedEverywhere(t *testing.T) {
	policyYAML := conditionalDenyYAML("NoSuchField == 1")

	// Consumer-side compile (simulator/CLI path): rejected at compile time.
	eng, err := newPolicyEngine(nil, testLogger())
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	pp, err := pipeline.ParsePolicy([]byte(policyYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := eng.CompilePolicy(pp); err == nil {
		t.Fatal("simulator compile of an unknown-field condition must fail")
	}

	// Runtime load: the org snapshot fails as a whole, with no partial plans.
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "bad-cond-1", OrgID: testOrg, Name: "cond-deny", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: policyYAML}, []adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	plans, _, err := rt.load(context.Background(), testOrg)
	if err == nil {
		t.Fatal("runtime load of an unknown-field condition must fail")
	}
	if len(plans) != 0 {
		t.Fatalf("failed load returned %d partial plans, want none", len(plans))
	}

	// Request path: enforce mode fails closed with an explicit 503, it never
	// serves the request without the policy.
	gw := testHookGateway(rt)
	body := []byte(parityBody)
	w, r := policyRequest(string(body))
	_, _, ok := gw.policyPreUpstream(w, r, "chat", parityModel, "openai", body)
	if ok {
		t.Fatal("unknown-field policy must fail closed, got pass-through")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 policy configuration unavailable", w.Code)
	}
	if !strings.Contains(w.Body.String(), "policy_configuration_unavailable") {
		t.Fatalf("body = %s, want the policy_configuration_unavailable code", w.Body.String())
	}
}
