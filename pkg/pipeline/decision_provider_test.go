package pipeline

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeProvider is a test double for the DecisionProvider seam. It exists only
// to pin the fail-closed normalization contract — the core ships no external
// provider implementation.
type fakeProvider struct {
	verdict DecisionVerdict
	gotReq  DecisionRequest
	gotCtx  context.Context
}

func (f *fakeProvider) Decide(ctx context.Context, req DecisionRequest) DecisionVerdict {
	f.gotCtx, f.gotReq = ctx, req
	return f.verdict
}

func TestAuthorizationVerdictClassContract(t *testing.T) {
	for _, tc := range []struct {
		name  string
		v     AuthorizationVerdict
		class DecisionClass
	}{
		{"allowed", AuthorizationVerdict{Allowed: true, Reason: "ok"}, DecisionClassAllowed},
		{"evaluated deny", AuthorizationVerdict{Reason: "authorization condition denied"}, DecisionClassDenied},
		{"unavailable", AuthorizationVerdict{Reason: "mandatory authorization check failed", Err: errors.New("boom")}, DecisionClassUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.v.Class(); got != tc.class {
				t.Fatalf("class = %q, want %q", got, tc.class)
			}
		})
	}
}

func TestUnavailableDenyCarriesTypedClassAndSentinel(t *testing.T) {
	v := UnavailableDeny("evaluator down", errors.New("boom"))
	if v.Allowed {
		t.Fatal("unavailable deny must never allow")
	}
	if v.Class() != DecisionClassUnavailable {
		t.Fatalf("class = %q, want unavailable", v.Class())
	}
	if !errors.Is(v.Err, ErrDecisionUnavailable) {
		t.Fatalf("Err must wrap the sentinel: %v", v.Err)
	}
	if !strings.Contains(v.Err.Error(), "boom") {
		t.Fatalf("original cause must be preserved: %v", v.Err)
	}
	// A nil cause still yields the sentinel (never a nil Err on a failure class).
	if bare := UnavailableDeny("down", nil); !errors.Is(bare.Err, ErrDecisionUnavailable) {
		t.Fatalf("nil cause must resolve to the sentinel: %v", bare.Err)
	}
}

func TestDecideExternalFailsClosed(t *testing.T) {
	env := DecisionEnvironment{
		Principal: DecisionPrincipal{
			ID:   TrustedAttribute{Value: "u", Source: "s"},
			Kind: TrustedAttribute{Value: "human", Source: "s"},
		},
		Action:   TrustedAttribute{Value: "a", Source: "s"},
		Resource: DecisionResource{Type: TrustedAttribute{Value: "t", Source: "s"}, ID: TrustedAttribute{Value: "i", Source: "s"}, Organization: TrustedAttribute{Value: "o", Source: "s"}},
		Context:  map[string]TrustedAttribute{"deny": {Value: "false", Source: "s"}},
	}

	t.Run("zero providers: nil provider denies unavailable", func(t *testing.T) {
		v := DecideExternal(context.Background(), nil, env)
		if v.Allowed || v.Class() != DecisionClassUnavailable || !errors.Is(v.Err, ErrDecisionUnavailable) {
			t.Fatalf("nil provider must fail closed: %+v", v)
		}
	})

	t.Run("nil context denies unavailable without calling the provider", func(t *testing.T) {
		p := &fakeProvider{verdict: DecisionVerdict{Allowed: true, Reason: "allow"}}
		v := DecideExternal(deliberatelyNilContext(), p, env)
		if v.Allowed || v.Class() != DecisionClassUnavailable {
			t.Fatalf("nil context must fail closed: %+v", v)
		}
		if p.gotCtx != nil {
			t.Fatal("provider must not be called without a context")
		}
	})

	t.Run("typed request reaches the provider", func(t *testing.T) {
		p := &fakeProvider{verdict: DecisionVerdict{Allowed: true, Class: DecisionClassAllowed, Reason: "external allow"}}
		v := DecideExternal(context.Background(), p, env)
		if !v.Allowed || v.Reason != "external allow" {
			t.Fatalf("provider allow must pass through: %+v", v)
		}
		if p.gotReq.Environment.Action.Value != "a" {
			t.Fatalf("provider must receive the typed environment: %+v", p.gotReq)
		}
	})

	t.Run("out-of-contract allow-with-error normalizes to unavailable deny", func(t *testing.T) {
		p := &fakeProvider{verdict: DecisionVerdict{Allowed: true, Reason: "inconsistent", Err: errors.New("provider half-failed")}}
		v := DecideExternal(context.Background(), p, env)
		if v.Allowed || v.Class() != DecisionClassUnavailable {
			t.Fatalf("inconsistent allow must fail closed: %+v", v)
		}
		if !errors.Is(v.Err, ErrDecisionUnavailable) {
			t.Fatalf("normalized error must carry the sentinel: %v", v.Err)
		}
	})

	t.Run("allow flag with a denied class cannot widen to an allow", func(t *testing.T) {
		p := &fakeProvider{verdict: DecisionVerdict{Allowed: true, Class: DecisionClassDenied, Reason: "contradictory"}}
		v := DecideExternal(context.Background(), p, env)
		if v.Allowed {
			t.Fatalf("class is authoritative: a denied class must never project to an allow: %+v", v)
		}
		if v.Class() != DecisionClassUnavailable || !errors.Is(v.Err, ErrDecisionUnavailable) {
			t.Fatalf("mismatched allow/denied verdict must normalize to the fail-closed unavailable deny: %+v", v)
		}
	})

	t.Run("allow flag without a class cannot widen to an allow", func(t *testing.T) {
		p := &fakeProvider{verdict: DecisionVerdict{Allowed: true, Reason: "classless allow"}}
		v := DecideExternal(context.Background(), p, env)
		if v.Allowed {
			t.Fatalf("class is authoritative: an undefined class must never project to an allow: %+v", v)
		}
		if v.Class() != DecisionClassUnavailable || !errors.Is(v.Err, ErrDecisionUnavailable) {
			t.Fatalf("classless allow verdict must normalize to the fail-closed unavailable deny: %+v", v)
		}
	})

	t.Run("provider unavailability preserves the cause", func(t *testing.T) {
		p := &fakeProvider{verdict: DecisionVerdict{Class: DecisionClassUnavailable, Reason: "timeout", Err: context.DeadlineExceeded}}
		v := DecideExternal(context.Background(), p, env)
		if v.Allowed || v.Class() != DecisionClassUnavailable || !errors.Is(v.Err, context.DeadlineExceeded) {
			t.Fatalf("provider outage must stay unavailable with its cause: %+v", v)
		}
	})

	t.Run("evaluated denial stays denied (not unavailable)", func(t *testing.T) {
		p := &fakeProvider{verdict: DecisionVerdict{Reason: "refused"}}
		v := DecideExternal(context.Background(), p, env)
		if v.Allowed || v.Class() != DecisionClassDenied || v.Err != nil {
			t.Fatalf("evaluated denial must keep its class: %+v", v)
		}
	})
}

// scopedRuleProgram is a fake compiled deny rule over the shared decision
// environment (the real compiled-Expr path is exercised by the handlers
// tests, which compile the actual rule sources).
type scopedRuleProgram struct {
	match func(env ConditionEnv) bool
	err   error
}

func (p scopedRuleProgram) Evaluate(_ context.Context, env ConditionEnv) (bool, error) {
	if p.err != nil {
		return false, p.err
	}
	return p.match(env), nil
}

func contextFlag(t *testing.T, env ConditionEnv, name string) string {
	t.Helper()
	flag, ok := env.Decision.Context[name]
	if !ok {
		t.Fatalf("context flag %q missing", name)
	}
	return flag.Value
}

func TestEvaluateScopedAuthorizationAbsoluteDenyAndFailClosed(t *testing.T) {
	denyRule := ScopedDenyRule{Name: "explicit_policy_deny", Condition: scopedRuleProgram{
		match: func(env ConditionEnv) bool { return contextFlag(t, env, "deny") == "true" },
	}}
	grantProgram := evaluatorProgram{value: true}

	env := func(deny bool) DecisionEnvironment {
		return DecisionEnvironment{
			Principal: DecisionPrincipal{
				ID:   TrustedAttribute{Value: "u1", Source: "session"},
				Kind: TrustedAttribute{Value: "human", Source: "session"},
			},
			Action:   TrustedAttribute{Value: "requests.read_payloads", Source: "route"},
			Resource: DecisionResource{Type: TrustedAttribute{Value: "request", Source: "route"}, ID: TrustedAttribute{Value: "req-1", Source: "route"}, Organization: TrustedAttribute{Value: "org-1", Source: "route"}},
			Context: map[string]TrustedAttribute{
				"deny":  {Value: boolString(deny), Source: "policy"},
				"grant": {Value: boolString(true), Source: "grant"},
				"own":   {Value: "false", Source: "principal"},
				"role":  {Value: boolString(true), Source: "role-store"},
			},
		}
	}

	t.Run("matched deny rule is absolute: grant and role are not consulted", func(t *testing.T) {
		v := (Evaluator{}).EvaluateScopedAuthorization(context.Background(), []ScopedDenyRule{denyRule}, grantProgram, env(true))
		if v.Allowed || v.Err != nil {
			t.Fatalf("mandatory deny must be an evaluated refusal: %+v", v)
		}
		if v.Class() != DecisionClassDenied {
			t.Fatalf("class = %q, want denied", v.Class())
		}
		if !strings.Contains(v.Reason, "explicit_policy_deny") {
			t.Fatalf("deny reason must name the matched rule: %q", v.Reason)
		}
	})

	t.Run("no rule match falls through to the grant program", func(t *testing.T) {
		if v := (Evaluator{}).EvaluateScopedAuthorization(context.Background(), []ScopedDenyRule{denyRule}, grantProgram, env(false)); !v.Allowed {
			t.Fatalf("grant evidence must allow: %+v", v)
		}
		v := (Evaluator{}).EvaluateScopedAuthorization(context.Background(), []ScopedDenyRule{denyRule}, evaluatorProgram{value: false}, env(false))
		if v.Allowed || v.Class() != DecisionClassDenied || v.Reason != "authorization condition denied" {
			t.Fatalf("no evidence must deny: %+v", v)
		}
	})

	t.Run("deny-rule evaluation failure fails closed as unavailable", func(t *testing.T) {
		broken := ScopedDenyRule{Name: "broken_rule", Condition: scopedRuleProgram{err: errors.New("rule engine exploded")}}
		v := (Evaluator{}).EvaluateScopedAuthorization(context.Background(), []ScopedDenyRule{broken}, grantProgram, env(false))
		if v.Allowed || v.Class() != DecisionClassUnavailable || !errors.Is(v.Err, ErrDecisionUnavailable) {
			t.Fatalf("a broken deny rule must fail closed with grant+role present: %+v", v)
		}
		if !strings.Contains(v.Reason, "broken_rule") {
			t.Fatalf("failure reason must name the rule: %q", v.Reason)
		}
	})

	t.Run("invalid deny rule (nil condition) fails closed", func(t *testing.T) {
		v := (Evaluator{}).EvaluateScopedAuthorization(context.Background(), []ScopedDenyRule{{Name: "x"}}, grantProgram, env(false))
		if v.Allowed || v.Class() != DecisionClassUnavailable {
			t.Fatalf("invalid rule must fail closed: %+v", v)
		}
	})

	t.Run("untrusted input denies unavailable before any rule", func(t *testing.T) {
		bad := env(false)
		bad.Principal.ID.Source = ""
		v := (Evaluator{}).EvaluateScopedAuthorization(context.Background(), []ScopedDenyRule{denyRule}, grantProgram, bad)
		if v.Allowed || v.Class() != DecisionClassUnavailable {
			t.Fatalf("untrusted input must deny unavailable: %+v", v)
		}
	})

	t.Run("nil context is an availability failure, never an allow", func(t *testing.T) {
		v := (Evaluator{}).EvaluateScopedAuthorization(deliberatelyNilContext(), []ScopedDenyRule{denyRule}, grantProgram, env(false))
		if v.Allowed || v.Class() != DecisionClassUnavailable {
			t.Fatalf("nil context must fail closed: %+v", v)
		}
	})
}

// deliberatelyNilContext produces the "no context" input on purpose: the
// mandatory-check contract must turn it into an unavailable deny, never an
// allow (both callees explicitly guard nil — this is the negative test for
// that guard, not an accident SA1012 should flag).
func deliberatelyNilContext() context.Context { return nil }

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
