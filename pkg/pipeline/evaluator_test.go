package pipeline

import (
	"context"
	"errors"
	"testing"
)

type evaluatorProgram struct {
	value bool
	err   error
	check func(ConditionEnv)
}

func (p evaluatorProgram) Evaluate(_ context.Context, env ConditionEnv) (bool, error) {
	if p.check != nil {
		p.check(env)
	}
	return p.value, p.err
}

func trustedDecisionInput() DecisionEnvironment {
	return DecisionEnvironment{
		Principal: DecisionPrincipal{
			ID:   TrustedAttribute{Value: "agent-7", Source: "identity-service"},
			Kind: TrustedAttribute{Value: "agent", Source: "identity-service"},
		},
		Action: TrustedAttribute{Value: "history.read", Source: "request-authorizer"},
		Resource: DecisionResource{
			Type:         TrustedAttribute{Value: "request", Source: "history-index"},
			ID:           TrustedAttribute{Value: "request-7", Source: "history-index"},
			Organization: TrustedAttribute{Value: "org-B", Source: "tenant-resolver"},
		},
		Context: map[string]TrustedAttribute{"environment": {Value: "prod", Source: "deployment-config"}},
	}
}

func TestEvaluatorKeepsDomainVerdictsSeparate(t *testing.T) {
	evaluator := Evaluator{}
	input := trustedDecisionInput()
	program := evaluatorProgram{value: false}

	authorization := evaluator.EvaluateAuthorization(context.Background(), program, input)
	if authorization.Allowed || authorization.Err != nil || authorization.Reason == "" {
		t.Fatalf("authorization verdict=%+v, want explicit deny", authorization)
	}
	guardrail := evaluator.EvaluateGuardrail(context.Background(), program, input)
	if !guardrail.Continue || guardrail.Err != nil || guardrail.Reason == "" {
		t.Fatalf("guardrail verdict=%+v, want continue for non-match", guardrail)
	}
	routing := evaluator.EvaluateRouting(context.Background(), []RouteCandidate{
		{Name: "model-a", Condition: program},
		{Name: "model-b", Condition: evaluatorProgram{value: true}},
	}, input)
	if routing.Route != "model-b" || routing.Err != nil {
		t.Fatalf("routing decision=%+v, want model-b", routing)
	}
}

func TestEvaluatorFailsClosedOnUnavailableMandatoryCheck(t *testing.T) {
	evaluator := Evaluator{}
	input := trustedDecisionInput()
	input.Principal.ID.Source = ""
	verdict := evaluator.EvaluateAuthorization(context.Background(), evaluatorProgram{value: true}, input)
	if verdict.Allowed || verdict.Err == nil || verdict.Reason == "" {
		t.Fatalf("untrusted authorization input verdict=%+v, want deny with cause", verdict)
	}

	input = trustedDecisionInput()
	verdict = evaluator.EvaluateAuthorization(context.Background(), evaluatorProgram{err: errors.New("evaluator unavailable")}, input)
	if verdict.Allowed || verdict.Err == nil {
		t.Fatalf("unavailable authorization verdict=%+v, want deny", verdict)
	}
	guardrail := evaluator.EvaluateGuardrail(context.Background(), evaluatorProgram{err: errors.New("mandatory detector failed")}, input)
	if guardrail.Continue || guardrail.Err == nil {
		t.Fatalf("failed guardrail verdict=%+v, want blocked", guardrail)
	}
	routing := evaluator.EvaluateRouting(context.Background(), []RouteCandidate{
		{Name: "primary", Condition: evaluatorProgram{err: errors.New("condition failed")}},
		{Name: "fallback", Condition: evaluatorProgram{value: true}},
	}, input)
	if routing.Route != "" || routing.Err == nil {
		t.Fatalf("failed route decision=%+v, want no route", routing)
	}
}

func TestEvaluatorProvidesTypedTrustedEnvironment(t *testing.T) {
	var seen bool
	program := evaluatorProgram{value: true, check: func(env ConditionEnv) {
		if env.Decision == nil {
			return
		}
		seen = env.Decision.Principal.ID.Value == "agent-7" &&
			env.Decision.Action.Value == "history.read" &&
			env.Decision.Resource.Organization.Value == "org-B" &&
			env.Decision.Context["environment"].Value == "prod"
	}}
	verdict := (Evaluator{}).EvaluateAuthorization(context.Background(), program, trustedDecisionInput())
	if !verdict.Allowed || !seen {
		t.Fatalf("typed environment not delivered: verdict=%+v seen=%t", verdict, seen)
	}
}
