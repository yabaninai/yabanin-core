package pipeline

import (
	"context"
	"errors"
	"fmt"
)

// TrustedAttribute carries a value and the trusted system that supplied it.
// Caller-provided values must not be marked trusted by blindly copying request
// payload fields into this structure.
type TrustedAttribute struct {
	Value  string
	Source string
}

// DecisionPrincipal identifies the actor for a policy decision.
type DecisionPrincipal struct {
	ID   TrustedAttribute
	Kind TrustedAttribute
}

// DecisionResource identifies the object on which an action operates.
type DecisionResource struct {
	Type         TrustedAttribute
	ID           TrustedAttribute
	Organization TrustedAttribute
}

// DecisionEnvironment is the shared, typed policy input. Every populated
// attribute must include provenance from a trusted source.
type DecisionEnvironment struct {
	Principal DecisionPrincipal
	Action    TrustedAttribute
	Resource  DecisionResource
	Context   map[string]TrustedAttribute
}

// AuthorizationVerdict is deliberately distinct from guardrail and routing
// results. An unavailable mandatory check is represented as a deny.
type AuthorizationVerdict struct {
	Allowed bool
	Reason  string
	Err     error
}

// GuardrailVerdict describes whether content may continue through the
// pipeline; it does not grant or revoke principal permissions.
type GuardrailVerdict struct {
	Continue bool
	Reason   string
	Err      error
}

// RouteCandidate pairs a route with its condition. Candidates are considered
// in order; an evaluation error aborts selection rather than falling through.
type RouteCandidate struct {
	Name      string
	Condition ConditionProgram
}

// RoutingDecision identifies the selected route. Route is empty on failure.
type RoutingDecision struct {
	Route  string
	Reason string
	Err    error
}

// Evaluator centralizes condition execution while preserving the distinct
// result contracts of authorization, guardrails, and routing.
type Evaluator struct{}

// EvaluateCondition evaluates a pipeline-local condition through the shared
// evaluator. Errors are returned to the caller, which must fail closed.
func (Evaluator) EvaluateCondition(ctx context.Context, program ConditionProgram, env ConditionEnv) (bool, error) {
	return evaluateCondition(ctx, program, env)
}

// EvaluateAuthorization evaluates a mandatory authorization check. Any
// missing/untrusted input or evaluation failure denies with a reason.
func (Evaluator) EvaluateAuthorization(ctx context.Context, program ConditionProgram, input DecisionEnvironment) AuthorizationVerdict {
	env, err := trustedConditionEnv(input)
	if err == nil {
		var allowed bool
		allowed, err = evaluateCondition(ctx, program, env)
		if err == nil {
			if allowed {
				return AuthorizationVerdict{Allowed: true, Reason: "authorization condition allowed"}
			}
			return AuthorizationVerdict{Reason: "authorization condition denied"}
		}
	}
	return AuthorizationVerdict{Reason: "mandatory authorization check failed", Err: err}
}

// ScopedDenyRule is one MANDATORY deny condition evaluated before any grant
// evidence (N04-P04-T04). Rules run through the same compiled-program path
// as every other condition; a match is an absolute refusal that grant or
// role evidence cannot override, and a rule evaluation failure is an
// availability failure (fail-closed deny), never a skip.
type ScopedDenyRule struct {
	// Name identifies the rule in the deny reason and the audit trail.
	Name string
	// Condition is the compiled rule program over the shared typed
	// decision environment (Expr via the registered engine).
	Condition ConditionProgram
}

// EvaluateScopedAuthorization evaluates the mandatory deny rules first, then
// the grant program. Semantics (pinned by tests):
//
//   - any matched deny rule → deny with a reason naming the rule; grant and
//     role inputs are never consulted (the mandatory deny is absolute);
//   - a deny-rule evaluation failure (or an invalid rule) → deny with an
//     error (Class unavailable — the mandatory check did not complete);
//   - otherwise the grant program decides exactly as EvaluateAuthorization.
func (Evaluator) EvaluateScopedAuthorization(ctx context.Context, denyRules []ScopedDenyRule, program ConditionProgram, input DecisionEnvironment) AuthorizationVerdict {
	env, err := trustedConditionEnv(input)
	if err != nil {
		return AuthorizationVerdict{Reason: "mandatory authorization check failed", Err: err}
	}
	for _, rule := range denyRules {
		if rule.Name == "" || rule.Condition == nil {
			return AuthorizationVerdict{}.unavailable("invalid mandatory deny rule", errors.New("deny rule requires name and condition"))
		}
		matched, ruleErr := evaluateCondition(ctx, rule.Condition, env)
		if ruleErr != nil {
			return AuthorizationVerdict{}.unavailable(fmt.Sprintf("mandatory deny rule %q failed", rule.Name), ruleErr)
		}
		if matched {
			return AuthorizationVerdict{Reason: fmt.Sprintf("scoped deny rule %q matched", rule.Name)}
		}
	}
	return evaluateAuthorizationEnv(ctx, program, env)
}

// evaluateAuthorizationEnv runs the grant program against an already
// trusted environment (the shared tail of both authorization entries).
func evaluateAuthorizationEnv(ctx context.Context, program ConditionProgram, env ConditionEnv) AuthorizationVerdict {
	allowed, err := evaluateCondition(ctx, program, env)
	if err != nil {
		return AuthorizationVerdict{Reason: "mandatory authorization check failed", Err: err}
	}
	if allowed {
		return AuthorizationVerdict{Allowed: true, Reason: "authorization condition allowed"}
	}
	return AuthorizationVerdict{Reason: "authorization condition denied"}
}

// EvaluateGuardrail maps a condition match to a block and an error to a
// fail-closed block. It never changes authorization state.
func (Evaluator) EvaluateGuardrail(ctx context.Context, program ConditionProgram, input DecisionEnvironment) GuardrailVerdict {
	env, err := trustedConditionEnv(input)
	if err == nil {
		var matched bool
		matched, err = evaluateCondition(ctx, program, env)
		if err == nil {
			if matched {
				return GuardrailVerdict{Continue: false, Reason: "guardrail condition matched"}
			}
			return GuardrailVerdict{Continue: true, Reason: "guardrail condition did not match"}
		}
	}
	return GuardrailVerdict{Continue: false, Reason: "guardrail evaluation failed", Err: err}
}

// EvaluateRouting evaluates route candidates in precedence order. No matching
// condition or any mandatory evaluation failure yields no route.
func (Evaluator) EvaluateRouting(ctx context.Context, candidates []RouteCandidate, input DecisionEnvironment) RoutingDecision {
	env, err := trustedConditionEnv(input)
	if err != nil {
		return RoutingDecision{Reason: "routing input unavailable", Err: err}
	}
	if len(candidates) == 0 {
		return RoutingDecision{Reason: "no route candidates"}
	}
	for _, candidate := range candidates {
		if candidate.Name == "" || candidate.Condition == nil {
			return RoutingDecision{Reason: "invalid mandatory route candidate", Err: errors.New("route candidate requires name and condition")}
		}
		matched, evalErr := evaluateCondition(ctx, candidate.Condition, env)
		if evalErr != nil {
			return RoutingDecision{Reason: "route evaluation failed", Err: fmt.Errorf("route %q: %w", candidate.Name, evalErr)}
		}
		if matched {
			return RoutingDecision{Route: candidate.Name, Reason: "route condition matched"}
		}
	}
	return RoutingDecision{Reason: "no route condition matched"}
}

func evaluateCondition(ctx context.Context, program ConditionProgram, env ConditionEnv) (bool, error) {
	if program == nil {
		return false, errors.New("condition program is required")
	}
	if ctx == nil {
		return false, errors.New("evaluation context is required")
	}
	matched, err := program.Evaluate(ctx, env)
	if err != nil {
		return false, err
	}
	return matched, nil
}

func trustedConditionEnv(input DecisionEnvironment) (ConditionEnv, error) {
	check := func(name string, value TrustedAttribute) error {
		if value.Source == "" {
			return fmt.Errorf("pipeline: %s attribute has no trusted source", name)
		}
		return nil
	}
	attributes := []struct {
		name  string
		value TrustedAttribute
	}{
		{"principal.id", input.Principal.ID}, {"principal.kind", input.Principal.Kind},
		{"action", input.Action}, {"resource.type", input.Resource.Type},
		{"resource.id", input.Resource.ID}, {"resource.organization", input.Resource.Organization},
	}
	for _, attribute := range attributes {
		if err := check(attribute.name, attribute.value); err != nil {
			return ConditionEnv{}, err
		}
	}
	for name, value := range input.Context {
		if name == "" {
			return ConditionEnv{}, errors.New("pipeline: context attribute name is required")
		}
		if err := check("context."+name, value); err != nil {
			return ConditionEnv{}, err
		}
	}
	trusted := DecisionEnvironment{
		Principal: input.Principal,
		Action:    input.Action,
		Resource:  input.Resource,
		Context:   make(map[string]TrustedAttribute, len(input.Context)),
	}
	for name, value := range input.Context {
		trusted.Context[name] = value
	}
	return ConditionEnv{Decision: &trusted}, nil
}
