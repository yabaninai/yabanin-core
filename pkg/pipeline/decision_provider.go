package pipeline

// N02-P03-T03 / N04-P04-T04 — the shared decision-provider seam.
//
// ONE minimal interface that both mandatory policy checks (the gateway
// policy-check boundary) and content authorization (AuthorizeContent and its
// consumers) can target when a future deployment wants decisions from an
// EXTERNAL source. OPA is explicitly deferred post-release: this file defines
// the seam and its failure contract only — the core ships ZERO provider
// implementations, compiles and works with none wired, and the built-in Expr
// evaluator (Evaluator.EvaluateAuthorization / EvaluateScopedAuthorization)
// stays the default decision path. Nothing in this file is consulted by any
// production call site today; wiring a provider is a deliberate future act.
//
// Seam contract:
//
//   - Requests and verdicts are TYPED and reuse the shared
//     DecisionEnvironment (trusted provenance on every attribute). A provider
//     never sees raw payload content.
//   - The caller's context carries the deadline. Implementations must honor
//     it; a deadline/timeout is an availability failure, never an allow.
//   - Error taxonomy: DecisionClass. `unavailable` (check could not run:
//     provider unreachable, timeout, invalid input) maps to the consumer's
//     fail-closed contract — deny with reason for content authorization,
//     503 policy store/decision unavailable at the gateway policy-check
//     boundary. `denied` is an evaluated refusal. `allowed` permits.
//   - Fail-closed normalization: DecideExternal is the one adapter consumers
//     should call. It converts any provider answer (including nil provider,
//     nil context, an inconsistent allow-with-error, or an out-of-contract
//     class) into the fail-closed AuthorizationVerdict the mandatory check
//     boundary already speaks. An external provider can therefore never
//     widen a mandatory check by returning malformed output.

import (
	"context"
	"errors"
	"fmt"
)

// DecisionClass is the typed outcome/error class shared by the built-in Expr
// evaluator and any future external DecisionProvider. It is the vocabulary
// of the fail-closed contract: reasons are informational, the class decides
// how the consumer must treat the verdict.
type DecisionClass string

// Decision classes.
const (
	// DecisionClassAllowed: the check ran and permitted the operation.
	DecisionClassAllowed DecisionClass = "allowed"
	// DecisionClassDenied: the check ran and refused the operation (an
	// evaluated policy deny — grant/role evidence cannot override a scoped
	// mandatory deny).
	DecisionClassDenied DecisionClass = "denied"
	// DecisionClassUnavailable: the check could not run (provider, store or
	// evaluator unreachable, timed out, or produced invalid output).
	// Consumers MUST fail closed: deny with reason for content authorization
	// and 503 (decision/policy unavailable) at the gateway policy boundary.
	// This is the class of every mandatory-check failure the audit seam
	// journals (N02-P03-T03).
	DecisionClassUnavailable DecisionClass = "unavailable"
)

// ErrDecisionUnavailable is the sentinel error carried by verdicts whose
// class is DecisionClassUnavailable. Consumers may use errors.Is against it
// when they need to distinguish "the check did not run" from an evaluated
// denial without importing provider-specific error types.
var ErrDecisionUnavailable = errors.New("pipeline: mandatory decision unavailable")

// DecisionRequest is the typed input of one external decision. It carries the
// same provenance-checked environment the built-in evaluator consumes; a
// provider must not require more and must never receive payload content.
type DecisionRequest struct {
	Environment DecisionEnvironment
}

// DecisionVerdict is the typed answer of a DecisionProvider. Class is part
// of the contract, not a convenience: an implementation that reports
// Allowed=true alongside Err != nil (or a non-allowed class) is
// out of contract, and DecideExternal normalizes it to a fail-closed
// unavailable deny.
type DecisionVerdict struct {
	Allowed bool
	Reason  string
	Class   DecisionClass
	Err     error
}

// DecisionProvider is the seam for future external decision sources (OPA is
// deliberately deferred post-release — no adapter ships in core). One method:
// implementations resolve one mandatory decision for the typed request and
// answer in the fail-closed vocabulary above. Implementations must be safe
// for concurrent use and must honor the context deadline (an expired deadline
// is DecisionClassUnavailable, never an allow). The core registers nothing
// here: the built-in Expr evaluator remains the default decision path and
// consumers work with zero providers.
type DecisionProvider interface {
	Decide(ctx context.Context, req DecisionRequest) DecisionVerdict
}

// UnavailableDeny builds the canonical fail-closed verdict for a mandatory
// check that could not run: Class unavailable, ErrDecisionUnavailable
// wrapped into the cause (so errors.Is works both ways), reason preserved.
// Every fail-closed producer — the built-in evaluator, the content
// authorization boundary, future providers — should answer through this
// constructor so the audit seam can key on the class.
func UnavailableDeny(reason string, cause error) AuthorizationVerdict {
	return AuthorizationVerdict{}.unavailable(reason, cause)
}

// Class reports the typed outcome class of a built-in evaluator verdict.
// Allowed → allowed; a deny carrying an error (the check itself failed) →
// unavailable; a deny without an error is an evaluated refusal → denied.
func (v AuthorizationVerdict) Class() DecisionClass {
	switch {
	case v.Allowed:
		return DecisionClassAllowed
	case v.Err != nil:
		return DecisionClassUnavailable
	default:
		return DecisionClassDenied
	}
}

// unavailable marks v as an availability failure, preserving the cause.
func (v AuthorizationVerdict) unavailable(reason string, err error) AuthorizationVerdict {
	if err == nil {
		err = ErrDecisionUnavailable
	} else if !errors.Is(err, ErrDecisionUnavailable) {
		err = fmt.Errorf("%w: %w", ErrDecisionUnavailable, err)
	}
	return AuthorizationVerdict{Reason: reason, Err: err}
}

// AuthorizationVerdict projects a provider answer onto the verdict type the
// mandatory check boundaries speak. It is CLASS-AUTHORITATIVE: the Class
// field decides the outcome and the Allowed flag can never widen it. An
// allow projects ONLY from a clean in-contract allow (Err == nil and Class
// allowed, one branch). An evaluated refusal (no error, no allow claim)
// stays a plain denied verdict. Everything else — an error, the unavailable
// class, or an allow-flagged answer carrying a denied or undefined class —
// normalizes to the fail-closed unavailable deny, so out-of-contract output
// can never become an allow.
func (v DecisionVerdict) AuthorizationVerdict() AuthorizationVerdict {
	if v.Err == nil && v.Class == DecisionClassAllowed {
		reason := v.Reason
		if reason == "" {
			reason = "decision provider allowed"
		}
		return AuthorizationVerdict{Allowed: true, Reason: reason}
	}
	if v.Err == nil && !v.Allowed && v.Class != DecisionClassAllowed {
		reason := v.Reason
		if reason == "" {
			reason = "decision provider denied"
		}
		return AuthorizationVerdict{Reason: reason}
	}
	reason := v.Reason
	if reason == "" {
		reason = "decision provider unavailable"
	}
	return AuthorizationVerdict{}.unavailable(reason, v.Err)
}

// DecideExternal adapts any DecisionProvider to the shared fail-closed
// authorization contract. It is the ONE entry point consumers should target
// when an external decision source is wired later:
//
//   - a nil provider (and a nil context) fails closed with the unavailable
//     class — core behavior with zero providers is a deny, not a panic;
//   - every provider answer passes through DecisionVerdict.AuthorizationVerdict,
//     so malformed output cannot widen a mandatory check;
//   - the default path never calls this: the built-in Expr evaluator stays
//     the built-in decision source (documented seam, no production wiring).
func DecideExternal(ctx context.Context, provider DecisionProvider, input DecisionEnvironment) AuthorizationVerdict {
	deny := AuthorizationVerdict{}.unavailable("decision provider unavailable", nil)
	if provider == nil {
		return deny
	}
	if ctx == nil {
		return deny
	}
	return provider.Decide(ctx, DecisionRequest{Environment: input}).AuthorizationVerdict()
}
