package retry

import "fmt"

// Outcome classification for upstream attempts.
//
// A failed upstream call does not always leave knowable evidence about what
// happened on the provider side: the request may or may not have reached the
// provider and may or may not have produced billable work or external side
// effects. Automatically repeating such a request can double-charge a
// customer or duplicate a mutation, so the classification below is the
// evidence contract that decides what may be repeated:
//
//	OutcomeNotExecuted — known-not-started: proof the exchange never reached
//	execution (DNS resolution or dial failure).
//	OutcomeExecuted    — known-completed: an HTTP answer arrived (whatever
//	its status), or execution became visible before the failure (response
//	bytes seen, translation failed, stream produced output).
//	OutcomeUnknown     — the default: the outcome cannot be determined from
//	the available evidence. Repeating it requires either proof of
//	non-execution or a verified provider deduplication contract
//	(IdempotencyProof); without one, an unknown attempt is terminal.

// OutcomeExecuted extends the safety classification with the
// known-completed class. It is deliberately not reachable as a zero value:
// an unclassified failed attempt stays OutcomeUnknown, and a caller may only
// set OutcomeExecuted when it observed an HTTP answer or upstream execution.
const OutcomeExecuted OutcomeSafety = 2

// Classify derives the outcome classification of one attempt from the
// transport evidence available at the call boundary: the HTTP status code
// (0 when no answer arrived) and the error.
//
// An HTTP answer of any status is a known-completed outcome: the exchange
// finished and the upstream produced a decision (success, refusal, or error
// answer), so what may follow is governed by the ordinary status-based retry
// policy, not by unknown-outcome suppression.
//
// Timeouts, cancellations, write failures and mid-flight read failures are
// classified unknown on purpose: none of them proves the upstream did not
// execute the request. Request bytes may already have been written, headers
// seen, or a stream started — an absent first byte is silence, not proof of
// non-execution.
func Classify(statusCode int, err error) OutcomeSafety {
	switch {
	case err == nil:
		return OutcomeExecuted
	case DefinitelyNotSent(err):
		return OutcomeNotExecuted
	case IsRequestNotSent(err):
		// Translate-layer refusal (N07-P01-T05): the proof is structural —
		// the request never reached the transport, so this is as strong as
		// a dial failure for chain-advance purposes.
		return OutcomeNotExecuted
	case statusCode > 0:
		return OutcomeExecuted
	default:
		return OutcomeUnknown
	}
}

// MayRepeat is the repetition-permission rule for a failed attempt that
// produced no HTTP answer: an automatic repeat is permitted only with proof
// that execution never started (OutcomeNotExecuted) or with a verified
// provider/action deduplication contract (IdempotencyProof). Every other
// outcome — unknown silence, absent first byte, partially observed execution —
// stays terminal: repeating it could double-charge a customer or duplicate a
// mutation.
//
// Both retry.Do and the fallback chain gate their repetition decisions on
// this single rule, so the evidence contract cannot drift between the two
// decision points.
func MayRepeat(safety OutcomeSafety, proof IdempotencyProof) bool {
	if safety == OutcomeNotExecuted {
		return true
	}
	return proof != nil && proof.AllowsRetry()
}

// String returns the stable machine-readable name of the classification for
// events, metrics and logs: "unknown", "not_executed" or "executed".
func (s OutcomeSafety) String() string {
	switch s {
	case OutcomeNotExecuted:
		return "not_executed"
	case OutcomeExecuted:
		return "executed"
	default:
		return "unknown"
	}
}

// Stable machine-readable refusal codes surfaced by SuppressedError.Code, so
// API envelopes and UI copy can explain why a failed attempt was not repeated
// instead of presenting a bare timeout.
const (
	// SuppressedUnknownCode marks a repeat refusal caused by an unknown
	// upstream outcome: no HTTP answer arrived and nothing proves the
	// exchange never started.
	SuppressedUnknownCode = "retry_suppressed_unknown_outcome"
	// SuppressedExecutedCode marks a repeat refusal caused by an attempt
	// whose execution was observed (an HTTP answer arrived, or execution
	// became visible before the failure — partial streaming, unusable
	// response).
	SuppressedExecutedCode = "retry_suppressed_executed_outcome"
)

// SuppressedError is the typed explanation of a refused automatic repeat: the
// repetition-permission rule (MayRepeat) declined to repeat the operation, so
// the failure is final. It carries the stable machine-readable reason API/UI
// layers render (Code), while the original terminal cause stays reachable via
// errors.Is / errors.As through Unwrap — the caller that owned the attempt
// keeps its error identity.
type SuppressedError struct {
	// Model is the candidate whose failed attempt was not repeated ("" when
	// the refusal happened outside a fallback chain).
	Model string
	// Outcome is the evidence class the refusal was based on.
	Outcome OutcomeSafety
	// Err is the original terminal error of the suppressed attempt.
	Err error
}

func (e *SuppressedError) Error() string {
	cause := "<nil>"
	if e.Err != nil {
		cause = e.Err.Error()
	}
	if e.Model != "" {
		return fmt.Sprintf("automatic repeat suppressed on %s (%s upstream outcome): %s", e.Model, e.Outcome, cause)
	}
	return fmt.Sprintf("automatic repeat suppressed (%s upstream outcome): %s", e.Outcome, cause)
}

// Unwrap exposes the original terminal cause of the suppressed attempt.
func (e *SuppressedError) Unwrap() error { return e.Err }

// Code returns the stable machine-readable refusal reason for API envelopes:
// retry_suppressed_executed_outcome when the refusal was based on observed
// execution, retry_suppressed_unknown_outcome for every other class (the
// conservative default — an unclassified refusal is reported as unknown).
func (e *SuppressedError) Code() string {
	if e.Outcome == OutcomeExecuted {
		return SuppressedExecutedCode
	}
	return SuppressedUnknownCode
}
