package retry

// N07-P01-T05 — the typed not-sent proof. A translate-layer refusal happens
// before any transport activity: no dial, no bytes, no outcome ambiguity.
// Classify must report NotExecuted (the fallback chain may advance to a
// candidate that can honor the request), while the retry.Result stays
// Unknown at the same-model level so retry.Do never repeats a deterministic
// refusal against the same provider.

import (
	"errors"
	"fmt"
	"testing"
)

func TestRequestNotSentError_ClassifyAndUnwrap(t *testing.T) {
	inner := errors.New(`anthropic: reasoning_effort "high" is not mapped; rejecting instead of silently dropping (I51)`)
	err := fmt.Errorf("translate request: %w", &RequestNotSentError{Err: inner})

	if got := Classify(0, err); got != OutcomeNotExecuted {
		t.Fatalf("Classify = %v, want not_executed", got)
	}
	if !IsRequestNotSent(err) {
		t.Fatal("IsRequestNotSent = false through fmt wrapping")
	}
	if IsRequestNotSent(inner) {
		t.Fatal("the bare adapter error is not the typed proof — only the transport-layer wrap carries the not-sent evidence")
	}
	if want := "translate request: " + inner.Error(); err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
}
