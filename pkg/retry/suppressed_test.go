package retry_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/retry"
)

// TestSuppressedError pins the typed explanation of a refused automatic
// repeat: the stable machine-readable code for API envelopes, the outcome
// class the refusal was based on, and an original cause that stays reachable
// through errors.Is / errors.As.
func TestSuppressedError(t *testing.T) {
	t.Parallel()

	cause := errors.New("upstream request timeout")

	t.Run("unknown outcome carries the unknown-outcome refusal code", func(t *testing.T) {
		t.Parallel()

		err := &retry.SuppressedError{Model: "primary", Outcome: retry.OutcomeUnknown, Err: cause}

		assert.Equal(t, retry.SuppressedUnknownCode, err.Code())
		assert.Equal(t, retry.OutcomeUnknown, err.Outcome)
	})

	t.Run("executed outcome carries the executed-outcome refusal code", func(t *testing.T) {
		t.Parallel()

		err := &retry.SuppressedError{Outcome: retry.OutcomeExecuted, Err: errors.New("stream aborted after first chunk")}

		assert.Equal(t, retry.SuppressedExecutedCode, err.Code())
	})

	t.Run("unclassified refusal reports the conservative unknown code", func(t *testing.T) {
		t.Parallel()

		err := &retry.SuppressedError{Err: cause}

		assert.Equal(t, retry.SuppressedUnknownCode, err.Code())
	})

	t.Run("message names the model, the outcome class and the cause", func(t *testing.T) {
		t.Parallel()

		err := &retry.SuppressedError{Model: "primary", Outcome: retry.OutcomeUnknown, Err: cause}

		assert.Contains(t, err.Error(), "primary")
		assert.Contains(t, err.Error(), "unknown")
		assert.Contains(t, err.Error(), "upstream request timeout")
	})

	t.Run("message without a model omits the model clause", func(t *testing.T) {
		t.Parallel()

		err := &retry.SuppressedError{Outcome: retry.OutcomeExecuted, Err: cause}

		assert.Contains(t, err.Error(), "executed upstream outcome")
		assert.NotContains(t, err.Error(), "on ")
	})

	t.Run("original cause stays reachable via errors.Is", func(t *testing.T) {
		t.Parallel()

		err := error(&retry.SuppressedError{Model: "primary", Outcome: retry.OutcomeUnknown, Err: cause})

		require.ErrorIs(t, err, cause)
	})

	t.Run("nil cause renders without panicking", func(t *testing.T) {
		t.Parallel()

		err := &retry.SuppressedError{Outcome: retry.OutcomeUnknown}

		assert.Contains(t, err.Error(), "<nil>")
		assert.NoError(t, err.Unwrap())
	})
}
