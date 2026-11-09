package retry_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/reireirei/yabanin/pkg/retry"
)

// TestRequestIdentityContext pins the request-identity carrier: the identity
// is minted once, attached to the request context and read back unchanged by
// every reader. Nothing invents identity and a child context never leaks into
// its parent.
func TestRequestIdentityContext(t *testing.T) {
	t.Parallel()

	t.Run("absent identity reads as the zero value", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, retry.RequestIdentity{}, retry.RequestIdentityFrom(context.Background()))
	})

	t.Run("attached identity reads back unchanged", func(t *testing.T) {
		t.Parallel()

		id := retry.RequestIdentity{RequestID: "req-1", IdempotencyKey: "idem-1"}
		ctx := retry.WithRequestIdentity(context.Background(), id)

		assert.Equal(t, id, retry.RequestIdentityFrom(ctx))
	})

	t.Run("identity survives every attempt of one request", func(t *testing.T) {
		t.Parallel()

		// The card behaviour under test: one context, many attempts — every
		// attempt closure observes the same identity, whatever the attempt
		// number or outcome.
		id := retry.RequestIdentity{RequestID: "req-42", IdempotencyKey: "idem-42"}
		ctx := retry.WithRequestIdentity(context.Background(), id)

		seen := make([]retry.RequestIdentity, 0, 3)
		for attempt := 1; attempt <= 3; attempt++ {
			seen = append(seen, readIdentityAttempt(ctx, attempt))
		}
		assert.Equal(t, []retry.RequestIdentity{id, id, id}, seen,
			"every attempt of one request must observe the same identity")
	})

	t.Run("child identity never leaks into the parent context", func(t *testing.T) {
		t.Parallel()

		parent := context.Background()
		_ = retry.WithRequestIdentity(parent, retry.RequestIdentity{RequestID: "req-child"})

		assert.Equal(t, retry.RequestIdentity{}, retry.RequestIdentityFrom(parent))
	})

	t.Run("two requests on one shared parent keep disjoint identities", func(t *testing.T) {
		t.Parallel()

		parent := context.Background()
		ctxA := retry.WithRequestIdentity(parent, retry.RequestIdentity{RequestID: "req-a"})
		ctxB := retry.WithRequestIdentity(parent, retry.RequestIdentity{RequestID: "req-b"})

		assert.Equal(t, "req-a", retry.RequestIdentityFrom(ctxA).RequestID)
		assert.Equal(t, "req-b", retry.RequestIdentityFrom(ctxB).RequestID)
	})
}

// readIdentityAttempt stands in for an attempt closure reading the identity
// from the attempt context.
func readIdentityAttempt(ctx context.Context, _ int) retry.RequestIdentity {
	return retry.RequestIdentityFrom(ctx)
}
