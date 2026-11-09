package policystore

// SQL contract for the durable guard-pack CAS (testdb.Postgres posture of
// sqlcontract_int_test.go): migration 0013's singleton row, written only
// through CompareAndSwap.
//
// Locked semantics:
//   - row absent ⇒ the first CAS bootstraps (active=to, previous=from);
//   - active_version == expected ⇒ the transition wins, the old active
//     becomes previous_version;
//   - active_version != expected ⇒ NOTHING is written, ErrGuardPackConflict;
//   - TWO store clients (two replicas) see the same durable row: exactly one
//     concurrent CAS wins, the loser reads the winner's version;
//   - a losing CAS leaves the row byte-identical (no mixed state).

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
)

// TestGuardPolicyCASContract is sequential by design: all cases share the
// package's single Postgres stand and one singleton row; every case starts
// from a clean row via resetGuardPackState.
func TestGuardPolicyCASContract(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := testCtx()

	t.Run("bootstrap on the first transition", func(t *testing.T) {
		resetGuardPackState(t, ctx, pool)
		cas := NewGuardPolicyCAS(pool)
		require.NoError(t, cas.CompareAndSwap(ctx, "core", "alpha@1"))
		state, err := cas.ActiveGuardPackState(ctx)
		require.NoError(t, err)
		assert.Equal(t, "alpha@1", state.ActiveVersion)
		assert.Equal(t, "core", state.PreviousVersion)
	})

	t.Run("win moves active to previous", func(t *testing.T) {
		resetGuardPackState(t, ctx, pool)
		cas := NewGuardPolicyCAS(pool)
		require.NoError(t, cas.CompareAndSwap(ctx, "core", "alpha@1"))
		require.NoError(t, cas.CompareAndSwap(ctx, "alpha@1", "alpha@2"))
		state, err := cas.ActiveGuardPackState(ctx)
		require.NoError(t, err)
		assert.Equal(t, "alpha@2", state.ActiveVersion)
		assert.Equal(t, "alpha@1", state.PreviousVersion)
	})

	t.Run("stale from applies nothing and conflicts", func(t *testing.T) {
		resetGuardPackState(t, ctx, pool)
		cas := NewGuardPolicyCAS(pool)
		require.NoError(t, cas.CompareAndSwap(ctx, "core", "alpha@1"))
		err := cas.CompareAndSwap(ctx, "core", "beta@1")
		require.ErrorIs(t, err, ErrGuardPackConflict, "a stale from must lose the CAS")
		state, readErr := cas.ActiveGuardPackState(ctx)
		require.NoError(t, readErr)
		assert.Equal(t, "alpha@1", state.ActiveVersion, "a lost CAS must not touch the row")
		assert.Equal(t, "core", state.PreviousVersion)
	})

	t.Run("two store clients: winner visible to the second client", func(t *testing.T) {
		resetGuardPackState(t, ctx, pool)
		// Two independent clients over the same store — the replica posture.
		clientA := NewGuardPolicyCAS(pool)
		clientB := NewGuardPolicyCAS(pool)

		require.NoError(t, clientA.CompareAndSwap(ctx, "core", "alpha@1"),
			"replica A activates first and wins")

		err := clientB.CompareAndSwap(ctx, "core", "beta@1")
		require.ErrorIs(t, err, ErrGuardPackConflict,
			"replica B's stale local view must lose against the durable winner")

		// The loser observes the winner through the store (no replica-local
		// memory involved).
		state, readErr := clientB.ActiveGuardPackState(ctx)
		require.NoError(t, readErr)
		assert.Equal(t, "alpha@1", state.ActiveVersion)
	})

	t.Run("rollback through the same CAS", func(t *testing.T) {
		resetGuardPackState(t, ctx, pool)
		cas := NewGuardPolicyCAS(pool)
		require.NoError(t, cas.CompareAndSwap(ctx, "core", "alpha@1"))
		require.NoError(t, cas.CompareAndSwap(ctx, "alpha@1", "core"),
			"rollback is the inverse transition through the identical CAS")
		state, err := cas.ActiveGuardPackState(ctx)
		require.NoError(t, err)
		assert.Equal(t, "core", state.ActiveVersion)
		assert.Equal(t, "alpha@1", state.PreviousVersion)
	})

	t.Run("concurrent CAS: exactly one winner, rest conflict", func(t *testing.T) {
		resetGuardPackState(t, ctx, pool)
		const racers = 8
		cas := NewGuardPolicyCAS(pool)
		results := make([]error, racers)
		var wg sync.WaitGroup
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i] = cas.CompareAndSwap(ctx, "core", fmt.Sprintf("racer-%d@1", i))
			}(i)
		}
		wg.Wait()

		wins := 0
		for _, err := range results {
			if err == nil {
				wins++
				continue
			}
			require.ErrorIs(t, err, ErrGuardPackConflict, "losers must conflict, not fail")
		}
		require.Equal(t, 1, wins, "exactly one concurrent CAS may win")

		state, err := cas.ActiveGuardPackState(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, state.ActiveVersion)
		var winnerSeen bool
		for i := 0; i < racers; i++ {
			if state.ActiveVersion == fmt.Sprintf("racer-%d@1", i) {
				winnerSeen = true
			}
		}
		require.True(t, winnerSeen, "final active version %q must be one of the racers", state.ActiveVersion)
	})

	t.Run("missing row reads as the zero state", func(t *testing.T) {
		resetGuardPackState(t, ctx, pool)
		state, err := NewGuardPolicyCAS(pool).ActiveGuardPackState(ctx)
		require.NoError(t, err, "a missing row is 'no durable activation yet', not an error")
		assert.Equal(t, GuardPackState{}, state)
	})
}

func resetGuardPackState(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(ctx, `DELETE FROM guard_pack_state WHERE id = 1`)
	if err != nil {
		t.Fatalf("reset guard_pack_state: %v", err)
	}
}
