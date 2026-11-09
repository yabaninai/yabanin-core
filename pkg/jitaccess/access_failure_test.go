package jitaccess

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failure stage: the DB error-propagation legs and boundary edges
// queryRow/exec doubles (no server needed); the Postgres probes exercise the
// real rows for what stubs cannot honestly reproduce (the concurrent-decision
// race, the sweep boundaries over live data).

type stubRow struct {
	scan func(dest ...any) error
}

func (r stubRow) Scan(dest ...any) error { return r.scan(dest...) }

func jitErrRow(err error) pgx.Row {
	return stubRow{scan: func(...any) error { return err }}
}

// jitStubRow scans like the 8-column fetch projection of access.go. A
// projection change must break this stub loudly rather than mis-scan.
func jitStubRow(t *testing.T, r JITRecord) pgx.Row {
	t.Helper()
	return stubRow{scan: func(dest ...any) error {
		if len(dest) != 8 {
			t.Fatalf("fetch projection changed: %d dests", len(dest))
		}
		*(dest[0].(*string)) = r.ID
		*(dest[1].(*string)) = r.AdminID
		*(dest[2].(*string)) = r.Role
		*(dest[3].(*string)) = r.Reason
		*(dest[4].(**string)) = r.ApproverID
		*(dest[5].(*string)) = r.Status
		*(dest[6].(*time.Time)) = r.ExpiresAt
		*(dest[7].(*time.Time)) = r.CreatedAt
		return nil
	}}
}

// jitLazyPool builds a never-connected pool: it passes the ready() guard so
// guards past it can be probed without a server.
func jitLazyPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://127.0.0.1:1/unused")
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func jitAllowAllRoot() RootChecker {
	return func(context.Context, string) (bool, error) { return true, nil }
}

func jitBasePending() JITRecord {
	created := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	r := JITRecord{
		ID:        "11111111-1111-1111-1111-111111111111",
		AdminID:   "admin-1",
		Role:      "root",
		Reason:    "failure probes",
		Status:    StatusPending,
		ExpiresAt: created.Add(PendingTTL),
		CreatedAt: created,
	}
	r.Binds = bindsFor(&r)
	return r
}

// TestJIT_Failure_FetchErrorsWrapped pins the fetch error-propagation legs
// (review priority b): a storage failure wraps as "load jit request" and
// must never masquerade as ErrNotFound, while a genuine missing row stays
// ErrNotFound.
func TestJIT_Failure_FetchErrorsWrapped(t *testing.T) {
	m := NewManager(jitLazyPool(t))
	m.WithRootCheck(jitAllowAllRoot())
	m.queryRow = func(context.Context, string, ...any) pgx.Row {
		return jitErrRow(errors.New("boom: connection reset"))
	}

	_, err := m.Get(context.Background(), "id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load jit request")
	assert.Contains(t, err.Error(), "boom: connection reset")
	require.NotErrorIs(t, err, ErrNotFound, "a storage failure must not read as a missing request")

	// The decision path shares the fetch leg and reports the same wrap.
	_, err = m.Approve(context.Background(), "id", "approver", ApprovalBinds{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load jit request")

	// A genuine missing row keeps the honest not-found mapping.
	m.queryRow = func(context.Context, string, ...any) pgx.Row {
		return jitErrRow(pgx.ErrNoRows)
	}
	_, err = m.Get(context.Background(), "id")
	assert.ErrorIs(t, err, ErrNotFound)
}

// TestJIT_Failure_DecisionExecErrorWrapped pins the terminal-UPDATE wrap for
// both decisions (review priority b): "record jit <decision>" carries the
// storage error outward instead of swallowing it.
func TestJIT_Failure_DecisionExecErrorWrapped(t *testing.T) {
	base := jitBasePending()
	m := NewManager(jitLazyPool(t))
	m.WithRootCheck(jitAllowAllRoot())
	m.queryRow = func(context.Context, string, ...any) pgx.Row { return jitStubRow(t, base) }
	m.exec = func(context.Context, string, ...any) (pgconn.CommandTag, error) {
		return pgconn.CommandTag{}, errors.New("boom: write failed")
	}

	_, err := m.Approve(context.Background(), base.ID, "approver-2", base.Binds)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "record jit approve")
	assert.Contains(t, err.Error(), "boom: write failed")

	_, err = m.Deny(context.Background(), base.ID, "approver-2", base.Binds)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "record jit denied")
}

// TestJIT_Failure_RacyZeroRowsHonestReread pins all three legs of the
// RowsAffected==0 re-read (review priority b): a lost race or mutated row
// reports the honest reason — still-pending means digest mismatch, a failing
// re-read propagates its storage error, a decided row reports not-pending.
func TestJIT_Failure_RacyZeroRowsHonestReread(t *testing.T) {
	base := jitBasePending()
	winner := "approver-2"
	approved := base
	approved.Status = StatusApproved
	approved.ApproverID = &winner
	approved.ExpiresAt = base.CreatedAt.Add(ApprovedTTL)
	approved.Binds = bindsFor(&approved)

	newManager := func(rows ...pgx.Row) *Manager {
		i := 0
		m := NewManager(jitLazyPool(t))
		m.WithRootCheck(jitAllowAllRoot())
		m.queryRow = func(context.Context, string, ...any) pgx.Row {
			r := rows[min(i, len(rows)-1)]
			i++
			return r
		}
		m.exec = func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil // zero rows affected
		}
		return m
	}

	t.Run("reread still pending reports digest mismatch", func(t *testing.T) {
		m := newManager(jitStubRow(t, base), jitStubRow(t, base))
		_, err := m.Approve(context.Background(), base.ID, "approver-2", base.Binds)
		assert.ErrorIs(t, err, ErrDigestMismatch)
	})

	t.Run("reread failure propagates", func(t *testing.T) {
		m := newManager(jitStubRow(t, base), jitErrRow(errors.New("boom: reread failed")))
		_, err := m.Approve(context.Background(), base.ID, "approver-2", base.Binds)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "boom: reread failed")
		assert.NotErrorIs(t, err, ErrDigestMismatch, "a re-read failure is not a digest verdict")
	})

	t.Run("reread sees the winner reports not pending", func(t *testing.T) {
		m := newManager(jitStubRow(t, base), jitStubRow(t, approved))
		_, err := m.Approve(context.Background(), base.ID, "approver-2", base.Binds)
		assert.ErrorIs(t, err, ErrNotPending)
	})
}

// TestJIT_Failure_ExpirePastDBError pins the sweep's DB-error propagation
// (review priority c): the wrap carries the storage error outward and the
// caller cannot mistake a failed sweep for a successful no-op.
func TestJIT_Failure_ExpirePastDBError(t *testing.T) {
	m := NewManager(jitLazyPool(t))
	m.exec = func(context.Context, string, ...any) (pgconn.CommandTag, error) {
		return pgconn.CommandTag{}, errors.New("boom: sweep failed")
	}
	_, err := m.ExpirePast(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expire jit requests")
	assert.Contains(t, err.Error(), "boom: sweep failed")
}

// TestJIT_Failure_IsActiveFailClosedOnQueryError: a failing lookup must
// answer inactive (D7), never active.
func TestJIT_Failure_IsActiveFailClosedOnQueryError(t *testing.T) {
	m := NewManager(jitLazyPool(t))
	m.queryRow = func(context.Context, string, ...any) pgx.Row {
		return jitErrRow(errors.New("boom: lookup failed"))
	}
	assert.False(t, m.IsActive(context.Background(), "admin-1", "root"))
}

// TestJIT_Failure_DecideGuardOrdering pins the guard order of the shared
// decision core: internal misuse (unknown decision) and empty approver are
// reported before authorization is attempted, so a wiring bug cannot read as
// an authorization verdict.
func TestJIT_Failure_DecideGuardOrdering(t *testing.T) {
	m := NewManager(jitLazyPool(t))
	_, err := m.decide(context.Background(), "id", "approver", ApprovalBinds{}, "expired")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown decision "expired"`)
	require.NotErrorIs(t, err, ErrApproverNotRoot)

	m.WithRootCheck(nil) // even without any root checker the input guard fires first
	_, err = m.decide(context.Background(), "id", "  ", ApprovalBinds{}, StatusApproved)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "approver id is required")
}

// TestIntJIT_Failure_ConcurrentDecisionSingleWinner: two simultaneous
// decisions of one pending request — exactly one wins; the loser reports the
// honest ErrNotPending (directly or via the RowsAffected==0 re-read) and the
// row holds a single consistent decision.
func TestIntJIT_Failure_ConcurrentDecisionSingleWinner(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	m := NewManager(pool)

	admins := seedJITAdmins(t, pool,
		jitAdminSpec{Root: true, Active: true},
		jitAdminSpec{Root: true, Active: true},
	)
	requester, approver := admins[0], admins[1]

	rec, err := m.Request(ctx, requester.ID, "root", "concurrent decision")
	require.NoError(t, err)

	const racers = 2
	type outcome struct {
		rec *JITRecord
		err error
	}
	results := make([]outcome, racers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			r, err := m.Approve(ctx, rec.ID, approver.ID, rec.Binds)
			results[i] = outcome{rec: r, err: err}
		}(i)
	}
	close(start)
	wg.Wait()

	wins, losses := 0, 0
	for i, r := range results {
		switch {
		case r.err == nil:
			wins++
			assert.Equal(t, StatusApproved, r.rec.Status, "winner %d", i)
		case errors.Is(r.err, ErrNotPending):
			losses++
		default:
			t.Fatalf("racer %d: unexpected decision outcome: %v", i, r.err)
		}
	}
	assert.Equal(t, 1, wins, "exactly one concurrent decision may win")
	assert.Equal(t, racers-1, losses, "the loser must report the honest not-pending refusal")

	after, err := m.Get(ctx, rec.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusApproved, after.Status)
}

// TestIntJIT_Failure_SweepBoundaries: a fresh pending request is not sweep
// fodder; an aged DENIED row is sweep-immune (denied is terminal); aged
// pending and approved rows flip; a second sweep is a no-op on the flipped
// rows (expired is terminal and excluded from the sweep set).
func TestIntJIT_Failure_SweepBoundaries(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	m := NewManager(pool)

	admins := seedJITAdmins(t, pool,
		jitAdminSpec{Root: true, Active: true},
		jitAdminSpec{Root: true, Active: true},
	)
	requester, approver := admins[0], admins[1]

	fresh, err := m.Request(ctx, requester.ID, "root", "fresh pending survives")
	require.NoError(t, err)
	aged, err := m.Request(ctx, requester.ID, "root", "aged pending flips")
	require.NoError(t, err)
	denied, err := m.Request(ctx, requester.ID, "root", "denied is sweep-immune")
	require.NoError(t, err)
	approved, err := m.Request(ctx, requester.ID, "root", "expired approval flips")
	require.NoError(t, err)

	_, err = m.Deny(ctx, denied.ID, approver.ID, denied.Binds)
	require.NoError(t, err)
	_, err = m.Approve(ctx, approved.ID, approver.ID, approved.Binds)
	require.NoError(t, err)

	ageRequest(t, pool, aged.ID)
	ageRequest(t, pool, denied.ID)
	ageRequest(t, pool, approved.ID)

	flipped, err := m.ExpirePast(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, flipped, int64(2), "aged pending + aged approval must flip")

	gotFresh, err := m.Get(ctx, fresh.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusPending, gotFresh.Status, "a fresh pending request must survive the sweep")
	gotDenied, err := m.Get(ctx, denied.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusDenied, gotDenied.Status, "denied is terminal: the sweep must never flip it")
	gotAged, err := m.Get(ctx, aged.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusExpired, gotAged.Status)
	gotApproved, err := m.Get(ctx, approved.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusExpired, gotApproved.Status)

	// Idempotent: expired rows are terminal, a repeat sweep cannot re-decide them.
	_, err = m.ExpirePast(ctx)
	require.NoError(t, err)
	gotAged2, err := m.Get(ctx, aged.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusExpired, gotAged2.Status)
}

// TestIntJIT_Failure_DigestBindFamily: every ApprovalBinds field participates
// in the binding — tampering any single field (org, entity, entity_version,
// params_digest) refuses the decision and leaves the request pending.
func TestIntJIT_Failure_DigestBindFamily(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	m := NewManager(pool)

	admins := seedJITAdmins(t, pool,
		jitAdminSpec{Root: true, Active: true},
		jitAdminSpec{Root: true, Active: true},
	)
	requester, approver := admins[0], admins[1]

	rec, err := m.Request(ctx, requester.ID, "root", "bind family")
	require.NoError(t, err)

	tamper := map[string]func(b *ApprovalBinds){
		"org":            func(b *ApprovalBinds) { b.Org = "someone-else" },
		"entity":         func(b *ApprovalBinds) { b.Entity = "other-role" },
		"entity_version": func(b *ApprovalBinds) { b.EntityVersion = "2000-01-01T00:00:00Z" },
		"params_digest":  func(b *ApprovalBinds) { b.ParamsDigest = strings.Repeat("f", 64) },
	}
	for name, mutate := range tamper {
		binds := rec.Binds
		mutate(&binds)
		_, err := m.Approve(ctx, rec.ID, approver.ID, binds)
		require.ErrorIs(t, err, ErrDigestMismatch, name)
		cur, err := m.Get(ctx, rec.ID)
		require.NoError(t, err, name)
		assert.Equal(t, StatusPending, cur.Status, name)
	}
}
