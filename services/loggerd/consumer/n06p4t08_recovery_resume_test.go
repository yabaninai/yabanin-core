package consumer

// N06-P04-T08 (recovery, 8h): interruption/retry/resume and result
// recovery without duplicates or losses. Every test drives the REAL
// SettlementWorker / ReconcileWorker against a disposable PG+Redis
// testcontainer and simulates crashes at the executor's actual seams —
// the flaky statement boundaries (tx abort ≡ process death: the durable
// state left behind is identical) and the lease-expiry recovery query
// (the production resume path, no wall-clock sleeps).
//
// The four axes, each DISTINCT from the neighbouring pins:
//
//  1. Per-job crash window between the ledger write and the reservation
//     release (resale: DeductMicro commits, the settle tx aborts) — the
//     restart heals through recoverExpiredLeases: the replayed charge is
//     an idempotent no-op, the missed release applies exactly once.
//     DISTINCT from TestImp99R1Live_ResaleCrashWindowAppliesMissedRelease
//     (a hand-seeded job, no consumer delivery, no lease-expiry resume)
//     and from TestNext18dLive_CrashBetweenCommitAndAckNoDoubleCharge
//     (payload already carries the key — mark-only replay).
//  2. Batch crash mid-transaction AFTER the in-tx ledger insert: the
//     whole org batch rolls back (no partial ledger write survives), the
//     same tick's per-job fallback applies every job exactly once, and a
//     repeat tick adds nothing. DISTINCT from
//     TestImp99R1Live_BatchFailureFallbackAppliesReserveRelease (that
//     fails the batch's FIRST statement — nothing is ever in flight;
//     this fails after the wallet ledger insert, the strongest rollback
//     window, and pins Σ ledger rows == 1).
//  3. Interrupted reconcile release pass (one allowance committed, the
//     second Begin aborts): the resumed pass converges to the same
//     verdict as an uninterrupted one — each allowance released exactly
//     once, nothing stranded, no duplicate return, a third pass no-op.
//     DISTINCT from T07's clean single-pass release
//     (n06p4t07ReleaseStake) and from N06-P05's abandoned-replica
//     takeover (replica fencing, not release-pass recovery).
//  4. The uncharged-unknown signal across a delivery retry: exactly one
//     increment per scope, never re-inflated by the redelivery of the
//     same entry id (the crash-after-increment retry), with the T07
//     known-zero semantics holding under retry too.
//
// Owner decisions I15, I40, I44, I45, I52, I61; contract D1–D3 in
// artifacts/internal-delivery-program/N06-P04/contract.md.

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func n06p4t08Consumer(ctx context.Context, t *testing.T, pool *pgxpool.Pool, rdb *redis.Client, stream string) *StreamConsumer {
	t.Helper()
	c := New(NewRedisOps(rdb), NewDBOps(pool), stream, silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	return c
}

func n06p4t08JobID(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org, requestID, kind string) int64 {
	t.Helper()
	var id int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM settlement_jobs WHERE org_id = $1 AND request_id = $2 AND charge_kind = $3`,
		org, requestID, kind).Scan(&id))
	return id
}

// n06p4t08UnknownSnapshot reads the four scope labels of the
// uncharged-unknown counter.
func n06p4t08UnknownSnapshot() map[string]float64 {
	return map[string]float64{
		"wallet":     promtestutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet")),
		"team_month": promtestutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("team_month")),
		"agent_day":  promtestutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("agent_day")),
		"session":    promtestutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("session")),
	}
}

// n06p4t08FlakyReconcileDB aborts the Nth Begin of a reconcile release
// pass — the per-row transaction boundary releaseOne commits at. Failing
// Begin #k with a real pool underneath leaves the exact durable state of
// a reconcile process killed after k−1 committed releases: a partial but
// consistent pass.
type n06p4t08FlakyReconcileDB struct {
	inner       *pgxpool.Pool
	mu          sync.Mutex
	begins      int
	failBeginAt int // 1-based; 0 disables
	failErr     error
}

func (w *n06p4t08FlakyReconcileDB) Begin(ctx context.Context) (pgx.Tx, error) {
	w.mu.Lock()
	w.begins++
	n := w.begins
	w.mu.Unlock()
	if w.failBeginAt == n {
		return nil, w.failErr
	}
	return w.inner.Begin(ctx)
}

func (w *n06p4t08FlakyReconcileDB) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	return w.inner.Exec(ctx, query, args...)
}

func (w *n06p4t08FlakyReconcileDB) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	return w.inner.Query(ctx, query, args...)
}

func (w *n06p4t08FlakyReconcileDB) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	return w.inner.QueryRow(ctx, query, args...)
}

// Axis 1 — the per-job crash window between the ledger write and the
// reservation release, healed by the production lease-expiry resume.
// Acceptance: the resume never duplicates the settle (Σ ledger rows stays
// exactly one) and never loses the release (the reserve moves exactly
// once, the §5.3 key commits with status='settled').
func TestN06P4T08Live_ChargeReleaseCrashWindowResumesExactlyOnce(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)
	c := n06p4t08Consumer(ctx, t, pool, rdb, "events:n06p4t08-a")

	// Priced client cancel of half the bound: four scope intents, each
	// settling min(actual, bound) = 5000 µUSD (D1 — the prefix bills once).
	const prefix = int64(5000)
	require.NoError(t, c.processMessage(ctx,
		n06p4t07CancelMsg("n06p4t08-a1", "req-n06p4t08-crash", n18dOrg, fx, "0.005", "0.005", false)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrg), "four scope intents, one org group → batch path first")

	// Tick 1 crashes twice at real statement boundaries:
	//   - the org batch aborts mid-transaction AFTER the in-tx ledger
	//     insert statement (strongest rollback window — nothing commits);
	//   - the same-tick per-job fallback re-executes from scratch, the
	//     wallet job's DeductMicro commits, and THEN its settle mark
	//     aborts — the exact durable state of a process killed between
	//     the ledger write and the reservation release.
	flaky := &flakySettlementDB{
		inner: pool,
		failNext: map[string]int{
			"UPDATE org_credits SET balance_cents": 1,
			"status = 'settled',":                  1,
		},
		failErr: errors.New("injected crash between charge and release"),
	}
	imp99r1Worker(flaky, pool).tick(ctx)

	// Crash-window state: the charge is durable, the release is lost, the
	// job sits claimed under a lease exactly as a killed executor leaves it.
	walletJob := n06p4t08JobID(ctx, t, pool, n18dOrg, "req-n06p4t08-crash", ChargeKindResaleDeduction)
	status, attempts, lastErr := jobStatus(ctx, t, pool, walletJob)
	require.Equal(t, "processing", status, "claimed when the settle aborted (last_err=%q)", lastErr)
	require.Equal(t, 1, attempts)
	assert.Nil(t, imp99r1SettleKey(ctx, t, pool, walletJob), "the §5.3 release never committed — no key without a decrement")

	st := imp99r1ReadScopeStates(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1), st.ledgerRows, "the wallet charge committed before the crash")
	assert.Equal(t, -prefix, st.ledgerMicro, "exactly the priced prefix, once")
	assert.Equal(t, int64(fx.bound), st.walletReserved, "the §5.3 release is lost — the crash window holds the full bound")
	assert.Equal(t, prefix, st.teamSpend, "the batch rollback lost nothing durable from the other scopes' fallback settles")
	assert.Equal(t, prefix, st.agentCost)
	assert.Equal(t, prefix, st.sessionSpent)
	assert.Equal(t, int64(fx.bound)-prefix, st.teamReserved, "team/agent/session settled by the same fallback — reserves moved once")
	assert.Equal(t, int64(fx.bound)-prefix, st.agentReserved)
	assert.Equal(t, int64(fx.bound)-prefix, st.sessionReserved)

	// The executor restarts: the lease-expiry recovery query re-queues the
	// abandoned job — the production resume path, no wall-clock sleep.
	_, err := pool.Exec(ctx,
		`UPDATE settlement_jobs SET lease_until = now() - interval '1 second' WHERE id = $1`, walletJob)
	require.NoError(t, err)
	imp99r1Worker(pool, pool).tick(ctx)

	status, attempts, lastErr = jobStatus(ctx, t, pool, walletJob)
	require.Equal(t, "settled", status, "attempts=%d last_err=%q", attempts, lastErr)
	require.Equal(t, 2, attempts, "recovered once by the lease-expiry pass, re-claimed exactly once")
	key := imp99r1SettleKey(ctx, t, pool, walletJob)
	require.NotNil(t, key, "the key commits exactly when the reserve moves")
	assert.Equal(t, prefix, *key, "min(actual, bound) recorded for the reconcile")

	st2 := imp99r1ReadScopeStates(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1), st2.ledgerRows, "the replayed DeductMicro is an idempotent no-op — never a second charge")
	assert.Equal(t, -prefix, st2.ledgerMicro)
	assert.Equal(t, int64(fx.bound)-prefix, st2.walletReserved,
		"the missed §5.3 bound decrement applies exactly once on resume — the reserve moves from the full bound to the settled remainder")
	assert.Equal(t, int64(fx.bound)-prefix, st2.teamReserved)
	assert.Equal(t, int64(fx.bound)-prefix, st2.agentReserved)
	assert.Equal(t, int64(fx.bound)-prefix, st2.sessionReserved)
	var keyRows int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM settlement_jobs WHERE id = $1 AND payload ? 'settle_decrement_micro_usd'`,
		walletJob).Scan(&keyRows))
	assert.Equal(t, int64(1), keyRows, "the settle key is written once — never re-inflated by the resume")

	// The three scopes settled during the crash tick are untouched by the
	// recovery (only 'processing' jobs re-queue).
	for _, kind := range []string{ChargeKindTeamSpend, ChargeKindAgentSpend, ChargeKindSessionSpend} {
		s, a, e := jobStatus(ctx, t, pool, n06p4t08JobID(ctx, t, pool, n18dOrg, "req-n06p4t08-crash", kind))
		assert.Equal(t, "settled", s, "%s (last_err=%q)", kind, e)
		assert.Equal(t, 1, a, "%s: the recovery must not re-run settled jobs", kind)
	}

	// Retry after recovery: a repeated tick adds nothing — Σ ledger rows
	// stays exactly one per operation.
	imp99r1Worker(pool, pool).tick(ctx)
	st3 := imp99r1ReadScopeStates(ctx, t, pool, n18dOrg)
	assert.Equal(t, st2, st3, "the repeat tick changes nothing")
}

// Axis 2 — the batch crash window after the in-tx ledger insert: the
// whole org batch rolls back (a partial ledger write never survives) and
// the same tick's per-job fallback applies every job exactly once.
func TestN06P4T08Live_BatchCrashRollsBackFallbackChargesExactlyOnce(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)
	c := n06p4t08Consumer(ctx, t, pool, rdb, "events:n06p4t08-b")

	require.NoError(t, c.processMessage(ctx,
		n18dCompletedMsg("n06p4t08-b1", "req-n06p4t08-batch", n18dOrg, fx)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrg), "four scope intents, one org group → batch path first")

	// The batch aborts AFTER the wallet ledger insert statement: the
	// ledger row, the spend upserts, the reserve decrements and the
	// settled marks were all in flight in one transaction — the crash
	// must roll ALL of it back (the batch executor's §5.5 promise).
	flaky := &flakySettlementDB{
		inner:    pool,
		failNext: map[string]int{"UPDATE org_credits SET balance_cents": 1},
		failErr:  errors.New("injected mid-batch crash"),
	}
	imp99r1Worker(flaky, pool).tick(ctx)

	// The same tick's per-job fallback applied every refused job exactly
	// once — with the batch's claim tokens (fencing intact, no second
	// claim: attempts stays 1 for every job).
	rows, err := pool.Query(ctx,
		`SELECT charge_kind, status, attempts FROM settlement_jobs WHERE org_id = $1 ORDER BY id`, n18dOrg)
	require.NoError(t, err)
	defer rows.Close()
	seen := map[string]string{}
	for rows.Next() {
		var kind, status string
		var attempts int
		require.NoError(t, rows.Scan(&kind, &status, &attempts))
		seen[kind] = status
		assert.Equal(t, 1, attempts, "%s: the fallback reuses the batch claim — never a second claim", kind)
	}
	require.NoError(t, rows.Err())
	require.Len(t, seen, 4)
	for _, kind := range []string{ChargeKindResaleDeduction, ChargeKindTeamSpend, ChargeKindAgentSpend, ChargeKindSessionSpend} {
		assert.Equal(t, "settled", seen[kind], "%s: the fallback applied the job", kind)
	}

	// Σ ledger rows is exactly ONE despite the mid-batch crash: the
	// batch's in-tx insert rolled back (a leaked insert plus the fallback
	// charge would make two), and the fallback charged once.
	st := imp99r1ReadScopeStates(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1), st.ledgerRows, "the batch rollback lost the partial write; the fallback charged exactly once")
	assert.Equal(t, -int64(fx.bound), st.ledgerMicro, "the exact completed-event amount, once")
	assert.Zero(t, st.walletReserved+st.teamReserved+st.agentReserved+st.sessionReserved,
		"§7.1.3: every scope reserve released exactly once")
	assert.Equal(t, int64(fx.bound), st.teamSpend)
	assert.Equal(t, int64(fx.bound), st.agentCost)
	assert.Equal(t, int64(fx.bound), st.sessionSpent)

	keyWallet, keyTeam, keyAgent, keySession := n06p4t07SettleKeys(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(fx.bound), keyWallet)
	assert.Equal(t, int64(fx.bound), keyTeam)
	assert.Equal(t, int64(fx.bound), keyAgent)
	assert.Equal(t, int64(fx.bound), keySession)

	// A repeat tick re-bills and re-releases nothing.
	imp99r1Worker(pool, pool).tick(ctx)
	st2 := imp99r1ReadScopeStates(ctx, t, pool, n18dOrg)
	assert.Equal(t, st, st2, "the repeat tick changes nothing")
}

// Axis 3 — the interrupted reconcile release pass converges to the same
// verdict as an uninterrupted one: each allowance released exactly once,
// no stranded capacity, no duplicate return, a third pass no-op.
func TestN06P4T08Live_InterruptedReconcilePassConverges(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)
	c := n06p4t08Consumer(ctx, t, pool, rdb, "events:n06p4t08-c")

	// Unknown-cancel outcome: the unknown shape — three zero-amount spend
	// intents plus the single pending_price record, never a wallet charge
	// (D2) — and this test never ticks the settlement worker, so every
	// reserve holds the full bound (ADR-0001 §6; the reconcile is their
	// only release path here).
	require.NoError(t, c.processMessage(ctx,
		n06p4t07CancelMsg("n06p4t08-c1", "req-n06p4t08-rc", n18dOrg, fx, "", "", true)))
	var pendingPrice int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM settlement_jobs WHERE org_id = $1 AND charge_kind = $2`,
		n18dOrg, ChargeKindPendingPrice).Scan(&pendingPrice))
	require.Equal(t, int64(1), pendingPrice, "one pending_price record keeps the unknown durably visible")
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrg), "three zero-amount spend intents + one pending_price")
	st := imp99r1ReadScopeStates(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(fx.bound), st.walletReserved)
	assert.Equal(t, int64(fx.bound), st.teamReserved)
	assert.Equal(t, int64(fx.bound), st.agentReserved)
	assert.Equal(t, int64(fx.bound), st.sessionReserved)

	n06p4t07LapseAllowances(ctx, t, pool, n18dOrg, "3 hours")

	// Interrupted pass: releaseOne #1 (the wallet allowance — candidates
	// walk in id order) commits; Begin #2 aborts — a reconcile process
	// killed mid-pass.
	flaky := &n06p4t08FlakyReconcileDB{inner: pool, failBeginAt: 2, failErr: errors.New("injected reconcile crash")}
	interrupted := budget.NewReconcileWorker(flaky, silentLogger(), budget.DefaultReconcileConfig())
	summary, err := interrupted.ReleasePass(ctx)
	require.Error(t, err, "the pass dies at the second candidate")
	assert.Equal(t, int64(1), summary.Released, "exactly the first candidate released before the crash")
	assert.Equal(t, int64(fx.bound), summary.ReturnedMicroUSD)

	// The crash state is partial but consistent: the wallet is released
	// exactly once (returned = granted − settled = the full bound), the
	// other three scopes still hold their stakes.
	statuses := n06p4t07AllowanceStatuses(ctx, t, pool, n18dOrg)
	assert.Equal(t, "released", statuses["wallet"])
	assert.Equal(t, "active", statuses["team_month"])
	assert.Equal(t, "active", statuses["agent_day"])
	assert.Equal(t, "active", statuses["session"])
	var released int64
	var returned int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE status = 'released'), COALESCE(SUM(returned_micro_usd), 0)
		 FROM budget_allowances WHERE org_id = $1`, n18dOrg).Scan(&released, &returned))
	assert.Equal(t, int64(1), released)
	assert.Equal(t, int64(fx.bound), returned, "the returned remainder is exact — never a double return")

	// Resume: the restarted worker's pass releases the rest.
	resumed := budget.NewReconcileWorker(pool, silentLogger(), budget.DefaultReconcileConfig())
	summary2, err := resumed.ReleasePass(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), summary2.Released, "the remaining three candidates release on resume")
	assert.Equal(t, 3*int64(fx.bound), summary2.ReturnedMicroUSD)

	// Convergence: the two passes together match an uninterrupted one —
	// every allowance released exactly once, every stake returned.
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE status = 'released'), COALESCE(SUM(returned_micro_usd), 0)
		 FROM budget_allowances WHERE org_id = $1`, n18dOrg).Scan(&released, &returned))
	assert.Equal(t, int64(4), released)
	assert.Equal(t, 4*int64(fx.bound), returned, "returned = granted − settled for every scope, once")
	st2 := imp99r1ReadScopeStates(ctx, t, pool, n18dOrg)
	assert.Zero(t, st2.walletReserved+st2.teamReserved+st2.agentReserved+st2.sessionReserved,
		"every scope reserve drained — no eternal hold, no stranded capacity")

	// §7.1.3 scoped to this test's own rows: side A (spend-table reserves)
	// must equal side B (granted − returned − Σ settled keys over this
	// org's allowances). The worker's CheckInvariants is a GLOBAL sweep —
	// sound only on an empty database, and the package shares one
	// disposable Postgres — so the convergence verdict here is org-scoped
	// by construction, the same math over this test's world.
	var divergence int64
	require.NoError(t, pool.QueryRow(ctx, `
		WITH reserved AS (
			SELECT (SELECT COALESCE(SUM(reserved_micro_usd), 0) FROM org_credits WHERE org_id = $1)
			     + (SELECT COALESCE(SUM(reserved_micro_usd), 0) FROM team_spend_monthly WHERE team_id = $2)
			     + (SELECT COALESCE(SUM(reserved_micro_usd), 0) FROM agent_spend_daily WHERE agent_id = $3)
			     + (SELECT COALESCE(SUM(reserved_micro_usd), 0) FROM session_spend WHERE session_key_id = $4) AS v
		),
		remainder AS (
			SELECT COALESCE(SUM(GREATEST(a.granted_micro_usd - a.returned_micro_usd - COALESCE((
				SELECT SUM(COALESCE((j.payload->>'settle_decrement_micro_usd')::bigint, 0))
				FROM settlement_jobs j WHERE j.allowance_id = a.id), 0), 0)), 0) AS v
			FROM budget_allowances a
			WHERE a.org_id = $1 AND a.status <> 'released'
		)
		SELECT ABS((SELECT v FROM reserved) - (SELECT v FROM remainder))`,
		n18dOrg, n18dTeam, n18dAgent, n18dSession).Scan(&divergence))
	assert.Zero(t, divergence, "§7.1.3: every scope of this world balanced after the resumed pass — nothing stranded")

	// Idempotence: a third pass finds nothing — no duplicate release rows,
	// nothing lost.
	summary3, err := resumed.ReleasePass(ctx)
	require.NoError(t, err)
	assert.Zero(t, summary3.Released)
	assert.Zero(t, summary3.ReturnedMicroUSD)
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*), COALESCE(SUM(returned_micro_usd), 0)
		 FROM budget_allowances WHERE org_id = $1 AND status = 'released'`, n18dOrg).Scan(&released, &returned))
	assert.Equal(t, int64(4), released)
	assert.Equal(t, 4*int64(fx.bound), returned, "the returned sums stay exact — the retry cannot double-return")
}

// Axis 4 — the uncharged-unknown signal across a delivery retry: exactly
// one increment per scope, never re-inflated by the redelivery of the
// same entry id (the crash-after-increment retry), with the T07
// known-zero semantics holding under retry too.
func TestN06P4T08Live_UnknownRetryCountsExactlyOnce(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)
	c := n06p4t08Consumer(ctx, t, pool, rdb, "events:n06p4t08-d")

	before := n06p4t08UnknownSnapshot()
	msg := n06p4t07CancelMsg("n06p4t08-d1", "req-n06p4t08-unk", n18dOrg, fx, "", "", true)
	require.NoError(t, c.processMessage(ctx, msg))

	afterFirst := n06p4t08UnknownSnapshot()
	for scope, got := range afterFirst {
		assert.InDelta(t, before[scope]+float64(fx.bound), got, 0.001,
			"first delivery counts the bound once, scope %s", scope)
	}

	// Durable visibility is transactional: the unknown shape is the three
	// zero-amount spend intents plus the single pending_price record —
	// never a wallet charge intent (D2), and every row commits once.
	var pendingPrice int64
	countPending := func() int64 {
		t.Helper()
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM settlement_jobs WHERE org_id = $1 AND charge_kind = $2`,
			n18dOrg, ChargeKindPendingPrice).Scan(&pendingPrice))
		return pendingPrice
	}
	require.Equal(t, int64(1), countPending(), "one pending_price record keeps the unknown durably visible")
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrg), "three zero-amount spend intents + one pending_price, nothing else")

	// The retry: the same entry id redelivered (the crash-after-increment
	// retry) must NOT re-inflate the signal — exactly one increment per
	// scope across the whole retry cycle.
	require.NoError(t, c.processMessage(ctx, msg))
	afterRetry := n06p4t08UnknownSnapshot()
	for scope, got := range afterRetry {
		assert.InDelta(t, afterFirst[scope], got, 0.001,
			"the retry re-inflates the uncharged-unknown signal, scope %s", scope)
	}
	require.Equal(t, int64(1), countPending(), "the redelivery duplicates no pending_price row")
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrg), "the redelivery writes nothing durable")

	// T07 known-zero semantics hold under retry: a provably-free cancel
	// never counts, and its redelivery does not make it count.
	zeroBefore := n06p4t08UnknownSnapshot()
	zeroMsg := n06p4t07CancelMsg("n06p4t08-d2", "req-n06p4t08-zero", n18dOrg, fx, "0.000000", "0.000000", false)
	require.NoError(t, c.processMessage(ctx, zeroMsg))
	require.NoError(t, c.processMessage(ctx, zeroMsg))
	for scope, got := range n06p4t08UnknownSnapshot() {
		assert.InDelta(t, zeroBefore[scope], got, 0.001,
			"known-zero cancels (and their retries) never count as unknown, scope %s", scope)
	}
}
