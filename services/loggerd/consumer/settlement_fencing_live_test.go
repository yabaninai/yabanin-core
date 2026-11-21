package consumer

// Worker-path fencing acceptance (0028/0029 invocation ledger, disposable
// migrated PG): a worker whose claim was superseded — by a NEWER claim
// (attempts bumped) or by LEASE RECOVERY while its token still matches
// (status flipped to 'retry', attempts UNCHANGED) — must not touch those
// jobs again: no batch settle, no per-job fallback writes, no
// retry/requires-attention marks that could overwrite the rightful state.
// The rightful worker then settles the re-claimed jobs exactly once.
// Drives the REAL worker methods (claimBatch/executeOrgBatch/markRetry/
// markRequiresAttention/recoverExpiredLeases), not budget.SettleOrgBatch
// directly, and asserts fenced attempts change NOTHING — status, attempts,
// last_error, next_attempt_at (NOT NULL since 0001 — compared, never
// nil-asserted), lease_until and the wallet are snapshotted and required
// equal.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fencingSeedWorld creates one org with a 10000c wallet and a clean slate.
func fencingSeedWorld(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $2)
		ON CONFLICT (id) DO NOTHING`, org, "fence-"+org)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO org_credits (org_id, balance_cents, remainder_micro_usd)
		VALUES ($1, 10000, 0)
		ON CONFLICT (org_id) DO UPDATE SET balance_cents = 10000,
			remainder_micro_usd = 0, reserved_micro_usd = 0`, org)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `DELETE FROM credit_transactions WHERE org_id = $1`, org)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `DELETE FROM settlement_jobs WHERE org_id = $1`, org)
	require.NoError(t, err)
}

// fencingSeedInvocationJob inserts a pending resale job carrying the
// billed invocation identity (the 0028+ claim projection shape).
func fencingSeedInvocationJob(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org, requestID, invocationID string, amount money.MicroUSD) int64 {
	t.Helper()
	payload, err := json.Marshal(resaleChargePayload{Model: "m", TokensIn: 1, TokensOut: 2, CostUSD: 0.003, ResaleUSD: 0.0045})
	require.NoError(t, err)
	var id int64
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO settlement_jobs (org_id, request_id, invocation_id, charge_kind, amount_cents, amount_micro_usd, status, payload)
		VALUES ($1, $2, $3, 'resale_deduction', $4, $5, 'pending', $6)
		RETURNING id`, org, requestID, invocationID, amount.Cents(), int64(amount), payload).Scan(&id),
		"seed invocation job")
	return id
}

// fencingJobSnapshot is one job row's full mutable state — next_attempt_at
// is NOT NULL (0001) and lease_until flips between the claim and recovery
// states, so every field is captured by value and compared structurally.
type fencingJobSnapshot struct {
	status      string
	attempts    int
	lastError   *string
	nextAttempt string
	leaseUntil  *string
}

func fencingSnapshot(ctx context.Context, t *testing.T, pool *pgxpool.Pool, jobID int64) fencingJobSnapshot {
	t.Helper()
	var s fencingJobSnapshot
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT status::text, attempts, last_error, next_attempt_at::text, lease_until::text
		FROM settlement_jobs WHERE id = $1`, jobID).Scan(
		&s.status, &s.attempts, &s.lastError, &s.nextAttempt, &s.leaseUntil))
	return s
}

func fencingSnapshots(ctx context.Context, t *testing.T, pool *pgxpool.Pool, jobIDs []int64) []fencingJobSnapshot {
	t.Helper()
	out := make([]fencingJobSnapshot, len(jobIDs))
	for i, id := range jobIDs {
		out[i] = fencingSnapshot(ctx, t, pool, id)
	}
	return out
}

func fencingWallet(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string) (balanceCents, remainderMicro, ledgerRows, ledgerMicro int64) {
	t.Helper()
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT (SELECT balance_cents FROM org_credits WHERE org_id = $1),
		       (SELECT remainder_micro_usd FROM org_credits WHERE org_id = $1),
		       (SELECT count(*) FROM credit_transactions WHERE org_id = $1 AND type = 'usage'),
		       (SELECT COALESCE(SUM(amount_micro_usd), 0) FROM credit_transactions WHERE org_id = $1 AND type = 'usage')`,
		org).Scan(&balanceCents, &remainderMicro, &ledgerRows, &ledgerMicro))
	return balanceCents, remainderMicro, ledgerRows, ledgerMicro
}

// TestSettlementWorkerCompetingClaims: a NEWER claim supersedes the stale
// worker's (attempts bumped, status still 'processing'). The token
// mismatch alone must fence the batch and the terminal marks; nothing —
// rows or money — may change; the rightful worker then settles exactly
// once.
func TestSettlementWorkerCompetingClaims(t *testing.T) {
	ctx, pool, _ := newNext18dEnv(t)

	const org = "77777777-7777-4777-8777-7777777777f1"
	const sharedReq = "wfnc-worker-shared-request"
	invocations := []string{
		"88888888-8888-4888-8888-888888888881",
		"88888888-8888-4888-8888-888888888882",
		"88888888-8888-4888-8888-888888888883",
	}
	fencingSeedWorld(ctx, t, pool, org)
	amount := money.MicroUSD(1_500_005) // 150c + 5µ each
	jobIDs := make([]int64, len(invocations))
	for i, inv := range invocations {
		jobIDs[i] = fencingSeedInvocationJob(ctx, t, pool, org, sharedReq, inv, amount)
	}

	w1 := imp99r1Worker(pool, pool)
	claimed, err := w1.claimBatch(ctx)
	require.NoError(t, err)
	require.Len(t, claimed, 3)
	for _, job := range claimed {
		require.Equal(t, 1, job.Attempts, "first claim holds token 1")
		require.NotNil(t, job.InvocationID, "claim projects the invocation identity")
	}
	groups := groupJobsByOrg(claimed)
	require.Len(t, groups, 1)
	require.Len(t, groups[0], 3)

	// A NEWER worker re-claims mid-flight (attempts bumped; the claim
	// keeps status 'processing') — exactly what claimBatch's UPDATE does.
	_, err = pool.Exec(ctx, `UPDATE settlement_jobs SET attempts = attempts + 1 WHERE org_id = $1`, org)
	require.NoError(t, err)

	// The stale state every fenced attempt below must preserve verbatim.
	staleSnap := fencingSnapshots(ctx, t, pool, jobIDs)
	staleBal, staleRem, staleRows, staleMicro := fencingWallet(ctx, t, pool, org)

	assert.Equal(t, orgBatchStale, w1.executeOrgBatch(ctx, groups[0]),
		"superseded claim must report stale, not fallback")
	w1.markRetry(ctx, &claimed[0], errors.New("stale boom"))
	w1.markRequiresAttention(ctx, &claimed[1], errors.New("stale boom"), "test")

	assert.Equal(t, staleSnap, fencingSnapshots(ctx, t, pool, jobIDs),
		"stale batch and fenced terminal marks change no job field at all")
	bal, rem, rows, micro := fencingWallet(ctx, t, pool, org)
	assert.Equal(t, staleBal, bal, "stale batch moves no money")
	assert.Equal(t, staleRem, rem)
	assert.Equal(t, staleRows, rows, "stale batch writes no ledger row")
	assert.Equal(t, staleMicro, micro)
	for _, s := range staleSnap {
		assert.Equal(t, "processing", s.status, "rightful claim's state untouched")
		assert.Equal(t, 2, s.attempts)
	}

	// The RIGHTFUL worker settles the re-claimed group exactly once:
	// three independent invocation charges under one client request id.
	w2 := imp99r1Worker(pool, pool)
	reclaimed, err := w2.claimBatch(ctx)
	require.NoError(t, err)
	require.Empty(t, reclaimed, "claims are still leased — nothing to re-claim yet")

	// Hand the lease back the way expiry would, then re-claim for real.
	_, err = pool.Exec(ctx, `UPDATE settlement_jobs SET lease_until = now() - interval '5s' WHERE org_id = $1`, org)
	require.NoError(t, err)
	require.NoError(t, w2.recoverExpiredLeases(ctx))
	for _, id := range jobIDs {
		s := fencingSnapshot(ctx, t, pool, id)
		require.Equal(t, "retry", s.status)
		require.Equal(t, 2, s.attempts, "recovery does not bump attempts")
	}
	reclaimed, err = w2.claimBatch(ctx)
	require.NoError(t, err)
	require.Len(t, reclaimed, 3)
	for _, job := range reclaimed {
		require.Equal(t, 3, job.Attempts, "re-claim holds token 3")
	}
	groups2 := groupJobsByOrg(reclaimed)
	require.Len(t, groups2, 1)
	assert.Equal(t, orgBatchCommitted, w2.executeOrgBatch(ctx, groups2[0]))

	for _, id := range jobIDs {
		assert.Equal(t, "settled", fencingSnapshot(ctx, t, pool, id).status)
	}
	bal, rem, rows, micro = fencingWallet(ctx, t, pool, org)
	assert.EqualValues(t, 9_550, bal, "three independent 150c charges")
	assert.EqualValues(t, 15, rem, "three 5µ rests carried")
	assert.EqualValues(t, 3, rows, "one ledger row per invocation")
	assert.EqualValues(t, -4_500_015, micro)

	var invSeen []string
	invRows, err := pool.Query(ctx, `SELECT invocation_id FROM credit_transactions WHERE org_id = $1 AND type = 'usage' ORDER BY id`, org)
	require.NoError(t, err)
	defer invRows.Close()
	for invRows.Next() {
		var inv *string
		require.NoError(t, invRows.Scan(&inv))
		require.NotNil(t, inv)
		invSeen = append(invSeen, *inv)
	}
	require.NoError(t, invRows.Err())
	assert.ElementsMatch(t, invocations, invSeen, "ledger keyed by the minted invocation uuids")
}

// TestSettlementWorkerRecoveredLeaseSameToken: the control the STATUS
// predicate of the fencing read exists for. The stale worker's token still
// matches settlement_jobs.attempts after recoverExpiredLeases (recovery
// does NOT bump attempts), so ONLY `AND status = 'processing'` fences the
// stale batch. A focused negative mutation below removes exactly that
// predicate from the fencing SELECT to prove this control bites: without
// it, the read locks and passes the recovered rows.
func TestSettlementWorkerRecoveredLeaseSameToken(t *testing.T) {
	ctx, pool, _ := newNext18dEnv(t)

	const org = "99999999-9999-4999-8999-9999999999f2"
	const sharedReq = "wfnc-same-token-recovery"
	invocations := []string{
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2",
	}
	fencingSeedWorld(ctx, t, pool, org)
	amount := money.MicroUSD(1_500_000)
	jobIDs := make([]int64, len(invocations))
	for i, inv := range invocations {
		jobIDs[i] = fencingSeedInvocationJob(ctx, t, pool, org, sharedReq, inv, amount)
	}

	// A GENUINE claim: the worker holds token 1 on 'processing' rows.
	w0 := imp99r1Worker(pool, pool)
	claimed, err := w0.claimBatch(ctx)
	require.NoError(t, err)
	require.Len(t, claimed, 2)
	for _, job := range claimed {
		require.Equal(t, 1, job.Attempts)
		require.NotNil(t, job.InvocationID)
	}
	groups := groupJobsByOrg(claimed)
	require.Len(t, groups, 1)
	require.Len(t, groups[0], 2)

	// The lease expires and recovery runs — the stale worker is NOT
	// re-claiming, so attempts stay at its token.
	_, err = pool.Exec(ctx, `UPDATE settlement_jobs SET lease_until = now() - interval '5s' WHERE org_id = $1`, org)
	require.NoError(t, err)
	require.NoError(t, w0.recoverExpiredLeases(ctx))

	// Precondition of this control: the DB attempts EQUAL the stale
	// worker's claimed token after the real recovery SQL ran — the token
	// alone cannot detect the lost ownership.
	for i, id := range jobIDs {
		s := fencingSnapshot(ctx, t, pool, id)
		require.Equal(t, "retry", s.status, "recovery requeued the job")
		require.Equal(t, claimed[i].Attempts, s.attempts,
			"recovered row keeps the stale worker's token — only the status predicate can fence")
	}

	// Focused negative mutation: the fencing SELECT with ONLY the status
	// predicate removed (token filter kept) still locks these rows — i.e.
	// that mutant would pass the fence and settle requeued jobs. The
	// production read (with the predicate) must therefore fence below.
	// (FOR UPDATE cannot combine with count(*): select the ids.)
	mutantRows, err := pool.Query(ctx, `
		SELECT id FROM settlement_jobs
		WHERE id = ANY($1::bigint[]) AND attempts = 1
		FOR UPDATE`, jobIDs)
	require.NoError(t, err)
	mutantLocked := 0
	for mutantRows.Next() {
		var id int64
		require.NoError(t, mutantRows.Scan(&id))
		mutantLocked++
	}
	require.NoError(t, mutantRows.Err())
	mutantRows.Close()
	assert.Equal(t, len(jobIDs), mutantLocked,
		"mutation probe: without `AND status = 'processing'` the fencing read would lock the recovered rows")

	// Snapshot AFTER the real recovery SQL (its writes are the baseline
	// the stale attempts must not disturb) and require atomic equality.
	recoveredSnap := fencingSnapshots(ctx, t, pool, jobIDs)
	recBal, recRem, recRows, recMicro := fencingWallet(ctx, t, pool, org)

	assert.Equal(t, orgBatchStale, w0.executeOrgBatch(ctx, groups[0]),
		"recovered-but-not-reclaimed jobs must fence despite the matching token")
	w0.markRetry(ctx, &claimed[0], errors.New("stale boom"))
	w0.markRequiresAttention(ctx, &claimed[1], errors.New("stale boom"), "test")

	assert.Equal(t, recoveredSnap, fencingSnapshots(ctx, t, pool, jobIDs),
		"stale batch and fenced marks change no field of the requeued state")
	bal, rem, rows, micro := fencingWallet(ctx, t, pool, org)
	assert.Equal(t, recBal, bal)
	assert.Equal(t, recRem, rem)
	assert.Equal(t, recRows, rows)
	assert.Equal(t, recMicro, micro)

	// The rightful worker re-claims (token 2) and settles exactly once.
	w2 := imp99r1Worker(pool, pool)
	reclaimed, err := w2.claimBatch(ctx)
	require.NoError(t, err)
	require.Len(t, reclaimed, 2)
	for _, job := range reclaimed {
		require.Equal(t, 2, job.Attempts)
	}
	groups2 := groupJobsByOrg(reclaimed)
	require.Len(t, groups2, 1)
	assert.Equal(t, orgBatchCommitted, w2.executeOrgBatch(ctx, groups2[0]))
	for _, id := range jobIDs {
		assert.Equal(t, "settled", fencingSnapshot(ctx, t, pool, id).status)
	}
	bal, rem, rows, micro = fencingWallet(ctx, t, pool, org)
	assert.EqualValues(t, 9_700, bal, "two independent 150c charges, exactly once")
	assert.EqualValues(t, 0, rem, "whole-cent charges carry no micro rests — the seeded zero remainder stays")
	assert.EqualValues(t, 2, rows)
	assert.EqualValues(t, -3_000_000, micro)
}
