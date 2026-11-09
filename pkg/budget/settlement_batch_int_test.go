//go:build integration

// NEXT-18d live acceptance (disposable PG, ADR-0001 rev. 3 §10.5): the
// batched settlement transaction is semantically EQUIVALENT to applying the
// jobs sequentially in id order — same wallet carry, same floor crossings,
// same idempotent no-ops, same reserve decrement sum. The sequential side
// of every property below is the production per-job implementation
// (credits.Store.DeductMicro, Record*SpendExact), never a re-model.
//
// Schema note: the §13 reservation objects (budget_allowances, reserved
// fixture applies the same idempotent DDL block so the tests run both
// before and after that merge; once 0023 is applied by the migrations
// runner, every statement here is a no-op.
package budget

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// applyReservationSchemaFixture mirrors the §13 schema block (ADR-0001 rev.
// 3) — every statement idempotent, additive only.
func applyReservationSchemaFixture(ctx context.Context, tb testing.TB, pool *pgxpool.Pool) {
	tb.Helper()
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS budget_allowances (
			id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
			replica_id text NOT NULL,
			scope_kind text NOT NULL CHECK (scope_kind IN ('wallet','team_month','agent_day','session')),
			scope_key text NOT NULL,
			period text NOT NULL DEFAULT '',
			org_id text NOT NULL,
			granted_micro_usd bigint NOT NULL DEFAULT 0 CHECK (granted_micro_usd >= 0),
			returned_micro_usd bigint NOT NULL DEFAULT 0 CHECK (returned_micro_usd >= 0),
			status text NOT NULL DEFAULT 'active'
				CHECK (status IN ('active','expired','draining','released')),
			lease_until timestamptz NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT budget_allowances_key UNIQUE (replica_id, scope_kind, scope_key, period)
		)`)
	require.NoError(tb, err, "fixture budget_allowances")
	_, err = pool.Exec(ctx, `
		ALTER TABLE org_credits ADD COLUMN IF NOT EXISTS reserved_micro_usd bigint NOT NULL DEFAULT 0 CHECK (reserved_micro_usd >= 0),
		                 ADD COLUMN IF NOT EXISTS grace_floor_cents bigint CHECK (grace_floor_cents BETWEEN -100000 AND 0)`)
	require.NoError(tb, err, "fixture org_credits columns")
	_, err = pool.Exec(ctx, `
		ALTER TABLE team_spend_monthly ADD COLUMN IF NOT EXISTS spend_micro_usd bigint NOT NULL DEFAULT 0,
		                               ADD COLUMN IF NOT EXISTS reserved_micro_usd bigint NOT NULL DEFAULT 0 CHECK (reserved_micro_usd >= 0)`)
	require.NoError(tb, err, "fixture team_spend_monthly columns")
	_, err = pool.Exec(ctx, `ALTER TABLE agent_spend_daily ADD COLUMN IF NOT EXISTS reserved_micro_usd bigint NOT NULL DEFAULT 0 CHECK (reserved_micro_usd >= 0)`)
	require.NoError(tb, err, "fixture agent_spend_daily column")
	_, err = pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS session_spend (
			session_key_id uuid PRIMARY KEY,
			spent_micro_usd bigint NOT NULL DEFAULT 0,
			reserved_micro_usd bigint NOT NULL DEFAULT 0 CHECK (reserved_micro_usd >= 0),
			updated_at timestamptz NOT NULL DEFAULT now()
		)`)
	require.NoError(tb, err, "fixture session_spend")
	_, err = pool.Exec(ctx, `ALTER TABLE settlement_jobs ADD COLUMN IF NOT EXISTS allowance_id bigint`)
	require.NoError(tb, err, "fixture settlement_jobs.allowance_id")
}

// seedBatchWallet creates the org row and a wallet with the given state.
func seedBatchWallet(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, org string, balanceCents, remainderMicro int64) {
	tb.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $2)
		ON CONFLICT (id) DO NOTHING`, org, "batch-"+org)
	require.NoError(tb, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO org_credits (org_id, balance_cents, remainder_micro_usd)
		VALUES ($1, $2, $3)
		ON CONFLICT (org_id) DO UPDATE SET balance_cents = EXCLUDED.balance_cents,
			remainder_micro_usd = EXCLUDED.remainder_micro_usd`,
		org, balanceCents, remainderMicro)
	require.NoError(tb, err)
	_, err = pool.Exec(ctx, `DELETE FROM credit_transactions WHERE org_id = $1`, org)
	require.NoError(tb, err)
	_, err = pool.Exec(ctx, `DELETE FROM settlement_jobs WHERE org_id = $1`, org)
	require.NoError(tb, err)
}

func settlementWalletState(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, org string) (balanceCents, remainderMicro int64) {
	tb.Helper()
	err := pool.QueryRow(ctx,
		`SELECT balance_cents, remainder_micro_usd FROM org_credits WHERE org_id = $1`, org).
		Scan(&balanceCents, &remainderMicro)
	require.NoError(tb, err)
	return balanceCents, remainderMicro
}

func walletLedger(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, org string) (rows int64, microSum int64) {
	tb.Helper()
	err := pool.QueryRow(ctx, `
		SELECT count(*), COALESCE(SUM(amount_micro_usd), 0) FROM credit_transactions
		WHERE org_id = $1 AND type = 'usage'`, org).Scan(&rows, &microSum)
	require.NoError(tb, err)
	return rows, microSum
}

// seedBatchJob inserts a pending settlement_jobs row the way the consumer's
// delivery transaction would, returning its generated id.
func seedBatchJob(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, org, requestID, kind string, amount money.MicroUSD, payload []byte) int64 {
	tb.Helper()
	var id int64
	err := pool.QueryRow(ctx, `
		INSERT INTO settlement_jobs (org_id, request_id, charge_kind, amount_cents, amount_micro_usd, status, payload)
		VALUES ($1, $2, $3, $4, $5, 'pending', $6)
		RETURNING id`, org, requestID, kind, amount.Cents(), int64(amount), payload).Scan(&id)
	require.NoError(tb, err, "seed settlement job")
	return id
}

// testUUID derives a valid UUID-shaped id from a tag and a counter —
// organizations.id and the team/agent/session keys are uuid columns.
func testUUID(tag uint32, n uint64) string {
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", tag, n)
}

// randomAmounts draws the iteration's job amounts (the shared random input
// both sides of the equivalence property apply).
func randomAmounts(rng *rand.Rand, maxJobs int) []money.MicroUSD {
	n := rng.Intn(maxJobs) + 1
	amounts := make([]money.MicroUSD, 0, n)
	for i := 0; i < n; i++ {
		amounts = append(amounts, money.MicroUSD(rng.Int63n(300_0000)+1))
	}
	return amounts
}

// batchEntriesFor seeds pending jobs for ONE org from the shared amounts.
// Request ids are org-scoped: the usage idempotency index is GLOBAL per
// request_id, so the two sides of the property must never share ids (a
// shared id would be the foreign-org identity conflict, by design).
func batchEntriesFor(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, org, tag string, amounts []money.MicroUSD) []SettleEntry {
	tb.Helper()
	entries := make([]SettleEntry, 0, len(amounts))
	for i, amount := range amounts {
		requestID := fmt.Sprintf("%s-%s-%d", tag, org, i)
		entries = append(entries, SettleEntry{
			JobID:     seedBatchJob(ctx, tb, pool, org, requestID, SettleKindResale, amount, []byte(`{}`)),
			RequestID: requestID,
			Kind:      SettleKindResale,
			Amount:    amount,
			Payload:   []byte(`{}`),
		})
	}
	return entries
}

// runSequentialWallet applies the entries with the production per-job
// executor in id order and reports which entries applied.
func runSequentialWallet(ctx context.Context, tb testing.TB, store *credits.Store, org string, entries []SettleEntry) map[int64]bool {
	tb.Helper()
	applied := make(map[int64]bool, len(entries))
	for _, e := range entries {
		err := store.DeductMicro(ctx, org, e.Amount, e.RequestID, map[string]any{
			"model": "", "tokens": int64(0), "amount_micro_usd": int64(e.Amount),
		})
		if err == nil {
			applied[e.JobID] = true
			continue
		}
		require.True(tb, credits.IsInsufficientCredits(err), "sequential reference: unexpected error %v", err)
		applied[e.JobID] = false
	}
	return applied
}

// runBatchWallet applies the same entries through the §5.5 batch executor.
func runBatchWallet(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, org string, floorCents int64, entries []SettleEntry) map[int64]BatchDisposition {
	tb.Helper()
	dispositions, err := SettleOrgBatch(ctx, pool, org, floorCents, entries, BatchSpenders{})
	require.NoError(tb, err, "batch execution")
	require.Len(tb, dispositions, len(entries))
	return dispositions
}

// Property (ADR-0001 §10.5): batch ≡ sequential on random amounts,
// remainders and floor crossings — final wallet state, per-job outcomes and
// the resulting ledger rows must all agree, and a replay of the same batch
// is an idempotent no-op (ON CONFLICT DO NOTHING semantics).
func TestSettleOrgBatch_EquivalentToSequential(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	applyReservationSchemaFixture(ctx, t, pool)

	rng := rand.New(rand.NewSource(181818)) //nolint:gosec // property fixture, not crypto
	const iterations = 120
	for iter := 0; iter < iterations; iter++ {
		orgSeq := testUUID(0x1818, uint64(iter)*2+1)
		orgBat := testUUID(0x1818, uint64(iter)*2+2)
		floorCents := -rng.Int63n(101) // 0 … −$1.00
		balance := rng.Int63n(600_00)  // $0 … $600
		remainder := rng.Int63n(int64(money.MicroPerCent))

		store := credits.NewStoreWithConfig(pool, nil, credits.Config{GracePeriodCents: floorCents})
		seedBatchWallet(ctx, t, pool, orgSeq, balance, remainder)
		seedBatchWallet(ctx, t, pool, orgBat, balance, remainder)

		amounts := randomAmounts(rng, 8)
		seqEntries := batchEntriesFor(ctx, t, pool, orgSeq, "seq", amounts)
		batEntries := batchEntriesFor(ctx, t, pool, orgBat, "bat", amounts)

		seqApplied := runSequentialWallet(ctx, t, store, orgSeq, seqEntries)
		batchDisp := runBatchWallet(ctx, t, pool, orgBat, floorCents, batEntries)

		// Per-job outcomes agree (same amounts in the same order).
		for i, amount := range amounts {
			e := seqEntries[i]
			d := batchDisp[batEntries[i].JobID]
			if seqApplied[e.JobID] {
				assert.Truef(t, d.Settled && d.Applied, "iter %d job %d (%dµ): sequential applied, batch did not (%+v)", iter, i, amount, d)
			} else {
				assert.Falsef(t, d.Settled, "iter %d job %d (%dµ): sequential blocked, batch settled", iter, i, amount)
				assert.Equalf(t, ReasonInsufficientCredits, d.Reason, "iter %d job %d: blocked reason", iter, i)
			}
		}

		// Final wallet state agrees.
		seqBalance, seqRemainder := settlementWalletState(ctx, t, pool, orgSeq)
		batBalance, batRemainder := settlementWalletState(ctx, t, pool, orgBat)
		assert.Equalf(t, seqBalance, batBalance, "iter %d: final balance", iter)
		assert.Equalf(t, seqRemainder, batRemainder, "iter %d: final remainder", iter)

		// Ledger rows agree (count, exact µ sum).
		seqRows, seqMicro := walletLedger(ctx, t, pool, orgSeq)
		batRows, batMicro := walletLedger(ctx, t, pool, orgBat)
		assert.Equalf(t, seqRows, batRows, "iter %d: ledger row count", iter)
		assert.Equalf(t, seqMicro, batMicro, "iter %d: ledger micro sum", iter)

		// Replay: the same batch again — entries that applied settle as
		// idempotent no-ops (ON CONFLICT DO NOTHING); entries the first run
		// parked (floor crossing) stay parked — the wallet they would cross
		// is unchanged.
		replay := runBatchWallet(ctx, t, pool, orgBat, floorCents, batEntries)
		for i := range amounts {
			if seqApplied[seqEntries[i].JobID] {
				assert.Truef(t, replay[batEntries[i].JobID].Settled, "iter %d job %d: replay settles (disp=%+v)", iter, i, replay[batEntries[i].JobID])
				assert.Falsef(t, replay[batEntries[i].JobID].Applied, "iter %d job %d: replay never re-applies", iter, i)
			} else {
				assert.Falsef(t, replay[batEntries[i].JobID].Settled, "iter %d job %d: replayed blocked job stays parked", iter, i)
				assert.Equalf(t, ReasonInsufficientCredits, replay[batEntries[i].JobID].Reason, "iter %d job %d: replay blocked reason", iter, i)
			}
		}
		replayBalance, replayRemainder := settlementWalletState(ctx, t, pool, orgBat)
		assert.Equalf(t, batBalance, replayBalance, "iter %d: replay leaves balance", iter)
		assert.Equalf(t, batRemainder, replayRemainder, "iter %d: replay leaves remainder", iter)
	}
}

// A floor-crossing job becomes requires_attention WITHOUT touching the
// wallet, and later jobs of the batch still apply (§5.5).
func TestSettleOrgBatch_FloorBlockedJobDoesNotStopBatch(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	applyReservationSchemaFixture(ctx, t, pool)

	org := testUUID(0x1819, 1)
	seedBatchWallet(ctx, t, pool, org, 100, 0) // $1.00, floor −$1.00

	mkEntry := func(requestID string, amount money.MicroUSD) SettleEntry {
		return SettleEntry{
			JobID:     seedBatchJob(ctx, t, pool, org, requestID, SettleKindResale, amount, []byte(`{}`)),
			RequestID: requestID,
			Kind:      SettleKindResale,
			Amount:    amount,
			Payload:   []byte(`{}`),
		}
	}
	entries := []SettleEntry{
		mkEntry(org+"-big", 3_000_000), // $3.00 crosses the floor
		mkEntry(org+"-fit", 500_000),   // $0.50 applies
		mkEntry(org+"-tiny", 4_000),    // $0.004 applies (exact µ)
	}
	disp, err := SettleOrgBatch(ctx, pool, org, -100, entries, BatchSpenders{})
	require.NoError(t, err)

	assert.False(t, disp[entries[0].JobID].Settled, "floor-crossing job is parked")
	assert.Equal(t, ReasonInsufficientCredits, disp[entries[0].JobID].Reason)
	assert.True(t, disp[entries[1].JobID].Settled && disp[entries[1].JobID].Applied)
	assert.True(t, disp[entries[2].JobID].Settled && disp[entries[2].JobID].Applied)

	balance, remainder := settlementWalletState(ctx, t, pool, org)
	assert.Equal(t, int64(50), balance, "100¢ − 50¢ whole-cent part; the $0.004 charge is pure residue")
	assert.Equal(t, int64(4000), remainder, "sub-cent residue durable on the wallet")

	var status string
	require.NoError(t, pool.QueryRow(ctx, `SELECT status FROM settlement_jobs WHERE id = $1`, entries[0].JobID).Scan(&status))
	assert.Equal(t, "requires_attention", status, "blocked job parked inside the batch transaction")
	require.NoError(t, pool.QueryRow(ctx, `SELECT status FROM settlement_jobs WHERE id = $1`, entries[1].JobID).Scan(&status))
	assert.Equal(t, "settled", status)
}

// Pre-existing usage rows (an earlier committed charge) settle as an
// idempotent no-op; a usage identity under a DIFFERENT org is the
// request-identity conflict — parked, never charged.
func TestSettleOrgBatch_IdempotentNoOpAndIdentityConflict(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	applyReservationSchemaFixture(ctx, t, pool)

	orgA, orgB := testUUID(0x181a, 1), testUUID(0x181a, 2)
	seedBatchWallet(ctx, t, pool, orgA, 1000, 0)
	seedBatchWallet(ctx, t, pool, orgB, 1000, 0)

	// orgB already charged req-shared; orgA's job carries the same id.
	_, err := pool.Exec(ctx, `
		INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type, request_id, amount_micro_usd)
		VALUES ($1, -100, 900, 'usage', 'req-shared', -1000000)`, orgB)
	require.NoError(t, err)

	job := seedBatchJob(ctx, t, pool, orgA, "req-shared", SettleKindResale, 250_000, []byte(`{}`))
	disp, err := SettleOrgBatch(ctx, pool, orgA, -100, []SettleEntry{
		{JobID: job, RequestID: "req-shared", Kind: SettleKindResale, Amount: 250_000, Payload: []byte(`{}`)},
	}, BatchSpenders{})
	require.NoError(t, err)
	assert.False(t, disp[job].Settled, "foreign-org identity conflict is parked")
	assert.Equal(t, ReasonIdentityConflict, disp[job].Reason)
	balance, _ := settlementWalletState(ctx, t, pool, orgA)
	assert.Equal(t, int64(1000), balance, "conflicting job never charges org A")

	// Same-org pre-existing charge: idempotent no-op settle.
	_, err = pool.Exec(ctx, `
		INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type, request_id, amount_micro_usd)
		VALUES ($1, -50, 950, 'usage', 'req-own', -500000)`, orgA)
	require.NoError(t, err)
	job2 := seedBatchJob(ctx, t, pool, orgA, "req-own", SettleKindResale, 500_000, []byte(`{}`))
	disp, err = SettleOrgBatch(ctx, pool, orgA, -100, []SettleEntry{
		{JobID: job2, RequestID: "req-own", Kind: SettleKindResale, Amount: 500_000, Payload: []byte(`{}`)},
	}, BatchSpenders{})
	require.NoError(t, err)
	assert.True(t, disp[job2].Settled, "same-org replay settles")
	assert.False(t, disp[job2].Applied, "same-org replay never re-applies")
	balance, _ = settlementWalletState(ctx, t, pool, orgA)
	assert.Equal(t, int64(1000), balance, "no second charge — the fixture wallet is untouched by the no-op")

	var status string
	require.NoError(t, pool.QueryRow(ctx, `SELECT status FROM settlement_jobs WHERE id = $1`, job2).Scan(&status))
	assert.Equal(t, "settled", status)
}

// A stale worker's lower claim token is rejected even when confirmations
// race. Replaying the winner's already-settled expense is an idempotent
// no-op and never debits the wallet or ledger twice.
func TestSettleOrgBatch_ConcurrentFencingAndIdempotentReplay(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	applyReservationSchemaFixture(ctx, t, pool)

	org := testUUID(0x1820, 1)
	requestID := "fenced-settlement-" + org
	seedBatchWallet(ctx, t, pool, org, 2_000, 0)
	jobID := seedBatchJob(ctx, t, pool, org, requestID, SettleKindResale, 1_000_000, []byte(`{}`))
	_, err := pool.Exec(ctx, `UPDATE settlement_jobs SET attempts = 2 WHERE id = $1`, jobID)
	require.NoError(t, err)

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, token := range []int32{1, 2} {
		wg.Add(1)
		go func(token int32) {
			defer wg.Done()
			<-start
			_, settleErr := SettleOrgBatch(ctx, pool, org, -100, []SettleEntry{{
				JobID: jobID, FencingToken: token, RequestID: requestID,
				Kind: SettleKindResale, Amount: 1_000_000, Payload: []byte(`{}`),
			}}, BatchSpenders{})
			results <- settleErr
		}(token)
	}
	close(start)
	wg.Wait()
	close(results)

	var succeeded, fenced int
	for settleErr := range results {
		if settleErr == nil {
			succeeded++
			continue
		}
		if errors.Is(settleErr, ErrStaleSettlementToken) {
			fenced++
			continue
		}
		require.NoError(t, settleErr)
	}
	assert.Equal(t, 1, succeeded, "only the current claim confirms")
	assert.Equal(t, 1, fenced, "older claim is rejected")

	rows, microSum := walletLedger(ctx, t, pool, org)
	assert.Equal(t, int64(1), rows)
	assert.Equal(t, int64(-1_000_000), microSum)
	balance, _ := settlementWalletState(ctx, t, pool, org)
	assert.Equal(t, int64(1_900), balance, "the wallet is debited once")

	dispositions, err := SettleOrgBatch(ctx, pool, org, -100, []SettleEntry{{
		JobID: jobID, FencingToken: 2, RequestID: requestID,
		Kind: SettleKindResale, Amount: 1_000_000, Payload: []byte(`{}`),
	}}, BatchSpenders{})
	require.NoError(t, err)
	assert.True(t, dispositions[jobID].Settled)
	assert.False(t, dispositions[jobID].Applied, "replay is a no-op")
	rows, microSum = walletLedger(ctx, t, pool, org)
	assert.Equal(t, int64(1), rows)
	assert.Equal(t, int64(-1_000_000), microSum)
}

// Spend upserts batch the same way (§5.5): one batch transaction vs
// sequential per-job exact upserts produce identical accumulators.
func TestSettleOrgBatch_SpendUpsertsEquivalentToSequential(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	applyReservationSchemaFixture(ctx, t, pool)

	const (
		teamSeq  = "1818aaaa-0000-4000-8000-0000000000a1"
		teamBat  = "1818bbbb-0000-4000-8000-0000000000b2"
		agentSeq = "1818cccc-0000-4000-8000-0000000000c3"
		agentBat = "1818dddd-0000-4000-8000-0000000000d4"
		keySeq   = "1818eeee-0000-4000-8000-0000000000e5"
		keyBat   = "1818ffff-0000-4000-8000-0000000000f6"
	)
	org := testUUID(0x181b, 1)
	seedBatchWallet(ctx, t, pool, org, 0, 0)
	for _, team := range []string{teamSeq, teamBat} {
		_, err := pool.Exec(ctx, `
			INSERT INTO organizations_teams (id, org_id, name, slug) VALUES ($1, $2, $3, $3)
			ON CONFLICT (id) DO NOTHING`, team, org, "t-"+team[:6])
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `DELETE FROM team_spend_monthly WHERE team_id = $1`, team)
		require.NoError(t, err)
	}
	for _, agent := range []string{agentSeq, agentBat} {
		_, err := pool.Exec(ctx, `DELETE FROM agent_spend_daily WHERE agent_id = $1`, agent)
		require.NoError(t, err)
	}
	for _, key := range []string{keySeq, keyBat} {
		_, err := pool.Exec(ctx, `DELETE FROM session_spend WHERE session_key_id = $1`, key)
		require.NoError(t, err)
	}

	const period, day = "2026-10", "2026-10-02"
	amounts := []money.MicroUSD{4_000, 12_300, 0, 1_000_000, 999_999}

	// Sequential reference: per-job exact upserts in their own transactions.
	spender := NewAgentEnforcer(pool, slog.Default())
	for _, amount := range amounts {
		require.NoError(t, pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			return RecordTeamSpendExact(ctx, tx, teamSeq, period, amount)
		}))
		require.NoError(t, pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			return spender.RecordAgentSpendExact(ctx, tx, agentSeq, amount, 1, 2)
		}))
		require.NoError(t, pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			return RecordSessionSpendExact(ctx, tx, keySeq, amount)
		}))
	}

	// Batch: all jobs of each kind in one transaction.
	entries := make([]SettleEntry, 0, len(amounts)*3)
	for i, amount := range amounts {
		teamPayload, err := json.Marshal(map[string]any{"team_id": teamBat, "period": period})
		require.NoError(t, err)
		agentPayload, err := json.Marshal(map[string]any{"agent_id": agentBat, "tokens_in": 1, "tokens_out": 2})
		require.NoError(t, err)
		sessionPayload, err := json.Marshal(map[string]any{"session_key_id": keyBat})
		require.NoError(t, err)
		entries = append(entries,
			SettleEntry{JobID: seedBatchJob(ctx, t, pool, org, fmt.Sprintf("%s-t%d", org, i), SettleKindTeam, amount, teamPayload),
				RequestID: fmt.Sprintf("%s-t%d", org, i), Kind: SettleKindTeam, Amount: amount, Payload: teamPayload},
			SettleEntry{JobID: seedBatchJob(ctx, t, pool, org, fmt.Sprintf("%s-a%d", org, i), SettleKindAgent, amount, agentPayload),
				RequestID: fmt.Sprintf("%s-a%d", org, i), Kind: SettleKindAgent, Amount: amount, Payload: agentPayload},
			SettleEntry{JobID: seedBatchJob(ctx, t, pool, org, fmt.Sprintf("%s-s%d", org, i), SettleKindSession, amount, sessionPayload),
				RequestID: fmt.Sprintf("%s-s%d", org, i), Kind: SettleKindSession, Amount: amount, Payload: sessionPayload},
		)
	}
	disp, err := SettleOrgBatch(ctx, pool, org, -100, entries, BatchSpenders{Agent: spender})
	require.NoError(t, err)
	for _, e := range entries {
		assert.True(t, disp[e.JobID].Settled, "job %d settles", e.JobID)
	}

	var seqMicro, batMicro, seqCount, batCount int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT spend_micro_usd, request_count FROM team_spend_monthly WHERE team_id = $1 AND period = $2`, teamSeq, period).Scan(&seqMicro, &seqCount))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT spend_micro_usd, request_count FROM team_spend_monthly WHERE team_id = $1 AND period = $2`, teamBat, period).Scan(&batMicro, &batCount))
	assert.Equal(t, seqMicro, batMicro, "team exact µ")
	assert.Equal(t, seqCount, batCount, "team request count")

	var seqCost, batCost int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT cost_micro_usd FROM agent_spend_daily WHERE agent_id = $1`, agentSeq).Scan(&seqCost))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT cost_micro_usd FROM agent_spend_daily WHERE agent_id = $1`, agentBat).Scan(&batCost))
	assert.Equal(t, seqCost, batCost, "agent exact µ")

	var seqSpent, batSpent int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT spent_micro_usd FROM session_spend WHERE session_key_id = $1`, keySeq).Scan(&seqSpent))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT spent_micro_usd FROM session_spend WHERE session_key_id = $1`, keyBat).Scan(&batSpent))
	assert.Equal(t, seqSpent, batSpent, "session exact µ")
}

// §5.3 Settle step 2 + §5.5: reserved drops by Σ min(actual, bound) over
// APPLIED jobs with live allocations; a released allocation is ledger-only
// and its payload carries no settle key.
func TestSettleOrgBatch_ReserveDecrementSumAndReleasedSkip(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	applyReservationSchemaFixture(ctx, t, pool)

	const (
		teamID    = "1818aaaa-0000-4000-8000-000000000111"
		agentID   = "1818bbbb-0000-4000-8000-000000000222"
		sessionID = "1818cccc-0000-4000-8000-000000000333"
		replica   = "replica-1818"
		period    = "2026-10"
		day       = "2026-10-02"
	)
	org := testUUID(0x181c, 1)
	seedBatchWallet(ctx, t, pool, org, 1000, 0)
	// The allowance natural key excludes org_id — clear this test's key
	// space (replica + scope keys) for repeatable runs.
	_, err := pool.Exec(ctx, `DELETE FROM budget_allowances WHERE org_id = $1 OR replica_id = $2`, org, replica)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO organizations_teams (id, org_id, name, slug) VALUES ($1, $2, $3, $3)
		ON CONFLICT (id) DO NOTHING`, teamID, org, "res-team")
	require.NoError(t, err)

	seedAllowance := func(scope, key, per string, bound int64, status string) int64 {
		var id int64
		require.NoError(t, pool.QueryRow(ctx, `
			INSERT INTO budget_allowances (replica_id, scope_kind, scope_key, period, org_id, granted_micro_usd, status, lease_until)
			VALUES ($1, $2, $3, $4, $5, $6, $7, now() + interval '10 minutes')
			RETURNING id`, replica, scope, key, per, org, bound, status).Scan(&id))
		return id
	}

	walletAllowance := seedAllowance("wallet", org, "", 800_000, "active")
	teamAllowance := seedAllowance("team_month", teamID, period, 400_000, "active")
	agentAllowance := seedAllowance("agent_day", agentID, day, 200_000, "active")
	sessionAllowance := seedAllowance("session", sessionID, "", 100_000, "active")
	releasedAllowance := seedAllowance("wallet", org+"-old", "", 50_000, "released")

	// Scope rows hold the reserves (bounds incl. the released allowance's).
	_, err = pool.Exec(ctx, `
		UPDATE org_credits SET reserved_micro_usd = $2 WHERE org_id = $1`, org, 800_000+50_000)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO team_spend_monthly (team_id, period, reserved_micro_usd) VALUES ($1, $2, $3)
		ON CONFLICT (team_id, period) DO UPDATE SET reserved_micro_usd = $3`, teamID, period, 400_000)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO agent_spend_daily (agent_id, day, reserved_micro_usd) VALUES ($1, $2, $3)
		ON CONFLICT (agent_id, day) DO UPDATE SET reserved_micro_usd = $3`, agentID, day, 200_000)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO session_spend (session_key_id, reserved_micro_usd) VALUES ($1, $2)
		ON CONFLICT (session_key_id) DO UPDATE SET reserved_micro_usd = $2`, sessionID, 100_000)
	require.NoError(t, err)

	// Jobs: wallet overshoots its bound (clamps), team matches, agent
	// undershoots (actual wins), session undershoots; the released one
	// settles ledger-only.
	teamPayload, err := json.Marshal(map[string]any{"team_id": teamID, "period": period})
	require.NoError(t, err)
	agentPayload, err := json.Marshal(map[string]any{"agent_id": agentID})
	require.NoError(t, err)
	sessionPayload, err := json.Marshal(map[string]any{"session_key_id": sessionID})
	require.NoError(t, err)

	entries := []SettleEntry{
		{JobID: seedBatchJob(ctx, t, pool, org, org+"-w", SettleKindResale, 900_000, []byte(`{}`)),
			RequestID: org + "-w", Kind: SettleKindResale, Amount: 900_000, AllowanceID: walletAllowance, Bound: 800_000, Payload: []byte(`{}`)},
		{JobID: seedBatchJob(ctx, t, pool, org, org+"-t", SettleKindTeam, 400_000, teamPayload),
			RequestID: org + "-t", Kind: SettleKindTeam, Amount: 400_000, AllowanceID: teamAllowance, Bound: 400_000, Payload: teamPayload},
		{JobID: seedBatchJob(ctx, t, pool, org, org+"-a", SettleKindAgent, 150_000, agentPayload),
			RequestID: org + "-a", Kind: SettleKindAgent, Amount: 150_000, AllowanceID: agentAllowance, Bound: 200_000, Payload: agentPayload},
		{JobID: seedBatchJob(ctx, t, pool, org, org+"-s", SettleKindSession, 60_000, sessionPayload),
			RequestID: org + "-s", Kind: SettleKindSession, Amount: 60_000, AllowanceID: sessionAllowance, Bound: 100_000, Payload: sessionPayload},
		{JobID: seedBatchJob(ctx, t, pool, org, org+"-r", SettleKindResale, 50_000, []byte(`{}`)),
			RequestID: org + "-r", Kind: SettleKindResale, Amount: 50_000, AllowanceID: releasedAllowance, Bound: 50_000, Payload: []byte(`{}`)},
	}
	// Wallet: $0.90 + $0.05 charges against $10.00, floor −$1.00 — all apply.
	disp, err := SettleOrgBatch(ctx, pool, org, -100, entries, BatchSpenders{Agent: NewAgentEnforcer(pool, slog.Default())})
	require.NoError(t, err)
	for _, e := range entries {
		assert.True(t, disp[e.JobID].Settled, "job %d settles", e.JobID)
	}

	// reserved decremented by Σ min(actual, bound) of live allocations.
	var reserved int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT reserved_micro_usd FROM org_credits WHERE org_id = $1`, org).Scan(&reserved))
	assert.Equal(t, int64(50_000), reserved, "wallet: 850k − min(900k, 800k); released allowance untouched")

	require.NoError(t, pool.QueryRow(ctx,
		`SELECT reserved_micro_usd FROM team_spend_monthly WHERE team_id = $1 AND period = $2`, teamID, period).Scan(&reserved))
	assert.Equal(t, int64(0), reserved, "team reserve fully settled")

	require.NoError(t, pool.QueryRow(ctx,
		`SELECT reserved_micro_usd FROM agent_spend_daily WHERE agent_id = $1`, agentID).Scan(&reserved))
	assert.Equal(t, int64(50_000), reserved, "agent: 200k − min(150k, 200k)")

	require.NoError(t, pool.QueryRow(ctx,
		`SELECT reserved_micro_usd FROM session_spend WHERE session_key_id = $1`, sessionID).Scan(&reserved))
	assert.Equal(t, int64(40_000), reserved, "session: 100k − min(60k, 100k)")

	// Dispositions carry the settle amounts; the released one decrements
	// nothing and writes no reconcile key.
	assert.Equal(t, int64(800_000), disp[entries[0].JobID].DecrementMicroUSD)
	assert.Equal(t, int64(400_000), disp[entries[1].JobID].DecrementMicroUSD)
	assert.Equal(t, int64(150_000), disp[entries[2].JobID].DecrementMicroUSD)
	assert.Equal(t, int64(60_000), disp[entries[3].JobID].DecrementMicroUSD)
	assert.Equal(t, int64(0), disp[entries[4].JobID].DecrementMicroUSD, "released allocation decrements nothing")

	var payload map[string]any
	require.NoError(t, pool.QueryRow(ctx, `SELECT payload FROM settlement_jobs WHERE id = $1`, entries[0].JobID).Scan(&payload))
	assert.Equal(t, float64(800_000), payload[ReconcileSettleKey], "settle key recorded for the reconcile")
	// The released one writes no settle key.
	require.NoError(t, pool.QueryRow(ctx, `SELECT payload FROM settlement_jobs WHERE id = $1`, entries[4].JobID).Scan(&payload))
	_, has := payload[ReconcileSettleKey]
	assert.False(t, has, "released allocation writes no settle key")
}

// W-MONEY: an unknown charge kind parks the job requires_attention with the
// poison reason INSIDE the batch transaction — the same disposition the
// per-job executor's unknown-kind ErrPoisonJob classification produces —
// instead of the entry surviving every settle attempt (the infinite
// requeue the missing default case used to cause).
func TestSettleOrgBatch_UnknownChargeKindIsPoison(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	applyReservationSchemaFixture(ctx, t, pool)

	org := testUUID(0x181d, 1)
	seedBatchWallet(ctx, t, pool, org, 1000, 0)

	// A healthy resale entry rides along: the unknown-kind pass must not
	// re-disposition entries the wallet phase already settled.
	resale := seedBatchJob(ctx, t, pool, org, org+"-ok", SettleKindResale, 100_000, []byte(`{}`))
	job := seedBatchJob(ctx, t, pool, org, org+"-pigeon", "carrier_pigeon", 100_000, []byte(`{}`))
	disp, err := SettleOrgBatch(ctx, pool, org, -100, []SettleEntry{
		{JobID: resale, RequestID: org + "-ok", Kind: SettleKindResale, Amount: 100_000, Payload: []byte(`{}`)},
		{JobID: job, RequestID: org + "-pigeon", Kind: "carrier_pigeon", Amount: 100_000, Payload: []byte(`{}`)},
	}, BatchSpenders{})
	require.NoError(t, err)
	assert.True(t, disp[resale].Settled && disp[resale].Applied, "the resale entry settles through the wallet phase")
	assert.False(t, disp[job].Settled, "an unknown kind never settles")
	assert.Equal(t, ReasonPoisonPayload, disp[job].Reason)

	var status, lastError string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT status, last_error FROM settlement_jobs WHERE id = $1`, job).Scan(&status, &lastError))
	assert.Equal(t, "requires_attention", status, "poison kind parks durably instead of requeueing")
	assert.Equal(t, ReasonPoisonPayload, lastError)

	balance, _ := settlementWalletState(ctx, t, pool, org)
	assert.Equal(t, int64(990), balance, "wallet pays exactly the resale cents; the poison kind touches nothing")
}

// W-MONEY (ADR I5): the batch passes the entry's REQUEST time through the
// BatchAgentSpenderAt upgrade, so the agent-day bucket is the request's day
// even when settlement runs after UTC midnight; a zero RequestedAt keeps
// the settle-time default.
func TestSettleOrgBatch_AgentDayBucketsByRequestTime(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	applyReservationSchemaFixture(ctx, t, pool)

	org := testUUID(0x181e, 1)
	seedBatchWallet(ctx, t, pool, org, 1000, 0)
	const agentID = "1818dddd-0000-4000-8000-000000000444"
	_, err := pool.Exec(ctx, `DELETE FROM agent_spend_daily WHERE agent_id = $1`, agentID)
	require.NoError(t, err)

	spender := NewAgentEnforcer(pool, slog.Default())
	spender.now = func() time.Time { return time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC) } // settle day 2026-09-06

	agentPayload, err := json.Marshal(map[string]any{"agent_id": agentID, "tokens_in": 1, "tokens_out": 2})
	require.NoError(t, err)
	requestAt := time.Date(2026, 9, 5, 23, 59, 0, 0, time.UTC) // served before UTC midnight

	jobAt := seedBatchJob(ctx, t, pool, org, org+"-a1", SettleKindAgent, 100_000, agentPayload)
	jobLegacy := seedBatchJob(ctx, t, pool, org, org+"-a0", SettleKindAgent, 50_000, agentPayload)
	disp, err := SettleOrgBatch(ctx, pool, org, -100, []SettleEntry{
		{JobID: jobAt, RequestID: org + "-a1", Kind: SettleKindAgent, Amount: 100_000, Payload: agentPayload, RequestedAt: requestAt},
		{JobID: jobLegacy, RequestID: org + "-a0", Kind: SettleKindAgent, Amount: 50_000, Payload: agentPayload},
	}, BatchSpenders{Agent: spender})
	require.NoError(t, err)
	assert.True(t, disp[jobAt].Settled && disp[jobAt].Applied)
	assert.True(t, disp[jobLegacy].Settled && disp[jobLegacy].Applied)

	var microAt, microLegacy int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT cost_micro_usd FROM agent_spend_daily WHERE agent_id = $1 AND day = '2026-09-05'`, agentID).Scan(&microAt))
	assert.Equal(t, int64(100_000), microAt, "the request-time entry lands in the request's day")

	require.NoError(t, pool.QueryRow(ctx,
		`SELECT cost_micro_usd FROM agent_spend_daily WHERE agent_id = $1 AND day = '2026-09-06'`, agentID).Scan(&microLegacy))
	assert.Equal(t, int64(50_000), microLegacy, "a zero RequestedAt keeps the settle-time default")
}

// N06-P04 D1 (priced partial cancel): a priced cancel — native provider
// usage or adapted estimated usage alike — settles the consumed prefix
// exactly once. The batch applies it, decrements the reserve by
// min(actual, bound), records the settle key, and a repeated delivery of
// the same event (the same job re-claimed and re-settled) is an idempotent
// no-op: no second debit, no second decrement, payload key untouched. A
// second job row for the same (org, request, charge_kind) cannot exist at
// all — settlement_jobs_charge_key is UNIQUE on it — so the replay IS the
// repeated-event form at batch level.
func TestSettleOrgBatch_CancelPartialSettlesOnceAndReplayNeverRecharges(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	applyReservationSchemaFixture(ctx, t, pool)

	const (
		replica = "replica-n06p04"
		bound   = 800_000 // reserve bound; consumed prefix $0.30
	)
	org := testUUID(0x181f, 1)
	seedBatchWallet(ctx, t, pool, org, 1000, 0)
	_, err := pool.Exec(ctx, `DELETE FROM budget_allowances WHERE org_id = $1 OR replica_id = $2`, org, replica)
	require.NoError(t, err)
	var allowance int64
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO budget_allowances (replica_id, scope_kind, scope_key, org_id, granted_micro_usd, status, lease_until)
		VALUES ($1, 'wallet', $2, $2, $3, 'active', now() + interval '10 minutes')
		RETURNING id`, replica, org, bound).Scan(&allowance))
	_, err = pool.Exec(ctx, `UPDATE org_credits SET reserved_micro_usd = $2 WHERE org_id = $1`, org, bound)
	require.NoError(t, err)

	requestID := org + "-cancel-partial"
	jobID := seedBatchJob(ctx, t, pool, org, requestID, SettleKindResale, 300_000, []byte(`{}`))
	entry := SettleEntry{
		JobID: jobID, RequestID: requestID, Kind: SettleKindResale,
		Amount: 300_000, AllowanceID: allowance, Bound: bound, Payload: []byte(`{}`),
	}

	disp, err := SettleOrgBatch(ctx, pool, org, -100, []SettleEntry{entry}, BatchSpenders{})
	require.NoError(t, err)
	d := disp[jobID]
	require.True(t, d.Settled && d.Applied, "priced partial applies once: %+v", d)
	assert.Equal(t, int64(300_000), d.DecrementMicroUSD, "settle amount is min(actual, bound)")

	balance, remainder := settlementWalletState(ctx, t, pool, org)
	assert.Equal(t, int64(970), balance, "wallet debited the consumed prefix once")
	var reserved int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT reserved_micro_usd FROM org_credits WHERE org_id = $1`, org).Scan(&reserved))
	assert.Equal(t, int64(bound-300_000), reserved, "reserve drops by the settle amount")
	var payload map[string]any
	require.NoError(t, pool.QueryRow(ctx, `SELECT payload FROM settlement_jobs WHERE id = $1`, jobID).Scan(&payload))
	assert.Equal(t, float64(300_000), payload[ReconcileSettleKey], "reconcile key recorded")

	// The repeated event: the same job re-delivered into a later batch.
	replay, err := SettleOrgBatch(ctx, pool, org, -100, []SettleEntry{entry}, BatchSpenders{})
	require.NoError(t, err)
	assert.True(t, replay[jobID].Settled, "replay settles idempotently")
	assert.False(t, replay[jobID].Applied, "replay never re-applies")
	assert.Equal(t, int64(0), replay[jobID].DecrementMicroUSD, "replay decrements nothing")

	balance, remainder = settlementWalletState(ctx, t, pool, org)
	assert.Equal(t, int64(970), balance, "no second charge")
	assert.Equal(t, int64(0), remainder)
	rows, microSum := walletLedger(ctx, t, pool, org)
	assert.Equal(t, int64(1), rows, "exactly one ledger row")
	assert.Equal(t, int64(-300_000), microSum)
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT reserved_micro_usd FROM org_credits WHERE org_id = $1`, org).Scan(&reserved))
	assert.Equal(t, int64(bound-300_000), reserved, "no second decrement")
	require.NoError(t, pool.QueryRow(ctx, `SELECT payload FROM settlement_jobs WHERE id = $1`, jobID).Scan(&payload))
	assert.Equal(t, float64(300_000), payload[ReconcileSettleKey], "reconcile key unchanged by the replay")
}

// N06-P04 D2 (unknown outcome surfacing): the producer never creates a
// claimable wallet intent for an unknown price — it writes the non-claimable
// pending_price row instead (services/loggerd/consumer/stream.go). So a
// zero or refund-shaped wallet entry that reaches the batch is a
// producer-contract violation, and the batch must SURFACE it (poison
// requires_attention) rather than mask it as a confirmed zero charge: no
// ledger row is written, so the request identity stays free for the real
// late priced event, which then completes exactly one operation.
func TestSettleOrgBatch_UnknownOutcomeNeverMaskedAsZero(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	applyReservationSchemaFixture(ctx, t, pool)

	org := testUUID(0x1821, 1)
	seedBatchWallet(ctx, t, pool, org, 1000, 0)

	zeroReq, refundReq := org+"-unknown", org+"-refund-shape"
	zeroJob := seedBatchJob(ctx, t, pool, org, zeroReq, SettleKindResale, 0, []byte(`{}`))
	refundJob := seedBatchJob(ctx, t, pool, org, refundReq, SettleKindResale, -50_000, []byte(`{}`))
	disp, err := SettleOrgBatch(ctx, pool, org, -100, []SettleEntry{
		{JobID: zeroJob, RequestID: zeroReq, Kind: SettleKindResale, Amount: 0, Payload: []byte(`{}`)},
		{JobID: refundJob, RequestID: refundReq, Kind: SettleKindResale, Amount: -50_000, Payload: []byte(`{}`)},
	}, BatchSpenders{})
	require.NoError(t, err)
	for _, job := range []int64{zeroJob, refundJob} {
		assert.Falsef(t, disp[job].Settled, "job %d must not settle", job)
		assert.Equalf(t, ReasonPoisonPayload, disp[job].Reason, "job %d surfaced as poison", job)
		var status, lastError string
		require.NoErrorf(t, pool.QueryRow(ctx,
			`SELECT status, last_error FROM settlement_jobs WHERE id = $1`, job).Scan(&status, &lastError), "job %d", job)
		assert.Equalf(t, "requires_attention", status, "job %d parked durably", job)
		assert.Equalf(t, ReasonPoisonPayload, lastError, "job %d last_error", job)
	}

	balance, _ := settlementWalletState(ctx, t, pool, org)
	assert.Equal(t, int64(1000), balance, "unknown outcomes never charge — not even a masked zero")
	rows, microSum := walletLedger(ctx, t, pool, org)
	assert.Equal(t, int64(0), rows, "no zero ledger row poisons the identity")

	// The late priced event (the producer promotes the SAME pending_price
	// row in place — settlement_jobs_charge_key makes a second row for the
	// identity impossible) now completes the ONE operation: it applies
	// normally because no zero row exists.
	disp, err = SettleOrgBatch(ctx, pool, org, -100, []SettleEntry{
		{JobID: zeroJob, RequestID: zeroReq, Kind: SettleKindResale, Amount: 120_000, Payload: []byte(`{}`)},
	}, BatchSpenders{})
	require.NoError(t, err)
	assert.True(t, disp[zeroJob].Settled && disp[zeroJob].Applied, "late priced usage applies after the surfaced unknown")
	balance, _ = settlementWalletState(ctx, t, pool, org)
	assert.Equal(t, int64(988), balance, "exactly the late event's charge")
	rows, microSum = walletLedger(ctx, t, pool, org)
	assert.Equal(t, int64(1), rows)
	assert.Equal(t, int64(-120_000), microSum)

	// Contrast — the harm a masked zero would cause: an org whose identity
	// already carries a confirmed zero usage row swallows the real late
	// charge as an idempotent no-op. Money silently lost; this is why the
	// batch must surface (poison), never mask.
	orgHarm := testUUID(0x1821, 2)
	seedBatchWallet(ctx, t, pool, orgHarm, 1000, 0)
	harmReq := orgHarm + "-late-real"
	_, err = pool.Exec(ctx, `
		INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type, request_id, amount_micro_usd)
		VALUES ($1, 0, 1000, 'usage', $2, 0)`, orgHarm, harmReq)
	require.NoError(t, err)
	harmJob := seedBatchJob(ctx, t, pool, orgHarm, harmReq, SettleKindResale, 200_000, []byte(`{}`))
	disp, err = SettleOrgBatch(ctx, pool, orgHarm, -100, []SettleEntry{
		{JobID: harmJob, RequestID: harmReq, Kind: SettleKindResale, Amount: 200_000, Payload: []byte(`{}`)},
	}, BatchSpenders{})
	require.NoError(t, err)
	assert.True(t, disp[harmJob].Settled, "with a zero row present, the real event settles as a no-op")
	assert.False(t, disp[harmJob].Applied, "…and never applies — the charge is lost")
	balance, _ = settlementWalletState(ctx, t, pool, orgHarm)
	assert.Equal(t, int64(1000), balance, "the real charge never lands behind the zero row")
}

// N06-P04 native/adapted asymmetry-blindness: the same consumed prefix
// arrives from a native endpoint (provider-reported usage shape) and an
// adapted endpoint (estimated usage shape, different payload fields). The
// batch moves money from the entry's Amount only — payload shape degrades
// metadata, never the charge — so both settle to identical money outcomes.
func TestSettleOrgBatch_NativeAndAdaptedPartialSettleIdentically(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	applyReservationSchemaFixture(ctx, t, pool)

	const (
		replica = "replica-n06p04-asym"
		bound   = 300_000
		amount  = money.MicroUSD(300_000)
	)
	orgNative := testUUID(0x1822, 1)
	orgAdapted := testUUID(0x1822, 2)
	seedBatchWallet(ctx, t, pool, orgNative, 1000, 0)
	seedBatchWallet(ctx, t, pool, orgAdapted, 1000, 0)
	_, err := pool.Exec(ctx, `DELETE FROM budget_allowances WHERE org_id = ANY($1) OR replica_id = $2`,
		[]string{orgNative, orgAdapted}, replica)
	require.NoError(t, err)
	seedWalletAllowance := func(org string) int64 {
		var id int64
		require.NoError(t, pool.QueryRow(ctx, `
			INSERT INTO budget_allowances (replica_id, scope_kind, scope_key, org_id, granted_micro_usd, status, lease_until)
			VALUES ($1, 'wallet', $2, $2, $3, 'active', now() + interval '10 minutes')
			RETURNING id`, replica, org, bound).Scan(&id))
		_, err := pool.Exec(ctx, `UPDATE org_credits SET reserved_micro_usd = $2 WHERE org_id = $1`, org, bound)
		require.NoError(t, err)
		return id
	}
	nativeAllowance := seedWalletAllowance(orgNative)
	adaptedAllowance := seedWalletAllowance(orgAdapted)

	nativePayload, err := json.Marshal(map[string]any{
		"model": "provider-model", "tokens_in": 1200, "tokens_out": 340,
		"cost_usd": 0.3, "resale_usd": 0.3, "usage_source": "provider",
	})
	require.NoError(t, err)
	adaptedPayload, err := json.Marshal(map[string]any{
		"model": "adapted-model", "usage_source": "estimated",
		"estimate": true, "tokens_in": 1200, "tokens_out": 340,
	})
	require.NoError(t, err)

	nativeReq, adaptedReq := orgNative+"-native-cancel", orgAdapted+"-adapted-cancel"
	nativeJob := seedBatchJob(ctx, t, pool, orgNative, nativeReq, SettleKindResale, amount, nativePayload)
	adaptedJob := seedBatchJob(ctx, t, pool, orgAdapted, adaptedReq, SettleKindResale, amount, adaptedPayload)
	disp, err := SettleOrgBatch(ctx, pool, orgNative, -100, []SettleEntry{{
		JobID: nativeJob, RequestID: nativeReq, Kind: SettleKindResale,
		Amount: amount, AllowanceID: nativeAllowance, Bound: bound, Payload: nativePayload,
	}}, BatchSpenders{})
	require.NoError(t, err)
	dispAdapted, err := SettleOrgBatch(ctx, pool, orgAdapted, -100, []SettleEntry{{
		JobID: adaptedJob, RequestID: adaptedReq, Kind: SettleKindResale,
		Amount: amount, AllowanceID: adaptedAllowance, Bound: bound, Payload: adaptedPayload,
	}}, BatchSpenders{})
	require.NoError(t, err)

	nativeD, adaptedD := disp[nativeJob], dispAdapted[adaptedJob]
	assert.Equal(t, nativeD.Settled, adaptedD.Settled, "dispositions agree")
	assert.Equal(t, nativeD.Applied, adaptedD.Applied, "dispositions agree")
	assert.Equal(t, nativeD.DecrementMicroUSD, adaptedD.DecrementMicroUSD, "same settle amount")
	require.True(t, nativeD.Settled && nativeD.Applied)
	require.True(t, adaptedD.Settled && adaptedD.Applied)

	for _, tc := range []struct {
		org   string
		jobID int64
	}{
		{orgNative, nativeJob},
		{orgAdapted, adaptedJob},
	} {
		balance, remainder := settlementWalletState(ctx, t, pool, tc.org)
		assert.Equalf(t, int64(970), balance, "%s: same wallet charge", tc.org)
		assert.Equalf(t, int64(0), remainder, "%s: exact micro charge", tc.org)
		rows, microSum := walletLedger(ctx, t, pool, tc.org)
		assert.Equalf(t, int64(1), rows, "%s: one ledger row", tc.org)
		assert.Equalf(t, int64(-300_000), microSum, "%s: same ledger micro", tc.org)
		var reserved int64
		require.NoErrorf(t, pool.QueryRow(ctx,
			`SELECT reserved_micro_usd FROM org_credits WHERE org_id = $1`, tc.org).Scan(&reserved), tc.org)
		assert.Equalf(t, int64(0), reserved, "%s: reserve settled", tc.org)
		var payload map[string]any
		require.NoErrorf(t, pool.QueryRow(ctx, `SELECT payload FROM settlement_jobs WHERE id = $1`, tc.jobID).Scan(&payload), "job %d", tc.jobID)
		assert.Equalf(t, float64(300_000), payload[ReconcileSettleKey], "%s: same reconcile key", tc.org)
	}
}
