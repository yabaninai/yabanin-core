//go:build integration

// Invocation-domain acceptance for the NEXT-18d batch executor on the FULLY
// MIGRATED ledger (0028 mint + 0029 contract): duplicate client request ids
// settle as independent per-invocation charges, the legacy global
// request-id domain survives unchanged for NULL-invocation rows, and the
// fencing token keeps a stale worker from touching recovered or re-claimed
// jobs. Every assertion reads back through the real schema — no re-model
// of the executor's arithmetic (that equivalence is the sibling file's
// property tests).
package budget

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedBatchInvocationJob inserts a pending settlement_jobs row carrying
// the billed invocation identity the 0028+ claim projection reads back.
// invocationID "" maps to SQL NULL — the legacy (NULL-invocation) domain —
// exactly how the executor's legacy insert path writes those rows; an
// empty-string uuid would be rejected by the column type (22P02).
func seedBatchInvocationJob(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, org, requestID, invocationID, kind string, amount money.MicroUSD, payload []byte) int64 {
	tb.Helper()
	var id int64
	err := pool.QueryRow(ctx, `
		INSERT INTO settlement_jobs (org_id, request_id, invocation_id, charge_kind, amount_cents, amount_micro_usd, status, payload)
		VALUES ($1, $2, NULLIF($3, '')::uuid, $4, $5, $6, 'pending', $7)
		RETURNING id`, org, requestID, invocationID, kind, amount.Cents(), int64(amount), payload).Scan(&id)
	require.NoError(tb, err, "seed invocation settlement job")
	return id
}

// invocationLedgerRow is one usage ledger row's identity fields.
type invocationLedgerRow struct {
	OrgID        string
	RequestID    string
	InvocationID *string
	MicroUSD     int64
}

func readInvocationLedger(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, org string) []invocationLedgerRow {
	tb.Helper()
	rows, err := pool.Query(ctx, `
		SELECT org_id, request_id, invocation_id, amount_micro_usd FROM credit_transactions
		WHERE org_id = $1 AND type = 'usage' ORDER BY id`, org)
	require.NoError(tb, err)
	defer rows.Close()
	var out []invocationLedgerRow
	for rows.Next() {
		var r invocationLedgerRow
		require.NoError(tb, rows.Scan(&r.OrgID, &r.RequestID, &r.InvocationID, &r.MicroUSD))
		out = append(out, r)
	}
	require.NoError(tb, rows.Err())
	return out
}

// TestSettleOrgBatchInvocationDomains pins the 0028/0029 identity split on
// the fully migrated ledger: two invocations sharing ONE client request id
// are two independent charges in the same org; the replay of either is a
// no-op; a CHANGED amount under the same invocation uuid is an identity
// conflict that moves no money; a legacy (NULL-invocation) row with the
// same request id text still settles (its domain excludes invocation
// rows); and a foreign org's invocation may reuse the same request id text
// without any interaction (duplicate ids stay tenant-independent).
func TestSettleOrgBatchInvocationDomains(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := testdb.Postgres(t)
	applyReservationSchemaFixture(ctx, t, pool)

	const orgA = "11111111-1111-4111-8111-1111111111a1"
	const orgB = "22222222-2222-4222-8222-2222222222b2"
	seedBatchWallet(ctx, t, pool, orgA, 10_000, 0)
	seedBatchWallet(ctx, t, pool, orgB, 5_000, 0)

	const sharedReq = "wfnc-shared-request-id"
	const inv1 = "33333333-3333-4333-8333-333333333331"
	const inv2 = "33333333-3333-4333-8333-333333333332"
	const inv3 = "44444444-4444-4444-8444-444444444443"
	amount := money.MicroUSD(1_500_005) // 150c + 5µ each: exercises the carry

	id1 := seedBatchInvocationJob(ctx, t, pool, orgA, sharedReq, inv1, SettleKindResale, amount, []byte(`{"model":"m"}`))
	id2 := seedBatchInvocationJob(ctx, t, pool, orgA, sharedReq, inv2, SettleKindResale, amount, []byte(`{"model":"m"}`))

	entries := []SettleEntry{
		{JobID: id1, RequestID: sharedReq, InvocationID: inv1, Kind: SettleKindResale, Amount: amount, Payload: []byte(`{"model":"m"}`)},
		{JobID: id2, RequestID: sharedReq, InvocationID: inv2, Kind: SettleKindResale, Amount: amount, Payload: []byte(`{"model":"m"}`)},
	}

	disp, err := SettleOrgBatch(ctx, pool, orgA, 0, entries, BatchSpenders{})
	require.NoError(t, err)
	for _, id := range []int64{id1, id2} {
		require.True(t, disp[id].Settled, "invocation entry must settle")
		require.True(t, disp[id].Applied, "first application must move money")
	}

	// Both charges applied independently under one request id: 300c off
	// the wallet, both 5µ rests carried, one ledger row per invocation.
	bal, rem := settlementWalletState(ctx, t, pool, orgA)
	assert.EqualValues(t, 9_700, bal, "two independent 150c invocation charges")
	assert.EqualValues(t, 10, rem, "both sub-cent rests carried")
	ledger := readInvocationLedger(ctx, t, pool, orgA)
	require.Len(t, ledger, 2)
	for i, want := range []string{inv1, inv2} {
		require.NotNil(t, ledger[i].InvocationID)
		assert.Equal(t, want, *ledger[i].InvocationID, "ledger row keyed by invocation")
		assert.Equal(t, sharedReq, ledger[i].RequestID)
		assert.EqualValues(t, -1_500_005, ledger[i].MicroUSD)
	}

	// Replay: idempotent no-ops, no new rows, no balance movement.
	disp, err = SettleOrgBatch(ctx, pool, orgA, 0, entries, BatchSpenders{})
	require.NoError(t, err)
	for _, id := range []int64{id1, id2} {
		assert.True(t, disp[id].Settled, "replay of a settled invocation is settled")
		assert.False(t, disp[id].Applied, "replay must not move money")
	}
	bal, rem = settlementWalletState(ctx, t, pool, orgA)
	assert.EqualValues(t, 9_700, bal)
	assert.EqualValues(t, 10, rem)
	assert.Len(t, readInvocationLedger(ctx, t, pool, orgA), 2)

	// Same invocation uuid, CHANGED amount: identity conflict, not a
	// silent re-settle and not a charge. Nothing moves.
	changed := entries
	changed[0].Amount = money.MicroUSD(2_500_000)
	disp, err = SettleOrgBatch(ctx, pool, orgA, 0, changed, BatchSpenders{})
	require.NoError(t, err)
	assert.False(t, disp[id1].Settled, "changed amount under a settled uuid must not settle")
	assert.Equal(t, ReasonIdentityConflict, disp[id1].Reason)
	bal, _ = settlementWalletState(ctx, t, pool, orgA)
	assert.EqualValues(t, 9_700, bal, "identity conflict moves no money")
	assert.Len(t, readInvocationLedger(ctx, t, pool, orgA), 2, "identity conflict writes no ledger row")

	// Legacy row with the SAME request id text: a different (NULL-invocation)
	// domain — settles, third ledger row, no cross-domain interference.
	idLegacy := seedBatchInvocationJob(ctx, t, pool, orgA, sharedReq, "", SettleKindResale, amount, []byte(`{"model":"m"}`))
	disp, err = SettleOrgBatch(ctx, pool, orgA, 0, []SettleEntry{
		{JobID: idLegacy, RequestID: sharedReq, Kind: SettleKindResale, Amount: amount, Payload: []byte(`{"model":"m"}`)},
	}, BatchSpenders{})
	require.NoError(t, err)
	require.True(t, disp[idLegacy].Settled)
	require.True(t, disp[idLegacy].Applied)
	ledger = readInvocationLedger(ctx, t, pool, orgA)
	require.Len(t, ledger, 3)
	assert.Nil(t, ledger[2].InvocationID, "legacy row stores NULL invocation_id (its own domain)")
	bal, rem = settlementWalletState(ctx, t, pool, orgA)
	assert.EqualValues(t, 9_550, bal, "legacy charge applied alongside the invocation charges")
	assert.EqualValues(t, 15, rem)

	// Foreign org, invocation domain, same request id text: independent.
	idB := seedBatchInvocationJob(ctx, t, pool, orgB, sharedReq, inv3, SettleKindResale, amount, []byte(`{"model":"m"}`))
	disp, err = SettleOrgBatch(ctx, pool, orgB, 0, []SettleEntry{
		{JobID: idB, RequestID: sharedReq, InvocationID: inv3, Kind: SettleKindResale, Amount: amount, Payload: []byte(`{"model":"m"}`)},
	}, BatchSpenders{})
	require.NoError(t, err)
	require.True(t, disp[idB].Settled)
	require.True(t, disp[idB].Applied)
	bal, _ = settlementWalletState(ctx, t, pool, orgB)
	assert.EqualValues(t, 4_850, bal, "cross-tenant invocation with shared request text is independent")
	assert.Len(t, readInvocationLedger(ctx, t, pool, orgB), 1)
}

// TestSettleOrgBatchLegacyCrossTenantConflict keeps the pre-0029 contract
// for legacy rows: the usage identity is global on request_id, so a second
// org settling the same legacy request id is parked with the identity
// conflict and moves no money.
func TestSettleOrgBatchLegacyCrossTenantConflict(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := testdb.Postgres(t)
	applyReservationSchemaFixture(ctx, t, pool)

	const orgA = "11111111-1111-4111-8111-1111111111a1"
	const orgB = "22222222-2222-4222-8222-2222222222b2"
	seedBatchWallet(ctx, t, pool, orgA, 10_000, 0)
	seedBatchWallet(ctx, t, pool, orgB, 5_000, 0)

	const req = "wfnc-legacy-conflict"
	amount := money.MicroUSD(1_000_000)
	idA := seedBatchInvocationJob(ctx, t, pool, orgA, req, "", SettleKindResale, amount, []byte(`{}`))
	disp, err := SettleOrgBatch(ctx, pool, orgA, 0, []SettleEntry{
		{JobID: idA, RequestID: req, Kind: SettleKindResale, Amount: amount, Payload: []byte(`{}`)},
	}, BatchSpenders{})
	require.NoError(t, err)
	require.True(t, disp[idA].Settled)

	idB := seedBatchInvocationJob(ctx, t, pool, orgB, req, "", SettleKindResale, amount, []byte(`{}`))
	disp, err = SettleOrgBatch(ctx, pool, orgB, 0, []SettleEntry{
		{JobID: idB, RequestID: req, Kind: SettleKindResale, Amount: amount, Payload: []byte(`{}`)},
	}, BatchSpenders{})
	require.NoError(t, err)
	assert.False(t, disp[idB].Settled, "cross-tenant legacy duplicate must not settle")
	assert.Equal(t, ReasonIdentityConflict, disp[idB].Reason)
	rows, micro := walletLedger(ctx, t, pool, orgB)
	assert.EqualValues(t, 0, rows, "conflicting org writes no ledger row")
	assert.EqualValues(t, 0, micro)
	bal, _ := settlementWalletState(ctx, t, pool, orgB)
	assert.EqualValues(t, 5_000, bal, "conflicting org's wallet untouched")
}

// TestSettleOrgBatchFencingLostOwnership pins the two stale-claim windows:
// a NEWER re-claim bumps attempts (token mismatch), and a lease RECOVERED
// but not yet re-claimed flips status to 'retry' with the SAME attempts —
// both must fence the batch, commit nothing, and leave the job row exactly
// as the rightful state left it.
func TestSettleOrgBatchFencingLostOwnership(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := testdb.Postgres(t)
	applyReservationSchemaFixture(ctx, t, pool)

	const org = "11111111-1111-4111-8111-1111111111a1"
	seedBatchWallet(ctx, t, pool, org, 10_000, 0)
	amount := money.MicroUSD(1_500_000)

	// Per-subtest invocation identities: all subtests share the org wallet
	// on one migrated stand, and uniq_settlement_jobs_invocation
	// (org_id, invocation_id, charge_kind) rejects re-seeding the same
	// uuids. Request-id texts collide with no domain and stay shared.
	fencingIdentity := func(variant int) (inv1, inv2 string) {
		base := 40 + 10*variant // v1: ...551/...552, v2: ...561/...562, v3: ...571/...572
		return fmt.Sprintf("55555555-5555-4555-8555-5555555555%02d", base+1),
			fmt.Sprintf("55555555-5555-4555-8555-5555555555%02d", base+2)
	}
	claim := func(t *testing.T, variant int) (id1, id2 int64) {
		t.Helper()
		inv1, inv2 := fencingIdentity(variant)
		id1 = seedBatchInvocationJob(ctx, t, pool, org, "fence-req-1", inv1, SettleKindResale, amount, []byte(`{}`))
		id2 = seedBatchInvocationJob(ctx, t, pool, org, "fence-req-2", inv2, SettleKindResale, amount, []byte(`{}`))
		// The state a live claim leaves behind.
		_, err := pool.Exec(ctx, `UPDATE settlement_jobs SET status = 'processing', attempts = 1, lease_until = now() + interval '30s' WHERE id = ANY($1::bigint[])`, []int64{id1, id2})
		require.NoError(t, err)
		return id1, id2
	}
	entriesFor := func(variant int, id1, id2 int64) []SettleEntry {
		inv1, inv2 := fencingIdentity(variant)
		return []SettleEntry{
			{JobID: id1, FencingToken: 1, RequestID: "fence-req-1", InvocationID: inv1, Kind: SettleKindResale, Amount: amount, Payload: []byte(`{}`)},
			{JobID: id2, FencingToken: 1, RequestID: "fence-req-2", InvocationID: inv2, Kind: SettleKindResale, Amount: amount, Payload: []byte(`{}`)},
		}
	}
	assertNothingMoved := func(t *testing.T) {
		t.Helper()
		bal, _ := settlementWalletState(ctx, t, pool, org)
		assert.EqualValues(t, 10_000, bal, "fenced batch moves no money")
		rows, _ := walletLedger(ctx, t, pool, org)
		assert.EqualValues(t, 0, rows, "fenced batch writes no ledger row")
	}

	t.Run("newer reclaim bumps the token", func(t *testing.T) {
		id1, id2 := claim(t, 1)
		// A newer claim: processing again, attempts incremented.
		_, err := pool.Exec(ctx, `UPDATE settlement_jobs SET attempts = 2 WHERE id = ANY($1::bigint[])`, []int64{id1, id2})
		require.NoError(t, err)
		_, err = SettleOrgBatch(ctx, pool, org, 0, entriesFor(1, id1, id2), BatchSpenders{})
		require.ErrorIs(t, err, ErrStaleSettlementToken)
		assertNothingMoved(t)
		var status string
		require.NoError(t, pool.QueryRow(ctx, `SELECT status FROM settlement_jobs WHERE id = $1`, id1).Scan(&status))
		assert.Equal(t, "processing", status, "rightful owner's claim untouched")
	})

	t.Run("recovered lease same token", func(t *testing.T) {
		id1, id2 := claim(t, 2)
		// recoverExpiredLeases: processing -> retry, attempts UNCHANGED.
		_, err := pool.Exec(ctx, `UPDATE settlement_jobs SET status = 'retry', lease_until = NULL, next_attempt_at = now() WHERE id = ANY($1::bigint[])`, []int64{id1, id2})
		require.NoError(t, err)
		_, err = SettleOrgBatch(ctx, pool, org, 0, entriesFor(2, id1, id2), BatchSpenders{})
		require.ErrorIs(t, err, ErrStaleSettlementToken, "recovered-but-not-reclaimed jobs must fence despite matching attempts")
		assertNothingMoved(t)
		var status string
		var attempts int
		require.NoError(t, pool.QueryRow(ctx, `SELECT status, attempts FROM settlement_jobs WHERE id = $1`, id1).Scan(&status, &attempts))
		assert.Equal(t, "retry", status, "requeued state must not be overwritten")
		assert.Equal(t, 1, attempts)
	})

	t.Run("zero token keeps direct-caller behavior", func(t *testing.T) {
		id1, id2 := claim(t, 3)
		entries := entriesFor(3, id1, id2)
		entries[0].FencingToken = 0
		entries[1].FencingToken = 0
		disp, err := SettleOrgBatch(ctx, pool, org, 0, entries, BatchSpenders{})
		require.NoError(t, err, "token=0 skips fencing: documented direct-caller compatibility")
		assert.True(t, disp[id1].Settled)
		assert.True(t, disp[id2].Settled)
		bal, _ := settlementWalletState(ctx, t, pool, org)
		assert.EqualValues(t, 7_000, bal)
	})
}

// TestSettleOrgBatchReleasedAllowance keeps the reserve linkage negative:
// a RELEASED allowance settles the wallet charge but decrements nothing,
// and the untouched reserved_micro_usd pool stays for its own reconcile.
func TestSettleOrgBatchReleasedAllowance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := testdb.Postgres(t)
	applyReservationSchemaFixture(ctx, t, pool)

	const org = "11111111-1111-4111-8111-1111111111a1"
	seedBatchWallet(ctx, t, pool, org, 10_000, 0)
	_, err := pool.Exec(ctx, `UPDATE org_credits SET reserved_micro_usd = 500_000 WHERE org_id = $1`, org)
	require.NoError(t, err)

	var allowanceID int64
	err = pool.QueryRow(ctx, `
		INSERT INTO budget_allowances (replica_id, scope_kind, scope_key, period, org_id, granted_micro_usd, returned_micro_usd, status, lease_until)
		VALUES ('wfnc-rel', 'wallet', $1, '', $1, 500000, 0, 'released', now())
		RETURNING id`, org).Scan(&allowanceID)
	require.NoError(t, err)

	const req = "wfnc-released-allowance"
	const inv = "66666666-6666-4666-8666-666666666661"
	amount := money.MicroUSD(1_200_000)
	id := seedBatchInvocationJob(ctx, t, pool, org, req, inv, SettleKindResale, amount, []byte(`{}`))

	disp, err := SettleOrgBatch(ctx, pool, org, 0, []SettleEntry{
		{JobID: id, FencingToken: 0, RequestID: req, InvocationID: inv, Kind: SettleKindResale, Amount: amount, Payload: []byte(`{}`), AllowanceID: allowanceID, Bound: amount},
	}, BatchSpenders{})
	require.NoError(t, err)
	require.True(t, disp[id].Settled)
	require.True(t, disp[id].Applied)
	assert.EqualValues(t, 0, disp[id].DecrementMicroUSD, "released allowance decrements nothing")

	bal, _ := settlementWalletState(ctx, t, pool, org)
	assert.EqualValues(t, 9_880, bal, "wallet charge applied: 1,200,000 µ = 120c at 10,000 µ per cent")
	var reserved int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT reserved_micro_usd FROM org_credits WHERE org_id = $1`, org).Scan(&reserved))
	assert.EqualValues(t, 500_000, reserved, "reserve pool untouched")

	var key *int64
	require.NoError(t, pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT (payload->>'%s')::bigint FROM settlement_jobs WHERE id = $1`, ReconcileSettleKey),
		id).Scan(&key))
	assert.Nil(t, key, "no reconcile key when nothing was decremented")

	var status string
	require.NoError(t, pool.QueryRow(ctx, `SELECT status FROM settlement_jobs WHERE id = $1`, id).Scan(&status))
	assert.Equal(t, "settled", status)
}
