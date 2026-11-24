package credits

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The invocation identity must be a canonical non-nil UUID before any
// database work: nil, URN, braced, compact and case-respelled spellings
// are all rejected — a malformed identity can never reach an idempotency
// key, and never silently downgrades onto the legacy domain.
func TestDeductMicroInvocation_CanonicalIDGate(t *testing.T) {
	store := NewStore(nil, nil)
	canonical := "0f0e0d0c-0b0a-4901-8203-040506070809"
	shapes := map[string]string{
		"nil uuid":     "00000000-0000-0000-0000-000000000000",
		"urn spelling": "urn:uuid:0f0e0d0c-0b0a-4901-8203-040506070809",
		"braced":       "{0f0e0d0c-0b0a-4901-8203-040506070809}",
		"compact":      "0f0e0d0c0b0a49018203040506070809",
		"uppercase":    "0F0E0D0C-0B0A-4901-8203-040506070809",
	}
	for name, id := range shapes {
		err := store.DeductMicroInvocation(context.Background(), "org-gate", 1000, "req-gate", id, nil)
		require.ErrorContains(t, err, "canonical", "%s must be rejected", name)
		require.NotErrorIs(t, err, ErrChargeIdentityConflict, "%s is malformed input, not an integrity conflict", name)
	}
	// Sanity: the canonical spelling passes the gate (and then fails only
	// on the nil-DB parameter check — never on the identity).
	err := store.DeductMicroInvocation(context.Background(), "org-gate", 1000, "req-gate", canonical, nil)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "canonical")
}

// A replayed invocation charge is idempotent: the wallet moves exactly
// once, the ledger holds exactly one usage row under the invocation, and
// the books reconcile.
func TestDeductMicroInvocation_ReplayIsIdempotent(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	defer teardownTestTables(ctx, t, pool)

	org := "inv-replay"
	seedWallet(ctx, t, pool, org, 0)
	store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -1_000_000})

	inv := "0f0e0d0c-0b0a-4901-8203-040506070809"
	require.NoError(t, store.DeductMicroInvocation(ctx, org, 15000, "req-replay", inv, nil))
	require.NoError(t, store.DeductMicroInvocation(ctx, org, 15000, "req-replay", inv, nil), "a replayed charge is a no-op success")
	require.NoError(t, store.DeductMicroInvocation(ctx, org, 15000, "req-replay", inv, nil))

	balanceCents, remainder := walletRow(ctx, t, pool, org)
	assert.Equal(t, int64(-1), balanceCents, "three replays charged exactly $0.015 once")
	assert.Equal(t, int64(5000), remainder)
	assertLedger := `SELECT count(*) FROM credit_transactions WHERE invocation_id = $1 AND type = 'usage'`
	var rows int
	require.NoError(t, pool.QueryRow(ctx, assertLedger, inv).Scan(&rows))
	assert.Equal(t, 1, rows, "exactly one usage row under the invocation")
	requireReconciled(ctx, t, pool, org)
}

// The same invocation identity under another tenant is an integrity
// conflict — never an idempotent no-op for the second tenant, and never a
// charge against the first tenant's row.
func TestDeductMicroInvocation_WrongTenantIsIntegrityConflict(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	defer teardownTestTables(ctx, t, pool)

	orgA, orgB := "inv-tenant-a", "inv-tenant-b"
	seedWallet(ctx, t, pool, orgA, 0)
	seedWallet(ctx, t, pool, orgB, 0)
	store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -1_000_000})

	inv := "11111111-2222-4333-8444-555555555555"
	require.NoError(t, store.DeductMicroInvocation(ctx, orgA, 15000, "req-tenant", inv, nil))

	err := store.DeductMicroInvocation(ctx, orgB, 15000, "req-tenant", inv, nil)
	require.ErrorIs(t, err, ErrChargeIdentityConflict)

	balanceCents, _ := walletRow(ctx, t, pool, orgA)
	assert.Equal(t, int64(-1), balanceCents, "org A was charged exactly once")
	_, remainderB := walletRow(ctx, t, pool, orgB)
	assert.Equal(t, int64(0), remainderB, "org B was never charged")
	var rowOrg string
	require.NoError(t, pool.QueryRow(ctx, `SELECT org_id FROM credit_transactions WHERE invocation_id = $1 AND type = 'usage'`, inv).Scan(&rowOrg))
	assert.Equal(t, orgA, rowOrg, "the authoritative row keeps its original tenant")
}

// The same invocation identity with a different amount is an integrity
// conflict: identity and amount are one fact, not two idempotency keys.
func TestDeductMicroInvocation_ChangedAmountIsIntegrityConflict(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	defer teardownTestTables(ctx, t, pool)

	org := "inv-amount"
	seedWallet(ctx, t, pool, org, 0)
	store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -1_000_000})

	inv := "22222222-3333-4444-8555-666666666666"
	require.NoError(t, store.DeductMicroInvocation(ctx, org, 15000, "req-amount", inv, nil))
	require.ErrorIs(t, store.DeductMicroInvocation(ctx, org, 16000, "req-amount", inv, nil),
		ErrChargeIdentityConflict, "a re-keyed amount under the same identity conflicts")

	balanceCents, _ := walletRow(ctx, t, pool, org)
	assert.Equal(t, int64(-1), balanceCents, "the conflicting replay charged nothing")
}

// A legacy charge after an invoked charge under the same correlation must
// never be silently suppressed by the invoked row: the idempotency lookup
// no longer matches it, so the insert runs and collides loudly with the
// still-live global usage index (interim posture until 0029) — an error
// that parks for attention, never a no-op and never a double charge.
func TestDeductMicro_LegacyAfterInvokedIsNeverSilentlySuppressed(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	defer teardownTestTables(ctx, t, pool)

	org := "inv-domains"
	seedWallet(ctx, t, pool, org, 0)
	store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -1_000_000})

	inv := "33333333-4444-4555-8666-777777777777"
	require.NoError(t, store.DeductMicroInvocation(ctx, org, 15000, "req-domains", inv, nil))

	err := store.DeductMicro(ctx, org, 15000, "req-domains", nil)
	require.Error(t, err, "the legacy charge is not suppressed into silence")
	require.NotErrorIs(t, err, ErrChargeIdentityConflict, "this is a loud insert collision, not a lookup conflict")
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr, "the collision is a Postgres unique violation")
	assert.Equal(t, "23505", pgErr.Code)

	balanceCents, _ := walletRow(ctx, t, pool, org)
	assert.Equal(t, int64(-1), balanceCents, "the failed legacy charge moved no money")
}

// The mirrored direction: an invoked charge after a legacy row under the
// same correlation is not swallowed by the legacy key — it fails loudly on
// the still-live global usage index (interim posture until 0029).
func TestDeductMicro_InvokedAfterLegacyCollidesLoudly(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	defer teardownTestTables(ctx, t, pool)

	org := "inv-domains-2"
	seedWallet(ctx, t, pool, org, 0)
	store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -1_000_000})

	require.NoError(t, store.DeductMicro(ctx, org, 15000, "req-domains-2", nil))
	inv := "44444444-5555-4666-8777-888888888888"
	err := store.DeductMicroInvocation(ctx, org, 15000, "req-domains-2", inv, nil)
	require.Error(t, err, "the invoked charge is not swallowed by the legacy row")
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	assert.Equal(t, "23505", pgErr.Code, "interim global usage index collision — loud, parked, retried")

	var usageRows int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM credit_transactions WHERE request_id = $1 AND type = 'usage'`, "req-domains-2").Scan(&usageRows))
	assert.Equal(t, 1, usageRows, "exactly one usage row exists")
}

// A transient ledger-schema probe failure propagates and is never cached
// as the old schema: the retried deduction probes again and succeeds.
func TestDeductMicro_ProbeFailureIsNotCachedAsOldSchema(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	defer teardownTestTables(ctx, t, pool)

	org := "inv-probe"
	seedWallet(ctx, t, pool, org, 0)
	store := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -1_000_000})

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	inv := "55555555-6666-4777-8888-999999999999"
	err := store.DeductMicroInvocation(canceled, org, 15000, "req-probe", inv, nil)
	require.ErrorContains(t, err, "resolve ledger schema", "the probe failure propagates")
	require.ErrorIs(t, err, context.Canceled)

	require.NoError(t, store.DeductMicroInvocation(ctx, org, 15000, "req-probe", inv, nil),
		"the retried deduction probes again and succeeds — no cached false")
	balanceCents, _ := walletRow(ctx, t, pool, org)
	assert.Equal(t, int64(-1), balanceCents)
}
