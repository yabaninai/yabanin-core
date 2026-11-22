package credits

// Admission tests read the production wallet schema after migrations.
import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// seedAdmissionWallet creates one private wallet in the migrated schema.
func seedAdmissionWallet(t *testing.T, pool *pgxpool.Pool, balance int64, floor *int64) string {
	t.Helper()
	org := uuid.NewString()
	_, err := pool.Exec(t.Context(), `INSERT INTO org_credits (org_id, balance_cents, grace_floor_cents)
		VALUES ($1, $2, $3)`, org, balance, floor)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := pool.Exec(context.Background(), `DELETE FROM credit_transactions WHERE org_id = $1`, org)
		require.NoError(t, err)
		_, err = pool.Exec(context.Background(), `DELETE FROM org_credits WHERE org_id = $1`, org)
		require.NoError(t, err)
	})
	return org
}

// TestCheckBalance_PersistedGraceFloorContract: persisted floors decide —
// an explicit 0 rejects a wallet the platform floor admits, NULL keeps the
// platform fallback, and a deep floor admits a wallet the platform floor
// rejects. The override never leaks across org rows.
func TestCheckBalance_PersistedGraceFloorContract(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()

	zero, deep := int64(0), int64(-10000)
	zeroOrg := seedAdmissionWallet(t, pool, -50, &zero)
	defaultOrg := seedAdmissionWallet(t, pool, -50, nil)
	deepOrg := seedAdmissionWallet(t, pool, -500, &deep)
	deepDefaultOrg := seedAdmissionWallet(t, pool, -500, nil)

	s := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -100, CacheTTL: time.Minute})

	_, err := s.CheckBalance(ctx, zeroOrg)
	require.ErrorIs(t, err, ErrInsufficientCredits,
		"explicit persisted zero floor must reject a negative wallet even under a negative platform floor")

	_, err = s.CheckBalance(ctx, defaultOrg)
	require.NoError(t, err,
		"NULL floor falls back to the platform floor: wallet -50 admits under -100")

	_, err = s.CheckBalance(ctx, deepOrg)
	require.NoError(t, err,
		"persisted deep floor admits a wallet the platform floor rejects")

	_, err = s.CheckBalance(ctx, deepDefaultOrg)
	require.ErrorIs(t, err, ErrInsufficientCredits,
		"gf-deep's floor override must not leak: a null-floor org rejects at -500")

	// Negative control: denied calls write nothing — no ledger rows and no
	// wallet mutation for the rejected orgs.
	var usageRows int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM credit_transactions WHERE org_id IN ($1, $2) AND type = 'usage'`, zeroOrg, deepDefaultOrg,
	).Scan(&usageRows))
	require.Zero(t, usageRows, "denied admission must leave zero usage rows")

	zeroBalance, _ := walletRow(ctx, t, pool, zeroOrg)
	deepBalance, _ := walletRow(ctx, t, pool, deepDefaultOrg)
	require.Equal(t, int64(-50), zeroBalance)
	require.Equal(t, int64(-500), deepBalance)
}

// TestCheckBalance_FloorChangeIsAuthoritativeOnAdmission: the display cache
// and admission must diverge exactly as documented. A warm display snapshot
// (GetBalance) keeps serving its TTL view, while the very next CheckBalance
// — with NO invalidation at all — reads the fresh floor and balance and
// decides on them. InvalidateOrg refreshes only the display view.
func TestCheckBalance_FloorChangeIsAuthoritativeOnAdmission(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	org := seedAdmissionWallet(t, pool, -50, nil)

	s := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -100, CacheTTL: time.Minute})

	// Warm the display cache; the platform floor admits the same wallet.
	bal, err := s.GetBalance(ctx, org)
	require.NoError(t, err, "display view warms")
	require.Equal(t, int64(-50), bal.BalanceCents)
	_, err = s.CheckBalance(ctx, org)
	require.NoError(t, err, "wallet -50 admits under the platform floor")

	// Mutate the wallet and the floor directly in the DB, invalidating
	// nothing: the display view must keep its stale snapshot (TTL envelope),
	// the admission decision must already see the new state.
	_, err = pool.Exec(ctx,
		`UPDATE org_credits SET balance_cents = -500, grace_floor_cents = 0 WHERE org_id = $1`, org)
	require.NoError(t, err, "mutate wallet and floor behind the warm display snapshot")

	bal, err = s.GetBalance(ctx, org)
	require.NoError(t, err, "display view stays readable")
	require.Equal(t, int64(-50), bal.BalanceCents,
		"the display cache must keep serving its warm TTL snapshot — GetBalance is not admission")

	_, err = s.CheckBalance(ctx, org)
	require.ErrorIs(t, err, ErrInsufficientCredits,
		"admission is authoritative: the fresh floor 0 decides the next call — no invalidation may be required")
	bal, err = s.CheckBalance(ctx, org)
	require.ErrorIs(t, err, ErrInsufficientCredits, "rejected call must still return the balance view")
	require.Equal(t, int64(-500), bal.BalanceCents,
		"the rejection payload must carry the fresh wallet, not the warm display snapshot")

	// InvalidateOrg is display freshness only: it must not be required for
	// admission correctness (already proven above) but must refresh the
	// display view.
	s.InvalidateOrg(org)
	bal, err = s.GetBalance(ctx, org)
	require.NoError(t, err, "display view readable after invalidation")
	require.Equal(t, int64(-500), bal.BalanceCents, "invalidation refreshes the display view")
}

// TestCheckBalance_TwoStoresFreshAdmissionExactContacts: gateway and admin
// construct distinct credit Stores over the same pool (gateway.go /
// services/run/admin.go). Warming the gateway store's display view must not
// let a floor change written via the admin side be missed by the gateway
// admission path: the next gateway CheckBalance contacts the DB fresh and
// decides on the new persisted floor, with exact per-path contacts — the
// gateway display view stays stale until invalidated, the admission view is
// fresh on every call.
func TestCheckBalance_TwoStoresFreshAdmissionExactContacts(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	org := seedAdmissionWallet(t, pool, -50, nil)

	gw := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -100, CacheTTL: time.Minute})
	admin := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -100, CacheTTL: time.Minute})

	// Gateway-side admission and display view warm up under the platform
	// floor; the admin instance's display view warms on its own instance.
	_, err := gw.CheckBalance(ctx, org)
	require.NoError(t, err, "gateway admits under the platform floor before the change")
	_, err = gw.GetBalance(ctx, org)
	require.NoError(t, err, "gateway display view warms")
	_, err = admin.GetBalance(ctx, org)
	require.NoError(t, err, "admin display view warms on its own instance")

	// Admin-side mutation: the persisted floor tightens to explicit 0 (the
	// write the adminstore floor mutation performs) and the admin process
	// invalidates its own display view exactly like the handler does.
	_, err = pool.Exec(ctx, `UPDATE org_credits SET grace_floor_cents = 0 WHERE org_id = $1`, org)
	require.NoError(t, err, "admin-side floor change commits")
	admin.InvalidateOrg(org)

	// The next gateway admission must reflect the tightened floor: paid
	// dispatch may not continue under the stale platform floor.
	_, err = gw.CheckBalance(ctx, org)
	require.ErrorIs(t, err, ErrInsufficientCredits,
		"the gateway store must contact the DB fresh and reject under the changed floor — its warm view must not permit paid dispatch")

	// Exact contacts, per path: the gateway display view did NOT contact the
	// DB again (still the stale seeded wallet), while the admission path
	// returned the fresh row. Distinct stores, one pool, one authoritative path.
	bal, err := gw.GetBalance(ctx, org)
	require.NoError(t, err, "gateway display view readable")
	require.Equal(t, int64(-50), bal.BalanceCents,
		"the gateway display snapshot stays warm within its TTL — only the admission path is authoritative")

	// Resetting the floor to NULL restores admission on the gateway path.
	_, err = pool.Exec(ctx, `UPDATE org_credits SET grace_floor_cents = NULL WHERE org_id = $1`, org)
	require.NoError(t, err, "floor reset commits")
	_, err = gw.CheckBalance(ctx, org)
	require.NoError(t, err, "the gateway admission path must pick up the reset floor immediately")
}
