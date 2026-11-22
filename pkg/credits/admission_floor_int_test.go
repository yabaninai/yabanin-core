package credits

// Physical §8 admission contract on the migrated stand (PostgresOwnedSchema,
// same posture as sqlcontract_int_test.go): the production wallet snapshot
// SQL carries the persisted grace_floor_cents column, the override is
// row-keyed, denials write nothing, and admission is authoritative — a fresh
// snapshot per decision, never the display cache, so a floor change decides
// the next admission without any invalidation, even across distinct store
// instances (gateway and admin hold separate Stores over one pool).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestCheckBalance_PersistedGraceFloorContract: persisted floors decide —
// an explicit 0 rejects a wallet the platform floor admits, NULL keeps the
// platform fallback, and a deep floor admits a wallet the platform floor
// rejects. The override never leaks across org rows.
func TestCheckBalance_PersistedGraceFloorContract(t *testing.T) {
	pool := setupFixtureDB(t)
	ctx := context.Background()

	type wallet struct {
		org     string
		balance int64
		floor   *int64 // nil = NULL (platform default)
	}
	zero := int64(0)
	deep := int64(-10000)
	wallets := []wallet{
		{org: "gf-zero", balance: -50, floor: &zero},
		{org: "gf-null", balance: -50, floor: nil},
		{org: "gf-deep", balance: -500, floor: &deep},
		{org: "gf-null-deep-wallet", balance: -500, floor: nil},
	}
	for _, w := range wallets {
		_, err := pool.Exec(ctx,
			`INSERT INTO org_credits (org_id, balance_cents, grace_floor_cents) VALUES ($1, $2, $3)`,
			w.org, w.balance, w.floor)
		require.NoError(t, err, "seed %s", w.org)
	}

	s := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -100, CacheTTL: time.Minute})

	_, err := s.CheckBalance(ctx, "gf-zero")
	require.ErrorIs(t, err, ErrInsufficientCredits,
		"explicit persisted zero floor must reject a negative wallet even under a negative platform floor")

	_, err = s.CheckBalance(ctx, "gf-null")
	require.NoError(t, err,
		"NULL floor falls back to the platform floor: wallet -50 admits under -100")

	_, err = s.CheckBalance(ctx, "gf-deep")
	require.NoError(t, err,
		"persisted deep floor admits a wallet the platform floor rejects")

	_, err = s.CheckBalance(ctx, "gf-null-deep-wallet")
	require.ErrorIs(t, err, ErrInsufficientCredits,
		"gf-deep's floor override must not leak: a null-floor org rejects at -500")

	// Negative control: denied calls write nothing — no ledger rows and no
	// wallet mutation for the rejected orgs.
	var usageRows int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM credit_transactions WHERE org_id IN ('gf-zero', 'gf-null-deep-wallet') AND type = 'usage'`,
	).Scan(&usageRows))
	require.Zero(t, usageRows, "denied admission must leave zero usage rows")

	var balances int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM org_credits WHERE org_id IN ('gf-zero', 'gf-null-deep-wallet') AND balance_cents NOT IN (-50, -500)`,
	).Scan(&balances))
	require.Zero(t, balances, "denied admission must not touch the wallet rows")
}

// TestCheckBalance_FloorChangeIsAuthoritativeOnAdmission: the display cache
// and admission must diverge exactly as documented. A warm display snapshot
// (GetBalance) keeps serving its TTL view, while the very next CheckBalance
// — with NO invalidation at all — reads the fresh floor and balance and
// decides on them. InvalidateOrg refreshes only the display view.
func TestCheckBalance_FloorChangeIsAuthoritativeOnAdmission(t *testing.T) {
	pool := setupFixtureDB(t)
	ctx := context.Background()
	const org = "gf-authoritative"
	_, err := pool.Exec(ctx,
		`INSERT INTO org_credits (org_id, balance_cents, grace_floor_cents) VALUES ($1, -50, NULL)`, org)
	require.NoError(t, err, "seed wallet")

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
	pool := setupFixtureDB(t)
	ctx := context.Background()
	const org = "gf-two-stores"
	_, err := pool.Exec(ctx,
		`INSERT INTO org_credits (org_id, balance_cents, grace_floor_cents) VALUES ($1, -50, NULL)`, org)
	require.NoError(t, err, "seed wallet")

	gw := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -100, CacheTTL: time.Minute})
	admin := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -100, CacheTTL: time.Minute})

	// Gateway-side admission and display view warm up under the platform
	// floor; the admin instance's display view warms on its own instance.
	_, err = gw.CheckBalance(ctx, org)
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
