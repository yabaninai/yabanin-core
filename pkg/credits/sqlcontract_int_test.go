package credits

// fully migrated Postgres (testdb.Postgres, no build tag — same harness
// posture as pkg/adminstore sqlcontract_int_test.go). Unit mocks match
// query substrings, so column lists, casts and placeholders were never
// exercised; the contract runs the production SQL and fails the test on
// any *pgconn.PgError (rejected columns/types/placeholders) or on any
// rows-iteration failure the store surfaces. Business errors (no wallet,
// insufficient credits, validation) are contract-legal and asserted where
// they pin the semantics.
//
// Wallet rows carry the 0023 reservation columns (reserved_micro_usd,
// grace_floor_cents) so the reserved/grace schema is part of the contract.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sqlc03fContract fails the test when Postgres rejects the SQL (any
// *pgconn.PgError) or when the caller reports a rows-stream breakage; other
// errors are business answers and only logged.
func sqlc03fContract(t *testing.T, name string, fn func(ctx context.Context) error) {
	t.Helper()
	err := fn(context.Background())
	if err == nil {
		return
	}
	var pgErr *pgconn.PgError
	switch {
	case errors.As(err, &pgErr):
		t.Errorf("%s: Postgres rejected the SQL: %s (code %s, where %s, detail %q)",
			name, pgErr.Message, pgErr.Code, pgErr.Where, pgErr.Detail)
	default:
		t.Logf("%s: non-SQL error tolerated by the contract: %v", name, err)
	}
}

// sqlc03fCreditsFixture seeds two token-scoped wallets: orgA is a funded
// wallet with a sub-cent remainder, a live reserve and a legacy-style
// ledger trail; orgB is a nearly empty wallet used for the grace floor and
// the low-balance scan. All identifiers carry the per-run token so the seed
// coexists with every other test on the shared stand, and cleanup removes
// exactly the seeded rows.
type sqlc03fCreditsFixture struct {
	Token       string
	OrgA, OrgB  string
	MissingOrg  string
	LowWalletID string
}

func sqlc03fSeed(t *testing.T, pool *pgxpool.Pool) *sqlc03fCreditsFixture {
	t.Helper()
	ctx := context.Background()
	token := fmt.Sprintf("sc03f%x", time.Now().UnixNano())

	// Fixture wall guard: this package's own tests drop and recreate the
	// credits tables in a pre-0023 shape (store_test.go setupTestTables /
	// teardownTestTables), and -shuffle can order this contract BEFORE that
	// setup, so make sure the base table exists, then restore the production
	// reservation columns — additive, exactly like the migrated schema.
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS org_credits (
			org_id TEXT PRIMARY KEY,
			balance_cents BIGINT NOT NULL DEFAULT 0,
			remainder_micro_usd BIGINT NOT NULL DEFAULT 0 CHECK (remainder_micro_usd >= 0 AND remainder_micro_usd < 10000),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`)
	require.NoError(t, err, "ensure the base org_credits table")
	_, err = pool.Exec(ctx, `
		ALTER TABLE org_credits
			ADD COLUMN IF NOT EXISTS reserved_micro_usd bigint NOT NULL DEFAULT 0 CHECK (reserved_micro_usd >= 0),
			ADD COLUMN IF NOT EXISTS grace_floor_cents bigint CHECK (grace_floor_cents BETWEEN -100000 AND 0)`)
	require.NoError(t, err, "restore the 0023 org_credits columns")

	fx := &sqlc03fCreditsFixture{
		Token:       token,
		OrgA:        token + "-org-a",
		OrgB:        token + "-org-b",
		MissingOrg:  token + "-org-none",
		LowWalletID: token + "-org-low",
	}

	// orgA: funded wallet with a sub-cent remainder, an active reserve and
	// an explicit grace floor (0023 columns); orgB: an empty wallet on the
	// platform default floor; low: 3 cents below a -1 floor for the
	// low-balance scan.
	seeds := []struct {
		org       string
		balance   int64
		remainder int64
		reserved  int64
		floor     *int64
	}{
		{fx.OrgA, 4988, 1234, 40_000, nil},
		{fx.OrgB, 0, 0, 0, nil},
		{fx.LowWalletID, 3, 0, 0, sqlc03fPtr(-1)},
	}
	for _, w := range seeds {
		_, err := pool.Exec(ctx, `
			INSERT INTO org_credits (org_id, balance_cents, remainder_micro_usd, reserved_micro_usd, grace_floor_cents)
			VALUES ($1, $2, $3, $4, $5)`,
			w.org, w.balance, w.remainder, w.reserved, w.floor)
		require.NoError(t, err, "seed wallet %s", w.org)
	}

	// Ledger trail for orgA: a top-up and a usage charge (exact micro on the
	// usage row, invoice ref on the top-up) — GetTransactions scans both
	// nullable columns; orgB keeps one top-up only.
	// Order-independence: store_test.go owns the legacy table shapes; under
	// -shuffle this contract can run before that setup, so create the base
	// tables here too (CREATE ... IF NOT EXISTS matches setupTestTables).
	_, err = pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS credit_transactions (
			id BIGSERIAL PRIMARY KEY,
			org_id TEXT NOT NULL,
			amount_cents BIGINT NOT NULL,
			balance_after BIGINT NOT NULL,
			type TEXT NOT NULL CHECK (type IN ('topup', 'usage')),
			request_id TEXT,
			invoice_ref TEXT,
			metadata JSONB DEFAULT '{}',
			amount_micro_usd BIGINT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`)
	require.NoError(t, err, "ensure the base credit_transactions table")
	_, err = pool.Exec(ctx, `
		INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type, request_id, invoice_ref, amount_micro_usd)
		VALUES ($1, 5000, 5000, 'topup', NULL, $2, 50000000),
		       ($1, -12, 4988, 'usage', $3, NULL, -120000)`,
		fx.OrgA, token+"-inv-1", token+"-req-1")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type)
		VALUES ($1, 5, 0, 'topup')`, fx.OrgB)
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanup := func(q string, args ...any) {
			if _, err := pool.Exec(ctx, q, args...); err != nil {
				t.Errorf("credits contract cleanup: %v", err)
			}
		}
		cleanup(`DELETE FROM credit_transactions WHERE org_id LIKE $1`, token+"%")
		cleanup(`DELETE FROM org_credits WHERE org_id LIKE $1`, token+"%")
	})
	return fx
}

func sqlc03fPtr(v int64) *int64 { return &v }

// sqlc03fCreditsBalance reads one wallet's raw balance for invariant checks.
func sqlc03fCreditsBalance(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string) int64 {
	t.Helper()
	var balance int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT balance_cents FROM org_credits WHERE org_id = $1`, org).Scan(&balance))
	return balance
}

func TestSQLContractCredits(t *testing.T) {
	pool := testdb.Postgres(t)
	fx := sqlc03fSeed(t, pool)
	ctx := context.Background()

	newStore := func(grace int64) *Store {
		return NewStoreWithConfig(pool, nil, Config{GracePeriodCents: grace, CacheTTL: time.Millisecond})
	}

	// GetBalance — remainder-aware wallet present; a fresh store per call
	// keeps every case on the DB path (TTL 1ms expires the cache fast).
	sqlc03fContract(t, "GetBalance[orgA]", func(ctx context.Context) error {
		bal, err := newStore(DefaultConfig().GracePeriodCents).GetBalance(ctx, fx.OrgA)
		if err != nil {
			return err
		}
		assert.Equal(t, int64(1234), bal.RemainderMicroUSD)
		assert.Equal(t, int64(4987), bal.BalanceCents) // floor((4988*10000-1234)/10000)
		assert.Equal(t, fx.OrgA, bal.OrgID)
		return nil
	})
	// GetBalance — no wallet: business error, asserted (never a PgError).
	bal, err := newStore(0).GetBalance(ctx, fx.MissingOrg)
	require.ErrorIs(t, err, ErrNoWallet, "GetBalance[missing] must report ErrNoWallet")
	assert.Nil(t, bal)

	// CheckBalance — funded wallet admits; the admission rule runs on the
	// configured grace floor, so an empty wallet is rejected exactly at the
	// floor (≤) and the 3-cent low wallet straddles it: admitted at a -1
	// floor, rejected at a 3-cent floor.
	_, err = newStore(DefaultConfig().GracePeriodCents).CheckBalance(ctx, fx.OrgA)
	require.NoError(t, err, "CheckBalance[orgA]")
	_, err = newStore(0).CheckBalance(ctx, fx.OrgB)
	require.ErrorIs(t, err, ErrInsufficientCredits, "CheckBalance[empty wallet, no overdraft]")
	_, err = newStore(-1).CheckBalance(ctx, fx.LowWalletID)
	require.NoError(t, err, "CheckBalance[low wallet, -1 floor]")
	_, err = newStore(3).CheckBalance(ctx, fx.LowWalletID)
	require.ErrorIs(t, err, ErrInsufficientCredits, "CheckBalance[at-floor is inclusive rejection]")

	// TopUp — the upsert + ledger CTE executes and moves the wallet.
	sqlc03fContract(t, "TopUp[orgA]", func(ctx context.Context) error {
		st := newStore(DefaultConfig().GracePeriodCents)
		if err := st.TopUp(ctx, fx.OrgA, 100, fx.Token+"-inv-topup"); err != nil {
			return err
		}
		bal, err := st.GetBalance(ctx, fx.OrgA)
		if err != nil {
			return err
		}
		assert.GreaterOrEqual(t, bal.BalanceCents, int64(5086), "top-up must land on the wallet")
		return nil
	})
	err = newStore(0).TopUp(ctx, fx.OrgA, 0, "")
	require.Error(t, err, "TopUp[zero amount] is a validation rejection")

	// Deduct — whole-cent path with an idempotent replay.
	sqlc03fContract(t, "Deduct[orgA]+replay", func(ctx context.Context) error {
		st := newStore(DefaultConfig().GracePeriodCents)
		if err := st.Deduct(ctx, fx.OrgA, 10, fx.Token+"-req-deduct", map[string]interface{}{"env": "contract"}); err != nil {
			return err
		}
		if err := st.Deduct(ctx, fx.OrgA, 10, fx.Token+"-req-deduct", nil); err != nil {
			return fmt.Errorf("idempotent replay must be a no-op success: %w", err)
		}
		bal, err := st.GetBalance(ctx, fx.OrgA)
		if err != nil {
			return err
		}
		assert.GreaterOrEqual(t, bal.BalanceCents, int64(5075), "exactly one deduction must have applied")
		return nil
	})

	// DeductMicro — sub-cent charge leaves its residue on the wallet
	// (reserved/grace schema in play), and the grace floor rejects a charge
	// that would cross it.
	sqlc03fContract(t, "DeductMicro[orgA,subcent]", func(ctx context.Context) error {
		st := newStore(DefaultConfig().GracePeriodCents)
		before, err := st.GetBalance(ctx, fx.OrgA)
		if err != nil {
			return err
		}
		if err := st.DeductMicro(ctx, fx.OrgA, 4004, fx.Token+"-req-micro", nil); err != nil {
			return err
		}
		after, err := st.GetBalance(ctx, fx.OrgA)
		if err != nil {
			return err
		}
		assert.NotEqual(t, before.BalanceMicroUSD, after.BalanceMicroUSD, "sub-cent charge must move the exact balance")
		return nil
	})
	err = newStore(0).DeductMicro(ctx, fx.LowWalletID, money.MicroUSD(200*int64(money.MicroPerCent)), fx.Token+"-req-over", nil)
	require.ErrorIs(t, err, ErrInsufficientCredits, "DeductMicro[below explicit floor]")

	// GetTransactions — limit variants: explicit, defaulting (0/negative/
	// oversize clamp to 50) and the empty result for an unknown org.
	sqlc03fContract(t, "GetTransactions[orgA,limit2]", func(ctx context.Context) error {
		txns, err := newStore(0).GetTransactions(ctx, fx.OrgA, 2)
		if err != nil {
			return err
		}
		if !assert.Len(t, txns, 2, "limit must cap the ledger read") {
			return nil
		}
		assert.False(t, txns[0].CreatedAt.Before(txns[1].CreatedAt), "rows must arrive created_at DESC")
		for _, txn := range txns {
			assert.Equal(t, fx.OrgA, txn.OrgID)
		}
		return nil
	})
	sqlc03fContract(t, "GetTransactions[orgB,default-limit]", func(ctx context.Context) error {
		txns, err := newStore(0).GetTransactions(ctx, fx.OrgB, 0)
		if err != nil {
			return err
		}
		assert.Len(t, txns, 1, "orgB carries exactly the seeded top-up")
		return nil
	})
	sqlc03fContract(t, "GetTransactions[orgA,clamped]", func(ctx context.Context) error {
		_, err := newStore(0).GetTransactions(ctx, fx.OrgA, 10_000)
		return err
	})
	sqlc03fContract(t, "GetTransactions[missing,empty]", func(ctx context.Context) error {
		txns, err := newStore(0).GetTransactions(ctx, fx.MissingOrg, 50)
		if err != nil {
			return err
		}
		assert.Empty(t, txns, "an unknown org has no ledger")
		return nil
	})

	// LowBalanceOrgs — threshold and limit combinations on the real scan.
	sqlc03fContract(t, "LowBalanceOrgs[threshold5]", func(ctx context.Context) error {
		orgs, err := newStore(0).LowBalanceOrgs(ctx, 5, 100)
		if err != nil {
			return err
		}
		assert.Contains(t, orgs, fx.LowWalletID, "the 3-cent wallet is below the threshold")
		assert.NotContains(t, orgs, fx.OrgA, "the funded wallet stays out")
		return nil
	})
	sqlc03fContract(t, "LowBalanceOrgs[limit1]", func(ctx context.Context) error {
		orgs, err := newStore(0).LowBalanceOrgs(ctx, 5, 1)
		if err != nil {
			return err
		}
		// Other tests on the shared stand may leave sub-threshold wallets
		// behind; the cap itself is the contract, and any row that does
		// come back must genuinely sit below the threshold.
		if assert.LessOrEqual(t, len(orgs), 1, "the limit must cap the scan") && len(orgs) == 1 {
			balance := sqlc03fCreditsBalance(ctx, t, pool, orgs[0])
			assert.Less(t, balance, int64(5), "returned wallets must satisfy the threshold")
		}
		return nil
	})
	sqlc03fContract(t, "LowBalanceOrgs[threshold0,empty]", func(ctx context.Context) error {
		orgs, err := newStore(0).LowBalanceOrgs(ctx, 0, 100)
		if err != nil {
			return err
		}
		assert.NotContains(t, orgs, fx.OrgA)
		assert.NotContains(t, orgs, fx.LowWalletID)
		return nil
	})
}
