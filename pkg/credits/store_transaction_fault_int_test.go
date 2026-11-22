package credits

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/require"
)

func TestDeductMicroSerializationRetryChargesOnce(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	const org, request = "credits-retry-once", "credits-retry-request"
	seedWallet(ctx, t, pool, org, 100)
	installCreditInsertSerializationFailure(t, ctx, pool, 1)

	store := NewStore(pool, nil)
	require.NoError(t, store.DeductMicro(ctx, org, money.MicroUSD(250000), request, nil))
	assertRetrySequence(t, ctx, pool, 2)
	assertCreditState(t, ctx, pool, org, 75, 0, 1, -250000)
	requireReconciledSeeded(ctx, t, pool, org, 100)
}

func TestDeductMicroSerializationRetryExhaustionLeavesNoDebit(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	const org, request = "credits-retry-exhausted", "credits-retry-exhausted-request"
	seedWallet(ctx, t, pool, org, 100)
	installCreditInsertSerializationFailure(t, ctx, pool, maxDeductRetries+1)

	err := NewStore(pool, nil).DeductMicro(ctx, org, money.MicroUSD(250000), request, nil)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "40001", pgErr.Code)
	assertRetrySequence(t, ctx, pool, int64(maxDeductRetries+1))
	assertCreditState(t, ctx, pool, org, 100, 0, 0, 0)
	requireReconciledSeeded(ctx, t, pool, org, 100)
}

func TestDeductMicroMetadataMarshalFailureRollsBackWalletAndLedger(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	const org, request = "credits-metadata-failure", "credits-metadata-failure-request"
	seedWallet(ctx, t, pool, org, 100)

	err := NewStore(pool, nil).DeductMicro(ctx, org, money.MicroUSD(250000), request,
		map[string]interface{}{"unsupported": make(chan int)})
	var typeErr *json.UnsupportedTypeError
	if !errors.As(err, &typeErr) {
		t.Fatalf("unmarshalable metadata must reject the debit, got %v", err)
	}
	assertCreditState(t, ctx, pool, org, 100, 0, 0, 0)
	requireReconciledSeeded(ctx, t, pool, org, 100)
}

func TestDeductMicroCommitFailureRollsBackWalletAndLedger(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	const org, request = "credits-commit-failure", "credits-commit-failure-request"
	seedWallet(ctx, t, pool, org, 100)
	_, err := pool.Exec(ctx, `CREATE FUNCTION reject_credit_commit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'forced deferred ledger failure' USING ERRCODE = '23514';
		END;
		$$`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `CREATE CONSTRAINT TRIGGER reject_credit_commit
		AFTER INSERT ON credit_transactions
		DEFERRABLE INITIALLY DEFERRED
		FOR EACH ROW EXECUTE FUNCTION reject_credit_commit()`)
	require.NoError(t, err)

	err = NewStore(pool, nil).DeductMicro(ctx, org, money.MicroUSD(250000), request, nil)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("deferred commit failure must return constraint error 23514, got %v", err)
	}
	assertCreditState(t, ctx, pool, org, 100, 0, 0, 0)
	requireReconciledSeeded(ctx, t, pool, org, 100)
}

func TestDeductOnceMicroClosedPoolFailsBeforeTransaction(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, "postgres://unused:unused@127.0.0.1:1/unused")
	require.NoError(t, err)
	pool.Close()
	_, poolErr := pool.Acquire(ctx)
	require.Error(t, poolErr)
	err = NewStore(pool, nil).deductOnceMicro(ctx, "org-credit", money.MicroUSD(1), "request-credit", "", nil, false)
	require.ErrorIs(t, err, poolErr)
	require.ErrorContains(t, err, "deduct begin tx")
}

func installCreditInsertSerializationFailure(t *testing.T, ctx context.Context, pool *pgxpool.Pool, failures int) {
	t.Helper()
	if failures < 0 || failures > maxDeductRetries+1 {
		t.Fatalf("invalid failure count %d", failures)
	}
	_, err := pool.Exec(ctx, `CREATE SEQUENCE credits_insert_attempts START WITH 1`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION fail_credit_insert_serialization() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF nextval('credits_insert_attempts') <= %d THEN
				RAISE EXCEPTION 'forced serialization failure' USING ERRCODE = '40001';
			END IF;
			RETURN NEW;
		END;
		$$`, failures))
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `CREATE TRIGGER fail_credit_insert_serialization
		BEFORE INSERT ON credit_transactions
		FOR EACH ROW EXECUTE FUNCTION fail_credit_insert_serialization()`)
	require.NoError(t, err)
}

func assertRetrySequence(t *testing.T, ctx context.Context, pool *pgxpool.Pool, want int64) {
	t.Helper()
	var got int64
	require.NoError(t, pool.QueryRow(ctx, "SELECT last_value FROM credits_insert_attempts").Scan(&got))
	require.Equal(t, want, got, "every failed commit attempt must execute the insert trigger once")
}

func assertCreditState(t *testing.T, ctx context.Context, pool *pgxpool.Pool, org string, wantBalance, wantRemainder, wantRows, wantMicro int64) {
	t.Helper()
	gotBalance, gotRemainder := walletRow(ctx, t, pool, org)
	require.Equal(t, wantBalance, gotBalance)
	require.Equal(t, wantRemainder, gotRemainder)
	var rows, micro int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*), COALESCE(sum(amount_micro_usd), 0)
		FROM credit_transactions WHERE org_id = $1 AND type = 'usage'
	`, org).Scan(&rows, &micro))
	require.Equal(t, wantRows, rows)
	require.Equal(t, wantMicro, micro)
}

func TestEffectiveBalanceOverflowInCheckBalanceFailsClosed(t *testing.T) {
	ctx := context.Background()
	pool := setupFixtureDB(t)
	setupTestTables(ctx, t, pool)
	const org = "credits-overflow-admission"
	_, err := pool.Exec(ctx,
		`INSERT INTO org_credits (org_id, balance_cents, remainder_micro_usd) VALUES ($1, $2, 0)`,
		org, int64(math.MaxInt64))
	require.NoError(t, err)

	balance, err := NewStore(pool, nil).CheckBalance(ctx, org)
	require.Nil(t, balance)
	require.EqualError(t, err, "balance 9223372036854775807 cents out of representable range")
}
