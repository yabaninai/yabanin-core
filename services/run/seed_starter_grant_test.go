package run

// W-CRED: the seed path of the beta starter grant. ApplySeed must land the
// grant exactly once per org — a re-seed (the idempotent bootstrap) is a
// no-op on the grant, and BETA_STARTER_CREDITS_CENTS=0 disables it entirely.

import (
	"log/slog"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/testdb"
)

func TestApplySeed_StarterGrantExactlyOnce(t *testing.T) {
	pool := testdb.Postgres(t)
	t.Setenv(credits.StarterGrantEnvVar, "7777")
	ctx := t.Context()
	opts := seedTestOptions(t, true)

	var firstOut, secondOut strings.Builder
	first, err := ApplySeed(ctx, pool, nil, opts, slog.Default(), &firstOut)
	require.NoError(t, err)

	second, err := ApplySeed(ctx, pool, nil, opts, slog.Default(), &secondOut)
	require.NoError(t, err)
	require.Equal(t, first.OrgID, second.OrgID, "both runs must address the same org")

	require.Equal(t, int64(1), countRow(t, pool,
		`SELECT count(*) FROM credit_transactions WHERE org_id = $1 AND type = 'topup' AND invoice_ref = $2`,
		first.OrgID, credits.StarterGrantReason),
		"the starter grant must be exactly one ledger row across both runs")

	var amount, balance int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT amount_cents FROM credit_transactions WHERE org_id = $1 AND invoice_ref = $2`,
		first.OrgID, credits.StarterGrantReason).Scan(&amount))
	require.Equal(t, int64(7777), amount, "the env-configured amount must be journalled")
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT balance_cents FROM org_credits WHERE org_id = $1`, first.OrgID).Scan(&balance))
	require.Equal(t, int64(seedCreditsCents+7777), balance)
}

func TestApplySeed_StarterGrantDisabledByZero(t *testing.T) {
	pool := testdb.Postgres(t)
	t.Setenv(credits.StarterGrantEnvVar, "0")
	ctx := t.Context()
	opts := seedTestOptions(t, true)

	var out strings.Builder
	res, err := ApplySeed(ctx, pool, nil, opts, slog.Default(), &out)
	require.NoError(t, err)

	require.Equal(t, int64(0), countRow(t, pool,
		`SELECT count(*) FROM credit_transactions WHERE org_id = $1 AND invoice_ref = $2`,
		res.OrgID, credits.StarterGrantReason),
		"a zero grant must not touch the ledger")

	var balance int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT balance_cents FROM org_credits WHERE org_id = $1`, res.OrgID).Scan(&balance))
	require.Equal(t, int64(seedCreditsCents), balance, "only the quickstart seed grant remains")
}

// TestApplySeed_StarterGrantLedgerIsExact pins the exact micro accounting on
// the seeded grant row (AF-05 contract: amount_cents mirrors amount_micro_usd).
func TestApplySeed_StarterGrantLedgerIsExact(t *testing.T) {
	pool := testdb.Postgres(t)
	t.Setenv(credits.StarterGrantEnvVar, strconv.FormatInt(credits.DefaultStarterGrantCents, 10))
	ctx := t.Context()
	opts := seedTestOptions(t, true)

	var out strings.Builder
	res, err := ApplySeed(ctx, pool, nil, opts, slog.Default(), &out)
	require.NoError(t, err)

	var micro int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT amount_micro_usd FROM credit_transactions WHERE org_id = $1 AND invoice_ref = $2`,
		res.OrgID, credits.StarterGrantReason).Scan(&micro))
	require.Equal(t, credits.DefaultStarterGrantCents*10000, micro)
}
