package credits

import (
	"context"
	"testing"

	pgxpool "github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// TestMigratedCreditsPostureIntact pins the shared stand's PUBLIC schema to
// the real 0029-contracted migration posture. Alphabetical file order places
// it after every pre-overshoot raw-DDL sibling and before
// overshoot_int_test.go, so it trips both regressions this package must
// never relive: a fixture teardown or destructive drop leaking out of its
// isolated schema onto public (missing tables — the overshoot 42P01s), or an
// interim-shape restore that reinstalls the obsolete global usage index
// contracted away by 0029. Overshoot measures production migrations and
// keeps running directly on this public schema.
func TestMigratedCreditsPostureIntact(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)

	mp29PublicTablesPresent(ctx, t, pool)

	// Qualified pg_catalog reads: no search_path dependence. 0028 expand
	// shipped (domain-split arbiters live) and 0029 contract held (the
	// superseded global usage index is not restored).
	have := mp29UsageIndexSet(ctx, t, pool)
	for _, want := range []string{"uniq_credit_transactions_usage_legacy", "uniq_credit_transactions_invocation"} {
		if !have[want] {
			t.Fatalf("0028 index %s missing on public.credit_transactions: the contracted migration posture drifted", want)
		}
	}
	if have["uniq_credit_transactions_usage_request_id"] {
		t.Fatal("obsolete global index uniq_credit_transactions_usage_request_id is restored on public.credit_transactions: 0029 contracted it away and the illustrative interim posture must stay inside isolated fixture schemas")
	}

	if !mp29InvocationColumnPresent(ctx, t, pool) {
		t.Fatal("credit_transactions.invocation_id missing on public: the 0028 expand posture drifted")
	}

	if mp29ChargeKeyConstraintPresent(ctx, t, pool) {
		t.Fatal("superseded settlement_jobs_charge_key constraint is back on public.settlement_jobs: 0029 contracted it away")
	}
}

// mp29PublicTablesPresent fails the test when either contracted credits
// table is missing from public — the signature of raw-DDL fixture work
// leaking out of its isolated schema (the 9d6d29b TestOvershoot_* 42P01
// poisoning).
func mp29PublicTablesPresent(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for _, table := range []string{"org_credits", "credit_transactions"} {
		var present bool
		if err := pool.QueryRow(ctx,
			`SELECT to_regclass('public.`+table+`') IS NOT NULL`).Scan(&present); err != nil {
			t.Fatalf("check public.%s: %v", table, err)
		}
		if !present {
			t.Fatalf("public.%s is missing from the migrated stand: raw-DDL fixture work leaked out of its isolated schema (the 9d6d29b TestOvershoot_* 42P01 poisoning)", table)
		}
	}
}

// mp29UsageIndexSet reads every index name on public.credit_transactions
// straight from pg_index (no search_path dependence).
func mp29UsageIndexSet(ctx context.Context, t *testing.T, pool *pgxpool.Pool) map[string]bool {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT i.relname
		FROM pg_index x
		JOIN pg_class i ON i.oid = x.indexrelid
		JOIN pg_class tbl ON tbl.oid = x.indrelid
		JOIN pg_namespace n ON n.oid = tbl.relnamespace
		WHERE n.nspname = 'public' AND tbl.relname = 'credit_transactions'`)
	if err != nil {
		t.Fatalf("read public.credit_transactions indexes: %v", err)
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan index name: %v", err)
		}
		have[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate index names: %v", err)
	}
	return have
}

// mp29InvocationColumnPresent reports whether credit_transactions carries
// the 0028 invocation_id column on public.
func mp29InvocationColumnPresent(ctx context.Context, t *testing.T, pool *pgxpool.Pool) bool {
	t.Helper()
	var hasInvocationCol bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public'
			  AND table_name = 'credit_transactions'
			  AND column_name = 'invocation_id')`).Scan(&hasInvocationCol); err != nil {
		t.Fatalf("check credit_transactions.invocation_id: %v", err)
	}
	return hasInvocationCol
}

// mp29ChargeKeyConstraintPresent reports whether the superseded
// settlement_jobs_charge_key constraint exists on public.settlement_jobs.
func mp29ChargeKeyConstraintPresent(ctx context.Context, t *testing.T, pool *pgxpool.Pool) bool {
	t.Helper()
	var hasChargeKey bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_constraint c
			JOIN pg_class tbl ON tbl.oid = c.conrelid
			JOIN pg_namespace n ON n.oid = tbl.relnamespace
			WHERE n.nspname = 'public'
			  AND tbl.relname = 'settlement_jobs'
			  AND c.conname = 'settlement_jobs_charge_key')`).Scan(&hasChargeKey); err != nil {
		t.Fatalf("check public.settlement_jobs constraints: %v", err)
	}
	return hasChargeKey
}
