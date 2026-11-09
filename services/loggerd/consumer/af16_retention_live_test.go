package consumer

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AF-16 live acceptance (disposable PG, same stand contract as AF-06): the
// settled-jobs retention removes terminal 'settled' rows past the window in
// bounded batches — and never touches durable debt (requires_attention) or
// live work (retry awaiting its backoff), no matter how old.

const af16RetentionOrg = "af16cccc-0000-4000-8000-0000000000f6"

func seedAF16Jobs(ctx context.Context, t *testing.T, pool SettlementDB, prefix, status string, count int, updatedAt string) {
	t.Helper()
	for i := 0; i < count; i++ {
		_, err := pool.Exec(ctx, fmt.Sprintf(`
			INSERT INTO settlement_jobs
				(org_id, request_id, charge_kind, amount_cents, amount_micro_usd, status, payload, updated_at)
			VALUES ($1, $2, $3, 0, 0, $4, '{}', now() - %s)`, updatedAt),
			af16RetentionOrg, fmt.Sprintf("%s-%d", prefix, i), ChargeKindResaleDeduction, status)
		require.NoError(t, err, "seed settlement_jobs retention fixture")
	}
}

func countAF16Jobs(ctx context.Context, t *testing.T, pool SettlementDB, prefix string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM settlement_jobs WHERE request_id LIKE $1`, prefix+"%").Scan(&n))
	return n
}

// 25 old settled + 5 fresh settled + 1 requires_attention (all past any
// realistic window) → pass 1 removes exactly BatchSize×Passes (20) old
// settled rows, pass 2 the remaining 5; fresh settled rows and the durable
// debt survive both passes.
func TestSettlementLive_SettledJobsRetentionBounded(t *testing.T) {
	ctx, pool := newSettlementLiveEnv(t)

	seedAF16Jobs(ctx, t, pool, "req-af16-old", "settled", 25, "interval '120 days'")
	seedAF16Jobs(ctx, t, pool, "req-af16-fresh", "settled", 5, "interval '0 seconds'")
	seedAF16Jobs(ctx, t, pool, "req-af16-debt", "requires_attention", 1, "interval '120 days'")
	// Live work awaiting its retry backoff is never retention-eligible.
	_, err := pool.Exec(ctx, `
		INSERT INTO settlement_jobs
			(org_id, request_id, charge_kind, amount_cents, amount_micro_usd, status, payload,
			 updated_at, next_attempt_at)
		VALUES ($1, 'req-af16-retry', $2, 0, 0, 'retry', '{}', now() - interval '120 days', now() + interval '1 hour')`,
		af16RetentionOrg, ChargeKindResaleDeduction)
	require.NoError(t, err)

	w := NewSettlementWorker(pool, nil, nil, silentLogger()).WithConfig(SettlementConfig{
		Interval:             time.Hour,
		SettledCleanupEvery:  time.Nanosecond, // always due
		SettledCleanupBatch:  10,
		SettledCleanupPasses: 2, // bounded: at most 20 settled rows per run
		SettledRetention:     90 * 24 * time.Hour,
	})

	w.tick(ctx)

	assert.Equal(t, int64(5), countAF16Jobs(ctx, t, pool, "req-af16-old"),
		"pass 1 is bounded to BatchSize×Passes old settled rows")
	assert.Equal(t, int64(5), countAF16Jobs(ctx, t, pool, "req-af16-fresh"),
		"fresh settled rows survive the retention cutoff")
	assert.Equal(t, int64(1), countAF16Jobs(ctx, t, pool, "req-af16-debt"),
		"requires_attention is durable debt — never removed by retention")
	assert.Equal(t, int64(1), countAF16Jobs(ctx, t, pool, "req-af16-retry"),
		"retry is live work — never removed by retention")

	w.tick(ctx) // next bounded pass removes the rest of the expired settled rows

	assert.Zero(t, countAF16Jobs(ctx, t, pool, "req-af16-old"),
		"the second bounded pass finishes the expired settled rows")
	assert.Equal(t, int64(5), countAF16Jobs(ctx, t, pool, "req-af16-fresh"))
	assert.Equal(t, int64(1), countAF16Jobs(ctx, t, pool, "req-af16-debt"))
	assert.Equal(t, int64(1), countAF16Jobs(ctx, t, pool, "req-af16-retry"))
}
