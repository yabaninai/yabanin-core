package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/reireirei/yabanin/pkg/metrics"
)

// rollupLockID is the advisory transaction lock for rollup refreshes.
// It is distinct from the cache purge lock.
const rollupLockID int64 = 18018

var (
	rollupRecentEvery = 5 * time.Minute
	rollupClockEvery  = time.Minute
)

// rollupTx is the slice of a transaction the refresher uses.
type rollupTx interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// RollupDB opens the refresh transaction. *pgxpool.Pool is adapted by NewRollupDB.
type RollupDB interface {
	Begin(ctx context.Context) (rollupTx, error)
}

type poolBeginner struct {
	pool *pgxpool.Pool
}

// NewRollupDB adapts a pool. Begin's concrete pgx.Tx satisfies rollupTx.
func NewRollupDB(pool *pgxpool.Pool) RollupDB {
	return poolBeginner{pool: pool}
}

func (p poolBeginner) Begin(ctx context.Context) (rollupTx, error) {
	return p.pool.Begin(ctx)
}

// RollupRefresher rewrites an hour window of analytics and label rollups.
type RollupRefresher struct {
	DB     RollupDB
	Now    func() time.Time
	Log    *slog.Logger
	Region string // optional; tests set it when the pool has no RLS hook
}

const rollupStatusClass = `CASE WHEN rl.status_code < 300 THEN '2xx' WHEN rl.status_code < 400 THEN '3xx' WHEN rl.status_code = 429 THEN '429' WHEN rl.status_code < 500 THEN '4xx' ELSE '5xx' END`

const rollupAgg = `COUNT(*),
       COALESCE(SUM(rl.tokens_in), 0),
       COALESCE(SUM(rl.tokens_out), 0),
       COALESCE(SUM(COALESCE(rl.cache_read_tokens, 0)), 0),
       COALESCE(SUM(rl.cost_in_usd) FILTER (WHERE rl.cost_status IN ('priced', 'cache_hit', 'legacy')), 0),
       COUNT(*) FILTER (WHERE rl.cost_status IN ('unknown_price', 'no_usage')),
       COUNT(*) FILTER (WHERE rl.cost_status = 'legacy'),
       COUNT(*) FILTER (WHERE rl.status_code >= 400),
       COUNT(*) FILTER (WHERE COALESCE(rl.retry_count, 0) > 0),
       COUNT(*) FILTER (WHERE COALESCE(rl.attempt_count, 1) > 1),
       COUNT(*) FILTER (WHERE rl.cache_hit_type IN ('exact', 'semantic'))`

const rollupInsertHourly = `INSERT INTO analytics_rollup_hourly (
    home_region, org_id, hour, model_used, endpoint, team_id, agent_id, status_class, cache_type,
    requests, tokens_in, tokens_out, cache_read_tokens, cost_usd, unpriced_requests, legacy_rows,
    errors, retried_requests, fallback_requests, cache_hits)
SELECT current_setting('app.region', true),
       rl.org_id,
       date_trunc('hour', rl.created_at),
       COALESCE(rl.model_used, ''),
       COALESCE(rl.endpoint, ''),
       COALESCE(rl.team_id, '00000000-0000-0000-0000-000000000000'::uuid),
       COALESCE(rl.agent_id, '00000000-0000-0000-0000-000000000000'::uuid),
       ` + rollupStatusClass + `,
       COALESCE(NULLIF(rl.cache_hit_type, ''), 'miss'),
       ` + rollupAgg + `
FROM request_logs rl
WHERE rl.home_region = current_setting('app.region', true)
  AND rl.created_at >= $1 AND rl.created_at < $2
  AND rl.org_id IS NOT NULL
  AND COALESCE(rl.ab_group, '') <> 'shadow'
GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9`

const rollupInsertLabelsPolicy = `INSERT INTO label_rollup_hourly (
    home_region, org_id, hour, key, value,
    requests, tokens_in, tokens_out, cache_read_tokens, cost_usd, unpriced_requests, legacy_rows,
    errors, retried_requests, fallback_requests, cache_hits)
SELECT current_setting('app.region', true),
       rl.org_id,
       date_trunc('hour', rl.created_at),
       kv.key,
       kv.value,
       ` + rollupAgg + `
FROM request_logs rl
CROSS JOIN LATERAL jsonb_each_text(rl.labels) kv
WHERE rl.home_region = current_setting('app.region', true)
  AND rl.created_at >= $1 AND rl.created_at < $2
  AND rl.org_id IS NOT NULL
  AND COALESCE(rl.ab_group, '') <> 'shadow'
  AND kv.key = ANY(ARRAY(SELECT jsonb_array_elements_text(COALESCE((SELECT lp.policy->'rollup_keys' FROM label_policies lp WHERE lp.org_id = rl.org_id), $3::jsonb))))
GROUP BY 1, 2, 3, 4, 5`

const rollupInsertLabelsDefault = `INSERT INTO label_rollup_hourly (
    home_region, org_id, hour, key, value,
    requests, tokens_in, tokens_out, cache_read_tokens, cost_usd, unpriced_requests, legacy_rows,
    errors, retried_requests, fallback_requests, cache_hits)
SELECT current_setting('app.region', true),
       rl.org_id,
       date_trunc('hour', rl.created_at),
       kv.key,
       kv.value,
       ` + rollupAgg + `
FROM request_logs rl
CROSS JOIN LATERAL jsonb_each_text(rl.labels) kv
WHERE rl.home_region = current_setting('app.region', true)
  AND rl.created_at >= $1 AND rl.created_at < $2
  AND rl.org_id IS NOT NULL
  AND COALESCE(rl.ab_group, '') <> 'shadow'
  AND kv.key = ANY(ARRAY(SELECT jsonb_array_elements_text($3::jsonb)))
GROUP BY 1, 2, 3, 4, 5`

// RefreshWindow rewrites [from, to) for the current region. skipped is true
// when another replica holds the advisory lock.
func (r *RollupRefresher) RefreshWindow(ctx context.Context, from, to time.Time) (skipped bool, err error) {
	started := time.Now()
	defer func() {
		metrics.RollupRefreshSeconds.Observe(time.Since(started).Seconds())
		if err != nil {
			metrics.RollupRefreshErrorsTotal.Inc()
		}
	}()
	if r == nil || r.DB == nil {
		return false, fmt.Errorf("rollup refresher has no database")
	}
	tx, err := r.DB.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("rollup begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if r.Region != "" {
		if _, err = tx.Exec(ctx, "SELECT set_config('app.region', $1, true)", r.Region); err != nil {
			return false, fmt.Errorf("rollup region: %w", err)
		}
	}

	var got bool
	if err = tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock($1)", rollupLockID).Scan(&got); err != nil {
		return false, fmt.Errorf("rollup lock: %w", err)
	}
	if !got {
		return true, nil
	}
	if _, err = tx.Exec(ctx, `DELETE FROM analytics_rollup_hourly WHERE home_region = current_setting('app.region', true) AND hour >= $1 AND hour < $2`, from, to); err != nil {
		return false, fmt.Errorf("rollup delete hourly: %w", err)
	}
	if _, err = tx.Exec(ctx, `DELETE FROM label_rollup_hourly WHERE home_region = current_setting('app.region', true) AND hour >= $1 AND hour < $2`, from, to); err != nil {
		return false, fmt.Errorf("rollup delete labels: %w", err)
	}
	if _, err = tx.Exec(ctx, rollupInsertHourly, from, to); err != nil {
		return false, fmt.Errorf("rollup insert hourly: %w", err)
	}
	keys, err := json.Marshal(labels.DefaultPolicy().RollupKeys)
	if err != nil {
		return false, err
	}
	var hasPolicies bool
	if err = tx.QueryRow(ctx, "SELECT to_regclass('public.label_policies') IS NOT NULL").Scan(&hasPolicies); err != nil {
		return false, fmt.Errorf("rollup policies: %w", err)
	}
	labelSQL := rollupInsertLabelsDefault
	if hasPolicies {
		labelSQL = rollupInsertLabelsPolicy
	}
	if _, err = tx.Exec(ctx, labelSQL, from, to, keys); err != nil {
		return false, fmt.Errorf("rollup insert labels: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("rollup commit: %w", err)
	}
	return false, nil
}

// Backfill rewrites [from, to) in one-day chunks.
func (r *RollupRefresher) Backfill(ctx context.Context, from, to time.Time) error {
	for _, chunk := range rollupDayChunks(from, to) {
		if _, err := r.RefreshWindow(ctx, chunk[0], chunk[1]); err != nil {
			return err
		}
	}
	return nil
}

func rollupDayChunks(from, to time.Time) [][2]time.Time {
	var out [][2]time.Time
	for cur := from; cur.Before(to); {
		next := cur.Add(24 * time.Hour)
		if next.After(to) {
			next = to
		}
		out = append(out, [2]time.Time{cur, next})
		cur = next
	}
	return out
}

// RunRollupSchedule refreshes the recent window every 5 minutes and the last
// 7 days at 03:17 UTC. leader reports whether this replica should write;
// a nil leader means the process is the only replica. YABANIN_ROLLUPS=0
// disables the loop. YABANIN_ROLLUP_BACKFILL=from,to (RFC3339) runs once.
func RunRollupSchedule(ctx context.Context, r *RollupRefresher, leader func() bool) {
	rollups := config.RollupFromEnv()
	if rollups.Disabled || r == nil {
		return
	}
	if leader == nil {
		leader = func() bool { return true }
	}
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	if spec := rollups.Backfill; spec != "" && leader() {
		from, to, err := parseRollupBackfill(spec)
		if err != nil && r.Log != nil {
			r.Log.Warn("rollup backfill ignored", "error", err)
		} else if err == nil {
			if err := r.Backfill(ctx, from, to); err != nil && r.Log != nil {
				r.Log.Warn("rollup backfill failed", "error", err)
			}
		}
	}
	recent := time.NewTicker(rollupRecentEvery)
	clock := time.NewTicker(rollupClockEvery)
	defer recent.Stop()
	defer clock.Stop()
	var lastNight string
	refreshRecent := func() {
		if !leader() {
			return
		}
		at := now().UTC()
		if _, err := r.RefreshWindow(ctx, at.Add(-3*time.Hour), at.Add(time.Hour)); err != nil && r.Log != nil {
			r.Log.Warn("rollup refresh failed", "error", err)
		}
	}
	refreshRecent()
	for {
		select {
		case <-ctx.Done():
			return
		case <-recent.C:
			refreshRecent()
		case <-clock.C:
			at := now().UTC()
			day := at.Format("2006-01-02")
			if at.Hour() == 3 && at.Minute() == 17 && lastNight != day && leader() {
				lastNight = day
				if err := r.Backfill(ctx, at.Add(-7*24*time.Hour), at); err != nil && r.Log != nil {
					r.Log.Warn("rollup nightly failed", "error", err)
				}
			}
		}
	}
}

func parseRollupBackfill(spec string) (time.Time, time.Time, error) {
	parts := strings.Split(spec, ",")
	if len(parts) != 2 {
		return time.Time{}, time.Time{}, fmt.Errorf("YABANIN_ROLLUP_BACKFILL must be from,to")
	}
	from, err := time.Parse(time.RFC3339, strings.TrimSpace(parts[0]))
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	to, err := time.Parse(time.RFC3339, strings.TrimSpace(parts[1]))
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !from.Before(to) {
		return time.Time{}, time.Time{}, fmt.Errorf("backfill from must be before to")
	}
	return from, to, nil
}
