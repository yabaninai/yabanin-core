//go:build af14perf

package adminstore

// AF-14 measurement stand: a reproducible savings/cost SQL benchmark on a real
// disposable Postgres (testcontainers) — baseline and after must run the same
// dataset, toolchain and methodology. Not part of any normal gate: build with
// -tags af14perf. Raw evidence goes to artifacts/agent-lanes/af14/ (env
// AF14_OUT overrides; AF14_PHASE labels the run, default "run").

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// Fixed org ids: deterministic dataset across baseline/after runs.
var af14Orgs = []string{
	"11111111-1111-4111-8111-111111111101",
	"22222222-2222-4222-8222-222222222202",
	"33333333-3333-4333-8333-333333333303",
	"44444444-4444-4444-8444-444444444404",
}

const (
	af14OrgA = 0 // 50% of rows
	af14OrgB = 1 // 20%
	af14OrgC = 2 // 20%
	af14OrgD = 3 // 10%
)

// recordingDB wraps a pool, implements pgxdb, and records every SQL with its
// args so the exact production queries can be replayed under EXPLAIN.
type recordingDB struct {
	pool    *pgxpool.Pool
	rec     bool
	capture []capturedQuery
}

type capturedQuery struct {
	kind string // "queryrow" | "query"
	sql  string
	args []interface{}
}

func (r *recordingDB) record(kind, sql string, args []interface{}) {
	if !r.rec {
		return
	}
	r.capture = append(r.capture, capturedQuery{kind: kind, sql: sql, args: args})
}

func (r *recordingDB) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	r.record("query", sql, args)
	return r.pool.Query(ctx, sql, args...)
}

func (r *recordingDB) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	r.record("queryrow", sql, args)
	return r.pool.QueryRow(ctx, sql, args...)
}

func (r *recordingDB) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	return r.pool.Exec(ctx, sql, args...)
}

func (r *recordingDB) BeginAuditTx(ctx context.Context) (auditTx, error) {
	return r.pool.Begin(ctx)
}

var af14Placeholder = regexp.MustCompile(`\$\d+`)

// af14RenderLiteral renders args as untyped SQL string literals so the
// replayed EXPLAIN text matches the parameterized plan (PostgreSQL coerces
// the literal from the column type in every predicate used here).
func af14RenderLiteral(v interface{}) string {
	switch t := v.(type) {
	case time.Time:
		return "'" + t.UTC().Format("2006-01-02 15:04:05.999999+00") + "'"
	case string:
		return "'" + strings.ReplaceAll(t, "'", "''") + "'"
	case int:
		return strconv.Itoa(t)
	default:
		return "'" + strings.ReplaceAll(fmt.Sprint(t), "'", "''") + "'"
	}
}

func af14Inline(sql string, args []interface{}) string {
	i := 0
	return af14Placeholder.ReplaceAllStringFunc(sql, func(p string) string {
		if i < len(args) {
			lit := af14RenderLiteral(args[i])
			i++
			return lit
		}
		return p
	})
}

func af14Seed(tb *testing.T, pool *pgxpool.Pool) int {
	tb.Helper()
	ctx := context.Background()

	models := []struct{ name, provider string }{
		{"alpha-fast", "openai"},
		{"alpha-big", "openai"},
		{"beta-mini", "anthropic"},
		{"beta-max", "anthropic"},
		{"gamma-legacy", "openai-compat"},
		// mystery-model deliberately absent from registry+pricing → unpriced.
	}
	for i, org := range af14Orgs {
		_, err := pool.Exec(ctx, `
			INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)
			ON CONFLICT (id) DO NOTHING`,
			org, fmt.Sprintf("AF14 Org %d", i+1), fmt.Sprintf("af14-org-%d", i+1))
		requireNoErr(tb, err)
	}
	for _, m := range models {
		_, err := pool.Exec(ctx, `DELETE FROM models_registry WHERE model_name = $1`, m.name)
		requireNoErr(tb, err)
		_, err = pool.Exec(ctx, `DELETE FROM models_pricing WHERE model = $1`, m.name)
		requireNoErr(tb, err)
		_, err = pool.Exec(ctx,
			`INSERT INTO models_registry (model_name, display_name, provider) VALUES ($1, $1, $2)`,
			m.name, m.provider)
		requireNoErr(tb, err)
		_, err = pool.Exec(ctx,
			`INSERT INTO models_pricing (provider, model, input_per_m, output_per_m) VALUES ($1, $2, 1.5, 3.0)`,
			m.provider, m.name)
		requireNoErr(tb, err)
	}
	for _, org := range af14Orgs {
		_, err := pool.Exec(ctx, `DELETE FROM request_logs WHERE org_id = $1`, org)
		requireNoErr(tb, err)
	}

	// 60k deterministic rows over 90 days (gcd(7,90)=1 → every day bucket is
	// hit): 5% shadow, 33% cache hits, 25% routed, ~4% unpriced (g%25==24).
	const rows = 60000
	insert := `
		INSERT INTO request_logs (
			org_id, model_requested, model_used, status_code, duration_ms,
			tokens_in, tokens_out, method, created_at, updated_at,
			cost_in_usd, counterfactual_cost_usd,
			cache_hit_type, tier_used, classifier_class, classifier_confidence,
			ab_group, home_region
		)
		SELECT
			(CASE
				WHEN g % 10 < 5 THEN $1::uuid
				WHEN g % 10 < 7 THEN $2::uuid
				WHEN g % 10 < 9 THEN $3::uuid
				ELSE $4::uuid
			END),
			(CASE g % 25
				WHEN 24 THEN 'mystery-model'
				WHEN 23 THEN 'gamma-legacy'
				WHEN 22 THEN 'beta-max'
				WHEN 21 THEN 'beta-mini'
				WHEN 20 THEN 'beta-mini'
				ELSE (CASE WHEN g % 2 = 0 THEN 'alpha-fast' ELSE 'alpha-big' END)
			END),
			(CASE g % 25
				WHEN 24 THEN 'mystery-model'
				WHEN 23 THEN 'gamma-legacy'
				WHEN 22 THEN 'beta-max'
				WHEN 21 THEN 'beta-mini'
				WHEN 20 THEN 'beta-mini'
				ELSE (CASE WHEN g % 2 = 0 THEN 'alpha-fast' ELSE 'alpha-big' END)
			END),
			200,
			100 + (g % 400),
			10 + (g % 100),
			20 + (g % 200),
			'POST',
			now() - ((g * 7) % 90) * interval '1 day' - ((g * 13) % 86400) * interval '1 second',
			now(),
			(((g % 997) + 1))::numeric / 100000,
			(((g % 997) + 1) * 3 + (g % 7))::numeric / 100000,
			CASE WHEN g % 3 = 0 THEN 'exact' END,
			CASE WHEN g % 4 = 0 THEN 'smart' END,
			CASE WHEN g % 4 = 0 THEN 'code' END,
			(g % 100)::real / 100,
			CASE WHEN g % 20 = 0 THEN 'shadow' END,
			'sg'
		FROM generate_series(1, $5) AS g`
	_, err := pool.Exec(ctx, insert,
		af14Orgs[af14OrgA], af14Orgs[af14OrgB], af14Orgs[af14OrgC], af14Orgs[af14OrgD], rows)
	requireNoErr(tb, err)

	var total int
	requireNoErr(tb, pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM request_logs WHERE org_id = $1`, af14Orgs[af14OrgA]).Scan(&total))
	return total
}

func requireNoErr(tb *testing.T, err error) {
	tb.Helper()
	if err != nil {
		tb.Fatalf("unexpected error: %v", err)
	}
}

type af14Sample struct {
	wallNs      int64
	poolAcqNs   int64
	emptyWaitNs int64
	queries     int
}

func af14Stats(xs []af14Sample) (min, mean, p50, p95, max time.Duration) {
	if len(xs) == 0 {
		return
	}
	sorted := append([]af14Sample(nil), xs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].wallNs < sorted[j].wallNs })
	pick := func(p float64) time.Duration {
		idx := int(p * float64(len(sorted)-1))
		return time.Duration(sorted[idx].wallNs)
	}
	var sum int64
	for _, x := range xs {
		sum += x.wallNs
	}
	return time.Duration(sorted[0].wallNs),
		time.Duration(sum / int64(len(xs))),
		pick(0.50), pick(0.95), time.Duration(sorted[len(sorted)-1].wallNs)
}

func TestAF14SavingsSQLStand(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()

	orgRows := af14Seed(t, pool)
	orgID := af14Orgs[af14OrgA]
	outDir := os.Getenv("AF14_OUT")
	if outDir == "" {
		outDir = filepath.Join("..", "..", "artifacts", "agent-lanes", "af14")
	}
	phase := os.Getenv("AF14_PHASE")
	if phase == "" {
		phase = "run"
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	scenPath := filepath.Join(outDir, phase+"_scenarios.txt")
	sumPath := filepath.Join(outDir, phase+"_summary.txt")
	scenF, err := os.Create(scenPath)
	if err != nil {
		t.Fatal(err)
	}
	defer scenF.Close()
	sumF, err := os.Create(sumPath)
	if err != nil {
		t.Fatal(err)
	}
	defer sumF.Close()

	fmt.Fprintf(scenF, "phase=%s org_rows=%d date=%s\n\n", phase, orgRows, time.Now().UTC().Format(time.RFC3339))

	type scenario struct {
		name     string
		org      string
		days     int
		provider string
	}
	scenarios := []scenario{
		{"org7d", orgID, 7, ""},
		{"org30d", orgID, 30, ""},
		{"org90d", orgID, 90, ""},
		{"global90d", "", 90, ""},
		{"orgProvider90d", orgID, 90, "openai"},
	}

	rec := &recordingDB{pool: pool}
	store := New(nil, slog.Default(), nil)
	store.db = rec

	for _, sc := range scenarios {
		// 1) capture the exact SQL the store sends
		rec.rec = true
		rec.capture = nil
		if sc.org == "" {
			// global savings path (org "")
			if _, err := store.GetSavingsReport(ctx, "", sc.days, sc.provider); err != nil {
				t.Fatalf("%s: %v", sc.name, err)
			}
		} else if _, err := store.GetSavingsReport(ctx, sc.org, sc.days, sc.provider); err != nil {
			t.Fatalf("%s: %v", sc.name, err)
		}
		captured := append([]capturedQuery{}, rec.capture...)
		rec.rec = false

		fmt.Fprintf(scenF, "=== scenario %s (org=%q days=%d provider=%q) — %d queries per report ===\n",
			sc.name, sc.org, sc.days, sc.provider, len(captured))
		for i, q := range captured {
			fmt.Fprintf(scenF, "--- query %d [%s] args=%d\n%s\n", i+1, q.kind, len(q.args), q.sql)
			explainSQL := "EXPLAIN (ANALYZE, BUFFERS, TIMING OFF) " + af14Inline(q.sql, q.args)
			rows, err := pool.Query(ctx, explainSQL)
			if err != nil {
				fmt.Fprintf(scenF, "EXPLAIN ERROR: %v\n", err)
				continue
			}
			for rows.Next() {
				var line string
				if err := rows.Scan(&line); err != nil {
					break
				}
				fmt.Fprintln(scenF, line)
			}
			rows.Close()
			fmt.Fprintln(scenF)
		}

		// 2) latency + pool wait: 5 warmup + 30 measured, recorder off
		const warmup, iters = 5, 30
		for i := 0; i < warmup; i++ {
			if _, err := store.GetSavingsReport(ctx, sc.org, sc.days, sc.provider); err != nil {
				t.Fatalf("%s warmup: %v", sc.name, err)
			}
		}
		samples := make([]af14Sample, 0, iters)
		for i := 0; i < iters; i++ {
			acq0 := pool.Stat().AcquireDuration()
			empty0 := pool.Stat().EmptyAcquireWaitTime()
			start := time.Now()
			if _, err := store.GetSavingsReport(ctx, sc.org, sc.days, sc.provider); err != nil {
				t.Fatalf("%s iter %d: %v", sc.name, i, err)
			}
			wall := time.Since(start)
			samples = append(samples, af14Sample{
				wallNs:      int64(wall),
				poolAcqNs:   int64(pool.Stat().AcquireDuration() - acq0),
				emptyWaitNs: int64(pool.Stat().EmptyAcquireWaitTime() - empty0),
				queries:     len(captured),
			})
		}
		min, mean, p50, p95, max := af14Stats(samples)
		var acqSum, emptySum int64
		var qCount int
		for _, x := range samples {
			acqSum += x.poolAcqNs
			emptySum += x.emptyWaitNs
			qCount += x.queries
		}
		fmt.Fprintf(sumF, "%-16s queries/call=%d wall min=%v mean=%v p50=%v p95=%v max=%v poolAcquire mean=%v emptyWait mean=%v\n",
			sc.name, len(captured), min, mean, p50, p95, max,
			time.Duration(acqSum/int64(len(samples))), time.Duration(emptySum/int64(len(samples))))
	}

	// 3) concurrency phase: 8 workers × 15 reports on org30d — pool wait
	// becomes observable under contention; identical methodology both phases.
	{
		const workers, calls = 8, 15
		acq0 := pool.Stat().AcquireDuration()
		empty0 := pool.Stat().EmptyAcquireWaitTime()
		start := time.Now()
		done := make(chan error, workers)
		for w := 0; w < workers; w++ {
			go func() {
				var last error
				for i := 0; i < calls; i++ {
					if _, err := store.GetSavingsReport(ctx, orgID, 30, ""); err != nil {
						last = err
					}
				}
				done <- last
			}()
		}
		for w := 0; w < workers; w++ {
			if err := <-done; err != nil {
				t.Fatalf("concurrent: %v", err)
			}
		}
		wall := time.Since(start)
		fmt.Fprintf(sumF, "%-16s workers=%d calls/worker=%d wall_total=%v wall_mean=%v poolAcquire total=%v emptyWait total=%v\n",
			"org30d_conc", workers, calls, wall, wall/(workers*calls),
			pool.Stat().AcquireDuration()-acq0, pool.Stat().EmptyAcquireWaitTime()-empty0)
	}

	t.Logf("AF-14 stand phase=%s done: evidence in %s and %s", phase, scenPath, sumPath)
}
