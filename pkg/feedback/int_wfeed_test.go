package feedback

// W-FEED integration coverage (testcontainers, real migrated Postgres):
// the owner listing/filter correctness on fixtures and the beta metrics SQL
// views returning exact numbers. The stand is disposable and shared per test
// binary (pkg/testdb); fixtures clean up after themselves.

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/testdb"
)

type viewsFixture struct {
	Token                  string
	OrgA, OrgB             string
	ModelG                 string // global registry model (anthropic)
	ModelBYOK              string // org A's custom model (zai-coding)
	ModelUnreg             string // absent from every registry → '(unknown)'
	Day1, Day2             time.Time
	OnboardedA, OnboardedB time.Time
	FirstA, FirstB         time.Time
}

// seedViewsFixturePG seeds two orgs, a global and a BYOK model, and a fixed
// request_logs / classifier_feedback mix with known-day timestamps so every
// view number below is hand-computable:
//
//	org A (onboarded Oct 1 10:00), day1 (Oct 3):
//	  r1 user u1  model-g     200 100ms  cache NULL
//	  r2 user u1  model-g     200 200ms  cache NULL
//	  r3 user u2  model-g     200 300ms  cache NULL
//	  r4 key  k1  model-byok  500  50ms  cache exact   (BYOK error row)
//	  r5 —        model-unreg 200  10ms  cache NULL    (unknown provider)
//	org B (onboarded Oct 2 09:00), day2 (Oct 4):
//	  r6 user u3  model-g     200 500ms  cache semantic
//
// Feedback rows are recorded by the caller through the collector.
func seedViewsFixturePG(t *testing.T, pool *pgxpool.Pool) *viewsFixture {
	t.Helper()
	ctx := context.Background()
	token := fmt.Sprintf("wfeed%x", time.Now().UnixNano())
	fx := &viewsFixture{
		Token:      token,
		ModelG:     token + "-model-g",
		ModelBYOK:  token + "-model-byok",
		ModelUnreg: token + "-model-unreg",
		Day1:       time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC),
		Day2:       time.Date(2026, 10, 4, 8, 0, 0, 0, time.UTC),
		OnboardedA: time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC),
		OnboardedB: time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC),
		FirstA:     time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC),
		FirstB:     time.Date(2026, 10, 4, 8, 0, 0, 0, time.UTC),
	}

	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		token+"-org-a", token+"-org-a").Scan(&fx.OrgA))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		token+"-org-b", token+"-org-b").Scan(&fx.OrgB))
	// Pin onboarding times: created_at defaults to now(); the TTFQ view must
	// compute against the seeded value.
	require.NoError(t, execWFeed(t, pool,
		`UPDATE organizations SET created_at = $2, updated_at = $2 WHERE id = $1::uuid`, fx.OrgA, fx.OnboardedA))
	require.NoError(t, execWFeed(t, pool,
		`UPDATE organizations SET created_at = $2, updated_at = $2 WHERE id = $1::uuid`, fx.OrgB, fx.OnboardedB))

	require.NoError(t, execWFeed(t, pool, `
		INSERT INTO models_registry (model_name, display_name, tier, provider, failover_models, tier_pool)
		VALUES ($1, $1, 'smart', 'anthropic', '{}'::text[], '{}'::text[])`, fx.ModelG))
	require.NoError(t, execWFeed(t, pool, `
		INSERT INTO org_custom_models (org_id, model_name, display_name, tier, provider)
		VALUES ($1::uuid, $2, $2, 'smart', 'zai-coding')`, fx.OrgA, fx.ModelBYOK))

	type logRow struct {
		org       string
		model     string
		userID    string // raw uuid text or ""
		apiKeyID  string
		status    int
		duration  int
		cacheType string
		errText   string
		at        time.Time
	}
	rows := []logRow{
		{fx.OrgA, fx.ModelG, "11111111-1111-1111-1111-111111111111", "", 200, 100, "", "", fx.Day1},
		{fx.OrgA, fx.ModelG, "11111111-1111-1111-1111-111111111111", "", 200, 200, "", "", fx.Day1.Add(time.Second)},
		{fx.OrgA, fx.ModelG, "22222222-2222-2222-2222-222222222222", "", 200, 300, "", "", fx.Day1.Add(2 * time.Second)},
		{fx.OrgA, fx.ModelBYOK, "", "33333333-3333-3333-3333-333333333333", 500, 50, "exact", "boom", fx.Day1.Add(3 * time.Second)},
		{fx.OrgA, fx.ModelUnreg, "", "", 200, 10, "", "", fx.Day1.Add(4 * time.Second)},
		{fx.OrgB, fx.ModelG, "44444444-4444-4444-4444-444444444444", "", 200, 500, "semantic", "", fx.Day2},
	}
	for i, r := range rows {
		require.NoError(t, execWFeed(t, pool, `
			INSERT INTO request_logs (org_id, model_requested, model_used, status_code, duration_ms,
				tokens_in, tokens_out, error, created_at, home_region, user_id, api_key_id, cache_hit_type)
			VALUES ($1::uuid, $2, $2, $3, $4, 10, 5, NULLIF($5, ''), $6, 'GLOBAL',
				NULLIF($7, '')::uuid, NULLIF($8, '')::uuid, NULLIF($9, ''))`,
			r.org, r.model, r.status, r.duration, r.errText, r.at, r.userID, r.apiKeyID, r.cacheType),
			"seed request_logs row %d", i)
	}

	t.Cleanup(func() {
		orgs := []string{fx.OrgA, fx.OrgB}
		cleanupWFeed(t, pool, `DELETE FROM classifier_feedback WHERE org_id::text = ANY($1)`, orgs)
		cleanupWFeed(t, pool, `DELETE FROM request_logs WHERE org_id::text = ANY($1)`, orgs)
		cleanupWFeed(t, pool, `DELETE FROM org_custom_models WHERE org_id::text = ANY($1)`, orgs)
		cleanupWFeed(t, pool, `DELETE FROM models_registry WHERE model_name LIKE $1`, token+"%")
		cleanupWFeed(t, pool, `DELETE FROM organizations WHERE id::text = ANY($1)`, orgs)
	})

	return fx
}

func execWFeed(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) error {
	t.Helper()
	_, err := pool.Exec(context.Background(), sql, args...)
	return err
}

func cleanupWFeed(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Errorf("w-feed fixture cleanup: %v", err)
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestEnsureMetricsViews_Idempotent_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()

	require.NoError(t, EnsureMetricsViews(ctx, pool), "first bootstrap must succeed")
	require.NoError(t, EnsureMetricsViews(ctx, pool), "second bootstrap (re-run) must stay a no-op success")

	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.views
		 WHERE table_schema = 'public' AND table_name = ANY($1)`,
		MetricsViewNames()).Scan(&n))
	assert.Equal(t, len(MetricsViewNames()), n, "all beta views must exist after the bootstrap")
}

func TestMetricsViews_Numbers_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	require.NoError(t, EnsureMetricsViews(ctx, pool))
	fx := seedViewsFixturePG(t, pool)

	// --- DAU / requests per org per day ---------------------------------
	type dauRow struct {
		day         time.Time
		org         string
		activeUsers int
		requests    int
	}
	var dau []dauRow
	gr, err := pool.Query(ctx, `
		SELECT day, org_id::text, active_users::bigint, requests::bigint
		  FROM beta_dau_daily WHERE org_id::text = ANY($1) ORDER BY day, org_id`, []string{fx.OrgA, fx.OrgB})
	require.NoError(t, err)
	for gr.Next() {
		var r dauRow
		require.NoError(t, gr.Scan(&r.day, &r.org, &r.activeUsers, &r.requests))
		dau = append(dau, r)
	}
	require.NoError(t, gr.Err())
	require.Len(t, dau, 2, "one row per org-day: org A day1 and org B day2")
	// Org A day1: principals u1 (twice), u2, api key k1, anonymous → 4 distinct.
	assert.Equal(t, fx.OrgA, dau[0].org)
	assert.Equal(t, 4, dau[0].activeUsers, "u1 twice collapses; k1 and anon stay distinct")
	assert.Equal(t, 5, dau[0].requests)
	assert.Equal(t, fx.OrgB, dau[1].org)
	assert.Equal(t, 1, dau[1].activeUsers)
	assert.Equal(t, 1, dau[1].requests)

	// --- provider distribution (BYOK via org_custom_models) -------------
	type provRow struct {
		org      string
		provider string
		byok     bool
		requests int
	}
	var provs []provRow
	pr, err := pool.Query(ctx, `
		SELECT org_id::text, provider, byok, requests::bigint
		  FROM beta_provider_distribution WHERE org_id::text = ANY($1) ORDER BY org_id, provider`, []string{fx.OrgA, fx.OrgB})
	require.NoError(t, err)
	for pr.Next() {
		var r provRow
		require.NoError(t, pr.Scan(&r.org, &r.provider, &r.byok, &r.requests))
		provs = append(provs, r)
	}
	require.NoError(t, pr.Err())
	byProvider := map[string]provRow{}
	for _, r := range provs {
		byProvider[r.org+"|"+r.provider] = r
	}
	require.Len(t, provs, 4, "anthropic (2 orgs) + zai-coding + unknown")
	assert.Equal(t, 3, byProvider[fx.OrgA+"|anthropic"].requests, "org A global-model traffic")
	assert.False(t, byProvider[fx.OrgA+"|anthropic"].byok)
	assert.Equal(t, 1, byProvider[fx.OrgA+"|zai-coding"].requests, "org A BYOK traffic via org_custom_models")
	assert.True(t, byProvider[fx.OrgA+"|zai-coding"].byok)
	assert.Equal(t, 1, byProvider[fx.OrgA+"|(unknown)"].requests)
	assert.Equal(t, 1, byProvider[fx.OrgB+"|anthropic"].requests)

	// --- errors per provider ---------------------------------------------
	type errRow struct {
		org, provider string
		requests      int
		errors        int
		rate          float64
	}
	var errs []errRow
	er, err := pool.Query(ctx, `
		SELECT org_id::text, provider, requests::bigint, errors::bigint, error_rate
		  FROM beta_provider_errors WHERE org_id::text = ANY($1) ORDER BY org_id, provider`, []string{fx.OrgA, fx.OrgB})
	require.NoError(t, err)
	for er.Next() {
		var r errRow
		require.NoError(t, er.Scan(&r.org, &r.provider, &r.requests, &r.errors, &r.rate))
		errs = append(errs, r)
	}
	require.NoError(t, er.Err())
	byErr := map[string]errRow{}
	for _, r := range errs {
		byErr[r.org+"|"+r.provider] = r
	}
	assert.Equal(t, 0, byErr[fx.OrgA+"|anthropic"].errors)
	assert.Equal(t, 1, byErr[fx.OrgA+"|zai-coding"].errors, "the BYOK 500 row")
	assert.InDelta(t, 1.0, byErr[fx.OrgA+"|zai-coding"].rate, 1e-9)
	assert.Equal(t, 0, byErr[fx.OrgB+"|anthropic"].errors)

	// --- p95 latency -------------------------------------------------------
	type latRow struct {
		org      string
		p50, p95 float64
	}
	latByOrg := map[string]latRow{}
	lr, err := pool.Query(ctx, `
		SELECT org_id::text, p50_ms, p95_ms
		  FROM beta_latency_daily WHERE org_id::text = ANY($1)`, []string{fx.OrgA, fx.OrgB})
	require.NoError(t, err)
	for lr.Next() {
		var r latRow
		require.NoError(t, lr.Scan(&r.org, &r.p50, &r.p95))
		latByOrg[r.org] = r
	}
	require.NoError(t, lr.Err())
	require.Len(t, latByOrg, 2)
	// Org A durations sorted [10,50,100,200,300]: p50 = 100, p95 = 200+0.8*100.
	assert.InDelta(t, 100.0, latByOrg[fx.OrgA].p50, 1e-9)
	assert.InDelta(t, 280.0, latByOrg[fx.OrgA].p95, 1e-9)
	// Org B single row: both percentiles equal the row.
	assert.InDelta(t, 500.0, latByOrg[fx.OrgB].p50, 1e-9)
	assert.InDelta(t, 500.0, latByOrg[fx.OrgB].p95, 1e-9)

	// --- cache hit rate ----------------------------------------------------
	type cacheRow struct {
		org  string
		hits int
		reqs int
		rate float64
	}
	cacheByOrg := map[string]cacheRow{}
	cr, err := pool.Query(ctx, `
		SELECT org_id::text, hits::bigint, requests::bigint, hit_rate
		  FROM beta_cache_hit_rate_daily WHERE org_id::text = ANY($1)`, []string{fx.OrgA, fx.OrgB})
	require.NoError(t, err)
	for cr.Next() {
		var r cacheRow
		require.NoError(t, cr.Scan(&r.org, &r.hits, &r.reqs, &r.rate))
		cacheByOrg[r.org] = r
	}
	require.NoError(t, cr.Err())
	require.Len(t, cacheByOrg, 2)
	assert.Equal(t, 1, cacheByOrg[fx.OrgA].hits)
	assert.Equal(t, 5, cacheByOrg[fx.OrgA].reqs)
	assert.InDelta(t, 0.2, cacheByOrg[fx.OrgA].rate, 1e-9)
	assert.InDelta(t, 1.0, cacheByOrg[fx.OrgB].rate, 1e-9)

	// --- time to first request after onboarding ---------------------------
	type ttfqRow struct {
		org      string
		firstReq *time.Time
		seconds  *float64
	}
	ttfqByOrg := map[string]ttfqRow{}
	tr, err := pool.Query(ctx, `
		SELECT org_id::text, first_request_at, seconds_to_first_request
		  FROM beta_onboarding_ttfq WHERE org_id::text = ANY($1)`, []string{fx.OrgA, fx.OrgB})
	require.NoError(t, err)
	for tr.Next() {
		var r ttfqRow
		require.NoError(t, tr.Scan(&r.org, &r.firstReq, &r.seconds))
		ttfqByOrg[r.org] = r
	}
	require.NoError(t, tr.Err())
	require.Len(t, ttfqByOrg, 2)

	orgA, okA := ttfqByOrg[fx.OrgA]
	require.True(t, okA)
	require.NotNil(t, orgA.seconds)
	require.NotNil(t, orgA.firstReq)
	assert.True(t, fx.FirstA.Equal(*orgA.firstReq), "first request: got %s", *orgA.firstReq)
	assert.InDelta(t, fx.FirstA.Sub(fx.OnboardedA).Seconds(), *orgA.seconds, 1e-6)

	orgB, okB := ttfqByOrg[fx.OrgB]
	require.True(t, okB)
	require.NotNil(t, orgB.seconds)
	assert.InDelta(t, fx.FirstB.Sub(fx.OnboardedB).Seconds(), *orgB.seconds, 1e-6)
}

func TestLister_ListFeedback_Filters_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	fx := seedViewsFixturePG(t, pool)
	ctx := context.Background()

	// Record through the real collector so the write path the feedback page
	// reads is the production one.
	collector := NewCollector(pool, discardLogger())
	require.NoError(t, collector.Record(ctx, fx.OrgA, "req-1", "hash-1", classifier.ClassEasy, ActionThumbsDown))
	require.NoError(t, collector.Record(ctx, fx.OrgA, "req-2", "hash-2", classifier.ClassMedium, ActionThumbsUp))
	require.NoError(t, collector.Record(ctx, fx.OrgB, "req-3", "hash-3", classifier.ClassHard, ActionThumbsDown))

	l := NewLister(pool)

	// No filter (root view): both orgs visible, newest first.
	page, err := l.ListFeedback(ctx, ListFilter{})
	require.NoError(t, err)
	require.Len(t, page.Entries, 3)
	assert.Equal(t, int64(3), page.Total)
	// req-3 recorded last → newest first.
	assert.Equal(t, "req-3", page.Entries[0].RequestID)

	// Org filter: foreign-org rows are excluded and the numbers stay exact.
	page, err = l.ListFeedback(ctx, ListFilter{OrgID: fx.OrgA})
	require.NoError(t, err)
	assert.Equal(t, int64(2), page.Total)
	require.Len(t, page.Entries, 2)
	for _, e := range page.Entries {
		assert.Equal(t, fx.OrgA, e.OrgID, "org filter must exclude foreign-org rows")
	}

	// Org + rating.
	page, err = l.ListFeedback(ctx, ListFilter{OrgID: fx.OrgA, Action: string(ActionThumbsDown)})
	require.NoError(t, err)
	assert.Equal(t, int64(1), page.Total)
	require.Len(t, page.Entries, 1)
	assert.Equal(t, "req-1", page.Entries[0].RequestID)
	assert.Equal(t, string(ActionThumbsDown), page.Entries[0].Action)

	// The inverse direction of the same contract: org B's filter never
	// returns org A rows (a thumbs_up exists only in org A).
	page, err = l.ListFeedback(ctx, ListFilter{OrgID: fx.OrgB, Action: string(ActionThumbsUp)})
	require.NoError(t, err)
	assert.Equal(t, int64(0), page.Total)
	assert.Empty(t, page.Entries)

	// Pagination: page 2 of size 1 is the second-newest row, total intact.
	page, err = l.ListFeedback(ctx, ListFilter{Page: 2, PageSize: 1})
	require.NoError(t, err)
	assert.Equal(t, int64(3), page.Total)
	require.Len(t, page.Entries, 1)
	assert.Equal(t, "req-2", page.Entries[0].RequestID)
}

func TestLister_ListFeedback_InvalidActionFilter_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	l := NewLister(pool)

	_, err := l.ListFeedback(context.Background(), ListFilter{Action: "star"})
	require.Error(t, err, "the store rejects ratings the collector never produced")
}

func TestLister_ListFeedback_Unwired_Integration(t *testing.T) {
	l := NewLister(nil)
	_, err := l.ListFeedback(context.Background(), ListFilter{})
	require.Error(t, err)
}
