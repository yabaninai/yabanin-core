package feedback

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Beta metrics SQL views (card W-FEED).
//
// idempotently (CREATE OR REPLACE VIEW) by the admin starter at startup —
// never by a migration file. Every statement is safe to re-run.
//
// Scoping model (mirrors the card's clarification): the consumers are the
// root-only owner surfaces (Grafana beta dashboard, admin plane), so the
// views stay plain default-definer views over request_logs / organizations /
// org_custom_models / models_registry and expose org_id as a column; every
// consumer scopes by an explicit org filter. Provider attribution: BYOK usage
// is a request whose model_used resolves to an org custom model
// (org_custom_models row for (org_id, model_used)); the provider falls back
// to the global models_registry, then '(unknown)'. (request_logs carries no
// used_org_key/provider columns — used_org_key lives only in the
//
// Content exposure: counts, percentiles and timestamps only — no prompt or
// response payload. If the views are ever granted to a non-root consumer,
// re-evaluate (aggregates reveal cross-org activity existence).
const metricsViewsSQL = `
CREATE OR REPLACE VIEW public.beta_dau_daily AS
SELECT date_trunc('day', rl.created_at AT TIME ZONE 'UTC') AS day,
       rl.org_id                        AS org_id,
       COUNT(DISTINCT COALESCE(rl.user_id::text, rl.api_key_id::text, rl.agent_id::text, 'anon')) AS active_users,
       COUNT(*)                         AS requests
  FROM public.request_logs rl
 GROUP BY 1, 2;

CREATE OR REPLACE VIEW public.beta_requests_daily AS
SELECT date_trunc('day', rl.created_at AT TIME ZONE 'UTC') AS day,
       rl.org_id                        AS org_id,
       COUNT(*)                         AS requests,
       COUNT(*) FILTER (WHERE rl.status_code >= 400) AS errors
  FROM public.request_logs rl
 GROUP BY 1, 2;

CREATE OR REPLACE VIEW public.beta_onboarding_ttfq AS
SELECT o.id          AS org_id,
       o.created_at  AS onboarded_at,
       f.first_request_at,
       EXTRACT(EPOCH FROM (f.first_request_at - o.created_at))::float8 AS seconds_to_first_request
  FROM public.organizations o
  LEFT JOIN (
       SELECT org_id, MIN(created_at) AS first_request_at
         FROM public.request_logs
        GROUP BY org_id
       ) f ON f.org_id = o.id;

CREATE OR REPLACE VIEW public.beta_provider_distribution AS
SELECT date_trunc('day', rl.created_at AT TIME ZONE 'UTC') AS day,
       rl.org_id                        AS org_id,
       COALESCE(byok.provider, glob.provider, '(unknown)') AS provider,
       (byok.org_id IS NOT NULL)        AS byok,
       COUNT(*)                         AS requests
  FROM public.request_logs rl
  LEFT JOIN LATERAL (
       SELECT ocm.org_id, ocm.provider
         FROM public.org_custom_models ocm
        WHERE ocm.org_id = rl.org_id AND ocm.model_name = rl.model_used
        LIMIT 1
       ) byok ON true
  LEFT JOIN LATERAL (
       SELECT mr.provider
         FROM public.models_registry mr
        WHERE mr.model_name = rl.model_used
        ORDER BY mr.version DESC
        LIMIT 1
       ) glob ON true
 GROUP BY 1, 2, 3, 4;

CREATE OR REPLACE VIEW public.beta_provider_errors AS
SELECT date_trunc('day', rl.created_at AT TIME ZONE 'UTC') AS day,
       rl.org_id                        AS org_id,
       COALESCE(byok.provider, glob.provider, '(unknown)') AS provider,
       (byok.org_id IS NOT NULL)        AS byok,
       COUNT(*)                         AS requests,
       COUNT(*) FILTER (WHERE rl.status_code >= 400) AS errors,
       (COUNT(*) FILTER (WHERE rl.status_code >= 400))::float8 / NULLIF(COUNT(*), 0)::float8 AS error_rate
  FROM public.request_logs rl
  LEFT JOIN LATERAL (
       SELECT ocm.org_id, ocm.provider
         FROM public.org_custom_models ocm
        WHERE ocm.org_id = rl.org_id AND ocm.model_name = rl.model_used
        LIMIT 1
       ) byok ON true
  LEFT JOIN LATERAL (
       SELECT mr.provider
         FROM public.models_registry mr
        WHERE mr.model_name = rl.model_used
        ORDER BY mr.version DESC
        LIMIT 1
       ) glob ON true
 GROUP BY 1, 2, 3, 4;

CREATE OR REPLACE VIEW public.beta_latency_daily AS
SELECT date_trunc('day', rl.created_at AT TIME ZONE 'UTC') AS day,
       rl.org_id                        AS org_id,
       (percentile_cont(0.5) WITHIN GROUP (ORDER BY rl.duration_ms))::float8 AS p50_ms,
       (percentile_cont(0.95) WITHIN GROUP (ORDER BY rl.duration_ms))::float8 AS p95_ms,
       COUNT(*)                         AS requests
  FROM public.request_logs rl
 GROUP BY 1, 2;

CREATE OR REPLACE VIEW public.beta_cache_hit_rate_daily AS
SELECT date_trunc('day', rl.created_at AT TIME ZONE 'UTC') AS day,
       rl.org_id                        AS org_id,
       COUNT(*) FILTER (WHERE rl.cache_hit_type IN ('exact', 'semantic')) AS hits,
       COUNT(*)                         AS requests,
       (COUNT(*) FILTER (WHERE rl.cache_hit_type IN ('exact', 'semantic')))::float8 / NULLIF(COUNT(*), 0)::float8 AS hit_rate
  FROM public.request_logs rl
 GROUP BY 1, 2;

-- The app role reads the views through the admin pool; grant only when the
-- role exists (bare stands bootstrap it, some deployments rename it).
DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'yabanin_app') THEN
    GRANT SELECT ON public.beta_dau_daily,
                     public.beta_requests_daily,
                     public.beta_onboarding_ttfq,
                     public.beta_provider_distribution,
                     public.beta_provider_errors,
                     public.beta_latency_daily,
                     public.beta_cache_hit_rate_daily TO yabanin_app;
  END IF;
END $$;
`

// Execer is the minimal SQL surface the view bootstrap needs (*pgxpool.Pool
// and *pgx.Conn both satisfy it).
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// MetricsViewNames lists the views EnsureMetricsViews manages (dashboard and
// documentation reference).
func MetricsViewNames() []string {
	return []string{
		"beta_dau_daily",
		"beta_requests_daily",
		"beta_onboarding_ttfq",
		"beta_provider_distribution",
		"beta_provider_errors",
		"beta_latency_daily",
		"beta_cache_hit_rate_daily",
	}
}

// EnsureMetricsViews creates or replaces the beta metrics views. Idempotent:
// every statement is CREATE OR REPLACE / a guarded grant, so re-running on an
// already-provisioned database is a no-op.
func EnsureMetricsViews(ctx context.Context, db Execer) error {
	if db == nil {
		return fmt.Errorf("feedback metrics views: database is not configured")
	}
	if _, err := db.Exec(ctx, metricsViewsSQL); err != nil {
		return fmt.Errorf("feedback metrics views bootstrap: %w", err)
	}
	return nil
}

// EnsureMetricsViewsURI runs EnsureMetricsViews over a dedicated short-lived
// pool for the given DSN. The admin pool downgrades every connection to the
// NOBYPASSRLS app role (SET ROLE), which cannot CREATE in the public schema —
// the bootstrap therefore connects as the DSN login (the migration owner)
// exactly once and closes the pool. Bounded by bootstrapTimeout: a database
// that cannot provision the views must not stall the admin startup.
func EnsureMetricsViewsURI(ctx context.Context, uri string) error {
	const bootstrapTimeout = 15 * time.Second
	ctx, cancel := context.WithTimeout(ctx, bootstrapTimeout)
	defer cancel()

	pool, err := pgxpool.New(ctx, uri)
	if err != nil {
		return fmt.Errorf("feedback metrics views bootstrap pool: %w", err)
	}
	defer pool.Close()
	return EnsureMetricsViews(ctx, pool)
}
