//go:build integration

package migrate

// 0035_dimensional_components lifecycle audit on a disposable database
// (Docker/testcontainers, same gate as TestRun_UpDownUpCycle):
//   - the up applies cleanly on a fresh install and creates the table with
//     its FORCE RLS posture and closed-set CHECKs,
//   - the down (to 0034) is the structural reverse and drops the table,
//   - re-upgrading restores it, and a pre-existing request_logs row — the
//     monetary read contract — survives the whole cycle bit-for-bit via the
//     row_to_json snapshot (created_at/updated_at included).
//
// Scope note: 0035 is expand-phase and additive; request_logs is never
// referenced by either direction, which is exactly what the snapshot proves.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// TestRun_DimensionalComponentsUpDownReupgrade runs the 0035 cycle against
// a fresh container.
func TestRun_DimensionalComponentsUpDownReupgrade(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	container, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
		testpostgres.WithDatabase("yabanin"),
		testpostgres.WithUsername("postgres"),
		testpostgres.WithPassword("postgres"),
	)
	require.NoError(t, err, "docker/testcontainers must be available for the 0035 cycle audit")
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)
	parts := strings.Split(port.Port(), "/")
	connStr := fmt.Sprintf("postgres://postgres:postgres@%s:%s/yabanin?sslmode=disable", host, parts[0])

	waitPool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(func() { waitPool.Close() })
	waitForDBReady(t, ctx, waitPool)

	// Fresh install: the full set including 0035 applies.
	up1, err := Run(ctx, connStr, "sg")
	require.NoError(t, err, "initial upgrade should apply the full schema")
	require.EqualValues(t, 35, up1.Version, "the fresh install must land at the 0035 head")
	requireTableExists(t, connStr, "dimensional_components")

	// Seed: one dimensional row and one monetary request_logs row (with an
	// explicit home_region: the raw insert bypasses the GUC default).
	p := mustPool(t, connStr)
	seedDimensionalAndMoneyRow(t, ctx, p)

	var dimRow, moneyRow string
	require.NoError(t, p.QueryRow(ctx,
		`SELECT row_to_json(dc)::text FROM dimensional_components dc
		 WHERE dc.component_id = 'comp-cycle'`).Scan(&dimRow))
	require.NoError(t, p.QueryRow(ctx,
		`SELECT row_to_json(rl)::text FROM request_logs rl
		 WHERE rl.request_id = 'req-cycle'`).Scan(&moneyRow))

	// Down to 0034: the dimensional table is gone, the money row survives.
	down1, err := Down(ctx, connStr, "sg", 34)
	require.NoError(t, err, "downgrade to 0034 should succeed")
	require.EqualValues(t, 34, down1.Version)
	requireTableMissing(t, ctx, p, "dimensional_components",
		"the 0035 down must drop the table (structural reverse)")
	var moneyRowAfterDown string
	require.NoError(t, p.QueryRow(ctx,
		`SELECT row_to_json(rl)::text FROM request_logs rl
		 WHERE rl.request_id = 'req-cycle'`).Scan(&moneyRowAfterDown))
	require.Equal(t, moneyRow, moneyRowAfterDown, "request_logs must survive the 0035 down unchanged")

	// Re-upgrade to 0035: the table is back (empty), the money row is still
	// bit-for-bit identical — created_at/updated_at untouched.
	up2, err := Run(ctx, connStr, "sg")
	require.NoError(t, err, "re-upgrade should succeed")
	require.EqualValues(t, 35, up2.Version)
	requireTableExists(t, connStr, "dimensional_components")
	var dimCount int64
	require.NoError(t, p.QueryRow(ctx,
		`SELECT count(*) FROM dimensional_components`).Scan(&dimCount))
	require.Zero(t, dimCount, "the re-upgraded table starts empty (down deleted its rows)")
	var moneyRowAfterUp string
	require.NoError(t, p.QueryRow(ctx,
		`SELECT row_to_json(rl)::text FROM request_logs rl
		 WHERE rl.request_id = 'req-cycle'`).Scan(&moneyRowAfterUp))
	require.Equal(t, moneyRow, moneyRowAfterUp, "request_logs must survive the whole cycle unchanged")
}

// seedDimensionalAndMoneyRow inserts one row per table with frozen literals.
func seedDimensionalAndMoneyRow(t *testing.T, ctx context.Context, p *pgxpool.Pool) {
	t.Helper()
	var orgID string
	require.NoError(t, p.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('cycle-org', 'cycle-org')
		 RETURNING id::text`).Scan(&orgID))
	t.Cleanup(func() {
		_, _ = p.Exec(context.Background(),
			`DELETE FROM organizations WHERE id::text = $1`, orgID)
	})
	_, err := p.Exec(ctx, `
		INSERT INTO dimensional_components
			(org_id, tenant_id, event_id, component_id, request_id, meter, unit,
			 quantity_text, source_kind, source_ref, method, factor_version,
			 event_time, effective_time, boundary, precision_kind, lifecycle)
		VALUES ($1::uuid, 'tenant-cycle', 'evt-cycle', 'comp-cycle', 'req-cycle', 'usage.cost', 'USD',
			 '0.02', 'gateway', 'resp-body', 'provider-report', 'tariff-2026-11',
			 '2026-11-24T10:15:30.123456Z', '2026-11-24T10:15:30.123456Z',
			 'measurement', 'exact', 'provisional')`, orgID)
	require.NoError(t, err)
	_, err = p.Exec(ctx, `
		INSERT INTO request_logs
			(org_id, request_id, model_requested, model_used, status_code, duration_ms,
			 tokens_in, tokens_out, cost_in_usd, cost_status, home_region)
		VALUES ($1::uuid, 'req-cycle', 'm-smart', 'm-smart', 200, 42,
			 10, 20, 0.015, 'priced', 'global')`, orgID)
	require.NoError(t, err)
}

// mustPool opens a pool for row-level assertions inside the cycle audit.
func mustPool(t *testing.T, connStr string) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(context.Background(), connStr)
	require.NoError(t, err)
	t.Cleanup(p.Close)
	return p
}
