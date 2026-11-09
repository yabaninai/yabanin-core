package trcli

// models_pricing. Unit tests here cover the flag contract, the JSON
// position errors and the URL fetch (loopback httptest only). The DB
// round-trip (clobber policy, idempotency, unit conversion in the real
// numeric(10,6) columns) runs on the disposable testcontainers Postgres
// (repo convention: skipped in -short mode / without Docker).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
)

// The canonical operator-facing fixture (single source of truth for tests
// and the documented day-0 example import).
const pricingSyncDay0Fixture = "../../scripts/pricing/fixtures/litellm_day0_subset.json"

func TestPricingSyncDay0_FlagContract(t *testing.T) {
	_, err := runTr(t, "pricing-sync", "--pg-uri", "postgres://x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--file")
	assert.Contains(t, err.Error(), "--url")
	assert.Contains(t, err.Error(), "https://raw.githubusercontent.com")

	_, err = runTr(t, "pricing-sync", "--pg-uri", "postgres://x",
		"--file", "a.json", "--url", "https://example.invalid/catalog.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")

	_, err = runTr(t, "pricing-sync", "--file", "a.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--pg-uri required")
}

func TestPricingSyncDay0_BrokenJSONReportsFileLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.json")
	content := "{\n" +
		"  \"openai/fixture-manual\": {\n" +
		"    \"mode\": \"chat\",\n" +
		"    \"price\": OOPS\n" +
		"  }\n" +
		"}"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	_, err := runTr(t, "pricing-sync", "--pg-uri", "postgres://x", "--file", path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), path+":4:")
	assert.Contains(t, err.Error(), "parse litellm catalog")
}

func TestPricingSyncDay0_URLMustBeHTTPAndFailsOnBadStatus(t *testing.T) {
	_, err := runTr(t, "pricing-sync", "--pg-uri", "postgres://x", "--url", "ftp://example.invalid/a.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "http(s)")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	_, err = runTr(t, "pricing-sync", "--pg-uri", "postgres://x", "--url", srv.URL+"/catalog.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status 404")
}

// TestPricingSyncDay0_Integration proves the full DB round-trip on the
// disposable stand: unit conversion into numeric(10,6), no-clobber of a
// manual row, update of a sync-owned row, adds for missing keys, dry-run
// default, idempotent re-apply and the URL fetch path.
func TestPricingSyncDay0_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	uri := pool.Config().ConnString()

	// The stand is shared within the test binary (migrations seed their own
	// pricing rows), so every count is scoped to the fixture keys below.
	const fixtureKeys = `
		 ('openai','fixture-manual'), ('openai','fixture-small'),
		 ('anthropic','fixture-cache'), ('gemini','fixture-tiered'),
		 ('deepseek','fixture-chat'), ('fireworks','fixture-normalized'),
		 ('openai','fixture-embedding'), ('xai','fixture-extra')`
	cleanup := func() {
		_, _ = pool.Exec(ctx,
			`DELETE FROM models_pricing WHERE (provider, model) IN (`+fixtureKeys+`)`)
	}
	cleanup()
	t.Cleanup(cleanup)

	// Seed: a manual override on a fixture key, and a stale sync-owned row.
	_, err := pool.Exec(ctx, `
		INSERT INTO models_pricing (provider, model, input_per_m, output_per_m, source)
		VALUES ('openai', 'fixture-manual', 99, 99, 'manual')`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO models_pricing (provider, model, input_per_m, output_per_m, cache_write_per_m, cache_read_per_m, source, source_ref)
		VALUES ('openai', 'fixture-small', 0.1, 0.5, 0, 0, 'catalog', 'old')`)
	require.NoError(t, err)

	run := func(t *testing.T, args ...string) string {
		t.Helper()
		out, err := runTr(t, append([]string{"pricing-sync", "--pg-uri", uri}, args...)...)
		require.NoError(t, err)
		return out
	}

	// Dry-run by default: the plan reports add/update/skip, the DB is untouched.
	out := run(t, "--file", pricingSyncDay0Fixture)
	assert.Contains(t, out, "catalog stats: total=10 imported=8 skipped_mode=1 skipped_no_price=0 skipped_invalid=1 duplicates=0 tiered_ignored=1")
	assert.Contains(t, out, "plan: added=6 updated=1 skipped=1 total=8")
	assert.Contains(t, out, "manual override (source=manual)")
	assert.Contains(t, out, "dry-run: nothing written")

	var manualInput float64
	var openCount int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT input_per_m FROM models_pricing WHERE provider='openai' AND model='fixture-manual' AND effective_to IS NULL
	`).Scan(&manualInput))
	assert.InDelta(t, 99, manualInput, 1e-9, "manual row untouched by dry-run")
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM models_pricing WHERE effective_to IS NULL AND (provider, model) IN (`+fixtureKeys+`)`).Scan(&openCount))
	assert.Equal(t, 2, openCount, "only the two seeded rows are open after dry-run")

	// Apply: adds + one update, manual row still untouched.
	out = run(t, "--file", pricingSyncDay0Fixture, "--apply")
	assert.Contains(t, out, "plan: added=6 updated=1 skipped=1 total=8")
	assert.Contains(t, out, "applied: added=6 updated=1 skipped=1")

	var closedCount, openMiniRows int
	var newInput, newOutput, claudeCacheW, claudeCacheR, grokInput, grokOutput float64
	var src, ref, updatedBy, manualSource string
	var manualOpen bool

	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM models_pricing
		WHERE provider='openai' AND model='fixture-small' AND effective_to IS NOT NULL`).Scan(&closedCount))
	assert.Equal(t, int64(1), int64(closedCount), "stale catalog row closed exactly once")

	require.NoError(t, pool.QueryRow(ctx, `
		SELECT input_per_m, output_per_m, source, source_ref, updated_by
		FROM models_pricing WHERE provider='openai' AND model='fixture-small' AND effective_to IS NULL
	`).Scan(&newInput, &newOutput, &src, &ref, &updatedBy))
	assert.InDelta(t, 14.3, newInput, 1e-9, "synthetic input USD/token * 1e6")
	assert.InDelta(t, 14.4, newOutput, 1e-9, "synthetic output USD/token * 1e6")
	assert.Equal(t, "catalog", src)
	assert.Contains(t, ref, "openai/fixture-small")
	assert.Equal(t, "pricing-sync", updatedBy)

	require.NoError(t, pool.QueryRow(ctx, `
		SELECT cache_write_per_m, cache_read_per_m FROM models_pricing
		WHERE provider='anthropic' AND model='fixture-cache' AND effective_to IS NULL
	`).Scan(&claudeCacheW, &claudeCacheR))
	assert.InDelta(t, 16.5, claudeCacheW, 1e-9, "synthetic cache write USD/token * 1e6")
	assert.InDelta(t, 16.1, claudeCacheR, 1e-9, "synthetic cache read USD/token * 1e6")

	require.NoError(t, pool.QueryRow(ctx, `
		SELECT input_per_m, output_per_m FROM models_pricing
		WHERE provider='xai' AND model='fixture-extra' AND effective_to IS NULL
	`).Scan(&grokInput, &grokOutput))
	assert.InDelta(t, 20.9, grokInput, 1e-9)
	assert.InDelta(t, 21.0, grokOutput, 1e-9)

	require.NoError(t, pool.QueryRow(ctx, `
		SELECT source, input_per_m, effective_to IS NULL FROM models_pricing
		WHERE provider='openai' AND model='fixture-manual' AND effective_to IS NULL
	`).Scan(&manualSource, &manualInput, &manualOpen))
	assert.Equal(t, "manual", manualSource)
	assert.InDelta(t, 99, manualInput, 1e-9, "manual override never rewritten")
	assert.True(t, manualOpen)

	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM models_pricing WHERE effective_to IS NULL AND (provider, model) IN (`+fixtureKeys+`)`).Scan(&openMiniRows))
	assert.Equal(t, 8, openMiniRows, "2 seeded + 6 adds + 1 replacement open after apply")

	// Re-apply is a no-op: everything is already in sync (or manually owned).
	out = run(t, "--file", pricingSyncDay0Fixture, "--apply")
	assert.Contains(t, out, "plan: added=0 updated=0 skipped=8 total=8")
	assert.Contains(t, out, "applied: added=0 updated=0 skipped=8")
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM models_pricing WHERE effective_to IS NULL AND (provider, model) IN (`+fixtureKeys+`)`).Scan(&openMiniRows))
	assert.Equal(t, 8, openMiniRows, "re-apply must not add history rows")

	// URL mode: same catalog served from a loopback server; the network call
	// happens only because --url was passed. The plan is all-unchanged.
	var hits atomic.Int64
	catSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		raw, err := os.ReadFile(pricingSyncDay0Fixture)
		if err != nil {
			http.Error(w, "fixture read failed", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(raw)
	}))
	t.Cleanup(catSrv.Close)

	out = run(t, "--url", catSrv.URL+"/model_prices_and_context_window.json")
	assert.Equal(t, int64(1), hits.Load(), "--url must fetch exactly once")
	assert.Contains(t, out, "catalog origin: "+catSrv.URL+"/model_prices_and_context_window.json")
	assert.Contains(t, out, "plan: added=0 updated=0 skipped=8 total=8")
}
