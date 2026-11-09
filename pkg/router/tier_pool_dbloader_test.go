package router

import (
	"context"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PO-05b: the tier-pool DB model loader must be NULL-safe on upstream_url.
//
// A models_registry row whose upstream_url is NULL used to fail
// ListModels with "cannot scan NULL into string", which aborted the whole
// model list and forced tier selection into its fallback. The fix wraps the
// column in COALESCE(upstream_url,'') — matching every other nullable column
// in the same SELECT — so the scan into ModelInfo.UpstreamURL (a plain string)
// never sees a NULL.
//
// Docker/testcontainers is unavailable in this environment, so the real SQL
// cannot be executed here. Instead:
//   - the scan path is exercised with a row whose upstream_url is the
//     post-COALESCE value ("") to prove ListModels survives an empty URL and
//     surfaces it as "" (no error, no fallback);
//   - a regression guard asserts the SELECT still carries
//     COALESCE(upstream_url,''), so the NULL-safety cannot silently regress.

// dbLoaderPoolMock implements the pgxPool interface for dbModelLoader.
type dbLoaderPoolMock struct {
	rows pgx.Rows
	err  error
	sql  string
}

func (m *dbLoaderPoolMock) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	return nil
}

func (m *dbLoaderPoolMock) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	m.sql = sql
	return m.rows, m.err
}

// modelRowFake is a pgx.Rows over one models_registry row. Column order must
// match ListModels' SELECT: model_name, tier, tier_pool, weight, upstream_url,
// enabled, country, vendor_hq, sovereignty_tier, cn_flagged.
type modelRowFake struct {
	row   []any
	index int
}

func (r *modelRowFake) Next() bool {
	if r.index >= 1 {
		return false
	}
	r.index++
	return true
}

func (r *modelRowFake) Scan(dest ...any) error {
	for i, d := range dest {
		if i >= len(r.row) {
			break
		}
		switch v := d.(type) {
		case *string:
			// Simulate COALESCE: a NULL (nil) column yields "".
			if r.row[i] == nil {
				*v = ""
			} else {
				*v = r.row[i].(string)
			}
		case *int:
			*v = r.row[i].(int)
		case *bool:
			*v = r.row[i].(bool)
		case *[]string:
			*v = r.row[i].([]string)
		default:
			return assert.AnError
		}
	}
	return nil
}
func (r *modelRowFake) Err() error                                   { return nil }
func (r *modelRowFake) Close()                                       {}
func (r *modelRowFake) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("") }
func (r *modelRowFake) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *modelRowFake) Conn() *pgx.Conn                              { return nil }
func (r *modelRowFake) RawValues() [][]byte                          { return nil }
func (r *modelRowFake) Values() ([]any, error)                       { return nil, nil }

// TestDBModelLoader_NullUpstreamURL_IsScanSafe: a model row whose upstream_url
// is NULL must not abort ListModels. After COALESCE the URL is "" and the
// model is still returned (tier selection can then decide to skip/route it).
func TestDBModelLoader_NullUpstreamURL_IsScanSafe(t *testing.T) {
	fake := &modelRowFake{row: []any{
		"glm-5.3",          // model_name
		"smart",            // tier
		[]string{"medium"}, // tier_pool
		1,                  // weight
		nil,                // upstream_url — NULL in the DB
		true,               // enabled
		"US",               // country
		"US",               // vendor_hq
		"foreign",          // sovereignty_tier
		false,              // cn_flagged
	}}
	loader := NewDBModelLoader(&dbLoaderPoolMock{rows: fake}, slog.Default())

	models, err := loader.ListModels(context.Background())
	require.NoError(t, err, "a NULL upstream_url must not abort the model list")
	require.Len(t, models, 1)
	assert.Equal(t, "glm-5.3", models[0].Name)
	assert.Empty(t, models[0].UpstreamURL, "NULL upstream_url must surface as empty string")
	assert.Equal(t, "smart", models[0].Tier)
	assert.True(t, models[0].Enabled)
}

// TestDBModelLoader_SetUpstreamURL_IsPreserved: a non-NULL upstream_url is
// passed through unchanged (the COALESCE does not clobber real values).
func TestDBModelLoader_SetUpstreamURL_IsPreserved(t *testing.T) {
	const url = "https://api.example.com/v1"
	fake := &modelRowFake{row: []any{
		"glm-5.3",
		"smart",
		[]string{"medium"},
		1,
		url, // upstream_url — set
		true,
		"US",
		"US",
		"foreign",
		false,
	}}
	loader := NewDBModelLoader(&dbLoaderPoolMock{rows: fake}, slog.Default())

	models, err := loader.ListModels(context.Background())
	require.NoError(t, err)
	require.Len(t, models, 1)
	assert.Equal(t, url, models[0].UpstreamURL)
}

// TestDBModelLoader_SQLCoalescesUpstreamURL guards the fix itself: the SELECT
// must wrap upstream_url in COALESCE(...,”) so the scan never receives a NULL.
func TestDBModelLoader_SQLCoalescesUpstreamURL(t *testing.T) {
	mock := &dbLoaderPoolMock{rows: &modelRowFake{row: nil}}
	l := NewDBModelLoader(mock, slog.Default())
	_, _ = l.ListModels(context.Background())

	require.Contains(t, mock.sql, "COALESCE(upstream_url,'')",
		"upstream_url must be COALESCE'd to '' for NULL-safe scanning; got: %q", mock.sql)
	// The raw column (no COALESCE) must no longer appear in the projection.
	require.NotContains(t, mock.sql, "COALESCE(weight,1), upstream_url, enabled",
		"the raw upstream_url column must be wrapped in COALESCE; got: %q", mock.sql)
}

// TypeMap satisfies the pgx.Rows interface (pgx v5.12 added the method);
// the fake synthesizes rows, so no type map is available or needed.
func (r *modelRowFake) TypeMap() *pgtype.Map { return nil }
