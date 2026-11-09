package adminstore

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// A01 + AF-07: pricing completeness + as-of in the analytics DTOs.
//
// Semantics under test:
//   - PricingAsOf always carries the bundled price-source provenance (never a
//     freshness or as-of-over-the-window claim, never a failure marker).
//   - CoverageStatus classifies the window: complete (share 0), partial
//     (0 < share < 1), unknown (measurement failed → share null, or 100%
//     unpriced → share 1), empty (no requests).
//   - UnpricedShare = unpriced_requests / total_requests (0..1); nil when not
//     measured — nil is NOT zero coverage.
//   - UnpricedModels lists the top unpriced models by request count.
//   - zero cost is NOT free: a model absent from models_pricing must show up
//     as unpriced, not as $0-free.

// queryMockDB builds a mockDB that answers QueryRow with the given 1-col
// values in order and Query with the given rows (empty slice = no rows).
func queryMockDB(t *testing.T, rowValues []interface{}, rows [][]interface{}) *mockDB {
	t.Helper()
	i := 0
	return &mockDB{
		queryRowFn: func(_ context.Context, _ string, _ ...interface{}) pgx.Row {
			require.Less(t, i, len(rowValues), "more QueryRow calls than mocked values")
			v := rowValues[i]
			i++
			return &mockPGXScalarRow{val: v}
		},
		queryFn: func(_ context.Context, _ string, _ ...interface{}) (pgx.Rows, error) {
			return &mockPGXRows{data: rows}, nil
		},
	}
}

// mockPGXRow is a one-value pgx.Row (the existing helper in store_test.go has
// no fields; A01 needs a configurable value).
type mockPGXScalarRow struct{ val interface{} }

func (r *mockPGXScalarRow) Scan(dest ...interface{}) error {
	if len(dest) == 0 {
		return nil
	}
	switch d := dest[0].(type) {
	case *int:
		switch v := r.val.(type) {
		case int:
			*d = v
		case int64:
			*d = int(v)
		}
	case *int64:
		switch v := r.val.(type) {
		case int:
			*d = int64(v)
		case int64:
			*d = v
		}
	case *float64:
		*d = r.val.(float64)
	case *string:
		*d = r.val.(string)
	default:
		return nil
	}
	return nil
}

func TestBuildPricingMetadata_ShareAndModels(t *testing.T) {
	db := queryMockDB(t, []interface{}{int(2)}, [][]interface{}{{"mystery-model", 42}})

	meta := buildPricingMetadata(db, context.Background(), "created_at BETWEEN $1 AND $2", 10)

	// A03: PricingAsOf cites the actual file-backed snapshot (source + date
	// + sha256), not the legacy embedded-table label.
	prov := pricing.DefaultFilePricer().Provenance()
	assert.Equal(t, prov.Source+" "+prov.Date+" "+prov.SHA256, meta.PricingAsOf,
		"PricingAsOf must carry the file-snapshot provenance (source + date + sha256)")
	require.NotNil(t, meta.UnpricedShare)
	assert.InDelta(t, 0.2, *meta.UnpricedShare, 1e-9, "2 of 10 requests unpriced")
	assert.Equal(t, CoveragePartial, meta.CoverageStatus)
	assert.Equal(t, []string{"mystery-model"}, meta.UnpricedModels)
	assert.Empty(t, meta.CoverageError, "a successful measurement carries no failure marker")
}

// TestBuildPricingMetadata_StructuredCatalogCitation: CORE-REF-04 — when the
// default pricer serves the reference catalog, the report payload carries
// the structured citation (version, generation date, sealed digest) next to
// the composed PricingAsOf line, so surfaces render `catalog:<version>
// digest:<prefix>` without parsing the label.
func TestBuildPricingMetadata_StructuredCatalogCitation(t *testing.T) {
	db := queryMockDB(t, []interface{}{int(0)}, nil)
	meta := buildPricingMetadata(db, context.Background(), "1=1", 3)

	prov := pricing.DefaultFilePricer().Provenance()
	info, ok := pricing.DefaultFilePricer().CatalogProvenance()
	require.True(t, ok, "the default pricer serves the reference catalog since CORE-REF-04")

	require.NotNil(t, meta.PricingCatalog, "catalog-backed reports must carry the structured citation")
	assert.Equal(t, info.Version, meta.PricingCatalog.Version)
	assert.Equal(t, info.GeneratedAt, meta.PricingCatalog.GeneratedAt)
	assert.Equal(t, info.Digest, meta.PricingCatalog.Digest)

	// The composed line stays the full label: yabanin-catalog@<version>
	// <date> sha256:<digest>.
	assert.Equal(t, prov.Source+" "+prov.Date+" "+prov.SHA256, meta.PricingAsOf)
	assert.Contains(t, meta.PricingAsOf, "yabanin-catalog@")
	assert.Contains(t, meta.PricingAsOf, "sha256:"+info.Digest)
}

func TestBuildPricingMetadata_ZeroRequestsNoDivisionByZero(t *testing.T) {
	db := queryMockDB(t, []interface{}{int(0)}, nil)
	meta := buildPricingMetadata(db, context.Background(), "1=1", 0)
	require.NotNil(t, meta.UnpricedShare)
	assert.InDelta(t, 0, *meta.UnpricedShare, 0, "no requests → share must be 0, not NaN")
	assert.Equal(t, CoverageEmpty, meta.CoverageStatus, "an empty window is a distinct state")
	assert.Empty(t, meta.UnpricedModels)
}

func TestBuildPricingMetadata_AllPriced(t *testing.T) {
	db := queryMockDB(t, []interface{}{int(0)}, nil)
	meta := buildPricingMetadata(db, context.Background(), "1=1", 7)
	require.NotNil(t, meta.UnpricedShare)
	assert.InDelta(t, 0, *meta.UnpricedShare, 0)
	assert.Equal(t, CoverageComplete, meta.CoverageStatus)
	assert.Empty(t, meta.UnpricedModels)
	assert.Contains(t, meta.PricingAsOf, "sha256:")
}

func TestBuildPricingMetadata_CoverageQueryFails_Degrades(t *testing.T) {
	// The coverage count succeeds (3 of 5 unpriced) but the top-unpriced
	// models query errors → the helper must degrade, not panic, and must not
	// leave the report looking like an unmarked success.
	db := &mockDB{
		queryRowFn: func(_ context.Context, _ string, _ ...interface{}) pgx.Row {
			return &mockPGXScalarRow{val: int(3)}
		},
		queryFn: func(_ context.Context, _ string, _ ...interface{}) (pgx.Rows, error) {
			return nil, assert.AnError
		},
	}
	meta := buildPricingMetadata(db, context.Background(), "1=1", 5)
	// AF-07: degrade to explicitly partial coverage — the measured share
	// stands, a dedicated failure marker is set, and provenance stays pure.
	assert.Equal(t, CoveragePartial, meta.CoverageStatus)
	require.NotNil(t, meta.UnpricedShare)
	assert.InDelta(t, 0.6, *meta.UnpricedShare, 1e-9)
	assert.Equal(t, "unpriced model list query failed", meta.CoverageError)
	assert.NotContains(t, meta.PricingAsOf, "coverage query failed",
		"provenance must stay separate from failure markers")
	assert.Contains(t, meta.PricingAsOf, "sha256:")
}

func TestBuildPricingMetadata_AllUnpricedIsUnknownCostShareStillMeasured(t *testing.T) {
	// 100% unpriced: the measurement succeeded (share = 1) but the cost of
	// the window is unknown — never a success-looking fully-priced report.
	db := queryMockDB(t, []interface{}{int(5)}, [][]interface{}{{"ghost-model", 5}})
	meta := buildPricingMetadata(db, context.Background(), "1=1", 5)
	assert.Equal(t, CoverageUnknown, meta.CoverageStatus)
	require.NotNil(t, meta.UnpricedShare)
	assert.InDelta(t, 1, *meta.UnpricedShare, 0, "share stays measured at 1")
	assert.Empty(t, meta.CoverageError, "this is unknown cost, not a measurement failure")
	assert.Equal(t, []string{"ghost-model"}, meta.UnpricedModels)
}

func TestSavingsReportDTO_HasPricingField(t *testing.T) {
	// Compile-time shape check: SavingsReport must expose the pricing block
	// (the wire contract A01 adds).
	share := 0.5
	var r SavingsReport
	r.Pricing = PricingMetadata{PricingAsOf: "x", CoverageStatus: CoveragePartial, UnpricedShare: &share, UnpricedModels: []string{"m"}}
	assert.True(t, strings.HasPrefix(r.Pricing.PricingAsOf, "x"))
	require.NotNil(t, r.Pricing.UnpricedShare)
	assert.InDelta(t, 0.5, *r.Pricing.UnpricedShare, 0)
	assert.Equal(t, CoveragePartial, r.Pricing.CoverageStatus)
}

func TestCostReportDTO_HasPricingField(t *testing.T) {
	var c CostReport
	c.Pricing = PricingMetadata{PricingAsOf: "y"}
	assert.Equal(t, "y", c.Pricing.PricingAsOf)
}
