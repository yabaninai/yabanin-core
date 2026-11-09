package adminstore

// AF-07 regressions (ported from the external audit overlay
// artifacts/code-review-2026-10-02/pricing_review_test.go): a failed pricing
// coverage measurement must never serialize as a fully priced report, and any
// Query/Scan/rows.Err failure must be explicitly marked instead of silently
// degrading.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestBuildPricingMetadata_QueryFailureIsUnknownCoverageNotFullyPriced(t *testing.T) {
	db := &mockDB{queryRowFn: func(context.Context, string, ...interface{}) pgx.Row {
		return &mockPGXRow{err: errors.New("coverage query unavailable")}
	}}
	meta := buildPricingMetadata(db, context.Background(), "TRUE", 10)

	raw, err := json.Marshal(meta)
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(raw, &fields))
	require.NotEqual(t, float64(0), fields["unpriced_share"],
		"failed coverage must not serialize as fully priced: %s", raw)
	share, present := fields["unpriced_share"]
	require.True(t, present, "unpriced_share key must stay present (explicit null): %s", raw)
	require.Nil(t, share, "unmeasured coverage must serialize as null, not 0: %s", raw)
	require.Equal(t, CoverageUnknown, fields["coverage_status"])
	require.Equal(t, "coverage query failed", fields["coverage_error"])
	require.NotContains(t, fields["pricing_as_of"], "coverage query failed",
		"provenance must stay separate from failure markers")
}

func TestBuildPricingMetadata_RowsErrIsNotSilentSuccess(t *testing.T) {
	db := &mockDB{
		queryRowFn: func(context.Context, string, ...interface{}) pgx.Row {
			return &mockPGXScalarRow{val: int(3)}
		},
		queryFn: func(context.Context, string, ...interface{}) (pgx.Rows, error) {
			return &mockPGXRows{
				data: [][]interface{}{{"m1", 2}},
				err:  errors.New("connection closed mid-iteration"),
			}, nil
		},
	}
	meta := buildPricingMetadata(db, context.Background(), "TRUE", 10)

	raw, err := json.Marshal(meta)
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(raw, &fields))
	require.NotNil(t, fields["coverage_status"],
		"rows.Err failure must carry an explicit coverage_status marker: %s", raw)
	require.Equal(t, CoveragePartial, fields["coverage_status"],
		"measured share + truncated list = explicitly partial, never complete: %s", raw)
	require.NotEmpty(t, fields["coverage_error"], "rows.Err must be marked: %s", raw)
	require.NotNil(t, fields["unpriced_share"], "the measured share still stands: %s", raw)
}

// scanErrRows fails mid-iteration the way a type mismatch would.
type scanErrRows struct{ *mockPGXRows }

func (r *scanErrRows) Scan(_ ...interface{}) error { return errors.New("cannot scan bool as int") }

func TestBuildPricingMetadata_ScanErrorIsExplicitlyMarked(t *testing.T) {
	db := &mockDB{
		queryRowFn: func(context.Context, string, ...interface{}) pgx.Row {
			return &mockPGXScalarRow{val: int(1)}
		},
		queryFn: func(context.Context, string, ...interface{}) (pgx.Rows, error) {
			return &scanErrRows{mockPGXRows: &mockPGXRows{data: [][]interface{}{{"m1", 1}}}}, nil
		},
	}
	meta := buildPricingMetadata(db, context.Background(), "TRUE", 10)
	require.Equal(t, CoveragePartial, meta.CoverageStatus,
		"scan failure degrades to partial, not an unmarked report")
	require.NotEmpty(t, meta.CoverageError)
	require.NotNil(t, meta.UnpricedModels, "list stays a (possibly truncated) array, not null")
}

func TestBuildPricingMetadata_ListQueryFailureDowngradesCompleteToPartial(t *testing.T) {
	// Share measured 0 (everything priced), but the top-unpriced list query
	// failed: a truncated check must not claim "complete".
	db := &mockDB{
		queryRowFn: func(context.Context, string, ...interface{}) pgx.Row {
			return &mockPGXScalarRow{val: int(0)}
		},
		queryFn: func(context.Context, string, ...interface{}) (pgx.Rows, error) {
			return nil, errors.New("list query failed")
		},
	}
	meta := buildPricingMetadata(db, context.Background(), "TRUE", 4)
	require.Equal(t, CoveragePartial, meta.CoverageStatus,
		"failed list must downgrade complete → partial")
	require.NotEmpty(t, meta.CoverageError)
	require.NotNil(t, meta.UnpricedShare)
	require.InDelta(t, 0, *meta.UnpricedShare, 0)
}
