package adminstore

// A04 (audit artifacts/preview-audit-20261101/AUDIT.txt §A04; cards
// N09-P05-T05 / N07-P07 error-honesty aspect): the region store keeps the
// typed no-row contract — a missing org_home_region row surfaces as the
// canonical pgx.ErrNoRows sentinel (distinguishable via errors.Is, the same
// mechanism sqlcontract_region_int_test.go pins against real Postgres),
// while any other failure (outage, timeout, miswiring) propagates unchanged
// so callers never confuse "org never pinned" with "store unavailable".
// These unit tests pin the distinction without a live pool.

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetOrgHomeRegion_NoRowSurfacesTypedErrNoRows(t *testing.T) {
	s := &Store{db: &mockDB{
		queryRowFn: func(_ context.Context, _ string, _ ...interface{}) pgx.Row {
			return &mockPGXRow{err: pgx.ErrNoRows}
		},
	}}
	region, pinned, err := s.GetOrgHomeRegion(context.Background(), "org-never-pinned")
	require.ErrorIs(t, err, pgx.ErrNoRows,
		"a missing assignment row must surface as the typed pgx.ErrNoRows sentinel")
	assert.Empty(t, region, "no zero-value masquerading beside a no-row error")
	assert.False(t, pinned)
}

func TestGetOrgHomeRegion_OutageIsNotTheNoRowSentinel(t *testing.T) {
	outage := errors.New("simulated store outage: connection refused")
	s := &Store{db: &mockDB{
		queryRowFn: func(_ context.Context, _ string, _ ...interface{}) pgx.Row {
			return &mockPGXRow{err: outage}
		},
	}}
	region, pinned, err := s.GetOrgHomeRegion(context.Background(), "org-1")
	require.Error(t, err, "a store outage must be an error")
	require.NotErrorIs(t, err, pgx.ErrNoRows,
		"an outage must stay distinguishable from a missing row — the handler relies on it")
	require.ErrorIs(t, err, outage, "the outage error must propagate unchanged (identity preserved)")
	assert.Empty(t, region)
	assert.False(t, pinned)
}

func TestGetOrgHomeRegion_RowValues(t *testing.T) {
	s := &Store{db: &mockDB{
		queryRowFn: func(_ context.Context, _ string, _ ...interface{}) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{{"eu", true}}}
		},
	}}
	region, pinned, err := s.GetOrgHomeRegion(context.Background(), "org-1")
	require.NoError(t, err)
	assert.Equal(t, "eu", region)
	assert.True(t, pinned)
}

func TestUpsertOrgHomeRegion_OutagePropagates(t *testing.T) {
	outage := errors.New("simulated store outage: connection refused")
	s := &Store{db: &mockDB{
		execFn: func(_ context.Context, _ string, _ ...interface{}) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, outage
		},
	}}
	err := s.UpsertOrgHomeRegion(context.Background(), "org-1", "eu", true)
	require.ErrorIs(t, err, outage,
		"an upsert outage must propagate unchanged; the handler decides the HTTP status")
}

func TestRegionStore_NilDBIsNotTheNoRowSentinel(t *testing.T) {
	s := &Store{} // unwired store is a miswiring, never a missing row
	_, _, err := s.GetOrgHomeRegion(context.Background(), "org-1")
	require.Error(t, err)
	require.NotErrorIs(t, err, pgx.ErrNoRows,
		"a miswired store must not read as the no-row default")
	err = s.UpsertOrgHomeRegion(context.Background(), "org-1", "eu", true)
	require.Error(t, err)
}
