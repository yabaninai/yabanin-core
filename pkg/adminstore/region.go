package adminstore

// services/admin/handlers/region_handlers.go. Every statement below is the
// byte-equivalent of the handler query it replaces.

import (
	"context"
	"fmt"
)

// GetOrgHomeRegion returns the home-region assignment for an org. The error
// contract is typed: a missing row surfaces as pgx.ErrNoRows (distinguishable
// via errors.Is — the org was never pinned; the handler answers the
// documented "sg" default), while any other failure (outage, timeout,
// miswiring) propagates unchanged so callers never mistake "no row" for
// "store unavailable" (A04).
func (s *Store) GetOrgHomeRegion(ctx context.Context, orgID string) (string, bool, error) {
	if s.db == nil {
		return "", false, fmt.Errorf("database not configured")
	}
	var region string
	var pinned bool
	err := s.db.QueryRow(ctx,
		`SELECT home_region, residency_pinned FROM org_home_region WHERE org_id=$1`, orgID).Scan(&region, &pinned)
	if err != nil {
		return "", false, err
	}
	return region, pinned, nil
}

// UpsertOrgHomeRegion upserts the org home-region assignment. Upsert
// failures (including store outages) propagate unchanged — the handler maps
// them to a non-2xx response; nothing is silently dropped.
func (s *Store) UpsertOrgHomeRegion(ctx context.Context, orgID, homeRegion string, pinned bool) error {
	if s.db == nil {
		return fmt.Errorf("database not configured")
	}
	_, err := s.db.Exec(ctx, `
		INSERT INTO org_home_region (org_id, home_region, residency_pinned, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (org_id) DO UPDATE SET
			home_region      = EXCLUDED.home_region,
			residency_pinned = EXCLUDED.residency_pinned,
			updated_at       = now()`,
		orgID, homeRegion, pinned)
	return err
}
