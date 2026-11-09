package regionrouter

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// errOrgNotFound is returned when no org_home_region row exists.
var errOrgNotFound = pgx.ErrNoRows

// PGStore is the *pgxpool.Pool-backed orgStore + orgWriter.
type PGStore struct {
	pool *pgxpool.Pool
}

// NewPGStore creates a DB-backed orgStore from a pgxpool.Pool.
func NewPGStore(pool *pgxpool.Pool) *PGStore { return &PGStore{pool: pool} }

// LookupRegion returns the org's home_region and residency_pinned flag.
func (s *PGStore) LookupRegion(ctx context.Context, orgID string) (string, bool, error) {
	var region string
	var pinned bool
	err := s.pool.QueryRow(ctx,
		`SELECT home_region, residency_pinned FROM org_home_region WHERE org_id=$1`,
		orgID).Scan(&region, &pinned)
	if err != nil {
		return "", false, err
	}
	return region, pinned, nil
}

// UpsertRegion creates or updates the org's home-region mapping.
func (s *PGStore) UpsertRegion(ctx context.Context, orgID, region string, pinned bool) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO org_home_region (org_id, home_region, residency_pinned, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (org_id) DO UPDATE SET
			home_region      = EXCLUDED.home_region,
			residency_pinned = EXCLUDED.residency_pinned,
			updated_at       = now()`,
		orgID, region, pinned)
	return err
}
