package adminstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
)

// OrgOnboarding is the per-organization onboarding progress flag (card
// W-WELCOME): the only server-persisted part of the dashboard's 3-step
// welcome flow. completed and skipped are mutually exclusive advancing marks
// — step detection itself is derived live from the existing APIs
// (provider-credentials, api-keys, request stats), never stored here.
type OrgOnboarding struct {
	OrgID     string `json:"org_id"`
	Completed bool   `json:"completed"`
	Skipped   bool   `json:"skipped"`
}

// GetOrgOnboarding returns the onboarding state for an organization. A
// missing row is NOT an error: an org that never answered the flow simply has
// not onboarded, and the zero state (false/false) is the honest answer — the
// authorization concern (does the caller belong to this org at all) is the
// route middleware's, not the store's.
func (s *Store) GetOrgOnboarding(ctx context.Context, orgID string) (*OrgOnboarding, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	oid, err := orgUUID(orgID)
	if err != nil {
		return nil, err
	}
	out := OrgOnboarding{OrgID: orgID}
	err = s.withOrgTx(ctx, oid.String(), func(tx auditTx) error {
		err := tx.QueryRow(ctx,
			`SELECT org_id::text, completed, skipped FROM org_onboarding WHERE org_id = $1`,
			oid,
		).Scan(&out.OrgID, &out.Completed, &out.Skipped)
		if IsNotFound(err) {
			return nil
		}
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("get org onboarding: %w", err)
	}
	return &out, nil
}

// UpsertOrgOnboarding advances the org's onboarding flags. Only advancing
// marks are accepted: exactly one of completed/skipped must be set, and an
// update ORs the flag in, so a mark can never be revoked through this
// surface. An unknown org (FK violation) is ErrNotFound.
func (s *Store) UpsertOrgOnboarding(ctx context.Context, orgID string, completed, skipped bool) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	if completed == skipped { // both false = nothing to mark; both true = conflicting
		return fmt.Errorf("update org onboarding: exactly one of completed/skipped must be set")
	}
	oid, err := orgUUID(orgID)
	if err != nil {
		return err
	}
	err = s.withOrgTx(ctx, oid.String(), func(tx auditTx) error {
		_, err := tx.Exec(ctx, `
		INSERT INTO org_onboarding (org_id, completed, skipped)
		VALUES ($1, $2, $3)
		ON CONFLICT (org_id) DO UPDATE
		    SET completed = org_onboarding.completed OR EXCLUDED.completed,
		        skipped = org_onboarding.skipped OR EXCLUDED.skipped,
		        updated_at = now()`,
			oid, completed, skipped,
		)
		return err
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" { // foreign_key_violation
		return fmt.Errorf("organization not found: %s: %w", orgID, ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("update org onboarding: %w", err)
	}
	return nil
}
