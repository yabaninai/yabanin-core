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
// withOnboardingTx runs fn inside one transaction whose app.current_org GUC
// is pinned to the org — the org_isolation RLS policy on org_onboarding
// (FORCE, migration 0001) scopes every read and write to that org. Without
// the GUC the policy denies all rows: the upsert fails the RLS WITH CHECK
// (HTTP 500) and the read silently answers "not onboarded" forever, so the
// welcome flow can never be dismissed (seen live on the quickstart stand).
func (s *Store) withOnboardingTx(ctx context.Context, orgID string, fn func(tx auditTx) error) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	tx, err := s.db.BeginAuditTx(ctx)
	if err != nil {
		return fmt.Errorf("begin org onboarding tx: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_org', $1, true)", orgID); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("set org onboarding isolation GUC: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit org onboarding tx: %w", err)
	}
	return nil
}

func (s *Store) GetOrgOnboarding(ctx context.Context, orgID string) (*OrgOnboarding, error) {
	oid, err := orgUUID(orgID)
	if err != nil {
		return nil, err
	}
	var out *OrgOnboarding
	err = s.withOnboardingTx(ctx, oid.String(), func(tx auditTx) error {
		var row OrgOnboarding
		err := tx.QueryRow(ctx,
			`SELECT org_id::text, completed, skipped FROM org_onboarding WHERE org_id = $1`,
			oid,
		).Scan(&row.OrgID, &row.Completed, &row.Skipped)
		if IsNotFound(err) {
			out = &OrgOnboarding{OrgID: orgID}
			return nil
		}
		if err != nil {
			return fmt.Errorf("get org onboarding: %w", err)
		}
		out = &row
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UpsertOrgOnboarding advances the org's onboarding flags. Only advancing
// marks are accepted: exactly one of completed/skipped must be set, and an
// update ORs the flag in, so a mark can never be revoked through this
// surface. An unknown org (FK violation) is ErrNotFound.
func (s *Store) UpsertOrgOnboarding(ctx context.Context, orgID string, completed, skipped bool) error {
	if completed == skipped { // both false = nothing to mark; both true = conflicting
		return fmt.Errorf("update org onboarding: exactly one of completed/skipped must be set")
	}
	oid, err := orgUUID(orgID)
	if err != nil {
		return err
	}
	return s.withOnboardingTx(ctx, oid.String(), func(tx auditTx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO org_onboarding (org_id, completed, skipped)
			VALUES ($1, $2, $3)
			ON CONFLICT (org_id) DO UPDATE
			    SET completed = org_onboarding.completed OR EXCLUDED.completed,
			        skipped = org_onboarding.skipped OR EXCLUDED.skipped,
			        updated_at = now()`,
			oid, completed, skipped,
		)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" { // foreign_key_violation
			return fmt.Errorf("organization not found: %s: %w", orgID, ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("update org onboarding: %w", err)
		}
		return nil
	})
}
