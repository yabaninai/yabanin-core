package adminstore

import (
	"context"
	"fmt"
	"time"
)

// LabelPolicyRow is the stored organization label policy.
type LabelPolicyRow struct {
	Policy    []byte
	UpdatedAt time.Time
	UpdatedBy string
}

// GetLabelPolicy returns the row. ok is false when the org uses the default.
func (s *Store) GetLabelPolicy(ctx context.Context, orgID string) (LabelPolicyRow, bool, error) {
	if s.db == nil {
		return LabelPolicyRow{}, false, fmt.Errorf("database not available")
	}
	var row LabelPolicyRow
	err := s.db.QueryRow(ctx,
		`SELECT policy, updated_at, updated_by FROM label_policies WHERE org_id = $1`, orgID,
	).Scan(&row.Policy, &row.UpdatedAt, &row.UpdatedBy)
	if err != nil {
		if IsNotFound(err) {
			return LabelPolicyRow{}, false, nil
		}
		return LabelPolicyRow{}, false, fmt.Errorf("get label policy: %w", err)
	}
	return row, true, nil
}

// UpsertLabelPolicy stores the compiled-ready policy JSON.
func (s *Store) UpsertLabelPolicy(ctx context.Context, orgID string, policy []byte, updatedBy string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	_, err := s.db.Exec(ctx,
		`INSERT INTO label_policies (org_id, policy, updated_at, updated_by)
		 VALUES ($1, $2, now(), $3)
		 ON CONFLICT (org_id) DO UPDATE
		 SET policy = EXCLUDED.policy, updated_at = now(), updated_by = EXCLUDED.updated_by`,
		orgID, policy, updatedBy)
	if err != nil {
		return fmt.Errorf("upsert label policy: %w", err)
	}
	return nil
}

// DeleteLabelPolicy removes the stored policy so the org falls back to the default.
func (s *Store) DeleteLabelPolicy(ctx context.Context, orgID string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	_, err := s.db.Exec(ctx, `DELETE FROM label_policies WHERE org_id = $1`, orgID)
	if err != nil {
		return fmt.Errorf("delete label policy: %w", err)
	}
	return nil
}
