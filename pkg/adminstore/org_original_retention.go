package adminstore

import (
	"context"
	"fmt"
)

// OriginalRetentionPlatformDefault is fail-closed: orgs with no explicit
// choice retain processed content only.
const OriginalRetentionPlatformDefault = false

// OrgOriginalRetention separates an org's nullable override from its effective
// value. A nil override explicitly inherits the platform default.
type OrgOriginalRetention struct {
	OrgID     string `json:"org_id"`
	Enabled   *bool  `json:"enabled"`
	Effective bool   `json:"effective_enabled"`
	Inherited bool   `json:"inherited"`
}

// getOrgOriginalRetentionOn resolves the org override and effective setting
// on the given executor — the pool or a read snapshot transaction — so a
// disclosure boundary can evaluate retention inside the same point-in-time
// snapshot as the data it governs.
func getOrgOriginalRetentionOn(ctx context.Context, ex exportQueryRunner, orgID string) (*OrgOriginalRetention, error) {
	var setting OrgOriginalRetention
	err := ex.QueryRow(ctx, `
		SELECT id::text, retain_original_text
		FROM organizations WHERE id = $1`, orgID,
	).Scan(&setting.OrgID, &setting.Enabled)
	if IsNotFound(err) {
		return nil, fmt.Errorf("org not found: %s: %w", orgID, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get org original retention: %w", err)
	}
	setting.Inherited = setting.Enabled == nil
	setting.Effective = OriginalRetentionPlatformDefault
	if setting.Enabled != nil {
		setting.Effective = *setting.Enabled
	}
	return &setting, nil
}

// GetOrgOriginalRetention returns the org override and effective setting.
func (s *Store) GetOrgOriginalRetention(ctx context.Context, orgID string) (*OrgOriginalRetention, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	return getOrgOriginalRetentionOn(ctx, s.db, orgID)
}

// UpdateOrgOriginalRetention sets an explicit org override; nil restores
// inheritance from the platform default.
func (s *Store) UpdateOrgOriginalRetention(ctx context.Context, orgID string, enabled *bool) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	tag, err := s.db.Exec(ctx, `
		UPDATE organizations SET retain_original_text = $2, updated_at = now()
		WHERE id = $1`, orgID, enabled)
	if err != nil {
		return fmt.Errorf("update org original retention: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("org not found: %s: %w", orgID, ErrNotFound)
	}
	return nil
}
