package adminstore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// CreateAPIKey creates a new API key.
func (s *Store) CreateAPIKey(ctx context.Context, keyHash, name string, orgID, teamID *string) (*APIKey, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var k APIKey
	err := scanAPIKey(s.db.QueryRow(ctx,
		`INSERT INTO api_keys (key_hash, org_id, team_id, name, active) VALUES ($1, $2, $3, $4, true)
		 RETURNING `+rowColumns,
		keyHash, orgID, teamID, name,
	), &k)
	if err != nil {
		return nil, fmt.Errorf("create api key: %w", err)
	}
	return &k, nil
}

// GetAPIKeyByID returns an API key by ID.
func (s *Store) GetAPIKeyByID(ctx context.Context, id string) (*APIKey, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var k APIKey
	err := scanAPIKey(s.db.QueryRow(ctx,
		`SELECT `+rowColumns+` FROM api_keys WHERE id = $1`,
		id,
	), &k)
	if err != nil {
		return nil, fmt.Errorf("get api key: %w", err)
	}
	return &k, nil
}

// ListAPIKeys returns a page of API keys (optionally filtered by org).
func (s *Store) ListAPIKeys(ctx context.Context, orgID *string, f PageFilter) ([]*APIKey, int64, error) {
	if s.db == nil {
		return nil, 0, fmt.Errorf("database not available")
	}
	if f.PageSize <= 0 {
		f = NewPageFilter(f.Page, f.PageSize)
	}
	var args []interface{}
	countQuery := `SELECT count(*) FROM api_keys`
	listQuery := `SELECT ` + rowColumns + ` FROM api_keys`
	if orgID != nil {
		countQuery += " WHERE org_id = $1"
		listQuery += " WHERE org_id = $1"
		args = append(args, *orgID)
	}
	var total int64
	if err := s.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count api keys: %w", err)
	}

	listQuery += f.OrderBy(APIKeySortColumns, "created_at", true) +
		" LIMIT $" + fmt.Sprintf("%d", len(args)+1) +
		" OFFSET $" + fmt.Sprintf("%d", len(args)+2)
	args = append(args, f.PageSize, f.Offset())

	rows, err := s.db.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	var keys []*APIKey
	for rows.Next() {
		var k APIKey
		if err := scanAPIKey(rows, &k); err != nil {
			return nil, 0, fmt.Errorf("scan api key: %w", err)
		}
		keys = append(keys, &k)
	}
	return keys, total, rows.Err()
}

// UpdateAPIKeyActive toggles the active status of an API key.
func (s *Store) UpdateAPIKeyActive(ctx context.Context, id string, active bool) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	_, err := s.db.Exec(ctx,
		`UPDATE api_keys SET active = $1 WHERE id = $2`,
		active, id,
	)
	if err != nil {
		return fmt.Errorf("update api key active: %w", err)
	}
	return nil
}

// DeleteAPIKey deletes an API key by ID.
func (s *Store) DeleteAPIKey(ctx context.Context, id string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	result, err := s.db.Exec(ctx,
		`DELETE FROM api_keys WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("delete api key: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("api key not found")
	}
	return nil
}

// scanAPIKey writes nullable org_id/team_id into *string fields. Passing the
// nil pointer values themselves (k.OrgID, k.TeamID) makes pgx Scan a nil dest
// and panic.
//
// into the *time.Time field as nil.
const rowColumns = `id::text, key_hash, org_id::text, team_id::text, name, active, created_at, COALESCE(labels, '{}'::jsonb), labels_locked, can_mint_sessions, can_read_usage, expires_at, last_used_at, priority`

func scanAPIKey(row scanner, k *APIKey) error {
	var raw []byte
	if err := row.Scan(&k.ID, &k.KeyHash, &k.OrgID, &k.TeamID, &k.Name, &k.Active, &k.CreatedAt, &raw, &k.LabelsLocked, &k.CanMintSessions, &k.CanReadUsage, &k.ExpiresAt, &k.LastUsedAt, &k.Priority); err != nil {
		return err
	}
	// W-SECADM: the hash is internal-only; has_hash tells HTTP clients a key
	// exists without exposing the material.
	k.HasHash = k.KeyHash != ""
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &k.Labels); err != nil {
			return fmt.Errorf("api key labels: %w", err)
		}
	}
	if k.Labels == nil {
		k.Labels = map[string]string{}
	}
	return nil
}

// UpdateAPIKeyExpiry clears the column: NULL means the key never expires. The caller is
// responsible for purging resolver cache entries afterwards so a newly past
// expiry takes effect immediately, not at TTL.
func (s *Store) UpdateAPIKeyExpiry(ctx context.Context, id string, expiresAt *time.Time) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE api_keys SET expires_at = $2, updated_at = now() WHERE id = $1`,
		id, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("update api key expiry: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateAPIKeyLabels stores labels and flags for one key.
func (s *Store) UpdateAPIKeyLabels(ctx context.Context, id string, labels map[string]string, locked, mint, usage bool) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	if labels == nil {
		labels = map[string]string{}
	}
	raw, err := json.Marshal(labels)
	if err != nil {
		return fmt.Errorf("update api key labels: %w", err)
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE api_keys SET labels = $2::jsonb, labels_locked = $3, can_mint_sessions = $4, can_read_usage = $5, updated_at = now() WHERE id = $1`,
		id, raw, locked, mint, usage)
	if err != nil {
		return fmt.Errorf("update api key labels: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetAPIKeyPriority accepts values in (0..9, 5 = default). Out-of-range values are rejected before the DB; an
// unknown key is ErrNotFound.
func (s *Store) SetAPIKeyPriority(ctx context.Context, id string, priority int) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	if !ValidAPIKeyPriority(priority) {
		return fmt.Errorf("priority must be between %d and %d", MinAPIKeyPriority, MaxAPIKeyPriority)
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE api_keys SET priority = $2, updated_at = now() WHERE id = $1`,
		id, priority,
	)
	if err != nil {
		return fmt.Errorf("update api key priority: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("api key not found: %s: %w", id, ErrNotFound)
	}
	return nil
}

// APIKeyPriority resolves one key's rejection-policy priority. An unknown key
// is ErrNotFound; the gateway treats every resolution error as "use the
// default" — fairness is best-effort and never fails a request by itself.
func (s *Store) APIKeyPriority(ctx context.Context, id string) (int, error) {
	if s.db == nil {
		return DefaultAPIKeyPriority, fmt.Errorf("database not available")
	}
	var p int
	if err := s.db.QueryRow(ctx,
		`SELECT priority FROM api_keys WHERE id = $1`, id,
	).Scan(&p); err != nil {
		if IsNotFound(err) {
			return DefaultAPIKeyPriority, fmt.Errorf("api key not found: %s: %w", id, ErrNotFound)
		}
		return DefaultAPIKeyPriority, fmt.Errorf("get api key priority: %w", err)
	}
	return p, nil
}

// --- Models Registry ---

// RotateAPIKey updates the hash for an API key (rotating to a new plaintext).
func (s *Store) RotateAPIKey(ctx context.Context, id, newHash string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	_, err := s.db.Exec(ctx,
		`UPDATE api_keys SET key_hash = $1, updated_at = now() WHERE id = $2`,
		newHash, id,
	)
	if err != nil {
		return fmt.Errorf("rotate api key: %w", err)
	}
	return nil
}

// --- Whitelists ---
