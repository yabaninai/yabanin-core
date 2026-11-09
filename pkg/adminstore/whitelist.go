package adminstore

import (
	"context"
	"fmt"
)

// AddKeyWhitelist adds a model whitelist entry for an API key.
func (s *Store) AddKeyWhitelist(ctx context.Context, apiKeyID, modelName string, allowed bool) (*WhitelistEntry, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var w WhitelistEntry
	err := s.db.QueryRow(ctx,
		`INSERT INTO api_key_model_whitelist (api_key_id, model_name, allowed)
		 VALUES ($1, $2, $3)
		 RETURNING id, api_key_id::text, model_name, allowed, created_at`,
		apiKeyID, modelName, allowed,
	).Scan(&w.ID, &w.TargetID, &w.ModelName, &w.Allowed, &w.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("add key whitelist: %w", err)
	}
	return &w, nil
}

// ListKeyWhitelist returns a page of whitelist entries for an API key.
func (s *Store) ListKeyWhitelist(ctx context.Context, apiKeyID string, f PageFilter) ([]*WhitelistEntry, int64, error) {
	if s.db == nil {
		return nil, 0, fmt.Errorf("database not available")
	}
	if f.PageSize <= 0 {
		f = NewPageFilter(f.Page, f.PageSize)
	}
	var total int64
	if err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM api_key_model_whitelist WHERE api_key_id = $1`, apiKeyID,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count key whitelist: %w", err)
	}
	rows, err := s.db.Query(ctx,
		`SELECT id, api_key_id::text, model_name, allowed, created_at
		 FROM api_key_model_whitelist WHERE api_key_id = $1
		 ORDER BY created_at
		 LIMIT $2 OFFSET $3`,
		apiKeyID, f.PageSize, f.Offset(),
	)
	if err != nil {
		return nil, 0, fmt.Errorf("list key whitelist: %w", err)
	}
	defer rows.Close()

	var entries []*WhitelistEntry
	for rows.Next() {
		var w WhitelistEntry
		w.TargetID = apiKeyID
		if err := rows.Scan(&w.ID, &w.TargetID, &w.ModelName, &w.Allowed, &w.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan whitelist entry: %w", err)
		}
		entries = append(entries, &w)
	}
	return entries, total, rows.Err()
}

// DeleteKeyWhitelist removes a whitelist entry for an API key.
func (s *Store) DeleteKeyWhitelist(ctx context.Context, apiKeyID, modelName string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	result, err := s.db.Exec(ctx,
		`DELETE FROM api_key_model_whitelist WHERE api_key_id = $1 AND model_name = $2`,
		apiKeyID, modelName,
	)
	if err != nil {
		return fmt.Errorf("delete key whitelist: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("whitelist entry not found")
	}
	return nil
}

// AddTeamWhitelist adds a model whitelist entry for a team.
func (s *Store) AddTeamWhitelist(ctx context.Context, teamID, modelName string, allowed bool) (*WhitelistEntry, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var w WhitelistEntry
	err := s.db.QueryRow(ctx,
		`INSERT INTO team_model_whitelist (team_id, model_name, allowed)
		 VALUES ($1, $2, $3)
		 RETURNING id, team_id::text, model_name, allowed, created_at`,
		teamID, modelName, allowed,
	).Scan(&w.ID, &w.TargetID, &w.ModelName, &w.Allowed, &w.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("add team whitelist: %w", err)
	}
	return &w, nil
}

// ListTeamWhitelist returns a page of whitelist entries for a team.
func (s *Store) ListTeamWhitelist(ctx context.Context, teamID string, f PageFilter) ([]*WhitelistEntry, int64, error) {
	if s.db == nil {
		return nil, 0, fmt.Errorf("database not available")
	}
	if f.PageSize <= 0 {
		f = NewPageFilter(f.Page, f.PageSize)
	}
	var total int64
	if err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM team_model_whitelist WHERE team_id = $1`, teamID,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count team whitelist: %w", err)
	}
	rows, err := s.db.Query(ctx,
		`SELECT id, team_id::text, model_name, allowed, created_at
		 FROM team_model_whitelist WHERE team_id = $1
		 ORDER BY created_at
		 LIMIT $2 OFFSET $3`,
		teamID, f.PageSize, f.Offset(),
	)
	if err != nil {
		return nil, 0, fmt.Errorf("list team whitelist: %w", err)
	}
	defer rows.Close()

	var entries []*WhitelistEntry
	for rows.Next() {
		var w WhitelistEntry
		w.TargetID = teamID
		if err := rows.Scan(&w.ID, &w.TargetID, &w.ModelName, &w.Allowed, &w.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan whitelist entry: %w", err)
		}
		entries = append(entries, &w)
	}
	return entries, total, rows.Err()
}

// DeleteTeamWhitelist removes a whitelist entry for a team.
func (s *Store) DeleteTeamWhitelist(ctx context.Context, teamID, modelName string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	result, err := s.db.Exec(ctx,
		`DELETE FROM team_model_whitelist WHERE team_id = $1 AND model_name = $2`,
		teamID, modelName,
	)
	if err != nil {
		return fmt.Errorf("delete team whitelist: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("whitelist entry not found")
	}
	return nil
}

// GetKeyWhitelistEntry returns the whitelist entry for a specific API key and model.
// Returns (nil, false, nil) when no entry exists.
func (s *Store) GetKeyWhitelistEntry(ctx context.Context, apiKeyID, modelName string) (*WhitelistEntry, bool, error) {
	if s.db == nil {
		return nil, false, fmt.Errorf("database not available")
	}
	var w WhitelistEntry
	err := s.db.QueryRow(ctx,
		`SELECT id, api_key_id::text, model_name, allowed, created_at
		 FROM api_key_model_whitelist WHERE api_key_id = $1 AND model_name = $2`,
		apiKeyID, modelName,
	).Scan(&w.ID, &w.TargetID, &w.ModelName, &w.Allowed, &w.CreatedAt)
	if IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("get key whitelist entry: %w", err)
	}
	return &w, true, nil
}

// GetTeamWhitelistEntry returns the whitelist entry for a specific team and model.
// Returns (nil, false, nil) when no entry exists.
func (s *Store) GetTeamWhitelistEntry(ctx context.Context, teamID, modelName string) (*WhitelistEntry, bool, error) {
	if s.db == nil {
		return nil, false, fmt.Errorf("database not available")
	}
	var w WhitelistEntry
	err := s.db.QueryRow(ctx,
		`SELECT id, team_id::text, model_name, allowed, created_at
		 FROM team_model_whitelist WHERE team_id = $1 AND model_name = $2`,
		teamID, modelName,
	).Scan(&w.ID, &w.TargetID, &w.ModelName, &w.Allowed, &w.CreatedAt)
	if IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("get team whitelist entry: %w", err)
	}
	return &w, true, nil
}

// --- Analytics (from request_logs) ---
