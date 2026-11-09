package adminstore

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// CreateTeam creates a new team within an organization.
func (s *Store) CreateTeam(ctx context.Context, orgID, name, slug string, parentTeamID *string) (*Team, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var t Team
	var hasParent bool
	err := s.db.QueryRow(ctx,
		`INSERT INTO organizations_teams (org_id, name, slug, parent_team_id)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id::text, org_id::text, name, slug, parent_team_id IS NOT NULL, created_at, updated_at`,
		orgID, name, slug, parentTeamID,
	).Scan(&t.ID, &t.OrgID, &t.Name, &t.Slug, &hasParent, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create team: %w", err)
	}
	if hasParent {
		t.ParentTeam = parentTeamID
	}
	return &t, nil
}

// GetTeamByID returns a team by ID.
func (s *Store) GetTeamByID(ctx context.Context, id string) (*Team, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var t Team
	var hasParent bool
	var parentTeamID sql.NullString
	err := s.db.QueryRow(ctx,
		`SELECT id::text, org_id::text, name, slug, parent_team_id IS NOT NULL, parent_team_id, created_at, updated_at
		 FROM organizations_teams WHERE id = $1`,
		id,
	).Scan(&t.ID, &t.OrgID, &t.Name, &t.Slug, &hasParent, &parentTeamID, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get team: %w", err)
	}
	if hasParent && parentTeamID.Valid {
		t.ParentTeam = &parentTeamID.String
	}
	return &t, nil
}

// ListTeamsByOrg returns a page of teams for an organization.
func (s *Store) ListTeamsByOrg(ctx context.Context, orgID string, f PageFilter) ([]*Team, int64, error) {
	if s.db == nil {
		return nil, 0, fmt.Errorf("database not available")
	}
	if f.PageSize <= 0 {
		f = NewPageFilter(f.Page, f.PageSize)
	}
	var total int64
	if err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM organizations_teams WHERE org_id = $1`, orgID,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count teams: %w", err)
	}
	rows, err := s.db.Query(ctx,
		`SELECT id::text, org_id::text, name, slug, parent_team_id IS NOT NULL, parent_team_id, created_at, updated_at
		 FROM organizations_teams WHERE org_id = $1
		 ORDER BY created_at
		 LIMIT $2 OFFSET $3`,
		orgID, f.PageSize, f.Offset(),
	)
	if err != nil {
		return nil, 0, fmt.Errorf("list teams: %w", err)
	}
	defer rows.Close()
	var teams []*Team
	for rows.Next() {
		var t Team
		var hasParent bool
		var parentTeamID sql.NullString
		t.OrgID = orgID
		if err := rows.Scan(&t.ID, &t.OrgID, &t.Name, &t.Slug, &hasParent, &parentTeamID, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan team: %w", err)
		}
		if hasParent && parentTeamID.Valid {
			t.ParentTeam = &parentTeamID.String
		}
		teams = append(teams, &t)
	}
	return teams, total, rows.Err()
}

// DeleteTeam deletes a team by ID.
func (s *Store) DeleteTeam(ctx context.Context, id string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	result, err := s.db.Exec(ctx,
		`DELETE FROM organizations_teams WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("delete team: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("team not found")
	}
	return nil
}

// UpdateTeam updates name, slug, and/or parent_team_id for a team.
func (s *Store) UpdateTeam(ctx context.Context, id, name, slug string, parentTeamID *string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	var set []string
	var args []interface{}
	n := 1
	set = append(set, "updated_at = now()")
	if name != "" {
		set = append(set, fmt.Sprintf("name = $%d", n))
		args = append(args, name)
		n++
	}
	if slug != "" {
		set = append(set, fmt.Sprintf("slug = $%d", n))
		args = append(args, slug)
		n++
	}
	if parentTeamID != nil {
		set = append(set, fmt.Sprintf("parent_team_id = $%d", n))
		args = append(args, *parentTeamID)
		n++
	}
	args = append(args, id)
	query := fmt.Sprintf(`UPDATE organizations_teams SET %s WHERE id = $%d`, joinSetClauses(set), n)
	if _, err := s.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("update team: %w", err)
	}
	return nil
}

// GetDefaultTeam returns the org's default team (slug='default'), creating
// it if absent. NEXT-01 owner decision 2026-09-18: default-team fallback.
func (s *Store) GetDefaultTeam(ctx context.Context, orgID string) (*Team, error) {
	var t Team
	var hasParent bool
	var parentTeamID sql.NullString
	err := s.db.QueryRow(ctx, `
		SELECT id::text, org_id::text, name, slug, parent_team_id IS NOT NULL, parent_team_id, created_at, updated_at
		FROM organizations_teams
		WHERE org_id = $1 AND slug = 'default'
		LIMIT 1`, orgID).Scan(
		&t.ID, &t.OrgID, &t.Name, &t.Slug, &hasParent, &parentTeamID, &t.CreatedAt, &t.UpdatedAt)
	if err == nil {
		return &t, nil
	}
	if err != pgx.ErrNoRows {
		return nil, fmt.Errorf("get default team: %w", err)
	}
	// Create the default team on first use.
	_, err = s.db.Exec(ctx, `
		INSERT INTO organizations_teams (org_id, name, slug)
		VALUES ($1, 'Default', 'default')
		ON CONFLICT DO NOTHING`, orgID)
	if err != nil {
		return nil, fmt.Errorf("create default team: %w", err)
	}
	err = s.db.QueryRow(ctx, `
		SELECT id::text, org_id::text, name, slug, parent_team_id IS NOT NULL, parent_team_id, created_at, updated_at
		FROM organizations_teams
		WHERE org_id = $1 AND slug = 'default'
		LIMIT 1`, orgID).Scan(
		&t.ID, &t.OrgID, &t.Name, &t.Slug, &hasParent, &parentTeamID, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get default team after create: %w", err)
	}
	if hasParent && parentTeamID.Valid {
		t.ParentTeam = &parentTeamID.String
	}
	return &t, nil
}
