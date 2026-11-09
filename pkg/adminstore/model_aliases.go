package adminstore

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

// modelAliasPattern matches the chk_model_aliases_alias constraint.
var modelAliasPattern = regexp.MustCompile(`^[A-Za-z0-9._:/@-]{1,128}\*?$`)

// ModelAlias is one row of model_aliases.
type ModelAlias struct {
	Alias       string    `json:"alias"`
	TargetModel string    `json:"target_model"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ValidModelAlias reports whether alias matches the database check.
func ValidModelAlias(alias string) bool {
	return modelAliasPattern.MatchString(alias)
}

// ListModelAliases returns every alias, ordered by name.
func (s *Store) ListModelAliases(ctx context.Context) ([]ModelAlias, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx, `SELECT alias, target_model, created_at, updated_at FROM model_aliases ORDER BY alias`)
	if err != nil {
		return nil, fmt.Errorf("list model aliases: %w", err)
	}
	defer rows.Close()
	var out []ModelAlias
	for rows.Next() {
		var row ModelAlias
		if err := rows.Scan(&row.Alias, &row.TargetModel, &row.CreatedAt, &row.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan model alias: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []ModelAlias{}
	}
	return out, nil
}

// CreateModelAlias inserts an alias. The target must already exist in the registry.
func (s *Store) CreateModelAlias(ctx context.Context, alias, target string) (*ModelAlias, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	if !ValidModelAlias(alias) || target == "" {
		return nil, fmt.Errorf("invalid model alias")
	}
	var row ModelAlias
	err := s.db.QueryRow(ctx, `
		INSERT INTO model_aliases (alias, target_model)
		VALUES ($1, $2)
		RETURNING alias, target_model, created_at, updated_at
	`, alias, target).Scan(&row.Alias, &row.TargetModel, &row.CreatedAt, &row.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create model alias: %w", err)
	}
	return &row, nil
}

// DeleteModelAlias removes an alias. A missing row is an error.
func (s *Store) DeleteModelAlias(ctx context.Context, alias string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	tag, err := s.db.Exec(ctx, `DELETE FROM model_aliases WHERE alias = $1`, alias)
	if err != nil {
		return fmt.Errorf("delete model alias: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("model alias %q not found", alias)
	}
	return nil
}
