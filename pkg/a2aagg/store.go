package a2aagg

// The org-managed registry of external A2A agents (migration 0015). The
// shape mirrors mcpagg's server store: org-scoped CRUD over the DB
// interface (mockable in tests), inert rows until enabled.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
)

// ErrNotFound is returned when an agent row does not exist for the org.
var ErrNotFound = errors.New("a2aagg: agent not found")

// Agent is a row of the a2a_agents registry.
type Agent struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	Name        string    `json:"name"`
	DisplayName *string   `json:"display_name,omitempty"`
	URL         string    `json:"url"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CreateParams is the input for Store.Create.
type CreateParams struct {
	OrgID       string
	Name        string
	DisplayName *string
	URL         string
	Enabled     bool
}

// UpdateParams is the input for Store.Update; nil fields are left untouched.
type UpdateParams struct {
	DisplayName *string
	URL         *string
	Enabled     *bool
}

// DB is the database surface the store needs (pgx pool satisfies it; tests
// provide a mock).
type DB interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Store is the a2a_agents registry.
type Store struct {
	db DB
}

// NewStore builds a Store over the DB interface.
func NewStore(db DB) *Store { return &Store{db: db} }

const agentColumns = "id, org_id, name, display_name, url, enabled, created_at, updated_at"

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// Create inserts a registry row; a (org, name) duplicate is returned as a
// typed error the admin API renders as 409.
func (s *Store) Create(ctx context.Context, p CreateParams) (*Agent, error) {
	row := s.db.QueryRow(ctx, `
		INSERT INTO a2a_agents (org_id, name, display_name, url, enabled)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+agentColumns,
		p.OrgID, p.Name, p.DisplayName, p.URL, p.Enabled)
	a, err := scanAgent(row)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("a2aagg: agent %q already exists for this org", p.Name)
		}
		return nil, fmt.Errorf("a2aagg: create agent: %w", err)
	}
	return a, nil
}

// GetEnabled returns the enabled agent (org, name) or ErrNotFound. The proxy
// uses it — a disabled row is indistinguishable from a missing one to a
// caller.
func (s *Store) GetEnabled(ctx context.Context, orgID, name string) (*Agent, error) {
	row := s.db.QueryRow(ctx,
		`SELECT `+agentColumns+` FROM a2a_agents WHERE org_id = $1 AND name = $2 AND enabled`,
		orgID, name)
	a, err := scanAgent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// Get returns the agent (org, name) regardless of enabled state.
func (s *Store) Get(ctx context.Context, orgID, name string) (*Agent, error) {
	row := s.db.QueryRow(ctx,
		`SELECT `+agentColumns+` FROM a2a_agents WHERE org_id = $1 AND name = $2`,
		orgID, name)
	a, err := scanAgent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// List returns the org's agents ordered by name.
func (s *Store) List(ctx context.Context, orgID string) ([]*Agent, error) {
	rows, err := s.db.Query(ctx,
		`SELECT `+agentColumns+` FROM a2a_agents WHERE org_id = $1 ORDER BY name`, orgID)
	if err != nil {
		return nil, fmt.Errorf("a2aagg: list agents: %w", err)
	}
	defer rows.Close()
	var out []*Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(&a.ID, &a.OrgID, &a.Name, &a.DisplayName, &a.URL, &a.Enabled, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("a2aagg: scan agent: %w", err)
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

// Update patches the mutable fields; the where-clause is org-scoped.
func (s *Store) Update(ctx context.Context, orgID, name string, p UpdateParams) (*Agent, error) {
	sets := []string{"updated_at = now()"}
	args := []any{orgID, name}
	n := 2
	if p.DisplayName != nil {
		n++
		sets = append(sets, fmt.Sprintf("display_name = $%d", n))
		args = append(args, *p.DisplayName)
	}
	if p.URL != nil {
		n++
		sets = append(sets, fmt.Sprintf("url = $%d", n))
		args = append(args, *p.URL)
	}
	if p.Enabled != nil {
		n++
		sets = append(sets, fmt.Sprintf("enabled = $%d", n))
		args = append(args, *p.Enabled)
	}
	row := s.db.QueryRow(ctx,
		`UPDATE a2a_agents SET `+strings.Join(sets, ", ")+` WHERE org_id = $1 AND name = $2 RETURNING `+agentColumns,
		args...)
	a, err := scanAgent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("a2aagg: update agent: %w", err)
	}
	return a, nil
}

// Delete removes the agent row; idempotent (nil when nothing was deleted).
func (s *Store) Delete(ctx context.Context, orgID, name string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM a2a_agents WHERE org_id = $1 AND name = $2`, orgID, name)
	if err != nil {
		return fmt.Errorf("a2aagg: delete agent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func scanAgent(row pgx.Row) (*Agent, error) {
	var a Agent
	err := row.Scan(&a.ID, &a.OrgID, &a.Name, &a.DisplayName, &a.URL, &a.Enabled, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}
