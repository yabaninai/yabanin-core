package toolpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
)

// DB is the database surface (pgx pool satisfies it; tests mock it).
type DB interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Store is the tool_policies registry.
type Store struct{ db DB }

// NewStore builds a Store over the DB interface.
func NewStore(db DB) *Store { return &Store{db: db} }

// withOrgTx runs fn inside one transaction whose app.current_org GUC is
// G4, the withOrgTx parity of the adminstore org-scoped stores). The
// binding is transaction-local (set_config ... true): pooled connections
// never leak it, and under the non-owner application role (yabanin_app,
// NOBYPASSRLS) a foreign org's rows are invisible and cross-tenant writes
// are rejected by the policy's WITH CHECK arm — defense in depth under the
// app-level `WHERE org_id = $1` scoping every statement keeps.
func (s *Store) withOrgTx(ctx context.Context, orgID string, fn func(tx pgx.Tx) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("toolpolicy: begin org tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_org', $1, true)", orgID); err != nil {
		return fmt.Errorf("toolpolicy: bind org rls context: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const policyColumns = "id, org_id, name, subject, server, tool, action, rules, priority, enabled, created_at, updated_at"

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// CreateParams is the input for Store.Create (validation is the caller's
// job — the admin handler runs Validate* first). An empty Server normalizes
// to "*" (chat-path rows).
type CreateParams struct {
	OrgID    string
	Name     string
	Subject  string
	Server   string
	Tool     string
	Action   string
	Rules    json.RawMessage
	Priority int
	Enabled  bool
}

// Create inserts a policy; a (org, name) duplicate surfaces as a typed
// error the admin API renders as 409.
func (s *Store) Create(ctx context.Context, p CreateParams) (*Policy, error) {
	if p.Server == "" {
		p.Server = "*"
	}
	var pol *Policy
	err := s.withOrgTx(ctx, p.OrgID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO tool_policies (org_id, name, subject, server, tool, action, rules, priority, enabled)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			RETURNING `+policyColumns,
			p.OrgID, p.Name, p.Subject, p.Server, p.Tool, p.Action, nullableJSON(p.Rules), p.Priority, p.Enabled)
		var err error
		pol, err = scanPolicy(row)
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("toolpolicy: policy %q already exists for this org", p.Name)
			}
			return fmt.Errorf("toolpolicy: create policy: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pol, nil
}

// ListEnabled loads the org's enabled policies (engine loader).
func (s *Store) ListEnabled(ctx context.Context, orgID string) ([]Policy, error) {
	var out []Policy
	err := s.withOrgTx(ctx, orgID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+policyColumns+` FROM tool_policies WHERE org_id = $1 AND enabled ORDER BY name`, orgID)
		if err != nil {
			return fmt.Errorf("toolpolicy: list policies: %w", err)
		}
		defer rows.Close()
		out, err = collect(rows)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// List loads all of the org's policies (admin UI), enabled or not.
func (s *Store) List(ctx context.Context, orgID string) ([]*Policy, error) {
	var out []*Policy
	err := s.withOrgTx(ctx, orgID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+policyColumns+` FROM tool_policies WHERE org_id = $1 ORDER BY name`, orgID)
		if err != nil {
			return fmt.Errorf("toolpolicy: list policies: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var p Policy
			var rules []byte
			if err := rows.Scan(&p.ID, &p.OrgID, &p.Name, &p.Subject, &p.Server, &p.Tool, &p.Action, &rules, &p.Priority, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
				return fmt.Errorf("toolpolicy: scan policy: %w", err)
			}
			if rules != nil {
				p.Rules = json.RawMessage(rules)
			}
			out = append(out, &p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Get returns the policy by name.
func (s *Store) Get(ctx context.Context, orgID, name string) (*Policy, error) {
	var pol *Policy
	err := s.withOrgTx(ctx, orgID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT `+policyColumns+` FROM tool_policies WHERE org_id = $1 AND name = $2`, orgID, name)
		var err error
		pol, err = scanPolicy(row)
		return err
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return pol, nil
}

// UpdateParams patches mutable fields; nil fields are left untouched.
type UpdateParams struct {
	Subject  *string
	Server   *string
	Tool     *string
	Action   *string
	Rules    *json.RawMessage
	Priority *int
	Enabled  *bool
}

// Update patches the policy (org-scoped where clause).
func (s *Store) Update(ctx context.Context, orgID, name string, p UpdateParams) (*Policy, error) {
	sets := []string{"updated_at = now()"}
	args := []any{orgID, name}
	n := 2
	if p.Subject != nil {
		n++
		sets = append(sets, fmt.Sprintf("subject = $%d", n))
		args = append(args, *p.Subject)
	}
	if p.Server != nil {
		n++
		sets = append(sets, fmt.Sprintf("server = $%d", n))
		args = append(args, *p.Server)
	}
	if p.Tool != nil {
		n++
		sets = append(sets, fmt.Sprintf("tool = $%d", n))
		args = append(args, *p.Tool)
	}
	if p.Action != nil {
		n++
		sets = append(sets, fmt.Sprintf("action = $%d", n))
		args = append(args, *p.Action)
	}
	if p.Rules != nil {
		n++
		sets = append(sets, fmt.Sprintf("rules = $%d", n))
		args = append(args, nullableJSON(*p.Rules))
	}
	if p.Priority != nil {
		n++
		sets = append(sets, fmt.Sprintf("priority = $%d", n))
		args = append(args, *p.Priority)
	}
	if p.Enabled != nil {
		n++
		sets = append(sets, fmt.Sprintf("enabled = $%d", n))
		args = append(args, *p.Enabled)
	}
	var pol *Policy
	err := s.withOrgTx(ctx, orgID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`UPDATE tool_policies SET `+strings.Join(sets, ", ")+` WHERE org_id = $1 AND name = $2 RETURNING `+policyColumns,
			args...)
		var err error
		pol, err = scanPolicy(row)
		return err
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return pol, nil
}

// Delete removes the policy (idempotent typed error when absent).
func (s *Store) Delete(ctx context.Context, orgID, name string) error {
	var deleted bool
	err := s.withOrgTx(ctx, orgID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM tool_policies WHERE org_id = $1 AND name = $2`, orgID, name)
		if err != nil {
			return fmt.Errorf("toolpolicy: delete policy: %w", err)
		}
		deleted = tag.RowsAffected() > 0
		return nil
	})
	if err != nil {
		return err
	}
	if !deleted {
		return ErrNotFound
	}
	return nil
}

func scanPolicy(row pgx.Row) (*Policy, error) {
	var p Policy
	var rules []byte
	err := row.Scan(&p.ID, &p.OrgID, &p.Name, &p.Subject, &p.Server, &p.Tool, &p.Action, &rules, &p.Priority, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if rules != nil {
		p.Rules = json.RawMessage(rules)
	}
	return &p, nil
}

func collect(rows pgx.Rows) ([]Policy, error) {
	var out []Policy
	for rows.Next() {
		var p Policy
		var rules []byte
		if err := rows.Scan(&p.ID, &p.OrgID, &p.Name, &p.Subject, &p.Server, &p.Tool, &p.Action, &rules, &p.Priority, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("toolpolicy: scan policy: %w", err)
		}
		if rules != nil {
			p.Rules = json.RawMessage(rules)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// nullableJSON maps an empty rules document to SQL NULL (the column's
// "no rules" value); []byte(nil) is already NULL for pgx.
func nullableJSON(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return nil
	}
	return []byte(raw)
}
