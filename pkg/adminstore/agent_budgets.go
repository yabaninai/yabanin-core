package adminstore

import (
	"context"
	"fmt"
	"time"
)

// AgentBudget is the per-agent daily spend limit (G2). Absence of a row means
// the agent may not spend (fail-closed, mirrors team_budgets).
type AgentBudget struct {
	AgentID         string    `json:"agent_id"`
	DailyLimitCents int64     `json:"daily_limit_cents"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// GetAgentBudget returns the agent's daily limit row.
func (s *Store) GetAgentBudget(ctx context.Context, agentID string) (*AgentBudget, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var b AgentBudget
	err := s.db.QueryRow(ctx,
		`SELECT agent_id::text, daily_limit_cents, updated_at FROM agent_budgets WHERE agent_id = $1`,
		agentID).Scan(&b.AgentID, &b.DailyLimitCents, &b.UpdatedAt)
	if err != nil {
		if IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get agent budget: %w", err)
	}
	return &b, nil
}

// UpsertAgentBudget creates or updates the agent's daily limit. A limit <= 0
// rejects (a zero limit would mean "deny everything" — use revoke instead).
func (s *Store) UpsertAgentBudget(ctx context.Context, agentID string, dailyLimitCents int64) (*AgentBudget, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	if dailyLimitCents <= 0 {
		return nil, fmt.Errorf("daily_limit_cents must be positive")
	}
	var b AgentBudget
	err := s.db.QueryRow(ctx, `
		INSERT INTO agent_budgets (agent_id, daily_limit_cents)
		VALUES ($1::uuid, $2)
		ON CONFLICT (agent_id) DO UPDATE SET daily_limit_cents = $2, updated_at = now()
		RETURNING agent_id::text, daily_limit_cents, updated_at`,
		agentID, dailyLimitCents).Scan(&b.AgentID, &b.DailyLimitCents, &b.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("upsert agent budget: %w", err)
	}
	return &b, nil
}

// DeleteAgentBudget removes the limit row — the agent goes back to
// "no budget configured" (denied) until a new row is set.
func (s *Store) DeleteAgentBudget(ctx context.Context, agentID string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	res, err := s.db.Exec(ctx, `DELETE FROM agent_budgets WHERE agent_id = $1`, agentID)
	if err != nil {
		return fmt.Errorf("delete agent budget: %w", err)
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
