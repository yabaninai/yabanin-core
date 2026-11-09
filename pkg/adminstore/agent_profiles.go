package adminstore

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// AgentProfile is a reusable agent role template (ADL-06). Issuing a yag_ key
// "on a profile" inherits its settings (tier hint, budget cap, MCP grants).
// Nothing secret is stored — a profile is an authorization template, not a
// credential (the issued key stays hash-only).
type AgentProfile struct {
	ID             string    `json:"id"`
	OrgID          string    `json:"org_id"`
	Name           string    `json:"name"`
	TierHint       string    `json:"tier_hint"`        // routing tier hint (empty = none)
	MCPGrants      []string  `json:"mcp_grants"`       // template grant server names
	BudgetCapCents *int64    `json:"budget_cap_cents"` // per-day cap (NULL = none)
	GuardMode      string    `json:"guard_mode"`       // guard mode (e.g. standard/strict/off)
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// AgentProfileCreateParams is the input for CreateAgentProfile. MCPGrants is
// the template grant set (server names); the caller enforces the invariant that
// these are ⊆ the org's available servers before calling.
type AgentProfileCreateParams struct {
	OrgID          string
	Name           string
	TierHint       string
	MCPGrants      []string
	BudgetCapCents *int64
	GuardMode      string
}

// AgentProfileUpdateParams is a partial update; nil fields are left untouched.
type AgentProfileUpdateParams struct {
	Name           *string
	TierHint       *string
	MCPGrants      *[]string
	BudgetCapCents **int64 // double pointer: nil = no change, &nil = clear
	GuardMode      *string
}

const agentProfileCols = `id::text, org_id::text, name, tier_hint, mcp_grants,
	budget_cap_cents, guard_mode, created_at, updated_at`

func scanAgentProfile(row pgx.Row) (*AgentProfile, error) {
	p := &AgentProfile{}
	var grantsJSON []byte
	if err := row.Scan(&p.ID, &p.OrgID, &p.Name, &p.TierHint, &grantsJSON, &p.BudgetCapCents, &p.GuardMode, &p.CreatedAt, &p.UpdatedAt); err != nil {
		if IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if len(grantsJSON) > 0 {
		if err := json.Unmarshal(grantsJSON, &p.MCPGrants); err != nil {
			return nil, fmt.Errorf("decode agent profile grants: %w", err)
		}
	}
	if p.MCPGrants == nil {
		p.MCPGrants = []string{}
	}
	return p, nil
}

func encodeGrants(grants []string) ([]byte, error) {
	if grants == nil {
		grants = []string{}
	}
	return json.Marshal(grants)
}

// CreateAgentProfile inserts a new profile and returns the row.
func (s *Store) CreateAgentProfile(ctx context.Context, p AgentProfileCreateParams) (*AgentProfile, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	if p.GuardMode == "" {
		p.GuardMode = "standard"
	}
	grantsJSON, err := encodeGrants(p.MCPGrants)
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRow(ctx,
		`INSERT INTO agent_profiles (org_id, name, tier_hint, mcp_grants, budget_cap_cents, guard_mode)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING `+agentProfileCols,
		p.OrgID, p.Name, p.TierHint, grantsJSON, p.BudgetCapCents, p.GuardMode)
	prof, err := scanAgentProfile(row)
	if err != nil {
		return nil, fmt.Errorf("create agent profile: %w", err)
	}
	return prof, nil
}

// GetAgentProfile returns a profile by ID.
func (s *Store) GetAgentProfile(ctx context.Context, id string) (*AgentProfile, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	prof, err := scanAgentProfile(s.db.QueryRow(ctx,
		`SELECT `+agentProfileCols+` FROM agent_profiles WHERE id = $1`, id))
	if err != nil {
		return nil, fmt.Errorf("get agent profile: %w", err)
	}
	return prof, nil
}

// ListAgentProfiles returns profiles for an org (newest first).
func (s *Store) ListAgentProfiles(ctx context.Context, orgID string) ([]*AgentProfile, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx,
		`SELECT `+agentProfileCols+` FROM agent_profiles WHERE org_id = $1 ORDER BY created_at DESC`,
		orgID)
	if err != nil {
		return nil, fmt.Errorf("list agent profiles: %w", err)
	}
	defer rows.Close()
	var out []*AgentProfile
	for rows.Next() {
		p := &AgentProfile{}
		var grantsJSON []byte
		if err := rows.Scan(&p.ID, &p.OrgID, &p.Name, &p.TierHint, &grantsJSON, &p.BudgetCapCents, &p.GuardMode, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan agent profile: %w", err)
		}
		if len(grantsJSON) > 0 {
			_ = json.Unmarshal(grantsJSON, &p.MCPGrants)
		}
		if p.MCPGrants == nil {
			p.MCPGrants = []string{}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdateAgentProfile applies a partial update (nil fields untouched).
func (s *Store) UpdateAgentProfile(ctx context.Context, id string, p AgentProfileUpdateParams) (*AgentProfile, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	sets := []string{}
	args := []interface{}{}
	n := 2
	add := func(col string, v interface{}) {
		args = append(args, v)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, n))
		n++
	}
	if p.Name != nil {
		add("name", *p.Name)
	}
	if p.TierHint != nil {
		add("tier_hint", *p.TierHint)
	}
	if p.MCPGrants != nil {
		g, err := encodeGrants(*p.MCPGrants)
		if err != nil {
			return nil, err
		}
		add("mcp_grants", g)
	}
	if p.BudgetCapCents != nil {
		var capVal interface{}
		if *p.BudgetCapCents != nil {
			capVal = *p.BudgetCapCents
		}
		add("budget_cap_cents", capVal)
	}
	if p.GuardMode != nil {
		add("guard_mode", *p.GuardMode)
	}
	if len(sets) == 0 {
		return s.GetAgentProfile(ctx, id)
	}
	sets = append(sets, "updated_at = now()")
	row := s.db.QueryRow(ctx,
		`UPDATE agent_profiles SET `+strings.Join(sets, ", ")+` WHERE id = $1 RETURNING `+agentProfileCols,
		append([]interface{}{id}, args...)...)
	prof, err := scanAgentProfile(row)
	if err != nil {
		return nil, fmt.Errorf("update agent profile: %w", err)
	}
	return prof, nil
}

// DeleteAgentProfile removes a profile.
func (s *Store) DeleteAgentProfile(ctx context.Context, id string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	tag, err := s.db.Exec(ctx, `DELETE FROM agent_profiles WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete agent profile: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
