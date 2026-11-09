package adminstore

// AF-09: atomic compare-and-set variants for the audited mutation families
// (label, enable, budget, allowlist). The audit journal's rollback replays a
// recorded reverse call; without a server-side precondition that replay can
// overwrite a newer state (10→20→100, rollback of the first → 10 wins).
//
// The contract: the caller passes the expected CURRENT state (the recorded
// after snapshot of the audited change) and the comparison happens inside
// the same SQL statement as the write — a concurrent mutation between the
// check and the write is impossible by construction. No new columns or
// tables: the relevant fields themselves are the CAS token, which is stricter
// and migration-free compared to an updated_at/version token that unrelated
// writers would bump.
//
// On mismatch the methods return ErrPreconditionFailed together with the row's
// current state (nil when the row does not exist) so the handler can answer
// 409 with the current state. A vanished row is reported as ErrNotFound.
// These methods are additive: the plain (non-preconditioned) store methods
// keep their exact previous behavior.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrPreconditionFailed reports that the expected current state no longer
// matches — the mutation was NOT applied.
var ErrPreconditionFailed = errors.New("precondition failed")

// APIKeyLabelsState is the comparable label surface of an API key.
type APIKeyLabelsState struct {
	Labels          map[string]string `json:"labels"`
	LabelsLocked    bool              `json:"labels_locked"`
	CanMintSessions bool              `json:"can_mint_sessions"`
	CanReadUsage    bool              `json:"can_read_usage"`
}

// UpdateAPIKeyActivePreconditioned toggles active while the row still holds
// expectActive (nil = unconditional, same as UpdateAPIKeyActive). Returns
// the row's state: the new value on success, the unchanged current value on
// ErrPreconditionFailed (nil when the row vanished → ErrNotFound).
func (s *Store) UpdateAPIKeyActivePreconditioned(ctx context.Context, id string, active bool, expectActive *bool) (*bool, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var current bool
	err := s.db.QueryRow(ctx,
		`UPDATE api_keys SET active = $1, updated_at = now()
		 WHERE id = $2 AND ($3::boolean IS NULL OR active = $3::boolean)
		 RETURNING active`,
		active, id, expectActive,
	).Scan(&current)
	if IsNotFound(err) {
		// A vanished row is a 404; a live row with a different value is the
		// precondition mismatch.
		var stored bool
		serr := s.db.QueryRow(ctx, `SELECT active FROM api_keys WHERE id = $1`, id).Scan(&stored)
		if IsNotFound(serr) {
			return nil, ErrNotFound
		}
		if serr != nil {
			return nil, fmt.Errorf("update api key active: %w", serr)
		}
		return &stored, ErrPreconditionFailed
	}
	if err != nil {
		return nil, fmt.Errorf("update api key active: %w", err)
	}
	return &current, nil
}

// UpdateRoutingRuleEnabledPreconditioned toggles the enabled flag while the
// rule still holds expectEnabled (nil = unconditional). Returns the row's
// state: the new value on success, the unchanged current value on
// ErrPreconditionFailed (nil when the row vanished → ErrNotFound).
func (s *Store) UpdateRoutingRuleEnabledPreconditioned(ctx context.Context, id string, enabled bool, expectEnabled *bool) (*bool, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var current bool
	err := s.db.QueryRow(ctx,
		`UPDATE routing_rules SET enabled = $1
		 WHERE id = $2 AND ($3::boolean IS NULL OR enabled = $3::boolean)
		 RETURNING enabled`,
		enabled, id, expectEnabled,
	).Scan(&current)
	if IsNotFound(err) {
		var stored bool
		serr := s.db.QueryRow(ctx, `SELECT enabled FROM routing_rules WHERE id = $1`, id).Scan(&stored)
		if IsNotFound(serr) {
			return nil, ErrNotFound
		}
		if serr != nil {
			return nil, fmt.Errorf("update routing rule enabled: %w", serr)
		}
		return &stored, ErrPreconditionFailed
	}
	if err != nil {
		return nil, fmt.Errorf("update routing rule enabled: %w", err)
	}
	return &current, nil
}

// UpdateAPIKeyLabelsPreconditioned stores the label set while the key still
// carries expect (nil = unconditional, same as UpdateAPIKeyLabels). Labels
// are compared as jsonb — order-independent map equality.
func (s *Store) UpdateAPIKeyLabelsPreconditioned(ctx context.Context, id string, labels map[string]string, locked, mint, usage bool, expect *APIKeyLabelsState) (*APIKeyLabelsState, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	if labels == nil {
		labels = map[string]string{}
	}
	raw, err := json.Marshal(labels)
	if err != nil {
		return nil, fmt.Errorf("update api key labels: %w", err)
	}
	var expectRaw []byte
	var expectLocked, expectMint, expectUsage bool
	if expect != nil {
		exp := expect.Labels
		if exp == nil {
			exp = map[string]string{}
		}
		if expectRaw, err = json.Marshal(exp); err != nil {
			return nil, fmt.Errorf("update api key labels: %w", err)
		}
		expectLocked, expectMint, expectUsage = expect.LabelsLocked, expect.CanMintSessions, expect.CanReadUsage
	}
	var current APIKeyLabelsState
	var rawLabels []byte
	err = s.db.QueryRow(ctx,
		`UPDATE api_keys SET labels = $2::jsonb, labels_locked = $3, can_mint_sessions = $4, can_read_usage = $5, updated_at = now()
		 WHERE id = $1 AND ($6::jsonb IS NULL OR (labels = $6::jsonb AND labels_locked = $7 AND can_mint_sessions = $8 AND can_read_usage = $9))
		 RETURNING labels, labels_locked, can_mint_sessions, can_read_usage`,
		id, raw, locked, mint, usage, expectRaw, expectLocked, expectMint, expectUsage,
	).Scan(&rawLabels, &current.LabelsLocked, &current.CanMintSessions, &current.CanReadUsage)
	if IsNotFound(err) {
		var stored APIKeyLabelsState
		var storedRaw []byte
		serr := s.db.QueryRow(ctx,
			`SELECT COALESCE(labels, '{}'::jsonb), labels_locked, can_mint_sessions, can_read_usage FROM api_keys WHERE id = $1`, id,
		).Scan(&storedRaw, &stored.LabelsLocked, &stored.CanMintSessions, &stored.CanReadUsage)
		if IsNotFound(serr) {
			return nil, ErrNotFound
		}
		if serr != nil {
			return nil, fmt.Errorf("update api key labels: %w", serr)
		}
		if uerr := json.Unmarshal(storedRaw, &stored.Labels); uerr != nil {
			return nil, fmt.Errorf("update api key labels: %w", uerr)
		}
		if stored.Labels == nil {
			stored.Labels = map[string]string{}
		}
		return &stored, ErrPreconditionFailed
	}
	if err != nil {
		return nil, fmt.Errorf("update api key labels: %w", err)
	}
	if uerr := json.Unmarshal(rawLabels, &current.Labels); uerr != nil {
		return nil, fmt.Errorf("update api key labels: %w", uerr)
	}
	if current.Labels == nil {
		current.Labels = map[string]string{}
	}
	return &current, nil
}

// TeamBudgetExpectation is the comparable team-budget surface. Absent marks
// "no row exists" — the expected state after an audited budget deletion.
type TeamBudgetExpectation struct {
	Absent          bool    `json:"absent,omitempty"`
	MonthlyLimitUSD float64 `json:"monthly_limit_usd,omitempty"`
	HardLimit       bool    `json:"hard_limit,omitempty"`
}

// UpsertTeamBudgetPreconditioned writes the budget while the stored state
// still matches expect (nil = unconditional, same as UpsertTeamBudget):
// expect.Absent requires the row to not exist; otherwise the stored limit
// and hard flag must equal the expectation. The comparison is part of the
// INSERT..ON CONFLICT statement, so a concurrent budget change conflicts
// instead of being overwritten.
func (s *Store) UpsertTeamBudgetPreconditioned(ctx context.Context, teamID string, monthlyLimit float64, hardLimit bool, expect *TeamBudgetExpectation) (*TeamBudget, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	if expect == nil {
		if err := s.UpsertTeamBudget(ctx, teamID, monthlyLimit, hardLimit); err != nil {
			return nil, err
		}
		return s.GetTeamBudget(ctx, teamID)
	}
	var row scanner
	if expect.Absent {
		row = s.db.QueryRow(ctx,
			`INSERT INTO team_budgets (team_id, monthly_limit_usd, hard_limit)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (team_id) DO NOTHING
			 RETURNING team_id::text, monthly_limit_usd, hard_limit, created_at, updated_at`,
			teamID, monthlyLimit, hardLimit)
	} else {
		row = s.db.QueryRow(ctx,
			`INSERT INTO team_budgets (team_id, monthly_limit_usd, hard_limit)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (team_id) DO UPDATE SET monthly_limit_usd = $2, hard_limit = $3, updated_at = now()
			 WHERE team_budgets.monthly_limit_usd = $4::numeric AND team_budgets.hard_limit = $5
			 RETURNING team_id::text, monthly_limit_usd, hard_limit, created_at, updated_at`,
			teamID, monthlyLimit, hardLimit, expect.MonthlyLimitUSD, expect.HardLimit)
	}
	tb, err := scanTeamBudget(row)
	if IsNotFound(err) {
		current, gerr := s.GetTeamBudget(ctx, teamID)
		if IsNotFound(gerr) {
			// Unreachable for a well-formed statement (no row → plain INSERT
			// path), but report honestly rather than guess.
			return nil, ErrPreconditionFailed
		}
		if gerr != nil {
			return nil, fmt.Errorf("upsert team budget: %w", gerr)
		}
		return current, ErrPreconditionFailed
	}
	if err != nil {
		return nil, fmt.Errorf("upsert team budget: %w", err)
	}
	return tb, nil
}

// DeleteTeamBudgetPreconditioned removes the budget only while it still
// holds the expected limit/hard pair (the recorded after of the audited
// creation). deleted=false + ErrPreconditionFailed carries the current row
// (nil current means the row is already gone — also a mismatch: the
// recorded state is lost, the operator sees the honest "no budget" answer).
func (s *Store) DeleteTeamBudgetPreconditioned(ctx context.Context, teamID string, expect TeamBudgetExpectation) (bool, *TeamBudget, error) {
	if s.db == nil {
		return false, nil, fmt.Errorf("database not available")
	}
	res, err := s.db.Exec(ctx,
		`DELETE FROM team_budgets WHERE team_id = $1 AND monthly_limit_usd = $2::numeric AND hard_limit = $3`,
		teamID, expect.MonthlyLimitUSD, expect.HardLimit,
	)
	if err != nil {
		return false, nil, fmt.Errorf("delete team budget: %w", err)
	}
	if res.RowsAffected() > 0 {
		return true, nil, nil
	}
	current, gerr := s.GetTeamBudget(ctx, teamID)
	if IsNotFound(gerr) {
		return false, nil, ErrPreconditionFailed
	}
	if gerr != nil {
		return false, nil, fmt.Errorf("delete team budget: %w", gerr)
	}
	return false, current, ErrPreconditionFailed
}

// AgentBudgetExpectation is the comparable agent-budget surface.
type AgentBudgetExpectation struct {
	Absent          bool  `json:"absent,omitempty"`
	DailyLimitCents int64 `json:"daily_limit_cents,omitempty"`
}

// UpsertAgentBudgetPreconditioned mirrors UpsertTeamBudgetPreconditioned for
// the per-agent daily cap.
func (s *Store) UpsertAgentBudgetPreconditioned(ctx context.Context, agentID string, dailyLimitCents int64, expect *AgentBudgetExpectation) (*AgentBudget, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	if dailyLimitCents <= 0 {
		return nil, fmt.Errorf("daily_limit_cents must be positive")
	}
	if expect == nil {
		return s.UpsertAgentBudget(ctx, agentID, dailyLimitCents)
	}
	var row scanner
	if expect.Absent {
		row = s.db.QueryRow(ctx,
			`INSERT INTO agent_budgets (agent_id, daily_limit_cents)
			 VALUES ($1::uuid, $2)
			 ON CONFLICT (agent_id) DO NOTHING
			 RETURNING agent_id::text, daily_limit_cents, updated_at`,
			agentID, dailyLimitCents)
	} else {
		row = s.db.QueryRow(ctx,
			`INSERT INTO agent_budgets (agent_id, daily_limit_cents)
			 VALUES ($1::uuid, $2)
			 ON CONFLICT (agent_id) DO UPDATE SET daily_limit_cents = $2, updated_at = now()
			 WHERE agent_budgets.daily_limit_cents = $3
			 RETURNING agent_id::text, daily_limit_cents, updated_at`,
			agentID, dailyLimitCents, expect.DailyLimitCents)
	}
	b, err := scanAgentBudget(row)
	if IsNotFound(err) {
		current, gerr := s.GetAgentBudget(ctx, agentID)
		if IsNotFound(gerr) {
			return nil, ErrPreconditionFailed
		}
		if gerr != nil {
			return nil, fmt.Errorf("upsert agent budget: %w", gerr)
		}
		return current, ErrPreconditionFailed
	}
	if err != nil {
		return nil, fmt.Errorf("upsert agent budget: %w", err)
	}
	return b, nil
}

// DeleteAgentBudgetPreconditioned removes the cap only while it still holds
// the expected value.
func (s *Store) DeleteAgentBudgetPreconditioned(ctx context.Context, agentID string, expectCents int64) (bool, *AgentBudget, error) {
	if s.db == nil {
		return false, nil, fmt.Errorf("database not available")
	}
	res, err := s.db.Exec(ctx,
		`DELETE FROM agent_budgets WHERE agent_id = $1::uuid AND daily_limit_cents = $2`,
		agentID, expectCents,
	)
	if err != nil {
		return false, nil, fmt.Errorf("delete agent budget: %w", err)
	}
	if res.RowsAffected() > 0 {
		return true, nil, nil
	}
	current, gerr := s.GetAgentBudget(ctx, agentID)
	if IsNotFound(gerr) {
		return false, nil, ErrPreconditionFailed
	}
	if gerr != nil {
		return false, nil, fmt.Errorf("delete agent budget: %w", gerr)
	}
	return false, current, ErrPreconditionFailed
}

// AddKeyWhitelistPreconditioned restores a removed allowlist entry only
// while it is still absent (the recorded after of the audited removal). An
// entry that reappeared — with any allowed value — is a mismatch.
func (s *Store) AddKeyWhitelistPreconditioned(ctx context.Context, apiKeyID, modelName string, allowed bool) (*WhitelistEntry, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	w, err := insertWhitelistReturning(s.db.QueryRow(ctx,
		`INSERT INTO api_key_model_whitelist (api_key_id, model_name, allowed)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (api_key_id, model_name) DO NOTHING
		 RETURNING id, api_key_id::text, model_name, allowed, created_at`,
		apiKeyID, modelName, allowed,
	))
	if IsNotFound(err) {
		if current, gerr := s.getKeyWhitelistEntryRow(ctx, apiKeyID, modelName); gerr != nil {
			return nil, fmt.Errorf("add key whitelist: %w", gerr)
		} else {
			return current, ErrPreconditionFailed
		}
	}
	if err != nil {
		return nil, fmt.Errorf("add key whitelist: %w", err)
	}
	return w, nil
}

// DeleteKeyWhitelistPreconditioned removes the entry only while it still
// carries the expected allowed value.
func (s *Store) DeleteKeyWhitelistPreconditioned(ctx context.Context, apiKeyID, modelName string, expectAllowed bool) (bool, *WhitelistEntry, error) {
	if s.db == nil {
		return false, nil, fmt.Errorf("database not available")
	}
	res, err := s.db.Exec(ctx,
		`DELETE FROM api_key_model_whitelist WHERE api_key_id = $1 AND model_name = $2 AND allowed = $3`,
		apiKeyID, modelName, expectAllowed,
	)
	if err != nil {
		return false, nil, fmt.Errorf("delete key whitelist: %w", err)
	}
	if res.RowsAffected() > 0 {
		return true, nil, nil
	}
	current, gerr := s.getKeyWhitelistEntryRow(ctx, apiKeyID, modelName)
	if gerr != nil {
		return false, nil, fmt.Errorf("delete key whitelist: %w", gerr)
	}
	return false, current, ErrPreconditionFailed
}

// AddTeamWhitelistPreconditioned mirrors AddKeyWhitelistPreconditioned.
func (s *Store) AddTeamWhitelistPreconditioned(ctx context.Context, teamID, modelName string, allowed bool) (*WhitelistEntry, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	w, err := insertWhitelistReturning(s.db.QueryRow(ctx,
		`INSERT INTO team_model_whitelist (team_id, model_name, allowed)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (team_id, model_name) DO NOTHING
		 RETURNING id, team_id::text, model_name, allowed, created_at`,
		teamID, modelName, allowed,
	))
	if IsNotFound(err) {
		if current, gerr := s.getTeamWhitelistEntryRow(ctx, teamID, modelName); gerr != nil {
			return nil, fmt.Errorf("add team whitelist: %w", gerr)
		} else {
			return current, ErrPreconditionFailed
		}
	}
	if err != nil {
		return nil, fmt.Errorf("add team whitelist: %w", err)
	}
	return w, nil
}

// DeleteTeamWhitelistPreconditioned mirrors DeleteKeyWhitelistPreconditioned.
func (s *Store) DeleteTeamWhitelistPreconditioned(ctx context.Context, teamID, modelName string, expectAllowed bool) (bool, *WhitelistEntry, error) {
	if s.db == nil {
		return false, nil, fmt.Errorf("database not available")
	}
	res, err := s.db.Exec(ctx,
		`DELETE FROM team_model_whitelist WHERE team_id = $1 AND model_name = $2 AND allowed = $3`,
		teamID, modelName, expectAllowed,
	)
	if err != nil {
		return false, nil, fmt.Errorf("delete team whitelist: %w", err)
	}
	if res.RowsAffected() > 0 {
		return true, nil, nil
	}
	current, gerr := s.getTeamWhitelistEntryRow(ctx, teamID, modelName)
	if gerr != nil {
		return false, nil, fmt.Errorf("delete team whitelist: %w", gerr)
	}
	return false, current, ErrPreconditionFailed
}

// scanTeamBudget scans a full team_budgets row.
func scanTeamBudget(row scanner) (*TeamBudget, error) {
	var tb TeamBudget
	err := row.Scan(&tb.TeamID, &tb.MonthlyLimitUSD, &tb.HardLimit, &tb.CreatedAt, &tb.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &tb, nil
}

// scanAgentBudget scans a full agent_budgets row.
func scanAgentBudget(row scanner) (*AgentBudget, error) {
	var b AgentBudget
	err := row.Scan(&b.AgentID, &b.DailyLimitCents, &b.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// insertWhitelistReturning scans the RETURNING row of a whitelist insert.
func insertWhitelistReturning(row scanner) (*WhitelistEntry, error) {
	var w WhitelistEntry
	if err := row.Scan(&w.ID, &w.TargetID, &w.ModelName, &w.Allowed, &w.CreatedAt); err != nil {
		return nil, err
	}
	return &w, nil
}

// getWhitelistEntryRow / getTeamWhitelistEntryRow return (nil, nil) when the
// entry does not exist.
func (s *Store) getKeyWhitelistEntryRow(ctx context.Context, apiKeyID, modelName string) (*WhitelistEntry, error) {
	entry, exists, err := s.GetKeyWhitelistEntry(ctx, apiKeyID, modelName)
	if err != nil || !exists {
		return nil, err
	}
	return entry, nil
}

func (s *Store) getTeamWhitelistEntryRow(ctx context.Context, teamID, modelName string) (*WhitelistEntry, error) {
	entry, exists, err := s.GetTeamWhitelistEntry(ctx, teamID, modelName)
	if err != nil || !exists {
		return nil, err
	}
	return entry, nil
}
