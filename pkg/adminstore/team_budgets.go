package adminstore

import (
	"context"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// P6.10: Team budgets — per-team monthly spend limits.
// ---------------------------------------------------------------------------

// TeamBudget holds the budget configuration for a team.
type TeamBudget struct {
	TeamID          string    `json:"team_id"`
	MonthlyLimitUSD float64   `json:"monthly_limit_usd"`
	HardLimit       bool      `json:"hard_limit"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// TeamSpendSummary holds current month spend for a team.
type TeamSpendSummary struct {
	TeamID          string  `json:"team_id"`
	Period          string  `json:"period"`
	SpendUSD        float64 `json:"spend_usd"`
	RequestCount    int64   `json:"request_count"`
	MonthlyLimitUSD float64 `json:"monthly_limit_usd"`
	HardLimit       bool    `json:"hard_limit"`
}

// GetTeamBudget returns the budget configuration for a team.
func (s *Store) GetTeamBudget(ctx context.Context, teamID string) (*TeamBudget, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	var tb TeamBudget
	err := s.db.QueryRow(ctx,
		`SELECT team_id::text, monthly_limit_usd, hard_limit, created_at, updated_at FROM team_budgets WHERE team_id = $1`,
		teamID,
	).Scan(&tb.TeamID, &tb.MonthlyLimitUSD, &tb.HardLimit, &tb.CreatedAt, &tb.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get team budget: %w", err)
	}
	return &tb, nil
}

// UpsertTeamBudget creates or updates the budget for a team.
func (s *Store) UpsertTeamBudget(ctx context.Context, teamID string, monthlyLimit float64, hardLimit bool) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	_, err := s.db.Exec(ctx,
		`INSERT INTO team_budgets (team_id, monthly_limit_usd, hard_limit)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (team_id) DO UPDATE SET monthly_limit_usd = $2, hard_limit = $3, updated_at = now()`,
		teamID, monthlyLimit, hardLimit,
	)
	if err != nil {
		return fmt.Errorf("upsert team budget: %w", err)
	}
	return nil
}

// DeleteTeamBudget removes the budget for a team.
func (s *Store) DeleteTeamBudget(ctx context.Context, teamID string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	_, err := s.db.Exec(ctx, `DELETE FROM team_budgets WHERE team_id = $1`, teamID)
	if err != nil {
		return fmt.Errorf("delete team budget: %w", err)
	}
	return nil
}

// GetTeamSpendSummary returns current month spend and budget for a team.
func (s *Store) GetTeamSpendSummary(ctx context.Context, teamID string) (*TeamSpendSummary, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	period := time.Now().UTC().Format("2006-01")

	var summary TeamSpendSummary
	summary.TeamID = teamID
	summary.Period = period

	// Get spend from monthly aggregate.
	_ = s.db.QueryRow(ctx,
		`SELECT COALESCE(spend_usd, 0), COALESCE(request_count, 0) FROM team_spend_monthly WHERE team_id = $1 AND period = $2`,
		teamID, period,
	).Scan(&summary.SpendUSD, &summary.RequestCount)

	// Get budget config (may not exist). Absence of the row is fail-closed
	// (mirrors agent_budgets): the summary must not present an unbudgeted
	// team as soft-limited, so the hard defaults are preset and only a real
	// row (or a NULL hard_limit via COALESCE) may change them.
	summary.MonthlyLimitUSD, summary.HardLimit = 0, true
	_ = s.db.QueryRow(ctx,
		`SELECT COALESCE(monthly_limit_usd, 0), COALESCE(hard_limit, true) FROM team_budgets WHERE team_id = $1`,
		teamID,
	).Scan(&summary.MonthlyLimitUSD, &summary.HardLimit)

	return &summary, nil
}

// ListTeamBudgetsByOrg returns all teams with budgets for an org.
func (s *Store) ListTeamBudgetsByOrg(ctx context.Context, orgID string) ([]TeamSpendSummary, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	period := time.Now().UTC().Format("2006-01")

	rows, err := s.db.Query(ctx,
		`SELECT tb.team_id::text, COALESCE(tsm.spend_usd, 0), COALESCE(tsm.request_count, 0),
		        tb.monthly_limit_usd, tb.hard_limit
		 FROM team_budgets tb
		 JOIN organizations_teams ot ON ot.id = tb.team_id
		 LEFT JOIN team_spend_monthly tsm ON tsm.team_id = tb.team_id AND tsm.period = $2
		 WHERE ot.org_id = $1`,
		orgID, period,
	)
	if err != nil {
		return nil, fmt.Errorf("list team budgets by org: %w", err)
	}
	defer rows.Close()

	var results []TeamSpendSummary
	for rows.Next() {
		var s TeamSpendSummary
		s.Period = period
		if err := rows.Scan(&s.TeamID, &s.SpendUSD, &s.RequestCount, &s.MonthlyLimitUSD, &s.HardLimit); err != nil {
			return nil, fmt.Errorf("scan team budget: %w", err)
		}
		results = append(results, s)
	}
	return results, rows.Err()
}
