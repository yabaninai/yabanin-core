package cache

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	pgxpool "github.com/jackc/pgx/v5/pgxpool"
)

// Experiment represents an A/B experiment for cache configuration.
type Experiment struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	OrgID            string    `json:"org_id"`
	ControlVariant   string    `json:"control_variant"`
	TreatmentVariant string    `json:"treatment_variant"`
	TrafficPct       int       `json:"traffic_pct"`
	Enabled          bool      `json:"enabled"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// Assignment represents a sticky A/B assignment.
type Assignment struct {
	ExperimentID string    `json:"experiment_id"`
	OrgID        string    `json:"org_id"`
	Variant      string    `json:"variant"`
	AssignedAt   time.Time `json:"assigned_at"`
}

// ExperimentStore provides CRUD operations for A/B experiments and sticky assignments.
type ExperimentStore struct {
	pool *pgxpool.Pool
}

// NewExperimentStore creates a new DB-backed experiment store.
func NewExperimentStore(pool *pgxpool.Pool) *ExperimentStore {
	return &ExperimentStore{pool: pool}
}

// CreateExperiment creates a new A/B experiment.
func (s *ExperimentStore) CreateExperiment(ctx context.Context, name, orgID string, trafficPct int) (*Experiment, error) {
	if s.pool == nil {
		return nil, fmt.Errorf("experiment store: no database")
	}

	var exp Experiment
	err := s.pool.QueryRow(ctx, `
		INSERT INTO ab_experiments (name, org_id, traffic_pct)
		VALUES ($1, $2, $3)
		RETURNING id, name, org_id, control_variant, treatment_variant, traffic_pct, enabled, created_at, updated_at
	`, name, orgID, trafficPct).Scan(
		&exp.ID, &exp.Name, &exp.OrgID, &exp.ControlVariant, &exp.TreatmentVariant,
		&exp.TrafficPct, &exp.Enabled, &exp.CreatedAt, &exp.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create experiment: %w", err)
	}
	return &exp, nil
}

// GetExperiment returns an experiment by ID.
func (s *ExperimentStore) GetExperiment(ctx context.Context, id string) (*Experiment, error) {
	if s.pool == nil {
		return nil, fmt.Errorf("experiment store: no database")
	}

	var exp Experiment
	err := s.pool.QueryRow(ctx, "SELECT id, name, org_id, control_variant, treatment_variant, traffic_pct, enabled, created_at, updated_at FROM ab_experiments WHERE id = $1", id).Scan(
		&exp.ID, &exp.Name, &exp.OrgID, &exp.ControlVariant, &exp.TreatmentVariant,
		&exp.TrafficPct, &exp.Enabled, &exp.CreatedAt, &exp.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get experiment: %w", err)
	}
	return &exp, nil
}

// ListExperiments returns all experiments (optionally filtered by org_id and enabled).
func (s *ExperimentStore) ListExperiments(ctx context.Context, orgID string, onlyEnabled bool) ([]*Experiment, error) {
	if s.pool == nil {
		return nil, fmt.Errorf("experiment store: no database")
	}

	query := "SELECT id, name, org_id, control_variant, treatment_variant, traffic_pct, enabled, created_at, updated_at FROM ab_experiments WHERE 1=1"
	var args []interface{}
	argIdx := 1

	if orgID != "" {
		query += fmt.Sprintf(" AND org_id = $%d", argIdx)
		args = append(args, orgID)
	}
	if onlyEnabled {
		query += " AND enabled = true"
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list experiments: %w", err)
	}
	defer rows.Close()

	var results []*Experiment
	for rows.Next() {
		var exp Experiment
		if err := rows.Scan(
			&exp.ID, &exp.Name, &exp.OrgID, &exp.ControlVariant, &exp.TreatmentVariant,
			&exp.TrafficPct, &exp.Enabled, &exp.CreatedAt, &exp.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan experiment: %w", err)
		}
		results = append(results, &exp)
	}
	return results, rows.Err()
}

// UpdateExperiment updates an experiment's traffic percentage and/or enabled status.
func (s *ExperimentStore) UpdateExperiment(ctx context.Context, id string, trafficPct *int, enabled *bool) error {
	if s.pool == nil {
		return fmt.Errorf("experiment store: no database")
	}

	var set []string
	var args []interface{}
	n := 1

	if trafficPct != nil {
		set = append(set, fmt.Sprintf("traffic_pct = $%d", n))
		args = append(args, *trafficPct)
		n++
	}
	if enabled != nil {
		set = append(set, fmt.Sprintf("enabled = $%d", n))
		args = append(args, *enabled)
		n++
	}
	set = append(set, "updated_at = now()")
	args = append(args, id)

	query := fmt.Sprintf("UPDATE ab_experiments SET %s WHERE id = $%d", joinSetClauses(set), n)
	if _, err := s.pool.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("update experiment: %w", err)
	}
	return nil
}

// DeleteExperiment deletes an experiment and its assignments.
func (s *ExperimentStore) DeleteExperiment(ctx context.Context, id string) error {
	if s.pool == nil {
		return fmt.Errorf("experiment store: no database")
	}
	if _, err := s.pool.Exec(ctx, "DELETE FROM ab_experiments WHERE id = $1", id); err != nil {
		return fmt.Errorf("delete experiment: %w", err)
	}
	return nil
}

// AssignAssignment ensures a sticky assignment exists for an experiment+org combo.
// If no assignment exists, it creates one using deterministic hash-based bucketing.
func (s *ExperimentStore) AssignAssignment(ctx context.Context, experimentID, orgID string) (*Assignment, error) {
	if s.pool == nil {
		return nil, fmt.Errorf("experiment store: no database")
	}

	// Check if assignment already exists (sticky).
	var existing Assignment
	err := s.pool.QueryRow(ctx, "SELECT experiment_id, org_id, variant, assigned_at FROM ab_assignments WHERE experiment_id = $1 AND org_id = $2", experimentID, orgID).Scan(
		&existing.ExperimentID, &existing.OrgID, &existing.Variant, &existing.AssignedAt,
	)
	if err == nil {
		return &existing, nil // sticky: return existing assignment
	}

	// Get experiment to determine bucketing.
	var exp Experiment
	err = s.pool.QueryRow(ctx, "SELECT traffic_pct, control_variant, treatment_variant FROM ab_experiments WHERE id = $1 AND enabled = true", experimentID).Scan(
		&exp.TrafficPct, &exp.ControlVariant, &exp.TreatmentVariant,
	)
	if err != nil {
		return nil, fmt.Errorf("get experiment for assignment: %w", err)
	}

	// Deterministic bucketing: hash(org_id + experiment_id) % 100 < traffic_pct.
	h := sha256.Sum256([]byte(orgID + ":" + experimentID))
	bucket := int(h[0]) % 100
	variant := exp.ControlVariant
	if bucket < exp.TrafficPct {
		variant = exp.TreatmentVariant
	}

	// Upsert assignment (PRIMARY KEY on experiment_id, org_id).
	_, err = s.pool.Exec(ctx, `
		INSERT INTO ab_assignments (experiment_id, org_id, variant)
		VALUES ($1, $2, $3)
		ON CONFLICT (experiment_id, org_id) DO NOTHING
	`, experimentID, orgID, variant)
	if err != nil {
		return nil, fmt.Errorf("insert assignment: %w", err)
	}

	return &Assignment{
		ExperimentID: experimentID,
		OrgID:        orgID,
		Variant:      variant,
		AssignedAt:   time.Now(),
	}, nil
}

// GetResults returns savings per variant for an experiment.
func (s *ExperimentStore) GetResults(ctx context.Context, experimentID string) (map[string]float64, error) {
	if s.pool == nil {
		return nil, fmt.Errorf("experiment store: no database")
	}

	var controlSavings, treatmentSavings float64

	err := s.pool.QueryRow(ctx, `
		SELECT
			COALESCE(SUM(CASE WHEN a.variant = 'control' THEN rl.counterfactual_cost_usd ELSE 0 END), 0) AS control_savings,
			COALESCE(SUM(CASE WHEN a.variant = 'treatment' THEN rl.counterfactual_cost_usd ELSE 0 END), 0) AS treatment_savings
		FROM ab_assignments a
		JOIN request_logs rl ON rl.org_id = a.org_id AND rl.cache_hit_type IS NOT NULL
		WHERE a.experiment_id = $1
	`, experimentID).Scan(&controlSavings, &treatmentSavings)
	if err != nil {
		return nil, fmt.Errorf("get results: %w", err)
	}

	return map[string]float64{
		"control_savings_usd":   controlSavings,
		"treatment_savings_usd": treatmentSavings,
	}, nil
}

// joinSetClauses joins SQL SET clauses with commas.
func joinSetClauses(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for _, p := range parts[1:] {
		result += ", " + p
	}
	return result
}
