package adminstore

import (
	"context"
	"fmt"
)

// CreateRoutingRule creates a new routing rule.
func (s *Store) CreateRoutingRule(ctx context.Context, orgID, matchExpr, targetModel string, priority int) (*RoutingRule, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var r RoutingRule
	err := s.db.QueryRow(ctx,
		`INSERT INTO routing_rules (org_id, match_expr, target_model, priority)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id::text, org_id::text, match_expr, target_model, priority, enabled, created_at`,
		orgID, matchExpr, targetModel, priority,
	).Scan(&r.ID, &r.OrgID, &r.MatchExpr, &r.TargetModel, &r.Priority, &r.Enabled, &r.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create routing rule: %w", err)
	}
	return &r, nil
}

// GetRoutingRuleByID returns a routing rule by ID.
func (s *Store) GetRoutingRuleByID(ctx context.Context, id string) (*RoutingRule, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var r RoutingRule
	err := s.db.QueryRow(ctx,
		`SELECT id::text, org_id::text, match_expr, target_model, priority, enabled, created_at
		 FROM routing_rules WHERE id = $1`,
		id,
	).Scan(&r.ID, &r.OrgID, &r.MatchExpr, &r.TargetModel, &r.Priority, &r.Enabled, &r.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get routing rule: %w", err)
	}
	return &r, nil
}

// ListRoutingRulesByOrg returns a page of rules for an organization.
func (s *Store) ListRoutingRulesByOrg(ctx context.Context, orgID string, f PageFilter) ([]*RoutingRule, int64, error) {
	if s.db == nil {
		return nil, 0, fmt.Errorf("database not available")
	}
	if f.PageSize <= 0 {
		f = NewPageFilter(f.Page, f.PageSize)
	}
	var total int64
	if err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM routing_rules WHERE org_id = $1`, orgID,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count routing rules: %w", err)
	}
	rows, err := s.db.Query(ctx,
		`SELECT id::text, org_id::text, match_expr, target_model, priority, enabled, created_at
		 FROM routing_rules WHERE org_id = $1`+
			f.OrderBy(RoutingRuleSortColumns, "priority", true)+
			` LIMIT $2 OFFSET $3`,
		orgID, f.PageSize, f.Offset(),
	)
	if err != nil {
		return nil, 0, fmt.Errorf("list routing rules: %w", err)
	}
	defer rows.Close()

	var rules []*RoutingRule
	for rows.Next() {
		var r RoutingRule
		r.OrgID = orgID
		if err := rows.Scan(&r.ID, &r.OrgID, &r.MatchExpr, &r.TargetModel, &r.Priority, &r.Enabled, &r.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan routing rule: %w", err)
		}
		rules = append(rules, &r)
	}
	return rules, total, rows.Err()
}

// UpdateRoutingRuleEnabled toggles the enabled status of a routing rule.
func (s *Store) UpdateRoutingRuleEnabled(ctx context.Context, id string, enabled bool) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	_, err := s.db.Exec(ctx,
		`UPDATE routing_rules SET enabled = $1 WHERE id = $2`,
		enabled, id,
	)
	if err != nil {
		return fmt.Errorf("update routing rule enabled: %w", err)
	}
	return nil
}

// DeleteRoutingRule deletes a routing rule by ID.
func (s *Store) DeleteRoutingRule(ctx context.Context, id string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	result, err := s.db.Exec(ctx,
		`DELETE FROM routing_rules WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("delete routing rule: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("routing rule not found")
	}
	return nil
}

// UpdateRoutingRule updates match_expr, target_model, priority for a routing rule.
func (s *Store) UpdateRoutingRule(ctx context.Context, id, matchExpr, targetModel string, priority *int) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	var set []string
	var args []interface{}
	n := 1
	if matchExpr != "" {
		set = append(set, fmt.Sprintf("match_expr = $%d", n))
		args = append(args, matchExpr)
		n++
	}
	if targetModel != "" {
		set = append(set, fmt.Sprintf("target_model = $%d", n))
		args = append(args, targetModel)
		n++
	}
	if priority != nil {
		set = append(set, fmt.Sprintf("priority = $%d", n))
		args = append(args, *priority)
		n++
	}
	args = append(args, id)
	query := fmt.Sprintf(`UPDATE routing_rules SET %s WHERE id = $%d`, joinSetClauses(set), n)
	if _, err := s.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("update routing rule: %w", err)
	}
	return nil
}
