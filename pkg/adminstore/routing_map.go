package adminstore

import (
	"context"
	"fmt"
)

// routed for one organization: the (global) model registry entries with their
// failover chains and tier pools, the model aliases with their targets, the
// org's routing rules with their targets, and the warnings computed over
// those targets (chain/cycle/disabled-target classes). Nothing here writes.

// RoutingMapModel is one models_registry row as the map view needs it.
// Upstream URL and API key are deliberately excluded — the map is visible to
// org members and must never carry upstream credentials.
type RoutingMapModel struct {
	ModelName      string   `json:"model_name"`
	DisplayName    string   `json:"display_name"`
	Tier           string   `json:"tier"`
	Provider       string   `json:"provider"`
	Enabled        bool     `json:"enabled"`
	FallbackModel  *string  `json:"fallback_model,omitempty"`
	FailoverModels []string `json:"failover_models"`
	TierPool       []string `json:"tier_pool"`
}

// RoutingMapAlias is one alias → target edge.
type RoutingMapAlias struct {
	Alias       string `json:"alias"`
	TargetModel string `json:"target_model"`
}

// RoutingMapRule is one org routing rule → target edge.
type RoutingMapRule struct {
	ID          string `json:"id"`
	MatchExpr   string `json:"match_expr"`
	TargetModel string `json:"target_model"`
	Priority    int    `json:"priority"`
	Enabled     bool   `json:"enabled"`
}

// RoutingMapWarning is one computed configuration problem. Code is a stable
// machine-readable identifier (the UI keys on it); Scope says which section
// of the map the warning belongs to.
type RoutingMapWarning struct {
	Code    string `json:"code"`  // chain_target_missing | chain_target_disabled | chain_cycle | alias_target_missing | alias_target_disabled | rule_target_missing | rule_target_disabled
	Scope   string `json:"scope"` // model | alias | rule
	Source  string `json:"source"`
	Target  string `json:"target,omitempty"`
	Message string `json:"message"`
}

// RoutingMap is the full read-only routing view for one organization.
// Models and aliases are platform-global; rules are org-scoped. Slices are
// always non-nil so an empty view serializes as [] (honest empty), not null.
type RoutingMap struct {
	OrgID    string              `json:"org_id"`
	Models   []RoutingMapModel   `json:"models"`
	Aliases  []RoutingMapAlias   `json:"aliases"`
	Rules    []RoutingMapRule    `json:"rules"`
	Warnings []RoutingMapWarning `json:"warnings"`
}

// Warning codes emitted by computeRoutingWarnings.
const (
	WarnChainTargetMissing  = "chain_target_missing"
	WarnChainTargetDisabled = "chain_target_disabled"
	WarnChainCycle          = "chain_cycle"
	WarnAliasTargetMissing  = "alias_target_missing"
	WarnAliasTargetDisabled = "alias_target_disabled"
	WarnRuleTargetMissing   = "rule_target_missing"
	WarnRuleTargetDisabled  = "rule_target_disabled"
)

// GetRoutingMap assembles the routing map for orgID: every registry model,
// every alias, the org's rules, and the warnings computed over the target
// references. Models/aliases are global platform configuration; only the
// rules section is scoped to orgID.
func (s *Store) GetRoutingMap(ctx context.Context, orgID string) (*RoutingMap, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	rows, err := s.db.Query(ctx, `
		SELECT model_name, display_name, tier, provider, enabled,
		       fallback_model, failover_models, tier_pool
		FROM models_registry
		ORDER BY model_name`)
	if err != nil {
		return nil, fmt.Errorf("routing map models: %w", err)
	}
	models := []RoutingMapModel{}
	for rows.Next() {
		var m RoutingMapModel
		m.FailoverModels = []string{}
		m.TierPool = []string{}
		if err := rows.Scan(&m.ModelName, &m.DisplayName, &m.Tier, &m.Provider, &m.Enabled,
			&m.FallbackModel, &m.FailoverModels, &m.TierPool); err != nil {
			return nil, fmt.Errorf("scan routing map model: %w", err)
		}
		models = append(models, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("routing map models: %w", err)
	}

	aliases, err := s.ListModelAliases(ctx)
	if err != nil {
		return nil, fmt.Errorf("routing map aliases: %w", err)
	}
	aliasRows := make([]RoutingMapAlias, 0, len(aliases))
	for _, a := range aliases {
		aliasRows = append(aliasRows, RoutingMapAlias{Alias: a.Alias, TargetModel: a.TargetModel})
	}

	ruleRows, err := s.db.Query(ctx, `
		SELECT id::text, match_expr, target_model, priority, enabled
		FROM routing_rules
		WHERE org_id = $1
		ORDER BY priority, created_at, id`, orgID)
	if err != nil {
		return nil, fmt.Errorf("routing map rules: %w", err)
	}
	rules := []RoutingMapRule{}
	for ruleRows.Next() {
		var r RoutingMapRule
		if err := ruleRows.Scan(&r.ID, &r.MatchExpr, &r.TargetModel, &r.Priority, &r.Enabled); err != nil {
			return nil, fmt.Errorf("scan routing map rule: %w", err)
		}
		rules = append(rules, r)
	}
	if err := ruleRows.Err(); err != nil {
		return nil, fmt.Errorf("routing map rules: %w", err)
	}

	return &RoutingMap{
		OrgID:    orgID,
		Models:   models,
		Aliases:  aliasRows,
		Rules:    rules,
		Warnings: computeRoutingWarnings(models, aliasRows, rules),
	}, nil
}

// computeRoutingWarnings derives the configuration warnings for a routing
// map. It is a pure function so the rules stay unit-testable without a DB:
//
//   - a failover/fallback chain entry that names a nonexistent or disabled
//     model (chain_target_missing / chain_target_disabled);
//   - a chain that loops back on itself (chain_cycle) — the gateway skips
//     such entries when building the attempt chain, so the map must say why
//     a listed hop never runs;
//   - an alias that resolves to a nonexistent or disabled model;
//   - an ENABLED rule whose target is a nonexistent or disabled model
//     (disabled rules are inert, so their targets are not warned about).
func computeRoutingWarnings(models []RoutingMapModel, aliases []RoutingMapAlias, rules []RoutingMapRule) []RoutingMapWarning {
	byName := make(map[string]*RoutingMapModel, len(models))
	for i := range models {
		byName[models[i].ModelName] = &models[i]
	}
	status := func(name string) string {
		m, ok := byName[name]
		if !ok {
			return "missing"
		}
		if !m.Enabled {
			return "disabled"
		}
		return "ok"
	}

	warnings := []RoutingMapWarning{}
	for i := range models {
		m := &models[i]
		// The chain the gateway assembles is [self] + fallback_model +
		// failover_models (pkg/router buildChain skips entries it has
		// already seen — that skip is exactly the cycle case).
		seen := map[string]bool{m.ModelName: true}
		targets := make([]string, 0, len(m.FailoverModels)+1)
		if m.FallbackModel != nil && *m.FallbackModel != "" {
			targets = append(targets, *m.FallbackModel)
		}
		targets = append(targets, m.FailoverModels...)
		for _, t := range targets {
			if t == "" {
				continue
			}
			switch {
			case seen[t]:
				warnings = append(warnings, RoutingMapWarning{
					Code: WarnChainCycle, Scope: "model", Source: m.ModelName, Target: t,
					Message: fmt.Sprintf("failover chain of %q loops back to %q; the gateway skips repeated hops", m.ModelName, t),
				})
			default:
				switch status(t) {
				case "missing":
					warnings = append(warnings, RoutingMapWarning{
						Code: WarnChainTargetMissing, Scope: "model", Source: m.ModelName, Target: t,
						Message: fmt.Sprintf("failover chain of %q points at nonexistent model %q", m.ModelName, t),
					})
				case "disabled":
					warnings = append(warnings, RoutingMapWarning{
						Code: WarnChainTargetDisabled, Scope: "model", Source: m.ModelName, Target: t,
						Message: fmt.Sprintf("failover chain of %q points at disabled model %q", m.ModelName, t),
					})
				}
			}
			seen[t] = true
		}
	}

	for _, a := range aliases {
		switch status(a.TargetModel) {
		case "missing":
			warnings = append(warnings, RoutingMapWarning{
				Code: WarnAliasTargetMissing, Scope: "alias", Source: a.Alias, Target: a.TargetModel,
				Message: fmt.Sprintf("alias %q points at nonexistent model %q", a.Alias, a.TargetModel),
			})
		case "disabled":
			warnings = append(warnings, RoutingMapWarning{
				Code: WarnAliasTargetDisabled, Scope: "alias", Source: a.Alias, Target: a.TargetModel,
				Message: fmt.Sprintf("alias %q points at disabled model %q", a.Alias, a.TargetModel),
			})
		}
	}

	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		switch status(r.TargetModel) {
		case "missing":
			warnings = append(warnings, RoutingMapWarning{
				Code: WarnRuleTargetMissing, Scope: "rule", Source: r.ID, Target: r.TargetModel,
				Message: fmt.Sprintf("routing rule %q targets nonexistent model %q", r.ID, r.TargetModel),
			})
		case "disabled":
			warnings = append(warnings, RoutingMapWarning{
				Code: WarnRuleTargetDisabled, Scope: "rule", Source: r.ID, Target: r.TargetModel,
				Message: fmt.Sprintf("routing rule %q targets disabled model %q", r.ID, r.TargetModel),
			})
		}
	}

	return warnings
}
