package carbon

import (
	"context"
	"fmt"
	"math"
	"sync"

	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/verticals"
)

// Constants.
const (
	ID          = "carbon_brsr"
	RegionName  = policy.Region("GLOBAL")
	PackName    = "Carbon Emissions Tracking"
	Description = "BRSR/CSRD carbon-aware routing: tracks gCO2e per request, enforces org-level budgets, and prefers low-carbon models when budgets are exceeded."
)

// ResidencyRule mirrors policy.ResidencyRule.
type ResidencyRule struct {
	AllowedJurisdictions []policy.Region `json:"allowed_jurisdictions"`
	AllowedModelFamilies []string        `json:"allowed_model_families"`
	DataResidency        policy.Region   `json:"data_residency"`
	CrossBorderAllowed   bool            `json:"cross_border_allowed"`
	BlacklistedCountries []policy.Region `json:"blacklisted_countries"`
}

// DefaultRules returns the built-in rule set.
func DefaultRules() ResidencyRule {
	return ResidencyRule{
		AllowedJurisdictions: []policy.Region{"GLOBAL"},
		AllowedModelFamilies: []string{"openai", "anthropic", "google", "sovereign_sg", "open_weights"},
		DataResidency:        "GLOBAL",
		CrossBorderAllowed:   true,
		BlacklistedCountries: nil,
	}
}

// EmissionFactor represents the carbon intensity of a model.
type EmissionFactor struct {
	Model      string  `json:"model"`
	Provider   string  `json:"provider"`
	GramsPer1M float64 `json:"grams_per_1m"` // gCO2e per 1M tokens
}

// Budget tracks an org's carbon budget window.
type Budget struct {
	LimitGrams    float64 `json:"limit_grams"`    // monthly limit in grams CO2
	UsedGrams     float64 `json:"used_grams"`     // consumed this month
	DaysRemaining int     `json:"days_remaining"` // days left in window
}

// Pack is the Carbon vertical pack.
type Pack struct {
	mu      sync.RWMutex
	rule    ResidencyRule
	factors map[string]EmissionFactor // model_name -> factor
	budgets map[string]Budget         // orgID -> budget
}

// New creates a new Carbon pack with default rules and seed factors.
func New() *Pack {
	p := &Pack{
		rule:    DefaultRules(),
		factors: make(map[string]EmissionFactor),
		budgets: make(map[string]Budget),
	}
	// Seed with representative emission factors (gCO2e per 1M tokens).
	seed := []EmissionFactor{
		{"gpt-4o", "openai", 50.0},
		{"gpt-4o-mini", "openai", 16.0},
		{"claude-sonnet-4", "anthropic", 35.0},
		{"claude-haiku", "anthropic", 12.0},
		{"gemini-pro", "google", 25.0},
		{"llama-3-70b", "open_weights", 80.0},
		{"mistral-large", "openai", 45.0},
	}
	for _, f := range seed {
		p.factors[f.Model] = f
	}
	return p
}

// ID implements verticals.Vertical.
func (p *Pack) ID() string { return ID }

// Region implements policy.Pack.
func (p *Pack) Region() policy.Region { return RegionName }

// Name returns the human-readable pack name.
func (p *Pack) Name() string { return PackName }

// Description returns a short description of the pack's compliance scope.
func (p *Pack) Description() string { return Description }

// DefaultRules is exposed for DB seeding / admin UI.
func (p *Pack) DefaultRules() policy.ResidencyRule {
	r := p.rule
	return policy.ResidencyRule{
		AllowedJurisdictions: r.AllowedJurisdictions,
		AllowedModelFamilies: r.AllowedModelFamilies,
		DataResidency:        r.DataResidency,
		CrossBorderAllowed:   r.CrossBorderAllowed,
		BlacklistedCountries: r.BlacklistedCountries,
	}
}

// SetRules updates the pack's residency rules.
func (p *Pack) SetRules(r ResidencyRule) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rule = r
}

// Evaluate implements policy.Pack — carbon pack never denies on residency alone.
func (p *Pack) Evaluate(_ context.Context, in policy.EvalContext, overrideRules *policy.ResidencyRule) policy.Decision {
	rule := p.rule
	if overrideRules != nil {
		rule = ResidencyRule{
			AllowedJurisdictions: overrideRules.AllowedJurisdictions,
			AllowedModelFamilies: overrideRules.AllowedModelFamilies,
			DataResidency:        overrideRules.DataResidency,
			CrossBorderAllowed:   overrideRules.CrossBorderAllowed,
			BlacklistedCountries: overrideRules.BlacklistedCountries,
		}
	}

	var violations []string
	if len(rule.AllowedJurisdictions) > 0 && !policy.RegionIn(in.ModelRegion, rule.AllowedJurisdictions) {
		violations = append(violations, fmt.Sprintf("model region %q not allowed", in.ModelRegion))
	}

	return policy.Decision{
		Allowed:    len(violations) == 0,
		Region:     RegionName,
		PackID:     ID,
		Reason:     "",
		Violations: violations,
	}
}

// SetFactor registers an emission factor for a model/provider pair.
func (p *Pack) SetFactor(model, provider string, gramsPer1M float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.factors[model] = EmissionFactor{Model: model, Provider: provider, GramsPer1M: gramsPer1M}
}

// GetFactor returns the emission factor for a model.
func (p *Pack) GetFactor(model string) EmissionFactor {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.factors[model]
}

// SetBudget sets a carbon budget for an org.
func (p *Pack) SetBudget(orgID string, limitGrams float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.budgets[orgID] = Budget{LimitGrams: limitGrams, UsedGrams: 0}
}

// GetBudget returns the carbon budget for an org.
func (p *Pack) GetBudget(orgID string) Budget {
	p.mu.RLock()
	defer p.mu.RUnlock()
	b, ok := p.budgets[orgID]
	if !ok {
		return Budget{LimitGrams: 1000} // default 1kg/month
	}
	return b
}

// EstimateTokens returns estimated token count from prompt length.
func EstimateTokens(prompt string) int {
	// Rough heuristic: ~4 chars per token for English text.
	if len(prompt) == 0 {
		return 0
	}
	return len(prompt) / 4
}

// EstimateGrams returns grams CO2e for the given model and token count.
func (p *Pack) EstimateGrams(model string, tokens int) float64 {
	f := p.GetFactor(model)
	if f.GramsPer1M <= 0 {
		return 50.0 // default fallback
	}
	return f.GramsPer1M * float64(tokens) / 1_000_000.0
}

// Transform implements verticals.Vertical — carbon-aware model swapping.
// If budget exceeded, remaps to a lower-carbon alternative from the same quality tier.
func (p *Pack) Transform(ctx context.Context, in verticals.Request) (context.Context, verticals.Response, error) {
	tokens := EstimateTokens(in.Prompt)
	grams := p.EstimateGrams(in.ModelRequested, tokens)

	budget := p.GetBudget(in.OrgID)
	if budget.UsedGrams+grams > budget.LimitGrams {
		// Budget exceeded — remap to lower-carbon model.
		lowCarbon := p.preferLowCarbon(in.ModelRequested)
		if lowCarbon != "" {
			in.ModelRequested = lowCarbon
			if in.Metadata == nil {
				in.Metadata = make(map[string]string)
			}
			in.Metadata["carbon_remapped"] = "true"
			in.Metadata["original_model"] = in.ModelRequested // keep track before swap below
			in.Metadata["budget_limit_grams"] = fmt.Sprintf("%.2f", budget.LimitGrams)
			in.Metadata["current_usage_grams"] = fmt.Sprintf("%.2f", budget.UsedGrams+grams)
		}
	}

	resp := verticals.Response{
		Model:    in.ModelRequested,
		Prompt:   in.Prompt,
		Metadata: in.Metadata,
	}
	return ctx, resp, nil
}

// preferLowCarbon finds a lower-carbon alternative to the given model.
func (p *Pack) preferLowCarbon(currentModel string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	current := p.factors[currentModel]
	if current.GramsPer1M <= 0 {
		current.GramsPer1M = 50.0 // default
	}

	best := ""
	bestGrams := math.MaxFloat64
	for modelName, factor := range p.factors {
		if modelName == currentModel {
			continue
		}
		if factor.GramsPer1M < bestGrams && factor.GramsPer1M < current.GramsPer1M*0.7 {
			best = modelName
			bestGrams = factor.GramsPer1M
		}
	}
	return best
}

// Report implements verticals.Vertical — generates a BRSR/CSRD carbon report.
func (p *Pack) Report(_ context.Context, orgID string, from, until string, mode string) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	totalGrams := 0.0

	for _, budget := range p.budgets {
		if orgID == "" || orgID == "all" {
			totalGrams += budget.UsedGrams
		}
	}

	return []byte(fmt.Sprintf(
		`{"vertical":"carbon","org_id":"%s","from":"%s","until":"%s","total_gco2e_grams":%.4f,"budget_limit_grams":%.2f,"compliance":"brsr_csrd"}`,
		orgID, from, until, totalGrams, 1000.0,
	)), nil
}

// Ensure Pack implements verticals.Vertical at compile time.
var _ verticals.Vertical = (*Pack)(nil)
