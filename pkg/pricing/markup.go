package pricing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/metrics"
)

// ErrUnknownModel returned when a model has no pricing data in the DB or static tables.
var ErrUnknownModel = errors.New("unknown model: no pricing data available")

// ResellerQuote is the resale price for a request, including markup.
// InputCostUSD prices the NON-cache input only: the cache subsets ride the
// dedicated CacheWrite/CacheRead line items (the input token count passed
// to Quote includes them — canonical provider.Usage semantics).
type ResellerQuote struct {
	InputCostUSD   float64 `json:"input_cost_usd"`  // non-cache input cost
	OutputCostUSD  float64 `json:"output_cost_usd"` // cost before markup
	CacheWriteCost float64 `json:"cache_write_cost_usd"`
	CacheReadCost  float64 `json:"cache_read_cost_usd"`

	InputResaleUSD   float64 `json:"input_resale_usd"`  // after markup
	OutputResaleUSD  float64 `json:"output_resale_usd"` // after markup
	CacheWriteResale float64 `json:"cache_write_resale_usd"`
	CacheReadResale  float64 `json:"cache_read_resale_usd"`

	TotalCostUSD   float64 `json:"total_cost_usd"`   // sum of cost fields
	TotalResaleUSD float64 `json:"total_resale_usd"` // sum of resale fields
	MarginPct      float64 `json:"margin_pct"`       // markup percentage applied

	ModelName string `json:"model_name"`
}

// MarkupPricer wraps a base Pricer and applies per-org, per-model resale markup.
// Pricing lookup priority:
//  1. org_id + model_name override (most specific)
//  2. org_id global default (org_id set, model_name NULL)
//  3. Global default (org_id NULL, model_name NULL) — seeded at 15%
type MarkupPricer struct {
	pool       *pgxpool.Pool
	basePricer Pricer // usually DBPricer or staticPricer
	log        *slog.Logger

	cache   map[string]pricingOverride
	cacheMu sync.RWMutex
	ttl     time.Duration
}

// pricingOverride holds a specific markup rule from the DB.
type pricingOverride struct {
	markupPct       float64
	fixedInputPerM  *float64 // nil = use cost-based markup
	fixedOutputPerM *float64 // nil = use cost-based markup
	loadedAt        time.Time
}

// NewMarkupPricer creates a reseller pricer that applies markup on top of base prices.
func NewMarkupPricer(pool *pgxpool.Pool, basePricer Pricer, log *slog.Logger) *MarkupPricer {
	l := log
	if l == nil {
		l = slog.New(slog.DiscardHandler)
	}
	return &MarkupPricer{
		pool:       pool,
		basePricer: basePricer,
		log:        l.With("component", "reseller-pricer"),
		cache:      make(map[string]pricingOverride),
		ttl:        1 * time.Minute,
	}
}

// Quote computes the resale price for a request given token counts and markup rules.
//
// inputTokens follows the canonical provider.Usage semantics: it counts
// EVERY input token, INCLUDING the cache-read and cache-write subsets that
// are also passed separately (the gateway forwards provider.Usage.PromptTokens
// verbatim). The cache subsets are billed at their own CacheWritePerM /
// CacheReadPerM rates and are EXCLUDED from the input term — clamped at zero
// when a misreporting source claims more cache tokens than input tokens —
// so cached tokens are never billed twice (input rate AND cache rate). This
// mirrors provider.ComputeCost on the base-cost side (N03-P06-T03). Callers
// that pass an already cache-subtracted input count will under-bill the
// remaining input; pass the canonical prompt token count.
func (mp *MarkupPricer) Quote(ctx context.Context, orgID, provider, model string,
	inputTokens, outputTokens, cacheWriteTokens, cacheReadTokens int64,
) (*ResellerQuote, error) {

	basePrice, known := mp.basePricer.Lookup(provider, model)
	if !known {
		// Unknown model — reject to prevent silent $0 billing.
		metrics.ResellerUnknownModelTotal.Inc()
		return nil, fmt.Errorf("quote %s/%s: %w", provider, model, ErrUnknownModel)
	}

	// Canonical input semantics (provider.Usage): the cache subsets are part
	// of the input count. Non-cache input is billed at InputPerM, the cache
	// portions at their own rates. Defensive clamp mirrors ComputeCost: don't
	// let a misreporting source produce a negative input term.
	nonCacheInput := inputTokens - cacheWriteTokens - cacheReadTokens
	if nonCacheInput < 0 {
		nonCacheInput = 0
	}

	// Look up markup override for this org+model.
	override := mp.getOverride(ctx, orgID, model)

	// FIX 2: If fixed pricing is set, use it directly (overrides markup).
	if override.fixedInputPerM != nil && override.fixedOutputPerM != nil {
		inputResale := float64(nonCacheInput) / 1_000_000 * *override.fixedInputPerM
		outputResale := float64(outputTokens) / 1_000_000 * *override.fixedOutputPerM
		cacheWriteResale := float64(cacheWriteTokens) / 1_000_000 * basePrice.CacheWritePerM
		cacheReadResale := float64(cacheReadTokens) / 1_000_000 * basePrice.CacheReadPerM

		totalCost := inputResale + outputResale + cacheWriteResale + cacheReadResale

		return &ResellerQuote{
			InputCostUSD:     inputResale,
			OutputCostUSD:    outputResale,
			CacheWriteCost:   cacheWriteResale,
			CacheReadCost:    cacheReadResale,
			InputResaleUSD:   inputResale,
			OutputResaleUSD:  outputResale,
			CacheWriteResale: cacheWriteResale,
			CacheReadResale:  cacheReadResale,
			TotalCostUSD:     totalCost,
			TotalResaleUSD:   totalCost,
			MarginPct:        0, // No markup, fixed prices
			ModelName:        model,
		}, nil
	}

	markupPct := override.markupPct

	inputCost := float64(nonCacheInput) / 1_000_000 * basePrice.InputPerM
	outputCost := float64(outputTokens) / 1_000_000 * basePrice.OutputPerM
	cacheWriteCost := float64(cacheWriteTokens) / 1_000_000 * basePrice.CacheWritePerM
	cacheReadCost := float64(cacheReadTokens) / 1_000_000 * basePrice.CacheReadPerM

	// Apply markup: resale = cost * (1 + markup/100)
	inputResale := inputCost * (1 + markupPct/100)
	outputResale := outputCost * (1 + markupPct/100)
	cacheWriteResale := cacheWriteCost * (1 + markupPct/100)
	cacheReadResale := cacheReadCost * (1 + markupPct/100)

	totalCost := inputCost + outputCost + cacheWriteCost + cacheReadCost
	totalResale := inputResale + outputResale + cacheWriteResale + cacheReadResale

	marginPct := 0.0
	if totalResale > 0 {
		marginPct = ((totalResale - totalCost) / totalCost) * 100
	}

	return &ResellerQuote{
		InputCostUSD:     inputCost,
		OutputCostUSD:    outputCost,
		CacheWriteCost:   cacheWriteCost,
		CacheReadCost:    cacheReadCost,
		InputResaleUSD:   inputResale,
		OutputResaleUSD:  outputResale,
		CacheWriteResale: cacheWriteResale,
		CacheReadResale:  cacheReadResale,
		TotalCostUSD:     totalCost,
		TotalResaleUSD:   totalResale,
		MarginPct:        marginPct,
		ModelName:        model,
	}, nil
}

// ComputeResaleAmount computes the dollar amount to deduct for a single request.
// This is the concise version of Quote — just returns the total resale USD.
// inputTokens is the canonical INCLUSIVE prompt count (see Quote).
func (mp *MarkupPricer) ComputeResaleAmount(ctx context.Context, orgID, provider, model string,
	inputTokens, outputTokens, cacheWriteTokens, cacheReadTokens int64,
) (float64, error) {
	quote, err := mp.Quote(ctx, orgID, provider, model, inputTokens, outputTokens, cacheWriteTokens, cacheReadTokens)
	if err != nil {
		return 0, err
	}
	return quote.TotalResaleUSD, nil
}

// getOverride returns the most specific pricing override for an org+model.
func (mp *MarkupPricer) getOverride(ctx context.Context, orgID, model string) pricingOverride {
	key := fmt.Sprintf("%s:%s", orgID, model)

	// FIX 3: Per-entry TTL check instead of global cacheTime.
	mp.cacheMu.RLock()
	if ov, ok := mp.cache[key]; ok && ov.loadedAt.Add(mp.ttl).After(time.Now()) {
		mp.cacheMu.RUnlock()
		return ov
	}
	mp.cacheMu.RUnlock()

	// Query DB with specificity priority: org+model > org-only > global.
	var ov pricingOverride

	if mp.pool != nil {
		// 1. Try org_id + model_name match.
		if err := mp.pool.QueryRow(ctx, `
			SELECT markup_pct, fixed_input_per_m, fixed_output_per_m
			FROM reseller_pricing
			WHERE org_id = $1 AND model_name = $2 AND active = true
			ORDER BY id DESC LIMIT 1
		`, orgID, model).Scan(&ov.markupPct, &ov.fixedInputPerM, &ov.fixedOutputPerM); err == nil {
			mp.cacheMu.Lock()
			mp.cache[key] = ov
			mp.cacheMu.Unlock()
			return ov
		} else if !errors.Is(err, pgx.ErrNoRows) {
			// FIX 3: Use errors.Is for error comparison.
			mp.log.Warn("reseller pricing lookup failed", "org_id", orgID, "model", model, "error", err)
		}

		// 2. Try org_id global (model_name NULL).
		if err := mp.pool.QueryRow(ctx, `
			SELECT markup_pct, fixed_input_per_m, fixed_output_per_m
			FROM reseller_pricing
			WHERE org_id = $1 AND model_name IS NULL AND active = true
			ORDER BY id DESC LIMIT 1
		`, orgID).Scan(&ov.markupPct, &ov.fixedInputPerM, &ov.fixedOutputPerM); err == nil {
			mp.cacheMu.Lock()
			mp.cache[key] = ov
			mp.cacheMu.Unlock()
			return ov
		} else if !errors.Is(err, pgx.ErrNoRows) {
			mp.log.Warn("reseller pricing org lookup failed", "org_id", orgID, "error", err)
		}

		// 3. Try global default (org_id NULL, model_name NULL).
		if err := mp.pool.QueryRow(ctx, `
			SELECT markup_pct, fixed_input_per_m, fixed_output_per_m
			FROM reseller_pricing
			WHERE org_id IS NULL AND model_name IS NULL AND active = true
			ORDER BY id DESC LIMIT 1
		`).Scan(&ov.markupPct, &ov.fixedInputPerM, &ov.fixedOutputPerM); err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				mp.log.Warn("reseller pricing global lookup failed", "error", err)
			} else {
				ov.markupPct = 15.0 // hard-coded default if no seed row
			}
		}
	} else {
		// No DB — use default 15% markup.
		ov.markupPct = 15.0
	}

	return ov
}
