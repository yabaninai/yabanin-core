package adminstore

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// over a bounded window: request count, error share, latency p50/p95 and the
// most recent error with its timestamp. Read-only; shadow traffic is
// excluded (the same convention as every other request_logs consumer).

// ProviderHealthModelRow is one flat provider×model aggregate as SQL returns
// it. Provider is the models_registry provider of model_used; the empty
// string means the model is not in the registry (mapped to "unknown" when
// grouped).
type ProviderHealthModelRow struct {
	Provider   string
	Model      string
	Requests   int64
	Errors     int64
	P50Ms      float64
	P95Ms      float64
	LastError  string
	LastErrorA *time.Time
}

// ProviderHealthModel is the per-model health view nested under a provider.
type ProviderHealthModel struct {
	Model      string     `json:"model"`
	Requests   int64      `json:"requests"`
	Errors     int64      `json:"errors"`
	ErrorRate  float64    `json:"error_rate"`
	P50Ms      float64    `json:"p50_ms"`
	P95Ms      float64    `json:"p95_ms"`
	LastError  string     `json:"last_error,omitempty"`
	LastErrorA *time.Time `json:"last_error_at,omitempty"`
}

// ProviderHealth aggregates one provider's models. Slices are always
// non-nil so an empty result serializes as [] (honest empty), not null.
type ProviderHealth struct {
	Provider  string                `json:"provider"`
	Requests  int64                 `json:"requests"`
	Errors    int64                 `json:"errors"`
	ErrorRate float64               `json:"error_rate"`
	Models    []ProviderHealthModel `json:"models"`
}

// GetProviderHealth returns the per-provider/per-model request_logs
// aggregates for orgID between from (inclusive) and to (exclusive). Rows
// whose model is absent from the registry are grouped under "unknown" so
// the org still sees the traffic it actually served.
func (s *Store) GetProviderHealth(ctx context.Context, orgID string, from, to time.Time) ([]ProviderHealth, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx, `
		SELECT COALESCE(mr.provider, '') AS provider,
		       rl.model_used,
		       COUNT(*) AS requests,
		       COALESCE(SUM(CASE WHEN rl.status_code >= 400 THEN 1 ELSE 0 END), 0) AS errors,
		       COALESCE(PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY rl.duration_ms), 0) AS p50,
		       COALESCE(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY rl.duration_ms), 0) AS p95,
		       MAX(rl.created_at) FILTER (WHERE rl.status_code >= 400) AS last_error_at,
		       COALESCE((ARRAY_AGG(rl.error ORDER BY rl.created_at DESC)
		                 FILTER (WHERE rl.status_code >= 400))[1], '') AS last_error
		FROM request_logs rl
		LEFT JOIN models_registry mr ON mr.model_name = rl.model_used
		WHERE rl.org_id = $1::uuid
		  AND rl.created_at >= $2
		  AND rl.created_at < $3
		  AND COALESCE(rl.ab_group, '') <> 'shadow'
		GROUP BY mr.provider, rl.model_used
		ORDER BY requests DESC, rl.model_used`, orgID, from, to)
	if err != nil {
		return nil, fmt.Errorf("provider health: %w", err)
	}
	records := []ProviderHealthModelRow{}
	for rows.Next() {
		var r ProviderHealthModelRow
		if err := rows.Scan(&r.Provider, &r.Model, &r.Requests, &r.Errors,
			&r.P50Ms, &r.P95Ms, &r.LastErrorA, &r.LastError); err != nil {
			return nil, fmt.Errorf("scan provider health: %w", err)
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("provider health: %w", err)
	}
	return groupProviderHealth(records), nil
}

// groupProviderHealth folds the flat provider×model rows into per-provider
// aggregates ordered by request volume (then name, deterministically).
func groupProviderHealth(rows []ProviderHealthModelRow) []ProviderHealth {
	byProvider := map[string]*ProviderHealth{}
	order := []string{}
	for _, r := range rows {
		provider := r.Provider
		if provider == "" {
			provider = "unknown"
		}
		p, ok := byProvider[provider]
		if !ok {
			p = &ProviderHealth{Provider: provider, Models: []ProviderHealthModel{}}
			byProvider[provider] = p
			order = append(order, provider)
		}
		p.Requests += r.Requests
		p.Errors += r.Errors
		p.Models = append(p.Models, ProviderHealthModel{
			Model:      r.Model,
			Requests:   r.Requests,
			Errors:     r.Errors,
			ErrorRate:  safeRate(r.Errors, r.Requests),
			P50Ms:      r.P50Ms,
			P95Ms:      r.P95Ms,
			LastError:  r.LastError,
			LastErrorA: r.LastErrorA,
		})
	}
	out := make([]ProviderHealth, 0, len(order))
	for _, name := range order {
		p := byProvider[name]
		p.ErrorRate = safeRate(p.Errors, p.Requests)
		out = append(out, *p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].Provider < out[j].Provider
	})
	return out
}

// safeRate is errors/total guarded against a zero denominator.
func safeRate(errors, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(errors) / float64(total)
}
