package adminstore

import (
	"context"
	"fmt"
	"time"
)

// ShadowComparison answers "what would it cost to run the shadow model as
// primary?" by joining primary request_logs rows with their shadow mirror
// rows on request_id (ab_group='shadow' discriminator). v9, S6.
type ShadowComparison struct {
	Period        string               `json:"period"`
	PrimaryModel  string               `json:"primary_model"`
	ShadowModel   string               `json:"shadow_model"`
	Overlap       int                  `json:"overlap"` // request_ids present in both
	PrimaryAvgUSD float64              `json:"primary_avg_usd"`
	ShadowAvgUSD  float64              `json:"shadow_avg_usd"`
	DeltaPct      float64              `json:"delta_pct"` // (shadow-primary)/primary*100; >0 = shadow pricier
	Verdict       string               `json:"verdict"`   // cheaper|pricier|insufficient_data
	ByModel       []ShadowModelCompare `json:"by_model"`
	// ADL-08: the task-tag dimension (cost + latency per model × task class).
	ByTaskClass []ShadowTaskClassCompare `json:"by_task_class"`
}

// ShadowModelCompare is one row of the per-primary-model breakdown.
type ShadowModelCompare struct {
	PrimaryModel  string  `json:"primary_model"`
	ShadowModel   string  `json:"shadow_model"`
	Overlap       int     `json:"overlap"`
	PrimaryAvgUSD float64 `json:"primary_avg_usd"`
	ShadowAvgUSD  float64 `json:"shadow_avg_usd"`
	DeltaPct      float64 `json:"delta_pct"`
	Verdict       string  `json:"verdict"`
}

// ShadowTaskClassCompare is the ADL-08 breakdown: the shadow-overlap cost +
// latency for one (task class, primary, shadow) triple. task_class is
// request_logs.task_id (NULL → "(untagged)"). This answers "what does the
// shadow (premium) model cost, per request, for which class of agentic task,
// and how does its latency compare to the primary it mirrors" — the missing
// task-tag dimension on the CMP screen.
type ShadowTaskClassCompare struct {
	TaskClass     string  `json:"task_class"`
	PrimaryModel  string  `json:"primary_model"`
	ShadowModel   string  `json:"shadow_model"`
	Overlap       int     `json:"overlap"`
	PrimaryAvgUSD float64 `json:"primary_avg_usd"`
	ShadowAvgUSD  float64 `json:"shadow_avg_usd"`
	DeltaPct      float64 `json:"delta_pct"`
	PrimaryAvgMs  int64   `json:"primary_avg_ms"`
	ShadowAvgMs   int64   `json:"shadow_avg_ms"`
	Verdict       string  `json:"verdict"`
}

const shadowInsufficientOverlap = 20 // below this, the verdict is not statistically meaningful

// GetShadowComparison compares primary vs shadow cost per request over a
// window. orgID empty = all orgs. Returns a zero-overlap report (verdict
// "insufficient_data") when no shadow traffic exists in the window — that is
// a valid answer, not an error.
func (s *Store) GetShadowComparison(ctx context.Context, orgID string, days int) (*ShadowComparison, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	if days <= 0 {
		days = 30
	}
	to := time.Now()
	from := to.AddDate(0, 0, -days)

	orgFilter := ""
	var args []interface{}
	args = append(args, from, to)
	if orgID != "" {
		// D-01: the placeholder number must be computed AFTER the argument is
		// appended (same pattern as quality_compare.go) — otherwise the filter
		// re-uses $2 (the window bound) and the org argument is never sent.
		args = append(args, orgID)
		orgFilter = " AND p.org_id::text = $" + fmt.Sprintf("%d", len(args))
	}

	// Per (primary_model, shadow_model) pair: average cost per request on
	// each side, joined on request_id. The primary side excludes shadow rows
	// (defensive: they are already isolated by ab_group, but the join must
	// only see real primary rows).
	const query = `
		SELECT p.model_used AS primary_model,
		       sh.model_used AS shadow_model,
		       COUNT(*) AS overlap,
		       COALESCE(AVG(p.cost_in_usd), 0) AS primary_avg,
		       COALESCE(AVG(sh.cost_in_usd), 0) AS shadow_avg
		FROM request_logs p
		JOIN request_logs sh
		  ON sh.request_id = p.request_id
		 AND sh.ab_group = 'shadow'
		 AND sh.created_at BETWEEN $1 AND $2` + " %s" + `
		WHERE p.ab_group IS DISTINCT FROM 'shadow'
		  AND p.request_id IS NOT NULL
		  AND p.created_at BETWEEN $1 AND $2
		GROUP BY p.model_used, sh.model_used
		ORDER BY overlap DESC`

	q := fmt.Sprintf(query, orgFilter)

	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("shadow comparison query: %w", err)
	}
	defer rows.Close()

	rep := &ShadowComparison{
		Period:      fmt.Sprintf("last_%d_days", days),
		ByModel:     []ShadowModelCompare{},
		ByTaskClass: []ShadowTaskClassCompare{},
	}
	var totalOverlap int
	for rows.Next() {
		var m ShadowModelCompare
		if err := rows.Scan(&m.PrimaryModel, &m.ShadowModel, &m.Overlap, &m.PrimaryAvgUSD, &m.ShadowAvgUSD); err != nil {
			return nil, fmt.Errorf("scan shadow comparison row: %w", err)
		}
		m.DeltaPct = deltaPct(m.PrimaryAvgUSD, m.ShadowAvgUSD)
		m.Verdict = verdict(m.Overlap, m.DeltaPct)
		totalOverlap += m.Overlap
		rep.ByModel = append(rep.ByModel, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate shadow comparison rows: %w", err)
	}

	// ADL-08: the task-tag dimension. Same join, grouped by
	// (task class, primary_model, shadow_model) and adding the average
	// duration_ms per side — so the screen shows, per class of agentic task,
	// which model costs how much and is how slow. task_id NULL → "(untagged)"
	// (the same convention as the ADL-04 quality by-task breakdown).
	const byTaskQuery = `
		SELECT COALESCE(p.task_id, ` + "'(untagged)'" + `) AS task_class,
		       p.model_used AS primary_model,
		       sh.model_used AS shadow_model,
		       COUNT(*) AS overlap,
		       COALESCE(AVG(p.cost_in_usd), 0)  AS primary_avg,
		       COALESCE(AVG(sh.cost_in_usd), 0) AS shadow_avg,
		       COALESCE(AVG(p.duration_ms::float8), 0) AS primary_ms,
		       COALESCE(AVG(sh.duration_ms::float8), 0) AS shadow_ms
		FROM request_logs p
		JOIN request_logs sh
		  ON sh.request_id = p.request_id
		 AND sh.ab_group = 'shadow'
		 AND sh.created_at BETWEEN $1 AND $2` + " %s" + `
		WHERE p.ab_group IS DISTINCT FROM 'shadow'
		  AND p.request_id IS NOT NULL
		  AND p.created_at BETWEEN $1 AND $2
		GROUP BY 1, p.model_used, sh.model_used
		ORDER BY overlap DESC`

	trows, err := s.db.Query(ctx, fmt.Sprintf(byTaskQuery, orgFilter), args...)
	if err != nil {
		return nil, fmt.Errorf("shadow by-task query: %w", err)
	}
	defer trows.Close()
	for trows.Next() {
		var g ShadowTaskClassCompare
		var primaryMs, shadowMs float64
		if err := trows.Scan(&g.TaskClass, &g.PrimaryModel, &g.ShadowModel, &g.Overlap,
			&g.PrimaryAvgUSD, &g.ShadowAvgUSD, &primaryMs, &shadowMs); err != nil {
			return nil, fmt.Errorf("scan shadow by-task row: %w", err)
		}
		g.PrimaryAvgMs = int64(primaryMs)
		g.ShadowAvgMs = int64(shadowMs)
		g.DeltaPct = deltaPct(g.PrimaryAvgUSD, g.ShadowAvgUSD)
		g.Verdict = verdict(g.Overlap, g.DeltaPct)
		rep.ByTaskClass = append(rep.ByTaskClass, g)
	}
	if err := trows.Err(); err != nil {
		return nil, fmt.Errorf("iterate shadow by-task rows: %w", err)
	}

	// Headline = the pair with the most overlap (the configured shadow
	// target dominates by construction when a single shadow model runs).
	if len(rep.ByModel) > 0 {
		top := rep.ByModel[0]
		rep.PrimaryModel = top.PrimaryModel
		rep.ShadowModel = top.ShadowModel
		rep.Overlap = totalOverlap
		rep.PrimaryAvgUSD = weightedAvg(rep.ByModel, func(m ShadowModelCompare) float64 { return m.PrimaryAvgUSD })
		rep.ShadowAvgUSD = weightedAvg(rep.ByModel, func(m ShadowModelCompare) float64 { return m.ShadowAvgUSD })
		rep.DeltaPct = deltaPct(rep.PrimaryAvgUSD, rep.ShadowAvgUSD)
		rep.Verdict = verdict(rep.Overlap, rep.DeltaPct)
	} else {
		rep.Verdict = "insufficient_data"
	}
	return rep, nil
}

func deltaPct(primary, shadow float64) float64 {
	if primary <= 0 {
		return 0
	}
	return ((shadow - primary) / primary) * 100
}

func verdict(overlap int, deltaPct float64) string {
	if overlap < shadowInsufficientOverlap {
		return "insufficient_data"
	}
	if deltaPct < -1.0 {
		return "cheaper"
	}
	if deltaPct > 1.0 {
		return "pricier"
	}
	return "insufficient_data" // within noise band — do not over-claim
}

func weightedAvg(rows []ShadowModelCompare, pick func(ShadowModelCompare) float64) float64 {
	var num, den float64
	for _, m := range rows {
		n := float64(m.Overlap)
		num += pick(m) * n
		den += n
	}
	if den == 0 {
		return 0
	}
	return num / den
}
