package adminstore

import (
	"context"
	"fmt"
	"time"
)

// ADL-04: the quality closed-loop. evalgate (LLM-as-judge) verdicts — written
// by the gateway for a SAMPLE of low-confidence medium-class requests and
// persisted to evalgate_results — are aggregated here into per-model and
// per-task-class quality scores, and into a single routing RECOMMENDATION with
// its justification (the data + the window).
//
// Scope honesty (the card requires "data + window"): evalgate only judges a
// sampled subset (medium class + confidence < 0.7), so the scores describe
// that subset over the window — never the whole org. The report states the
// sample scope and the window explicitly; the UI renders them as the applied
// caption. A window with no judged traffic returns a valid empty report
// (verdict "insufficient_data"), not an error — the same posture as the shadow
// comparison.

// QualityModelScore is the quality of one (primary, shadow) model pair over
// the window: the average cheap-model (primary) and premium-model (shadow)
// quality the judge assigned, plus the upgrade pressure (how often the judge
// said the premium would have done better).
type QualityModelScore struct {
	PrimaryModel   string  `json:"primary_model"`
	ShadowModel    string  `json:"shadow_model"`
	Verdicts       int     `json:"verdicts"`
	CheapQuality   float64 `json:"cheap_quality"`   // avg of cheap_quality (0..1)
	PremiumQuality float64 `json:"premium_quality"` // avg of premium_quality (0..1)
	UpgradeRate    float64 `json:"upgrade_rate"`    // fraction should_upgrade (0..1)
}

// QualityTaskClassScore is the quality breakdown by task class (request_logs
// task_id; NULL → "(untagged)"), so the screen shows which model serves which
// class of agentic task well.
type QualityTaskClassScore struct {
	TaskClass    string  `json:"task_class"`
	PrimaryModel string  `json:"primary_model"`
	Verdicts     int     `json:"verdicts"`
	CheapQuality float64 `json:"cheap_quality"`
	UpgradeRate  float64 `json:"upgrade_rate"`
}

// QualityRecommendation is the human-facing suggestion to change routing. The
// match_expr targets model_requested (the only valid rule field that can
// express "this model" — task_id is not a rule field), so it is a model-swap
// draft. Applying it is HUMAN-ONLY: the UI pre-fills the rule form with this
// draft and does NOT save it.
type QualityRecommendation struct {
	HasRecommendation bool    `json:"has_recommendation"`
	PrimaryModel      string  `json:"primary_model"`
	ShadowModel       string  `json:"shadow_model"`
	MatchExpr         string  `json:"match_expr"` // draft rule: model_requested == "<primary>"
	TargetModel       string  `json:"target_model"`
	Priority          int     `json:"priority"`
	UpgradeRate       float64 `json:"upgrade_rate"`
	Verdicts          int     `json:"verdicts"`
	Justification     string  `json:"justification"` // data + window
}

// QualityReport is the ADL-04 quality closed-loop payload for the CMP-01
// screen.
type QualityReport struct {
	OrgID           string                  `json:"org_id"`
	Period          string                  `json:"period"`
	From            time.Time               `json:"from"`
	To              time.Time               `json:"to"`
	TotalVerdicts   int                     `json:"total_verdicts"`
	ByModel         []QualityModelScore     `json:"by_model"`
	ByTaskClass     []QualityTaskClassScore `json:"by_task_class"`
	Recommendation  *QualityRecommendation  `json:"recommendation,omitempty"`
	Verdict         string                  `json:"verdict"` // has_data | insufficient_data
	SampleScopeNote string                  `json:"sample_scope_note"`
}

const (
	// qualityMinVerdicts: below this many judged samples the score is not
	// meaningful (mirrors shadowInsufficientOverlap in spirit).
	qualityMinVerdicts = 20
	// qualityRecommendUpgradeRate: recommend a swap only when the upgrade
	// pressure clearly exceeds a coin-flip (≥ 60% of judged samples say the
	// premium model would have been better).
	qualityRecommendUpgradeRate = 0.60
	// qualityDraftRulePriority: the default priority for the draft routing rule
	// (a low number = evaluated early; the human can change it before saving).
	qualityDraftRulePriority = 50
)

// GetQualityScores aggregates evalgate verdicts into per-model and
// per-task-class quality scores plus a routing recommendation, over [from,to].
// orgID empty = all orgs. org_id types differ across the two tables
// (request_logs.org_id is uuid, evalgate_results.org_id is text), so the org
// filter is applied on the request_logs side and both sides are cast to text
// for the join.
func (s *Store) GetQualityScores(ctx context.Context, orgID string, from, to time.Time) (*QualityReport, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	// The org filter rides on request_logs (uuid) — cast to text for parity
	// with evalgate_results.org_id (text) and the join key.
	orgFilter := ""
	var args []interface{}
	args = append(args, from, to)
	if orgID != "" {
		args = append(args, orgID)
		orgFilter = fmt.Sprintf(" AND rl.org_id::text = $%d", len(args))
	}

	// Per (cheap_model, premium_model) pair: the judge scored BOTH responses on
	// the same sampled request, so averaging per side gives the primary's
	// (cheap) quality and the shadow's (premium) quality on the SAME overlap —
	// directly comparable, exactly like the shadow cost comparison.
	const byModelQuery = `
		SELECT e.cheap_model,
		       e.premium_model,
		       COUNT(*) AS verdicts,
		       COALESCE(AVG(e.cheap_quality), 0)  AS cheap_q,
		       COALESCE(AVG(e.premium_quality), 0) AS premium_q,
		       COALESCE(AVG(e.should_upgrade::int::float8), 0) AS upgrade_rate
		FROM evalgate_results e
		JOIN request_logs rl ON rl.request_id = e.request_id
		WHERE e.created_at BETWEEN $1 AND $2` + " %s" + `
		GROUP BY e.cheap_model, e.premium_model
		ORDER BY verdicts DESC`

	rows, err := s.db.Query(ctx, fmt.Sprintf(byModelQuery, orgFilter), args...)
	if err != nil {
		return nil, fmt.Errorf("quality by-model query: %w", err)
	}
	var byModel []QualityModelScore
	total := 0
	for rows.Next() {
		var m QualityModelScore
		if err := rows.Scan(&m.PrimaryModel, &m.ShadowModel, &m.Verdicts, &m.CheapQuality, &m.PremiumQuality, &m.UpgradeRate); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan quality by-model row: %w", err)
		}
		total += m.Verdicts
		byModel = append(byModel, m)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate quality by-model rows: %w", err)
	}
	rows.Close()
	if byModel == nil {
		byModel = []QualityModelScore{}
	}

	// Per task class (request_logs.task_id; NULL → "(untagged)"), joined to the
	// judged request to carry the cheap model + upgrade flag.
	const byTaskQuery = `
		SELECT COALESCE(rl.task_id, ` + "'(untagged)'" + `) AS task_class,
		       e.cheap_model,
		       COUNT(*) AS verdicts,
		       COALESCE(AVG(e.cheap_quality), 0) AS cheap_q,
		       COALESCE(AVG(e.should_upgrade::int::float8), 0) AS upgrade_rate
		FROM evalgate_results e
		JOIN request_logs rl ON rl.request_id = e.request_id
		WHERE e.created_at BETWEEN $1 AND $2` + " %s" + `
		GROUP BY 1, e.cheap_model
		ORDER BY verdicts DESC`

	trows, err := s.db.Query(ctx, fmt.Sprintf(byTaskQuery, orgFilter), args...)
	if err != nil {
		return nil, fmt.Errorf("quality by-task query: %w", err)
	}
	var byTask []QualityTaskClassScore
	for trows.Next() {
		var g QualityTaskClassScore
		if err := trows.Scan(&g.TaskClass, &g.PrimaryModel, &g.Verdicts, &g.CheapQuality, &g.UpgradeRate); err != nil {
			trows.Close()
			return nil, fmt.Errorf("scan quality by-task row: %w", err)
		}
		byTask = append(byTask, g)
	}
	if err := trows.Err(); err != nil {
		trows.Close()
		return nil, fmt.Errorf("iterate quality by-task rows: %w", err)
	}
	trows.Close()
	if byTask == nil {
		byTask = []QualityTaskClassScore{}
	}

	rep := &QualityReport{
		OrgID:           orgID,
		Period:          "last_window",
		From:            from,
		To:              to,
		TotalVerdicts:   total,
		ByModel:         byModel,
		ByTaskClass:     byTask,
		Verdict:         "insufficient_data",
		SampleScopeNote: "LLM-as-judge sample (medium class, low confidence) — not the whole org",
	}
	if total > 0 {
		rep.Verdict = "has_data"
	}

	// Recommendation: the (primary, shadow) pair with the most judged samples
	// that also shows clear upgrade pressure. The match_expr targets
	// model_requested (task_id is not a valid rule field), so it drafts a
	// model-swap; applying is human-only (the UI pre-fills, never saves).
	if len(byModel) > 0 {
		top := byModel[0]
		if top.Verdicts >= qualityMinVerdicts && top.UpgradeRate >= qualityRecommendUpgradeRate {
			rep.Recommendation = &QualityRecommendation{
				HasRecommendation: true,
				PrimaryModel:      top.PrimaryModel,
				ShadowModel:       top.ShadowModel,
				MatchExpr:         fmt.Sprintf(`model_requested == %q`, top.PrimaryModel),
				TargetModel:       top.ShadowModel,
				Priority:          qualityDraftRulePriority,
				UpgradeRate:       top.UpgradeRate,
				Verdicts:          top.Verdicts,
				Justification: fmt.Sprintf(
					"Across %d judged samples in this window, the judge said the premium model (%s) would have answered better in %d%% of cases (cheap-model avg quality %.2f vs premium %.2f).",
					top.Verdicts, top.ShadowModel, int(top.UpgradeRate*100), top.CheapQuality, top.PremiumQuality,
				),
			}
		}
	}
	return rep, nil
}
