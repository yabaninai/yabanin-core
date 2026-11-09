package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	evaluator "github.com/reireirei/yabanin/pkg/rulesengine"
)

// AUX-19: POST /api/rules/preview — read-only candidate-rule evaluation for
// the Rules screen. The console sends the draft rule plus optional sample
// requests; the handler compiles a throwaway evaluator.Snapshot for the
// candidate (per request, never cached — the production SnapshotCache is not
// touched) and answers with the honest verdict: matched or not, the effective
// target model, and a per-clause explanation.
//
// Trust boundaries:
//   - org scope comes from the trusted identity channel (the X-Yabanin-Org-Id
//     scope header / resolved scope context), never from the request body;
//   - the route sits in the root-only group, like every other /api/rules
//     route (MustBeRoot) — a non-root caller is 403'd before evaluation;
//   - the response echoes only caller-supplied sample fields and the rule's
//     own fields — no store lookups, no upstream credentials in the payload.
//
// A malformed expression is an explicit machine-readable 400
// (reason=invalid_match_expression), not a silent never-match and not a 500:
// RT-01 guarantees a nil AST never matches, but preview must TELL the admin.

// maxPreviewSamples bounds the sample batch: evaluation is in-memory and
// cheap, but the request body and response stay small and predictable.
const maxPreviewSamples = 25

// rulesPreviewError carries a machine-readable reason next to the human
// message (apiError has only the free-form "error" field).
type rulesPreviewError struct {
	Error  string `json:"error"`
	Reason string `json:"reason"`
}

type rulesPreviewSample struct {
	ModelRequested string `json:"model_requested"`
	SessionID      string `json:"session_id"`
	ClientIP       string `json:"client_ip"`
	UserAgent      string `json:"user_agent"`
}

type rulesPreviewRequest struct {
	MatchExpr   string               `json:"match_expr"`
	TargetModel string               `json:"target_model"`
	Priority    int                  `json:"priority"`
	OrgID       string               `json:"org_id"` // ignored: org scope is the trusted identity, never the body
	Samples     []rulesPreviewSample `json:"samples"`
}

type rulesPreviewTerm struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
	Actual   string `json:"actual"`
	Matched  bool   `json:"matched"`
}

type rulesPreviewResult struct {
	Index          int    `json:"index"`
	RequestedModel string `json:"requested_model"`
	Matched        bool   `json:"matched"`
	// EffectiveModel is where the request would route: the candidate's target
	// on match, otherwise the requested model (no override).
	EffectiveModel string             `json:"effective_model"`
	Terms          []rulesPreviewTerm `json:"terms"`
}

type rulesPreviewResponse struct {
	OrgID       string               `json:"org_id"`
	MatchExpr   string               `json:"match_expr"`
	TargetModel string               `json:"target_model"`
	Priority    int                  `json:"priority"`
	Results     []rulesPreviewResult `json:"results"`
	Summary     struct {
		Total   int `json:"total"`
		Matched int `json:"matched"`
	} `json:"summary"`
}

// PreviewRoutingRule evaluates a draft routing rule against sample requests.
func (h *AdminHandlers) PreviewRoutingRule() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req rulesPreviewRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}

		// Org scope from the trusted identity channel (the scope middleware's
		// resolved context, else the out-of-band scope header). A body org_id
		// is ignored by construction — there is no read of it anywhere.
		orgID := OrgScopeFromRequest(r)
		if orgID == "" {
			orgID = r.Header.Get(OrgHeader)
		}
		if orgID == "" {
			writeJSON(w, http.StatusBadRequest, rulesPreviewError{
				Error:  "missing org scope: set the " + OrgHeader + " header",
				Reason: "missing_org_scope",
			})
			return
		}

		// Explicit, machine-readable rejection for an expression that would
		// compile to a nil AST (never matches): preview exists to TELL the
		// admin this before saving, not to simulate the silent no-op.
		if !evaluator.ExprParses(req.MatchExpr) {
			writeJSON(w, http.StatusBadRequest, rulesPreviewError{
				Error:  "match expression does not parse against the rules grammar and would never match",
				Reason: "invalid_match_expression",
			})
			return
		}

		samples := req.Samples
		if len(samples) > maxPreviewSamples {
			samples = samples[:maxPreviewSamples]
		}

		// Candidate rule compiled exactly like the gateway does (RT-01
		// snapshot mechanics), but per request and never cached: preview has
		// no state effects and never enters the production SnapshotCache.
		// Enabled is always true — the preview shows what the rule WOULD do.
		candidate := evaluator.Rule{
			ID:          "preview",
			OrgID:       orgID,
			MatchExpr:   req.MatchExpr,
			TargetModel: req.TargetModel,
			Priority:    req.Priority,
			Enabled:     true,
		}
		snap := evaluator.NewSnapshot(orgID, []evaluator.Rule{candidate})

		resp := rulesPreviewResponse{
			OrgID:       orgID,
			MatchExpr:   req.MatchExpr,
			TargetModel: req.TargetModel,
			Priority:    req.Priority,
			Results:     make([]rulesPreviewResult, 0, len(samples)),
		}
		for i, s := range samples {
			ctx := evaluator.Context{
				OrgID:     orgID,
				SessionID: s.SessionID,
				ClientIP:  s.ClientIP,
				UserAgent: s.UserAgent,
			}
			// The verdict: the same Snapshot.Evaluate the gateway request
			// path runs. TraceTerms only describes the clauses.
			matched := snap.Evaluate(ctx, s.ModelRequested) != ""
			terms := evaluator.TraceTerms(req.MatchExpr, ctx, s.ModelRequested)
			effective := s.ModelRequested
			if matched {
				effective = req.TargetModel
			}
			if matched {
				resp.Summary.Matched++
			}
			resp.Results = append(resp.Results, rulesPreviewResult{
				Index:          i,
				RequestedModel: s.ModelRequested,
				Matched:        matched,
				EffectiveModel: effective,
				Terms:          convertPreviewTerms(terms),
			})
			resp.Summary.Total++
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func convertPreviewTerms(terms []evaluator.TermTrace) []rulesPreviewTerm {
	out := make([]rulesPreviewTerm, 0, len(terms))
	for _, t := range terms {
		out = append(out, rulesPreviewTerm{
			Field:    t.Field,
			Operator: t.Operator,
			Value:    t.Value,
			Actual:   t.Actual,
			Matched:  t.Matched,
		})
	}
	return out
}
