package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// GetTeamBudget handles GET /api/teams/{id}/budget.
// Returns the team's budget configuration and current month spend.
func (h *AdminHandlers) GetTeamBudget() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		teamID := chi.URLParam(r, "id")
		if _, ok := h.teamInScope(w, r, teamID); !ok {
			return
		}
		summary, err := h.store.GetTeamSpendSummary(r.Context(), teamID)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("team budget: %w", err), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, summary)
	}
}

// UpsertTeamBudget handles PUT /api/teams/{id}/budget.
// Body: {"monthly_limit_usd": 500.0, "hard_limit": true}
//
// AF-09: an optional expected {absent, monthly_limit_usd, hard_limit} turns
// the upsert into an atomic compare-and-set for the audit rollback path; a
// stale rollback conflicts with 409 + current state and never overwrites a
// newer limit.
func (h *AdminHandlers) UpsertTeamBudget() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		teamID := chi.URLParam(r, "id")
		if _, ok := h.teamInScope(w, r, teamID); !ok {
			return
		}

		var req struct {
			MonthlyLimitUSD float64                           `json:"monthly_limit_usd"`
			HardLimit       bool                              `json:"hard_limit"`
			Expected        *adminstore.TeamBudgetExpectation `json:"expected,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}

		if req.MonthlyLimitUSD <= 0 {
			h.respondError(w, r, fmt.Errorf("monthly_limit_usd must be positive"), http.StatusBadRequest)
			return
		}

		if req.Expected != nil {
			cs := h.cas()
			if cs == nil {
				h.respondError(w, r, fmt.Errorf("preconditioned updates not supported"), http.StatusNotImplemented)
				return
			}
			current, err := cs.UpsertTeamBudgetPreconditioned(r.Context(), teamID, req.MonthlyLimitUSD, req.HardLimit, req.Expected)
			if err != nil {
				if errors.Is(err, adminstore.ErrPreconditionFailed) {
					writeConflict(w, teamBudgetCurrent(teamID, current))
					return
				}
				h.respondError(w, r, fmt.Errorf("upsert team budget: %w", err), http.StatusInternalServerError)
				return
			}
			// CAS success proves the previous state: exactly the expectation
			// (nothing when expect.Absent), so the journal's before is exact.
			var before any
			if !req.Expected.Absent {
				before = map[string]any{
					"team_id":           teamID,
					"monthly_limit_usd": req.Expected.MonthlyLimitUSD,
					"hard_limit":        req.Expected.HardLimit,
				}
			}
			after := map[string]any{
				"team_id":           teamID,
				"monthly_limit_usd": req.MonthlyLimitUSD,
				"hard_limit":        req.HardLimit,
			}
			h.auditLogActionDiff(r, "update", "team_budget",
				fmt.Sprintf("team=%s limit=%.2f hard=%v", teamID, req.MonthlyLimitUSD, req.HardLimit), before, after)
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}

		// AUX-14b: journal the previous budget config (nil when none was
		// configured) so the audit page can offer the reverse call.
		var before any
		if prev, prevErr := h.store.GetTeamSpendSummary(r.Context(), teamID); prevErr == nil && prev != nil && prev.MonthlyLimitUSD > 0 {
			before = map[string]any{
				"team_id":           teamID,
				"monthly_limit_usd": prev.MonthlyLimitUSD,
				"hard_limit":        prev.HardLimit,
			}
		}

		if err := h.store.UpsertTeamBudget(r.Context(), teamID, req.MonthlyLimitUSD, req.HardLimit); err != nil {
			h.respondError(w, r, fmt.Errorf("upsert team budget: %w", err), http.StatusInternalServerError)
			return
		}

		after := map[string]any{
			"team_id":           teamID,
			"monthly_limit_usd": req.MonthlyLimitUSD,
			"hard_limit":        req.HardLimit,
		}
		h.auditLogActionDiff(r, "update", "team_budget",
			fmt.Sprintf("team=%s limit=%.2f hard=%v", teamID, req.MonthlyLimitUSD, req.HardLimit), before, after)

		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// teamBudgetCurrent renders the current row (nil when absent) for a 409 body.
func teamBudgetCurrent(teamID string, tb *adminstore.TeamBudget) map[string]any {
	if tb == nil {
		return nil
	}
	return map[string]any{
		"team_id":           teamID,
		"monthly_limit_usd": tb.MonthlyLimitUSD,
		"hard_limit":        tb.HardLimit,
	}
}

// DeleteTeamBudget handles DELETE /api/teams/{id}/budget.
//
// AF-09: an optional expected {monthly_limit_usd, hard_limit} makes the
// delete conditional — the rollback of an audited budget creation removes
// the row only while it still carries the created values.
func (h *AdminHandlers) DeleteTeamBudget() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		teamID := chi.URLParam(r, "id")
		if _, ok := h.teamInScope(w, r, teamID); !ok {
			return
		}

		var req struct {
			Expected *adminstore.TeamBudgetExpectation `json:"expected,omitempty"`
		}
		if r.Body != nil {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
				h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
				return
			}
		}

		if req.Expected != nil {
			cs := h.cas()
			if cs == nil {
				h.respondError(w, r, fmt.Errorf("preconditioned updates not supported"), http.StatusNotImplemented)
				return
			}
			_, current, err := cs.DeleteTeamBudgetPreconditioned(r.Context(), teamID, *req.Expected)
			if err != nil {
				if errors.Is(err, adminstore.ErrPreconditionFailed) {
					writeConflict(w, teamBudgetCurrent(teamID, current))
					return
				}
				h.respondError(w, r, fmt.Errorf("delete team budget: %w", err), http.StatusInternalServerError)
				return
			}
			h.auditLogActionDiff(r, "delete", "team_budget",
				fmt.Sprintf("team=%s", teamID), nil, nil)
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}

		// AUX-14b: journal the removed budget config so the audit page can
		// offer to restore it (a safe reverse PUT).
		var before any
		if prev, prevErr := h.store.GetTeamSpendSummary(r.Context(), teamID); prevErr == nil && prev != nil && prev.MonthlyLimitUSD > 0 {
			before = map[string]any{
				"team_id":           teamID,
				"monthly_limit_usd": prev.MonthlyLimitUSD,
				"hard_limit":        prev.HardLimit,
			}
		}

		if err := h.store.DeleteTeamBudget(r.Context(), teamID); err != nil {
			h.respondError(w, r, fmt.Errorf("delete team budget: %w", err), http.StatusInternalServerError)
			return
		}

		h.auditLogActionDiff(r, "delete", "team_budget",
			fmt.Sprintf("team=%s", teamID), before, nil)

		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// ListOrgTeamBudgets handles GET /api/organizations/{id}/team-budgets.
// Returns all team budgets for an organization.
func (h *AdminHandlers) ListOrgTeamBudgets() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := chi.URLParam(r, "id")
		if resolved := h.requireOrgScope(w, r, orgID, adminstore.PermBudgetsManage); resolved == "" {
			return
		}
		budgets, err := h.store.ListTeamBudgetsByOrg(r.Context(), orgID)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("list team budgets: %w", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, budgets)
	}
}

// teamInScope loads the team and hides it when it belongs to another org.
func (h *AdminHandlers) teamInScope(w http.ResponseWriter, r *http.Request, teamID string) (*adminstore.Team, bool) {
	team, err := h.store.GetTeamByID(r.Context(), teamID)
	if err != nil || team == nil {
		if err == nil {
			err = fmt.Errorf("team not found")
		}
		h.respondError(w, r, err, http.StatusNotFound)
		return nil, false
	}
	if h.resourceHidden(w, r, team.OrgID) {
		return nil, false
	}
	return team, true
}
