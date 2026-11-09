package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// --- Agent budgets (G2 debt fix: admin CRUD for agent_budgets) ---

// GetAgentBudget handles GET /api/agent-keys/{id}/budget.
func (h *AdminHandlers) GetAgentBudget() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		if _, ok := h.agentKeyVisible(w, r, chi.URLParam(r, "id")); !ok {
			return
		}
		b, err := h.store.GetAgentBudget(r.Context(), chi.URLParam(r, "id"))
		if err != nil {
			h.respondError(w, r, err, http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, b)
	}
}

// UpsertAgentBudget handles PUT /api/agent-keys/{id}/budget
// {"daily_limit_cents": 5000}. Creating a budget AUTHORIZES the agent to
// spend up to that daily cap; until a row exists the agent is denied (403 on
// request). A zero/negative limit is rejected — revoke the key instead.
//
// AF-09: an optional expected {absent, daily_limit_cents} turns the upsert
// into an atomic compare-and-set for the audit rollback path; a stale
// rollback conflicts with 409 + current state.
//
// AUDIT-P1-03: for a DELEGATED child key (parent_id set) the new cap is
// validated against the parent's remaining headroom inside an advisory-
// locked transaction (plain and CAS variants alike) — widening one child
// past what the parent can still fund is refused with 409. The child's own
// current cap is freed from the sibling sum before the check, so shrinking
// one child always allows re-allocating that amount to another. Root keys
// keep the unconstrained legacy path (shrinking a parent only tightens the
// family — fail-closed).
func (h *AdminHandlers) UpsertAgentBudget() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		key, ok := h.agentKeyVisible(w, r, id)
		if !ok {
			return
		}
		var req struct {
			DailyLimitCents int64                              `json:"daily_limit_cents"`
			Expected        *adminstore.AgentBudgetExpectation `json:"expected,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		if req.DailyLimitCents <= 0 {
			h.respondError(w, r, fmt.Errorf("daily_limit_cents must be positive"), http.StatusBadRequest)
			return
		}
		if key.ParentID != nil {
			h.upsertDelegatedChildBudget(w, r, id, key, req.DailyLimitCents, req.Expected)
			return
		}
		if req.Expected != nil {
			cs := h.cas()
			if cs == nil {
				h.respondError(w, r, fmt.Errorf("preconditioned updates not supported"), http.StatusNotImplemented)
				return
			}
			current, err := cs.UpsertAgentBudgetPreconditioned(r.Context(), id, req.DailyLimitCents, req.Expected)
			if err != nil {
				if errors.Is(err, adminstore.ErrPreconditionFailed) {
					writeConflict(w, agentBudgetCurrent(id, current))
					return
				}
				h.respondError(w, r, err, http.StatusInternalServerError)
				return
			}
			// CAS success proves the previous state: exactly the expectation.
			var before any
			if !req.Expected.Absent {
				before = map[string]any{"agent_id": id, "daily_limit_cents": req.Expected.DailyLimitCents}
			}
			after := map[string]any{"agent_id": id, "daily_limit_cents": req.DailyLimitCents}
			h.auditLogActionDiff(r, "upsert", "agent_budget", "id="+id+",cents="+strconv.FormatInt(req.DailyLimitCents, 10), before, after)
			writeJSON(w, http.StatusOK, current)
			return
		}
		// AUX-14b: journal the previous budget (nil when none existed) so the
		// audit page can offer the reverse call (restore old cap / delete).
		var before any
		if prev, prevErr := h.store.GetAgentBudget(r.Context(), id); prevErr == nil && prev != nil {
			before = map[string]any{"agent_id": prev.AgentID, "daily_limit_cents": prev.DailyLimitCents}
		}
		b, err := h.store.UpsertAgentBudget(r.Context(), id, req.DailyLimitCents)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		after := map[string]any{"agent_id": id, "daily_limit_cents": req.DailyLimitCents}
		h.auditLogActionDiff(r, "upsert", "agent_budget", "id="+id+",cents="+strconv.FormatInt(req.DailyLimitCents, 10), before, after)
		writeJSON(w, http.StatusOK, b)
	}
}

// upsertDelegatedChildBudget applies the AUDIT-P1-03 invariant for a
// delegated child's budget upsert (plain and CAS variants). Refusals map to
// 409 with the sentinel message; a stale CAS expectation keeps the AF-09
// 409 + current-state shape.
func (h *AdminHandlers) upsertDelegatedChildBudget(w http.ResponseWriter, r *http.Request, id string, key *adminstore.AgentKey, cents int64, expect *adminstore.AgentBudgetExpectation) {
	ds := h.delegationBudget()
	if ds == nil {
		h.respondError(w, r, fmt.Errorf("delegation budget enforcement not supported"), http.StatusNotImplemented)
		return
	}
	var (
		b   *adminstore.AgentBudget
		err error
	)
	if expect != nil {
		b, err = ds.UpsertAgentBudgetPreconditionedChecked(r.Context(), id, cents, expect)
	} else {
		b, err = ds.UpsertAgentBudgetChecked(r.Context(), id, cents)
	}
	if err != nil {
		switch {
		case errors.Is(err, adminstore.ErrPreconditionFailed):
			writeConflict(w, agentBudgetCurrent(id, b))
		case errors.Is(err, adminstore.ErrNotFound):
			h.respondError(w, r, err, http.StatusNotFound)
		case errors.Is(err, adminstore.ErrParentBudgetMissing),
			errors.Is(err, adminstore.ErrDelegationHeadroomExceeded),
			errors.Is(err, adminstore.ErrParentNotDelegable):
			h.respondError(w, r, err, http.StatusConflict)
		default:
			h.respondError(w, r, err, http.StatusInternalServerError)
		}
		return
	}
	var before any
	if expect != nil && !expect.Absent {
		before = map[string]any{"agent_id": id, "daily_limit_cents": expect.DailyLimitCents}
	}
	after := map[string]any{"agent_id": id, "daily_limit_cents": cents}
	h.auditLogActionDiff(r, "upsert", "agent_budget", "id="+id+",cents="+strconv.FormatInt(cents, 10), before, after)
	writeJSON(w, http.StatusOK, b)
}

// agentBudgetCurrent renders the current row (nil when absent) for a 409 body.
func agentBudgetCurrent(id string, b *adminstore.AgentBudget) map[string]any {
	if b == nil {
		return nil
	}
	return map[string]any{"agent_id": id, "daily_limit_cents": b.DailyLimitCents}
}

// DeleteAgentBudget handles DELETE /api/agent-keys/{id}/budget — the agent
// returns to "no budget configured" (denied) until a new row is set.
//
// AF-09: an optional expected daily_limit_cents makes the delete
// conditional for the audit rollback path.
func (h *AdminHandlers) DeleteAgentBudget() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		if _, ok := h.agentKeyVisible(w, r, id); !ok {
			return
		}
		var req struct {
			ExpectedDailyLimitCents *int64 `json:"expected_daily_limit_cents,omitempty"`
		}
		if r.Body != nil {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
				h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
				return
			}
		}
		if req.ExpectedDailyLimitCents != nil {
			cs := h.cas()
			if cs == nil {
				h.respondError(w, r, fmt.Errorf("preconditioned updates not supported"), http.StatusNotImplemented)
				return
			}
			_, current, err := cs.DeleteAgentBudgetPreconditioned(r.Context(), id, *req.ExpectedDailyLimitCents)
			if err != nil {
				if errors.Is(err, adminstore.ErrPreconditionFailed) {
					writeConflict(w, agentBudgetCurrent(id, current))
					return
				}
				h.respondError(w, r, err, http.StatusInternalServerError)
				return
			}
			// CAS success proves the removed row held exactly the expected cap.
			before := map[string]any{"agent_id": id, "daily_limit_cents": *req.ExpectedDailyLimitCents}
			h.auditLogActionDiff(r, "delete", "agent_budget", "id="+id, before, nil)
			writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
			return
		}
		// AUX-14b: journal the removed budget so the audit page can offer to
		// restore it (a safe reverse PUT).
		var before any
		if prev, prevErr := h.store.GetAgentBudget(r.Context(), id); prevErr == nil && prev != nil {
			before = map[string]any{"agent_id": prev.AgentID, "daily_limit_cents": prev.DailyLimitCents}
		}
		if err := h.store.DeleteAgentBudget(r.Context(), id); err != nil {
			h.respondError(w, r, err, http.StatusNotFound)
			return
		}
		h.auditLogActionDiff(r, "delete", "agent_budget", "id="+id, before, nil)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	}
}
