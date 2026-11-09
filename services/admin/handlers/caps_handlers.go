package handlers

// W-CAPS: org caps — the admin surface over the beta limits (default
// 60 RPM / 200k TPM / $50 monthly budget; per-org overrides in org_caps,
// Enforcement lives in the gateway (pkg/gateway/ratelimit.go,
// YABANIN_ORG_CAPS shadow|enforce); this file owns read/write + rights.
//
// Rights (same matrix as the NEXT-18f org settings, so the caps endpoint
// behaves like its neighbors):
//
//	root                        — any org, everything;
//	org member + budgets.manage — own org: read + write;
//	org member without it       — 403 (the org is theirs, the setting is not);
//	no membership               — 404 (the org is invisible, no leak).
//
// null in a PUT field CLEARS that override — back to the beta default for
// (they have no beta default); the beta default is never "unlimited".

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// OrgCapsStore is the narrow capability interface for the org caps
// (type-asserted from StoreInterface like CASStore). The real adminstore.Store
// implements it; stores that predate W-CAPS answer 501 instead of silently
// degrading.
type OrgCapsStore interface {
	EffectiveOrgCaps(ctx context.Context, orgID string) (*adminstore.EffectiveOrgCaps, error)
	UpdateOrgCaps(ctx context.Context, orgID string, u adminstore.OrgCapsUpdate) error
}

// orgCapsStore returns the capability, or nil when unsupported.
func (h *AdminHandlers) orgCapsStore() OrgCapsStore {
	s, _ := h.store.(OrgCapsStore)
	return s
}

// mountOrgCapsRoutes registers the W-CAPS caps routes on an authenticated
// router (the `protected` group in SetupRouter). Gates live in the handlers.
func (h *AdminHandlers) mountOrgCapsRoutes(r chi.Router) {
	r.Get("/api/orgs/{id}/caps", h.GetOrgCaps())
	r.Put("/api/orgs/{id}/caps", h.PutOrgCaps())
}

// orgCapsAccess gates one request against the target org. It writes the
// error response and returns false when access is denied.
func (h *AdminHandlers) orgCapsAccess(w http.ResponseWriter, r *http.Request, orgID string) bool {
	if !h.requireStore(w, r) {
		return false
	}
	if h.orgCapsStore() == nil {
		h.respondError(w, r, fmt.Errorf("org caps store not available"), http.StatusNotImplemented)
		return false
	}
	if isRoot(r) {
		return true
	}
	role, ok := h.callerRoleOnOrg(r, orgID)
	if !ok {
		// No membership: the org must not be distinguishable from a
		// nonexistent one (resourceHidden semantics).
		writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
		return false
	}
	if !adminstore.RoleHas(string(role), adminstore.PermBudgetsManage) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "insufficient permission for this organization"})
		return false
	}
	return true
}

// orgCapsResponse is the GET/PUT payload: the effective caps, the measured
// month-to-date spend, and the raw overrides (null = beta default; for the
type orgCapsResponse struct {
	OrgID              string `json:"org_id"`
	RPM                int64  `json:"rpm"`
	TPM                int64  `json:"tpm"`
	MonthlyBudgetCents int64  `json:"monthly_budget_cents"`
	// split token caps (0 = off — no window for the dimension) and
	// the per-key TPM cap for every key of the org.
	InputTokensPerMin  int64 `json:"input_tokens_per_min"`
	OutputTokensPerMin int64 `json:"output_tokens_per_min"`
	KeyTokensPerMin    int64 `json:"key_tokens_per_min"`
	MonthSpendCents    int64 `json:"month_spend_cents"`
	BudgetExceeded     bool  `json:"budget_exceeded"`

	RPMOverride         *int64 `json:"rpm_override"`
	TPMOverride         *int64 `json:"tpm_override"`
	BudgetOverrideCents *int64 `json:"monthly_budget_override_cents"`
	InputTPMOverride    *int64 `json:"input_tokens_per_min_override"`
	OutputTPMOverride   *int64 `json:"output_tokens_per_min_override"`
	KeyTPMOverride      *int64 `json:"key_tokens_per_min_override"`
}

func orgCapsPayload(ctx context.Context, s OrgCapsStore, orgID string) (*orgCapsResponse, error) {
	caps, err := s.EffectiveOrgCaps(ctx, orgID)
	if err != nil {
		return nil, err
	}
	spend, err := spendForCaps(ctx, s, orgID)
	if err != nil {
		return nil, err
	}
	return &orgCapsResponse{
		OrgID:               caps.OrgID,
		RPM:                 caps.RPM,
		TPM:                 caps.TPM,
		MonthlyBudgetCents:  caps.MonthlyBudgetCents,
		InputTokensPerMin:   caps.InputTPM,
		OutputTokensPerMin:  caps.OutputTPM,
		KeyTokensPerMin:     caps.KeyTPM,
		MonthSpendCents:     spend,
		BudgetExceeded:      spend >= caps.MonthlyBudgetCents,
		RPMOverride:         caps.RPMOverride,
		TPMOverride:         caps.TPMOverride,
		BudgetOverrideCents: caps.BudgetOverrideCents,
		InputTPMOverride:    caps.InputTPMOverride,
		OutputTPMOverride:   caps.OutputTPMOverride,
		KeyTPMOverride:      caps.KeyTPMOverride,
	}, nil
}

// spendForCaps reads the month-to-date spend through the same store; stores
// that cannot measure spend (interface without the method) report 0 — the
// caps fields stay authoritative and the UI shows the honest zero state.
func spendForCaps(ctx context.Context, s OrgCapsStore, orgID string) (int64, error) {
	type spendSource interface {
		OrgMonthSpendCents(ctx context.Context, orgID string) (int64, error)
	}
	sp, ok := s.(spendSource)
	if !ok {
		return 0, nil
	}
	return sp.OrgMonthSpendCents(ctx, orgID)
}

// GetOrgCaps handles GET /api/orgs/{id}/caps — the effective caps block.
func (h *AdminHandlers) GetOrgCaps() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := chi.URLParam(r, "id")
		if orgID == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org ID is required"})
			return
		}
		if !h.orgCapsAccess(w, r, orgID) {
			return
		}
		out, err := orgCapsPayload(r.Context(), h.orgCapsStore(), orgID)
		if err != nil {
			if errors.Is(err, adminstore.ErrNotFound) {
				writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
				return
			}
			h.respondError(w, r, fmt.Errorf("get org caps: %w", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// PutOrgCaps handles PUT /api/orgs/{id}/caps.
// Body: {"rpm": 120, "tpm": 400000, "monthly_budget_cents": 10000000,
// "input_tokens_per_min": 300000, "output_tokens_per_min": 100000,
// "key_tokens_per_min": 50000, "reason": "..."} — every null field clears
// back to OFF); a value must be within the settable bounds. The reason is
// mandatory and lands in the journal next to the before/after snapshots.
func (h *AdminHandlers) PutOrgCaps() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := chi.URLParam(r, "id")
		if orgID == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org ID is required"})
			return
		}
		if !h.orgCapsAccess(w, r, orgID) {
			return
		}
		var req struct {
			RPM                *int64 `json:"rpm"`
			TPM                *int64 `json:"tpm"`
			MonthlyBudgetCents *int64 `json:"monthly_budget_cents"`
			InputTPM           *int64 `json:"input_tokens_per_min"`
			OutputTPM          *int64 `json:"output_tokens_per_min"`
			KeyTPM             *int64 `json:"key_tokens_per_min"`
			Reason             string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "malformed JSON body"})
			return
		}
		if mutationReason(req.Reason, r) == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "reason is required"})
			return
		}
		update := adminstore.OrgCapsUpdate{
			RPM:                req.RPM,
			TPM:                req.TPM,
			MonthlyBudgetCents: req.MonthlyBudgetCents,
			InputTPM:           req.InputTPM,
			OutputTPM:          req.OutputTPM,
			KeyTPM:             req.KeyTPM,
		}
		if err := adminstore.ValidateOrgCapsUpdate(update); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}

		before := h.orgCapsBefore(r, orgID)
		if err := h.orgCapsStore().UpdateOrgCaps(r.Context(), orgID, update); err != nil {
			if errors.Is(err, adminstore.ErrNotFound) {
				writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
				return
			}
			h.respondError(w, r, fmt.Errorf("update org caps: %w", err), http.StatusInternalServerError)
			return
		}
		h.auditOrgCaps(r, orgID, before)
		out, err := orgCapsPayload(r.Context(), h.orgCapsStore(), orgID)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("get org caps: %w", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// orgCapsBefore snapshots the current caps for the journal's before side. A
// read failure degrades to nil (the journal keeps the after side; the
// mutation itself is never blocked by a read-only snapshot problem).
func (h *AdminHandlers) orgCapsBefore(r *http.Request, orgID string) map[string]any {
	caps, err := h.orgCapsStore().EffectiveOrgCaps(r.Context(), orgID)
	if err != nil {
		return nil
	}
	return orgCapsMap(caps)
}

// auditOrgCaps journals one mutation with symmetric full-block before/after
// snapshots: after is re-read post-commit, so the journal shows exactly what
// changed (and any concurrent writer that slipped between).
func (h *AdminHandlers) auditOrgCaps(r *http.Request, orgID string, before map[string]any) {
	var after map[string]any
	if caps, err := h.orgCapsStore().EffectiveOrgCaps(r.Context(), orgID); err == nil {
		after = orgCapsMap(caps)
	}
	h.auditLogActionDiff(r, "update", "org_caps", "org="+orgID, before, after)
}

// orgCapsMap renders the effective caps as the journal snapshot.
func orgCapsMap(c *adminstore.EffectiveOrgCaps) map[string]any {
	return map[string]any{
		"org_id":                c.OrgID,
		"rpm":                   c.RPM,
		"tpm":                   c.TPM,
		"monthly_budget_cents":  c.MonthlyBudgetCents,
		"input_tokens_per_min":  c.InputTPM,
		"output_tokens_per_min": c.OutputTPM,
		"key_tokens_per_min":    c.KeyTPM,
		"rpm_override":          nullableIntJSON(c.RPMOverride),
		"tpm_override":          nullableIntJSON(c.TPMOverride),
		"budget_override_cents": nullableIntJSON(c.BudgetOverrideCents),
		"input_tpm_override":    nullableIntJSON(c.InputTPMOverride),
		"output_tpm_override":   nullableIntJSON(c.OutputTPMOverride),
		"key_tpm_override":      nullableIntJSON(c.KeyTPMOverride),
	}
}
