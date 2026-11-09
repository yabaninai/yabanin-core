package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/credits"
)

// NEXT-18f: org budget settings — per-org grace floor (§8), reservations
// mode (§9) and the default output-cap override. One settings block, three
// focused mutations, every mutation journalled with before/after and a
// mandatory operator reason.
//
// Rights (enforced here, not by route groups, so a foreign org id can be
// answered 404 without revealing it exists):
//
//	root                         — any org, everything;
//	org member + budgets.manage  — own org: read + grace/output-cap writes;
//	org member without it        — 403 (the org is theirs, the setting is not);
//	no membership                — 404 (the org is invisible, no leak).
//
// The reservations-mode switch is root-only (§9: platform rollout flag); a
// non-root caller gets 403 regardless of membership. Switching back to off
// is immediate — the mode is read at each admission decision.
//
// ROUTING: routes are registered via mountOrgBudgetSettingsRoutes; the
// The one-line call into SetupRouter is kept separate because router.go is
// owned by another component.

// OrgBudgetSettingsStore is the narrow capability interface for the org
// budget settings (type-asserted from StoreInterface like CASStore). The
// real adminstore.Store implements it; stores that predate NEXT-18f answer
// 501 instead of silently degrading.
type OrgBudgetSettingsStore interface {
	GetOrgBudgetSettings(ctx context.Context, orgID string) (*adminstore.OrgBudgetSettings, error)
	UpdateOrgGraceFloor(ctx context.Context, orgID string, floorCents *int64) error
	UpdateOrgReservationsMode(ctx context.Context, orgID, mode string) error
	UpdateOrgDefaultOutputCap(ctx context.Context, orgID string, capTokens *int64) error
}

// orgBudgetSettingsStore returns the capability, or nil when unsupported.
func (h *AdminHandlers) orgBudgetSettingsStore() OrgBudgetSettingsStore {
	s, _ := h.store.(OrgBudgetSettingsStore)
	return s
}

// deepOverdraftCents is the §8 root signal threshold: an org whose wallet
// sits below -$100 is surfaced as deep_overdraft (the historical default
// grace is -$1.00, so this is ten times past it — a genuine incident).
const deepOverdraftCents int64 = -10000

// mountOrgBudgetSettingsRoutes registers the NEXT-18f org settings routes on
// an authenticated router (the `protected` group in SetupRouter). Gates live
// in the handlers.
func (h *AdminHandlers) mountOrgBudgetSettingsRoutes(r chi.Router) {
	r.Get("/api/orgs/{id}/credits/grace", h.GetOrgBudgetSettings())
	r.Put("/api/orgs/{id}/credits/grace", h.PutOrgGraceFloor())
	r.Put("/api/orgs/{id}/reservations-mode", h.PutOrgReservationsMode())
	r.Put("/api/orgs/{id}/output-cap", h.PutOrgDefaultOutputCap())
}

// orgBudgetAccess gates one request against the target org. rootOnly marks
// the platform-level switch (reservations mode). It writes the error
// response and returns false when access is denied.
func (h *AdminHandlers) orgBudgetAccess(w http.ResponseWriter, r *http.Request, orgID string, rootOnly bool) bool {
	if !h.requireStore(w, r) {
		return false
	}
	if h.orgBudgetSettingsStore() == nil {
		h.respondError(w, r, fmt.Errorf("org budget settings store not available"), http.StatusNotImplemented)
		return false
	}
	if isRoot(r) {
		return true
	}
	if rootOnly {
		writeJSON(w, http.StatusForbidden, apiError{Error: "reservations mode is root-only"})
		return false
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

// orgBudgetSettingsResponse is the GET payload: the stored settings plus the
// context needed to act on them. balance_cents is null when the credits
// store is not wired (balance unknown — never fabricated); deep_overdraft
// is the §8 root signal (wallet below -$100).
//
// Reservations mode appears twice on purpose (N06-P03): reservations_mode
// keeps its historical meaning (the stored column — backward compatibility
// for existing consumers), saved_reservations_mode names that same stored
// value explicitly, and effective_reservations_mode is the mode runtime
// admission actually applies after the deployment gate clamped it down.
type orgBudgetSettingsResponse struct {
	OrgID                     string `json:"org_id"`
	GraceFloorCents           *int64 `json:"grace_floor_cents"`
	EffectiveGraceFloorCents  int64  `json:"effective_grace_floor_cents"`
	ReservationsMode          string `json:"reservations_mode"`
	SavedReservationsMode     string `json:"saved_reservations_mode"`
	EffectiveReservationsMode string `json:"effective_reservations_mode"`
	DefaultOutputCapTokens    *int64 `json:"default_output_cap_tokens"`
	BalanceCents              *int64 `json:"balance_cents"`
	DeepOverdraft             bool   `json:"deep_overdraft"`
}

// orgReservationsGate is the deployment rollout ceiling with the zero value
// normalized: a handler whose gate was never wired (tests, embedded routers)
// reports the config default off — the same fail-safe ResolveMode applies to
// the gateway env value. The clamp can only degrade a stored mode (§9),
// never upgrade one.
func (h *AdminHandlers) orgReservationsGate() budget.Mode {
	return budget.ResolveMode(string(h.reservationsGate))
}

// orgBudgetSettingsPayload renders the shared GET shape. The effective mode
// is computed by pkg/budget.EffectiveMode — the same function the gateway
// admission applies (Admission.orgSettings), so API and runtime derive one
// value; this handler never recomputes the rule.
func (h *AdminHandlers) orgBudgetSettingsPayload(ctx context.Context, orgID string, s *adminstore.OrgBudgetSettings) orgBudgetSettingsResponse {
	out := orgBudgetSettingsResponse{
		OrgID:                     s.OrgID,
		GraceFloorCents:           s.GraceFloorCents,
		EffectiveGraceFloorCents:  credits.DefaultConfig().GracePeriodCents,
		ReservationsMode:          s.ReservationsMode,
		SavedReservationsMode:     s.ReservationsMode,
		EffectiveReservationsMode: string(budget.EffectiveMode(h.orgReservationsGate(), budget.ResolveMode(s.ReservationsMode))),
		DefaultOutputCapTokens:    s.DefaultOutputCapTokens,
	}
	if s.GraceFloorCents != nil {
		out.EffectiveGraceFloorCents = *s.GraceFloorCents
	}
	if h.billing.creditStore != nil {
		if bal, err := h.billing.creditStore.GetBalance(ctx, orgID); err == nil {
			cents := bal.BalanceCents
			out.BalanceCents = &cents
			out.DeepOverdraft = cents < deepOverdraftCents
		}
	}
	return out
}

// orgBudgetSettingsAfter re-reads the settings post-commit and writes the
// response body; a read failure here is a 500 (the mutation itself committed).
func (h *AdminHandlers) orgBudgetSettingsAfter(w http.ResponseWriter, r *http.Request, orgID string) {
	settings, err := h.orgBudgetSettingsStore().GetOrgBudgetSettings(r.Context(), orgID)
	if err != nil {
		h.respondError(w, r, fmt.Errorf("get org budget settings: %w", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, h.orgBudgetSettingsPayload(r.Context(), orgID, settings))
}

// GetOrgBudgetSettings handles GET /api/orgs/{id}/credits/grace — the full
// settings block for the org (floor, mode, output cap, balance context).
// Root and the org's budgets.manage admins may read it.
func (h *AdminHandlers) GetOrgBudgetSettings() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := chi.URLParam(r, "id")
		if orgID == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org ID is required"})
			return
		}
		if !h.orgBudgetAccess(w, r, orgID, false) {
			return
		}
		settings, err := h.orgBudgetSettingsStore().GetOrgBudgetSettings(r.Context(), orgID)
		if err != nil {
			if errors.Is(err, adminstore.ErrNotFound) {
				writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
				return
			}
			h.respondError(w, r, fmt.Errorf("get org budget settings: %w", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, h.orgBudgetSettingsPayload(r.Context(), orgID, settings))
	}
}

// mutationReason resolves the mandatory operator reason: the JSON body field
// first, the X-Audit-Reason header as the fallback (the dashboard dialogs
// send the header, API consumers send the field).
func mutationReason(bodyReason string, r *http.Request) string {
	if reason := strings.TrimSpace(bodyReason); reason != "" {
		// Make the journal see the body reason the same way as a header
		// reason (recordAudit reads the header only).
		if auditReason(r) == "" {
			r.Header.Set(auditReasonHeader, reason)
		}
		return reason
	}
	return auditReason(r)
}

// PutOrgGraceFloor handles PUT /api/orgs/{id}/credits/grace.
// Body: {"grace_floor_cents": -500 | null, "reason": "..."} — null (or an
// absent field) resets to the platform default; an explicit 0 forbids
// overdraft and is preserved (AF-01); the valid range is [-100000, 0]
// (-$1000.00 … 0). The reason is mandatory and lands in the journal next to
// the before/after snapshots.
func (h *AdminHandlers) PutOrgGraceFloor() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := chi.URLParam(r, "id")
		if orgID == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org ID is required"})
			return
		}
		if !h.orgBudgetAccess(w, r, orgID, false) {
			return
		}
		var req struct {
			GraceFloorCents *int64 `json:"grace_floor_cents"`
			Reason          string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "malformed JSON body"})
			return
		}
		if mutationReason(req.Reason, r) == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "reason is required"})
			return
		}
		if req.GraceFloorCents != nil && !adminstore.ValidGraceFloorCents(*req.GraceFloorCents) {
			writeJSON(w, http.StatusBadRequest, apiError{
				Error: fmt.Sprintf("grace_floor_cents must be between %d and %d, or null for the platform default",
					adminstore.GraceFloorMinCents, adminstore.GraceFloorMaxCents),
			})
			return
		}

		before := h.orgBudgetSettingsBefore(r, orgID)
		if err := h.orgBudgetSettingsStore().UpdateOrgGraceFloor(r.Context(), orgID, req.GraceFloorCents); err != nil {
			if errors.Is(err, adminstore.ErrNotFound) {
				writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
				return
			}
			h.respondError(w, r, fmt.Errorf("update org grace floor: %w", err), http.StatusInternalServerError)
			return
		}
		h.auditOrgBudgetSettings(r, "org_grace_floor", orgID, before)
		h.orgBudgetSettingsAfter(w, r, orgID)
	}
}

// PutOrgReservationsMode handles PUT /api/orgs/{id}/reservations-mode.
// Body: {"mode": "off|shadow|enforce", "reason": "..."} — root-only (§9);
// the switch takes effect on the next admission decision, rolling back to
// off is immediate.
func (h *AdminHandlers) PutOrgReservationsMode() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := chi.URLParam(r, "id")
		if orgID == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org ID is required"})
			return
		}
		if !h.orgBudgetAccess(w, r, orgID, true) {
			return
		}
		var req struct {
			Mode   string `json:"mode"`
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "malformed JSON body"})
			return
		}
		if mutationReason(req.Reason, r) == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "reason is required"})
			return
		}
		if !adminstore.ValidReservationsMode(req.Mode) {
			writeJSON(w, http.StatusBadRequest, apiError{
				Error: fmt.Sprintf("mode must be one of: %s, %s, %s",
					adminstore.ReservationsOff, adminstore.ReservationsShadow, adminstore.ReservationsEnforce),
			})
			return
		}

		before := h.orgBudgetSettingsBefore(r, orgID)
		if err := h.orgBudgetSettingsStore().UpdateOrgReservationsMode(r.Context(), orgID, req.Mode); err != nil {
			if errors.Is(err, adminstore.ErrNotFound) {
				writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
				return
			}
			h.respondError(w, r, fmt.Errorf("update org reservations mode: %w", err), http.StatusInternalServerError)
			return
		}
		h.auditOrgBudgetSettings(r, "org_reservations_mode", orgID, before)
		h.orgBudgetSettingsAfter(w, r, orgID)
	}
}

// PutOrgDefaultOutputCap handles PUT /api/orgs/{id}/output-cap.
// Body: {"default_output_cap_tokens": 4096 | null, "reason": "..."} — the
// org override of the reserve-sizing fallback; null clears the override,
// an explicit value must be > 0.
func (h *AdminHandlers) PutOrgDefaultOutputCap() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := chi.URLParam(r, "id")
		if orgID == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org ID is required"})
			return
		}
		if !h.orgBudgetAccess(w, r, orgID, false) {
			return
		}
		var req struct {
			DefaultOutputCapTokens *int64 `json:"default_output_cap_tokens"`
			Reason                 string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "malformed JSON body"})
			return
		}
		if mutationReason(req.Reason, r) == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "reason is required"})
			return
		}
		if req.DefaultOutputCapTokens != nil && *req.DefaultOutputCapTokens <= 0 {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "default_output_cap_tokens must be positive, or null to clear"})
			return
		}

		before := h.orgBudgetSettingsBefore(r, orgID)
		if err := h.orgBudgetSettingsStore().UpdateOrgDefaultOutputCap(r.Context(), orgID, req.DefaultOutputCapTokens); err != nil {
			if errors.Is(err, adminstore.ErrNotFound) {
				writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
				return
			}
			h.respondError(w, r, fmt.Errorf("update org output cap: %w", err), http.StatusInternalServerError)
			return
		}
		h.auditOrgBudgetSettings(r, "org_output_cap", orgID, before)
		h.orgBudgetSettingsAfter(w, r, orgID)
	}
}

// orgBudgetSettingsBefore snapshots the current settings for the journal's
// before side. A read failure degrades to nil (the journal keeps the after
// side; the mutation itself is never blocked by a read-only snapshot
// problem).
func (h *AdminHandlers) orgBudgetSettingsBefore(r *http.Request, orgID string) map[string]any {
	settings, err := h.orgBudgetSettingsStore().GetOrgBudgetSettings(r.Context(), orgID)
	if err != nil {
		return nil
	}
	return orgBudgetSettingsMap(settings)
}

// auditOrgBudgetSettings journals one mutation with symmetric full-block
// before/after snapshots: after is re-read post-commit, so the journal shows
// exactly what changed (and any concurrent writer that slipped between).
func (h *AdminHandlers) auditOrgBudgetSettings(r *http.Request, resource, orgID string, before map[string]any) {
	var after map[string]any
	if settings, err := h.orgBudgetSettingsStore().GetOrgBudgetSettings(r.Context(), orgID); err == nil {
		after = orgBudgetSettingsMap(settings)
	}
	h.auditLogActionDiff(r, "update", resource, "org="+orgID, before, after)
}

// orgBudgetSettingsMap renders the stored settings as the journal snapshot.
func orgBudgetSettingsMap(s *adminstore.OrgBudgetSettings) map[string]any {
	return map[string]any{
		"org_id":                    s.OrgID,
		"grace_floor_cents":         nullableIntJSON(s.GraceFloorCents),
		"reservations_mode":         s.ReservationsMode,
		"default_output_cap_tokens": nullableIntJSON(s.DefaultOutputCapTokens),
	}
}

// nullableIntJSON makes a nullable int64 JSON-safe inside before/after maps
// (nil pointers become nil → JSON null).
func nullableIntJSON(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}
