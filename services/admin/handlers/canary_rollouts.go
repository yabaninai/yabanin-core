package handlers

// HTTP surface (policy_pipelines.go pattern). Every mutation bumps the
// store-level canary version key (canarystore:ver:<orgID>), dropping the
// gateway rollout caches immediately; activation (PUT active_version) and
// rollback (PUT enabled=false) are single atomic store transactions.
//
// Gated by the existing routing.manage permission: a canary rollout IS model
// choice — the same sensitivity class the matrix already models as
// PermRoutingManage (the policy handlers' comment draws exactly this line).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// CanaryRolloutStore is the narrow store capability the canary handlers
type CanaryRolloutStore interface {
	CreateCanaryRollout(ctx context.Context, orgID, name, baseModel, canaryModel string, percent int, createdBy string) (adminstore.CanaryRollout, adminstore.CanaryRolloutVersion, error)
	GetCanaryRollout(ctx context.Context, orgID, rolloutID string) (adminstore.CanaryRollout, error)
	ListCanaryRollouts(ctx context.Context, orgID string) ([]adminstore.CanaryRollout, error)
	UpdateCanaryRollout(ctx context.Context, orgID, rolloutID string, enabled bool) (adminstore.CanaryRollout, error)
	CreateCanaryRolloutVersion(ctx context.Context, orgID, rolloutID, baseModel, canaryModel string, percent int, createdBy string) (adminstore.CanaryRolloutVersion, error)
	ListCanaryRolloutVersions(ctx context.Context, orgID, rolloutID string) ([]adminstore.CanaryRolloutVersion, error)
	SetActiveCanaryRolloutVersion(ctx context.Context, orgID, rolloutID string, version int) (adminstore.CanaryRollout, error)
	DeleteCanaryRollout(ctx context.Context, orgID, rolloutID string) error
	// CanaryRolloutEvidence is the D3 auto-Recommendation hook: measured
	// rollout health for a human decision (evidence only, never an action).
	CanaryRolloutEvidence(ctx context.Context, orgID, rolloutID string, window time.Duration) (adminstore.CanaryEvidence, error)
}

// compile pin: the production store implements the narrow capability.
var _ CanaryRolloutStore = (*adminstore.Store)(nil)

// canaryBodyLimit caps the JSON body (small structured payloads; a DoS
// bound, not a feature limit).
const canaryBodyLimit = 32 * 1024

// CanaryRolloutHandlers serves the canary rollout routes. The admin server
// wires it with SetCanaryRolloutHandlers over *adminstore.Store.
type CanaryRolloutHandlers struct {
	store CanaryRolloutStore
	// audit is the AdminHandlers journal hook (nil = no journal in bare
	// test instances).
	audit func(r *http.Request, action, resource, details string)
}

// NewCanaryRolloutHandlers builds the canary handlers over store.
func NewCanaryRolloutHandlers(store CanaryRolloutStore) *CanaryRolloutHandlers {
	return &CanaryRolloutHandlers{store: store}
}

// SetCanaryRolloutHandlers attaches the canary rollout handlers to the admin
// router. nil (the default) keeps the routes mounted but unwired: they
// answer 503 until the canarystore is wired by the admin server.
func (h *AdminHandlers) SetCanaryRolloutHandlers(o *CanaryRolloutHandlers) {
	h.canaryRollouts = o
	if o != nil {
		o.audit = h.auditLogAction
	}
}

// RequireOrgPermissionRoutingManage is the canary-surface variant of
// RequireOrgPermission (roles_authz.go) for adminstore.PermRoutingManage,
// with the org_settings-style resourceHidden difference: a caller with NO
// membership on the target org gets 404, not 403 — a foreign org must not be
// distinguishable from a nonexistent one. The name keeps the
// "RequireOrgPermission" fragment so the route inventories classify the
// chain as an org gate.
func (h *AdminHandlers) RequireOrgPermissionRoutingManage() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isRoot(r) {
				next.ServeHTTP(w, r)
				return
			}
			orgID := targetOrgID(r)
			if orgID == "" {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "org target required"})
				return
			}
			role, ok := h.callerRoleOnOrg(r, orgID)
			if !ok {
				writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
				return
			}
			if !adminstore.RoleHas(string(role), adminstore.PermRoutingManage) {
				writeJSON(w, http.StatusForbidden, apiError{Error: "insufficient permission for this organization"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// mountCanaryRollouts registers the canary rollout routes under the
// routing.manage org gate. Mounted unconditionally (nil handlers answer
// 503). The {id} path param is the org; cross-org rollout ids are invisible
// (the store answers 404 under the org-isolation GUC).
func (h *AdminHandlers) mountCanaryRollouts(protected chi.Router) {
	canary := protected.With(h.RequireOrgPermissionRoutingManage())
	canary.Get("/api/organizations/{id}/canary-rollouts", h.canaryRollouts.handleList)
	canary.Post("/api/organizations/{id}/canary-rollouts", h.canaryRollouts.handleCreate)
	canary.Get("/api/organizations/{id}/canary-rollouts/{rolloutId}", h.canaryRollouts.handleGet)
	canary.Put("/api/organizations/{id}/canary-rollouts/{rolloutId}", h.canaryRollouts.handleUpdate)
	canary.Delete("/api/organizations/{id}/canary-rollouts/{rolloutId}", h.canaryRollouts.handleRemove)
	canary.Get("/api/organizations/{id}/canary-rollouts/{rolloutId}/recommendation", h.canaryRollouts.handleRecommendation)
}

// unwired reports whether the canary store is missing and, when it is,
// writes the 503. Nil-receiver safe.
func (o *CanaryRolloutHandlers) unwired(w http.ResponseWriter) bool {
	if o == nil || o.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "canary rollout store not configured"})
		return true
	}
	return false
}

type canaryRolloutCreateBody struct {
	Name        string `json:"name"`
	BaseModel   string `json:"base_model"`
	CanaryModel string `json:"canary_model"`
	Percent     *int   `json:"percent"`
}

type canaryRolloutUpdateBody struct {
	// Content change (all three fields required together) appends a NEW
	// draft version — never an in-place edit.
	BaseModel     *string `json:"base_model"`
	CanaryModel   *string `json:"canary_model"`
	Percent       *int    `json:"percent"`
	ActiveVersion *int    `json:"active_version"`
	// Enabled flips the attach/rollback flag; false is the manual rollback.
	Enabled *bool `json:"enabled"`
}

// canaryDetail is the GET single-rollout payload: the rollout row plus its
// versions (newest first).
type canaryDetail struct {
	Rollout  adminstore.CanaryRollout          `json:"rollout"`
	Versions []adminstore.CanaryRolloutVersion `json:"versions"`
}

// validateCanaryTriple is the handler-side content gate (validatePolicyYAML
// parity): whole percent 1..99 (D2), non-empty distinct model names. The
// store re-validates (defense in depth for non-HTTP writers); this gate maps
// violations to clean 400s instead of store errors.
func validateCanaryTriple(w http.ResponseWriter, baseModel, canaryModel string, percent int) bool {
	if baseModel == "" || len(baseModel) > 256 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "base model must be 1 to 256 characters"})
		return false
	}
	if canaryModel == "" || len(canaryModel) > 256 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "canary model must be 1 to 256 characters"})
		return false
	}
	if baseModel == canaryModel {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "base and canary models must differ"})
		return false
	}
	if percent < 1 || percent > 99 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "canary percent must be a whole number between 1 and 99"})
		return false
	}
	return true
}

// handleList serves GET /api/organizations/{id}/canary-rollouts.
func (o *CanaryRolloutHandlers) handleList(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	rollouts, err := o.store.ListCanaryRollouts(r.Context(), r.PathValue("id"))
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rollouts, "count": len(rollouts)})
}

// handleCreate serves POST /api/organizations/{id}/canary-rollouts: creates
// the rollout with version 1 (draft, detached). Activating is the explicit
// PUT {active_version: 1} step.
func (o *CanaryRolloutHandlers) handleCreate(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID := r.PathValue("id")
	var body canaryRolloutCreateBody
	if !decodeCanaryBody(w, r, &body) {
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 256 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "name must be 1 to 256 characters"})
		return
	}
	if body.Percent == nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "percent is required"})
		return
	}
	baseModel, canaryModel := strings.TrimSpace(body.BaseModel), strings.TrimSpace(body.CanaryModel)
	if !validateCanaryTriple(w, baseModel, canaryModel, *body.Percent) {
		return
	}
	rollout, version, err := o.store.CreateCanaryRollout(r.Context(), orgID, name,
		baseModel, canaryModel, *body.Percent, o.callerEmail(r))
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	o.auditAction(r, "create", "canary_rollout", "rollout="+rollout.Name+",org="+orgID)
	writeJSON(w, http.StatusCreated, canaryDetail{Rollout: rollout, Versions: []adminstore.CanaryRolloutVersion{version}})
}

// handleGet serves GET /api/organizations/{id}/canary-rollouts/{rolloutId}:
// the rollout plus its versions. A foreign rolloutId is the same 404 as a
// missing one.
func (o *CanaryRolloutHandlers) handleGet(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID, rolloutID := r.PathValue("id"), r.PathValue("rolloutId")
	rollout, ok := o.visibleRollout(w, r, orgID, rolloutID)
	if !ok {
		return
	}
	versions, err := o.store.ListCanaryRolloutVersions(r.Context(), orgID, rolloutID)
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, canaryDetail{Rollout: rollout, Versions: versions})
}

// handleUpdate serves PUT /api/organizations/{id}/canary-rollouts/{rolloutId}.
// Every present field applies (nil fields keep the stored value):
//   - base_model+canary_model+percent (all three, together) → appends a NEW
//     draft version (content changes are versions, never in-place edits)
//   - active_version → points current_version at that version (the atomic
//     activation)
//   - enabled → flips the attach flag (false = the manual rollback, D3)
//
// The response carries the refreshed rollout row (use GET for the versions).
func (o *CanaryRolloutHandlers) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID, rolloutID := r.PathValue("id"), r.PathValue("rolloutId")
	var body canaryRolloutUpdateBody
	if !decodeCanaryBody(w, r, &body) {
		return
	}
	rollout, ok := o.visibleRollout(w, r, orgID, rolloutID)
	if !ok {
		return
	}
	applied := ""
	if content := canaryContentChange(body); content != nil {
		if !validateCanaryTriple(w, content.baseModel, content.canaryModel, content.percent) {
			return
		}
		if _, err := o.store.CreateCanaryRolloutVersion(r.Context(), orgID, rolloutID,
			content.baseModel, content.canaryModel, content.percent, o.callerEmail(r)); err != nil {
			o.writeStoreError(w, err)
			return
		}
		applied = "version"
	}
	if body.ActiveVersion != nil {
		activated, err := o.store.SetActiveCanaryRolloutVersion(r.Context(), orgID, rolloutID, *body.ActiveVersion)
		if err != nil {
			o.writeStoreError(w, err)
			return
		}
		rollout = activated
		applied = joinApplied(applied, "active_version")
	}
	if body.Enabled != nil && *body.Enabled != rollout.Enabled {
		updated, err := o.store.UpdateCanaryRollout(r.Context(), orgID, rolloutID, *body.Enabled)
		if err != nil {
			o.writeStoreError(w, err)
			return
		}
		rollout = updated
		applied = joinApplied(applied, "enabled")
	}
	if applied == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "nothing to update (set base_model+canary_model+percent, active_version or enabled)"})
		return
	}
	o.auditAction(r, "update", "canary_rollout", "rollout="+rollout.Name+",org="+orgID+",applied="+applied)
	writeJSON(w, http.StatusOK, canaryDetail{Rollout: rollout})
}

// handleRemove serves DELETE /api/organizations/{id}/canary-rollouts/{rolloutId}.
func (o *CanaryRolloutHandlers) handleRemove(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID, rolloutID := r.PathValue("id"), r.PathValue("rolloutId")
	rollout, ok := o.visibleRollout(w, r, orgID, rolloutID)
	if !ok {
		return
	}
	if err := o.store.DeleteCanaryRollout(r.Context(), orgID, rolloutID); err != nil {
		o.writeStoreError(w, err)
		return
	}
	o.auditAction(r, "delete", "canary_rollout", "rollout="+rollout.Name+",org="+orgID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleRecommendation serves GET
// /api/organizations/{id}/canary-rollouts/{rolloutId}/recommendation — the
// D3 auto-Recommendation hook: measured split + per-arm failure counts from
// request_logs over the window (default 24h, ?window_hours=1..720). Evidence
// for a human rollback decision; nothing here acts by itself.
func (o *CanaryRolloutHandlers) handleRecommendation(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID, rolloutID := r.PathValue("id"), r.PathValue("rolloutId")
	windowHours := 24
	if v := strings.TrimSpace(r.URL.Query().Get("window_hours")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 720 {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "window_hours must be between 1 and 720"})
			return
		}
		windowHours = n
	}
	evidence, err := o.store.CanaryRolloutEvidence(r.Context(), orgID, rolloutID, time.Duration(windowHours)*time.Hour)
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"evidence":      evidence,
		"action":        "manual", // D3: the system never rolls back by itself
		"rollback_hint": "PUT enabled=false is the manual rollback; it is atomic and never touches active streams",
	})
}

// canaryContentChange extracts the append-version triple from an update
// body: present only when at least one content field is set, and then ALL
// three must be present (partial content updates are rejected — the stored
// triple is never merged implicitly).
func canaryContentChange(body canaryRolloutUpdateBody) *canaryContent {
	hasBase, hasCanary, hasPercent := body.BaseModel != nil, body.CanaryModel != nil, body.Percent != nil
	if !hasBase && !hasCanary && !hasPercent {
		return nil
	}
	return &canaryContent{
		baseModel:   strings.TrimSpace(derefString(body.BaseModel)),
		canaryModel: strings.TrimSpace(derefString(body.CanaryModel)),
		percent:     derefInt(body.Percent),
	}
}

type canaryContent struct {
	baseModel, canaryModel string
	percent                int
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefInt(i *int) int {
	if i == nil {
		return 0
	}
	return *i
}

// visibleRollout looks rolloutID up within the PATH org only; a rollout of
// another org (or a missing one) is the same 404.
func (o *CanaryRolloutHandlers) visibleRollout(w http.ResponseWriter, r *http.Request, orgID, rolloutID string) (adminstore.CanaryRollout, bool) {
	rollout, err := o.store.GetCanaryRollout(r.Context(), orgID, rolloutID)
	if err != nil {
		o.writeStoreError(w, err)
		return adminstore.CanaryRollout{}, false
	}
	return rollout, true
}

// callerEmail extracts the acting admin's identity for created_by.
func (o *CanaryRolloutHandlers) callerEmail(r *http.Request) string {
	return adminNameFromContext(r)
}

// auditAction journals a canary mutation (nil-safe).
func (o *CanaryRolloutHandlers) auditAction(r *http.Request, action, resource, details string) {
	if o == nil || o.audit == nil {
		return
	}
	o.audit(r, action, resource, details)
}

// decodeCanaryBody reads a canary JSON body under the cap and rejects
// unknown fields (decodePolicyBody parity).
func decodeCanaryBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, canaryBodyLimit))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request body"})
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request body"})
		return false
	}
	return true
}

// writeStoreError maps store failures: not-found → 404, an org-unique
// constraint violation (duplicate name) → 409, a validation error → 400,
// anything else → a generic 500.
func (o *CanaryRolloutHandlers) writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, adminstore.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		writeJSON(w, http.StatusConflict, apiError{Error: "a rollout with this name already exists in this organization"})
		return
	}
	writeJSON(w, http.StatusInternalServerError, apiError{Error: "internal error"})
}
