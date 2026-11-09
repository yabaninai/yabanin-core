package handlers

// prompts / versions / labels / partials over the adminstore prompt surface
// (migration 0010).
//
// The store is the narrow PromptStudioStore capability (*adminstore.Store
// satisfies it — compile pin, pkg/adminstore/promptstudio.go). Versioning
// semantics live in the store: PUT of a prompt APPENDS a version (draft
// follows the latest saved version); labels are movable pointers moved via
// the labels endpoint. This file adds boundary validation only: the ref-safe
// name grammar (the key templates and prompt_refs address), the params JSON
// object shape and the size bounds.
//
// PERMISSION GATE — WHY policies.manage (existing permission, no new one):
// prompts are pipeline INPUTS — a judge prompt decides verdicts and partials
// are substituted into policy pipelines — the exact sensitivity class the
// matrix already models as PermPoliciesManage (org-admin only; the
// policy-pipeline routes set the precedent). models.manage is the model
// catalog, keys.manage is credential custody; neither matches. The mount
// reuses RequireOrgPermissionPoliciesManage verbatim (root passes, a member
// with policies.manage passes, a member without it 403s, a non-member gets
// the resourceHidden 404).
//
// Cross-org RESOURCE ids are invisible: the handlers read rows through the
// org-scoped store, so a foreign promptId/partial name is the same 404 as a
// missing one. Duplicate names are a 409 (store unique violation, code
// 23505).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// PromptStudioStore is the narrow store capability the prompt studio
// it).
type PromptStudioStore interface {
	CreatePrompt(ctx context.Context, orgID, name, description, template string, params json.RawMessage, createdBy string) (adminstore.Prompt, adminstore.PromptVersion, error)
	GetPrompt(ctx context.Context, orgID, promptID string) (adminstore.Prompt, error)
	ListPrompts(ctx context.Context, orgID string) ([]adminstore.Prompt, error)
	UpdatePrompt(ctx context.Context, orgID, promptID, template string, params json.RawMessage, createdBy string, expectedVersion int) (adminstore.PromptVersion, error)
	PromoteLabel(ctx context.Context, orgID, promptID, label string, version int) (adminstore.PromptLabel, error)
	ListPromptLabels(ctx context.Context, orgID, promptID string) ([]adminstore.PromptLabel, error)
	ListPromptVersions(ctx context.Context, orgID, promptID string) ([]adminstore.PromptVersion, error)
	DeletePrompt(ctx context.Context, orgID, promptID string) error
	CreatePartial(ctx context.Context, orgID, name, body string) (adminstore.Partial, error)
	UpdatePartial(ctx context.Context, orgID, name, body string, expectedVersion int) (adminstore.Partial, error)
	GetPartial(ctx context.Context, orgID, name string) (adminstore.Partial, error)
	ListPartials(ctx context.Context, orgID string) ([]adminstore.Partial, error)
	DeletePartial(ctx context.Context, orgID, name string) error
}

// compile pin: the production store implements the narrow capability.
var _ PromptStudioStore = (*adminstore.Store)(nil)

// Sizing bounds for the prompt studio surface.
const (
	// promptBodyLimit caps the JSON body (a template plus params; the
	// biggest realistic templates stay far below this — a DoS bound, not a
	// feature limit).
	promptBodyLimit = 128 * 1024
	// promptNameMaxLen mirrors the store/ref grammar bound.
	promptNameMaxLen = 256
	// promptDescriptionMaxLen mirrors the 0010 CHECK constraint.
	promptDescriptionMaxLen = 1024
	// promptParamsMaxLen mirrors the store bound.
	promptParamsMaxLen = 16 * 1024
	// partialBodyMaxLen mirrors adminstore.maxPartialBodyBytes (in turn
	// aligned with the builtins substitution step's limit).
	partialBodyMaxLen = 64 * 1024
)

// PromptStudioHandlers serves the prompt studio routes. The admin server
// wires it with SetPromptStudioHandlers over *adminstore.Store.
type PromptStudioHandlers struct {
	store PromptStudioStore
	// audit is the AdminHandlers journal hook (wired by
	// SetPromptStudioHandlers; nil = no journal in bare test instances).
	audit func(r *http.Request, action, resource, details string)
}

// NewPromptStudioHandlers builds the prompt studio handlers over store.
func NewPromptStudioHandlers(store PromptStudioStore) *PromptStudioHandlers {
	return &PromptStudioHandlers{store: store}
}

// SetPromptStudioHandlers attaches the prompt studio handlers to the admin
// router. nil (the default) keeps the routes mounted but unwired: they
// answer 503 until the store is wired by the admin server.
func (h *AdminHandlers) SetPromptStudioHandlers(o *PromptStudioHandlers) {
	h.promptStudio = o
	if o != nil {
		o.audit = h.auditLogAction
	}
}

// mountPromptStudio registers the prompt studio routes under the org
// permission gate (policies.manage — see the file comment). Mounted
// unconditionally (nil handlers answer 503): the route inventories
// param is the org; RequireOrgPermissionPoliciesManage resolves it and hides
// a foreign org (404) or 403s a member without policies.manage.
func (h *AdminHandlers) mountPromptStudio(protected chi.Router) {
	prompts := protected.With(h.RequireOrgPermissionPoliciesManage())
	prompts.Get("/api/organizations/{id}/prompts", h.promptStudio.handleList)
	prompts.Post("/api/organizations/{id}/prompts", h.promptStudio.handleCreate)
	prompts.Get("/api/organizations/{id}/prompts/{promptId}", h.promptStudio.handleGet)
	prompts.Put("/api/organizations/{id}/prompts/{promptId}", h.promptStudio.handleUpdate)
	prompts.Delete("/api/organizations/{id}/prompts/{promptId}", h.promptStudio.handleRemove)
	prompts.Post("/api/organizations/{id}/prompts/{promptId}/labels", h.promptStudio.handlePromoteLabel)
	prompts.Get("/api/organizations/{id}/partials", h.promptStudio.handlePartialList)
	prompts.Post("/api/organizations/{id}/partials", h.promptStudio.handlePartialCreate)
	prompts.Put("/api/organizations/{id}/partials/{partialName}", h.promptStudio.handlePartialUpdate)
	prompts.Delete("/api/organizations/{id}/partials/{partialName}", h.promptStudio.handlePartialRemove)
}

// unwired reports whether the store is missing and, when it is, writes the
// 503. Nil-receiver safe: the routes are mounted unconditionally.
func (o *PromptStudioHandlers) unwired(w http.ResponseWriter) bool {
	if o == nil || o.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "prompt studio store not configured"})
		return true
	}
	return false
}

type promptCreateBody struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Template    string          `json:"template"`
	Params      json.RawMessage `json:"params"`
}

type promptUpdateBody struct {
	Version  *int            `json:"version"`
	Template string          `json:"template"`
	Params   json.RawMessage `json:"params"`
}

type promptLabelBody struct {
	Label   string `json:"label"`
	Version *int   `json:"version"`
}

type partialCreateBody struct {
	Name string `json:"name"`
	Body string `json:"body"`
}

type partialUpdateBody struct {
	Version *int   `json:"version"`
	Body    string `json:"body"`
}

// promptDetail is the GET single-prompt payload: the prompt row plus its
// versions (newest first) and label bindings.
type promptDetail struct {
	Prompt   adminstore.Prompt          `json:"prompt"`
	Versions []adminstore.PromptVersion `json:"versions"`
	Labels   []adminstore.PromptLabel   `json:"labels"`
}

// handleList serves GET /api/organizations/{id}/prompts.
func (o *PromptStudioHandlers) handleList(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	prompts, err := o.store.ListPrompts(r.Context(), r.PathValue("id"))
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": prompts, "count": len(prompts)})
}

// handleCreate serves POST /api/organizations/{id}/prompts: creates the
// prompt with version 1 and the draft binding.
func (o *PromptStudioHandlers) handleCreate(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID := r.PathValue("id")
	var body promptCreateBody
	if !o.decodeBody(w, r, &body) {
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > promptNameMaxLen {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "name must be 1 to 256 characters"})
		return
	}
	if len(body.Description) > promptDescriptionMaxLen {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "description must be at most 1024 characters"})
		return
	}
	if strings.TrimSpace(body.Template) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "template is required"})
		return
	}
	params, ok := validatePromptParamsBody(w, body.Params)
	if !ok {
		return
	}

	p, v, err := o.store.CreatePrompt(r.Context(), orgID, name, body.Description, body.Template, params, adminNameFromContext(r))
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	o.auditAction(r, "create", "prompt", "prompt="+p.Name+",org="+orgID)
	writeJSON(w, http.StatusCreated, promptDetail{Prompt: p, Versions: []adminstore.PromptVersion{v}})
}

// handleGet serves GET /api/organizations/{id}/prompts/{promptId}: the
// prompt plus versions and labels. A foreign promptId is the same 404 as a
// missing one (resourceHidden for org-scoped rows).
func (o *PromptStudioHandlers) handleGet(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID, promptID := r.PathValue("id"), r.PathValue("promptId")
	p, ok := o.visiblePrompt(w, r, orgID, promptID)
	if !ok {
		return
	}
	versions, err := o.store.ListPromptVersions(r.Context(), orgID, promptID)
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	labels, err := o.store.ListPromptLabels(r.Context(), orgID, promptID)
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, promptDetail{Prompt: p, Versions: versions, Labels: labels})
}

// handleUpdate serves PUT /api/organizations/{id}/prompts/{promptId}: the
// body appends a NEW version (never an in-place edit — immutable history is
// the point) and the draft label follows it. The response carries the
// refreshed prompt row plus the new version (use GET for the full detail).
func (o *PromptStudioHandlers) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID, promptID := r.PathValue("id"), r.PathValue("promptId")
	var body promptUpdateBody
	if !o.decodeBody(w, r, &body) {
		return
	}
	p, ok := o.visiblePrompt(w, r, orgID, promptID)
	if !ok {
		return
	}
	if body.Version == nil || *body.Version < 1 {
		writeJSON(w, http.StatusPreconditionRequired, apiError{Error: "version is required"})
		return
	}
	if strings.TrimSpace(body.Template) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "template is required"})
		return
	}
	params, ok := validatePromptParamsBody(w, body.Params)
	if !ok {
		return
	}
	v, err := o.store.UpdatePrompt(r.Context(), orgID, promptID, body.Template, params, adminNameFromContext(r), *body.Version)
	if err != nil {
		if errors.Is(err, adminstore.ErrPreconditionFailed) {
			versions, _ := o.store.ListPromptVersions(r.Context(), orgID, promptID)
			current := 0
			if len(versions) > 0 {
				current = versions[0].Version
			}
			writeJSON(w, http.StatusConflict, map[string]any{"error": "version conflict: prompt changed since it was loaded", "current_version": current})
			return
		}
		o.writeStoreError(w, err)
		return
	}
	o.auditAction(r, "update", "prompt", "prompt="+p.Name+",org="+orgID+",version="+itoaPrompt(v.Version))
	writeJSON(w, http.StatusOK, promptDetail{Prompt: p, Versions: []adminstore.PromptVersion{v}})
}

// handlePromoteLabel serves POST
// /api/organizations/{id}/prompts/{promptId}/labels: binds {label, version}
// (upsert — the previous binding of the same label moves).
func (o *PromptStudioHandlers) handlePromoteLabel(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID, promptID := r.PathValue("id"), r.PathValue("promptId")
	var body promptLabelBody
	if !o.decodeBody(w, r, &body) {
		return
	}
	label := strings.TrimSpace(body.Label)
	switch label {
	case adminstore.PromptLabelDraft, adminstore.PromptLabelActive, adminstore.PromptLabelCanary, adminstore.PromptLabelCustom:
	default:
		writeJSON(w, http.StatusBadRequest, apiError{Error: "label must be one of draft|active|canary|custom"})
		return
	}
	if body.Version == nil || *body.Version < 1 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "version must be >= 1"})
		return
	}
	p, ok := o.visiblePrompt(w, r, orgID, promptID)
	if !ok {
		return
	}
	l, err := o.store.PromoteLabel(r.Context(), orgID, promptID, label, *body.Version)
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	o.auditAction(r, "update", "prompt_label", "prompt="+p.Name+",org="+orgID+",label="+label+",version="+itoaPrompt(l.Version))
	writeJSON(w, http.StatusOK, map[string]any{"label": l})
}

// handleRemove serves DELETE /api/organizations/{id}/prompts/{promptId}.
func (o *PromptStudioHandlers) handleRemove(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID, promptID := r.PathValue("id"), r.PathValue("promptId")
	p, ok := o.visiblePrompt(w, r, orgID, promptID)
	if !ok {
		return
	}
	if err := o.store.DeletePrompt(r.Context(), orgID, promptID); err != nil {
		o.writeStoreError(w, err)
		return
	}
	o.auditAction(r, "delete", "prompt", "prompt="+p.Name+",org="+orgID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handlePartialList serves GET /api/organizations/{id}/partials.
func (o *PromptStudioHandlers) handlePartialList(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	partials, err := o.store.ListPartials(r.Context(), r.PathValue("id"))
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": partials, "count": len(partials)})
}

// handlePartialCreate serves POST /api/organizations/{id}/partials.
func (o *PromptStudioHandlers) handlePartialCreate(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID := r.PathValue("id")
	var body partialCreateBody
	if !o.decodeBody(w, r, &body) {
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > promptNameMaxLen {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "name must be 1 to 256 characters"})
		return
	}
	if !o.validatePartialBody(w, body.Body) {
		return
	}
	p, err := o.store.CreatePartial(r.Context(), orgID, name, body.Body)
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	o.auditAction(r, "create", "partial", "partial="+p.Name+",org="+orgID)
	writeJSON(w, http.StatusCreated, map[string]any{"partial": p})
}

// handlePartialUpdate serves PUT /api/organizations/{id}/partials/{partialName}:
// replaces the body and bumps the partial's version. Missing/foreign → 404.
func (o *PromptStudioHandlers) handlePartialUpdate(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID, name := r.PathValue("id"), r.PathValue("partialName")
	var body partialUpdateBody
	if !o.decodeBody(w, r, &body) {
		return
	}
	if !o.validatePartialBody(w, body.Body) {
		return
	}
	if _, err := o.store.GetPartial(r.Context(), orgID, name); err != nil {
		o.writeStoreError(w, err)
		return
	}
	if body.Version == nil || *body.Version < 1 {
		writeJSON(w, http.StatusPreconditionRequired, apiError{Error: "version is required"})
		return
	}
	p, err := o.store.UpdatePartial(r.Context(), orgID, name, body.Body, *body.Version)
	if err != nil {
		if errors.Is(err, adminstore.ErrPreconditionFailed) {
			current, getErr := o.store.GetPartial(r.Context(), orgID, name)
			if getErr != nil {
				o.writeStoreError(w, getErr)
				return
			}
			writeJSON(w, http.StatusConflict, map[string]any{"error": "version conflict: partial changed since it was loaded", "current_version": current.Version})
			return
		}
		o.writeStoreError(w, err)
		return
	}
	o.auditAction(r, "update", "partial", "partial="+p.Name+",org="+orgID+",version="+itoaPrompt(p.Version))
	writeJSON(w, http.StatusOK, map[string]any{"partial": p})
}

// handlePartialRemove serves DELETE
// /api/organizations/{id}/partials/{partialName}.
func (o *PromptStudioHandlers) handlePartialRemove(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID, name := r.PathValue("id"), r.PathValue("partialName")
	if err := o.store.DeletePartial(r.Context(), orgID, name); err != nil {
		o.writeStoreError(w, err)
		return
	}
	o.auditAction(r, "delete", "partial", "partial="+name+",org="+orgID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// visiblePrompt looks promptID up within the PATH org only. A prompt of
// another org (or a missing one) is the same 404 — cross-org resource ids
// stay invisible (the resourceHidden semantics for org-scoped rows).
func (o *PromptStudioHandlers) visiblePrompt(w http.ResponseWriter, r *http.Request, orgID, promptID string) (adminstore.Prompt, bool) {
	p, err := o.store.GetPrompt(r.Context(), orgID, promptID)
	if err != nil {
		o.writeStoreError(w, err)
		return adminstore.Prompt{}, false
	}
	return p, true
}

// validatePromptParamsBody checks the optional params document (absent/empty
// = '{}'; otherwise a JSON object within the store bound). Writes the 400
// itself (false = response written).
func validatePromptParamsBody(w http.ResponseWriter, raw json.RawMessage) (json.RawMessage, bool) {
	if len(raw) == 0 {
		return nil, true
	}
	if len(raw) > promptParamsMaxLen {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "params must be at most 16384 bytes"})
		return nil, false
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "params must be a JSON object"})
		return nil, false
	}
	return raw, true
}

// validatePartialBody applies the size bound shared with the builtins
// substitution step (a partial the step would refuse must never be storable).
// Writes the 400 itself (false = response written).
func (o *PromptStudioHandlers) validatePartialBody(w http.ResponseWriter, body string) bool {
	if body == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "body is required"})
		return false
	}
	if len(body) > partialBodyMaxLen {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "body must be at most 65536 bytes"})
		return false
	}
	return true
}

// auditAction journals a prompt studio mutation (nil-safe: bare test
// instances without SetPromptStudioHandlers skip the journal).
func (o *PromptStudioHandlers) auditAction(r *http.Request, action, resource, details string) {
	if o == nil || o.audit == nil {
		return
	}
	o.audit(r, action, resource, details)
}

// decodePromptBody reads a prompt studio JSON body under the cap and rejects
// unknown fields — a typo'd payload 400s instead of silently dropping, say,
// a template field under a different name.
func (o *PromptStudioHandlers) decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, promptBodyLimit))
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
// constraint violation (duplicate name) → 409, anything else → a generic 500
// (the store error text can carry driver internals; it goes to the log,
// never to the wire).
func (o *PromptStudioHandlers) writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, adminstore.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		writeJSON(w, http.StatusConflict, apiError{Error: "a resource with this name already exists in this organization"})
		return
	}
	writeJSON(w, http.StatusInternalServerError, apiError{Error: "internal error"})
}

// itoaPrompt formats small integers for audit details.
func itoaPrompt(v int) string {
	return strconv.Itoa(v)
}
