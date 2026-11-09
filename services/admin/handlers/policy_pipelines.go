package handlers

// OP-0b (OUTPLAY-PLAN-2026-10-06 §3): admin CRUD for versioned policy
// pipelines — the policystore HTTP surface.
//
// The store is the narrow PolicyPipelineStore capability (*adminstore.Store
// satisfies it — compile pin, pkg/adminstore/policystore.go). Validation
// BOUNDARY (owner decision 2026-11-04 (a), STRICT EVERYWHERE FAIL-CLOSED):
// every stored policy document passes the SAME strict pkg/pipeline.ParsePolicy
// schema the gateway compiles at load time (unknown fields are errors, one
// document, non-empty steps) plus Policy.Validate (structure, no registries).
// An unparseable policy is NEVER stored — the UI validates through the same
// parser at save time (POST /policies/validate) and the CLI reconciler parses
// the declarations with the same schema, so every writer (UI, API, git
// reconcile) shares one parser. FULL compilation (detector/script resolution)
// still happens gateway-side when a version is loaded — a document with an
// unknown detector NAME passes here and fails visibly (in the decision log)
// at load; that residual boundary keeps the admin plane independent of the
// engine's registry evolution.
//
// GIT AUTHORSHIP (owner decision 2026-11-04, closes G3): the API accepts no
// caller-supplied git_sha. git_sha is the reconcile drift detector's anchor
// ("this version came from git rev X"); an API path that records whatever
// the caller sends would make UI edits indistinguishable from reconciled
// git content — the honor-system spoof. UI/API-authored versions store
// git_sha="" (the drift detector's "authored outside git" attribution);
// only `yb policies reconcile` records a real sha.
//
// Cache invalidation is store-level (SetPolicyVersionBumper → the
// policystore:ver:<orgID> Redis key, contract on
// adminstore.PolicyVersionKeyPrefix): every mutation path bumps, including
// no bumper of its own.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/pipeline"
)

// PolicyPipelineStore is the narrow store capability the policy handlers
// consume (exactly the OP-0b contract; *adminstore.Store satisfies it).
type PolicyPipelineStore interface {
	CreatePolicy(ctx context.Context, orgID, name, yamlDoc, gitSHA, createdBy string) (adminstore.PolicyPipeline, adminstore.PolicyVersion, error)
	GetPolicy(ctx context.Context, orgID, policyID string) (adminstore.PolicyPipeline, error)
	ListPolicies(ctx context.Context, orgID string) ([]adminstore.PolicyPipeline, error)
	UpdatePolicy(ctx context.Context, orgID, policyID string, enabled bool) (adminstore.PolicyPipeline, error)
	CreatePolicyVersion(ctx context.Context, orgID, policyID, yamlDoc, gitSHA, createdBy string) (adminstore.PolicyVersion, error)
	ListPolicyVersions(ctx context.Context, orgID, policyID string) ([]adminstore.PolicyVersion, error)
	SetActivePolicyVersion(ctx context.Context, orgID, policyID string, version int) (adminstore.PolicyPipeline, error)
	SetPolicyAttachments(ctx context.Context, orgID, policyID string, atts []adminstore.PolicyAttachment) ([]adminstore.PolicyAttachment, error)
	ListPolicyAttachments(ctx context.Context, orgID, policyID string) ([]adminstore.PolicyAttachment, error)
	DeletePolicy(ctx context.Context, orgID, policyID string) error
	// UpdatePolicyCAS applies a whole
	// preconditioned PUT atomically — see adminstore.UpdatePolicyCAS.
	UpdatePolicyCAS(ctx context.Context, orgID, policyID string, upd adminstore.PolicyUpdate, expectVersion *int, createdBy string) (adminstore.PolicyPipeline, adminstore.PolicyVersion, error)
}

// compile pin: the production store implements the narrow capability.
var _ PolicyPipelineStore = (*adminstore.Store)(nil)

// Sizing bounds for the policy surface.
const (
	// policyBodyLimit caps the JSON body (a policy YAML document plus
	// attachments metadata; the biggest realistic YPP documents stay far
	// below this — it is a DoS bound, not a feature limit).
	policyBodyLimit = 128 * 1024
	// policyMaxAttachments bounds one replace-all set.
	policyMaxAttachments = 64
	// policyAttachmentFieldMaxLen bounds attachment string fields.
	policyAttachmentFieldMaxLen = 256
	// policyAttachmentMaxPriority bounds the priority integer.
	policyAttachmentMaxPriority = 1_000_000
)

// PolicyPipelineHandlers serves the policy pipeline routes. The admin server
// wires it with SetPolicyPipelineHandlers over *adminstore.Store.
type PolicyPipelineHandlers struct {
	store PolicyPipelineStore
	// audit is the AdminHandlers journal hook (wired by
	// SetPolicyPipelineHandlers; nil = no journal in bare test instances).
	audit func(r *http.Request, action, resource, details string)
}

// NewPolicyPipelineHandlers builds the policy handlers over store.
func NewPolicyPipelineHandlers(store PolicyPipelineStore) *PolicyPipelineHandlers {
	return &PolicyPipelineHandlers{store: store}
}

// SetPolicyPipelineHandlers attaches the policy pipeline handlers to the
// admin router. nil (the default) keeps the routes mounted but unwired:
// they answer 503 until the policystore is wired by the admin server.
func (h *AdminHandlers) SetPolicyPipelineHandlers(o *PolicyPipelineHandlers) {
	h.policyPipes = o
	if o != nil {
		o.audit = h.auditLogAction
	}
}

// RequireOrgPermissionPoliciesManage is the policy-surface variant of
// RequireOrgPermission (roles_authz.go) for adminstore.PermPoliciesManage,
// with the org_settings-style resourceHidden difference: a caller with NO
// membership on the target org gets 404, not 403 — a foreign org must not be
// distinguishable from a nonexistent one. A member whose role lacks
// policies.manage is 403. Root always passes. The name keeps the
// "RequireOrgPermission" fragment so the route inventories classify the
// chain as an org gate.
//
// WHY policies.manage (existing permission, no new one): policies are
// security objects — they deny/mask/rewrite traffic — the exact sensitivity
// class the matrix already models as PermPoliciesManage (the only role
// holding it today is org-admin; the label-policy routes set the precedent).
// keys.manage would conflate credential custody with traffic policy;
// routing.manage is about model choice, not guardrails.
func (h *AdminHandlers) RequireOrgPermissionPoliciesManage() func(http.Handler) http.Handler {
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
			if !adminstore.RoleHas(string(role), adminstore.PermPoliciesManage) {
				writeJSON(w, http.StatusForbidden, apiError{Error: "insufficient permission for this organization"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// mountPolicyPipelines registers the policy pipeline routes under the
// org-permission gate. Mounted unconditionally (nil handlers answer 503):
// wiring. The {id} path param is the org; RequireOrgPermissionPoliciesManage
// resolves it (targetOrgID reads the /api/organizations/ prefix) and hides a
// foreign org (404) or 403s a member without policies.manage. Cross-org
// RESOURCE ids (a policyId of another org) are invisible too: the handlers
// read rows through the org-scoped store and answer 404.
func (h *AdminHandlers) mountPolicyPipelines(protected chi.Router) {
	policies := protected.With(h.RequireOrgPermissionPoliciesManage())
	policies.Get("/api/organizations/{id}/policies", h.policyPipes.handleList)
	policies.Post("/api/organizations/{id}/policies", h.policyPipes.handleCreate)
	// Static segments before {policyId}: validate (POST) is the UI's
	// save-time arbiter — the SAME strict parser the store path runs
	// (owner decision 2026-11-04 (a)).
	policies.Post("/api/organizations/{id}/policies/validate", h.policyPipes.handleValidate)
	policies.Get("/api/organizations/{id}/policies/drift", h.policyPipes.handleDrift)
	policies.Get("/api/organizations/{id}/policies/{policyId}", h.policyPipes.handleGet)
	policies.Put("/api/organizations/{id}/policies/{policyId}", h.policyPipes.handleUpdate)
	policies.Delete("/api/organizations/{id}/policies/{policyId}", h.policyPipes.handleRemove)
}

// unwired reports whether the policy store is missing and, when it is,
// writes the 503. Nil-receiver safe: the routes are mounted unconditionally.
func (o *PolicyPipelineHandlers) unwired(w http.ResponseWriter) bool {
	if o == nil || o.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "policy pipeline store not configured"})
		return true
	}
	return false
}

// validatePolicyYAML is the STRICT save gate (owner decision 2026-11-04 (a)):
// the document must parse with the same pkg/pipeline.ParsePolicy the gateway
// compiles at load time (unknown fields are errors, one YAML document,
// non-empty steps) and pass Policy.Validate (structure — mode, hooks, step
// kinds, ids, timeouts — without resolving detectors/scripts). A document
// that fails here is never stored: the lenient header-only check that used
// to live on this path let the UI store policies the gateway then refused
// to load — the store↔gateway asymmetry (audit gap G2) this closes.
func validatePolicyYAML(doc string) error {
	if strings.TrimSpace(doc) == "" {
		return errors.New("policy yaml is required")
	}
	p, err := pipeline.ParsePolicy([]byte(doc))
	if err != nil {
		return fmt.Errorf("policy yaml: %w", err)
	}
	if err := p.Validate(); err != nil {
		return fmt.Errorf("policy yaml: %w", err)
	}
	return nil
}

// policyValidateBody is the POST /policies/validate request: the draft
// document, nothing else (validation is stateless).
type policyValidateBody struct {
	YAML string `json:"yaml"`
}

// handleValidate serves POST /api/organizations/{id}/policies/validate: the
// UI's save-time arbiter. It runs EXACTLY the store-path validation
// (validatePolicyYAML — strict ParsePolicy + Validate), so a 200 here means
// the subsequent create/update stores the same bytes. Invalid documents
// answer 400 with the same error text the save would produce; the endpoint
// never touches the store.
func (o *PolicyPipelineHandlers) handleValidate(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	var body policyValidateBody
	if !decodePolicyBody(w, r, &body) {
		return
	}
	if err := validatePolicyYAML(body.YAML); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	p, _ := pipeline.ParsePolicy([]byte(body.YAML)) // validated above
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "name": p.Name, "mode": p.Mode})
}

type policyAttachmentBody struct {
	KeyLabel     string `json:"key_label"`
	ModelPattern string `json:"model_pattern"`
	Endpoint     string `json:"endpoint"`
	Priority     *int   `json:"priority"`
}

type policyPipelineCreateBody struct {
	Name        string                  `json:"name"`
	YAML        string                  `json:"yaml"`
	GitSHA      string                  `json:"git_sha"`
	Enabled     *bool                   `json:"enabled"`
	Attachments *[]policyAttachmentBody `json:"attachments"`
}

type policyPipelineUpdateBody struct {
	YAML          *string                 `json:"yaml"`
	GitSHA        *string                 `json:"git_sha"`
	Enabled       *bool                   `json:"enabled"`
	ActiveVersion *int                    `json:"active_version"`
	Attachments   *[]policyAttachmentBody `json:"attachments"`
	// Version is the optimistic-concurrency
	// token: the pipeline's current_version the caller loaded. Present but
	// stale → 409 {"error":"conflict","current":{…}} and NOTHING applies.
	// Absent → the legacy unconditional PUT (field-by-field).
	Version *int `json:"version"`
}

// policyDetail is the GET single-policy payload: the pipeline row plus its
// versions (newest first) and attachments (priority first).
type policyDetail struct {
	Policy      adminstore.PolicyPipeline     `json:"policy"`
	Versions    []adminstore.PolicyVersion    `json:"versions"`
	Attachments []adminstore.PolicyAttachment `json:"attachments"`
}

// handleList serves GET /api/organizations/{id}/policies.
func (o *PolicyPipelineHandlers) handleList(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	policies, err := o.store.ListPolicies(r.Context(), r.PathValue("id"))
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": policies, "count": len(policies)})
}

// handleCreate serves POST /api/organizations/{id}/policies: creates the
// pipeline with version 1 (draft). Optional enabled/attachments apply
// immediately after the create; every applied change bumps the store's
// version key (store-level).
func (o *PolicyPipelineHandlers) handleCreate(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID := r.PathValue("id")
	var body policyPipelineCreateBody
	if !decodePolicyBody(w, r, &body) {
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 256 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "name must be 1 to 256 characters"})
		return
	}
	if err := validatePolicyYAML(body.YAML); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	gitSHA, ok := validatePolicyGitSHA(w, body.GitSHA)
	if !ok {
		return
	}
	atts, ok := validatePolicyAttachments(w, body.Attachments)
	if !ok {
		return
	}

	p, _, err := o.store.CreatePolicy(r.Context(), orgID, name, body.YAML, gitSHA, o.callerEmail(r))
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	if body.Enabled != nil && *body.Enabled != p.Enabled {
		updated, err := o.store.UpdatePolicy(r.Context(), orgID, p.ID, *body.Enabled)
		if err != nil {
			o.writeStoreError(w, err)
			return
		}
		p = updated
	}
	if atts != nil {
		if _, err := o.store.SetPolicyAttachments(r.Context(), orgID, p.ID, atts); err != nil {
			o.writeStoreError(w, err)
			return
		}
	}
	o.auditAction(r, "create", "policy_pipeline", "policy="+p.Name+",org="+orgID)
	writeJSON(w, http.StatusCreated, policyDetail{Policy: p})
}

// handleGet serves GET /api/organizations/{id}/policies/{policyId}: the
// pipeline plus versions and attachments. A foreign policyId is the same 404
// as a missing one (resourceHidden for org-scoped rows).
func (o *PolicyPipelineHandlers) handleGet(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID, policyID := r.PathValue("id"), r.PathValue("policyId")
	p, ok := o.visiblePolicy(w, r, orgID, policyID)
	if !ok {
		return
	}
	versions, err := o.store.ListPolicyVersions(r.Context(), orgID, policyID)
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	atts, err := o.store.ListPolicyAttachments(r.Context(), orgID, policyID)
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policyDetail{Policy: p, Versions: versions, Attachments: atts})
}

// handleUpdate serves PUT /api/organizations/{id}/policies/{policyId}.
// Every present field applies (nil fields keep the stored value):
//   - yaml            → appends a NEW draft version (never an in-place edit)
//   - enabled         → flips the mode flag
//   - active_version  → points current_version at that version
//   - attachments     → replace-all of the attachment set
//
// token — the current_version the caller loaded. Present → the WHOLE body
// applies atomically through the store's CAS path; a stale token answers
// 409 {"error":"conflict","current":{policy row}} and nothing stores. The
// token is the pipeline's current_version (the state the runtime
// evaluates): a concurrent activation is the overwrite the guard exists to
// catch. Concurrent draft appends do not move the token by design —
// versions are immutable append-only rows and the editor re-reads after
// every save.
//
// The response carries the refreshed pipeline row (use GET for the full
// detail).
func (o *PolicyPipelineHandlers) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID, policyID := r.PathValue("id"), r.PathValue("policyId")
	var body policyPipelineUpdateBody
	if !decodePolicyBody(w, r, &body) {
		return
	}
	p, ok := o.visiblePolicy(w, r, orgID, policyID)
	if !ok {
		return
	}
	if body.Version != nil {
		o.handleUpdateCAS(w, r, orgID, policyID, body, *body.Version)
		return
	}
	applied := ""
	if body.YAML != nil {
		if err := validatePolicyYAML(*body.YAML); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		gitSHA := ""
		if body.GitSHA != nil {
			gitSHA = *body.GitSHA
		}
		gitSHA, ok = validatePolicyGitSHA(w, gitSHA)
		if !ok {
			return
		}
		if _, err := o.store.CreatePolicyVersion(r.Context(), orgID, policyID, *body.YAML, gitSHA, o.callerEmail(r)); err != nil {
			o.writeStoreError(w, err)
			return
		}
		applied = "version"
	} else if body.GitSHA != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "git_sha applies only together with yaml"})
		return
	}
	if body.Enabled != nil && *body.Enabled != p.Enabled {
		updated, err := o.store.UpdatePolicy(r.Context(), orgID, policyID, *body.Enabled)
		if err != nil {
			o.writeStoreError(w, err)
			return
		}
		p = updated
		applied = joinApplied(applied, "enabled")
	}
	if body.ActiveVersion != nil {
		var err error
		activated, err := o.store.SetActivePolicyVersion(r.Context(), orgID, policyID, *body.ActiveVersion)
		if err != nil {
			o.writeStoreError(w, err)
			return
		}
		p = activated
		applied = joinApplied(applied, "active_version")
	}
	if body.Attachments != nil {
		atts, ok := validatePolicyAttachments(w, body.Attachments)
		if !ok {
			return
		}
		if _, err := o.store.SetPolicyAttachments(r.Context(), orgID, policyID, atts); err != nil {
			o.writeStoreError(w, err)
			return
		}
		applied = joinApplied(applied, "attachments")
	}
	if applied == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "nothing to update (set yaml, enabled, active_version or attachments)"})
		return
	}
	o.auditAction(r, "update", "policy_pipeline", "policy="+p.Name+",org="+orgID+",applied="+applied)
	writeJSON(w, http.StatusOK, policyDetail{Policy: p})
}

// handleUpdateCAS is the preconditioned PUT: every present field applies in
// ONE store transaction under the caller-supplied expected version; a stale
// token answers the AF-09 conflict wire shape (409 + the entity's CURRENT
// relevant state, crud.go writeConflict parity).
func (o *PolicyPipelineHandlers) handleUpdateCAS(w http.ResponseWriter, r *http.Request, orgID, policyID string, body policyPipelineUpdateBody, expectVersion int) {
	if body.YAML != nil {
		if err := validatePolicyYAML(*body.YAML); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		gitSHA := ""
		if body.GitSHA != nil {
			gitSHA = *body.GitSHA
		}
		gitSHA, ok := validatePolicyGitSHA(w, gitSHA)
		if !ok {
			return
		}
		body.GitSHA = &gitSHA
	} else if body.GitSHA != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "git_sha applies only together with yaml"})
		return
	}
	var atts []adminstore.PolicyAttachment
	if body.Attachments != nil {
		var ok bool
		atts, ok = validatePolicyAttachments(w, body.Attachments)
		if !ok {
			return
		}
	}
	upd := adminstore.PolicyUpdate{YAML: body.YAML, GitSHA: body.GitSHA, Enabled: body.Enabled, ActiveVersion: body.ActiveVersion}
	if body.Attachments != nil {
		upd.Attachments = &atts
	}
	if upd.Empty() {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "nothing to update (set yaml, enabled, active_version or attachments)"})
		return
	}
	p, _, err := o.store.UpdatePolicyCAS(r.Context(), orgID, policyID, upd, &expectVersion, o.callerEmail(r))
	if err != nil {
		if errors.Is(err, adminstore.ErrPreconditionFailed) {
			// The stale-edit negative: nothing applied; the live row rides
			// the body so the editor can offer refresh-and-rebase.
			o.auditAction(r, "update_conflict", "policy_pipeline",
				"policy="+p.Name+",org="+orgID+",expected_version="+strconv.Itoa(expectVersion)+",current_version="+strconv.Itoa(p.CurrentVersion))
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":   "version conflict: the policy changed since you loaded it",
				"current": policyDetail{Policy: p},
			})
			return
		}
		o.writeStoreError(w, err)
		return
	}
	o.auditAction(r, "update", "policy_pipeline", "policy="+p.Name+",org="+orgID+",applied=version:"+strconv.Itoa(expectVersion))
	writeJSON(w, http.StatusOK, policyDetail{Policy: p})
}

// handleRemove serves DELETE /api/organizations/{id}/policies/{policyId}.
func (o *PolicyPipelineHandlers) handleRemove(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID, policyID := r.PathValue("id"), r.PathValue("policyId")
	p, ok := o.visiblePolicy(w, r, orgID, policyID)
	if !ok {
		return
	}
	if err := o.store.DeletePolicy(r.Context(), orgID, policyID); err != nil {
		o.writeStoreError(w, err)
		return
	}
	o.auditAction(r, "delete", "policy_pipeline", "policy="+p.Name+",org="+orgID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// visiblePolicy looks policyID up within the PATH org only. A policy of
// another org (or a missing one) is the same 404 — cross-org resource ids
// stay invisible (the resourceHidden semantics for org-scoped rows).
func (o *PolicyPipelineHandlers) visiblePolicy(w http.ResponseWriter, r *http.Request, orgID, policyID string) (adminstore.PolicyPipeline, bool) {
	p, err := o.store.GetPolicy(r.Context(), orgID, policyID)
	if err != nil {
		o.writeStoreError(w, err)
		return adminstore.PolicyPipeline{}, false
	}
	return p, true
}

// callerEmail extracts the acting admin's identity for created_by ("" when
// unavailable — anonymous/system callers still store, just unattributed).
func (o *PolicyPipelineHandlers) callerEmail(r *http.Request) string {
	return adminNameFromContext(r)
}

// auditAction journals a policy mutation (nil-safe: bare test instances
// without SetPolicyPipelineHandlers skip the journal).
func (o *PolicyPipelineHandlers) auditAction(r *http.Request, action, resource, details string) {
	if o == nil || o.audit == nil {
		return
	}
	o.audit(r, action, resource, details)
}

// validatePolicyAttachments validates an optional attachment list (nil =
// absent). Writes the 400 itself (false = response written).
func validatePolicyAttachments(w http.ResponseWriter, bodies *[]policyAttachmentBody) ([]adminstore.PolicyAttachment, bool) {
	if bodies == nil {
		return nil, true
	}
	if len(*bodies) > policyMaxAttachments {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "too many attachments"})
		return nil, false
	}
	out := make([]adminstore.PolicyAttachment, 0, len(*bodies))
	for _, b := range *bodies {
		pattern := strings.TrimSpace(b.ModelPattern)
		endpoint := strings.TrimSpace(b.Endpoint)
		label := strings.TrimSpace(b.KeyLabel)
		if pattern == "" || len(pattern) > policyAttachmentFieldMaxLen {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "attachment model_pattern must be 1 to 256 characters"})
			return nil, false
		}
		if endpoint == "" || len(endpoint) > policyAttachmentFieldMaxLen {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "attachment endpoint must be 1 to 256 characters"})
			return nil, false
		}
		if len(label) > policyAttachmentFieldMaxLen {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "attachment key_label must be at most 256 characters"})
			return nil, false
		}
		priority := 100
		if b.Priority != nil {
			priority = *b.Priority
		}
		if priority < 0 || priority > policyAttachmentMaxPriority {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "attachment priority must be between 0 and 1000000"})
			return nil, false
		}
		out = append(out, adminstore.PolicyAttachment{
			KeyLabel:     label,
			ModelPattern: pattern,
			Endpoint:     endpoint,
			Priority:     priority,
		})
	}
	return out, true
}

// validatePolicyGitSHA enforces the git-authorship boundary (owner decision
// 2026-11-04, closes audit gap G3): API callers cannot claim a git revision.
// git_sha is the reconcile drift detector's anchor — only `yb policies
// reconcile` (which derives it from `git rev-parse`) may record one; a
// caller-supplied non-empty value is a 400. UI/API-authored versions carry
// git_sha="" so drift classification stays unspoofable. Writes the 400
// itself (false = response written).
func validatePolicyGitSHA(w http.ResponseWriter, gitSHA string) (string, bool) {
	gitSHA = strings.TrimSpace(gitSHA)
	if gitSHA != "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "git_sha is recorded by policies reconcile only; API-created versions are authored outside git"})
		return "", false
	}
	return "", true
}

// decodePolicyBody reads a policy JSON body under the cap and rejects
// unknown fields — a typo'd payload 400s instead of silently dropping, say,
// a yaml field under a different name.
func decodePolicyBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, policyBodyLimit))
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
func (o *PolicyPipelineHandlers) writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, adminstore.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		writeJSON(w, http.StatusConflict, apiError{Error: "a policy with this name already exists in this organization"})
		return
	}
	writeJSON(w, http.StatusInternalServerError, apiError{Error: "internal error"})
}

// joinApplied appends one applied-field name to the audit detail.
func joinApplied(applied, field string) string {
	if applied == "" {
		return field
	}
	return applied + "," + field
}
