package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	chi "github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

// --- Principal delegation chain (N04-P05 T03) ---
//
// «создание ключа само не даёт доступа»: an agent key authenticates a
// subject but grants nothing. Access exists only while a live delegation —
// issued here by a human principal for one org, one bounded permission
// subset, one mandatory expiry — backs the subject, and only while the
// grantor still holds the delegated permission (re-checked at every
// evaluation, so demotion or membership removal cascades immediately).

// principalDelegationStore is the delegation-chain seam on the admin store.
// Handlers fail closed when the store does not implement it.
type principalDelegationStore interface {
	CreatePrincipalDelegation(ctx context.Context, p adminstore.PrincipalDelegationCreateParams, now time.Time) (*adminstore.PrincipalDelegation, error)
	EvaluatePrincipalDelegation(ctx context.Context, orgID, subjectType, subjectID string, perm adminstore.Permission, now time.Time) (bool, error)
	RevokePrincipalDelegation(ctx context.Context, id, orgID string, now time.Time) error
	ListPrincipalDelegations(ctx context.Context, orgID, subjectID string) ([]adminstore.PrincipalDelegation, error)
}

// delegationStore returns the delegation seam or nil (fail-closed).
func (h *AdminHandlers) delegationStore() principalDelegationStore {
	store, _ := h.store.(principalDelegationStore)
	return store
}

// evaluateSubjectDelegation evaluates the live delegation for a marked
// non-human subject. It returns the two request-history capabilities the
// chain grants right now: metadata read and payload read. Any store failure
// is denial (fail-closed); human subjects never delegate anything here.
func (h *AdminHandlers) evaluateSubjectDelegation(r *http.Request, orgID string, subject adminstore.RequestPayloadSubject) (read, payload bool) {
	store := h.delegationStore()
	if store == nil || orgID == "" || subject.AgentID == "" {
		return false, false
	}
	read, err := store.EvaluatePrincipalDelegation(r.Context(), orgID, string(subject.Type), subject.AgentID, adminstore.PermRequestsRead, time.Now().UTC())
	if err != nil || !read {
		return false, false
	}
	payload, err = store.EvaluatePrincipalDelegation(r.Context(), orgID, string(subject.Type), subject.AgentID, adminstore.PermRequestsPayloads, time.Now().UTC())
	if err != nil {
		return read, false
	}
	return read, payload
}

// delegationIssueRequest is the POST /api/agent-keys/{id}/delegations body.
type delegationIssueRequest struct {
	OrgID       string   `json:"org_id"`
	Permissions []string `json:"permissions"`
	TTLSeconds  int64    `json:"ttl_seconds"`
	// SubjectType optionally pins the delegate principal kind ("agent" or
	// "ci"). It defaults to "agent"; the value must match the subject type
	// the ingress reports for the key, or evaluation denies.
	SubjectType string `json:"subject_type"`
}

// IssuePrincipalDelegation — POST /api/agent-keys/{id}/delegations.
//
// Bounded issuance invariants (escalation impossible by construction):
//   - the delegate key must exist, be active, and be inside the caller's org
//     scope (a foreign id is 404 — no existence oracle across orgs);
//   - every requested permission must be delegatable (read-only subset;
//     requests.read_originals is never delegatable) AND currently held by the
//     caller on that org — a grantor cannot delegate what it does not have;
//   - the TTL is mandatory and bounded (≤ 30 days); revocation is explicit.
//
// The created row is the chain provenance: who (grantor) delegated what
// (permission subset) to whom (subject), audited on issue.
func (h *AdminHandlers) IssuePrincipalDelegation() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		store := h.delegationStore()
		if store == nil {
			h.respondError(w, r, fmt.Errorf("principal delegation store unavailable"), http.StatusServiceUnavailable)
			return
		}
		var req delegationIssueRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		orgID := h.requireOrgScope(w, r, req.OrgID, adminstore.PermAgentKeysManage)
		if orgID == "" {
			return
		}
		if req.TTLSeconds <= 0 {
			h.respondError(w, r, fmt.Errorf("ttl_seconds is required and must be positive"), http.StatusBadRequest)
			return
		}
		ttl := time.Duration(req.TTLSeconds) * time.Second
		if ttl > adminstore.MaxPrincipalDelegationTTL {
			h.respondError(w, r, fmt.Errorf("ttl_seconds must be at most %d", int(adminstore.MaxPrincipalDelegationTTL/time.Second)), http.StatusBadRequest)
			return
		}
		subjectType := req.SubjectType
		if subjectType == "" {
			subjectType = adminstore.PrincipalDelegationSubjectAgent
		}
		if subjectType != adminstore.PrincipalDelegationSubjectAgent && subjectType != adminstore.PrincipalDelegationSubjectCI {
			h.respondError(w, r, fmt.Errorf("subject_type must be agent or ci"), http.StatusBadRequest)
			return
		}
		for _, p := range req.Permissions {
			if !adminstore.IsDelegatablePermission(adminstore.Permission(p)) {
				h.respondError(w, r, fmt.Errorf("permission %q is not delegatable", p), http.StatusBadRequest)
				return
			}
		}

		// The delegate key must exist and live in the caller's org. Missing
		// and foreign ids are the same 404 (no existence oracle) — including
		// for root, which passes the scope middleware for any org.
		key, ok := h.agentKeyVisible(w, r, chi.URLParam(r, "id"))
		if !ok {
			return
		}
		if key.OrgID != orgID {
			h.respondError(w, r, fmt.Errorf("agent key not found"), http.StatusNotFound)
			return
		}
		if !key.Active {
			h.respondError(w, r, fmt.Errorf("agent key is revoked"), http.StatusConflict)
			return
		}

		// No escalation: the grantor must hold every delegated permission on
		// the org right now. Root holds the whole delegatable subset.
		grantorType := adminstore.PrincipalDelegationGrantorAdmin
		if isRoot(r) {
			grantorType = adminstore.PrincipalDelegationGrantorRoot
		} else {
			role, member := h.callerRoleOnOrg(r, orgID)
			if !member {
				h.respondError(w, r, fmt.Errorf("you do not have a role on this organization"), http.StatusForbidden)
				return
			}
			for _, p := range req.Permissions {
				if !adminstore.RoleHas(string(role), adminstore.Permission(p)) {
					h.respondError(w, r, fmt.Errorf("cannot delegate a permission you do not hold: %s", p), http.StatusForbidden)
					return
				}
			}
		}

		d, err := store.CreatePrincipalDelegation(r.Context(), adminstore.PrincipalDelegationCreateParams{
			OrgID:       orgID,
			GrantorType: grantorType,
			GrantorID:   requestUserID(r),
			SubjectType: subjectType,
			SubjectID:   key.ID,
			Permissions: req.Permissions,
			TTL:         ttl,
		}, time.Now().UTC())
		if err != nil {
			status := http.StatusInternalServerError
			if err == adminstore.ErrInvalidPrincipalDelegation {
				status = http.StatusBadRequest
			}
			h.respondError(w, r, err, status)
			return
		}
		details, _ := json.Marshal(map[string]any{
			"delegation_id": d.ID, "org_id": d.OrgID, "grantor_type": d.GrantorType,
			"grantor_id": d.GrantorID, "subject_type": d.SubjectType, "subject_id": d.SubjectID,
			"permissions": d.Permissions, "expires_at": d.ExpiresAt.UTC().Format(time.RFC3339),
		})
		h.auditLogAction(r, "principal_delegation.grant_issued", "agent_key:"+key.ID, string(details))
		writeJSON(w, http.StatusCreated, d)
	}
}

// ListPrincipalDelegations — GET /api/agent-keys/{id}/delegations?org_id=.
// Returns the delegation chain provenance for the key (metadata only).
func (h *AdminHandlers) ListPrincipalDelegations() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		store := h.delegationStore()
		if store == nil {
			h.respondError(w, r, fmt.Errorf("principal delegation store unavailable"), http.StatusServiceUnavailable)
			return
		}
		orgID := h.requireOrgScope(w, r, r.URL.Query().Get("org_id"), adminstore.PermAgentKeysManage)
		if orgID == "" {
			return
		}
		key, ok := h.agentKeyVisible(w, r, chi.URLParam(r, "id"))
		if !ok {
			return
		}
		delegations, err := store.ListPrincipalDelegations(r.Context(), orgID, key.ID)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": delegations})
	}
}

// RevokePrincipalDelegation — POST
// /api/agent-keys/{id}/delegations/{delegationID}/revoke. Revocation is
// immediate at the next evaluation: the delegate loses the scope without any
// propagation step. Only the original grantor or the platform root may
// revoke; everyone else (including another org admin) is 403.
func (h *AdminHandlers) RevokePrincipalDelegation() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		store := h.delegationStore()
		if store == nil {
			h.respondError(w, r, fmt.Errorf("principal delegation store unavailable"), http.StatusServiceUnavailable)
			return
		}
		orgID := h.requireOrgScope(w, r, r.URL.Query().Get("org_id"), adminstore.PermAgentKeysManage)
		if orgID == "" {
			return
		}
		key, ok := h.agentKeyVisible(w, r, chi.URLParam(r, "id"))
		if !ok {
			return
		}
		delegationID := chi.URLParam(r, "delegationID")
		delegations, err := store.ListPrincipalDelegations(r.Context(), orgID, key.ID)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		var target *adminstore.PrincipalDelegation
		for i := range delegations {
			if delegations[i].ID == delegationID {
				target = &delegations[i]
				break
			}
		}
		if target == nil {
			// Unknown or already-revoked delegations are the same 404.
			h.respondError(w, r, fmt.Errorf("delegation not found"), http.StatusNotFound)
			return
		}
		if !isRoot(r) && target.GrantorID != requestUserID(r) {
			h.respondError(w, r, fmt.Errorf("only the grantor or the platform root can revoke a delegation"), http.StatusForbidden)
			return
		}
		if err := store.RevokePrincipalDelegation(r.Context(), delegationID, orgID, time.Now().UTC()); err != nil {
			status := http.StatusInternalServerError
			if err == adminstore.ErrNotFound {
				status = http.StatusNotFound
			}
			h.respondError(w, r, err, status)
			return
		}
		details, _ := json.Marshal(map[string]any{
			"delegation_id": delegationID, "org_id": orgID,
			"grantor_id": target.GrantorID, "subject_id": key.ID,
			"permissions": target.Permissions,
		})
		h.auditLogAction(r, "principal_delegation.grant_revoked", "agent_key:"+key.ID, string(details))
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
	}
}
