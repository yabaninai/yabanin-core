package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// delegationFixtureStore embeds the shared mockStore and adds the four
// principal-delegation methods, so the delegation HTTP surface can be tested
// end to end (issue → evaluate → revoke → cascade) against mock org state:
// grantor authority is re-derived from orgMembers/adminUsers exactly like the
// durable evaluation joins, so demotion cascades are observable at handler
// level too.
type delegationFixtureStore struct {
	*mockStore

	mu          sync.Mutex
	delegations []adminstore.PrincipalDelegation
	nextID      int
	evalErr     error // fails the next evaluation (fail-closed wiring check)
}

func newDelegationFixtureStore() *delegationFixtureStore {
	return &delegationFixtureStore{mockStore: newMockStore()}
}

func (s *delegationFixtureStore) CreatePrincipalDelegation(_ context.Context, p adminstore.PrincipalDelegationCreateParams, now time.Time) (*adminstore.PrincipalDelegation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	d := &adminstore.PrincipalDelegation{
		ID: "delegation-" + strconv.Itoa(s.nextID), OrgID: p.OrgID,
		GrantorType: p.GrantorType, GrantorID: p.GrantorID,
		SubjectType: p.SubjectType, SubjectID: p.SubjectID,
		Permissions: p.Permissions, ExpiresAt: now.Add(p.TTL), CreatedAt: now,
	}
	s.delegations = append(s.delegations, *d)
	return d, nil
}

// EvaluatePrincipalDelegation mirrors the durable evaluation semantics: live
// row + matching org/subject/permission + grantor still holding the
// permission (org membership role for admins, is_root+active for root).
func (s *delegationFixtureStore) EvaluatePrincipalDelegation(_ context.Context, orgID, subjectType, subjectID string, perm adminstore.Permission, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.evalErr != nil {
		return false, s.evalErr
	}
	if key, ok := s.agentKeys[subjectID]; !ok || !key.Active {
		return false, nil
	}
	for _, d := range s.delegations {
		if d.OrgID != orgID || d.SubjectType != subjectType || d.SubjectID != subjectID {
			continue
		}
		if d.RevokedAt != nil || !now.Before(d.ExpiresAt) {
			continue
		}
		if !delegationPermListHas(d.Permissions, string(perm)) {
			continue
		}
		switch d.GrantorType {
		case adminstore.PrincipalDelegationGrantorAdmin:
			mem, ok := s.orgMembers[d.GrantorID+"/"+orgID]
			if ok && adminstore.RoleHas(string(mem.Role), perm) {
				return true, nil
			}
		case adminstore.PrincipalDelegationGrantorRoot:
			if u, ok := s.adminUsers[d.GrantorID]; ok && u.IsRoot && u.Active {
				return true, nil
			}
		}
	}
	return false, nil
}

func (s *delegationFixtureStore) RevokePrincipalDelegation(_ context.Context, id, orgID string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.delegations {
		d := &s.delegations[i]
		if d.ID == id && d.OrgID == orgID && d.RevokedAt == nil {
			d.RevokedAt = &now
			return nil
		}
	}
	return adminstore.ErrNotFound
}

func (s *delegationFixtureStore) ListPrincipalDelegations(_ context.Context, orgID, subjectID string) ([]adminstore.PrincipalDelegation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []adminstore.PrincipalDelegation{}
	for _, d := range s.delegations {
		if d.OrgID != orgID {
			continue
		}
		if subjectID != "" && d.SubjectID != subjectID {
			continue
		}
		out = append(out, d)
	}
	return out, nil
}

func delegationPermListHas(list []string, perm string) bool {
	for _, p := range list {
		if p == perm {
			return true
		}
	}
	return false
}

// --- request builders ---

// delegationGrants evaluates the delegation chain for the subject the way the
// request handlers do, returning (metadata-read, payload-read).
func delegationGrants(h *AdminHandlers, orgID, agentID string) (read, payload bool) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	return h.evaluateSubjectDelegation(r, orgID, adminstore.RequestPayloadSubject{
		Type: adminstore.RequestPayloadAgent, AgentID: agentID,
	})
}

// delegationAdminRequest is a non-root org admin session pinned to orgScope
// with the given role.
func delegationAdminRequest(method, target, body, orgScope string, role adminstore.OrgRole) *http.Request {
	ctx := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "admin-1")
	ctx = context.WithValue(ctx, adminauth.ContextKeyIsRoot{}, false)
	ctx = context.WithValue(ctx, ctxKeyOrgScope{}, orgScope)
	if role != "" {
		ctx = context.WithValue(ctx, ctxKeyOrgRole{}, map[string]adminstore.OrgRole{orgScope: role})
	}
	return httptest.NewRequestWithContext(ctx, method, target, strings.NewReader(body))
}

func delegationRootRequest(method, target, body string) *http.Request {
	ctx := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "admin-root")
	ctx = context.WithValue(ctx, adminauth.ContextKeyIsRoot{}, true)
	return httptest.NewRequestWithContext(ctx, method, target, strings.NewReader(body))
}

// delegationAgentRequest is an authenticated non-human subject marker on a
// request (what the ingress derives from an agent/CI key).
func delegationAgentRequest(method, target, subjectType, agentID string) *http.Request {
	ctx := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "agent-key-1")
	req := httptest.NewRequestWithContext(ctx, method, target, nil)
	return req.WithContext(adminstore.WithRequestPayloadSubject(req.Context(), adminstore.RequestPayloadSubject{
		Type: adminstore.RequestPayloadSubjectType(subjectType), AgentID: agentID,
	}))
}

func seedDelegationWorld(t *testing.T, s *delegationFixtureStore) {
	t.Helper()
	s.adminUsers["admin-1"] = &adminstore.AdminUser{ID: "admin-1", Email: "admin@example.com", Active: true}
	s.adminUsers["admin-root"] = &adminstore.AdminUser{ID: "admin-root", Email: "root@example.com", IsRoot: true, Active: true}
	s.orgMembers["admin-1/org-1"] = &adminstore.OrgMembership{ID: "mem-1", UserID: "admin-1", OrgID: "org-1", Role: adminstore.RoleOrgAdmin}
	s.orgs["org-1"] = &adminstore.Organization{ID: "org-1", Name: "Org One"}
	s.orgs["org-2"] = &adminstore.Organization{ID: "org-2", Name: "Org Two"}
	s.agentKeys["agent-key-1"] = &adminstore.AgentKey{ID: "agent-key-1", Name: "worker", OrgID: "org-1", Active: true}
	s.agentKeys["agent-key-2"] = &adminstore.AgentKey{ID: "agent-key-2", Name: "foreign", OrgID: "org-2", Active: true}
	s.agentKeys["agent-key-dead"] = &adminstore.AgentKey{ID: "agent-key-dead", Name: "revoked", OrgID: "org-1", Active: false}
}

// --- joint criterion: creation inert, scoped grant opens the subset ---

func TestAgentKeyCreationIsInertDelegationOpensScope(t *testing.T) {
	store := newDelegationFixtureStore()
	seedDelegationWorld(t, store)
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)

	// Creation is inert: an agent-key subject with NO delegation gets no
	// request-history surface at all — the export denies and the denial is
	// audited (zero access, not degraded access).
	rec := httptest.NewRecorder()
	h.apiOrgRequestExport()(rec, delegationAgentRequest(http.MethodGet,
		"/api/organizations/org-1/requests/export", "agent", "agent-key-1"))
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

	// A scoped grant opens exactly the delegated subset. Note: an org admin
	// never holds requests.read_payloads (payload reads are resource-scoped),
	// so the read-only grant below is the ceiling a role-holding admin can
	// delegate; the payload scope is delegatable only by root (tested after).
	issued := httptest.NewRecorder()
	wrapWithParams(h.IssuePrincipalDelegation(), "/api/agent-keys/{id}/delegations")(issued, delegationAdminRequest(http.MethodPost,
		"/api/agent-keys/agent-key-1/delegations",
		`{"org_id":"org-1","permissions":["requests.read"],"ttl_seconds":3600}`,
		"org-1", adminstore.RoleOrgAdmin))
	require.Equal(t, http.StatusCreated, issued.Code, issued.Body.String())

	read, payload := delegationGrants(h, "org-1", "agent-key-1")
	require.True(t, read, "delegated requests.read must open metadata read")
	require.False(t, payload, "the payload scope stays closed without its delegation")

	// Root may delegate the payload scope: the subset opens for exactly the
	// delegated permission, nothing more.
	rootIssued := httptest.NewRecorder()
	wrapWithParams(h.IssuePrincipalDelegation(), "/api/agent-keys/{id}/delegations")(rootIssued, delegationRootRequest(http.MethodPost,
		"/api/agent-keys/agent-key-1/delegations",
		`{"org_id":"org-1","permissions":["requests.read_payloads"],"ttl_seconds":3600}`))
	require.Equal(t, http.StatusCreated, rootIssued.Code, rootIssued.Body.String())
	read, payload = delegationGrants(h, "org-1", "agent-key-1")
	require.True(t, read, "the earlier read delegation still grants")
	require.True(t, payload, "the delegated payload scope now opens")

	// Provenance is audited on issue with who → whom → what.
	require.NotEmpty(t, store.auditRecords)
	last := store.auditRecords[len(store.auditRecords)-1]
	assert.Equal(t, "principal_delegation.grant_issued", last.Action)
	assert.Contains(t, last.Details, `"subject_id":"agent-key-1"`)
	assert.Contains(t, last.Details, `"grantor_type":"root"`)
	assert.Contains(t, last.Details, `"permissions":["requests.read_payloads"]`)
}

func TestIssuePrincipalDelegationValidations(t *testing.T) {
	store := newDelegationFixtureStore()
	seedDelegationWorld(t, store)
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)

	issue := func(body string, role adminstore.OrgRole) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		wrapWithParams(h.IssuePrincipalDelegation(), "/api/agent-keys/{id}/delegations")(rec, delegationAdminRequest(http.MethodPost,
			"/api/agent-keys/agent-key-1/delegations", body, "org-1", role))
		return rec
	}

	// requests.read_originals is never delegatable — forged scope escalation
	// at issuance is a 400, never a silent downgrade.
	rec := issue(`{"org_id":"org-1","permissions":["requests.read_originals"],"ttl_seconds":60}`, adminstore.RoleOrgAdmin)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "not delegatable")

	// A grantor cannot delegate a permission it does not hold: an org admin
	// holds agent_keys.manage (so it passes the issuance scope) but never
	// requests.read_payloads — that delegation is a 403, not a grant.
	rec = issue(`{"org_id":"org-1","permissions":["requests.read_payloads"],"ttl_seconds":60}`, adminstore.RoleOrgAdmin)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "do not hold")

	// Manage permissions are outside the delegatable subset for any role.
	rec = issue(`{"org_id":"org-1","permissions":["agent_keys.manage"],"ttl_seconds":60}`, adminstore.RoleOrgAdmin)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

	// TTL is mandatory and bounded (≤ 30 days).
	rec = issue(`{"org_id":"org-1","permissions":["requests.read"],"ttl_seconds":0}`, adminstore.RoleOrgAdmin)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	rec = issue(`{"org_id":"org-1","permissions":["requests.read"],"ttl_seconds":2592001}`, adminstore.RoleOrgAdmin)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

	// A revoked delegate key is a conflict, not a delegation.
	deadRec := httptest.NewRecorder()
	wrapWithParams(h.IssuePrincipalDelegation(), "/api/agent-keys/{id}/delegations")(deadRec, delegationAdminRequest(http.MethodPost,
		"/api/agent-keys/agent-key-dead/delegations",
		`{"org_id":"org-1","permissions":["requests.read"],"ttl_seconds":60}`, "org-1", adminstore.RoleOrgAdmin))
	require.Equal(t, http.StatusConflict, deadRec.Code, deadRec.Body.String())

	// No row persisted for any rejected issuance.
	require.Empty(t, store.delegations)
}

func TestIssuePrincipalDelegationCrossOrgIs404(t *testing.T) {
	store := newDelegationFixtureStore()
	seedDelegationWorld(t, store)
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)

	// Org admin scoped to org-1 addressing org-2's key: the same 404 as a
	// missing id — no existence oracle across orgs.
	rec := httptest.NewRecorder()
	wrapWithParams(h.IssuePrincipalDelegation(), "/api/agent-keys/{id}/delegations")(rec, delegationAdminRequest(http.MethodPost,
		"/api/agent-keys/agent-key-2/delegations",
		`{"org_id":"org-1","permissions":["requests.read"],"ttl_seconds":60}`, "org-1", adminstore.RoleOrgAdmin))
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())

	// Root passes visibility but the org match still binds: delegating an
	// org-2 key under org_id=org-1 is the same 404.
	rootRec := httptest.NewRecorder()
	wrapWithParams(h.IssuePrincipalDelegation(), "/api/agent-keys/{id}/delegations")(rootRec, delegationRootRequest(http.MethodPost,
		"/api/agent-keys/agent-key-2/delegations",
		`{"org_id":"org-1","permissions":["requests.read"],"ttl_seconds":60}`))
	require.Equal(t, http.StatusNotFound, rootRec.Code, rootRec.Body.String())

	require.Empty(t, store.delegations)
}

// --- revocation: grantor-only, audited, cascading at the next evaluation ---

func TestRevokePrincipalDelegationGrantorOnlyAndCascade(t *testing.T) {
	store := newDelegationFixtureStore()
	seedDelegationWorld(t, store)
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)

	// The grantor issues a scoped delegation to the agent key.
	issued := httptest.NewRecorder()
	wrapWithParams(h.IssuePrincipalDelegation(), "/api/agent-keys/{id}/delegations")(issued, delegationAdminRequest(http.MethodPost,
		"/api/agent-keys/agent-key-1/delegations",
		`{"org_id":"org-1","permissions":["requests.read"],"ttl_seconds":3600}`,
		"org-1", adminstore.RoleOrgAdmin))
	require.Equal(t, http.StatusCreated, issued.Code, issued.Body.String())
	var delegation struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(issued.Body.Bytes(), &delegation))
	require.NotEmpty(t, delegation.ID)

	read, _ := delegationGrants(h, "org-1", "agent-key-1")
	require.True(t, read, "live delegation must grant before revoke")

	// A different org admin (not the grantor) may not revoke.
	otherAdmin := delegationAdminRequest(http.MethodPost,
		"/api/agent-keys/agent-key-1/delegations/"+delegation.ID+"/revoke?org_id=org-1", "", "org-1", adminstore.RoleOrgAdmin)
	otherAdmin = otherAdmin.WithContext(context.WithValue(otherAdmin.Context(), adminauth.ContextKeyUserID{}, "admin-2"))
	otherRec := httptest.NewRecorder()
	wrapWithParams(h.RevokePrincipalDelegation(), "/api/agent-keys/{id}/delegations/{delegationID}/revoke")(otherRec, otherAdmin)
	require.Equal(t, http.StatusForbidden, otherRec.Code, otherRec.Body.String())

	// The grantor revokes; denial cascades at the very next evaluation — no
	// propagation step.
	revokeRec := httptest.NewRecorder()
	wrapWithParams(h.RevokePrincipalDelegation(), "/api/agent-keys/{id}/delegations/{delegationID}/revoke")(revokeRec, delegationAdminRequest(http.MethodPost,
		"/api/agent-keys/agent-key-1/delegations/"+delegation.ID+"/revoke?org_id=org-1", "",
		"org-1", adminstore.RoleOrgAdmin))
	require.Equal(t, http.StatusOK, revokeRec.Code, revokeRec.Body.String())
	read, _ = delegationGrants(h, "org-1", "agent-key-1")
	require.False(t, read, "revoked delegation must deny at the next evaluation")

	// Double revoke is the same 404 as an unknown id.
	againRec := httptest.NewRecorder()
	wrapWithParams(h.RevokePrincipalDelegation(), "/api/agent-keys/{id}/delegations/{delegationID}/revoke")(againRec, delegationAdminRequest(http.MethodPost,
		"/api/agent-keys/agent-key-1/delegations/"+delegation.ID+"/revoke?org_id=org-1", "",
		"org-1", adminstore.RoleOrgAdmin))
	require.Equal(t, http.StatusNotFound, againRec.Code, againRec.Body.String())

	// Revocation is audited with the chain provenance.
	var revokedAudit bool
	for i := range store.auditRecords {
		if store.auditRecords[i].Action == "principal_delegation.grant_revoked" &&
			strings.Contains(store.auditRecords[i].Details, `"delegation_id":"`+delegation.ID+`"`) {
			revokedAudit = true
		}
	}
	require.True(t, revokedAudit, "revocation must be audited")
}

func TestDelegatorDemotionCascadesToDelegate(t *testing.T) {
	store := newDelegationFixtureStore()
	seedDelegationWorld(t, store)
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)

	// The org-admin grantor delegates only what it holds.
	issued := httptest.NewRecorder()
	wrapWithParams(h.IssuePrincipalDelegation(), "/api/agent-keys/{id}/delegations")(issued, delegationAdminRequest(http.MethodPost,
		"/api/agent-keys/agent-key-1/delegations",
		`{"org_id":"org-1","permissions":["requests.read"],"ttl_seconds":3600}`,
		"org-1", adminstore.RoleOrgAdmin))
	require.Equal(t, http.StatusCreated, issued.Code, issued.Body.String())

	read, payload := delegationGrants(h, "org-1", "agent-key-1")
	require.True(t, read, "live delegation must grant before demotion")
	require.False(t, payload, "the read-only delegation never opened the payload scope")

	// The delegator loses the membership → the delegate loses the scope at
	// the next evaluation (the fixture re-derives grantor authority from the
	// same org-membership state the middleware uses).
	delete(store.orgMembers, "admin-1/org-1")
	read, payload = delegationGrants(h, "org-1", "agent-key-1")
	require.False(t, read, "delegator losing the right must cascade to the delegate")
	require.False(t, payload, "the cascade covers the whole chain, not one permission")
}

// --- negatives at the HTTP shape level ---

func TestDelegatedExportOriginalsScopeEscalationDenied(t *testing.T) {
	store := newDelegationFixtureStore()
	seedDelegationWorld(t, store)
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)

	// Even a live read delegation never lifts originals: a delegated subject
	// asking for scope=payload.read_originals is a forged scope escalation —
	// 403 and an audited denial, not a silent downgrade to payload.read.
	issued := httptest.NewRecorder()
	wrapWithParams(h.IssuePrincipalDelegation(), "/api/agent-keys/{id}/delegations")(issued, delegationAdminRequest(http.MethodPost,
		"/api/agent-keys/agent-key-1/delegations",
		`{"org_id":"org-1","permissions":["requests.read"],"ttl_seconds":3600}`,
		"org-1", adminstore.RoleOrgAdmin))
	require.Equal(t, http.StatusCreated, issued.Code, issued.Body.String())

	esc := httptest.NewRecorder()
	h.apiOrgRequestExport()(esc, delegationAgentRequest(http.MethodGet,
		"/api/organizations/org-1/requests/export?scope=payload.read_originals",
		"agent", "agent-key-1"))
	require.Equal(t, http.StatusForbidden, esc.Code, esc.Body.String())
	assert.NotContains(t, esc.Body.String(), "choices")

	var escalationAudited bool
	for i := range store.auditRecords {
		if store.auditRecords[i].Action == "request_export.denied" &&
			strings.Contains(store.auditRecords[i].Details, "scope_escalation_denied") {
			escalationAudited = true
		}
	}
	require.True(t, escalationAudited, "the escalation attempt must be journalled")
}

func TestExpiredAndForeignDelegationDeny(t *testing.T) {
	store := newDelegationFixtureStore()
	seedDelegationWorld(t, store)
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)

	// An expired delegation denies at evaluation (TTL is part of the scope).
	store.mu.Lock()
	store.delegations = append(store.delegations, adminstore.PrincipalDelegation{
		ID: "d-expired", OrgID: "org-1", GrantorType: adminstore.PrincipalDelegationGrantorAdmin,
		GrantorID: "admin-1", SubjectType: adminstore.PrincipalDelegationSubjectAgent,
		SubjectID: "agent-key-1", Permissions: []string{"requests.read"},
		ExpiresAt: time.Now().Add(-time.Minute), CreatedAt: time.Now().Add(-time.Hour),
	})
	store.mu.Unlock()
	read, _ := delegationGrants(h, "org-1", "agent-key-1")
	require.False(t, read, "expired delegation must deny")

	// A foreign-org delegation for the same key denies (scope is org-bound).
	store.mu.Lock()
	store.delegations[0].OrgID = "org-2"
	store.delegations[0].ExpiresAt = time.Now().Add(time.Hour)
	store.mu.Unlock()
	read, _ = delegationGrants(h, "org-1", "agent-key-1")
	require.False(t, read, "cross-org delegation must deny")

	// Store failure fails closed.
	store.mu.Lock()
	store.evalErr = errors.New("db down")
	store.mu.Unlock()
	read, _ = delegationGrants(h, "org-1", "agent-key-1")
	require.False(t, read, "store error must deny (fail-closed)")
}

func TestEvaluateSubjectDelegationFailsClosedWithoutDelegationStore(t *testing.T) {
	// A plain mockStore does not implement the delegation seam: the handler
	// must deny, never panic, never grant.
	store := newMockStore()
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	read, payload := h.evaluateSubjectDelegation(r, "org-1",
		adminstore.RequestPayloadSubject{Type: adminstore.RequestPayloadAgent, AgentID: "agent-key-1"})
	require.False(t, read)
	require.False(t, payload)
}

func TestListPrincipalDelegationsReturnsProvenance(t *testing.T) {
	store := newDelegationFixtureStore()
	seedDelegationWorld(t, store)
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)

	issued := httptest.NewRecorder()
	wrapWithParams(h.IssuePrincipalDelegation(), "/api/agent-keys/{id}/delegations")(issued, delegationRootRequest(http.MethodPost,
		"/api/agent-keys/agent-key-1/delegations",
		`{"org_id":"org-1","permissions":["requests.read","audit.read"],"ttl_seconds":60}`))
	require.Equal(t, http.StatusCreated, issued.Code, issued.Body.String())

	list := httptest.NewRecorder()
	wrapWithParams(h.ListPrincipalDelegations(), "/api/agent-keys/{id}/delegations")(list, delegationRootRequest(http.MethodGet,
		"/api/agent-keys/agent-key-1/delegations?org_id=org-1", ""))
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	assert.Contains(t, list.Body.String(), `"grantor_type":"root"`)
	assert.Contains(t, list.Body.String(), `"subject_id":"agent-key-1"`)
	assert.Contains(t, list.Body.String(), `"permissions":["requests.read","audit.read"]`)
}
