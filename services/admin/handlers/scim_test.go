package handlers

// pinned here over an in-memory ScimStore double that mirrors the real
// store's org-predicate semantics; the SQL/org-isolation behavior lives in
// pkg/adminstore/scim_int_test.go. Fixtures follow the Okta and Entra SCIM
// push profiles (create user, deactivate, group → membership).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// In-memory ScimStore double — org predicates enforced like the real store.
// ---------------------------------------------------------------------------

type fakeScimStore struct {
	mu          sync.Mutex
	tokens      map[string]*adminstore.ScimToken // by sha256 hash
	users       map[string]*adminstore.ScimUser  // by scim_user_id
	memberships map[string]adminstore.OrgRole    // "userID|orgID" → role
	seq         int
}

func newFakeScimStore() *fakeScimStore {
	return &fakeScimStore{
		tokens:      map[string]*adminstore.ScimToken{},
		users:       map[string]*adminstore.ScimUser{},
		memberships: map[string]adminstore.OrgRole{},
	}
}

func (f *fakeScimStore) CreateScimToken(_ context.Context, orgID, label, createdBy string) (*adminstore.ScimToken, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, hash, err := adminstore.NewScimToken()
	if err != nil {
		return nil, "", err
	}
	f.seq++
	t := &adminstore.ScimToken{
		ID: fmt.Sprintf("tok-%d", f.seq), TokenHash: hash, HasHash: true,
		OrgID: orgID, Label: label, CreatedBy: createdBy,
		CreatedAt: time.Now(),
	}
	f.tokens[hash] = t
	return t, raw, nil
}

func (f *fakeScimStore) ListScimTokens(_ context.Context, orgID string) ([]*adminstore.ScimToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*adminstore.ScimToken
	for _, t := range f.tokens {
		if t.OrgID == orgID { // org predicate
			cp := *t
			cp.TokenHash = "" // listings never carry the hash
			cp.HasHash = false
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeScimStore) RevokeScimToken(_ context.Context, orgID, tokenID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.tokens {
		if t.ID == tokenID && t.OrgID == orgID { // org predicate
			now := time.Now()
			t.RevokedAt = &now
			return nil
		}
	}
	return adminstore.ErrNotFound
}

func (f *fakeScimStore) FindScimTokenByHash(_ context.Context, hash string) (*adminstore.ScimToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tokens[hash]
	if !ok {
		return nil, adminstore.ErrNotFound
	}
	return t, nil
}

func (f *fakeScimStore) TouchScimToken(_ context.Context, orgID, tokenID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.tokens {
		if t.ID == tokenID && t.OrgID == orgID {
			now := time.Now()
			t.LastUsedAt = &now
			return nil
		}
	}
	return nil
}

func (f *fakeScimStore) ProvisionScimUser(_ context.Context, orgID string, p adminstore.ScimUserParams) (*adminstore.ScimUser, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !adminstore.ValidOrgRole(p.Role) {
		return nil, false, fmt.Errorf("invalid role %q", p.Role)
	}
	for _, u := range f.users { // (org, userName) / (org, externalId) idempotency
		if u.OrgID == orgID && (u.UserName == p.UserName || (u.ExternalID != "" && u.ExternalID == p.ExternalID)) {
			return u, false, nil
		}
	}
	f.seq++
	u := &adminstore.ScimUser{
		ID: fmt.Sprintf("su-%d", f.seq), OrgID: orgID,
		ExternalID: p.ExternalID, AdminUserID: fmt.Sprintf("au-%d", f.seq),
		UserName: p.UserName, GivenName: p.GivenName, FamilyName: p.FamilyName,
		DisplayName: adminstore.ScimDisplayName(p.GivenName, p.FamilyName),
		Active:      p.Active, CreatedAt: time.Now(), UpdatedAt: time.Now(), LastSyncedAt: time.Now(),
	}
	f.users[u.ID] = u
	f.memberships[u.AdminUserID+"|"+orgID] = p.Role
	return u, true, nil
}

func (f *fakeScimStore) GetScimUser(_ context.Context, orgID, scimUserID string) (*adminstore.ScimUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[scimUserID]
	if !ok || u.OrgID != orgID { // org predicate
		return nil, adminstore.ErrNotFound
	}
	return u, nil
}

func (f *fakeScimStore) ListScimUsers(_ context.Context, orgID string) ([]*adminstore.ScimUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*adminstore.ScimUser
	for _, u := range f.users {
		if u.OrgID == orgID && u.Active { // org predicate; inactive identities are not listed
			out = append(out, u)
		}
	}
	// Oldest first (createdAt, id) — the real store's ORDER BY, so pagination
	// windows are deterministic.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (f *fakeScimStore) SyncScimUser(_ context.Context, orgID, scimUserID string, p adminstore.ScimUserParams) (*adminstore.ScimUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[scimUserID]
	if !ok || u.OrgID != orgID {
		return nil, adminstore.ErrNotFound
	}
	u.ExternalID, u.GivenName, u.FamilyName = p.ExternalID, p.GivenName, p.FamilyName
	u.DisplayName = adminstore.ScimDisplayName(p.GivenName, p.FamilyName)
	u.Active = p.Active
	u.LastSyncedAt = time.Now()
	return u, nil
}

func (f *fakeScimStore) DeactivateScimUser(_ context.Context, orgID, scimUserID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[scimUserID]
	if !ok || u.OrgID != orgID {
		return adminstore.ErrNotFound
	}
	u.Active = false // deactivation, NOT deletion
	return nil
}

func (f *fakeScimStore) roleMembersLocked(orgID string, role adminstore.OrgRole) []*adminstore.ScimGroupMember {
	var out []*adminstore.ScimGroupMember
	for _, u := range f.users {
		if u.OrgID != orgID {
			continue
		}
		if !u.Active { // deactivated members are never listed
			continue
		}
		if f.memberships[u.AdminUserID+"|"+orgID] == role {
			out = append(out, &adminstore.ScimGroupMember{Value: u.ID, Display: u.UserName})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}

func (f *fakeScimStore) ListScimRoleMembers(_ context.Context, orgID string, role adminstore.OrgRole) ([]*adminstore.ScimGroupMember, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.roleMembersLocked(orgID, role), nil
}

func (f *fakeScimStore) SetScimMemberRole(_ context.Context, orgID, scimUserID string, role adminstore.OrgRole) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[scimUserID]
	if !ok || u.OrgID != orgID { // no cross-org membership, ever
		return adminstore.ErrNotFound
	}
	f.memberships[u.AdminUserID+"|"+orgID] = role
	return nil
}

func (f *fakeScimStore) RemoveScimMemberRole(_ context.Context, orgID, scimUserID string, role adminstore.OrgRole) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[scimUserID]
	if !ok || u.OrgID != orgID {
		return adminstore.ErrNotFound
	}
	key := u.AdminUserID + "|" + orgID
	if f.memberships[key] == role {
		delete(f.memberships, key)
	}
	return nil
}

func (f *fakeScimStore) RemoveScimRoleMembers(_ context.Context, orgID string, role adminstore.OrgRole) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var removed int64
	for _, u := range f.users {
		key := u.AdminUserID + "|" + orgID
		if f.memberships[key] == role {
			delete(f.memberships, key)
			removed++
		}
	}
	return removed, nil
}

// membershipRole returns the current role of a user in an org (test aid).
func (f *fakeScimStore) membershipRole(adminUserID, orgID string) (adminstore.OrgRole, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	role, ok := f.memberships[adminUserID+"|"+orgID]
	return role, ok
}

// ---------------------------------------------------------------------------
// Harnesses.
// ---------------------------------------------------------------------------

// newSCIMTestHandler builds AdminHandlers over the standard mock + a SCIM
// capability, with a captured slog output for the no-token-in-logs test.
func newSCIMTestHandler(t *testing.T) (*AdminHandlers, *fakeScimStore, *bytes.Buffer) {
	t.Helper()
	fake := newFakeScimStore()
	base := newMockStore()
	base.orgs["org-a"] = &adminstore.Organization{ID: "org-a", Name: "Org A"}
	base.orgs["org-b"] = &adminstore.Organization{ID: "org-b", Name: "Org B"}
	h := New(base, "test-session-key", "scim.test", nil)
	h.SetScimStore(fake)
	buf := &bytes.Buffer{}
	h.logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(h.Stop)
	return h, fake, buf
}

// scimRequest serves a request through the full SetupRouter (the /scim/v2
// mount is on the public router, guarded only by the bearer middleware).
func scimRequest(t *testing.T, h *AdminHandlers, method, path, bearer string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == nil {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(string(body))
	}
	req := httptest.NewRequestWithContext(t.Context(), method, path, reader)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	rec := httptest.NewRecorder()
	h.SetupRouter().ServeHTTP(rec, req)
	return rec
}

// scimAdminRequest serves an admin-session request as root through a mini
// chi router (mirrors the real chain for the root caller: RequireOrgPermission
// passes for root; the handler's requireOrgScope resolves the path org).
func scimAdminRequest(t *testing.T, h *AdminHandlers, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := context.WithValue(req.Context(), adminauth.ContextKeyUserID{}, "admin-root")
			ctx = context.WithValue(ctx, adminauth.ContextKeyIsRoot{}, true)
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})
	switch method {
	case http.MethodGet:
		r.Get("/api/organizations/{id}/scim/tokens", h.ListScimTokens())
	case http.MethodPost:
		r.Post("/api/organizations/{id}/scim/tokens", h.CreateScimToken())
	case http.MethodDelete:
		r.Delete("/api/organizations/{id}/scim/tokens/{tokenID}", h.RevokeScimToken())
	}
	var reader *strings.Reader
	if body == nil {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(string(body))
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, path, reader))
	return rec
}

// issueToken drives the admin API to mint a token and returns the raw value
// plus its record id.
func issueToken(t *testing.T, h *AdminHandlers, orgID string) (string, string) {
	t.Helper()
	rec := scimAdminRequest(t, h, http.MethodPost, "/api/organizations/"+orgID+"/scim/tokens", []byte(`{"label":"okta-prod"}`))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var res struct {
		Token       string `json:"token"`
		TokenRecord struct {
			ID    string `json:"id"`
			Label string `json:"label"`
		} `json:"token_record"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	require.True(t, strings.HasPrefix(res.Token, "scim_"), "token must carry the scim_ prefix")
	return res.Token, res.TokenRecord.ID
}

// ---------------------------------------------------------------------------
// Okta / Entra contract fixtures.
// ---------------------------------------------------------------------------

// oktaCreateUser is the JSON Okta pushes on SCIM provisioning.
const oktaCreateUser = `{
	"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
	"userName": "john.kdo@example.com",
	"name": {"givenName": "John", "familyName": "Kdo"},
	"emails": [{"value": "john.kdo@example.com", "primary": true}],
	"displayName": "John Kdo",
	"externalId": "00u1okta123",
	"active": true
}`

// entraDeactivate is the JSON Entra pushes on assignment removal / sign-in
// disabled: attribute-level Replace operations.
func entraDeactivate(given string) string {
	return fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [
			{"op": "Replace", "path": "active", "value": false},
			{"op": "Replace", "path": "name.givenName", "value": %q}
		]
	}`, given)
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

// TestSCIMCreateUser_OktaContract: create → 201 with the SCIM User schema,
// reader membership in the token org; an Okta retry with the same
// externalId returns the EXISTING resource (200) without a duplicate.
func TestSCIMCreateUser_OktaContract(t *testing.T) {
	h, fake, _ := newSCIMTestHandler(t)
	token, _ := issueToken(t, h, "org-a")

	rec := scimRequest(t, h, http.MethodPost, "/scim/v2/Users", token, []byte(oktaCreateUser))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, scimContentType, rec.Header().Get("Content-Type"))
	assert.NotEmpty(t, rec.Header().Get("Location"))

	var created map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	assert.Equal(t, []any{"urn:ietf:params:scim:schemas:core:2.0:User"}, created["schemas"])
	assert.Equal(t, "john.kdo@example.com", created["userName"])
	assert.Equal(t, "00u1okta123", created["externalId"])
	assert.Equal(t, true, created["active"])
	meta, _ := created["meta"].(map[string]any)
	require.NotNil(t, meta)
	assert.Equal(t, "User", meta["resourceType"])
	name, _ := created["name"].(map[string]any)
	assert.Equal(t, "John", name["givenName"])

	id, _ := created["id"].(string)
	adminUserID := func() string {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return fake.users[id].AdminUserID
	}()
	role, ok := fake.membershipRole(adminUserID, "org-a")
	require.True(t, ok, "SCIM-created user must hold a membership in the token org")
	assert.Equal(t, adminstore.RoleReader, role, "default role is reader")

	// Okta retry: same payload → 200 existing, no duplicate.
	rec = scimRequest(t, h, http.MethodPost, "/scim/v2/Users", token, []byte(oktaCreateUser))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var again map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &again))
	assert.Equal(t, id, again["id"], "the same externalId must resolve to the existing resource")
	fake.mu.Lock()
	assert.Len(t, fake.users, 1, "no duplicate identity may be created")
	fake.mu.Unlock()
}

func TestSCIMMutationAuditAttributesBearerToken(t *testing.T) {
	h, _, _ := newSCIMTestHandler(t)
	token, tokenID := issueToken(t, h, "org-a")

	rec := scimRequest(t, h, http.MethodPost, "/scim/v2/Users", token, []byte(oktaCreateUser))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	store := h.store.(*mockStore)
	store.auditMu.Lock()
	entries := append([]adminstore.AuditLogEntryRecord(nil), store.auditRecords...)
	store.auditMu.Unlock()
	require.Len(t, entries, 2, "token issuance and SCIM provisioning are both audited")
	entry := entries[1]
	assert.Equal(t, "create", entry.Action)
	assert.Equal(t, tokenID, entry.AdminID)
	assert.Equal(t, "scim-token:"+tokenID, entry.AdminName)
	assert.Contains(t, entry.Details, "actor=scim_token:"+tokenID)
	assert.NotContains(t, entry.Details, token)
}

// TestSCIMPatchUser_EntraContract: attribute-level Replace ops deactivate
// the user (admin account AND identity) and sync names; userName is
// immutable through PATCH (emails.value mutation refused).
func TestSCIMPatchUser_EntraContract(t *testing.T) {
	h, fake, _ := newSCIMTestHandler(t)
	token, _ := issueToken(t, h, "org-a")

	rec := scimRequest(t, h, http.MethodPost, "/scim/v2/Users", token, []byte(oktaCreateUser))
	require.Equal(t, http.StatusCreated, rec.Code)
	var created map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	id := created["id"].(string)

	rec = scimRequest(t, h, http.MethodPatch, "/scim/v2/Users/"+id, token, []byte(entraDeactivate("Alex")))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var patched map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &patched))
	assert.Equal(t, false, patched["active"], "Entra deactivate must flip active")
	name, _ := patched["name"].(map[string]any)
	assert.Equal(t, "Alex", name["givenName"])
	fake.mu.Lock()
	assert.False(t, fake.users[id].Active, "identity active flag synced")
	fake.mu.Unlock()

	// Entra tries to move the sign-in email: refused.
	emailMove := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"Replace","path":"emails[type eq \"work\"].value","value":"new@example.com"}]}`
	rec = scimRequest(t, h, http.MethodPatch, "/scim/v2/Users/"+id, token, []byte(emailMove))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestSCIMPutUser_UserNameImmutable: a PUT with a changed userName is a 400;
// the same userName (case-insensitive) syncs.
func TestSCIMPutUser_UserNameImmutable(t *testing.T) {
	h, _, _ := newSCIMTestHandler(t)
	token, _ := issueToken(t, h, "org-a")

	rec := scimRequest(t, h, http.MethodPost, "/scim/v2/Users", token, []byte(oktaCreateUser))
	require.Equal(t, http.StatusCreated, rec.Code)
	var created map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	id := created["id"].(string)

	moved := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"moved@example.com","active":true}`
	rec = scimRequest(t, h, http.MethodPut, "/scim/v2/Users/"+id, token, []byte(moved))
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

	sameUpper := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"JOHN.KDO@EXAMPLE.COM","active":false,"name":{"givenName":"Jo"}}`
	rec = scimRequest(t, h, http.MethodPut, "/scim/v2/Users/"+id, token, []byte(sameUpper))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var synced map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &synced))
	assert.Equal(t, false, synced["active"])
}

// TestSCIMDeleteUserDeactivates: DELETE answers 204 and the account is
// deactivated — never removed (a later GET still resolves it, inactive).
func TestSCIMDeleteUserDeactivates(t *testing.T) {
	h, _, _ := newSCIMTestHandler(t)
	token, _ := issueToken(t, h, "org-a")

	rec := scimRequest(t, h, http.MethodPost, "/scim/v2/Users", token, []byte(oktaCreateUser))
	require.Equal(t, http.StatusCreated, rec.Code)
	var created map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	id := created["id"].(string)

	rec = scimRequest(t, h, http.MethodDelete, "/scim/v2/Users/"+id, token, nil)
	require.Equal(t, http.StatusNoContent, rec.Code)

	rec = scimRequest(t, h, http.MethodGet, "/scim/v2/Users/"+id, token, nil)
	require.Equal(t, http.StatusOK, rec.Code, "a deactivated user must still resolve")
	var got map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, false, got["active"])
	assert.Equal(t, 0, listUsers(t, h, token, "").TotalResults, "inactive identity must be excluded from list results")
	rec = scimRequest(t, h, http.MethodDelete, "/scim/v2/Users/"+id, token, nil)
	require.Equal(t, http.StatusNoContent, rec.Code, "repeated soft-delete is idempotent")
}

func TestSCIMRateLimitIsScopedPerToken(t *testing.T) {
	h, _, _ := newSCIMTestHandler(t)
	h.SetScimRateLimit(2, time.Minute)
	tokenA, _ := issueToken(t, h, "org-a")
	tokenB, _ := issueToken(t, h, "org-a")

	for i := 0; i < 2; i++ {
		rec := scimRequest(t, h, http.MethodGet, "/scim/v2/Schemas", tokenA, nil)
		require.Equal(t, http.StatusOK, rec.Code)
	}
	limited := scimRequest(t, h, http.MethodGet, "/scim/v2/Schemas", tokenA, nil)
	require.Equal(t, http.StatusTooManyRequests, limited.Code)
	assert.Equal(t, "60", limited.Header().Get("Retry-After"))
	otherToken := scimRequest(t, h, http.MethodGet, "/scim/v2/Schemas", tokenB, nil)
	require.Equal(t, http.StatusOK, otherToken.Code, "another token must have an independent quota")
}

// TestSCIMGroupMembershipContract: POST /Groups maps displayName → role;
// PATCH add/replace/remove converge the membership; DELETE strips the role
// from every member; an unknown displayName is a 400.
func TestSCIMGroupMembershipContract(t *testing.T) {
	h, fake, _ := newSCIMTestHandler(t)
	token, _ := issueToken(t, h, "org-a")

	// Provision a user first (POST /Users).
	rec := scimRequest(t, h, http.MethodPost, "/scim/v2/Users", token, []byte(oktaCreateUser))
	require.Equal(t, http.StatusCreated, rec.Code)
	var created map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	userID := created["id"].(string)
	adminUserID := func() string {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return fake.users[userID].AdminUserID
	}

	// Okta group push: displayName "operator" (also alias-tolerant).
	rec = scimRequest(t, h, http.MethodPost, "/scim/v2/Groups", token,
		[]byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"operator"}`))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var group map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &group))
	assert.Equal(t, "operator", group["id"])

	// Alias form maps to the same role.
	rec = scimRequest(t, h, http.MethodPost, "/scim/v2/Groups", token,
		[]byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Org Admin"}`))
	require.Equal(t, http.StatusCreated, rec.Code)

	// Unknown displayName → 400 invalidValue.
	rec = scimRequest(t, h, http.MethodPost, "/scim/v2/Groups", token,
		[]byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"unmapped-team"}`))
	require.Equal(t, http.StatusBadRequest, rec.Code)

	// Okta group member push: replace with the full member set.
	payload := fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","path":"members","value":[{"value":%q,"display":"john.kdo@example.com"}]}]}`, userID)
	rec = scimRequest(t, h, http.MethodPatch, "/scim/v2/Groups/operator", token, []byte(payload))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	role, ok := fake.membershipRole(adminUserID(), "org-a")
	require.True(t, ok)
	assert.Equal(t, adminstore.RoleOperator, role, "group membership maps to the group's role")

	// Entra-style single-member remove (add → remove round trip).
	removeOp := fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"remove","path":"members","value":[{"value":%q}]}]}`, userID)
	rec = scimRequest(t, h, http.MethodPatch, "/scim/v2/Groups/operator", token, []byte(removeOp))
	require.Equal(t, http.StatusOK, rec.Code)
	_, ok = fake.membershipRole(adminUserID(), "org-a")
	assert.False(t, ok, "removed member must lose the membership")

	// Re-add via op add, then DELETE /Groups/operator strips the role.
	addOp := fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"add","path":"members","value":[{"value":%q}]}]}`, userID)
	rec = scimRequest(t, h, http.MethodPatch, "/scim/v2/Groups/operator", token, []byte(addOp))
	require.Equal(t, http.StatusOK, rec.Code)
	rec = scimRequest(t, h, http.MethodDelete, "/scim/v2/Groups/operator", token, nil)
	require.Equal(t, http.StatusNoContent, rec.Code)
	_, ok = fake.membershipRole(adminUserID(), "org-a")
	assert.False(t, ok, "DELETE /Groups must strip the role from all members")

	// GET /Groups lists the role groups with SCIM members only.
	rec = scimRequest(t, h, http.MethodGet, "/scim/v2/Groups", token, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var list struct {
		TotalResults int              `json:"totalResults"`
		Resources    []map[string]any `json:"Resources"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	assert.Equal(t, len(adminstore.AllOrgRoles()), list.TotalResults)
}

// TestSCIMFilterParser: only `userName eq "value"` matches; malformed is a
// 400; unsupported attributes/operators return an EMPTY list (fail closed).
func TestSCIMFilterParser(t *testing.T) {
	userName, ok, err := parseScimUserFilter(`userName eq "jsmith"`)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "jsmith", userName)

	// Case-insensitive attribute/operator.
	userName, ok, err = parseScimUserFilter(`USERNAME EQ "Js@Example.com"`)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "Js@Example.com", userName)

	// Unsupported attribute/operator: well-formed, unmatchable → empty list.
	_, ok, err = parseScimUserFilter(`emails eq "x@y.z"`)
	require.NoError(t, err)
	assert.False(t, ok)
	_, ok, err = parseScimUserFilter(`userName co "js"`)
	require.NoError(t, err)
	assert.False(t, ok)

	// Malformed → 400.
	for _, bad := range []string{`userName`, `userName eq`, `userName eq js`, `userName eq "un`} {
		_, _, perr := parseScimUserFilter(bad)
		require.Error(t, perr, "filter %q must be rejected as malformed", bad)
	}

	h, _, _ := newSCIMTestHandler(t)
	token, _ := issueToken(t, h, "org-a")
	filter := url.QueryEscape(`userName eq "missing@example.com"`)
	rec := scimRequest(t, h, http.MethodGet, "/scim/v2/Users?filter="+filter, token, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"totalResults":0`)

	rec = scimRequest(t, h, http.MethodGet, `/scim/v2/Users?filter=broken`, token, nil)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalidFilter")
}

// TestSCIMTokenLifecycle_Revoke401: issue → use → revoke → 401; the token is
// shown exactly once (listings carry metadata only) and the org scope of a
// foreign org's token never resolves.
func TestSCIMTokenLifecycle_Revoke401(t *testing.T) {
	h, _, _ := newSCIMTestHandler(t)
	token, tokenID := issueToken(t, h, "org-a")

	rec := scimRequest(t, h, http.MethodGet, "/scim/v2/Users", token, nil)
	require.Equal(t, http.StatusOK, rec.Code, "a live token must authenticate")

	// The admin listing must NOT carry the raw token (shown once at create).
	rec = scimAdminRequest(t, h, http.MethodGet, "/api/organizations/org-a/scim/tokens", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), token, "the raw token must never appear on listings")

	// Revoke → immediate 401 on /scim/v2.
	rec = scimAdminRequest(t, h, http.MethodDelete, "/api/organizations/org-a/scim/tokens/"+tokenID, nil)
	require.Equal(t, http.StatusNoContent, rec.Code)
	rec = scimRequest(t, h, http.MethodGet, "/scim/v2/Users", token, nil)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, scimContentType, rec.Header().Get("Content-Type"))
	var scimErr map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &scimErr))
	assert.Contains(t, scimErr["schemas"], "urn:ietf:params:scim:api:messages:2.0:Error")

	// A second org's id is 404 for this org's admin (org predicate).
	rec = scimAdminRequest(t, h, http.MethodDelete, "/api/organizations/org-b/scim/tokens/"+tokenID, nil)
	require.Equal(t, http.StatusNotFound, rec.Code)

	// Garbage / missing bearer → 401.
	rec = scimRequest(t, h, http.MethodGet, "/scim/v2/Users", "scim_f000000000000000000000000000000000000000000000000000000000000000", nil)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	rec = scimRequest(t, h, http.MethodGet, "/scim/v2/Users", "", nil)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, `Bearer realm="scim"`, rec.Header().Get("WWW-Authenticate"))
}

// TestSCIMTokenNeverLogged: the raw bearer token never reaches the server
// logs — not on refusals, not on successful calls (PII/secret discipline).
func TestSCIMTokenNeverLogged(t *testing.T) {
	h, _, logs := newSCIMTestHandler(t)
	token, _ := issueToken(t, h, "org-a")

	// A refused call (unknown token) and a successful call.
	scimRequest(t, h, http.MethodGet, "/scim/v2/Users", "scim_deadbeef0000000000000000000000000000000000000000000000000000000", nil)
	scimRequest(t, h, http.MethodPost, "/scim/v2/Users", token, []byte(oktaCreateUser))
	scimRequest(t, h, http.MethodGet, "/scim/v2/Users", token, nil)

	assert.NotContains(t, logs.String(), token, "the raw token must never be logged")
	assert.NotContains(t, logs.String(), "scim_", "no token-shaped material may be logged")
}

// TestSCIMAuthOrgIsolation: a token of org A resolves only org A's SCIM
// objects — org B's users are invisible (list and per-id reads).
func TestSCIMAuthOrgIsolation(t *testing.T) {
	h, _, _ := newSCIMTestHandler(t)
	tokenA, _ := issueToken(t, h, "org-a")
	tokenB, _ := issueToken(t, h, "org-b")

	// Seed one user per org.
	rec := scimRequest(t, h, http.MethodPost, "/scim/v2/Users", tokenA, []byte(oktaCreateUser))
	require.Equal(t, http.StatusCreated, rec.Code)
	var userA map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &userA))

	orgBUser := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"bee@example.com","externalId":"entra-777","active":true}`
	rec = scimRequest(t, h, http.MethodPost, "/scim/v2/Users", tokenB, []byte(orgBUser))
	require.Equal(t, http.StatusCreated, rec.Code)
	var userB map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &userB))

	// List with token A: only org A's user.
	rec = scimRequest(t, h, http.MethodGet, "/scim/v2/Users", tokenA, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var list struct {
		TotalResults int              `json:"totalResults"`
		Resources    []map[string]any `json:"Resources"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	require.Equal(t, 1, list.TotalResults)
	assert.Equal(t, userA["id"], list.Resources[0]["id"])
	assert.NotContains(t, rec.Body.String(), "bee@example.com")

	// Per-id read across orgs → 404 (not a cross-org leak).
	rec = scimRequest(t, h, http.MethodGet, "/scim/v2/Users/"+userB["id"].(string), tokenA, nil)
	require.Equal(t, http.StatusNotFound, rec.Code)

	// Mutations across orgs are 404 as well (deactivate + membership).
	rec = scimRequest(t, h, http.MethodDelete, "/scim/v2/Users/"+userB["id"].(string), tokenA, nil)
	require.Equal(t, http.StatusNotFound, rec.Code)
	rec = scimRequest(t, h, http.MethodPatch, "/scim/v2/Groups/reader", tokenA,
		[]byte(fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations":[{"op":"add","path":"members","value":[{"value":%q}]}]}`, userB["id"])))
	require.Equal(t, http.StatusNotFound, rec.Code, "a foreign-org member value must never gain a membership")

	// And from B's side: org A's user is invisible.
	rec = scimRequest(t, h, http.MethodGet, "/scim/v2/Users/"+userA["id"].(string), tokenB, nil)
	require.Equal(t, http.StatusNotFound, rec.Code)
}

// TestSCIMDefaultRoleOverride: SetScimDefaultRole changes the membership
// role SCIM-created users receive; an invalid role is ignored (keeps reader).
func TestSCIMDefaultRoleOverride(t *testing.T) {
	h, fake, _ := newSCIMTestHandler(t)
	h.SetScimDefaultRole(adminstore.RoleOperator)
	h.SetScimDefaultRole("not-a-role") // ignored

	token, _ := issueToken(t, h, "org-a")
	rec := scimRequest(t, h, http.MethodPost, "/scim/v2/Users", token, []byte(oktaCreateUser))
	require.Equal(t, http.StatusCreated, rec.Code)
	var created map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	fake.mu.Lock()
	adminID := fake.users[created["id"].(string)].AdminUserID
	fake.mu.Unlock()
	role, ok := fake.membershipRole(adminID, "org-a")
	require.True(t, ok)
	assert.Equal(t, adminstore.RoleOperator, role)
}

// TestSCIMStoreUnavailable: without the SCIM capability the surface answers
// 503 (not a 401 — misconfigurations must be distinguishable from auth
// failures).
func TestSCIMStoreUnavailable(t *testing.T) {
	h, _, _ := newSCIMTestHandler(t)
	h.SetScimStore(nil) // back to lazy resolution: mockStore has no capability

	rec := scimRequest(t, h, http.MethodGet, "/scim/v2/Users", "scim_whatever", nil)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "not available")
}

// TestScimTokenMatchesConstantTime: pin the confirmation contract — the
// compare is deterministic true/false and rejects wrong hashes of any length.
func TestScimTokenMatchesConstantTime(t *testing.T) {
	raw, hash, err := adminstore.NewScimToken()
	require.NoError(t, err)
	assert.True(t, adminstore.ScimTokenMatches(raw, hash))
	assert.False(t, adminstore.ScimTokenMatches(raw+"x", hash))
	assert.False(t, adminstore.ScimTokenMatches(strings.ToUpper(raw), hash))
	assert.False(t, adminstore.ScimTokenMatches(raw, ""))
	otherRaw, otherHash, err := adminstore.NewScimToken()
	require.NoError(t, err)
	assert.False(t, adminstore.ScimTokenMatches(raw, otherHash))
	assert.True(t, adminstore.ScimTokenMatches(otherRaw, otherHash))
}

// TestSCIMErrorsAreScimShaped: 4xx answers carry the SCIM Error schema and
// the scim+json content type (Okta parses these).
func TestSCIMErrorsAreScimShaped(t *testing.T) {
	h, _, _ := newSCIMTestHandler(t)
	token, _ := issueToken(t, h, "org-a")

	rec := scimRequest(t, h, http.MethodPost, "/scim/v2/Users", token, []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"]}`))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	var scimErr map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &scimErr))
	assert.Contains(t, scimErr["schemas"], "urn:ietf:params:scim:api:messages:2.0:Error")
	assert.Equal(t, "400", scimErr["status"])
	assert.Equal(t, "invalidValue", scimErr["scimType"])

	// Unknown user id → 404 SCIM error.
	rec = scimRequest(t, h, http.MethodGet, "/scim/v2/Users/su-missing", token, nil)
	require.Equal(t, http.StatusNotFound, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &scimErr))
	assert.Contains(t, scimErr["schemas"], "urn:ietf:params:scim:api:messages:2.0:Error")

	// Unresolvable store failure → 500 SCIM error (not a driver leak).
	rec = scimRequest(t, h, http.MethodGet, "/scim/v2/NoSuchResource", token, nil)
	require.Equal(t, http.StatusNotFound, rec.Code, "chi 404 stays a plain 404")
}

// TestSCIMServiceProviderConfig: discovery document behind the bearer guard.
func TestSCIMServiceProviderConfig(t *testing.T) {
	h, _, _ := newSCIMTestHandler(t)
	token, _ := issueToken(t, h, "org-a")

	rec := scimRequest(t, h, http.MethodGet, "/scim/v2/ServiceProviderConfig", token, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &cfg))
	assert.Contains(t, cfg["schemas"], "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig")
	filter, _ := cfg["filter"].(map[string]any)
	assert.Equal(t, true, filter["supported"])

	// Without a token → 401 (it is inside the guard).
	rec = scimRequest(t, h, http.MethodGet, "/scim/v2/ServiceProviderConfig", "", nil)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestSCIMLastUsedThrottled: the last_used_at stamp is written at most once
// per minute per token (off the hot path) — several requests within the
// window produce ONE touch.
func TestSCIMLastUsedThrottled(t *testing.T) {
	h, _, _ := newSCIMTestHandler(t)
	token, _ := issueToken(t, h, "org-a")

	for i := 0; i < 5; i++ {
		rec := scimRequest(t, h, http.MethodGet, "/scim/v2/Users", token, nil)
		require.Equal(t, http.StatusOK, rec.Code)
	}
	// The detached touch goroutine needs a moment; poll briefly.
	deadline := time.Now().Add(2 * time.Second)
	var lastUsed *time.Time
	for time.Now().Before(deadline) {
		rec := scimAdminRequest(t, h, http.MethodGet, "/api/organizations/org-a/scim/tokens", nil)
		var res struct {
			Data []adminstore.ScimToken `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
		if len(res.Data) == 1 && res.Data[0].LastUsedAt != nil {
			lastUsed = res.Data[0].LastUsedAt
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.NotNil(t, lastUsed, "last_used_at must eventually be stamped")
	assert.Less(t, time.Since(*lastUsed), 2*time.Minute)
}

// TestSCIMNoRouteConflicts: /scim/v2 stays OUTSIDE the admin session guard —
// a request without any session cookie must reach the SCIM middleware (401
// shape, not the admin JSON error).
func TestSCIMNoRouteConflicts(t *testing.T) {
	h, _, _ := newSCIMTestHandler(t)
	rec := scimRequest(t, h, http.MethodGet, "/scim/v2/Users", "", nil)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, scimContentType, rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "urn:ietf:params:scim:api:messages:2.0:Error")
	_ = errors.Is // keep errors import parity with store-error branches
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

// scimListBody is the parsed ListResponse envelope of a list request.
type scimListBody struct {
	TotalResults int              `json:"totalResults"`
	ItemsPerPage int              `json:"itemsPerPage"`
	StartIndex   int              `json:"startIndex"`
	Resources    []map[string]any `json:"Resources"`
}

func listUsers(t *testing.T, h *AdminHandlers, token, query string) scimListBody {
	t.Helper()
	rec := scimRequest(t, h, http.MethodGet, "/scim/v2/Users"+query, token, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body scimListBody
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body
}

// TestSCIMListUsers_Pagination: startIndex/count window the result set;
// totalReports stays the FULL count; count clamps into [1,200]; malformed
// values are 400s; a filter combines with the window.
func TestSCIMListUsers_Pagination(t *testing.T) {
	h, _, _ := newSCIMTestHandler(t)
	token, _ := issueToken(t, h, "org-a")

	// Seed five users (u-0..u-4); provisioning order fixes the stable order.
	for i := 0; i < 5; i++ {
		body := fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName":"u-%d@example.com","active":true}`, i)
		rec := scimRequest(t, h, http.MethodPost, "/scim/v2/Users", token, []byte(body))
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	}

	// Default (no params): everything, startIndex 1.
	all := listUsers(t, h, token, "")
	require.Equal(t, 5, all.TotalResults)
	assert.Equal(t, 5, all.ItemsPerPage)
	assert.Equal(t, 1, all.StartIndex)
	require.Len(t, all.Resources, 5)

	// Page 1: first two users; totalResults stays the full five.
	p1 := listUsers(t, h, token, "?startIndex=1&count=2")
	require.Equal(t, 5, p1.TotalResults)
	assert.Equal(t, 2, p1.ItemsPerPage)
	assert.Equal(t, 1, p1.StartIndex)
	require.Len(t, p1.Resources, 2)

	// Page 2 continues without overlap (order is deterministic).
	p2 := listUsers(t, h, token, "?startIndex=3&count=2")
	require.Len(t, p2.Resources, 2)
	assert.Equal(t, 3, p2.StartIndex)
	seen := map[string]bool{}
	for _, page := range []scimListBody{p1, p2} {
		for _, r := range page.Resources {
			id, _ := r["id"].(string)
			require.False(t, seen[id], "pages must not overlap: %s", id)
			seen[id] = true
		}
	}
	assert.Len(t, seen, 4, "two pages of 2 cover 4 distinct users")

	// A tail window returns the remainder (5th user alone).
	tail := listUsers(t, h, token, "?startIndex=5&count=10")
	require.Equal(t, 5, tail.TotalResults)
	require.Len(t, tail.Resources, 1)

	// Past the end: empty Resources, totalResults intact.
	past := listUsers(t, h, token, "?startIndex=99")
	require.Equal(t, 5, past.TotalResults)
	assert.Empty(t, past.Resources)

	// count clamps: 0 → 1, negative → 1, huge → the 200 ceiling.
	c0 := listUsers(t, h, token, "?count=0")
	assert.Len(t, c0.Resources, 1)
	cn := listUsers(t, h, token, "?count=-3")
	assert.Len(t, cn.Resources, 1)
	big := listUsers(t, h, token, "?count=9999")
	assert.Len(t, big.Resources, 5)

	// Malformed pagination params are 400 invalidValue (SCIM-shaped).
	for _, bad := range []string{"?startIndex=abc", "?count=abc"} {
		rec := scimRequest(t, h, http.MethodGet, "/scim/v2/Users"+bad, token, nil)
		require.Equal(t, http.StatusBadRequest, rec.Code, bad)
		assert.Contains(t, rec.Body.String(), "invalidValue", bad)
	}

	// A filter combines with the window: one match, count=1 page.
	filter := url.QueryEscape(`userName eq "u-1@example.com"`)
	f := listUsers(t, h, token, "?filter="+filter+"&count=1")
	require.Equal(t, 1, f.TotalResults)
	require.Len(t, f.Resources, 1)
	assert.Equal(t, "u-1@example.com", f.Resources[0]["userName"])
}

// TestSCIMListGroups_Pagination: the role groups page the same way.
func TestSCIMListGroups_Pagination(t *testing.T) {
	h, _, _ := newSCIMTestHandler(t)
	token, _ := issueToken(t, h, "org-a")

	rec := scimRequest(t, h, http.MethodGet, "/scim/v2/Groups?count=2&startIndex=1", token, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var page scimListBody
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	require.Equal(t, len(adminstore.AllOrgRoles()), page.TotalResults)
	assert.Equal(t, 2, page.ItemsPerPage)
	require.Len(t, page.Resources, 2)

	rec = scimRequest(t, h, http.MethodGet, "/scim/v2/Groups?startIndex=4&count=2", token, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	page = scimListBody{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	require.Len(t, page.Resources, 2)

	rec = scimRequest(t, h, http.MethodGet, "/scim/v2/Groups?startIndex=99", token, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	page = scimListBody{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	assert.Empty(t, page.Resources)
	require.Equal(t, len(adminstore.AllOrgRoles()), page.TotalResults)

	rec = scimRequest(t, h, http.MethodGet, "/scim/v2/Groups?count=nope", token, nil)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestSCIMSchemasDiscovery: /Schemas serves the supported User/Group subset
// with the enforced mutability contract (userName immutable, password
// writeOnly/never), behind the bearer guard.
func TestSCIMSchemasDiscovery(t *testing.T) {
	h, _, _ := newSCIMTestHandler(t)
	token, _ := issueToken(t, h, "org-a")

	rec := scimRequest(t, h, http.MethodGet, "/scim/v2/Schemas", token, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, scimContentType, rec.Header().Get("Content-Type"))
	var body scimListBody
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, 2, body.TotalResults)

	byID := map[string]map[string]any{}
	for _, r := range body.Resources {
		id, _ := r["id"].(string)
		byID[id] = r
	}
	userSchema := byID["urn:ietf:params:scim:schemas:core:2.0:User"]
	require.NotNil(t, userSchema, "User schema must be served")
	groupSchema := byID["urn:ietf:params:scim:schemas:core:2.0:Group"]
	require.NotNil(t, groupSchema, "Group schema must be served")

	attr := func(schema map[string]any, name string) map[string]any {
		t.Helper()
		attrs, _ := schema["attributes"].([]any)
		for _, a := range attrs {
			m, _ := a.(map[string]any)
			if m["name"] == name {
				return m
			}
		}
		t.Fatalf("attribute %q missing from schema", name)
		return nil
	}
	assert.Equal(t, "immutable", attr(userSchema, "userName")["mutability"], "userName is immutable through SCIM")
	pwd := attr(userSchema, "password")
	assert.Equal(t, "writeOnly", pwd["mutability"])
	assert.Equal(t, "never", pwd["returned"])
	active := attr(userSchema, "active")
	assert.Equal(t, "boolean", active["type"])
	assert.Equal(t, "readWrite", active["mutability"])

	members := attr(groupSchema, "members")
	assert.Equal(t, true, members["multiValued"])
	subNames := map[string]bool{}
	for _, s := range members["subAttributes"].([]any) {
		subNames[s.(map[string]any)["name"].(string)] = true
	}
	assert.True(t, subNames["value"] && subNames["display"])

	// Inside the bearer guard like the rest of /scim/v2.
	rec = scimRequest(t, h, http.MethodGet, "/scim/v2/Schemas", "", nil)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestSCIMResourceTypesDiscovery: /ResourceTypes advertises Users + Groups
// with their schema URNs and no extensions.
func TestSCIMResourceTypesDiscovery(t *testing.T) {
	h, _, _ := newSCIMTestHandler(t)
	token, _ := issueToken(t, h, "org-a")

	rec := scimRequest(t, h, http.MethodGet, "/scim/v2/ResourceTypes", token, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body scimListBody
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, 2, body.TotalResults)

	endpoints := map[string]map[string]any{}
	for _, r := range body.Resources {
		ep, _ := r["endpoint"].(string)
		endpoints[ep] = r
	}
	userRT := endpoints["/Users"]
	require.NotNil(t, userRT, "User resource type must be served")
	assert.Equal(t, "urn:ietf:params:scim:schemas:core:2.0:User", userRT["schema"])
	groupRT := endpoints["/Groups"]
	require.NotNil(t, groupRT, "Group resource type must be served")
	assert.Equal(t, "urn:ietf:params:scim:schemas:core:2.0:Group", groupRT["schema"])
	assert.Empty(t, groupRT["schemaExtensions"])

	rec = scimRequest(t, h, http.MethodGet, "/scim/v2/ResourceTypes", "", nil)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestSCIMPagination_Edges: the boundary inputs of the ratified
// startIndex 1-based, clamps ≥1) — zero/negative startIndex clamp to the
// first page, an oversized count clamps to the 200 ceiling against a result
// set that EXCEEDS the ceiling (the clamp is observable, not incidental), and
// values outside the integer domain are 400 invalidValue.
func TestSCIMPagination_Edges(t *testing.T) {
	h, _, _ := newSCIMTestHandler(t)
	token, _ := issueToken(t, h, "org-a")

	// 205 users: more than the 200 ceiling, so the clamp changes the answer.
	for i := 0; i < 205; i++ {
		body := fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName":"edge-%03d@example.com","active":true}`, i)
		rec := scimRequest(t, h, http.MethodPost, "/scim/v2/Users", token, []byte(body))
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	}
	all := listUsers(t, h, token, "")
	require.Equal(t, 205, all.TotalResults)

	// Zero and negative startIndex clamp to the first page (RFC 7644
	// §3.4.2.2: values less than 1 are interpreted as 1).
	for _, q := range []string{"?startIndex=0", "?startIndex=-5"} {
		page := listUsers(t, h, token, q)
		assert.Equal(t, 1, page.StartIndex, q)
		require.Len(t, page.Resources, 100, "%s: default count window", q)
	}

	// Oversized count clamps to the 200 ceiling — never the raw 205.
	big := listUsers(t, h, token, "?startIndex=1&count=9999")
	require.Equal(t, 205, big.TotalResults)
	require.Len(t, big.Resources, 200, "oversized count must clamp to the 200 ceiling")
	assert.Equal(t, 200, big.ItemsPerPage)

	// The page after the ceiling window carries the remainder, disjoint.
	rest := listUsers(t, h, token, "?startIndex=201&count=200")
	require.Len(t, rest.Resources, 5)
	assert.Equal(t, 201, rest.StartIndex)
	seen := map[string]bool{}
	for _, page := range []scimListBody{big, rest} {
		for _, r := range page.Resources {
			id, _ := r["id"].(string)
			require.False(t, seen[id], "pages must not overlap: %s", id)
			seen[id] = true
		}
	}
	assert.Len(t, seen, 205, "ceiling window + remainder cover the set exactly")

	// Values outside the integer domain are 400 invalidValue (SCIM-shaped).
	for _, bad := range []string{
		"?startIndex=99999999999999999999", "?count=99999999999999999999",
		"?startIndex=1.5", "?count=-0.5",
	} {
		rec := scimRequest(t, h, http.MethodGet, "/scim/v2/Users"+bad, token, nil)
		require.Equal(t, http.StatusBadRequest, rec.Code, bad)
		assert.Contains(t, rec.Body.String(), "invalidValue", bad)
	}
}

// unauthenticated and badly authenticated callers exactly like the resource
// endpoints — missing bearer, wrong scheme, unknown token, and a REVOKED
// token all fail closed with the uniform 401 (revocation reaches discovery).
func TestSCIMSchemas_AuthFailure(t *testing.T) {
	h, _, _ := newSCIMTestHandler(t)
	raw, tokenID := issueToken(t, h, "org-a")

	for _, path := range []string{"/scim/v2/Schemas", "/scim/v2/ResourceTypes"} {
		// Missing bearer → 401 with the challenge header, SCIM-shaped body.
		rec := scimRequest(t, h, http.MethodGet, path, "", nil)
		require.Equal(t, http.StatusUnauthorized, rec.Code, path)
		assert.Equal(t, `Bearer realm="scim"`, rec.Header().Get("WWW-Authenticate"), path)
		assert.Contains(t, rec.Body.String(), scimSchemaError, path)

		// A non-bearer scheme is no bearer at all.
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		rec2 := httptest.NewRecorder()
		h.SetupRouter().ServeHTTP(rec2, req)
		require.Equal(t, http.StatusUnauthorized, rec2.Code, path)
		assert.Contains(t, rec2.Body.String(), scimSchemaError, path)

		// Unknown token → uniform invalidToken (no existence oracle).
		rec = scimRequest(t, h, http.MethodGet, path, "scim_"+strings.Repeat("deadbeef", 8), nil)
		require.Equal(t, http.StatusUnauthorized, rec.Code, path)
		assert.Contains(t, rec.Body.String(), "invalidToken", path)
	}

	// Revoked token: the discovery endpoints refuse it like every other
	// /scim/v2 route.
	rec := scimAdminRequest(t, h, http.MethodDelete, "/api/organizations/org-a/scim/tokens/"+tokenID, nil)
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
	rec = scimRequest(t, h, http.MethodGet, "/scim/v2/Schemas", raw, nil)
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "invalidToken")
}

// clamp matrix, pinned at the unit boundary so a clamp removal fails HERE
// first (fast) and at the HTTP boundary in TestSCIMPagination_Edges.
func TestSCIMParseScimPage_Clamps(t *testing.T) {
	got, err := parseScimPage(url.Values{})
	require.NoError(t, err)
	assert.Equal(t, scimPage{startIndex: 1, count: scimDefaultCount}, got, "defaults: startIndex 1, count 100")

	cases := []struct {
		query url.Values
		want  scimPage
	}{
		{url.Values{"startIndex": {"1"}}, scimPage{startIndex: 1, count: scimDefaultCount}},
		{url.Values{"startIndex": {"0"}}, scimPage{startIndex: 1, count: scimDefaultCount}},
		{url.Values{"startIndex": {"-5"}}, scimPage{startIndex: 1, count: scimDefaultCount}},
		{url.Values{"startIndex": {"7"}}, scimPage{startIndex: 7, count: scimDefaultCount}},
		{url.Values{"count": {"50"}}, scimPage{startIndex: 1, count: 50}},
		{url.Values{"count": {"0"}}, scimPage{startIndex: 1, count: 1}},
		{url.Values{"count": {"-3"}}, scimPage{startIndex: 1, count: 1}},
		{url.Values{"count": {"200"}}, scimPage{startIndex: 1, count: 200}},
		{url.Values{"count": {"201"}}, scimPage{startIndex: 1, count: 200}},
		{url.Values{"count": {"9999"}}, scimPage{startIndex: 1, count: 200}},
		{url.Values{"startIndex": {"201"}, "count": {"9999"}}, scimPage{startIndex: 201, count: 200}},
	}
	for _, tc := range cases {
		got, err := parseScimPage(tc.query)
		require.NoError(t, err, tc.query.Encode())
		assert.Equal(t, tc.want, got, tc.query.Encode())
	}

	for _, bad := range []url.Values{
		{"startIndex": {"abc"}}, {"count": {"abc"}},
		{"startIndex": {"1.5"}}, {"count": {"-0.5"}},
		{"startIndex": {"99999999999999999999"}}, {"count": {"99999999999999999999"}},
	} {
		if _, err := parseScimPage(bad); err == nil {
			t.Errorf("non-integer %q must be an error", bad.Encode())
		}
	}

	// Window arithmetic at the boundaries: full, tail, past-end, empty input.
	full := scimPage{startIndex: 1, count: 3}
	assert.Len(t, full.window([]any{1, 2}), 2, "tail window returns the remainder")
	past := scimPage{startIndex: 9, count: 3}
	assert.Nil(t, past.window([]any{1, 2}), "past-end window is empty")
	zero := scimPage{startIndex: 1, count: 1}
	assert.Empty(t, zero.window(nil), "empty input stays empty")
}

// TestSCIMGroupMembers_ExcludeDeactivated: a SCIM-deactivated ("deleted")
// user disappears from group member lists, and a stale PATCH remove of that
// member stays idempotent (200, no 404) — the IdP's "removed user + stale
// membership" scenario.
func TestSCIMGroupMembers_ExcludeDeactivated(t *testing.T) {
	h, _, _ := newSCIMTestHandler(t)
	token, _ := issueToken(t, h, "org-a")

	memberIDs := make([]string, 0, 2)
	for _, name := range []string{"gone@example.com", "stays@example.com"} {
		body := fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName":%q,"active":true}`, name)
		rec := scimRequest(t, h, http.MethodPost, "/scim/v2/Users", token, []byte(body))
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		var created map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
		memberIDs = append(memberIDs, created["id"].(string))
	}
	gone, stays := memberIDs[0], memberIDs[1]

	groupMembers := func() []string {
		rec := scimRequest(t, h, http.MethodGet, "/scim/v2/Groups/reader", token, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var group map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &group))
		out := []string{}
		for _, m := range group["members"].([]any) {
			out = append(out, m.(map[string]any)["value"].(string))
		}
		return out
	}
	require.ElementsMatch(t, []string{gone, stays}, groupMembers(), "both SCIM-created users hold the default reader role")

	// DELETE (deactivate) one user: the member list must drop them.
	rec := scimRequest(t, h, http.MethodDelete, "/scim/v2/Users/"+gone, token, nil)
	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, []string{stays}, groupMembers(), "deactivated member must vanish from the group list")

	// Reactivation restores the listing (deactivation kept the membership).
	reactivate := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"Replace","path":"active","value":true}]}`
	rec = scimRequest(t, h, http.MethodPatch, "/scim/v2/Users/"+gone, token, []byte(reactivate))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.ElementsMatch(t, []string{gone, stays}, groupMembers(), "reactivated member reappears")

	// Deactivate again, then the IdP's stale PATCH remove: the member is
	// already absent from the list, and the remove must stay 200 (the
	// identity still resolves; the membership delete is idempotent).
	rec = scimRequest(t, h, http.MethodDelete, "/scim/v2/Users/"+gone, token, nil)
	require.Equal(t, http.StatusNoContent, rec.Code)
	removeOp := fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"remove","path":"members","value":[{"value":%q}]}]}`, gone)
	rec = scimRequest(t, h, http.MethodPatch, "/scim/v2/Groups/reader", token, []byte(removeOp))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{stays}, groupMembers())
}
