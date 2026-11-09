package handlers_test

// W-BYOK-API: routing contract for the BYOK org provider-credential surface,
// asserted through the FULL SetupRouter (session auth + CSRF chain, exactly
// like org_settings_routing_test.go): the org-permission gate lives in the
// mount, the resource rules live in the handlers —
//
//	anon                          → 401 (session boundary)
//	root                          → 200/201 (any org; store unwired → 503)
//	member with keys.manage       → 200/201 (operator and org-admin hold it)
//	member without the permission → 403
//	no membership                 → 404 (the org stays invisible —
//	                                 resourceHidden semantics, as in
//	                                 org_settings_routing_test.go)
//	cross-org credId              → 404 (org-scoped lookup; never revealed)
//	store not wired               → 503 (until W-BYOK-DB lands)
//
// Masking contract: every response carries key_last4 only — the plaintext
// never appears in any body (the row type has no plaintext field).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

const (
	credSecret   = "test-session-secret" // #nosec G101 -- test-only HMAC key
	credCSRF     = "csrf-token-value"    // #nosec G101 -- test-only value
	credOrgA     = "org-a"
	credOrgB     = "org-b"
	credKeyOK    = "sk-test-credential-plaintext-9876" // #nosec G101 -- test-only fake key value
	credBaseOK   = "https://api.openai.com/v1"         // #nosec G101 -- test-only fake upstream URL
	credPathList = "/api/orgs/" + credOrgA + "/provider-credentials"
)

// credStoreStub implements the handlers.OrgCredentialStore contract over
// in-memory maps, plus the membership lookup the session chain needs. The
// stub mimics the store-side duties the real store owns: masking (key_last4)
// and the key-version bump on rotation. Tests run sequentially.
type credStoreStub struct {
	stubStore
	roles map[string]adminstore.OrgRole
	creds map[string]handlers.OrgCredential
	keys  map[string]string // cred id → plaintext (ResolveKey source)
	seq   int
}

func newCredStoreStub(roles map[string]adminstore.OrgRole) *credStoreStub {
	return &credStoreStub{
		roles: roles,
		creds: map[string]handlers.OrgCredential{},
		keys:  map[string]string{},
	}
}

func (s *credStoreStub) GetUserOrgRoles(context.Context, string) (map[string]adminstore.OrgRole, error) {
	return s.roles, nil
}

func (s *credStoreStub) List(_ context.Context, orgID string) ([]handlers.OrgCredential, error) {
	var out []handlers.OrgCredential
	for id, c := range s.creds {
		if c.OrgID == orgID {
			out = append(out, s.creds[id])
		}
	}
	return out, nil
}

func (s *credStoreStub) Create(_ context.Context, orgID, name, prov, baseURL, plaintextKey string) (handlers.OrgCredential, error) {
	if s.nameTaken(orgID, name, "") {
		// Mimic the real store: the org-unique violation surfaces as a
		// *pgconn.PgError(23505) the handler maps to 409.
		return handlers.OrgCredential{}, fmt.Errorf("credential name %q already exists in this org: %w",
			name, &pgconn.PgError{Code: "23505", Message: "duplicate key"})
	}
	s.seq++
	id := fmt.Sprintf("cred-%d", s.seq)
	c := handlers.OrgCredential{
		ID: id, OrgID: orgID, Name: name, Provider: prov, BaseURL: baseURL,
		KeyLast4: plaintextKey[max(0, len(plaintextKey)-4):],
		Enabled:  true, KeyVersion: 1,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	s.creds[id] = c
	s.keys[id] = plaintextKey
	return c, nil
}

// nameTaken reports whether another credential of the org already holds the
// name (exceptID skips the row being updated — the rename target itself).
func (s *credStoreStub) nameTaken(orgID, name, exceptID string) bool {
	for id, c := range s.creds {
		if c.OrgID == orgID && c.Name == name && id != exceptID {
			return true
		}
	}
	return false
}

func (s *credStoreStub) Update(_ context.Context, orgID, id string, updated handlers.OrgCredential, newPlaintextKey string) (handlers.OrgCredential, error) {
	c, ok := s.creds[id]
	if !ok {
		return handlers.OrgCredential{}, adminstore.ErrNotFound
	}
	if s.nameTaken(c.OrgID, updated.Name, id) {
		return handlers.OrgCredential{}, fmt.Errorf("credential name %q already exists in this org: %w",
			updated.Name, &pgconn.PgError{Code: "23505", Message: "duplicate key"})
	}
	updated.CreatedAt, updated.UpdatedAt = c.CreatedAt, time.Now()
	if newPlaintextKey != "" {
		updated.KeyLast4 = newPlaintextKey[len(newPlaintextKey)-4:]
		updated.KeyVersion = c.KeyVersion + 1
	}
	s.creds[id] = updated
	if newPlaintextKey != "" {
		s.keys[id] = newPlaintextKey
	}
	return updated, nil
}

func (s *credStoreStub) Delete(_ context.Context, orgID, id string) error {
	if _, ok := s.creds[id]; !ok {
		return adminstore.ErrNotFound
	}
	delete(s.creds, id)
	delete(s.keys, id)
	return nil
}

func (s *credStoreStub) ResolveKey(_ context.Context, orgID, prov, baseURL string) (string, bool, error) {
	for id, c := range s.creds {
		if c.OrgID == orgID && c.Provider == prov && c.BaseURL == baseURL {
			return s.keys[id], s.keys[id] != "", nil
		}
	}
	return "", false, nil
}

// seed inserts a credential directly (bypassing the POST validation) so the
// probe tests can point at a loopback httptest upstream.
func (s *credStoreStub) seed(orgID, baseURL string) handlers.OrgCredential {
	c, err := s.Create(context.Background(), orgID, "seeded", "openai", baseURL, credKeyOK)
	if err != nil {
		panic(err)
	}
	return c
}

// credBumper records SetOrgCredsVersion calls (the W-BYOK-CORE invalidation
// hook); fail forces errors so tests can pin "bump failure never fails CRUD".
type credBumper struct {
	mu    sync.Mutex
	orgs  []string
	fail  bool
	calls int
}

func (b *credBumper) SetOrgCredsVersion(_ context.Context, orgID string, _ int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	if b.fail {
		return errors.New("redis down")
	}
	b.orgs = append(b.orgs, orgID)
	return nil
}

func (b *credBumper) bumped() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.orgs...)
}

// credRequest runs one request through the router with the session + CSRF
// double-submit pair (GETs ignore the CSRF token, like the middleware).
func credRequest(t *testing.T, router http.Handler, method, path, cookie, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequestWithContext(t.Context(), method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.AddCookie(testCookie("yabanin_admin_session", cookie))
		req.AddCookie(testCookie("yabanin_csrf_token", credCSRF))
		req.Header.Set("X-CSRF-Token", credCSRF)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// credRouter builds the full SetupRouter with the credential handlers wired
// (wired=false keeps them unwired → 503).
func credRouter(t *testing.T, store *credStoreStub, opts handlers.OrgCredentialHandlerOptions, wired bool) http.Handler {
	t.Helper()
	return credRouterWithBumper(t, store, opts, wired, nil)
}

func credRouterWithBumper(t *testing.T, store *credStoreStub, opts handlers.OrgCredentialHandlerOptions, wired bool, bumper *credBumper) http.Handler {
	t.Helper()
	h := handlers.New(store, credSecret, "localhost", nil)
	if wired {
		// Only assign a non-nil bumper: a typed-nil *credBumper in the
		// interface would pass the nil check and panic on the bump.
		if bumper != nil {
			opts.VersionBumper = bumper
		}
		h.SetOrgCredentialHandlers(handlers.NewOrgCredentialHandlers(store, opts, nil))
	}
	return h.SetupRouter()
}

func credRootCookie(t *testing.T) string {
	t.Helper()
	return makeSessionCookie(t, "root@x.test", true, credSecret)
}
func credMemberCookie(t *testing.T) string {
	t.Helper()
	return makeSessionCookie(t, "admin@x.test", false, credSecret)
}

func credCreateBody(provider, baseURL, key string) string {
	return credCreateBodyNamed("prod key", provider, baseURL, key)
}

func credCreateBodyNamed(name, provider, baseURL, key string) string {
	return `{"name":"` + name + `","provider":"` + provider + `","base_url":"` + baseURL + `","api_key":"` + key + `"}`
}

func TestOrgCredentialsRoutingContract(t *testing.T) {
	rootCookie := credRootCookie(t)

	t.Run("anon is 401 on read and write (session boundary)", func(t *testing.T) {
		store := newCredStoreStub(nil)
		router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{}, true)

		if w := credRequest(t, router, http.MethodGet, credPathList, "", ""); w.Code != http.StatusUnauthorized {
			t.Errorf("anon GET = %d, want 401", w.Code)
		}
		if w := credRequest(t, router, http.MethodPost, credPathList, "", credCreateBody("openai", credBaseOK, credKeyOK)); w.Code != http.StatusUnauthorized {
			t.Errorf("anon POST = %d, want 401", w.Code)
		}
	})

	t.Run("unwired store answers 503 behind the session gate", func(t *testing.T) {
		store := newCredStoreStub(nil)
		router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{}, false)

		if w := credRequest(t, router, http.MethodGet, credPathList, rootCookie, ""); w.Code != http.StatusServiceUnavailable {
			t.Errorf("root GET unwired = %d, want 503", w.Code)
		}
		if w := credRequest(t, router, http.MethodGet, credPathList, "", ""); w.Code != http.StatusUnauthorized {
			t.Errorf("anon GET unwired = %d, want 401 (gate runs before the wiring check)", w.Code)
		}
	})

	t.Run("root CRUDs any org", func(t *testing.T) {
		store := newCredStoreStub(nil)
		router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{}, true)

		w := credRequest(t, router, http.MethodPost, credPathList, rootCookie, credCreateBody("openai", credBaseOK, credKeyOK))
		if w.Code != http.StatusCreated {
			t.Fatalf("root POST = %d, want 201 (body: %s)", w.Code, w.Body.String())
		}
		w = credRequest(t, router, http.MethodGet, credPathList, rootCookie, "")
		if w.Code != http.StatusOK {
			t.Errorf("root GET = %d, want 200", w.Code)
		}
		var list struct {
			Count int `json:"count"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		if list.Count != 1 {
			t.Errorf("count = %d, want 1", list.Count)
		}
	})

	t.Run("member with keys.manage CRUDs the org, without it is 403, non-member 404", func(t *testing.T) {
		newRouter := func(role adminstore.OrgRole) http.Handler {
			store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: role})
			return credRouter(t, store, handlers.OrgCredentialHandlerOptions{}, true)
		}

		router := newRouter(adminstore.RoleOperator)
		w := credRequest(t, router, http.MethodPost, credPathList, credMemberCookie(t), credCreateBody("openai", credBaseOK, credKeyOK))
		if w.Code != http.StatusCreated {
			t.Fatalf("operator POST = %d, want 201 (body: %s)", w.Code, w.Body.String())
		}
		if w := credRequest(t, router, http.MethodGet, credPathList, credMemberCookie(t), ""); w.Code != http.StatusOK {
			t.Errorf("operator GET = %d, want 200", w.Code)
		}

		router = newRouter(adminstore.RoleReader)
		if w := credRequest(t, router, http.MethodGet, credPathList, credMemberCookie(t), ""); w.Code != http.StatusForbidden {
			t.Errorf("reader GET = %d, want 403", w.Code)
		}

		router = newRouter(adminstore.OrgRole("")) // member with an empty/unknown role
		if w := credRequest(t, router, http.MethodGet, credPathList, credMemberCookie(t), ""); w.Code != http.StatusForbidden {
			t.Errorf("empty-role member GET = %d, want 403", w.Code)
		}

		noMember := newCredStoreStub(nil) // no membership on the target org at all
		router = credRouter(t, noMember, handlers.OrgCredentialHandlerOptions{}, true)
		if w := credRequest(t, router, http.MethodGet, credPathList, credMemberCookie(t), ""); w.Code != http.StatusNotFound {
			t.Errorf("non-member GET = %d, want 404 (foreign org invisible)", w.Code)
		}
	})
}

func TestOrgCredentialsMasking(t *testing.T) {
	store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
	router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{}, true)
	cookie := credMemberCookie(t)

	w := credRequest(t, router, http.MethodPost, credPathList, cookie, credCreateBody("openai", credBaseOK, credKeyOK))
	if w.Code != http.StatusCreated {
		t.Fatalf("POST = %d, want 201 (body: %s)", w.Code, w.Body.String())
	}
	var cred handlers.OrgCredential
	if err := json.Unmarshal(w.Body.Bytes(), &cred); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if cred.KeyLast4 != "9876" {
		t.Errorf("key_last4 = %q, want 9876", cred.KeyLast4)
	}
	if strings.Contains(w.Body.String(), credKeyOK) {
		t.Fatal("create response leaks the plaintext key")
	}

	// The list and the update responses mask too.
	w = credRequest(t, router, http.MethodGet, credPathList, cookie, "")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), credKeyOK) {
		t.Fatalf("GET list = %d, plaintext leaked: %v", w.Code, strings.Contains(w.Body.String(), credKeyOK))
	}
	w = credRequest(t, router, http.MethodPut, credPathList+"/"+cred.ID, cookie, `{"name":"renamed"}`)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), credKeyOK) {
		t.Fatalf("PUT rename = %d, plaintext leaked: %v", w.Code, strings.Contains(w.Body.String(), credKeyOK))
	}

	// Rotation: the new plaintext never shows up, the version bumps.
	newKey := "sk-rotated-credential-plaintext-4242"
	w = credRequest(t, router, http.MethodPut, credPathList+"/"+cred.ID, cookie, `{"api_key":"`+newKey+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT rotate = %d (body: %s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), newKey) {
		t.Fatal("rotate response leaks the new plaintext key")
	}
	cred = handlers.OrgCredential{}
	if err := json.Unmarshal(w.Body.Bytes(), &cred); err != nil {
		t.Fatalf("decode rotate: %v", err)
	}
	if cred.KeyLast4 != "4242" || cred.KeyVersion != 2 {
		t.Errorf("after rotate: key_last4=%q key_version=%d, want 4242/2", cred.KeyLast4, cred.KeyVersion)
	}

	// The connection-test response carries no key material either.
	w = credRequest(t, router, http.MethodPost, credPathList+"/"+cred.ID+"/test", cookie, "")
	if strings.Contains(w.Body.String(), newKey) {
		t.Fatal("test response leaks the plaintext key")
	}
}

// TestOrgCredentialVersionBump pins the W-BYOK-CORE invalidation contract:
// every SUCCESSFUL CRUD bumps the org's credential version; a failed bump is
// swallowed (warning only) — staleness is bounded by the gateway's 30s TTL.
func TestOrgCredentialVersionBump(t *testing.T) {
	store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
	bumper := &credBumper{}
	router := credRouterWithBumper(t, store, handlers.OrgCredentialHandlerOptions{}, true, bumper)
	cookie := credMemberCookie(t)

	w := credRequest(t, router, http.MethodPost, credPathList, cookie, credCreateBody("openai", credBaseOK, credKeyOK))
	if w.Code != http.StatusCreated {
		t.Fatalf("POST = %d (body: %s)", w.Code, w.Body.String())
	}
	var cred handlers.OrgCredential
	if err := json.Unmarshal(w.Body.Bytes(), &cred); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	if w := credRequest(t, router, http.MethodPut, credPathList+"/"+cred.ID, cookie, `{"name":"renamed"}`); w.Code != http.StatusOK {
		t.Fatalf("PUT rename = %d (body: %s)", w.Code, w.Body.String())
	}
	if w := credRequest(t, router, http.MethodPut, credPathList+"/"+cred.ID, cookie, `{"api_key":"`+"sk-rotated-credential-plaintext-1111"+`"}`); w.Code != http.StatusOK {
		t.Fatalf("PUT rotate = %d (body: %s)", w.Code, w.Body.String())
	}
	if w := credRequest(t, router, http.MethodDelete, credPathList+"/"+cred.ID, cookie, ""); w.Code != http.StatusOK {
		t.Fatalf("DELETE = %d (body: %s)", w.Code, w.Body.String())
	}

	// Failed CRUDs must NOT bump: a validation 400 and a missing-id PUT stay
	// silent.
	if w := credRequest(t, router, http.MethodPost, credPathList, cookie, credCreateBody("nope", credBaseOK, credKeyOK)); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid POST = %d, want 400", w.Code)
	}
	if w := credRequest(t, router, http.MethodPut, credPathList+"/cred-404", cookie, `{"name":"x"}`); w.Code != http.StatusNotFound {
		t.Fatalf("missing PUT = %d, want 404", w.Code)
	}
	if got := bumper.bumped(); len(got) != 4 {
		t.Fatalf("bumps after create+rename+rotate+delete = %v, want exactly 4 (all org-a)", got)
	}
	for _, org := range bumper.bumped() {
		if org != credOrgA {
			t.Errorf("bump for org %q, want %q", org, credOrgA)
		}
	}

	// A broken version store never fails the CRUD response.
	bumper.fail = true
	w = credRequest(t, router, http.MethodPost, credPathList, cookie, credCreateBodyNamed("second", "openai", credBaseOK, credKeyOK))
	if w.Code != http.StatusCreated {
		t.Fatalf("POST with failing bumper = %d, want 201 (body: %s)", w.Code, w.Body.String())
	}
}

// TestOrgCredentialConflict pins the store's org-unique violation on the
// wire: a duplicate credential name is 409, on create and on rename.
func TestOrgCredentialConflict(t *testing.T) {
	store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
	router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{}, true)
	cookie := credMemberCookie(t)

	if w := credRequest(t, router, http.MethodPost, credPathList, cookie, credCreateBody("openai", credBaseOK, credKeyOK)); w.Code != http.StatusCreated {
		t.Fatalf("first POST = %d (body: %s)", w.Code, w.Body.String())
	}
	w := credRequest(t, router, http.MethodPost, credPathList, cookie, credCreateBody("openai", credBaseOK, credKeyOK))
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate POST = %d, want 409 (body: %s)", w.Code, w.Body.String())
	}

	// Same name in ANOTHER org is fine (org-scoped uniqueness).
	foreign := "/api/orgs/" + credOrgB + "/provider-credentials"
	if w := credRequest(t, router, http.MethodPost, foreign, credRootCookie(t), credCreateBody("openai", credBaseOK, credKeyOK)); w.Code != http.StatusCreated {
		t.Fatalf("foreign-org same-name POST = %d, want 201 (body: %s)", w.Code, w.Body.String())
	}

	// Rename onto the org's other credential is 409 too.
	w = credRequest(t, router, http.MethodPost, credPathList, cookie, credCreateBodyNamed("other", "anthropic", credBaseOK, credKeyOK))
	if w.Code != http.StatusCreated {
		t.Fatalf("second POST = %d (body: %s)", w.Code, w.Body.String())
	}
	var other handlers.OrgCredential
	if err := json.Unmarshal(w.Body.Bytes(), &other); err != nil {
		t.Fatalf("decode second POST: %v", err)
	}
	if w := credRequest(t, router, http.MethodPut, credPathList+"/"+other.ID, cookie, `{"name":"prod key"}`); w.Code != http.StatusConflict {
		t.Fatalf("rename onto taken name = %d, want 409 (body: %s)", w.Code, w.Body.String())
	}
}

func TestOrgCredentialValidation(t *testing.T) {
	store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
	router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{}, true)
	cookie := credMemberCookie(t)

	cases := []struct {
		name string
		body string
		want int
	}{
		{"unknown provider", credCreateBody("not-a-provider", credBaseOK, credKeyOK), http.StatusBadRequest},
		{"empty provider", credCreateBody("", credBaseOK, credKeyOK), http.StatusBadRequest},
		{"key too short", credCreateBody("openai", credBaseOK, "sk-short"), http.StatusBadRequest},
		{"key too long", credCreateBody("openai", credBaseOK, strings.Repeat("k", 5001)), http.StatusBadRequest},
		{"http hostname rejected", credCreateBody("openai", "http://api.openai.com/v1", credKeyOK), http.StatusBadRequest},
		{"http private IP without flag", credCreateBody("openai", "http://10.1.2.3:8000/v1", credKeyOK), http.StatusBadRequest},
		{"ftp scheme rejected", credCreateBody("openai", "ftp://api.openai.com", credKeyOK), http.StatusBadRequest},
		{"userinfo rejected", credCreateBody("openai", "https://user:pass@api.openai.com", credKeyOK), http.StatusBadRequest},
		{"empty base_url", credCreateBody("openai", "", credKeyOK), http.StatusBadRequest},
		{"unknown field", `{"name":"n","provider":"openai","base_url":"` + credBaseOK + `","api_key":"` + credKeyOK + `","extra":1}`, http.StatusBadRequest},
		{"empty name", credCreateBodyNamed("", "openai", credBaseOK, credKeyOK), http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := credRequest(t, router, http.MethodPost, credPathList, cookie, tc.body)
			if w.Code != tc.want {
				t.Errorf("POST = %d, want %d (body: %s)", w.Code, tc.want, w.Body.String())
			}
		})
	}

	t.Run("oversized body is 400", func(t *testing.T) {
		big := `{"name":"` + strings.Repeat("x", 40*1024) + `"}`
		if w := credRequest(t, router, http.MethodPost, credPathList, cookie, big); w.Code != http.StatusBadRequest {
			t.Errorf("oversized POST = %d, want 400", w.Code)
		}
	})

	t.Run("boundary key lengths accepted", func(t *testing.T) {
		if w := credRequest(t, router, http.MethodPost, credPathList, cookie, credCreateBodyNamed("short key", "openai", credBaseOK, strings.Repeat("k", 20))); w.Code != http.StatusCreated {
			t.Errorf("20-char key = %d, want 201", w.Code)
		}
		if w := credRequest(t, router, http.MethodPost, credPathList, cookie, credCreateBodyNamed("long key", "openai", credBaseOK, strings.Repeat("k", 5000))); w.Code != http.StatusCreated {
			t.Errorf("5000-char key = %d, want 201", w.Code)
		}
	})

	t.Run("http private IP accepted behind the flag", func(t *testing.T) {
		flagged := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		flaggedRouter := credRouter(t, flagged, handlers.OrgCredentialHandlerOptions{AllowHTTPPrivate: true}, true)
		w := credRequest(t, flaggedRouter, http.MethodPost, credPathList, cookie, credCreateBody("openai", "http://10.1.2.3:8000/v1", credKeyOK))
		if w.Code != http.StatusCreated {
			t.Errorf("flagged http private = %d, want 201 (body: %s)", w.Code, w.Body.String())
		}
	})

	t.Run("cross-org credId is 404", func(t *testing.T) {
		foreign := store.seed(credOrgB, credBaseOK)
		// Root targets org-a: a cred of org-b does not exist in that namespace.
		if w := credRequest(t, router, http.MethodDelete, credPathList+"/"+foreign.ID, credRootCookie(t), ""); w.Code != http.StatusNotFound {
			t.Errorf("root DELETE foreign cred = %d, want 404", w.Code)
		}
		// A member of org-a gets the same 404 (the row is never revealed).
		if w := credRequest(t, router, http.MethodPut, credPathList+"/"+foreign.ID, cookie, `{"name":"x"}`); w.Code != http.StatusNotFound {
			t.Errorf("member PUT foreign cred = %d, want 404", w.Code)
		}
	})
}

func TestOrgCredentialTestEndpoint(t *testing.T) {
	newUpstream := func(t *testing.T, status int) (*httptest.Server, *string) {
		t.Helper()
		var gotAuth string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			if r.URL.Path != "/v1/models" {
				t.Errorf("upstream path = %q, want /v1/models", r.URL.Path)
			}
			w.WriteHeader(status)
		}))
		t.Cleanup(srv.Close)
		return srv, &gotAuth
	}

	t.Run("ok path sends the key once and reports {ok,status}", func(t *testing.T) {
		srv, gotAuth := newUpstream(t, http.StatusOK)
		store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		cred := store.seed(credOrgA, srv.URL+"/v1")
		router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: srv.Client()}, true)

		w := credRequest(t, router, http.MethodPost, credPathList+"/"+cred.ID+"/test", credMemberCookie(t), "")
		if w.Code != http.StatusOK {
			t.Fatalf("test = %d (body: %s)", w.Code, w.Body.String())
		}
		var res struct {
			OK     bool   `json:"ok"`
			Status int    `json:"status"`
			Error  string `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode result: %v", err)
		}
		if !res.OK || res.Status != http.StatusOK || res.Error != "" {
			t.Errorf("result = %+v, want ok=true status=200", res)
		}
		if *gotAuth != "Bearer "+credKeyOK {
			t.Errorf("upstream Authorization = %q, want the stored key as bearer", *gotAuth)
		}
	})

	t.Run("upstream rejection reports {ok:false,status}", func(t *testing.T) {
		srv, _ := newUpstream(t, http.StatusUnauthorized)
		store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		cred := store.seed(credOrgA, srv.URL+"/v1")
		router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: srv.Client()}, true)

		w := credRequest(t, router, http.MethodPost, credPathList+"/"+cred.ID+"/test", credMemberCookie(t), "")
		var res struct {
			OK     bool   `json:"ok"`
			Status int    `json:"status"`
			Error  string `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode result: %v", err)
		}
		if res.OK || res.Status != http.StatusUnauthorized || res.Error == "" {
			t.Errorf("result = %+v, want ok=false status=401 error set", res)
		}
	})

	t.Run("rate limit is 1 per minute per org", func(t *testing.T) {
		srv, _ := newUpstream(t, http.StatusOK)
		store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		credA := store.seed(credOrgA, srv.URL+"/v1")
		router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: srv.Client()}, true)
		cookie := credMemberCookie(t)

		if w := credRequest(t, router, http.MethodPost, credPathList+"/"+credA.ID+"/test", cookie, ""); w.Code != http.StatusOK {
			t.Fatalf("first test = %d, want 200", w.Code)
		}
		if w := credRequest(t, router, http.MethodPost, credPathList+"/"+credA.ID+"/test", cookie, ""); w.Code != http.StatusTooManyRequests {
			t.Errorf("second test = %d, want 429", w.Code)
		}
		// The throttle is per org: another org still gets through (root view).
		credB := store.seed(credOrgB, srv.URL+"/v1")
		if w := credRequest(t, router, http.MethodPost, "/api/orgs/"+credOrgB+"/provider-credentials/"+credB.ID+"/test", credRootCookie(t), ""); w.Code != http.StatusOK {
			t.Errorf("other-org test = %d, want 200", w.Code)
		}
	})

	t.Run("default client refuses loopback upstreams (SSRF guard on)", func(t *testing.T) {
		srv, _ := newUpstream(t, http.StatusOK)
		store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		cred := store.seed(credOrgA, srv.URL) // http://127.0.0.1:port — reserved
		// No HTTPClient override: the production guarded client must refuse
		// the reserved target before any bytes leave.
		router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{}, true)

		w := credRequest(t, router, http.MethodPost, credPathList+"/"+cred.ID+"/test", credMemberCookie(t), "")
		if w.Code != http.StatusOK {
			t.Fatalf("test = %d, want 200 (result payload reports the refusal)", w.Code)
		}
		var res struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode result: %v", err)
		}
		if res.OK {
			t.Fatal("guarded client reached a loopback upstream")
		}
		if res.Error == "" {
			t.Fatal("refusal carries no error text")
		}
	})
}

// (POST …/{credId}/models): the stored key is resolved server-side and sent
// upstream exactly once as a Bearer header, the OpenAI-compat {data[].id}
// body is parsed into a display-only snapshot (discovered=true,
// verified=false — discovery is NOT verified usability), and every failure
// is a machine-readable reason derived only from the upstream status/parse
// outcome. Zero key material may reach any response body.
func TestOrgCredentialModelsEndpoint(t *testing.T) {
	// newUpstreamCatalog serves handler at {srv}/v1/models and records every
	// request (count + Authorization header) for the leak/observability pins.
	newUpstreamCatalog := func(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, *int, *string) {
		t.Helper()
		var mu sync.Mutex
		hits := 0
		var gotAuth string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits++
			gotAuth = r.Header.Get("Authorization")
			mu.Unlock()
			if r.URL.Path != "/v1/models" {
				t.Errorf("upstream path = %q, want /v1/models", r.URL.Path)
			}
			handler(w, r)
		}))
		t.Cleanup(srv.Close)
		return srv, &hits, &gotAuth
	}
	catalogHandler := func(status int, body string) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}
	}
	// modelsRequest posts the discovery route and asserts the session gate
	// shape, returning the recorder.
	modelsRequest := func(t *testing.T, router http.Handler, credID, cookie string) *httptest.ResponseRecorder {
		t.Helper()
		return credRequest(t, router, http.MethodPost, credPathList+"/"+credID+"/models", cookie, "")
	}
	// noKey asserts the zero-key-material invariant on any response.
	noKey := func(t *testing.T, w *httptest.ResponseRecorder) {
		t.Helper()
		if strings.Contains(w.Body.String(), credKeyOK) {
			t.Fatalf("response leaks the plaintext key: %s", w.Body.String())
		}
	}

	t.Run("ok path parses the catalog once with the stored key as bearer", func(t *testing.T) {
		srv, hits, gotAuth := newUpstreamCatalog(t, catalogHandler(http.StatusOK,
			`{"object":"list","data":[{"id":"example-large","object":"model"},{"id":"example-mini","object":"model"}]}`))
		store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		cred := store.seed(credOrgA, srv.URL+"/v1")
		router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: srv.Client()}, true)

		w := modelsRequest(t, router, cred.ID, credMemberCookie(t))
		if w.Code != http.StatusOK {
			t.Fatalf("models = %d (body: %s)", w.Code, w.Body.String())
		}
		noKey(t, w)
		var res struct {
			Provider   string   `json:"provider"`
			BaseURL    string   `json:"base_url"`
			Count      int      `json:"count"`
			Data       []string `json:"data"`
			Discovered bool     `json:"discovered"`
			Verified   *bool    `json:"verified"`
			Reason     string   `json:"reason"`
			Status     int      `json:"status"`
			Error      string   `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode catalog: %v", err)
		}
		if !res.Discovered || res.Reason != "" || res.Error != "" || res.Status != 0 {
			t.Errorf("result = %+v, want a clean discovery snapshot", res)
		}
		if res.Verified == nil || *res.Verified {
			t.Errorf("verified = %v, want an explicit false (discovery is not verified usability)", res.Verified)
		}
		if res.Count != 2 || len(res.Data) != 2 || res.Data[0] != "example-large" || res.Data[1] != "example-mini" {
			t.Errorf("catalog = %v (count %d), want [example-large example-mini]", res.Data, res.Count)
		}
		if res.Provider != "openai" || res.BaseURL != srv.URL+"/v1" {
			t.Errorf("provider/base_url = %q/%q, want openai/%s", res.Provider, res.BaseURL, srv.URL+"/v1")
		}
		if *hits != 1 {
			t.Errorf("upstream hits = %d, want exactly 1", *hits)
		}
		if *gotAuth != "Bearer "+credKeyOK {
			t.Errorf("upstream Authorization = %q, want the stored key as bearer", *gotAuth)
		}
	})

	t.Run("upstream refusals are diagnosable reasons, derived from status only", func(t *testing.T) {
		cases := []struct {
			name       string
			status     int
			wantReason string
		}{
			{"no list API (404)", http.StatusNotFound, "models_list_unavailable"},
			{"key without list permission (403)", http.StatusForbidden, "key_forbidden"},
			{"revoked key (401)", http.StatusUnauthorized, "key_unauthorized"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				srv, hits, _ := newUpstreamCatalog(t, catalogHandler(tc.status, `{"error":{"message":"upstream detail"}}`))
				store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
				cred := store.seed(credOrgA, srv.URL+"/v1")
				router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: srv.Client()}, true)

				w := modelsRequest(t, router, cred.ID, credMemberCookie(t))
				// The refusal is a state of the key/list-API, not a failed
				// admin-API call: HTTP 200 with a machine-readable reason.
				if w.Code != http.StatusOK {
					t.Fatalf("models = %d, want 200 (body: %s)", w.Code, w.Body.String())
				}
				noKey(t, w)
				var res struct {
					Count      int    `json:"count"`
					Discovered bool   `json:"discovered"`
					Data       []any  `json:"data"`
					Reason     string `json:"reason"`
					Status     int    `json:"status"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
					t.Fatalf("decode refusal: %v", err)
				}
				if res.Discovered || res.Count != 0 || res.Data != nil {
					t.Errorf("refusal = %+v, want no catalog data", res)
				}
				if res.Reason != tc.wantReason || res.Status != tc.status {
					t.Errorf("reason/status = %q/%d, want %q/%d", res.Reason, res.Status, tc.wantReason, tc.status)
				}
				// The upstream body is never echoed.
				if strings.Contains(w.Body.String(), "upstream detail") {
					t.Error("refusal echoes the upstream body")
				}
				if *hits != 1 {
					t.Errorf("upstream hits = %d, want exactly 1", *hits)
				}
			})
		}
	})

	t.Run("non-JSON 200 is never a success (parse fail = models_list_unavailable)", func(t *testing.T) {
		srv, _, _ := newUpstreamCatalog(t, catalogHandler(http.StatusOK, "<html>no list api here</html>"))
		store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		cred := store.seed(credOrgA, srv.URL+"/v1")
		router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: srv.Client()}, true)

		w := modelsRequest(t, router, cred.ID, credMemberCookie(t))
		noKey(t, w)
		var res struct {
			Discovered bool   `json:"discovered"`
			Reason     string `json:"reason"`
			Status     int    `json:"status"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if res.Discovered || res.Reason != "models_list_unavailable" || res.Status != http.StatusOK {
			t.Errorf("result = %+v, want models_list_unavailable with status 200", res)
		}
	})

	t.Run("catalog body over the 1 MiB parse cap is a refusal, not a partial success", func(t *testing.T) {
		big := `{"object":"list","data":[{"id":"` + strings.Repeat("m", 1024*1024+16) + `"}]}`
		srv, _, _ := newUpstreamCatalog(t, catalogHandler(http.StatusOK, big))
		store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		cred := store.seed(credOrgA, srv.URL+"/v1")
		router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: srv.Client()}, true)

		w := modelsRequest(t, router, cred.ID, credMemberCookie(t))
		noKey(t, w)
		var res struct {
			Discovered bool   `json:"discovered"`
			Reason     string `json:"reason"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if res.Discovered || res.Reason != "models_list_unavailable" {
			t.Errorf("result = %+v, want a models_list_unavailable refusal", res)
		}
	})

	t.Run("stored key resolution fails → key_unavailable (no upstream call)", func(t *testing.T) {
		srv, hits, _ := newUpstreamCatalog(t, catalogHandler(http.StatusOK, `{"data":[]}`))
		store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		cred := store.seed(credOrgA, srv.URL+"/v1")
		// Simulate the real store's ok=false (e.g. the credential is
		// disabled): no enabled key resolves for this row.
		store.keys[cred.ID] = ""
		router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: srv.Client()}, true)

		w := modelsRequest(t, router, cred.ID, credMemberCookie(t))
		if w.Code != http.StatusOK {
			t.Fatalf("models = %d (body: %s)", w.Code, w.Body.String())
		}
		noKey(t, w)
		var res struct {
			Reason string `json:"reason"`
			Count  int    `json:"count"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if res.Reason != "key_unavailable" || res.Count != 0 {
			t.Errorf("result = %+v, want key_unavailable with count 0", res)
		}
		if *hits != 0 {
			t.Errorf("upstream hits = %d, want 0 (nothing to authenticate with)", *hits)
		}
	})

	t.Run("empty catalog is a success with an empty snapshot", func(t *testing.T) {
		srv, _, _ := newUpstreamCatalog(t, catalogHandler(http.StatusOK, `{"object":"list","data":[]}`))
		store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		cred := store.seed(credOrgA, srv.URL+"/v1")
		router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: srv.Client()}, true)

		w := modelsRequest(t, router, cred.ID, credMemberCookie(t))
		noKey(t, w)
		var res struct {
			Discovered bool `json:"discovered"`
			Count      int  `json:"count"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !res.Discovered || res.Count != 0 {
			t.Errorf("result = %+v, want discovered=true count=0", res)
		}
	})

	t.Run("throttle is shared with /test (1 per minute per org)", func(t *testing.T) {
		srv, _, _ := newUpstreamCatalog(t, catalogHandler(http.StatusOK, `{"data":[]}`))
		store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		cred := store.seed(credOrgA, srv.URL+"/v1")
		router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: srv.Client()}, true)
		cookie := credMemberCookie(t)

		if w := modelsRequest(t, router, cred.ID, cookie); w.Code != http.StatusOK {
			t.Fatalf("first models = %d, want 200", w.Code)
		}
		// D-4 default: one budget for both surfaces — /test is now throttled
		// out by the discovery call.
		if w := credRequest(t, router, http.MethodPost, credPathList+"/"+cred.ID+"/test", cookie, ""); w.Code != http.StatusTooManyRequests {
			t.Errorf("test after models = %d, want 429", w.Code)
		}
		if w := modelsRequest(t, router, cred.ID, cookie); w.Code != http.StatusTooManyRequests {
			t.Errorf("second models = %d, want 429", w.Code)
		}
	})

	t.Run("default client refuses loopback upstreams (SSRF guard on)", func(t *testing.T) {
		srv, hits, _ := newUpstreamCatalog(t, catalogHandler(http.StatusOK, `{"data":[]}`))
		store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		cred := store.seed(credOrgA, srv.URL) // http://127.0.0.1:port — reserved
		// No HTTPClient override: the production guarded client must refuse
		// the reserved target before any bytes (and the key) leave.
		router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{}, true)

		w := modelsRequest(t, router, cred.ID, credMemberCookie(t))
		if w.Code != http.StatusOK {
			t.Fatalf("models = %d, want 200 (result payload reports the refusal)", w.Code)
		}
		noKey(t, w)
		var res struct {
			Discovered bool   `json:"discovered"`
			Reason     string `json:"reason"`
			Error      string `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if res.Discovered || res.Reason != "transport_error" || res.Error == "" {
			t.Errorf("result = %+v, want transport_error with sanitized error text", res)
		}
		if *hits != 0 {
			t.Errorf("upstream hits = %d, want 0 (guarded client refused before dialing)", *hits)
		}
	})

	t.Run("gate and wiring parity with the credential surface", func(t *testing.T) {
		srv, _, _ := newUpstreamCatalog(t, catalogHandler(http.StatusOK, `{"data":[]}`))
		store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleReader, credOrgB: adminstore.RoleOrgAdmin})
		foreign := store.seed(credOrgB, srv.URL+"/v1")
		own := store.seed(credOrgA, srv.URL+"/v1")

		router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: srv.Client()}, true)
		// anon → 401 (session boundary).
		if w := modelsRequest(t, router, own.ID, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("anon models = %d, want 401", w.Code)
		}
		// member without keys.manage → 403.
		if w := modelsRequest(t, router, own.ID, credMemberCookie(t)); w.Code != http.StatusForbidden {
			t.Errorf("reader models = %d, want 403", w.Code)
		}
		// cross-org credId → 404 (resourceHidden; root targets org-a).
		w := credRequest(t, router, http.MethodPost, credPathList+"/"+foreign.ID+"/models", credRootCookie(t), "")
		if w.Code != http.StatusNotFound {
			t.Errorf("foreign credId models = %d, want 404", w.Code)
		}
		noKey(t, w)

		// unwired store → 503 behind the session gate.
		unwired := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		unwiredRouter := credRouter(t, unwired, handlers.OrgCredentialHandlerOptions{}, false)
		if w := modelsRequest(t, unwiredRouter, "cred-1", credRootCookie(t)); w.Code != http.StatusServiceUnavailable {
			t.Errorf("unwired models = %d, want 503", w.Code)
		}
	})
}

// compile-time guard: the stub satisfies the frozen contract exactly.
var _ handlers.OrgCredentialStore = (*credStoreStub)(nil)

// modelsBodyOfSize builds a valid {data:[{id:…}]} wire body of exactly size
// bytes (the pad rides an extra field the parser ignores) so the 1 MiB cap
// boundary can be probed byte-exactly through the full router.
func modelsBodyOfSize(t *testing.T, size int) string {
	t.Helper()
	const prefix = `{"object":"list","data":[{"id":"cap-model","pad":"`
	const suffix = `"}]}`
	if size < len(prefix)+len(suffix) {
		t.Fatalf("modelsBodyOfSize: size %d below the minimum %d", size, len(prefix)+len(suffix))
	}
	body := prefix + strings.Repeat("p", size-len(prefix)-len(suffix)) + suffix
	if len(body) != size {
		t.Fatalf("modelsBodyOfSize: built %d bytes, want %d", len(body), size)
	}
	return body
}

// abortProbeTransport lets the probe start, then aborts it mid-flight and
// reports context.Canceled — the exact error the real client surfaces when
// the request context is canceled (operator closed the tab, proxy dropped).
// The abort is signaled from the test so ServeHTTP stays synchronous: the
// admin router's timeout middleware abandons (does not wait for) the handler
// goroutine once the request context dies, so a real cancel there would race
// the recorder read instead of the handler.
type abortProbeTransport struct {
	started chan struct{}
	abort   chan struct{}
}

func (a *abortProbeTransport) RoundTrip(*http.Request) (*http.Response, error) {
	close(a.started)
	<-a.abort
	return nil, context.Canceled
}

// catalogWire mirrors credCatalogResult as the tests read it off the wire.
type catalogWire struct {
	Discovered bool   `json:"discovered"`
	Count      int    `json:"count"`
	Reason     string `json:"reason"`
	Status     int    `json:"status"`
	Error      string `json:"error"`
}

// boundary matrix on the wire: truncation and malformed catalogs never read
// as success and never echo upstream content, the 1 MiB cap is byte-exact,
// a repeated call is a diagnosable 429, foreign tenants and bad ids get
// zero upstream traffic, and a mid-probe cancellation is a transport_error —
// every one of them display-only (nothing persisted, no bump, no key leak).
func TestOrgCredentialModelsEndpointBoundaries(t *testing.T) {
	modelsRequest := func(t *testing.T, router http.Handler, credID, cookie string) *httptest.ResponseRecorder {
		t.Helper()
		return credRequest(t, router, http.MethodPost, credPathList+"/"+credID+"/models", cookie, "")
	}
	noKey := func(t *testing.T, w *httptest.ResponseRecorder) {
		t.Helper()
		if strings.Contains(w.Body.String(), credKeyOK) {
			t.Fatalf("response leaks the plaintext key: %s", w.Body.String())
		}
	}
	newUpstream := func(t *testing.T, body string) (*httptest.Server, *int) {
		t.Helper()
		var mu sync.Mutex
		hits := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits++
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return srv, &hits
	}
	decode := func(t *testing.T, w *httptest.ResponseRecorder) catalogWire {
		t.Helper()
		var res catalogWire
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode body %s: %v", w.Body.String(), err)
		}
		return res
	}

	t.Run("truncated upstream catalog never reads as success nor leaks ids", func(t *testing.T) {
		// A upstream that dies mid-body: valid JSON prefix, cut inside the
		// second record — well under the cap, so only the parse can save us.
		srv, hits := newUpstream(t, `{"object":"list","data":[{"id":"visible-a"},{"id":"cut-mid`)
		store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		cred := store.seed(credOrgA, srv.URL+"/v1")
		router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: srv.Client()}, true)

		w := modelsRequest(t, router, cred.ID, credMemberCookie(t))
		if w.Code != http.StatusOK {
			t.Fatalf("models = %d (body: %s)", w.Code, w.Body.String())
		}
		noKey(t, w)
		res := decode(t, w)
		if res.Discovered || res.Reason != "models_list_unavailable" || res.Count != 0 || res.Status != http.StatusOK {
			t.Errorf("result = %+v, want models_list_unavailable with status 200", res)
		}
		// Neither the complete nor the truncated id may be echoed back.
		if strings.Contains(w.Body.String(), "visible-a") || strings.Contains(w.Body.String(), "cut-mid") {
			t.Errorf("refusal echoes upstream content: %s", w.Body.String())
		}
		if *hits != 1 {
			t.Errorf("upstream hits = %d, want exactly 1", *hits)
		}
	})

	t.Run("catalog body exactly at the 1 MiB cap parses through the wire", func(t *testing.T) {
		srv, hits := newUpstream(t, modelsBodyOfSize(t, 1024*1024))
		store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		cred := store.seed(credOrgA, srv.URL+"/v1")
		router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: srv.Client()}, true)

		w := modelsRequest(t, router, cred.ID, credMemberCookie(t))
		if w.Code != http.StatusOK {
			t.Fatalf("models = %d (body: %s)", w.Code, w.Body.String())
		}
		noKey(t, w)
		res := decode(t, w)
		if !res.Discovered || res.Reason != "" || res.Count != 1 {
			t.Errorf("result = %+v, want a snapshot with the single cap-model entry", res)
		}
		var snap struct {
			Data     []string `json:"data"`
			Verified *bool    `json:"verified"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &snap); err != nil {
			t.Fatalf("decode snapshot: %v", err)
		}
		if len(snap.Data) != 1 || snap.Data[0] != "cap-model" {
			t.Errorf("data = %v, want [cap-model]", snap.Data)
		}
		if snap.Verified == nil || *snap.Verified {
			t.Errorf("verified = %v, want an explicit false (display-only snapshot)", snap.Verified)
		}
		if *hits != 1 {
			t.Errorf("upstream hits = %d, want exactly 1", *hits)
		}
	})

	t.Run("malformed entries refuse and persist nothing (display-only posture)", func(t *testing.T) {
		srv, hits := newUpstream(t, `{"data":[{"object":"model"},{"id":"real-one"},{"id":123}]}`)
		store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		bumper := &credBumper{}
		router := credRouterWithBumper(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: srv.Client()}, true, bumper)
		cred := store.seed(credOrgA, srv.URL+"/v1")
		rowsBefore := len(store.creds)

		w := modelsRequest(t, router, cred.ID, credMemberCookie(t))
		if w.Code != http.StatusOK {
			t.Fatalf("models = %d (body: %s)", w.Code, w.Body.String())
		}
		noKey(t, w)
		res := decode(t, w)
		if res.Discovered || res.Reason != "models_list_unavailable" || res.Count != 0 {
			t.Errorf("result = %+v, want a refusal — the entry before the bad one is not a partial success", res)
		}
		if strings.Contains(w.Body.String(), "real-one") {
			t.Errorf("refusal echoes upstream content: %s", w.Body.String())
		}
		// Display-only (D-3): no store row, key, or version bump may change.
		if len(store.creds) != rowsBefore || store.keys[cred.ID] != credKeyOK {
			t.Errorf("store mutated by a refused discovery: rows=%d key=%q", len(store.creds), store.keys[cred.ID])
		}
		if bumped := bumper.bumped(); len(bumped) != 0 {
			t.Errorf("version bumps = %v, want none (discovery is not a CRUD)", bumped)
		}
		if *hits != 1 {
			t.Errorf("upstream hits = %d, want exactly 1", *hits)
		}
	})

	t.Run("repeat within the window is a diagnosable 429, never a success", func(t *testing.T) {
		srv, hits := newUpstream(t, `{"object":"list","data":[]}`)
		store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		cred := store.seed(credOrgA, srv.URL+"/v1")
		router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: srv.Client()}, true)
		cookie := credMemberCookie(t)

		if w := modelsRequest(t, router, cred.ID, cookie); w.Code != http.StatusOK {
			t.Fatalf("first models = %d (body: %s)", w.Code, w.Body.String())
		}
		w := modelsRequest(t, router, cred.ID, cookie)
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("second models = %d, want 429 (body: %s)", w.Code, w.Body.String())
		}
		noKey(t, w)
		res := decode(t, w)
		if res.Discovered || res.Reason != "" || res.Count != 0 {
			t.Errorf("429 body = %+v, want no catalog payload (a throttle is not a refusal snapshot)", res)
		}
		if res.Error == "" || !strings.Contains(res.Error, "rate limit") {
			t.Errorf("429 error text = %q, want a diagnosable rate-limit reason", res.Error)
		}
		if *hits != 1 {
			t.Errorf("upstream hits = %d, want exactly 1 (the repeat never dials)", *hits)
		}
	})

	t.Run("foreign tenants and bad ids are diagnosable with zero upstream traffic", func(t *testing.T) {
		// One upstream for every router: the total hit count must stay 0 —
		// none of these refusals may ever reach a provider.
		srv, hits := newUpstream(t, `{"object":"list","data":[]}`)
		refusalShape := func(t *testing.T, w *httptest.ResponseRecorder, wantCode int, wantErrFragment string) {
			t.Helper()
			if w.Code != wantCode {
				t.Fatalf("code = %d, want %d (body: %s)", w.Code, wantCode, w.Body.String())
			}
			noKey(t, w)
			if strings.Contains(w.Body.String(), "discovered") || strings.Contains(w.Body.String(), `"data"`) {
				t.Errorf("refusal body carries a catalog payload: %s", w.Body.String())
			}
			var api struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &api); err != nil {
				t.Fatalf("decode refusal %s: %v", w.Body.String(), err)
			}
			if !strings.Contains(api.Error, wantErrFragment) {
				t.Errorf("error = %q, want it to mention %q (diagnosable)", api.Error, wantErrFragment)
			}
		}

		// A member with keys.manage in org-b only: org-a is invisible → 404.
		foreign := newCredStoreStub(map[string]adminstore.OrgRole{credOrgB: adminstore.RoleOrgAdmin})
		hiddenCred := foreign.seed(credOrgA, srv.URL+"/v1")
		foreignRouter := credRouter(t, foreign, handlers.OrgCredentialHandlerOptions{HTTPClient: srv.Client()}, true)
		refusalShape(t, modelsRequest(t, foreignRouter, hiddenCred.ID, credMemberCookie(t)),
			http.StatusNotFound, "not found")

		// A reader of org-a (no keys.manage) → 403, own cred, upstream 0.
		reader := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleReader})
		ownCred := reader.seed(credOrgA, srv.URL+"/v1")
		readerRouter := credRouter(t, reader, handlers.OrgCredentialHandlerOptions{HTTPClient: srv.Client()}, true)
		refusalShape(t, modelsRequest(t, readerRouter, ownCred.ID, credMemberCookie(t)),
			http.StatusForbidden, "insufficient permission")

		// An org-a admin aiming at org-b's credId under the org-a path → 404
		// (cross-org resource ids stay invisible).
		mixed := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin, credOrgB: adminstore.RoleOrgAdmin})
		foreignCred := mixed.seed(credOrgB, srv.URL+"/v1")
		_ = mixed.seed(credOrgA, srv.URL+"/v1")
		mixedRouter := credRouter(t, mixed, handlers.OrgCredentialHandlerOptions{HTTPClient: srv.Client()}, true)
		refusalShape(t, modelsRequest(t, mixedRouter, foreignCred.ID, credMemberCookie(t)),
			http.StatusNotFound, "not found")

		// Invalid input: an unknown own-org credId → the same 404. The probe
		// budget is spent even on the 404 (throttle runs before the lookup),
		// so this gets its own router — and the immediate repeat is 429: an
		// unknown credId must not become a free prober.
		fresh := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		_ = fresh.seed(credOrgA, srv.URL+"/v1")
		freshRouter := credRouter(t, fresh, handlers.OrgCredentialHandlerOptions{HTTPClient: srv.Client()}, true)
		refusalShape(t, modelsRequest(t, freshRouter, "cred-does-not-exist", credMemberCookie(t)),
			http.StatusNotFound, "not found")
		if w := modelsRequest(t, freshRouter, "cred-does-not-exist", credMemberCookie(t)); w.Code != http.StatusTooManyRequests {
			t.Errorf("repeat on unknown credId = %d, want 429 (not a free prober)", w.Code)
		}

		if *hits != 0 {
			t.Errorf("upstream hits = %d, want 0 (authorization refusals never touch the provider)", *hits)
		}
	})

	t.Run("cancellation mid-probe is a transport_error, never a success", func(t *testing.T) {
		srv, hits := newUpstream(t, `{"object":"list","data":[]}`)
		store := newCredStoreStub(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		cred := store.seed(credOrgA, srv.URL+"/v1")
		transport := &abortProbeTransport{started: make(chan struct{}), abort: make(chan struct{})}
		router := credRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: &http.Client{Transport: transport}}, true)

		go func() {
			<-transport.started
			close(transport.abort)
		}()
		w := modelsRequest(t, router, cred.ID, credMemberCookie(t))

		if w.Code != http.StatusOK {
			t.Fatalf("models = %d (body: %s)", w.Code, w.Body.String())
		}
		noKey(t, w)
		res := decode(t, w)
		if res.Discovered || res.Reason != "transport_error" {
			t.Errorf("result = %+v, want a transport_error refusal (an aborted probe is never a snapshot)", res)
		}
		if !strings.Contains(res.Error, "context canceled") {
			t.Errorf("error = %q, want the cancellation reason (sanitized, truncated)", res.Error)
		}
		if *hits != 0 {
			t.Errorf("upstream hits = %d, want 0 (the probe was aborted before a response)", *hits)
		}
	})
}
