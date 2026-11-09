package handlers_test

// OP-0b: routing contract for the policy pipeline surface, asserted through
// the FULL SetupRouter (session auth + CSRF chain, exactly like
// org_credentials_test.go): the org-permission gate lives in the mount, the
// resource rules live in the handlers —
//
//	anon                          → 401 (session boundary)
//	root                          → 200/201 (any org)
//	member with policies.manage   → 200/201 (org-admin holds it)
//	member without the permission → 403 (operator/reader)
//	no membership                 → 404 (the org stays invisible —
//	                                 resourceHidden semantics)
//	cross-org policyId            → 404 (org-scoped lookup; never revealed)
//	store not wired               → 503 (routes stay mounted unwired)
//
// Validation boundary: YAML is checked SYNTACTICALLY here (minimal header
// struct); full compilation happens gateway-side at load (OP-8) — the tests
// pin that a schema-plausible document stores fine and the shallow gate
// rejects malformed ones.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

const (
	polSecret   = "test-session-secret" // #nosec G101 -- test-only HMAC key
	polCSRF     = "csrf-token-value"    // #nosec G101 -- test-only value
	polOrgA     = "org-a"
	polOrgB     = "org-foreign"
	polPathBase = "/api/organizations/" + polOrgA + "/policies"
	// polYAMLOK is STRICT-schema valid (owner decision 2026-11-04 (a)): the
	// save gate runs pkg/pipeline.ParsePolicy + Validate, so the fixture
	// carries mode and hooks — exactly what the gateway compiles.
	polYAMLOK      = "apiVersion: ypp/v1\nkind: Policy\nname: t\nmode: shadow\nhooks: [pre_upstream]\nsteps:\n  - id: s\n    detector: builtin/secrets\n"
	polYAMLNoKind  = "apiVersion: ypp/v1\nname: t\nmode: shadow\nhooks: [pre_upstream]\nsteps:\n  - id: s\n"
	polYAMLNoSteps = "apiVersion: ypp/v1\nkind: Policy\nname: t\nmode: shadow\nhooks: [pre_upstream]\n"
)

// policyStoreStub implements the handlers.PolicyPipelineStore contract over
// in-memory maps, plus the membership lookup the session chain needs. The
// stub mimics the store-side org-unique name rule (a 23505 PgError the
// handler maps to 409). Tests run sequentially.
type policyStoreStub struct {
	stubStore
	roles    map[string]adminstore.OrgRole
	policies map[string]adminstore.PolicyPipeline
	versions map[string][]adminstore.PolicyVersion // policyID → versions
	atts     map[string][]adminstore.PolicyAttachment
	seq      int
}

func newPolicyStoreStub(roles map[string]adminstore.OrgRole) *policyStoreStub {
	return &policyStoreStub{
		roles:    roles,
		policies: map[string]adminstore.PolicyPipeline{},
		versions: map[string][]adminstore.PolicyVersion{},
		atts:     map[string][]adminstore.PolicyAttachment{},
	}
}

func (s *policyStoreStub) GetUserOrgRoles(context.Context, string) (map[string]adminstore.OrgRole, error) {
	return s.roles, nil
}

func (s *policyStoreStub) nameTaken(orgID, name string) bool {
	for _, p := range s.policies {
		if p.OrgID == orgID && p.Name == name {
			return true
		}
	}
	return false
}

func (s *policyStoreStub) dupNameErr(name string) error {
	return fmt.Errorf("policy name %q already exists in this org: %w",
		name, &pgconn.PgError{Code: "23505", Message: "duplicate key"})
}

func (s *policyStoreStub) CreatePolicy(_ context.Context, orgID, name, yamlDoc, gitSHA, createdBy string) (adminstore.PolicyPipeline, adminstore.PolicyVersion, error) {
	if s.nameTaken(orgID, name) {
		return adminstore.PolicyPipeline{}, adminstore.PolicyVersion{}, s.dupNameErr(name)
	}
	s.seq++
	id := fmt.Sprintf("pol-%d", s.seq)
	p := adminstore.PolicyPipeline{
		ID: id, OrgID: orgID, Name: name, Enabled: false, CurrentVersion: 0,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	s.policies[id] = p
	v := adminstore.PolicyVersion{
		ID: id + "-v1", PolicyID: id, OrgID: orgID, Version: 1,
		YAML: yamlDoc, GitSHA: gitSHA, Label: adminstore.PolicyLabelDraft,
		CreatedBy: createdBy, CreatedAt: time.Now(),
	}
	s.versions[id] = []adminstore.PolicyVersion{v}
	return p, v, nil
}

func (s *policyStoreStub) GetPolicy(_ context.Context, orgID, policyID string) (adminstore.PolicyPipeline, error) {
	p, ok := s.policies[policyID]
	if !ok || p.OrgID != orgID {
		return adminstore.PolicyPipeline{}, adminstore.ErrNotFound
	}
	return p, nil
}

func (s *policyStoreStub) ListPolicies(_ context.Context, orgID string) ([]adminstore.PolicyPipeline, error) {
	var out []adminstore.PolicyPipeline
	for _, p := range s.policies {
		if p.OrgID == orgID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (s *policyStoreStub) UpdatePolicy(_ context.Context, orgID, policyID string, enabled bool) (adminstore.PolicyPipeline, error) {
	p, ok := s.policies[policyID]
	if !ok || p.OrgID != orgID {
		return adminstore.PolicyPipeline{}, adminstore.ErrNotFound
	}
	p.Enabled = enabled
	p.UpdatedAt = time.Now()
	s.policies[policyID] = p
	return p, nil
}

func (s *policyStoreStub) CreatePolicyVersion(_ context.Context, orgID, policyID, yamlDoc, gitSHA, createdBy string) (adminstore.PolicyVersion, error) {
	if _, ok := s.policies[policyID]; !ok {
		return adminstore.PolicyVersion{}, adminstore.ErrNotFound
	}
	list := s.versions[policyID]
	v := adminstore.PolicyVersion{
		ID: fmt.Sprintf("%s-v%d", policyID, len(list)+1), PolicyID: policyID, OrgID: orgID,
		Version: len(list) + 1, YAML: yamlDoc, GitSHA: gitSHA,
		Label: adminstore.PolicyLabelDraft, CreatedBy: createdBy, CreatedAt: time.Now(),
	}
	s.versions[policyID] = append(list, v)
	return v, nil
}

func (s *policyStoreStub) ListPolicyVersions(_ context.Context, orgID, policyID string) ([]adminstore.PolicyVersion, error) {
	if _, ok := s.policies[policyID]; !ok {
		return nil, adminstore.ErrNotFound
	}
	out := append([]adminstore.PolicyVersion{}, s.versions[policyID]...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func (s *policyStoreStub) SetActivePolicyVersion(_ context.Context, orgID, policyID string, version int) (adminstore.PolicyPipeline, error) {
	p, ok := s.policies[policyID]
	if !ok || p.OrgID != orgID || version < 1 || version > len(s.versions[policyID]) {
		return adminstore.PolicyPipeline{}, adminstore.ErrNotFound
	}
	p.CurrentVersion = version
	s.policies[policyID] = p
	return p, nil
}

func (s *policyStoreStub) SetPolicyAttachments(_ context.Context, orgID, policyID string, atts []adminstore.PolicyAttachment) ([]adminstore.PolicyAttachment, error) {
	if _, ok := s.policies[policyID]; !ok {
		return nil, adminstore.ErrNotFound
	}
	s.atts[policyID] = atts
	return atts, nil
}

func (s *policyStoreStub) ListPolicyAttachments(_ context.Context, orgID, policyID string) ([]adminstore.PolicyAttachment, error) {
	if _, ok := s.policies[policyID]; !ok {
		return nil, adminstore.ErrNotFound
	}
	return s.atts[policyID], nil
}

func (s *policyStoreStub) DeletePolicy(_ context.Context, orgID, policyID string) error {
	p, ok := s.policies[policyID]
	if !ok || p.OrgID != orgID {
		return adminstore.ErrNotFound
	}
	delete(s.policies, policyID)
	delete(s.versions, policyID)
	delete(s.atts, policyID)
	return nil
}

// UpdatePolicyCAS mirrors the store's preconditioned PUT over the in-memory
// maps: the token is the pipeline's current_version; a mismatch applies
// NOTHING and returns ErrPreconditionFailed with the live row.
func (s *policyStoreStub) UpdatePolicyCAS(ctx context.Context, orgID, policyID string, upd adminstore.PolicyUpdate, expectVersion *int, createdBy string) (adminstore.PolicyPipeline, adminstore.PolicyVersion, error) {
	p, ok := s.policies[policyID]
	if !ok || p.OrgID != orgID {
		return adminstore.PolicyPipeline{}, adminstore.PolicyVersion{}, adminstore.ErrNotFound
	}
	if expectVersion != nil && p.CurrentVersion != *expectVersion {
		return p, adminstore.PolicyVersion{}, adminstore.ErrPreconditionFailed
	}
	var appended adminstore.PolicyVersion
	if upd.YAML != nil {
		v, err := s.CreatePolicyVersion(ctx, orgID, policyID, *upd.YAML, "", createdBy)
		if err != nil {
			return adminstore.PolicyPipeline{}, adminstore.PolicyVersion{}, err
		}
		appended = v
	}
	if upd.Enabled != nil && *upd.Enabled != p.Enabled {
		updated, err := s.UpdatePolicy(ctx, orgID, policyID, *upd.Enabled)
		if err != nil {
			return adminstore.PolicyPipeline{}, adminstore.PolicyVersion{}, err
		}
		p = updated
	}
	if upd.ActiveVersion != nil {
		updated, err := s.SetActivePolicyVersion(ctx, orgID, policyID, *upd.ActiveVersion)
		if err != nil {
			return adminstore.PolicyPipeline{}, adminstore.PolicyVersion{}, err
		}
		p = updated
	}
	if upd.Attachments != nil {
		if _, err := s.SetPolicyAttachments(ctx, orgID, policyID, *upd.Attachments); err != nil {
			return adminstore.PolicyPipeline{}, adminstore.PolicyVersion{}, err
		}
	}
	return p, appended, nil
}

// policyRouter builds the full SetupRouter with the policy handlers wired.
func policyRouter(t *testing.T, store *policyStoreStub) http.Handler {
	t.Helper()
	h := handlers.New(store, polSecret, "localhost", nil)
	h.SetPolicyPipelineHandlers(handlers.NewPolicyPipelineHandlers(store))
	return h.SetupRouter()
}

// policyRequest runs one request through the router with the session + CSRF
// double-submit pair (GETs ignore the CSRF token, like the middleware).
func policyRequest(t *testing.T, router http.Handler, method, path, cookie, body string) *httptest.ResponseRecorder {
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
		req.AddCookie(testCookie("yabanin_csrf_token", polCSRF))
		req.Header.Set("X-CSRF-Token", polCSRF)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestPolicyPipelines_RoutingContract(t *testing.T) {
	anonCookie := ""
	rootCookie := makeSessionCookie(t, "root@x.test", true, polSecret)
	adminCookie := makeSessionCookie(t, "admin@x.test", false, polSecret)

	createBody := `{"name":"guard","yaml":` + policyJSONString(polYAMLOK) + `}`

	t.Run("anon is 401 on read and write (session boundary)", func(t *testing.T) {
		router := policyRouter(t, newPolicyStoreStub(polAdminRoles))
		if w := policyRequest(t, router, http.MethodGet, polPathBase, anonCookie, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("anon GET policies = %d, want 401", w.Code)
		}
		if w := policyRequest(t, router, http.MethodPost, polPathBase, anonCookie, createBody); w.Code != http.StatusUnauthorized {
			t.Errorf("anon POST policies = %d, want 401", w.Code)
		}
	})

	t.Run("root reads and writes any org", func(t *testing.T) {
		router := policyRouter(t, newPolicyStoreStub(polAdminRoles))
		w := policyRequest(t, router, http.MethodPost, polPathBase, rootCookie, createBody)
		if w.Code != http.StatusCreated {
			t.Fatalf("root POST policies = %d, want 201 (body: %s)", w.Code, w.Body.String())
		}
		if w := policyRequest(t, router, http.MethodGet, polPathBase, rootCookie, ""); w.Code != http.StatusOK {
			t.Errorf("root GET policies = %d, want 200", w.Code)
		}
	})

	t.Run("org-admin member reads and writes; operator member is 403 (policies.manage)", func(t *testing.T) {
		adminRoles := map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin}
		router := policyRouter(t, newPolicyStoreStub(adminRoles))

		w := policyRequest(t, router, http.MethodPost, polPathBase, adminCookie, createBody)
		if w.Code != http.StatusCreated {
			t.Fatalf("org-admin POST policies = %d, want 201 (body: %s)", w.Code, w.Body.String())
		}
		if w := policyRequest(t, router, http.MethodGet, polPathBase, adminCookie, ""); w.Code != http.StatusOK {
			t.Errorf("org-admin GET policies = %d, want 200", w.Code)
		}

		operatorRouter := policyRouter(t, newPolicyStoreStub(map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOperator}))
		if w := policyRequest(t, operatorRouter, http.MethodGet, polPathBase, adminCookie, ""); w.Code != http.StatusForbidden {
			t.Errorf("operator GET policies = %d, want 403 (operator lacks policies.manage)", w.Code)
		}
		if w := policyRequest(t, operatorRouter, http.MethodPost, polPathBase, adminCookie, createBody); w.Code != http.StatusForbidden {
			t.Errorf("operator POST policies = %d, want 403", w.Code)
		}
	})

	t.Run("non-member gets 404 without revealing the org", func(t *testing.T) {
		router := policyRouter(t, newPolicyStoreStub(map[string]adminstore.OrgRole{}))
		foreign := "/api/organizations/" + polOrgB + "/policies"
		if w := policyRequest(t, router, http.MethodGet, foreign, adminCookie, ""); w.Code != http.StatusNotFound {
			t.Errorf("non-member GET foreign org = %d, want 404 (resourceHidden)", w.Code)
		}
		if w := policyRequest(t, router, http.MethodPost, foreign, adminCookie, createBody); w.Code != http.StatusNotFound {
			t.Errorf("non-member POST foreign org = %d, want 404", w.Code)
		}
	})

	t.Run("cross-org policyId is the same 404", func(t *testing.T) {
		store := newPolicyStoreStub(map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin})
		p, _, err := store.CreatePolicy(context.Background(), polOrgB, "secret-policy", polYAMLOK, "", "")
		if err != nil {
			t.Fatalf("seed foreign policy: %v", err)
		}
		router := policyRouter(t, store)
		foreignDetail := polPathBase + "/" + p.ID
		if w := policyRequest(t, router, http.MethodGet, foreignDetail, adminCookie, ""); w.Code != http.StatusNotFound {
			t.Errorf("GET foreign policyId = %d, want 404", w.Code)
		}
		if w := policyRequest(t, router, http.MethodDelete, foreignDetail, adminCookie, ""); w.Code != http.StatusNotFound {
			t.Errorf("DELETE foreign policyId = %d, want 404", w.Code)
		}
	})

	t.Run("unwired store answers 503 with routes still mounted", func(t *testing.T) {
		h := handlers.New(newPolicyStoreStub(nil), polSecret, "localhost", nil)
		router := h.SetupRouter() // SetPolicyPipelineHandlers never called
		if w := policyRequest(t, router, http.MethodGet, polPathBase, rootCookie, ""); w.Code != http.StatusServiceUnavailable {
			t.Errorf("unwired GET policies = %d, want 503", w.Code)
		}
		// The validate endpoint (N16-P01-T02) follows the same wiring rule.
		if w := policyRequest(t, router, http.MethodPost, polPathBase+"/validate", rootCookie, `{"yaml":"x"}`); w.Code != http.StatusServiceUnavailable {
			t.Errorf("unwired POST validate = %d, want 503", w.Code)
		}
	})
}

func TestPolicyPipelines_ValidationContract(t *testing.T) {
	adminCookie := makeSessionCookie(t, "admin@x.test", false, polSecret)
	newRouter := func() http.Handler {
		return policyRouter(t, newPolicyStoreStub(map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin}))
	}

	t.Run("malformed YAML is a 400", func(t *testing.T) {
		router := newRouter()
		body := `{"name":"guard","yaml":"steps: [unclosed"}`
		if w := policyRequest(t, router, http.MethodPost, polPathBase, adminCookie, body); w.Code != http.StatusBadRequest {
			t.Errorf("POST invalid yaml = %d, want 400 (body: %s)", w.Code, w.Body.String())
		}
	})

	t.Run("missing kind or steps is a 400 (strict schema gate)", func(t *testing.T) {
		router := newRouter()
		body := `{"name":"guard","yaml":` + policyJSONString(polYAMLNoKind) + `}`
		if w := policyRequest(t, router, http.MethodPost, polPathBase, adminCookie, body); w.Code != http.StatusBadRequest {
			t.Errorf("POST yaml without kind = %d, want 400", w.Code)
		}
		body = `{"name":"guard","yaml":` + policyJSONString(polYAMLNoSteps) + `}`
		if w := policyRequest(t, router, http.MethodPost, polPathBase, adminCookie, body); w.Code != http.StatusBadRequest {
			t.Errorf("POST yaml without steps = %d, want 400", w.Code)
		}
	})

	t.Run("a schema-plausible document with unknown detector names stores (compile is OP-8's job)", func(t *testing.T) {
		router := newRouter()
		yamlDoc := polYAMLOK + "  - id: future\n    detector: builtin/not-invented-yet\n"
		body := `{"name":"guard","yaml":` + policyJSONString(yamlDoc) + `}`
		w := policyRequest(t, router, http.MethodPost, polPathBase, adminCookie, body)
		if w.Code != http.StatusCreated {
			t.Fatalf("POST plausible yaml = %d, want 201 (body: %s)", w.Code, w.Body.String())
		}
	})

	t.Run("unknown JSON fields are rejected", func(t *testing.T) {
		router := newRouter()
		body := `{"name":"guard","yaml":` + policyJSONString(polYAMLOK) + `,"plain_text_key":"nope"}`
		if w := policyRequest(t, router, http.MethodPost, polPathBase, adminCookie, body); w.Code != http.StatusBadRequest {
			t.Errorf("POST unknown field = %d, want 400", w.Code)
		}
	})

	t.Run("empty name is a 400; duplicate name is a 409", func(t *testing.T) {
		router := newRouter()
		body := `{"name":"  ","yaml":` + policyJSONString(polYAMLOK) + `}`
		if w := policyRequest(t, router, http.MethodPost, polPathBase, adminCookie, body); w.Code != http.StatusBadRequest {
			t.Errorf("POST empty name = %d, want 400", w.Code)
		}
		ok := `{"name":"dup","yaml":` + policyJSONString(polYAMLOK) + `}`
		if w := policyRequest(t, router, http.MethodPost, polPathBase, adminCookie, ok); w.Code != http.StatusCreated {
			t.Fatalf("POST first dup = %d, want 201", w.Code)
		}
		if w := policyRequest(t, router, http.MethodPost, polPathBase, adminCookie, ok); w.Code != http.StatusConflict {
			t.Errorf("POST duplicate name = %d, want 409", w.Code)
		}
	})

	t.Run("PUT appends a version and activates; attachments replace-all", func(t *testing.T) {
		router := newRouter()
		w := policyRequest(t, router, http.MethodPost, polPathBase, adminCookie,
			`{"name":"flow","yaml":`+policyJSONString(polYAMLOK)+`}`)
		if w.Code != http.StatusCreated {
			t.Fatalf("POST = %d, want 201", w.Code)
		}
		var created struct {
			Policy adminstore.PolicyPipeline `json:"policy"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create: %v", err)
		}
		detail := polPathBase + "/" + created.Policy.ID

		w = policyRequest(t, router, http.MethodPut, detail, adminCookie,
			`{"yaml":`+policyJSONString(polYAMLOK+"# v2\n")+`,"active_version":2,"enabled":true,
			  "attachments":[{"key_label":"prod","model_pattern":"gpt*","endpoint":"chat","priority":10}]}`)
		if w.Code != http.StatusOK {
			t.Fatalf("PUT = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		var got struct {
			Policy adminstore.PolicyPipeline `json:"policy"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode put: %v", err)
		}
		if got.Policy.CurrentVersion != 2 || !got.Policy.Enabled {
			t.Errorf("PUT state = %+v, want current_version 2 enabled", got.Policy)
		}

		// The full detail (versions newest first, attachments) is the GET.
		w = policyRequest(t, router, http.MethodGet, detail, adminCookie, "")
		if w.Code != http.StatusOK {
			t.Fatalf("GET detail = %d, want 200", w.Code)
		}
		var full struct {
			Policy      adminstore.PolicyPipeline     `json:"policy"`
			Versions    []adminstore.PolicyVersion    `json:"versions"`
			Attachments []adminstore.PolicyAttachment `json:"attachments"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &full); err != nil {
			t.Fatalf("decode get: %v", err)
		}
		if len(full.Versions) != 2 || full.Versions[0].Version != 2 {
			t.Errorf("GET versions=%+v, want 2 versions newest first", full.Versions)
		}
		if len(full.Attachments) != 1 {
			t.Fatalf("GET attachments=%d, want 1", len(full.Attachments))
		}
		if full.Attachments[0].KeyLabel != "prod" || full.Attachments[0].ModelPattern != "gpt*" {
			t.Errorf("attachment = %+v, want prod/gpt*", full.Attachments[0])
		}

		// PUT with no actionable field is a 400.
		if w := policyRequest(t, router, http.MethodPut, detail, adminCookie, `{}`); w.Code != http.StatusBadRequest {
			t.Errorf("empty PUT = %d, want 400", w.Code)
		}
		// git_sha without yaml is a 400.
		if w := policyRequest(t, router, http.MethodPut, detail, adminCookie, `{"git_sha":"abc"}`); w.Code != http.StatusBadRequest {
			t.Errorf("git_sha-only PUT = %d, want 400", w.Code)
		}
	})

	t.Run("attachment validation rejects empty pattern and bad priority", func(t *testing.T) {
		router := newRouter()
		w := policyRequest(t, router, http.MethodPost, polPathBase, adminCookie,
			`{"name":"att","yaml":`+policyJSONString(polYAMLOK)+`,"attachments":[{"model_pattern":"","endpoint":"chat"}]}`)
		if w.Code != http.StatusBadRequest {
			t.Errorf("POST empty pattern = %d, want 400", w.Code)
		}
		w = policyRequest(t, router, http.MethodPost, polPathBase, adminCookie,
			`{"name":"att2","yaml":`+policyJSONString(polYAMLOK)+`,"attachments":[{"model_pattern":"*","endpoint":"chat","priority":-1}]}`)
		if w.Code != http.StatusBadRequest {
			t.Errorf("POST negative priority = %d, want 400", w.Code)
		}
	})
}

// policyJSONString embeds a YAML document as a JSON string literal.
func policyJSONString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err) // json.Marshal of a string cannot fail
	}
	return string(b)
}

// compile-time guard: the stub error path uses adminstore.ErrNotFound.
var _ = errors.New

// `version` field is the optimistic-concurrency token. Contract under test:
//
//	stale version   → 409 {"error":"conflict","current":{policy}} and NOTHING
//	                   applied (not even the other fields of the same body)
//	current version → applies atomically (yaml+active_version+enabled in one
//	                  body land together)
//	version absent  → legacy unconditional PUT keeps working
//	version 0       → a NEVER-ACTIVATED policy's real token (distinguishable
//	                  from absent: *int, not int)
func TestPolicyPipelines_VersionConflict(t *testing.T) {
	adminCookie := makeSessionCookie(t, "admin@x.test", false, polSecret)

	// seedPolicy creates a policy and activates v1: current_version = 1,
	// the token every editor would have loaded.
	seedPolicy := func(t *testing.T, store *policyStoreStub) string {
		t.Helper()
		p, _, err := store.CreatePolicy(context.Background(), polOrgA, "stale-guard", polYAMLOK, "", "")
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
		if _, err := store.CreatePolicyVersion(context.Background(), polOrgA, p.ID, polYAMLOK+"# v2\n", "", ""); err != nil {
			t.Fatalf("seed v2: %v", err)
		}
		if _, err := store.SetActivePolicyVersion(context.Background(), polOrgA, p.ID, 1); err != nil {
			t.Fatalf("seed activate: %v", err)
		}
		return p.ID
	}

	t.Run("stale activate is a 409 carrying the current version, nothing applied", func(t *testing.T) {
		store := newPolicyStoreStub(map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin})
		polID := seedPolicy(t, store)
		router := policyRouter(t, store)
		detail := polPathBase + "/" + polID

		// Operator B activates v2 underneath (current_version 1 → 2).
		if w := policyRequest(t, router, http.MethodPut, detail, adminCookie, `{"active_version":2}`); w.Code != http.StatusOK {
			t.Fatalf("B activate = %d (body %s)", w.Code, w.Body.String())
		}
		// Operator A still holds version 1: activate + enabled in ONE body —
		// the conflict must reject the WHOLE body (enabled must not land).
		w := policyRequest(t, router, http.MethodPut, detail, adminCookie,
			`{"active_version":1,"enabled":true,"version":1}`)
		if w.Code != http.StatusConflict {
			t.Fatalf("stale PUT = %d, want 409 (body: %s)", w.Code, w.Body.String())
		}
		var conflict struct {
			Error   string `json:"error"`
			Current struct {
				Policy adminstore.PolicyPipeline `json:"policy"`
			} `json:"current"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &conflict); err != nil {
			t.Fatalf("decode conflict: %v", err)
		}
		if conflict.Current.Policy.CurrentVersion != 2 {
			t.Errorf("conflict current_version = %d, want 2 (the live row)", conflict.Current.Policy.CurrentVersion)
		}
		live, err := store.GetPolicy(context.Background(), polOrgA, polID)
		if err != nil {
			t.Fatalf("live read: %v", err)
		}
		if live.Enabled {
			t.Errorf("stale PUT applied enabled=true — a conflict must apply NOTHING")
		}
		if live.CurrentVersion != 2 {
			t.Errorf("stale PUT moved current_version = %d, want 2 untouched", live.CurrentVersion)
		}
	})

	t.Run("stale yaml save is a 409 (an activation moved underneath)", func(t *testing.T) {
		store := newPolicyStoreStub(map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin})
		polID := seedPolicy(t, store)
		router := policyRouter(t, store)
		detail := polPathBase + "/" + polID

		// B activates v2; A saves a draft still holding version 1.
		if w := policyRequest(t, router, http.MethodPut, detail, adminCookie, `{"active_version":2}`); w.Code != http.StatusOK {
			t.Fatalf("B activate = %d", w.Code)
		}
		w := policyRequest(t, router, http.MethodPut, detail, adminCookie,
			`{"yaml":`+policyJSONString(polYAMLOK+"# A's draft\n")+`,"version":1}`)
		if w.Code != http.StatusConflict {
			t.Fatalf("stale yaml PUT = %d, want 409 (body: %s)", w.Code, w.Body.String())
		}
		versions, err := store.ListPolicyVersions(context.Background(), polOrgA, polID)
		if err != nil {
			t.Fatalf("versions: %v", err)
		}
		if len(versions) != 2 {
			t.Errorf("stale yaml PUT appended a version (have %d, want 2)", len(versions))
		}
	})

	t.Run("current version applies atomically (yaml + activate + enabled)", func(t *testing.T) {
		store := newPolicyStoreStub(map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin})
		polID := seedPolicy(t, store)
		router := policyRouter(t, store)
		detail := polPathBase + "/" + polID

		w := policyRequest(t, router, http.MethodPut, detail, adminCookie,
			`{"yaml":`+policyJSONString(polYAMLOK+"# v3\n")+`,"active_version":3,"enabled":true,"version":1}`)
		if w.Code != http.StatusOK {
			t.Fatalf("fresh PUT = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		var got struct {
			Policy adminstore.PolicyPipeline `json:"policy"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Policy.CurrentVersion != 3 || !got.Policy.Enabled {
			t.Errorf("fresh PUT state = %+v, want current_version 3 enabled", got.Policy)
		}
	})

	t.Run("version 0 is the real token of a never-activated policy", func(t *testing.T) {
		store := newPolicyStoreStub(map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin})
		p, _, err := store.CreatePolicy(context.Background(), polOrgA, "fresh", polYAMLOK, "", "")
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
		router := policyRouter(t, store)
		detail := polPathBase + "/" + p.ID

		// Token 0 matches the never-activated row: the write lands.
		w := policyRequest(t, router, http.MethodPut, detail, adminCookie,
			`{"yaml":`+policyJSONString(polYAMLOK+"# v2\n")+`,"active_version":2,"version":0}`)
		if w.Code != http.StatusOK {
			t.Fatalf("version-0 PUT = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		// After the activation the token moved to 2: a second version-0
		// write must now conflict.
		w = policyRequest(t, router, http.MethodPut, detail, adminCookie,
			`{"enabled":true,"version":0}`)
		if w.Code != http.StatusConflict {
			t.Fatalf("stale version-0 PUT = %d, want 409", w.Code)
		}
		if live, _ := store.GetPolicy(context.Background(), polOrgA, p.ID); live.Enabled {
			t.Errorf("conflict applied enabled — nothing must land")
		}
	})

	t.Run("version absent keeps the legacy unconditional PUT", func(t *testing.T) {
		store := newPolicyStoreStub(map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin})
		polID := seedPolicy(t, store)
		router := policyRouter(t, store)
		detail := polPathBase + "/" + polID

		if w := policyRequest(t, router, http.MethodPut, detail, adminCookie, `{"active_version":2}`); w.Code != http.StatusOK {
			t.Fatalf("legacy PUT = %d, want 200", w.Code)
		}
	})

	t.Run("stale PUT on a missing policy is still the 404, not 409", func(t *testing.T) {
		store := newPolicyStoreStub(map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin})
		router := policyRouter(t, store)
		w := policyRequest(t, router, http.MethodPut, polPathBase+"/nope", adminCookie, `{"enabled":true,"version":1}`)
		if w.Code != http.StatusNotFound {
			t.Errorf("missing policy PUT = %d, want 404", w.Code)
		}
	})

	t.Run("nothing-to-update with only a version is still the 400", func(t *testing.T) {
		store := newPolicyStoreStub(map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin})
		polID := seedPolicy(t, store)
		router := policyRouter(t, store)
		w := policyRequest(t, router, http.MethodPut, polPathBase+"/"+polID, adminCookie, `{"version":1}`)
		if w.Code != http.StatusBadRequest {
			t.Errorf("version-only PUT = %d, want 400", w.Code)
		}
	})
}

// --- N16-P01-T02: strict-at-save (G2), git_sha boundary (G3), validate endpoint

// polAdminRoles grants the session identity the org-admin role the
// policies.manage gate demands (tests run sequentially; the stub only reads
// the map).
var polAdminRoles = map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin}

const polYAMLUnknownField = "apiVersion: ypp/v1\nkind: Policy\nname: t\nmode: shadow\nhooks: [pre_upstream]\nsteps:\n  - id: s\n    detector: builtin/secrets\nbogus_field: true\n"

// TestPolicyPipelines_StrictSaveGate pins owner decision 2026-11-04 (a):
// create/update store NOTHING that the gateway's strict parser would refuse
// — the lenient header-only gate used to let the UI persist documents the
// gateway then rejected at load (the store↔gateway asymmetry, audit gap G2).
func TestPolicyPipelines_StrictSaveGate(t *testing.T) {
	adminCookie := makeSessionCookie(t, "admin@x.test", false, polSecret)

	t.Run("unknown field in the policy document is a 400 naming the field", func(t *testing.T) {
		stub := newPolicyStoreStub(polAdminRoles)
		router := policyRouter(t, stub)
		body := `{"name":"guard","yaml":` + policyJSONString(polYAMLUnknownField) + `}`
		w := policyRequest(t, router, http.MethodPost, polPathBase, adminCookie, body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("POST unknown-field yaml = %d, want 400 (body: %s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "bogus_field") {
			t.Errorf("error must name the offending field (strict decoder), got: %s", w.Body.String())
		}
		// Nothing stored: the gate runs before the store call.
		if got := len(stub.policies); got != 0 {
			t.Errorf("rejected document stored %d policies — the gate must run first", got)
		}
	})

	t.Run("unknown field via the CAS PUT is a 400 too", func(t *testing.T) {
		stub := newPolicyStoreStub(polAdminRoles)
		router := policyRouter(t, stub)
		create := `{"name":"guard","yaml":` + policyJSONString(polYAMLOK) + `}`
		if w := policyRequest(t, router, http.MethodPost, polPathBase, adminCookie, create); w.Code != http.StatusCreated {
			t.Fatalf("setup create = %d (body: %s)", w.Code, w.Body.String())
		}
		id := "pol-1"
		body := `{"yaml":` + policyJSONString(polYAMLUnknownField) + `,"version":0}`
		w := policyRequest(t, router, http.MethodPut, polPathBase+"/"+id, adminCookie, body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("CAS PUT unknown-field yaml = %d, want 400 (body: %s)", w.Code, w.Body.String())
		}
		if versions := stub.versions[id]; len(versions) != 1 {
			t.Errorf("rejected CAS PUT appended versions: %d", len(versions))
		}
	})
}

// TestPolicyPipelines_GitSHABoundary pins owner decision 2026-11-04 (G3):
// no API caller can claim a git revision — git_sha is the reconcile drift
// detector's anchor, and a spoofable one makes UI edits indistinguishable
// from reconciled git content. Non-empty caller-supplied sha = 400 on every
// write path; "" (or absent) stays legal (authored outside git).
func TestPolicyPipelines_GitSHABoundary(t *testing.T) {
	adminCookie := makeSessionCookie(t, "admin@x.test", false, polSecret)

	t.Run("create with git_sha is a 400", func(t *testing.T) {
		router := policyRouter(t, newPolicyStoreStub(polAdminRoles))
		body := `{"name":"guard","yaml":` + policyJSONString(polYAMLOK) + `,"git_sha":"deadbeef"}`
		if w := policyRequest(t, router, http.MethodPost, polPathBase, adminCookie, body); w.Code != http.StatusBadRequest {
			t.Fatalf("POST with git_sha = %d, want 400 (body: %s)", w.Code, w.Body.String())
		}
	})

	t.Run("update yaml+git_sha is a 400 (plain and CAS)", func(t *testing.T) {
		stub := newPolicyStoreStub(polAdminRoles)
		router := policyRouter(t, stub)
		create := `{"name":"guard","yaml":` + policyJSONString(polYAMLOK) + `}`
		if w := policyRequest(t, router, http.MethodPost, polPathBase, adminCookie, create); w.Code != http.StatusCreated {
			t.Fatalf("setup create = %d", w.Code)
		}
		body := `{"yaml":` + policyJSONString(polYAMLOK+"# v2\n") + `,"git_sha":"deadbeef"}`
		if w := policyRequest(t, router, http.MethodPut, polPathBase+"/pol-1", adminCookie, body); w.Code != http.StatusBadRequest {
			t.Errorf("plain PUT with git_sha = %d, want 400", w.Code)
		}
		body = `{"yaml":` + policyJSONString(polYAMLOK+"# v2\n") + `,"git_sha":"deadbeef","version":0}`
		if w := policyRequest(t, router, http.MethodPut, polPathBase+"/pol-1", adminCookie, body); w.Code != http.StatusBadRequest {
			t.Errorf("CAS PUT with git_sha = %d, want 400", w.Code)
		}
		if got := len(stub.versions["pol-1"]); got != 1 {
			t.Errorf("rejected PUTs must store nothing, versions=%d", got)
		}
	})

	t.Run("absent or empty git_sha stores with git_sha empty (authored outside git)", func(t *testing.T) {
		stub := newPolicyStoreStub(polAdminRoles)
		router := policyRouter(t, stub)
		create := `{"name":"guard","yaml":` + policyJSONString(polYAMLOK) + `,"git_sha":""}`
		if w := policyRequest(t, router, http.MethodPost, polPathBase, adminCookie, create); w.Code != http.StatusCreated {
			t.Fatalf("POST with empty git_sha = %d, want 201 (body: %s)", w.Code, w.Body.String())
		}
		body := `{"yaml":` + policyJSONString(polYAMLOK+"# v2\n") + `}`
		if w := policyRequest(t, router, http.MethodPut, polPathBase+"/pol-1", adminCookie, body); w.Code != http.StatusOK {
			t.Fatalf("PUT without git_sha = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		for _, v := range stub.versions["pol-1"] {
			if v.GitSHA != "" {
				t.Errorf("API-authored version %d recorded git_sha %q — must stay empty", v.Version, v.GitSHA)
			}
		}
	})
}

// TestPolicyPipelines_ValidateEndpoint pins the UI's save-time arbiter
// (owner decision 2026-11-04 (a)): POST /policies/validate runs EXACTLY the
// store-path validation, so validate-200 ⟺ the same bytes would store.
func TestPolicyPipelines_ValidateEndpoint(t *testing.T) {
	adminCookie := makeSessionCookie(t, "admin@x.test", false, polSecret)
	valPath := polPathBase + "/validate"

	t.Run("valid document: 200 with the parsed identity", func(t *testing.T) {
		router := policyRouter(t, newPolicyStoreStub(polAdminRoles))
		body := `{"yaml":` + policyJSONString(polYAMLOK) + `}`
		w := policyRequest(t, router, http.MethodPost, valPath, adminCookie, body)
		if w.Code != http.StatusOK {
			t.Fatalf("POST validate = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		for _, want := range []string{`"valid":true`, `"name":"t"`, `"mode":"shadow"`} {
			if !strings.Contains(w.Body.String(), want) {
				t.Errorf("validate response missing %s: %s", want, w.Body.String())
			}
		}
	})

	t.Run("invalid document: the same 400 text the save would produce", func(t *testing.T) {
		router := policyRouter(t, newPolicyStoreStub(polAdminRoles))
		body := `{"yaml":` + policyJSONString(polYAMLUnknownField) + `}`
		wv := policyRequest(t, router, http.MethodPost, valPath, adminCookie, body)
		if wv.Code != http.StatusBadRequest {
			t.Fatalf("POST validate invalid = %d, want 400", wv.Code)
		}
		// Same bytes through the create path: identical error text — one
		// parser, one message (the parity the UI relies on).
		create := `{"name":"guard","yaml":` + policyJSONString(polYAMLUnknownField) + `}`
		wc := policyRequest(t, router, http.MethodPost, polPathBase, adminCookie, create)
		if wc.Code != http.StatusBadRequest {
			t.Fatalf("POST create invalid = %d, want 400", wc.Code)
		}
		if wv.Body.String() != wc.Body.String() {
			t.Errorf("validate/create error texts diverge:\nvalidate: %s\ncreate:   %s", wv.Body.String(), wc.Body.String())
		}
	})

	t.Run("empty yaml is a 400; unknown JSON fields are a 400", func(t *testing.T) {
		router := policyRouter(t, newPolicyStoreStub(polAdminRoles))
		if w := policyRequest(t, router, http.MethodPost, valPath, adminCookie, `{"yaml":"  "}`); w.Code != http.StatusBadRequest {
			t.Errorf("validate empty yaml = %d, want 400", w.Code)
		}
		if w := policyRequest(t, router, http.MethodPost, valPath, adminCookie, `{"yaml":"x","nosuch":1}`); w.Code != http.StatusBadRequest {
			t.Errorf("validate unknown field = %d, want 400", w.Code)
		}
	})

	t.Run("the endpoint is inside the org permission gate", func(t *testing.T) {
		router := policyRouter(t, newPolicyStoreStub(polAdminRoles))
		if w := policyRequest(t, router, http.MethodPost, valPath, "", `{"yaml":"x"}`); w.Code != http.StatusUnauthorized {
			t.Errorf("anon validate = %d, want 401", w.Code)
		}
	})
}
