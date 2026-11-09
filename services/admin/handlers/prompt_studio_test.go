package handlers_test

// the FULL SetupRouter (session auth + CSRF chain, exactly like
// policy_pipelines_test.go): the org-permission gate lives in the mount
// (policies.manage), the resource rules live in the handlers —
//
//	anon                          → 401 (session boundary)
//	root                          → 200/201 (any org)
//	member with policies.manage   → 200/201 (org-admin holds it)
//	member without the permission → 403 (operator/reader)
//	no membership                 → 404 (the org stays invisible —
//	                                 resourceHidden semantics)
//	cross-org promptId / partial  → 404 (org-scoped lookup; never revealed)
//	store not wired               → 503 (routes stay mounted unwired)
//	duplicate name                → 409 (store unique violation)
//	unknown JSON fields           → 400

import (
	"context"
	"encoding/json"
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
	psOrgA     = "org-a"
	psOrgB     = "org-foreign"
	psPathBase = "/api/organizations/" + psOrgA + "/prompts"
	psPartBase = "/api/organizations/" + psOrgA + "/partials"
	psTemplate = "You are {{role}}.\n{{partials.rules}}\nInput: {{input}}"
)

// promptDetailPayload mirrors the handler's promptDetail response shape.
type promptDetailPayload struct {
	Prompt   adminstore.Prompt          `json:"prompt"`
	Versions []adminstore.PromptVersion `json:"versions"`
	Labels   []adminstore.PromptLabel   `json:"labels"`
}

// promptStudioStub implements the handlers.PromptStudioStore contract over
// in-memory maps, plus the membership lookup the session chain needs. The
// stub mimics the store-side org-unique name rule (a 23505 PgError the
// handler maps to 409). Tests run sequentially.
type promptStudioStub struct {
	stubStore
	roles    map[string]adminstore.OrgRole
	prompts  map[string]adminstore.Prompt
	versions map[string][]adminstore.PromptVersion
	labels   map[string][]adminstore.PromptLabel
	partials map[string]adminstore.Partial
	seq      int
}

func newPromptStudioStub(roles map[string]adminstore.OrgRole) *promptStudioStub {
	return &promptStudioStub{
		roles:    roles,
		prompts:  map[string]adminstore.Prompt{},
		versions: map[string][]adminstore.PromptVersion{},
		labels:   map[string][]adminstore.PromptLabel{},
		partials: map[string]adminstore.Partial{},
	}
}

func (s *promptStudioStub) GetUserOrgRoles(context.Context, string) (map[string]adminstore.OrgRole, error) {
	return s.roles, nil
}

func (s *promptStudioStub) dupErr(name string) error {
	return fmt.Errorf("prompt name %q already exists in this org: %w",
		name, &pgconn.PgError{Code: "23505", Message: "duplicate key"})
}

func (s *promptStudioStub) CreatePrompt(_ context.Context, orgID, name, description, template string, params json.RawMessage, createdBy string) (adminstore.Prompt, adminstore.PromptVersion, error) {
	for _, p := range s.prompts {
		if p.OrgID == orgID && p.Name == name {
			return adminstore.Prompt{}, adminstore.PromptVersion{}, s.dupErr(name)
		}
	}
	s.seq++
	id := fmt.Sprintf("prm-%d", s.seq)
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	p := adminstore.Prompt{ID: id, OrgID: orgID, Name: name, Description: description, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	s.prompts[id] = p
	v := adminstore.PromptVersion{ID: id + "-v1", PromptID: id, OrgID: orgID, Version: 1, Template: template, Params: params, CreatedBy: createdBy, CreatedAt: time.Now()}
	s.versions[id] = []adminstore.PromptVersion{v}
	s.labels[id] = []adminstore.PromptLabel{{PromptID: id, OrgID: orgID, Label: adminstore.PromptLabelDraft, Version: 1, UpdatedAt: time.Now()}}
	return p, v, nil
}

func (s *promptStudioStub) GetPrompt(_ context.Context, orgID, promptID string) (adminstore.Prompt, error) {
	p, ok := s.prompts[promptID]
	if !ok || p.OrgID != orgID {
		return adminstore.Prompt{}, adminstore.ErrNotFound
	}
	return p, nil
}

func (s *promptStudioStub) ListPrompts(_ context.Context, orgID string) ([]adminstore.Prompt, error) {
	var out []adminstore.Prompt
	for _, p := range s.prompts {
		if p.OrgID == orgID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (s *promptStudioStub) UpdatePrompt(_ context.Context, orgID, promptID, template string, params json.RawMessage, createdBy string, expectedVersion int) (adminstore.PromptVersion, error) {
	p, ok := s.prompts[promptID]
	if !ok || p.OrgID != orgID {
		return adminstore.PromptVersion{}, adminstore.ErrNotFound
	}
	list := s.versions[promptID]
	if len(list) != expectedVersion {
		return adminstore.PromptVersion{}, adminstore.ErrPreconditionFailed
	}
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	v := adminstore.PromptVersion{
		ID: fmt.Sprintf("%s-v%d", promptID, len(list)+1), PromptID: promptID, OrgID: orgID,
		Version: len(list) + 1, Template: template, Params: params, CreatedBy: createdBy, CreatedAt: time.Now(),
	}
	s.versions[promptID] = append(list, v)
	s.setLabel(promptID, orgID, adminstore.PromptLabelDraft, v.Version)
	return v, nil
}

func (s *promptStudioStub) setLabel(promptID, orgID, label string, version int) {
	for i := range s.labels[promptID] {
		if s.labels[promptID][i].Label == label {
			s.labels[promptID][i].Version = version
			s.labels[promptID][i].UpdatedAt = time.Now()
			return
		}
	}
	s.labels[promptID] = append(s.labels[promptID], adminstore.PromptLabel{PromptID: promptID, OrgID: orgID, Label: label, Version: version, UpdatedAt: time.Now()})
}

func (s *promptStudioStub) PromoteLabel(_ context.Context, orgID, promptID, label string, version int) (adminstore.PromptLabel, error) {
	p, ok := s.prompts[promptID]
	if !ok || p.OrgID != orgID {
		return adminstore.PromptLabel{}, adminstore.ErrNotFound
	}
	found := false
	for _, v := range s.versions[promptID] {
		if v.Version == version {
			found = true
			break
		}
	}
	if !found {
		return adminstore.PromptLabel{}, adminstore.ErrNotFound
	}
	s.setLabel(promptID, orgID, label, version)
	for _, l := range s.labels[promptID] {
		if l.Label == label {
			return l, nil
		}
	}
	return adminstore.PromptLabel{}, adminstore.ErrNotFound
}

func (s *promptStudioStub) ListPromptLabels(_ context.Context, orgID, promptID string) ([]adminstore.PromptLabel, error) {
	if _, ok := s.prompts[promptID]; !ok {
		return nil, adminstore.ErrNotFound
	}
	return append([]adminstore.PromptLabel{}, s.labels[promptID]...), nil
}

func (s *promptStudioStub) ListPromptVersions(_ context.Context, orgID, promptID string) ([]adminstore.PromptVersion, error) {
	if _, ok := s.prompts[promptID]; !ok {
		return nil, adminstore.ErrNotFound
	}
	out := append([]adminstore.PromptVersion{}, s.versions[promptID]...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func (s *promptStudioStub) DeletePrompt(_ context.Context, orgID, promptID string) error {
	p, ok := s.prompts[promptID]
	if !ok || p.OrgID != orgID {
		return adminstore.ErrNotFound
	}
	delete(s.prompts, promptID)
	delete(s.versions, promptID)
	delete(s.labels, promptID)
	return nil
}

func (s *promptStudioStub) CreatePartial(_ context.Context, orgID, name, body string) (adminstore.Partial, error) {
	key := orgID + "/" + name
	if _, ok := s.partials[key]; ok {
		return adminstore.Partial{}, s.dupErr(name)
	}
	s.seq++
	p := adminstore.Partial{ID: fmt.Sprintf("prt-%d", s.seq), OrgID: orgID, Name: name, Body: body, Version: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	s.partials[key] = p
	return p, nil
}

func (s *promptStudioStub) UpdatePartial(_ context.Context, orgID, name, body string, expectedVersion int) (adminstore.Partial, error) {
	key := orgID + "/" + name
	p, ok := s.partials[key]
	if !ok {
		return adminstore.Partial{}, adminstore.ErrNotFound
	}
	if p.Version != expectedVersion {
		return adminstore.Partial{}, adminstore.ErrPreconditionFailed
	}
	p.Body, p.Version, p.UpdatedAt = body, p.Version+1, time.Now()
	s.partials[key] = p
	return p, nil
}

func (s *promptStudioStub) GetPartial(_ context.Context, orgID, name string) (adminstore.Partial, error) {
	p, ok := s.partials[orgID+"/"+name]
	if !ok {
		return adminstore.Partial{}, adminstore.ErrNotFound
	}
	return p, nil
}

func (s *promptStudioStub) ListPartials(_ context.Context, orgID string) ([]adminstore.Partial, error) {
	var out []adminstore.Partial
	for _, p := range s.partials {
		if p.OrgID == orgID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (s *promptStudioStub) DeletePartial(_ context.Context, orgID, name string) error {
	key := orgID + "/" + name
	if _, ok := s.partials[key]; !ok {
		return adminstore.ErrNotFound
	}
	delete(s.partials, key)
	return nil
}

// promptStudioRouter builds the full SetupRouter with the prompt studio
// handlers wired.
func promptStudioRouter(t *testing.T, store *promptStudioStub) http.Handler {
	t.Helper()
	h := handlers.New(store, polSecret, "localhost", nil)
	h.SetPromptStudioHandlers(handlers.NewPromptStudioHandlers(store))
	return h.SetupRouter()
}

// promptStudioRequest runs one request through the router with the session +
// CSRF double-submit pair (GETs ignore the CSRF token, like the middleware).
func promptStudioRequest(t *testing.T, router http.Handler, method, path, cookie, body string) *httptest.ResponseRecorder {
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

func TestPromptStudio_RoutingContract(t *testing.T) {
	anonCookie := ""
	rootCookie := makeSessionCookie(t, "root@x.test", true, polSecret)
	adminCookie := makeSessionCookie(t, "admin@x.test", false, polSecret)

	createBody := `{"name":"judge","description":"d","template":` + policyJSONString(psTemplate) + `}`

	t.Run("anon is 401 on read and write (session boundary)", func(t *testing.T) {
		router := promptStudioRouter(t, newPromptStudioStub(nil))
		if w := promptStudioRequest(t, router, http.MethodGet, psPathBase, anonCookie, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("anon GET prompts = %d, want 401", w.Code)
		}
		if w := promptStudioRequest(t, router, http.MethodPost, psPathBase, anonCookie, createBody); w.Code != http.StatusUnauthorized {
			t.Errorf("anon POST prompts = %d, want 401", w.Code)
		}
		if w := promptStudioRequest(t, router, http.MethodGet, psPartBase, anonCookie, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("anon GET partials = %d, want 401", w.Code)
		}
	})

	t.Run("root reads and writes any org", func(t *testing.T) {
		router := promptStudioRouter(t, newPromptStudioStub(nil))
		if w := promptStudioRequest(t, router, http.MethodPost, psPathBase, rootCookie, createBody); w.Code != http.StatusCreated {
			t.Fatalf("root POST prompts = %d, want 201 (body: %s)", w.Code, w.Body.String())
		}
		if w := promptStudioRequest(t, router, http.MethodGet, psPathBase, rootCookie, ""); w.Code != http.StatusOK {
			t.Errorf("root GET prompts = %d, want 200", w.Code)
		}
		if w := promptStudioRequest(t, router, http.MethodGet, psPartBase, rootCookie, ""); w.Code != http.StatusOK {
			t.Errorf("root GET partials = %d, want 200", w.Code)
		}
	})

	t.Run("org-admin reads and writes; operator is 403 (policies.manage)", func(t *testing.T) {
		router := promptStudioRouter(t, newPromptStudioStub(map[string]adminstore.OrgRole{psOrgA: adminstore.RoleOrgAdmin}))
		if w := promptStudioRequest(t, router, http.MethodPost, psPathBase, adminCookie, createBody); w.Code != http.StatusCreated {
			t.Fatalf("org-admin POST prompts = %d, want 201 (body: %s)", w.Code, w.Body.String())
		}
		if w := promptStudioRequest(t, router, http.MethodGet, psPartBase, adminCookie, ""); w.Code != http.StatusOK {
			t.Errorf("org-admin GET partials = %d, want 200", w.Code)
		}

		operatorRouter := promptStudioRouter(t, newPromptStudioStub(map[string]adminstore.OrgRole{psOrgA: adminstore.RoleOperator}))
		if w := promptStudioRequest(t, operatorRouter, http.MethodGet, psPathBase, adminCookie, ""); w.Code != http.StatusForbidden {
			t.Errorf("operator GET prompts = %d, want 403 (operator lacks policies.manage)", w.Code)
		}
		if w := promptStudioRequest(t, operatorRouter, http.MethodPost, psPartBase, adminCookie, `{"name":"r","body":"b"}`); w.Code != http.StatusForbidden {
			t.Errorf("operator POST partials = %d, want 403", w.Code)
		}
	})

	t.Run("non-member gets 404 without revealing the org", func(t *testing.T) {
		router := promptStudioRouter(t, newPromptStudioStub(map[string]adminstore.OrgRole{}))
		foreign := "/api/organizations/" + psOrgB + "/prompts"
		if w := promptStudioRequest(t, router, http.MethodGet, foreign, adminCookie, ""); w.Code != http.StatusNotFound {
			t.Errorf("non-member GET foreign org = %d, want 404 (resourceHidden)", w.Code)
		}
		if w := promptStudioRequest(t, router, http.MethodPost, foreign, adminCookie, createBody); w.Code != http.StatusNotFound {
			t.Errorf("non-member POST foreign org = %d, want 404", w.Code)
		}
	})

	t.Run("cross-org promptId and partial name are the same 404", func(t *testing.T) {
		store := newPromptStudioStub(map[string]adminstore.OrgRole{psOrgA: adminstore.RoleOrgAdmin})
		p, _, err := store.CreatePrompt(context.Background(), psOrgB, "secret-prompt", "", "t", nil, "")
		if err != nil {
			t.Fatalf("seed foreign prompt: %v", err)
		}
		if _, err := store.CreatePartial(context.Background(), psOrgB, "secret-partial", "b"); err != nil {
			t.Fatalf("seed foreign partial: %v", err)
		}
		router := promptStudioRouter(t, store)
		if w := promptStudioRequest(t, router, http.MethodGet, psPathBase+"/"+p.ID, adminCookie, ""); w.Code != http.StatusNotFound {
			t.Errorf("GET foreign promptId = %d, want 404", w.Code)
		}
		if w := promptStudioRequest(t, router, http.MethodDelete, psPathBase+"/"+p.ID, adminCookie, ""); w.Code != http.StatusNotFound {
			t.Errorf("DELETE foreign promptId = %d, want 404", w.Code)
		}
		if w := promptStudioRequest(t, router, http.MethodPut, psPartBase+"/secret-partial", adminCookie, `{"body":"evil"}`); w.Code != http.StatusNotFound {
			t.Errorf("PUT foreign partial = %d, want 404", w.Code)
		}
	})

	t.Run("unwired store answers 503 with routes still mounted", func(t *testing.T) {
		h := handlers.New(newPromptStudioStub(nil), polSecret, "localhost", nil)
		router := h.SetupRouter() // SetPromptStudioHandlers never called
		if w := promptStudioRequest(t, router, http.MethodGet, psPathBase, rootCookie, ""); w.Code != http.StatusServiceUnavailable {
			t.Errorf("unwired GET prompts = %d, want 503", w.Code)
		}
		if w := promptStudioRequest(t, router, http.MethodGet, psPartBase, rootCookie, ""); w.Code != http.StatusServiceUnavailable {
			t.Errorf("unwired GET partials = %d, want 503", w.Code)
		}
	})
}

func TestPromptStudio_ValidationContract(t *testing.T) {
	adminCookie := makeSessionCookie(t, "admin@x.test", false, polSecret)
	newRouter := func() http.Handler {
		return promptStudioRouter(t, newPromptStudioStub(map[string]adminstore.OrgRole{psOrgA: adminstore.RoleOrgAdmin}))
	}

	t.Run("unknown JSON fields are rejected", func(t *testing.T) {
		router := newRouter()
		body := `{"name":"p","template":"t","plain_text_key":"nope"}`
		if w := promptStudioRequest(t, router, http.MethodPost, psPathBase, adminCookie, body); w.Code != http.StatusBadRequest {
			t.Errorf("POST unknown field = %d, want 400", w.Code)
		}
	})

	t.Run("empty template and params shape are 400", func(t *testing.T) {
		router := newRouter()
		if w := promptStudioRequest(t, router, http.MethodPost, psPathBase, adminCookie, `{"name":"p","template":"  "}`); w.Code != http.StatusBadRequest {
			t.Errorf("POST empty template = %d, want 400", w.Code)
		}
		if w := promptStudioRequest(t, router, http.MethodPost, psPathBase, adminCookie, `{"name":"p","template":"t","params":[1]}`); w.Code != http.StatusBadRequest {
			t.Errorf("POST array params = %d, want 400", w.Code)
		}
	})

	t.Run("empty name is a 400; duplicate name is a 409", func(t *testing.T) {
		router := newRouter()
		if w := promptStudioRequest(t, router, http.MethodPost, psPathBase, adminCookie, `{"name":"  ","template":"t"}`); w.Code != http.StatusBadRequest {
			t.Errorf("POST empty name = %d, want 400", w.Code)
		}
		ok := `{"name":"dup","template":"t"}`
		if w := promptStudioRequest(t, router, http.MethodPost, psPathBase, adminCookie, ok); w.Code != http.StatusCreated {
			t.Fatalf("POST first dup = %d, want 201", w.Code)
		}
		if w := promptStudioRequest(t, router, http.MethodPost, psPathBase, adminCookie, ok); w.Code != http.StatusConflict {
			t.Errorf("POST duplicate name = %d, want 409", w.Code)
		}
	})

	t.Run("PUT appends a version; labels promote; GET carries versions+labels", func(t *testing.T) {
		router := newRouter()
		w := promptStudioRequest(t, router, http.MethodPost, psPathBase, adminCookie,
			`{"name":"flow","template":`+policyJSONString(psTemplate)+`,"params":{"model":"gpt-4o-mini"}}`)
		if w.Code != http.StatusCreated {
			t.Fatalf("POST = %d, want 201 (body: %s)", w.Code, w.Body.String())
		}
		var created promptDetailPayload
		if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create: %v", err)
		}
		detail := psPathBase + "/" + created.Prompt.ID

		w = promptStudioRequest(t, router, http.MethodPut, detail, adminCookie,
			`{"version":1,"template":`+policyJSONString(psTemplate+" # v2")+`,"params":{"temperature":0.5}}`)
		if w.Code != http.StatusOK {
			t.Fatalf("PUT = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		var updated promptDetailPayload
		if err := json.Unmarshal(w.Body.Bytes(), &updated); err != nil {
			t.Fatalf("decode put: %v", err)
		}
		if len(updated.Versions) != 1 || updated.Versions[0].Version != 2 {
			t.Errorf("PUT version = %+v, want the appended v2", updated.Versions)
		}
		conflict := promptStudioRequest(t, router, http.MethodPut, detail, adminCookie, `{"version":1,"template":"stale"}`)
		if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), `"current_version":2`) {
			t.Errorf("stale PUT = %d %s, want 409 with current version 2", conflict.Code, conflict.Body.String())
		}

		// Labels: bad label is a 400; version must exist.
		w = promptStudioRequest(t, router, http.MethodPost, detail+"/labels", adminCookie, `{"label":"latest","version":1}`)
		if w.Code != http.StatusBadRequest {
			t.Errorf("POST bad label = %d, want 400", w.Code)
		}
		w = promptStudioRequest(t, router, http.MethodPost, detail+"/labels", adminCookie, `{"label":"active","version":99}`)
		if w.Code != http.StatusNotFound {
			t.Errorf("POST label with missing version = %d, want 404", w.Code)
		}
		w = promptStudioRequest(t, router, http.MethodPost, detail+"/labels", adminCookie, `{"label":"canary","version":2}`)
		if w.Code != http.StatusOK {
			t.Fatalf("POST canary label = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}

		// The full detail (versions newest first, labels) is the GET.
		w = promptStudioRequest(t, router, http.MethodGet, detail, adminCookie, "")
		if w.Code != http.StatusOK {
			t.Fatalf("GET detail = %d, want 200", w.Code)
		}
		var full promptDetailPayload
		if err := json.Unmarshal(w.Body.Bytes(), &full); err != nil {
			t.Fatalf("decode get: %v", err)
		}
		if len(full.Versions) != 2 || full.Versions[0].Version != 2 {
			t.Errorf("GET versions=%+v, want 2 versions newest first", full.Versions)
		}
		if len(full.Labels) != 2 {
			t.Fatalf("GET labels=%+v, want draft+canary", full.Labels)
		}
		for _, l := range full.Labels {
			if l.Label == "canary" && l.Version != 2 {
				t.Errorf("canary binding = %+v, want version 2", l)
			}
		}

		// DELETE removes the prompt.
		if w := promptStudioRequest(t, router, http.MethodDelete, detail, adminCookie, ""); w.Code != http.StatusOK {
			t.Errorf("DELETE = %d, want 200", w.Code)
		}
		if w := promptStudioRequest(t, router, http.MethodGet, detail, adminCookie, ""); w.Code != http.StatusNotFound {
			t.Errorf("GET after delete = %d, want 404", w.Code)
		}
	})

	t.Run("partials: create 409 on dup, PUT bumps, DELETE, foreign 404", func(t *testing.T) {
		router := newRouter()
		w := promptStudioRequest(t, router, http.MethodPost, psPartBase, adminCookie, `{"name":"rules","body":"RULE-1"}`)
		if w.Code != http.StatusCreated {
			t.Fatalf("POST partial = %d, want 201 (body: %s)", w.Code, w.Body.String())
		}
		if w := promptStudioRequest(t, router, http.MethodPost, psPartBase, adminCookie, `{"name":"rules","body":"dup"}`); w.Code != http.StatusConflict {
			t.Errorf("POST duplicate partial = %d, want 409", w.Code)
		}
		if w := promptStudioRequest(t, router, http.MethodPost, psPartBase, adminCookie, `{"name":"rules","body":""}`); w.Code != http.StatusBadRequest {
			t.Errorf("POST empty body = %d, want 400", w.Code)
		}
		if w := promptStudioRequest(t, router, http.MethodPut, psPartBase+"/rules", adminCookie, `{"version":1,"body":"RULE-1\nRULE-2"}`); w.Code != http.StatusOK {
			t.Errorf("PUT partial = %d, want 200", w.Code)
		}
		if w := promptStudioRequest(t, router, http.MethodPut, psPartBase+"/missing", adminCookie, `{"body":"x"}`); w.Code != http.StatusNotFound {
			t.Errorf("PUT missing partial = %d, want 404", w.Code)
		}
		if w := promptStudioRequest(t, router, http.MethodGet, psPartBase, adminCookie, ""); w.Code != http.StatusOK {
			t.Errorf("GET partials = %d, want 200", w.Code)
		}
		if w := promptStudioRequest(t, router, http.MethodDelete, psPartBase+"/rules", adminCookie, ""); w.Code != http.StatusOK {
			t.Errorf("DELETE partial = %d, want 200", w.Code)
		}
		if w := promptStudioRequest(t, router, http.MethodDelete, psPartBase+"/rules", adminCookie, ""); w.Code != http.StatusNotFound {
			t.Errorf("DELETE missing partial = %d, want 404", w.Code)
		}
	})
}
