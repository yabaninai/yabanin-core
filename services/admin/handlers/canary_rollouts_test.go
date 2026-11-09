package handlers_test

// the FULL SetupRouter (the policy_pipelines_test.go pattern):
//
//	anon                          → 401 (session boundary)
//	root                          → 200/201 (any org)
//	member with routing.manage    → 200/201 (org-admin/operator hold it)
//	member without the permission → 403
//	no membership                 → 404 (resourceHidden)
//	cross-org rolloutId           → 404
//	store not wired               → 503
//
// Validation: percent 1..99 whole numbers (D2), base != canary, content
// changes require the full triple, activation and rollback are the explicit
// PUT steps.

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
	canSecret = "test-session-secret" // #nosec G101 -- test-only HMAC key
	canCSRF   = "csrf-token-value"    // #nosec G101 -- test-only value
	canOrgA   = "org-a"
	canOrgB   = "org-foreign"
	canPath   = "/api/organizations/" + canOrgA + "/canary-rollouts"
)

// canaryStoreStub implements the handlers.CanaryRolloutStore contract over
// in-memory maps (policyStoreStub parity).
type canaryStoreStub struct {
	stubStore
	roles    map[string]adminstore.OrgRole
	rollouts map[string]adminstore.CanaryRollout
	versions map[string][]adminstore.CanaryRolloutVersion
	evidence map[string]adminstore.CanaryEvidence
	seq      int
}

func newCanaryStoreStub(roles map[string]adminstore.OrgRole) *canaryStoreStub {
	return &canaryStoreStub{
		roles:    roles,
		rollouts: map[string]adminstore.CanaryRollout{},
		versions: map[string][]adminstore.CanaryRolloutVersion{},
		evidence: map[string]adminstore.CanaryEvidence{},
	}
}

func (s *canaryStoreStub) GetUserOrgRoles(context.Context, string) (map[string]adminstore.OrgRole, error) {
	return s.roles, nil
}

func (s *canaryStoreStub) nameTaken(orgID, name string) bool {
	for _, r := range s.rollouts {
		if r.OrgID == orgID && r.Name == name {
			return true
		}
	}
	return false
}

func (s *canaryStoreStub) CreateCanaryRollout(_ context.Context, orgID, name, baseModel, canaryModel string, percent int, createdBy string) (adminstore.CanaryRollout, adminstore.CanaryRolloutVersion, error) {
	if s.nameTaken(orgID, name) {
		return adminstore.CanaryRollout{}, adminstore.CanaryRolloutVersion{}, fmt.Errorf(
			"rollout name %q already exists in this org: %w", name, &pgconn.PgError{Code: "23505", Message: "duplicate key"})
	}
	if err := adminstoreExportedValidate(baseModel, canaryModel, percent); err != nil {
		return adminstore.CanaryRollout{}, adminstore.CanaryRolloutVersion{}, err
	}
	s.seq++
	id := fmt.Sprintf("roll-%d", s.seq)
	r := adminstore.CanaryRollout{ID: id, OrgID: orgID, Name: name, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	s.rollouts[id] = r
	v := adminstore.CanaryRolloutVersion{
		ID: id + "-v1", RolloutID: id, OrgID: orgID, Version: 1,
		BaseModel: baseModel, CanaryModel: canaryModel, Percent: percent,
		Label: adminstore.CanaryLabelDraft, CreatedBy: createdBy, CreatedAt: time.Now(),
	}
	s.versions[id] = []adminstore.CanaryRolloutVersion{v}
	return r, v, nil
}

func (s *canaryStoreStub) GetCanaryRollout(_ context.Context, orgID, rolloutID string) (adminstore.CanaryRollout, error) {
	r, ok := s.rollouts[rolloutID]
	if !ok || r.OrgID != orgID {
		return adminstore.CanaryRollout{}, adminstore.ErrNotFound
	}
	return r, nil
}

func (s *canaryStoreStub) ListCanaryRollouts(_ context.Context, orgID string) ([]adminstore.CanaryRollout, error) {
	var out []adminstore.CanaryRollout
	for _, r := range s.rollouts {
		if r.OrgID == orgID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *canaryStoreStub) UpdateCanaryRollout(_ context.Context, orgID, rolloutID string, enabled bool) (adminstore.CanaryRollout, error) {
	r, ok := s.rollouts[rolloutID]
	if !ok || r.OrgID != orgID {
		return adminstore.CanaryRollout{}, adminstore.ErrNotFound
	}
	r.Enabled = enabled
	r.UpdatedAt = time.Now()
	s.rollouts[rolloutID] = r
	return r, nil
}

func (s *canaryStoreStub) CreateCanaryRolloutVersion(_ context.Context, orgID, rolloutID, baseModel, canaryModel string, percent int, createdBy string) (adminstore.CanaryRolloutVersion, error) {
	if err := adminstoreExportedValidate(baseModel, canaryModel, percent); err != nil {
		return adminstore.CanaryRolloutVersion{}, err
	}
	list := s.versions[rolloutID]
	v := adminstore.CanaryRolloutVersion{
		ID: fmt.Sprintf("%s-v%d", rolloutID, len(list)+1), RolloutID: rolloutID, OrgID: orgID,
		Version: len(list) + 1, BaseModel: baseModel, CanaryModel: canaryModel, Percent: percent,
		Label: adminstore.CanaryLabelDraft, CreatedBy: createdBy, CreatedAt: time.Now(),
	}
	s.versions[rolloutID] = append(list, v)
	return v, nil
}

func (s *canaryStoreStub) ListCanaryRolloutVersions(_ context.Context, orgID, rolloutID string) ([]adminstore.CanaryRolloutVersion, error) {
	if _, ok := s.rollouts[rolloutID]; !ok {
		return nil, adminstore.ErrNotFound
	}
	out := append([]adminstore.CanaryRolloutVersion(nil), s.versions[rolloutID]...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func (s *canaryStoreStub) SetActiveCanaryRolloutVersion(_ context.Context, orgID, rolloutID string, version int) (adminstore.CanaryRollout, error) {
	r, ok := s.rollouts[rolloutID]
	if !ok || r.OrgID != orgID || version < 1 || version > len(s.versions[rolloutID]) {
		return adminstore.CanaryRollout{}, adminstore.ErrNotFound
	}
	r.CurrentVersion = version
	s.rollouts[rolloutID] = r
	return r, nil
}

func (s *canaryStoreStub) DeleteCanaryRollout(_ context.Context, orgID, rolloutID string) error {
	r, ok := s.rollouts[rolloutID]
	if !ok || r.OrgID != orgID {
		return adminstore.ErrNotFound
	}
	delete(s.rollouts, rolloutID)
	delete(s.versions, rolloutID)
	return nil
}

func (s *canaryStoreStub) CanaryRolloutEvidence(_ context.Context, orgID, rolloutID string, _ time.Duration) (adminstore.CanaryEvidence, error) {
	if _, ok := s.rollouts[rolloutID]; !ok {
		return adminstore.CanaryEvidence{}, adminstore.ErrNotFound
	}
	return s.evidence[rolloutID], nil
}

// adminstoreExportedValidate mirrors the store validation bounds (the stub
// must reject what the store rejects so the handler mapping stays honest).
func adminstoreExportedValidate(baseModel, canaryModel string, percent int) error {
	if baseModel == "" || canaryModel == "" || baseModel == canaryModel {
		return fmt.Errorf("invalid rollout content")
	}
	if percent < 1 || percent > 99 {
		return fmt.Errorf("canary percent must be a whole number between 1 and 99")
	}
	return nil
}

func canaryRouter(t *testing.T, store *canaryStoreStub) http.Handler {
	t.Helper()
	h := handlers.New(store, canSecret, "localhost", nil)
	h.SetCanaryRolloutHandlers(handlers.NewCanaryRolloutHandlers(store))
	return h.SetupRouter()
}

// canaryRequest runs one request through the router with the session + CSRF
// double-submit pair (policyRequest parity).
func canaryRequest(t *testing.T, router http.Handler, method, path, cookie, body string) *httptest.ResponseRecorder {
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
		req.AddCookie(testCookie("yabanin_csrf_token", canCSRF))
		req.Header.Set("X-CSRF-Token", canCSRF)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

const canCreateBody = `{"name":"glm-migration","base_model":"glm-4.5","canary_model":"glm-5.3","percent":10}`

func TestCanaryRollouts_RoutingContract(t *testing.T) {
	anonCookie := ""
	rootCookie := makeSessionCookie(t, "root@x.test", true, canSecret)
	adminCookie := makeSessionCookie(t, "admin@x.test", false, canSecret)

	t.Run("anon is 401 on read and write (session boundary)", func(t *testing.T) {
		router := canaryRouter(t, newCanaryStoreStub(nil))
		if w := canaryRequest(t, router, http.MethodGet, canPath, anonCookie, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("anon GET rollouts = %d, want 401", w.Code)
		}
		if w := canaryRequest(t, router, http.MethodPost, canPath, anonCookie, canCreateBody); w.Code != http.StatusUnauthorized {
			t.Errorf("anon POST rollouts = %d, want 401", w.Code)
		}
	})

	t.Run("root reads and writes any org", func(t *testing.T) {
		router := canaryRouter(t, newCanaryStoreStub(nil))
		if w := canaryRequest(t, router, http.MethodPost, canPath, rootCookie, canCreateBody); w.Code != http.StatusCreated {
			t.Fatalf("root POST rollouts = %d, want 201 (body: %s)", w.Code, w.Body.String())
		}
		if w := canaryRequest(t, router, http.MethodGet, canPath, rootCookie, ""); w.Code != http.StatusOK {
			t.Errorf("root GET rollouts = %d, want 200", w.Code)
		}
	})

	t.Run("org-admin member reads and writes; a role without routing.manage is 403", func(t *testing.T) {
		adminRoles := map[string]adminstore.OrgRole{canOrgA: adminstore.RoleOrgAdmin}
		router := canaryRouter(t, newCanaryStoreStub(adminRoles))
		if w := canaryRequest(t, router, http.MethodPost, canPath, adminCookie, canCreateBody); w.Code != http.StatusCreated {
			t.Fatalf("org-admin POST rollouts = %d, want 201 (body: %s)", w.Code, w.Body.String())
		}

		// reader holds neither routing.manage nor policies.manage → 403.
		readerRouter := canaryRouter(t, newCanaryStoreStub(map[string]adminstore.OrgRole{canOrgA: adminstore.RoleReader}))
		if w := canaryRequest(t, readerRouter, http.MethodGet, canPath, adminCookie, ""); w.Code != http.StatusForbidden {
			t.Errorf("reader GET rollouts = %d, want 403", w.Code)
		}
	})

	t.Run("operator holds routing.manage", func(t *testing.T) {
		// The exact separation the policy handlers' comment draws: an
		// operator manages model choice (routing.manage → rollouts) but not
		// guardrails (policies.manage).
		operatorRouter := canaryRouter(t, newCanaryStoreStub(map[string]adminstore.OrgRole{canOrgA: adminstore.RoleOperator}))
		if w := canaryRequest(t, operatorRouter, http.MethodGet, canPath, adminCookie, ""); w.Code != http.StatusOK {
			t.Errorf("operator GET rollouts = %d, want 200 (routing.manage)", w.Code)
		}
	})

	t.Run("non-member gets 404 without revealing the org", func(t *testing.T) {
		router := canaryRouter(t, newCanaryStoreStub(map[string]adminstore.OrgRole{}))
		foreign := "/api/organizations/" + canOrgB + "/canary-rollouts"
		if w := canaryRequest(t, router, http.MethodGet, foreign, adminCookie, ""); w.Code != http.StatusNotFound {
			t.Errorf("non-member GET foreign org = %d, want 404 (resourceHidden)", w.Code)
		}
	})

	t.Run("cross-org rolloutId is the same 404", func(t *testing.T) {
		store := newCanaryStoreStub(map[string]adminstore.OrgRole{canOrgA: adminstore.RoleOrgAdmin})
		r, _, err := store.CreateCanaryRollout(context.Background(), canOrgB, "secret-roll", "a", "b", 10, "")
		if err != nil {
			t.Fatalf("seed foreign rollout: %v", err)
		}
		router := canaryRouter(t, store)
		foreignDetail := canPath + "/" + r.ID
		if w := canaryRequest(t, router, http.MethodGet, foreignDetail, adminCookie, ""); w.Code != http.StatusNotFound {
			t.Errorf("GET foreign rolloutId = %d, want 404", w.Code)
		}
		if w := canaryRequest(t, router, http.MethodDelete, foreignDetail, adminCookie, ""); w.Code != http.StatusNotFound {
			t.Errorf("DELETE foreign rolloutId = %d, want 404", w.Code)
		}
	})

	t.Run("unwired store answers 503 with routes still mounted", func(t *testing.T) {
		h := handlers.New(newCanaryStoreStub(nil), canSecret, "localhost", nil)
		router := h.SetupRouter() // SetCanaryRolloutHandlers never called
		if w := canaryRequest(t, router, http.MethodGet, canPath, rootCookie, ""); w.Code != http.StatusServiceUnavailable {
			t.Errorf("unwired GET rollouts = %d, want 503", w.Code)
		}
	})
}

func TestCanaryRollouts_LifecycleContract(t *testing.T) {
	adminCookie := makeSessionCookie(t, "admin@x.test", false, canSecret)
	store := newCanaryStoreStub(map[string]adminstore.OrgRole{canOrgA: adminstore.RoleOrgAdmin})
	router := canaryRouter(t, store)

	// Create → v1 draft, detached.
	w := canaryRequest(t, router, http.MethodPost, canPath, adminCookie, canCreateBody)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST = %d, want 201 (body: %s)", w.Code, w.Body.String())
	}
	var created struct {
		Rollout  adminstore.CanaryRollout          `json:"rollout"`
		Versions []adminstore.CanaryRolloutVersion `json:"versions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	detail := canPath + "/" + created.Rollout.ID
	if created.Rollout.Enabled || created.Rollout.CurrentVersion != 0 {
		t.Errorf("created rollout = %+v, want detached with no active version", created.Rollout)
	}

	// Ramp to 25% (full triple appends v2) + activate + attach in ONE PUT.
	w = canaryRequest(t, router, http.MethodPut, detail, adminCookie,
		`{"base_model":"glm-4.5","canary_model":"glm-5.3","percent":25,"active_version":2,"enabled":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT ramp+activate = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var got struct {
		Rollout adminstore.CanaryRollout `json:"rollout"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode put: %v", err)
	}
	if got.Rollout.CurrentVersion != 2 || !got.Rollout.Enabled {
		t.Errorf("PUT state = %+v, want current_version 2 enabled", got.Rollout)
	}

	// Rollback is the explicit enabled=false (D3).
	w = canaryRequest(t, router, http.MethodPut, detail, adminCookie, `{"enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT rollback = %d, want 200", w.Code)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode rollback: %v", err)
	}
	if got.Rollout.Enabled {
		t.Errorf("rollback left the rollout enabled: %+v", got.Rollout)
	}
	if got.Rollout.CurrentVersion != 2 {
		t.Errorf("rollback must not touch version history: %+v", got.Rollout)
	}

	// Recommendation endpoint (evidence only).
	w = canaryRequest(t, router, http.MethodGet, detail+"/recommendation", adminCookie, "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET recommendation = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var rec struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatalf("decode recommendation: %v", err)
	}
	if rec.Action != "manual" {
		t.Errorf("recommendation action = %q, want manual (D3: no auto-rollback)", rec.Action)
	}
}

func TestCanaryRollouts_ValidationContract(t *testing.T) {
	adminCookie := makeSessionCookie(t, "admin@x.test", false, canSecret)
	newRouter := func() http.Handler {
		return canaryRouter(t, newCanaryStoreStub(map[string]adminstore.OrgRole{canOrgA: adminstore.RoleOrgAdmin}))
	}

	t.Run("percent 0 and 100 are 400s (whole 1..99, D2)", func(t *testing.T) {
		router := newRouter()
		for _, bad := range []string{`"percent":0`, `"percent":100`, `"percent":-1`} {
			body := `{"name":"bad","base_model":"a","canary_model":"b",` + bad + `}`
			if w := canaryRequest(t, router, http.MethodPost, canPath, adminCookie, body); w.Code != http.StatusBadRequest {
				t.Errorf("POST %s = %d, want 400", bad, w.Code)
			}
		}
	})

	t.Run("base == canary is a 400", func(t *testing.T) {
		router := newRouter()
		body := `{"name":"same","base_model":"m","canary_model":"m","percent":10}`
		if w := canaryRequest(t, router, http.MethodPost, canPath, adminCookie, body); w.Code != http.StatusBadRequest {
			t.Errorf("POST base==canary = %d, want 400", w.Code)
		}
	})

	t.Run("duplicate name is a 409", func(t *testing.T) {
		router := newRouter()
		if w := canaryRequest(t, router, http.MethodPost, canPath, adminCookie, canCreateBody); w.Code != http.StatusCreated {
			t.Fatalf("first create = %d", w.Code)
		}
		if w := canaryRequest(t, router, http.MethodPost, canPath, adminCookie, canCreateBody); w.Code != http.StatusConflict {
			t.Errorf("duplicate create = %d, want 409", w.Code)
		}
	})

	t.Run("partial content triple is a 400; empty PUT is a 400; unknown fields are 400", func(t *testing.T) {
		router := newRouter()
		w := canaryRequest(t, router, http.MethodPost, canPath, adminCookie, canCreateBody)
		if w.Code != http.StatusCreated {
			t.Fatalf("create = %d (body %s)", w.Code, w.Body.String())
		}
		var created struct {
			Rollout adminstore.CanaryRollout `json:"rollout"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &created)
		detail := canPath + "/" + created.Rollout.ID

		if w := canaryRequest(t, router, http.MethodPut, detail, adminCookie, `{"percent":50}`); w.Code != http.StatusBadRequest {
			t.Errorf("partial triple PUT = %d, want 400", w.Code)
		}
		if w := canaryRequest(t, router, http.MethodPut, detail, adminCookie, `{}`); w.Code != http.StatusBadRequest {
			t.Errorf("empty PUT = %d, want 400", w.Code)
		}
		if w := canaryRequest(t, router, http.MethodPut, detail, adminCookie, `{"percentx":50}`); w.Code != http.StatusBadRequest {
			t.Errorf("unknown field PUT = %d, want 400", w.Code)
		}
	})
}
