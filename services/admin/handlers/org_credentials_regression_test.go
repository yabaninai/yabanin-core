package handlers_test

// the working discovery path end to end, as observable behavior — a stored
// credential discovered through POST …/{credId}/models returns the parsed
// catalog as a display-only snapshot (discovered=true, verified=false) with
// exactly one upstream call carrying the STORED key, every refusal stays
// honest and diagnosable while the manual-entry fallback remains the only
// registration path, and no key material ever reaches a response body, a
// response header, or a log line.
//
// and the package acceptance criterion «Fallback ручного ввода; discovery не
// означает verified usability». The boundary matrix (cap boundaries,
// malformed entries, throttle shapes, foreign tenants, cancellation, dashboard
// state machine) is NOT duplicated here — see TestOrgCredentialModelsEndpoint,
// TestOrgCredentialModelsEndpointBoundaries and TestParseModelCatalog*.
//
// upstream-call accounting, display-only posture) run against the assertions
// in this file and in providerKeysRegression.test.ts; every mutation run is
// recorded with exact commands and exit codes in

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

const (
	// regressionKey is the stored plaintext for these scenarios — distinct
	// from credKeyOK so a leak of the RESOLVED key cannot hide behind the
	// create payload or the other fixtures. #nosec G101 -- test-only fake.
	regressionKey = "sk-regression-discovery-stored-0042"
	// regressionRotatedKey is the rotation target in the revoked-key
	// scenario. #nosec G101 -- test-only fake.
	regressionRotatedKey = "sk-regression-discovery-rotated-7777"
	// regressionCatalog is the OpenAI-compat list body from contract
	// Example A (the same wire format the gateway emits).
	regressionCatalog = `{"object":"list","data":[{"id":"example-large","object":"model"},{"id":"example-mini","object":"model"}]}`
)

// regressionStore is credStoreStub plus a working in-memory models registry:
// the manual-entry fallback (root-only POST /api/models) must stay functional
// through every discovery outcome, so the scenario store implements the
// registry surface the credential stub leaves at errStub. Discovery must
// never touch this registry — registrySize is the display-only pin.
type regressionStore struct {
	*credStoreStub
	mu       sync.Mutex
	registry map[string]*adminstore.ModelRegistry
	seq      int
}

func newRegressionStore(roles map[string]adminstore.OrgRole) *regressionStore {
	return &regressionStore{
		credStoreStub: newCredStoreStub(roles),
		registry:      map[string]*adminstore.ModelRegistry{},
	}
}

func (s *regressionStore) CreateModelWithParams(_ context.Context, p adminstore.CreateModelParams) (*adminstore.ModelRegistry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	m := &adminstore.ModelRegistry{
		ID:          fmt.Sprintf("model-%d", s.seq),
		ModelName:   p.ModelName,
		DisplayName: p.DisplayName,
		Tier:        p.Tier,
		Provider:    p.Provider,
		Enabled:     true,
		CreatedAt:   time.Now(),
	}
	s.registry[p.ModelName] = m
	return m, nil
}

func (s *regressionStore) ListModels(_ context.Context, _ adminstore.PageFilter) ([]*adminstore.ModelRegistry, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*adminstore.ModelRegistry, 0, len(s.registry))
	for _, m := range s.registry {
		out = append(out, m)
	}
	return out, int64(len(out)), nil
}

func (s *regressionStore) registrySize() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.registry)
}

// seedKey inserts a credential with an explicit plaintext (unlike
// credStoreStub.seed, which pins credKeyOK) so scenarios can store
// regressionKey directly and prove discovery resolves exactly that key.
func (s *regressionStore) seedKey(orgID, baseURL, plaintext string) handlers.OrgCredential {
	c, err := s.Create(context.Background(), orgID, "seeded-regression", "openai", baseURL, plaintext)
	if err != nil {
		panic(err)
	}
	return c
}

// regressionEnv wires one hermetic scenario: the full SetupRouter (session +
// CSRF + org gate) with the credential handlers over regressionStore, a
// captured slog buffer (the zero-log-leak assertion) and a version bumper
// (the display-only pin).
type regressionEnv struct {
	store  *regressionStore
	router http.Handler
	bumper *credBumper
	logs   *bytes.Buffer
}

func newRegressionEnv(t *testing.T, store *regressionStore, opts handlers.OrgCredentialHandlerOptions) *regressionEnv {
	t.Helper()
	logs := &bytes.Buffer{}
	bumper := &credBumper{}
	opts.VersionBumper = bumper
	h := handlers.New(store, credSecret, "localhost", nil)
	h.SetOrgCredentialHandlers(handlers.NewOrgCredentialHandlers(store, opts, slog.New(slog.NewTextHandler(logs, nil))))
	return &regressionEnv{store: store, router: h.SetupRouter(), bumper: bumper, logs: logs}
}

// noKeyMaterial is the zero-key-leak regression assertion: the stored
// plaintext may appear in NO response body, NO response header and NO log
func noKeyMaterial(t *testing.T, w *httptest.ResponseRecorder, logs *bytes.Buffer) {
	t.Helper()
	if strings.Contains(w.Body.String(), regressionKey) {
		t.Fatalf("response body leaks the stored key: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), regressionRotatedKey) {
		t.Fatalf("response body leaks the rotated key: %s", w.Body.String())
	}
	for name, values := range w.Header() {
		for _, v := range values {
			if strings.Contains(v, regressionKey) || strings.Contains(v, regressionRotatedKey) {
				t.Fatalf("response header %q leaks key material: %s", name, v)
			}
		}
	}
	if logs != nil {
		if leaked := logs.String(); strings.Contains(leaked, regressionKey) || strings.Contains(leaked, regressionRotatedKey) {
			t.Fatalf("log output leaks key material: %s", leaked)
		}
	}
}

// catalogUpstream is a loopback fake provider: it counts every hit, records
// the last Authorization header and serves a switchable status/body so one
// scenario can walk refusal → rotation → success against a single server.
type catalogUpstream struct {
	mu   sync.Mutex
	hits int
	auth string
	code int
	body string
	srv  *httptest.Server
}

func newCatalogUpstream(t *testing.T, code int, body string) *catalogUpstream {
	t.Helper()
	u := &catalogUpstream{code: code, body: body}
	// TLS so the stored credential's base_url can be created through the
	// public https-only POST contract; srv.Client() trusts the test cert.
	u.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.hits++
		u.auth = r.Header.Get("Authorization")
		code, body := u.code, u.body
		u.mu.Unlock()
		if r.URL.Path != "/v1/models" {
			t.Errorf("upstream path = %q, want /v1/models", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

// serve flips the canned answer (the rotation scenario reuses one server).
func (u *catalogUpstream) serve(code int, body string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.code, u.body = code, body
}

func (u *catalogUpstream) hitCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits
}

func (u *catalogUpstream) gotAuth() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.auth
}

// storeCredential creates the credential through the public POST contract
// (like the contract example) and returns the row.
func storeCredential(t *testing.T, router http.Handler, cookie, baseURL string) handlers.OrgCredential {
	t.Helper()
	w := credRequest(t, router, http.MethodPost, credPathList, cookie,
		credCreateBody("openai-compat", baseURL, regressionKey))
	if w.Code != http.StatusCreated {
		t.Fatalf("credential create = %d, want 201 (body: %s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), regressionKey) {
		t.Fatalf("create response leaks the plaintext key: %s", w.Body.String())
	}
	var cred handlers.OrgCredential
	if err := json.Unmarshal(w.Body.Bytes(), &cred); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	return cred
}

// regressionCatalogWire mirrors credCatalogResult as the scenarios read it.
type regressionCatalogWire struct {
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

// manualEntry registers one model through the root-only registry API (the
// fallback) and asserts the create response leaks nothing.
func manualEntry(t *testing.T, router http.Handler, logs *bytes.Buffer) {
	t.Helper()
	w := credRequest(t, router, http.MethodPost, "/api/models", credRootCookie(t),
		`{"model_name":"example-large","display_name":"Example Large","tier":"standard"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("manual model create = %d, want 201 (body: %s)", w.Code, w.Body.String())
	}
	noKeyMaterial(t, w, logs)
}

// registryRows reads GET /api/models (the registry the fallback writes to).
func registryRows(t *testing.T, router http.Handler, logs *bytes.Buffer) ([]struct {
	ModelName string `json:"model_name"`
}, int) {
	t.Helper()
	w := credRequest(t, router, http.MethodGet, "/api/models", credRootCookie(t), "")
	if w.Code != http.StatusOK {
		t.Fatalf("registry list = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	noKeyMaterial(t, w, logs)
	var page struct {
		Data []struct {
			ModelName string `json:"model_name"`
		} `json:"data"`
		Pagination struct {
			Total int `json:"total"`
		} `json:"pagination"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode registry page: %v", err)
	}
	return page.Data, page.Pagination.Total
}

// TestOrgCredentialDiscoveryRegressionScenarioA pins contract Example A end
// to end: the operator stores the key, discovery answers with the parsed
// catalog (discovered=true, verified=false) after EXACTLY ONE upstream call
// carrying the stored key as Bearer; nothing is persisted anywhere; the
// manual-entry fallback registers the only model that ever reaches the
// registry.
func TestOrgCredentialDiscoveryRegressionScenarioA(t *testing.T) {
	upstream := newCatalogUpstream(t, http.StatusOK, regressionCatalog)
	env := newRegressionEnv(t, newRegressionStore(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin}),
		handlers.OrgCredentialHandlerOptions{HTTPClient: upstream.srv.Client()})
	cookie := credMemberCookie(t)

	cred := storeCredential(t, env.router, cookie, upstream.srv.URL+"/v1")
	if cred.KeyLast4 != "0042" || !cred.Enabled || cred.KeyVersion != 1 {
		t.Fatalf("stored row = %+v, want last4 0042, enabled, version 1", cred)
	}
	bumpsAfterCreate := len(env.bumper.bumped()) // the create is a CRUD — it legitimately bumps

	w := credRequest(t, env.router, http.MethodPost, credPathList+"/"+cred.ID+"/models", cookie, "")
	if w.Code != http.StatusOK {
		t.Fatalf("models = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	noKeyMaterial(t, w, env.logs)
	var res regressionCatalogWire
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	if !res.Discovered || res.Verified == nil || *res.Verified {
		t.Fatalf("snapshot flags = %+v, want discovered=true with an explicit verified=false (discovery is not verified usability)", res)
	}
	if res.Reason != "" || res.Error != "" || res.Status != 0 {
		t.Errorf("snapshot carries refusal metadata: %+v", res)
	}
	if res.Count != 2 || len(res.Data) != 2 || res.Data[0] != "example-large" || res.Data[1] != "example-mini" {
		t.Errorf("catalog = %v (count %d), want [example-large example-mini]", res.Data, res.Count)
	}
	if res.Provider != "openai-compat" || res.BaseURL != upstream.srv.URL+"/v1" {
		t.Errorf("provider/base_url = %q/%q, want openai-compat/%s", res.Provider, res.BaseURL, upstream.srv.URL+"/v1")
	}

	// Exactly one upstream call, with the STORED key (resolved server-side —
	// the discovery request itself carries no key).
	if got := upstream.hitCount(); got != 1 {
		t.Errorf("upstream hits = %d, want exactly 1", got)
	}
	if got := upstream.gotAuth(); got != "Bearer "+regressionKey {
		t.Errorf("upstream Authorization = %q, want the stored key as bearer", got)
	}

	// Display-only: the success snapshot persisted nothing — no registry row,
	// no NEW version bump (beyond the create's own), the credential row untouched.
	if got := env.store.registrySize(); got != 0 {
		t.Errorf("registry rows after discovery = %d, want 0 (display-only, D-3)", got)
	}
	if bumps := len(env.bumper.bumped()); bumps != bumpsAfterCreate {
		t.Errorf("version bumps = %v, want none from discovery (discovery is not a CRUD)", env.bumper.bumped())
	}

	// Manual-entry fallback untouched: discovery did not pre-populate or
	// block the registry — the operator registers the model by hand and that
	// is the only row that ever appears.
	manualEntry(t, env.router, env.logs)
	rows, total := registryRows(t, env.router, env.logs)
	if total != 1 || len(rows) != 1 || rows[0].ModelName != "example-large" {
		t.Fatalf("registry after manual entry = %v (total %d), want exactly [example-large]", rows, total)
	}
}

// TestOrgCredentialDiscoveryRegressionScenariosB pins the three
// package-criterion refusals (contract §6 B) at scenario level: each is an
// honest, diagnosable, non-echoing 200 snapshot after exactly one upstream
// probe; the credential stays enabled (a listing refusal is NOT a broken
// credential); nothing persists; the manual-entry fallback still works.
func TestOrgCredentialDiscoveryRegressionScenariosB(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		wantReason string
	}{
		{"list API absent (404)", http.StatusNotFound, "models_list_unavailable"},
		{"key without list permission (403)", http.StatusForbidden, "key_forbidden"},
		{"revoked key (401)", http.StatusUnauthorized, "key_unauthorized"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := newCatalogUpstream(t, tc.status, `{"error":{"message":"upstream secret detail"}}`)
			env := newRegressionEnv(t, newRegressionStore(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin}),
				handlers.OrgCredentialHandlerOptions{HTTPClient: upstream.srv.Client()})
			cookie := credMemberCookie(t)
			cred := storeCredential(t, env.router, cookie, upstream.srv.URL+"/v1")

			w := credRequest(t, env.router, http.MethodPost, credPathList+"/"+cred.ID+"/models", cookie, "")
			if w.Code != http.StatusOK {
				t.Fatalf("models = %d, want 200 (a refusal is a state, not a failed call)", w.Code)
			}
			noKeyMaterial(t, w, env.logs)
			var res regressionCatalogWire
			if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
				t.Fatalf("decode refusal: %v", err)
			}
			if res.Discovered || res.Reason != tc.wantReason || res.Status != tc.status || res.Count != 0 || res.Data != nil {
				t.Fatalf("refusal = %+v, want %s with no catalog data", res, tc.wantReason)
			}
			if strings.Contains(w.Body.String(), "upstream secret detail") {
				t.Errorf("refusal echoes the upstream body: %s", w.Body.String())
			}
			if got := upstream.hitCount(); got != 1 {
				t.Errorf("upstream hits = %d, want exactly 1 (diagnosable, bounded)", got)
			}

			// The credential is NOT disabled and nothing was persisted; the
			// manual-entry fallback remains available. (The create bumped the
			// version once — discovery must add no bump of its own.)
			if env.store.registrySize() != 0 || len(env.bumper.bumped()) != 1 {
				t.Errorf("refused discovery mutated state: registry=%d bumps=%v",
					env.store.registrySize(), env.bumper.bumped())
			}
			manualEntry(t, env.router, env.logs)
			if _, total := registryRows(t, env.router, env.logs); total != 1 {
				t.Fatalf("registry total after manual entry = %d, want 1 (fallback untouched)", total)
			}
		})
	}

	// Revoked key, continued: the existing PUT rotation contract repairs the
	// credential, and the NEXT discovery follows the rotated stored key.
	t.Run("revoked key: refusal then rotation, discovery follows the new stored key", func(t *testing.T) {
		upstream := newCatalogUpstream(t, http.StatusUnauthorized, `{"error":{"message":"invalid api key"}}`)
		store := newRegressionStore(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
		env := newRegressionEnv(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: upstream.srv.Client()})
		cookie := credMemberCookie(t)
		cred := storeCredential(t, env.router, cookie, upstream.srv.URL+"/v1")

		w := credRequest(t, env.router, http.MethodPost, credPathList+"/"+cred.ID+"/models", cookie, "")
		var res regressionCatalogWire
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode refusal: %v", err)
		}
		if res.Discovered || res.Reason != "key_unauthorized" || res.Status != http.StatusUnauthorized {
			t.Fatalf("refusal = %+v, want key_unauthorized/401", res)
		}

		// Rotate through the existing contract (key_version bumps, plaintexts
		// — old or new — never appear in the response).
		w = credRequest(t, env.router, http.MethodPut, credPathList+"/"+cred.ID, cookie,
			`{"api_key":"`+regressionRotatedKey+`"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("rotation = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		noKeyMaterial(t, w, env.logs)
		var rotated handlers.OrgCredential
		if err := json.Unmarshal(w.Body.Bytes(), &rotated); err != nil {
			t.Fatalf("decode rotation: %v", err)
		}
		if rotated.KeyVersion != 2 || rotated.KeyLast4 != "7777" {
			t.Errorf("rotated row = version %d last4 %q, want 2/7777", rotated.KeyVersion, rotated.KeyLast4)
		}

		// The refusal spent the org's probe budget: the next discovery runs
		// on a fresh router (fresh throttle) over the SAME store — and must
		// use the rotated key upstream.
		env2 := newRegressionEnv(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: upstream.srv.Client()})
		upstream.serve(http.StatusOK, regressionCatalog)
		w = credRequest(t, env2.router, http.MethodPost, credPathList+"/"+cred.ID+"/models", cookie, "")
		if w.Code != http.StatusOK {
			t.Fatalf("models after rotation = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		noKeyMaterial(t, w, env2.logs)
		var snap regressionCatalogWire
		if err := json.Unmarshal(w.Body.Bytes(), &snap); err != nil {
			t.Fatalf("decode snapshot: %v", err)
		}
		if !snap.Discovered || snap.Count != 2 {
			t.Fatalf("snapshot after rotation = %+v, want the parsed catalog", snap)
		}
		if got := upstream.gotAuth(); got != "Bearer "+regressionRotatedKey {
			t.Errorf("upstream Authorization after rotation = %q, want the rotated stored key as bearer", got)
		}
		if got := upstream.hitCount(); got != 2 {
			t.Errorf("upstream hits = %d, want exactly 2 (refusal + post-rotation discovery)", got)
		}
	})
}

// TestOrgCredentialDiscoveryRegressionScenarioC pins the SSRF boundary
// scenario (contract §6 C3): a loopback upstream is refused by the guarded
// production client before any bytes — and before the key — leave; the
// answer is an honest transport_error and the key material appears NOWHERE
// turn red.
func TestOrgCredentialDiscoveryRegressionScenarioC(t *testing.T) {
	upstream := newCatalogUpstream(t, http.StatusOK, regressionCatalog)
	store := newRegressionStore(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin})
	env := newRegressionEnv(t, store, handlers.OrgCredentialHandlerOptions{})
	cred := store.seedKey(credOrgA, upstream.srv.URL, regressionKey) // http://127.0.0.1:port — reserved

	w := credRequest(t, env.router, http.MethodPost, credPathList+"/"+cred.ID+"/models", credMemberCookie(t), "")
	if w.Code != http.StatusOK {
		t.Fatalf("models = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	noKeyMaterial(t, w, env.logs)
	var res regressionCatalogWire
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Discovered || res.Reason != "transport_error" || res.Error == "" {
		t.Fatalf("result = %+v, want an honest transport_error", res)
	}
	if strings.Contains(res.Error, regressionKey) {
		t.Fatal("transport error text carries the stored key")
	}
	if got := upstream.hitCount(); got != 0 {
		t.Errorf("upstream hits = %d, want 0 (the guarded client refused before dialing)", got)
	}
	if env.store.registrySize() != 0 || len(env.bumper.bumped()) != 0 {
		t.Errorf("refused discovery mutated state: registry=%d bumps=%v",
			env.store.registrySize(), env.bumper.bumped())
	}
}

// TestOrgCredentialDiscoveryRegressionScenarioD pins upstream-call
// accounting on the throttle seam: the FIRST discovery dials once; the
// throttled repeat answers 429 with NO catalog payload and NEVER reaches the
// red (a denied call reaching upstream would push hits past 1).
func TestOrgCredentialDiscoveryRegressionScenarioD(t *testing.T) {
	upstream := newCatalogUpstream(t, http.StatusOK, regressionCatalog)
	env := newRegressionEnv(t, newRegressionStore(map[string]adminstore.OrgRole{credOrgA: adminstore.RoleOrgAdmin}),
		handlers.OrgCredentialHandlerOptions{HTTPClient: upstream.srv.Client()})
	cookie := credMemberCookie(t)
	cred := storeCredential(t, env.router, cookie, upstream.srv.URL+"/v1")

	if w := credRequest(t, env.router, http.MethodPost, credPathList+"/"+cred.ID+"/models", cookie, ""); w.Code != http.StatusOK {
		t.Fatalf("first models = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}

	w := credRequest(t, env.router, http.MethodPost, credPathList+"/"+cred.ID+"/models", cookie, "")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled repeat = %d, want 429 (body: %s)", w.Code, w.Body.String())
	}
	noKeyMaterial(t, w, env.logs)
	var api struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &api); err != nil {
		t.Fatalf("decode 429: %v", err)
	}
	if !strings.Contains(api.Error, "rate limit") {
		t.Errorf("429 error = %q, want a diagnosable rate-limit reason", api.Error)
	}
	if strings.Contains(w.Body.String(), "discovered") || strings.Contains(w.Body.String(), `"data"`) {
		t.Errorf("429 body carries a catalog payload: %s", w.Body.String())
	}
	if got := upstream.hitCount(); got != 1 {
		t.Errorf("upstream hits = %d, want exactly 1 (the throttled call never dials)", got)
	}
}
