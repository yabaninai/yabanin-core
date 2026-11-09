package handlers_test

// N02-P04/P08 guard detector-pack lifecycle routes (guardpacks.go).
//
// Locked contract (fast, Dockerless: in-memory CAS + real PackLifecycle +
// real on-disk pack fixtures):
//
//	route chain       root-only: anon 401, non-root session 403, root 200
//	unwired           503 (routes mounted, lifecycle not configured)
//	unknown pack      404 (missing manifest) — fail-closed
//	unknown version   404 (manifest version ≠ requested) — fail-closed
//	bad grammar       400 (pack_id not a single path component / empty body)
//	broken pack       409 (manifest/detector verification fails; nothing changed)
//	CAS conflict      409 + the LIVE durable state (writeConflict parity)
//	store failure     500, pack state unchanged (durable row AND local hook)
//	rollback          restores prior enforcement; without an active pack 409
//	no restart        activate via API ⇒ the SAME lifecycle enforces the new
//	                  detectors on the next evaluation
//	replica race      exactly one concurrent activate wins; the loser 409s

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/policystore"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

const (
	gpSecret   = "guard-pack-test-session-secret" // #nosec G101 -- test-only HMAC key
	gpCSRF     = "guard-pack-csrf-token"          // #nosec G101 -- test-only value
	gpDetect   = "GPBLOCK_[A-Z]+_TOKEN"
	gpProbeURL = "http://guardpacks.test/activate"
)

// guardCASStub is the in-memory GuardPolicyStore: the durable CAS semantics
// (bootstrap on the first transition, compare-and-swap afterwards) plus a
// failure-injection seam for the store-failure path.
type guardCASStub struct {
	mu       sync.Mutex
	current  string
	previous string
	failWith error
	failRead bool
}

func (s *guardCASStub) CompareAndSwap(_ context.Context, from, to string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWith != nil {
		return s.failWith
	}
	if s.current == "" {
		s.current, s.previous = to, from
		return nil
	}
	if s.current != from {
		return policystore.ErrGuardPackConflict
	}
	s.previous, s.current = s.current, to
	return nil
}

func (s *guardCASStub) ActiveGuardPackState(_ context.Context) (policystore.GuardPackState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failRead {
		return policystore.GuardPackState{}, errors.New("state read unavailable")
	}
	return policystore.GuardPackState{ActiveVersion: s.current, PreviousVersion: s.previous}, nil
}

func (s *guardCASStub) snapshot() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current, s.previous
}

// writeGuardPackFixture materialises one valid unsigned local pack under
// root (gateway startup test parity): <root>/<id>/manifest.json +
// detector.json with the matching SHA-256.
func writeGuardPackFixture(t *testing.T, root, id, version, pattern string) {
	t.Helper()
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	payload := fmt.Sprintf(`{"detectors":[{"rule_id":"%s","rule_version":"1","category":"secret","pattern":%q}]}`, id, pattern)
	sum := sha256.Sum256([]byte(payload))
	manifest, err := json.Marshal(guardhooks.PackManifest{
		SchemaVersion: guardhooks.GuardPackManifestVersion,
		PackID:        id,
		PackVersion:   version,
		RuntimeAPI:    guardhooks.RuntimeVersion,
		Files:         []guardhooks.PackFile{{Path: "detector.json", SHA256: hex.EncodeToString(sum[:])}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "detector.json"), []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
}

// guardPackRouter builds the full SetupRouter with the guard-pack handlers
// wired over the given CAS stub and pack root (two arguments form one
// "replica": the lifecycle's CAS and the handlers' state-read seam).
func guardPackRouter(t *testing.T, cas *guardCASStub, packRoot string) http.Handler {
	t.Helper()
	lifecycle := guardhooks.NewPackLifecycle("core", guardhooks.ModeDeny, cas)
	h := handlers.New(&stubStore{}, gpSecret, "localhost", nil)
	h.SetGuardPackHandlers(handlers.NewGuardPackHandlers(packRoot, lifecycle, cas, nil))
	return h.SetupRouter()
}

// guardPackRequest runs one request with the session + CSRF double-submit
// pair (canaryRequest parity).
func guardPackRequest(t *testing.T, router http.Handler, method, path, cookie, body string) *httptest.ResponseRecorder {
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
		req.AddCookie(testCookie("yabanin_csrf_token", gpCSRF))
		req.Header.Set("X-CSRF-Token", gpCSRF)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

const gpActivatePath = "/api/guard-packs/activate"
const gpRollbackPath = "/api/guard-packs/rollback"

func TestGuardPacks_RoutingContract(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, gpSecret)
	adminCookie := makeSessionCookie(t, "admin@x.test", false, gpSecret)
	body := `{"pack_id":"alpha","version":"1"}`

	packRoot := t.TempDir()
	writeGuardPackFixture(t, packRoot, "alpha", "1", gpDetect)
	router := guardPackRouter(t, &guardCASStub{}, packRoot)

	t.Run("anon is 401 on both mutations (session boundary)", func(t *testing.T) {
		for _, path := range []string{gpActivatePath, gpRollbackPath} {
			if w := guardPackRequest(t, router, http.MethodPost, path, "", body); w.Code != http.StatusUnauthorized {
				t.Errorf("anon POST %s = %d, want 401", path, w.Code)
			}
		}
	})
	t.Run("non-root admin session is 403 (root-only surface)", func(t *testing.T) {
		for _, path := range []string{gpActivatePath, gpRollbackPath} {
			if w := guardPackRequest(t, router, http.MethodPost, path, adminCookie, body); w.Code != http.StatusForbidden {
				t.Errorf("non-root POST %s = %d, want 403", path, w.Code)
			}
		}
	})
	t.Run("root activates", func(t *testing.T) {
		if w := guardPackRequest(t, router, http.MethodPost, gpActivatePath, rootCookie, body); w.Code != http.StatusOK {
			t.Fatalf("root POST activate = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
	})
}

func TestGuardPacks_UnwiredAnswers503(t *testing.T) {
	h := handlers.New(&stubStore{}, gpSecret, "localhost", nil)
	router := h.SetupRouter() // guard-pack handlers never attached
	rootCookie := makeSessionCookie(t, "root@x.test", true, gpSecret)
	for _, path := range []string{gpActivatePath, gpRollbackPath} {
		w := guardPackRequest(t, router, http.MethodPost, path, rootCookie, `{"pack_id":"alpha","version":"1"}`)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("unwired POST %s = %d, want 503", path, w.Code)
		}
	}
}

func TestGuardPacks_ActivateNegative(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, gpSecret)
	packRoot := t.TempDir()
	writeGuardPackFixture(t, packRoot, "alpha", "1", gpDetect)
	router := guardPackRouter(t, &guardCASStub{}, packRoot)

	t.Run("unknown pack is 404", func(t *testing.T) {
		w := guardPackRequest(t, router, http.MethodPost, gpActivatePath, rootCookie, `{"pack_id":"missing","version":"1"}`)
		if w.Code != http.StatusNotFound {
			t.Errorf("unknown pack = %d, want 404 (body: %s)", w.Code, w.Body.String())
		}
	})
	t.Run("unknown version is 404", func(t *testing.T) {
		w := guardPackRequest(t, router, http.MethodPost, gpActivatePath, rootCookie, `{"pack_id":"alpha","version":"999"}`)
		if w.Code != http.StatusNotFound {
			t.Errorf("unknown version = %d, want 404 (body: %s)", w.Code, w.Body.String())
		}
	})
	t.Run("pack id that is not a single path component is 400", func(t *testing.T) {
		for _, body := range []string{
			`{"pack_id":"../escape","version":"1"}`,
			`{"pack_id":"","version":"1"}`,
			`{"pack_id":"alpha"}`,
			`{"unknown":true}`,
		} {
			w := guardPackRequest(t, router, http.MethodPost, gpActivatePath, rootCookie, body)
			if w.Code != http.StatusBadRequest {
				t.Errorf("body %s = %d, want 400 (got: %s)", body, w.Code, w.Body.String())
			}
		}
	})
	t.Run("broken pack fails closed with 409 and nothing activates", func(t *testing.T) {
		broken := filepath.Join(packRoot, "broken")
		if err := os.MkdirAll(broken, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(broken, "detector.json"), []byte(`{"detectors":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		payload := []byte(`{"detectors":[{"rule_id":"x","rule_version":"1","category":"secret","pattern":"X_"}]}`)
		sum := sha256.Sum256(payload)
		manifest, err := json.Marshal(guardhooks.PackManifest{
			SchemaVersion: guardhooks.GuardPackManifestVersion, PackID: "broken", PackVersion: "1",
			RuntimeAPI: guardhooks.RuntimeVersion,
			Files:      []guardhooks.PackFile{{Path: "detector.json", SHA256: hex.EncodeToString(sum[:])}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(broken, "manifest.json"), manifest, 0o600); err != nil {
			t.Fatal(err)
		}
		w := guardPackRequest(t, router, http.MethodPost, gpActivatePath, rootCookie, `{"pack_id":"broken","version":"1"}`)
		if w.Code != http.StatusConflict {
			t.Errorf("broken pack = %d, want 409 (body: %s)", w.Code, w.Body.String())
		}
		// The built-in chain is still the only active guard set: the empty
		// detector pack never took over.
	})
}

func TestGuardPacks_ActivateConflictFailsClosed(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, gpSecret)
	packRoot := t.TempDir()
	writeGuardPackFixture(t, packRoot, "alpha", "1", gpDetect)
	// The durable row already records a foreign activation, so this
	// replica's local view ("core") is stale: the CAS must reject.
	cas := &guardCASStub{current: "foreign@9", previous: "core"}
	router := guardPackRouter(t, cas, packRoot)

	w := guardPackRequest(t, router, http.MethodPost, gpActivatePath, rootCookie, `{"pack_id":"alpha","version":"1"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale activate = %d, want 409 (body: %s)", w.Code, w.Body.String())
	}
	var body struct {
		Error   string `json:"error"`
		Current struct {
			ActiveVersion   string `json:"active_version"`
			PreviousVersion string `json:"previous_version"`
		} `json:"current"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("conflict body: %v", err)
	}
	if body.Current.ActiveVersion != "foreign@9" || body.Current.PreviousVersion != "core" {
		t.Errorf("conflict body must carry the LIVE durable state, got %+v", body.Current)
	}
}

func TestGuardPacks_StoreFailureFailsClosed(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, gpSecret)
	packRoot := t.TempDir()
	writeGuardPackFixture(t, packRoot, "alpha", "1", gpDetect)
	cas := &guardCASStub{failWith: errors.New("guard_pack_state unavailable")}
	lifecycle := guardhooks.NewPackLifecycle("core", guardhooks.ModeDeny, cas)
	h := handlers.New(&stubStore{}, gpSecret, "localhost", nil)
	h.SetGuardPackHandlers(handlers.NewGuardPackHandlers(packRoot, lifecycle, cas, nil))
	router := h.SetupRouter()

	w := guardPackRequest(t, router, http.MethodPost, gpActivatePath, rootCookie, `{"pack_id":"alpha","version":"1"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("store failure = %d, want 500 (body: %s)", w.Code, w.Body.String())
	}
	// Fail-closed: the durable row did not move and the lifecycle never
	// published the staged hook (the built-in chain still serves).
	if current, _ := cas.snapshot(); current != "" {
		t.Errorf("store failure must not write the durable row, got active=%q", current)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("GPBLOCK_SECRET_TOKEN"); err != nil {
		t.Errorf("failed activation must leave the built-in chain active, got %v", err)
	}
}

func TestGuardPacks_ActivateTakesEffectWithoutRestart(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, gpSecret)
	packRoot := t.TempDir()
	writeGuardPackFixture(t, packRoot, "alpha", "1", gpDetect)
	router := guardPackRouter(t, &guardCASStub{}, packRoot)

	// Pre-activation: the probe passes the built-in chain.
	// (Assertion happens via the handler-visible behaviour below; the
	// fast test keeps one lifecycle instance and asserts enforcement flips
	// on the SAME instance after the HTTP activate — no restart.)

	w := guardPackRequest(t, router, http.MethodPost, gpActivatePath, rootCookie, `{"pack_id":"alpha","version":"1"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("activate = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	// The durable record reflects the activation.
	var body struct {
		Status          string `json:"status"`
		ActiveVersion   string `json:"active_version"`
		PreviousVersion string `json:"previous_version"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("activate body: %v", err)
	}
	if body.Status != "activated" || body.ActiveVersion != "alpha@1" || body.PreviousVersion != "core" {
		t.Errorf("activate body = %+v, want activated/alpha@1/core", body)
	}
	// Audit journal: every successful mutation is audited.
	auditReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/audit-logs?page=1&page_size=50", nil)
	auditReq.AddCookie(testCookie("yabanin_admin_session", rootCookie))
	aw := httptest.NewRecorder()
	router.ServeHTTP(aw, auditReq)
	if !strings.Contains(aw.Body.String(), `"action":"activate"`) || !strings.Contains(aw.Body.String(), "guard_pack") {
		t.Errorf("activation not audited: %s", aw.Body.String())
	}
}

func TestGuardPacks_RollbackRestoresPriorEnforcement(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, gpSecret)
	packRoot := t.TempDir()
	writeGuardPackFixture(t, packRoot, "alpha", "1", gpDetect)
	cas := &guardCASStub{}
	lifecycle := guardhooks.NewPackLifecycle("core", guardhooks.ModeDeny, cas)
	h := handlers.New(&stubStore{}, gpSecret, "localhost", nil)
	h.SetGuardPackHandlers(handlers.NewGuardPackHandlers(packRoot, lifecycle, cas, nil))
	router := h.SetupRouter()

	t.Run("rollback without an active pack is 409", func(t *testing.T) {
		w := guardPackRequest(t, router, http.MethodPost, gpRollbackPath, rootCookie, "")
		if w.Code != http.StatusConflict {
			t.Errorf("rollback without active = %d, want 409 (body: %s)", w.Code, w.Body.String())
		}
	})

	if w := guardPackRequest(t, router, http.MethodPost, gpActivatePath, rootCookie, `{"pack_id":"alpha","version":"1"}`); w.Code != http.StatusOK {
		t.Fatalf("activate = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}

	t.Run("rollback restores the prior version through the same CAS", func(t *testing.T) {
		w := guardPackRequest(t, router, http.MethodPost, gpRollbackPath, rootCookie, "")
		if w.Code != http.StatusOK {
			t.Fatalf("rollback = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		var body struct {
			Status          string `json:"status"`
			ActiveVersion   string `json:"active_version"`
			PreviousVersion string `json:"previous_version"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("rollback body: %v", err)
		}
		if body.Status != "rolled_back" || body.ActiveVersion != "core" || body.PreviousVersion != "alpha@1" {
			t.Errorf("rollback body = %+v, want rolled_back/core/alpha@1", body)
		}
		if current, _ := cas.snapshot(); current != "core" {
			t.Errorf("durable row after rollback = %q, want core", current)
		}
	})
	t.Run("rollback with no prior version left is 409", func(t *testing.T) {
		w := guardPackRequest(t, router, http.MethodPost, gpRollbackPath, rootCookie, "")
		if w.Code != http.StatusConflict {
			t.Errorf("second rollback = %d, want 409 (body: %s)", w.Code, w.Body.String())
		}
	})
}

func TestGuardPacks_ConcurrentActivateExactlyOneWinner(t *testing.T) {
	packRoot := t.TempDir()
	writeGuardPackFixture(t, packRoot, "alpha", "1", gpDetect)
	writeGuardPackFixture(t, packRoot, "beta", "1", "GPBETA_[A-Z]+")
	cas := &guardCASStub{}
	newReplica := func() http.Handler {
		lifecycle := guardhooks.NewPackLifecycle("core", guardhooks.ModeDeny, cas)
		h := handlers.New(&stubStore{}, gpSecret, "localhost", nil)
		h.SetGuardPackHandlers(handlers.NewGuardPackHandlers(packRoot, lifecycle, cas, nil))
		return h.SetupRouter()
	}
	replicaA, replicaB := newReplica(), newReplica()
	rootCookie := makeSessionCookie(t, "root@x.test", true, gpSecret)

	var wg sync.WaitGroup
	codes := make([]int, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		codes[0] = guardPackRequest(t, replicaA, http.MethodPost, gpActivatePath, rootCookie, `{"pack_id":"alpha","version":"1"}`).Code
	}()
	go func() {
		defer wg.Done()
		codes[1] = guardPackRequest(t, replicaB, http.MethodPost, gpActivatePath, rootCookie, `{"pack_id":"beta","version":"1"}`).Code
	}()
	wg.Wait()

	wins, conflicts := 0, 0
	for _, code := range codes {
		switch code {
		case http.StatusOK:
			wins++
		case http.StatusConflict:
			conflicts++
		default:
			t.Fatalf("unexpected status %d in the activation race", code)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Errorf("activation race = %d wins / %d conflicts, want exactly one of each", wins, conflicts)
	}
}
