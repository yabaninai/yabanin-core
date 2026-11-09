package handlers_test

// N02-P08 (T02/T06) guard detector-pack READ + DRY-RUN surface
// (guardpacks_read.go). Locked contract (fast, Dockerless: in-memory CAS +
// real PackLifecycle + real on-disk pack fixtures, guardpacks_test.go parity):
//
//	route chain        root-only: anon 401, non-root session 403, root 200
//	unwired            503 (routes mounted, lifecycle not configured)
//	list               one row per pack directory; a broken directory is
//	                   listed WITH its error (never hidden); non-dir entries
//	                   are skipped; the durable active/previous versions ride
//	                   along; a store read failure is 500
//	status             durable state + staged candidate + the runtime load
//	                   check: built-in/empty identity loadable, a healthy pack
//	                   loadable, a pack broken on disk NOT loadable (the
//	                   watcher-failure precondition), a stale identity named
//	                   honestly; no fabricated applied version/failure count
//	validate           activate-stage parity without mutation: 200 valid +
//	                   digest + detector count, 404 unknown identity, 409
//	                   broken pack, 400 grammar; nothing staged afterwards
//	simulate           detect-only preview: pack + built-in detectors both
//	                   report, 128 KiB body cap, unknown fields rejected,
//	                   nothing staged, no journal write
//
// The journal invariant (feedback/mutations only): validate/simulate/list/
// status never write the audit journal — only activate/rollback do
// (pinned in TestGuardPacks_ActivateTakesEffectWithoutRestart).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/services/admin/handlers"
)

const (
	gpListPath     = "/api/guard-packs"
	gpStatusPath   = "/api/guard-packs/status"
	gpValidatePath = "/api/guard-packs/validate"
	gpSimulatePath = "/api/guard-packs/simulate"
)

func TestGuardPacksRead_RoutingContract(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, gpSecret)
	adminCookie := makeSessionCookie(t, "admin@x.test", false, gpSecret)

	packRoot := t.TempDir()
	writeGuardPackFixture(t, packRoot, "alpha", "1", gpDetect)
	router := guardPackRouter(t, &guardCASStub{}, packRoot)

	cases := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, gpListPath, ""},
		{http.MethodGet, gpStatusPath, ""},
		{http.MethodPost, gpValidatePath, `{"pack_id":"alpha","version":"1"}`},
		{http.MethodPost, gpSimulatePath, `{"pack_id":"alpha","version":"1","sample":"x"}`},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			if w := guardPackRequest(t, router, tc.method, tc.path, "", tc.body); w.Code != http.StatusUnauthorized {
				t.Errorf("anon = %d, want 401", w.Code)
			}
			if w := guardPackRequest(t, router, tc.method, tc.path, adminCookie, tc.body); w.Code != http.StatusForbidden {
				t.Errorf("non-root = %d, want 403", w.Code)
			}
			if w := guardPackRequest(t, router, tc.method, tc.path, rootCookie, tc.body); w.Code != http.StatusOK {
				t.Errorf("root = %d, want 200 (body: %s)", w.Code, w.Body.String())
			}
		})
	}
}

func TestGuardPacksRead_UnwiredAnswers503(t *testing.T) {
	h := handlers.New(&stubStore{}, gpSecret, "localhost", nil)
	router := h.SetupRouter() // guard-pack handlers never attached
	rootCookie := makeSessionCookie(t, "root@x.test", true, gpSecret)
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, gpListPath, ""},
		{http.MethodGet, gpStatusPath, ""},
		{http.MethodPost, gpValidatePath, `{"pack_id":"a","version":"1"}`},
		{http.MethodPost, gpSimulatePath, `{"pack_id":"a","version":"1","sample":""}`},
	} {
		if w := guardPackRequest(t, router, tc.method, tc.path, rootCookie, tc.body); w.Code != http.StatusServiceUnavailable {
			t.Errorf("unwired %s %s = %d, want 503", tc.method, tc.path, w.Code)
		}
	}
}

func TestGuardPacksRead_List(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, gpSecret)
	packRoot := t.TempDir()
	writeGuardPackFixture(t, packRoot, "alpha", "1", gpDetect)
	writeGuardPackFixture(t, packRoot, "beta", "2", "GPBETA_[A-Z]+")
	// A directory with no manifest and a stray file (not a pack directory):
	// both must be handled honestly — the broken dir is listed with its
	// error, the stray file is skipped.
	if err := os.MkdirAll(packRoot+"/ghost", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(packRoot+"/README", []byte("not a pack"), 0o600); err != nil {
		t.Fatal(err)
	}

	cas := &guardCASStub{current: "alpha@1", previous: "core"}
	router := guardPackRouter(t, cas, packRoot)
	w := guardPackRequest(t, router, http.MethodGet, gpListPath, rootCookie, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var body struct {
		Packs []struct {
			Dir               string `json:"dir"`
			PackID            string `json:"pack_id"`
			PackVersion       string `json:"pack_version"`
			Files             int    `json:"files"`
			SignatureDeclared bool   `json:"signature_declared"`
			Error             string `json:"error"`
		} `json:"packs"`
		ActiveVersion   string `json:"active_version"`
		PreviousVersion string `json:"previous_version"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("list body: %v", err)
	}
	if body.ActiveVersion != "alpha@1" || body.PreviousVersion != "core" {
		t.Errorf("durable state = %q/%q, want alpha@1/core", body.ActiveVersion, body.PreviousVersion)
	}
	byDir := map[string]map[string]any{}
	for _, row := range body.Packs {
		raw, _ := json.Marshal(row)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		byDir[row.Dir] = m
	}
	if len(byDir) != 3 {
		t.Fatalf("rows = %d (%v), want 3 (alpha, beta, ghost; stray files skipped)", len(byDir), body.Packs)
	}
	alpha := byDir["alpha"]
	if alpha["pack_id"] != "alpha" || alpha["pack_version"] != "1" || alpha["files"] != float64(1) {
		t.Errorf("alpha row = %v", alpha)
	}
	if alpha["signature_declared"] == true {
		t.Errorf("unsigned alpha must not claim a declared signature: %v", alpha)
	}
	if errText, _ := alpha["error"].(string); errText != "" {
		t.Errorf("healthy alpha carries no error: %v", alpha)
	}
	ghost := byDir["ghost"]
	if ghost["error"] == "" {
		t.Errorf("ghost dir must be listed WITH its error, got %v", ghost)
	}

	t.Run("store read failure is a 500 (no inventory without the durable state)", func(t *testing.T) {
		failing := &guardCASStub{failRead: true}
		failingRouter := guardPackRouter(t, failing, packRoot)
		if w := guardPackRequest(t, failingRouter, http.MethodGet, gpListPath, rootCookie, ""); w.Code != http.StatusInternalServerError {
			t.Errorf("failRead list = %d, want 500", w.Code)
		}
	})
	t.Run("unreadable pack root is a 500, not an empty inventory", func(t *testing.T) {
		missing := guardPackRouter(t, &guardCASStub{}, packRoot+"/does-not-exist")
		if w := guardPackRequest(t, missing, http.MethodGet, gpListPath, rootCookie, ""); w.Code != http.StatusInternalServerError {
			t.Errorf("missing root list = %d, want 500", w.Code)
		}
	})
}

func TestGuardPacksRead_Status(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, gpSecret)
	packRoot := t.TempDir()
	writeGuardPackFixture(t, packRoot, "alpha", "1", gpDetect)

	t.Run("built-in active state is loadable and honest", func(t *testing.T) {
		router := guardPackRouter(t, &guardCASStub{}, packRoot)
		w := guardPackRequest(t, router, http.MethodGet, gpStatusPath, rootCookie, "")
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		var body guardStatusBody
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("status body: %v", err)
		}
		if body.ActiveVersion != "" || body.PreviousVersion != "" {
			t.Errorf("fresh deployment = %+v, want empty durable state", body)
		}
		if !body.Runtime.ActivePackLoadable || body.Runtime.LoadError != "" {
			t.Errorf("built-in chain must be loadable, got %+v", body.Runtime)
		}
		if !strings.Contains(body.Runtime.Check, "gateway_guard_pack_watch_failures_total") {
			t.Errorf("the check must name what it verifies (watcher parity), got %q", body.Runtime.Check)
		}
		if _, has := body.UpdatedAtMap["updated_at"]; has {
			t.Errorf("zero updated_at must be omitted, got %v", body.UpdatedAtMap)
		}
	})

	t.Run("an active pack broken on disk is reported NOT loadable", func(t *testing.T) {
		cas := &guardCASStub{current: "alpha@1", previous: "core"}
		router := guardPackRouter(t, cas, packRoot)
		// Healthy first.
		w := guardPackRequest(t, router, http.MethodGet, gpStatusPath, rootCookie, "")
		var body guardStatusBody
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if !body.Runtime.ActivePackLoadable {
			t.Fatalf("healthy pack reported unloadable: %+v", body.Runtime)
		}
		// Now corrupt detector.json on disk: the SHA-256 no longer matches the
		// manifest — exactly the condition that makes every replica's runtime
		// adoption fail and keep the last known-good hook.
		if err := os.WriteFile(packRoot+"/alpha/detector.json", []byte(`{"detectors":[{"rule_id":"alpha","rule_version":"1","category":"secret","pattern":"TAMPERED"}]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		w = guardPackRequest(t, router, http.MethodGet, gpStatusPath, rootCookie, "")
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Runtime.ActivePackLoadable {
			t.Errorf("corrupted pack reported loadable: %+v", body.Runtime)
		}
		if !strings.Contains(body.Runtime.LoadError, "alpha@1") {
			t.Errorf("load error must name the failing identity, got %q", body.Runtime.LoadError)
		}
	})

	t.Run("a stale durable identity is named, not masked", func(t *testing.T) {
		router := guardPackRouter(t, &guardCASStub{current: "alpha@999"}, packRoot)
		w := guardPackRequest(t, router, http.MethodGet, gpStatusPath, rootCookie, "")
		var body guardStatusBody
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Runtime.ActivePackLoadable {
			t.Errorf("stale identity reported loadable: %+v", body.Runtime)
		}
		if !strings.Contains(body.Runtime.LoadError, "alpha@999") || !strings.Contains(body.Runtime.LoadError, "alpha@1") {
			t.Errorf("load error must carry requested vs declared, got %q", body.Runtime.LoadError)
		}
	})
}

// guardStatusBody mirrors the status response plus a raw map so omitted
// fields are distinguishable from zero values.
type guardStatusBody struct {
	ActiveVersion   string `json:"active_version"`
	PreviousVersion string `json:"previous_version"`
	StagedVersion   string `json:"staged_version"`
	Runtime         struct {
		ActivePackLoadable bool   `json:"active_pack_loadable"`
		LoadError          string `json:"load_error"`
		Check              string `json:"check"`
	} `json:"runtime"`
	UpdatedAtMap map[string]any `json:"-"`
}

func (b *guardStatusBody) UnmarshalJSON(data []byte) error {
	type alias guardStatusBody
	var plain alias
	if err := json.Unmarshal(data, &plain); err != nil {
		return err
	}
	*b = guardStatusBody(plain)
	return json.Unmarshal(data, &b.UpdatedAtMap)
}

func TestGuardPacksRead_Validate(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, gpSecret)
	packRoot := t.TempDir()
	writeGuardPackFixture(t, packRoot, "alpha", "1", gpDetect)
	cas := &guardCASStub{}
	lifecycleRouter := guardPackRouter(t, cas, packRoot)

	t.Run("valid pack answers with digest and detector count", func(t *testing.T) {
		w := guardPackRequest(t, lifecycleRouter, http.MethodPost, gpValidatePath, rootCookie, `{"pack_id":"alpha","version":"1"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("validate = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		var body struct {
			Status      string `json:"status"`
			PackID      string `json:"pack_id"`
			PackVersion string `json:"pack_version"`
			Digest      string `json:"digest"`
			Detectors   int    `json:"detectors"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Status != "valid" || body.PackID != "alpha" || body.PackVersion != "1" || body.Digest == "" || body.Detectors != 1 {
			t.Errorf("validate body = %+v", body)
		}
	})

	t.Run("dry-run never stages: status stays empty and the durable row untouched", func(t *testing.T) {
		w := guardPackRequest(t, lifecycleRouter, http.MethodGet, gpStatusPath, rootCookie, "")
		var body guardStatusBody
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.StagedVersion != "" {
			t.Errorf("validate staged a candidate: %q", body.StagedVersion)
		}
		if current, _ := cas.snapshot(); current != "" {
			t.Errorf("validate wrote the durable row: %q", current)
		}
	})

	t.Run("unknown pack/version are 404, broken pack is 409, bad grammar is 400", func(t *testing.T) {
		cases := []struct {
			body string
			want int
		}{
			{`{"pack_id":"missing","version":"1"}`, http.StatusNotFound},
			{`{"pack_id":"alpha","version":"999"}`, http.StatusNotFound},
			{`{"pack_id":"../escape","version":"1"}`, http.StatusBadRequest},
			{`{"pack_id":"alpha","version":""}`, http.StatusBadRequest},
			{`{"unknown":true}`, http.StatusBadRequest},
		}
		for _, tc := range cases {
			if w := guardPackRequest(t, lifecycleRouter, http.MethodPost, gpValidatePath, rootCookie, tc.body); w.Code != tc.want {
				t.Errorf("validate %s = %d, want %d", tc.body, w.Code, tc.want)
			}
		}
		// Present but corrupt: manifest declares a SHA the file no longer
		// matches — 409 (parity with the activate stage failure).
		if err := os.WriteFile(packRoot+"/alpha/detector.json", []byte(`{"detectors":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if w := guardPackRequest(t, lifecycleRouter, http.MethodPost, gpValidatePath, rootCookie, `{"pack_id":"alpha","version":"1"}`); w.Code != http.StatusConflict {
			t.Errorf("corrupted pack validate = %d, want 409", w.Code)
		}
	})
}

func TestGuardPacksRead_Simulate(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, gpSecret)
	packRoot := t.TempDir()
	writeGuardPackFixture(t, packRoot, "alpha", "1", gpDetect)
	cas := &guardCASStub{}
	lifecycleRouter := guardPackRouter(t, cas, packRoot)

	t.Run("pack and built-in detectors both report with offsets", func(t *testing.T) {
		sample := `token GPBLOCK_ABC_TOKEN and key sk-abcdefghijklmnopqrstuvwxyz`
		body := fmt.Sprintf(`{"pack_id":"alpha","version":"1","sample":%q}`, sample)
		w := guardPackRequest(t, lifecycleRouter, http.MethodPost, gpSimulatePath, rootCookie, body)
		if w.Code != http.StatusOK {
			t.Fatalf("simulate = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		var resp struct {
			Status        string   `json:"status"`
			PackID        string   `json:"pack_id"`
			PackVersion   string   `json:"pack_version"`
			Digest        string   `json:"digest"`
			TotalFindings int      `json:"total_findings"`
			Truncated     bool     `json:"truncated"`
			Categories    []string `json:"categories"`
			Findings      []struct {
				Detector string  `json:"detector"`
				Category string  `json:"category"`
				Start    int     `json:"start"`
				End      int     `json:"end"`
				Confid   float64 `json:"confidence"`
			} `json:"findings"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Status != "simulated" || resp.PackID != "alpha" || resp.Digest == "" || resp.Truncated {
			t.Errorf("simulate envelope = %+v", resp)
		}
		packHit, builtinHit := false, false
		for _, f := range resp.Findings {
			if f.Category != "secret" {
				continue
			}
			// Span sanity: the offsets must point at the sample text.
			if f.Start < 0 || f.End <= f.Start || f.End > len(sample) {
				t.Errorf("finding span [%d,%d) outside sample (len %d)", f.Start, f.End, len(sample))
				continue
			}
			if strings.HasPrefix(sample[f.Start:f.End], "GPBLOCK_") {
				packHit = strings.HasPrefix(f.Detector, "alpha:")
			}
			if strings.HasPrefix(sample[f.Start:f.End], "sk-") {
				builtinHit = true
			}
		}
		if !packHit {
			t.Errorf("pack detector finding missing: %+v", resp.Findings)
		}
		if !builtinHit {
			t.Errorf("built-in detector finding missing (the preview must run the combined chain): %+v", resp.Findings)
		}
		// Scan-parity view: the secret category the runtime would act on.
		if len(resp.Categories) != 1 || resp.Categories[0] != "secret" {
			t.Errorf("categories = %v, want [secret]", resp.Categories)
		}
	})

	t.Run("empty sample is an honest no-findings dry run; nothing staged", func(t *testing.T) {
		w := guardPackRequest(t, lifecycleRouter, http.MethodPost, gpSimulatePath, rootCookie, `{"pack_id":"alpha","version":"1","sample":""}`)
		if w.Code != http.StatusOK {
			t.Fatalf("empty sample = %d, want 200", w.Code)
		}
		if !strings.Contains(w.Body.String(), `"total_findings":0`) {
			t.Errorf("empty sample body = %s", w.Body.String())
		}
		sw := guardPackRequest(t, lifecycleRouter, http.MethodGet, gpStatusPath, rootCookie, "")
		if !strings.Contains(sw.Body.String(), `"staged_version":""`) {
			t.Errorf("simulate staged a candidate: %s", sw.Body.String())
		}
		if current, _ := cas.snapshot(); current != "" {
			t.Errorf("simulate wrote the durable row: %q", current)
		}
	})

	t.Run("unknown pack is 404; bad body is 400; oversized body is 400", func(t *testing.T) {
		if w := guardPackRequest(t, lifecycleRouter, http.MethodPost, gpSimulatePath, rootCookie, `{"pack_id":"missing","version":"1","sample":"x"}`); w.Code != http.StatusNotFound {
			t.Errorf("unknown pack = %d, want 404", w.Code)
		}
		if w := guardPackRequest(t, lifecycleRouter, http.MethodPost, gpSimulatePath, rootCookie, `{"pack_id":"alpha","unknown":1,"sample":"x"}`); w.Code != http.StatusBadRequest {
			t.Errorf("unknown field = %d, want 400", w.Code)
		}
		huge := `{"pack_id":"alpha","version":"1","sample":"` + strings.Repeat("a", 200*1024) + `"}`
		if w := guardPackRequest(t, lifecycleRouter, http.MethodPost, gpSimulatePath, rootCookie, huge); w.Code != http.StatusBadRequest {
			t.Errorf("oversized sample = %d, want 400", w.Code)
		}
	})

	t.Run("read-only routes never write the audit journal", func(t *testing.T) {
		for _, tc := range []struct{ method, path, body string }{
			{http.MethodGet, gpListPath, ""},
			{http.MethodGet, gpStatusPath, ""},
			{http.MethodPost, gpValidatePath, `{"pack_id":"alpha","version":"1"}`},
			{http.MethodPost, gpSimulatePath, `{"pack_id":"alpha","version":"1","sample":"x"}`},
		} {
			guardPackRequest(t, lifecycleRouter, tc.method, tc.path, rootCookie, tc.body)
		}
		auditReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/audit-logs?page=1&page_size=50", nil)
		auditReq.AddCookie(testCookie("yabanin_admin_session", rootCookie))
		w := httptest.NewRecorder()
		lifecycleRouter.ServeHTTP(w, auditReq)
		if strings.Contains(w.Body.String(), `"resource":"guard_pack"`) {
			t.Errorf("read-only surface journaled: %s", w.Body.String())
		}
	})
}
