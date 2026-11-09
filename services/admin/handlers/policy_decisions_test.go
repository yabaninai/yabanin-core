package handlers_test

// OP-9: routing contract for the policy decision-log surface, asserted
// through the FULL SetupRouter (session auth + CSRF chain, exactly like
// policy_pipelines_test.go) — the org-permission gate lives in the mount:
//
//	anon              → 401 (session boundary)
//	root              → 200 (any org)
//	org-admin member  → 200 (policies.manage)
//	operator member   → 403 (lacks policies.manage)
//	no membership     → 404 (the org stays invisible)
//	bad filters       → 400 (verdict/mode allowlists)
//	unwired store     → 503 (route stays mounted)
//
// Plus the response contract: the standard pagination envelope
// {data, pagination:{page, page_size, total, total_pages}} with the filters
// applied by the store.

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

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

// decisionStoreStub implements the handlers.PolicyDecisionStore contract
// over an in-memory slice, plus the membership lookup the session chain
// needs. Tests run sequentially. lastFilters records the filters of the most
// recent list call so tests can pin the handler→store parameter contract.
type decisionStoreStub struct {
	stubStore
	roles       map[string]adminstore.OrgRole
	decisions   []adminstore.PolicyDecision
	lastFilters *adminstore.PolicyDecisionFilters
}

func (s *decisionStoreStub) GetUserOrgRoles(context.Context, string) (map[string]adminstore.OrgRole, error) {
	return s.roles, nil
}

// decisionMatchesFilters is the stub-side mirror of the store WHERE clause —
// enough fidelity for the parameter-passing and entity tests (the real SQL
// behavior is pinned by the store integration tests).
func decisionMatchesFilters(d adminstore.PolicyDecision, filters adminstore.PolicyDecisionFilters) bool {
	if filters.Verdict != "" && d.Verdict != filters.Verdict {
		return false
	}
	if filters.Mode != "" && d.Mode != filters.Mode {
		return false
	}
	if filters.PolicyID != "" && d.PolicyID != filters.PolicyID {
		return false
	}
	if filters.PolicyVersion != nil && d.PolicyVersion != *filters.PolicyVersion {
		return false
	}
	if filters.RequestID != "" && d.RequestID != filters.RequestID {
		return false
	}
	if filters.Step != "" && !decisionHasStep(d, filters.Step) {
		return false
	}
	if filters.CreatedFrom != nil && d.CreatedAt.Before(*filters.CreatedFrom) {
		return false
	}
	if filters.CreatedTo != nil && d.CreatedAt.After(*filters.CreatedTo) {
		return false
	}
	return true
}

// decisionHasStep reports whether the decision's stored findings array
// carries a finding with the given step (malformed findings never match).
func decisionHasStep(d adminstore.PolicyDecision, step string) bool {
	var findings []struct {
		Step string `json:"step"`
	}
	if err := json.Unmarshal(d.Findings, &findings); err != nil {
		return false
	}
	for _, f := range findings {
		if f.Step == step {
			return true
		}
	}
	return false
}

func (s *decisionStoreStub) ListPolicyDecisions(_ context.Context, orgID string, filters adminstore.PolicyDecisionFilters) ([]adminstore.PolicyDecision, int64, error) {
	if orgID == "" {
		return nil, 0, fmt.Errorf("org id is required")
	}
	s.lastFilters = &filters
	var out []adminstore.PolicyDecision
	for _, d := range s.decisions {
		if d.OrgID != orgID || !decisionMatchesFilters(d, filters) {
			continue
		}
		out = append(out, d)
	}
	return paginateDecisions(out, filters)
}

func (s *decisionStoreStub) ListPolicyDecisionRequests(_ context.Context, orgID string, filters adminstore.PolicyDecisionFilters) ([]adminstore.PolicyDecisionRequestSummary, int64, error) {
	if orgID == "" {
		return nil, 0, fmt.Errorf("org id is required")
	}
	s.lastFilters = &filters
	byRequest := map[string]*adminstore.PolicyDecisionRequestSummary{}
	for _, d := range s.decisions {
		if d.OrgID != orgID || d.RequestID == "" || !decisionMatchesFilters(d, filters) {
			continue
		}
		r, ok := byRequest[d.RequestID]
		if !ok {
			r = &adminstore.PolicyDecisionRequestSummary{RequestID: d.RequestID, FirstSeenAt: d.CreatedAt, LastSeenAt: d.CreatedAt}
			byRequest[d.RequestID] = r
		}
		r.Evaluations++
		if d.CreatedAt.Before(r.FirstSeenAt) {
			r.FirstSeenAt = d.CreatedAt
		}
		if d.CreatedAt.After(r.LastSeenAt) {
			r.LastSeenAt = d.CreatedAt
		}
	}
	out := make([]adminstore.PolicyDecisionRequestSummary, 0, len(byRequest))
	for _, r := range byRequest {
		out = append(out, *r)
	}
	// Most-recent activity first, request_id tiebreak (the store's order).
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			a, b := out[j-1], out[j]
			if b.LastSeenAt.After(a.LastSeenAt) || (b.LastSeenAt.Equal(a.LastSeenAt) && b.RequestID > a.RequestID) {
				out[j-1], out[j] = b, a
				continue
			}
			break
		}
	}
	return paginateSummaries(out, filters)
}

func paginateDecisions(rows []adminstore.PolicyDecision, filters adminstore.PolicyDecisionFilters) ([]adminstore.PolicyDecision, int64, error) {
	total := int64(len(rows))
	start := filters.Offset()
	if start >= len(rows) {
		return []adminstore.PolicyDecision{}, total, nil
	}
	end := start + filters.PageSize
	if end > len(rows) {
		end = len(rows)
	}
	return rows[start:end], total, nil
}

func paginateSummaries(rows []adminstore.PolicyDecisionRequestSummary, filters adminstore.PolicyDecisionFilters) ([]adminstore.PolicyDecisionRequestSummary, int64, error) {
	total := int64(len(rows))
	start := filters.Offset()
	if start >= len(rows) {
		return []adminstore.PolicyDecisionRequestSummary{}, total, nil
	}
	end := start + filters.PageSize
	if end > len(rows) {
		end = len(rows)
	}
	return rows[start:end], total, nil
}

func decisionRouter(t *testing.T, store *decisionStoreStub) http.Handler {
	t.Helper()
	h := handlers.New(store, polSecret, "localhost", nil)
	h.SetPolicyDecisionHandlers(handlers.NewPolicyDecisionHandlers(store))
	return h.SetupRouter()
}

func decisionRequest(t *testing.T, router http.Handler, method, path, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	req := httptest.NewRequestWithContext(t.Context(), method, path, reader)
	if cookie != "" {
		req.AddCookie(testCookie("yabanin_admin_session", cookie))
		req.AddCookie(testCookie("yabanin_csrf_token", polCSRF))
		req.Header.Set("X-CSRF-Token", polCSRF)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestPolicyDecisions_RoutingContract(t *testing.T) {
	const decisionsPath = "/api/organizations/" + polOrgA + "/policy-decisions"
	anonCookie := ""
	rootCookie := makeSessionCookie(t, "root@x.test", true, polSecret)
	adminCookie := makeSessionCookie(t, "admin@x.test", false, polSecret)

	seed := func(orgID string, n int) []adminstore.PolicyDecision {
		out := make([]adminstore.PolicyDecision, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, adminstore.PolicyDecision{
				ID: fmt.Sprintf("d-%d", i), OrgID: orgID, RequestID: fmt.Sprintf("req-%d", i),
				PolicyID: "pol-1", PolicyVersion: 1, Mode: "enforce", Verdict: "deny",
				Findings: []byte(`[]`), DurationMs: int64(i),
			})
		}
		return out
	}

	t.Run("anon is 401 (session boundary)", func(t *testing.T) {
		router := decisionRouter(t, &decisionStoreStub{roles: nil})
		if w := decisionRequest(t, router, http.MethodGet, decisionsPath, anonCookie); w.Code != http.StatusUnauthorized {
			t.Errorf("anon GET policy-decisions = %d, want 401", w.Code)
		}
	})

	t.Run("root reads any org", func(t *testing.T) {
		router := decisionRouter(t, &decisionStoreStub{roles: nil, decisions: seed(polOrgA, 2)})
		w := decisionRequest(t, router, http.MethodGet, decisionsPath, rootCookie)
		if w.Code != http.StatusOK {
			t.Fatalf("root GET policy-decisions = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"total":2`) {
			t.Errorf("root GET body = %s, want the pagination envelope with total 2", w.Body.String())
		}
	})

	t.Run("org-admin member reads; operator member is 403 (policies.manage)", func(t *testing.T) {
		router := decisionRouter(t, &decisionStoreStub{roles: map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin}, decisions: seed(polOrgA, 3)})
		if w := decisionRequest(t, router, http.MethodGet, decisionsPath, adminCookie); w.Code != http.StatusOK {
			t.Errorf("org-admin GET policy-decisions = %d, want 200", w.Code)
		}
		operatorRouter := decisionRouter(t, &decisionStoreStub{roles: map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOperator}})
		if w := decisionRequest(t, operatorRouter, http.MethodGet, decisionsPath, adminCookie); w.Code != http.StatusForbidden {
			t.Errorf("operator GET policy-decisions = %d, want 403 (operator lacks policies.manage)", w.Code)
		}
	})

	t.Run("non-member gets 404 without revealing the org", func(t *testing.T) {
		router := decisionRouter(t, &decisionStoreStub{roles: map[string]adminstore.OrgRole{}, decisions: seed(polOrgA, 1)})
		if w := decisionRequest(t, router, http.MethodGet, "/api/organizations/"+polOrgB+"/policy-decisions", adminCookie); w.Code != http.StatusNotFound {
			t.Errorf("non-member GET foreign org = %d, want 404 (resourceHidden)", w.Code)
		}
	})

	t.Run("invalid verdict/mode filters are 400", func(t *testing.T) {
		router := decisionRouter(t, &decisionStoreStub{roles: map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin}})
		if w := decisionRequest(t, router, http.MethodGet, decisionsPath+"?verdict=nuke", adminCookie); w.Code != http.StatusBadRequest {
			t.Errorf("GET verdict=nuke = %d, want 400", w.Code)
		}
		if w := decisionRequest(t, router, http.MethodGet, decisionsPath+"?mode=kill", adminCookie); w.Code != http.StatusBadRequest {
			t.Errorf("GET mode=kill = %d, want 400", w.Code)
		}
	})

	t.Run("unwired store answers 503 with the route still mounted", func(t *testing.T) {
		h := handlers.New(&decisionStoreStub{roles: nil}, polSecret, "localhost", nil)
		router := h.SetupRouter() // SetPolicyDecisionHandlers never called
		if w := decisionRequest(t, router, http.MethodGet, decisionsPath, rootCookie); w.Code != http.StatusServiceUnavailable {
			t.Errorf("unwired GET policy-decisions = %d, want 503", w.Code)
		}
	})
}

// CORE-TRACE-01: the findings wire contract is the HTTP shape, asserted as
// parsed JSON exactly as a typed client sees it:
//   - findings is ALWAYS a JSON array of content-free {step, category,
//     severity, span?, action} objects (never the stored base64/[]byte form
//     this bug shipped, never null);
//   - empty stored findings `[]` stay a valid empty array (findings_valid
//     true);
//   - invalid legacy data (null / object / junk / mistyped elements) is
//     served as [] with findings_valid FALSE — a corrupt record must never
//     read as a clean "nothing found" verdict (the stored verdict is kept);
//   - unknown element keys never surface (reader strips like the writer).
func TestPolicyDecisions_FindingsWireShape(t *testing.T) {
	const decisionsPath = "/api/organizations/" + polOrgA + "/policy-decisions"
	adminCookie := makeSessionCookie(t, "admin@x.test", false, polSecret)

	stubWithFindings := func(findings string) *decisionStoreStub {
		return &decisionStoreStub{
			roles: map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin},
			decisions: []adminstore.PolicyDecision{{
				ID: "d-1", OrgID: polOrgA, RequestID: "req-1",
				PolicyID: "pol-1", PolicyVersion: 1, Mode: "enforce", Verdict: "deny",
				Findings: json.RawMessage(findings), DurationMs: 5,
			}},
		}
	}
	firstRow := func(t *testing.T, stub *decisionStoreStub) (map[string]any, string) {
		t.Helper()
		router := decisionRouter(t, stub)
		w := decisionRequest(t, router, http.MethodGet, decisionsPath, adminCookie)
		if w.Code != http.StatusOK {
			t.Fatalf("GET policy-decisions = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		var body struct {
			Data []map[string]any `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode body: %v (%s)", err, w.Body.String())
		}
		if len(body.Data) != 1 {
			t.Fatalf("data rows = %d, want 1 (body: %s)", len(body.Data), w.Body.String())
		}
		return body.Data[0], w.Body.String()
	}
	findingsArray := func(t *testing.T, d map[string]any) []any {
		t.Helper()
		out, ok := d["findings"].([]any)
		if !ok {
			t.Fatalf("findings wire = %v (%T), want a JSON array — a string/base64 here is the CORE-TRACE-01 bug", d["findings"], d["findings"])
		}
		return out
	}

	t.Run("non-empty findings are a JSON array of contract finding objects", func(t *testing.T) {
		d, _ := firstRow(t, stubWithFindings(`[{"step":"in","category":"pan","severity":"high","span":"arg","action":"deny"}]`))
		findings := findingsArray(t, d)
		if len(findings) != 1 {
			t.Fatalf("findings = %v, want exactly one element", findings)
		}
		f, ok := findings[0].(map[string]any)
		if !ok {
			t.Fatalf("findings[0] = %T, want an object", findings[0])
		}
		for k, want := range map[string]any{"step": "in", "category": "pan", "severity": "high", "span": "arg", "action": "deny"} {
			if f[k] != want {
				t.Errorf("finding[%q] = %v, want %q", k, f[k], want)
			}
		}
		if v, ok := d["findings_valid"].(bool); !ok || !v {
			t.Errorf("findings_valid = %v, want true for a well-formed array", d["findings_valid"])
		}
	})

	t.Run("empty stored findings stay a valid empty array", func(t *testing.T) {
		d, body := firstRow(t, stubWithFindings(`[]`))
		if got := findingsArray(t, d); len(got) != 0 {
			t.Errorf("findings = %v, want []", got)
		}
		if v, ok := d["findings_valid"].(bool); !ok || !v {
			t.Errorf("findings_valid = %v, want true (body: %s)", d["findings_valid"], body)
		}
	})

	t.Run("unknown element keys never surface (content-free reader contract)", func(t *testing.T) {
		d, _ := firstRow(t, stubWithFindings(`[{"step":"s","category":"c","severity":"low","action":"flag","evidence":"SECRET","extra":1}]`))
		findings := findingsArray(t, d)
		f, _ := findings[0].(map[string]any)
		if _, leak := f["evidence"]; leak {
			t.Errorf("finding leaked evidence key: %v", f)
		}
		if len(f) != 4 {
			t.Errorf("finding keys = %v, want exactly step/category/severity/action (span omitted when empty)", f)
		}
	})

	t.Run("invalid legacy findings are visibly degraded, never a clean verdict", func(t *testing.T) {
		for _, tc := range []struct{ name, stored string }{
			{"json null", `null`},
			{"json string", `"junk"`},
			{"json object", `{"step":"in"}`},
			{"empty stored bytes", ``},
			{"array with null element", `[null]`},
			{"array with string element", `["oops"]`},
			{"array with mistyped field", `[{"step":123}]`},
			{"truncated json", `[{"step":`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				d, _ := firstRow(t, stubWithFindings(tc.stored))
				if got := findingsArray(t, d); len(got) != 0 {
					t.Errorf("findings = %v, want [] for stored %q", got, tc.stored)
				}
				if v, ok := d["findings_valid"].(bool); !ok || v {
					t.Errorf("findings_valid = %v, want false for stored %q", d["findings_valid"], tc.stored)
				}
				if d["verdict"] != "deny" {
					t.Errorf("verdict = %v, want the stored verdict preserved on a degraded row", d["verdict"])
				}
			})
		}
	})

	// CORE-TRACE-05: the envelope read model. The consumer stores decisions
	// as versioned envelope objects; the read surface exposes the evaluation
	// contract (hook, matched, effective/applied split, bounded steps,
	// completeness) with absence-is-unknown semantics.
	t.Run("envelope v1 row surfaces the evaluation contract", func(t *testing.T) {
		envelope := `{"envelope_version":1,` +
			`"findings":[{"step":"scan.pii","category":"innsnils","severity":"high","action":"deny"}],` +
			`"steps":[{"step":"scan.pii","outcome":"ran","duration_ms":3},{"step":"judge","outcome":"skipped","error":"short-circuited after deny"}],` +
			`"steps_total":2,"findings_total":1,"trace_completeness":"full",` +
			`"hook":"pre_upstream","rule_namespace":"policy","matched":true,` +
			`"effective_action":"deny","applied_action":"deny"}`
		d, _ := firstRow(t, stubWithFindings(envelope))
		findings := findingsArray(t, d)
		if len(findings) != 1 {
			t.Fatalf("findings = %v, want the envelope's findings array", findings)
		}
		if d["envelope_version"].(float64) != 1 {
			t.Errorf("envelope_version = %v, want 1", d["envelope_version"])
		}
		if d["hook"] != "pre_upstream" || d["rule_namespace"] != "policy" {
			t.Errorf("hook/rule_namespace = %v/%v, want pre_upstream/policy", d["hook"], d["rule_namespace"])
		}
		if m, ok := d["matched"].(bool); !ok || !m {
			t.Errorf("matched = %v, want true", d["matched"])
		}
		if d["effective_action"] != "deny" || d["applied_action"] != "deny" {
			t.Errorf("effective/applied = %v/%v, want deny/deny", d["effective_action"], d["applied_action"])
		}
		if d["trace_completeness"] != "full" {
			t.Errorf("trace_completeness = %v, want full", d["trace_completeness"])
		}
		steps, ok := d["steps"].([]any)
		if !ok || len(steps) != 2 {
			t.Fatalf("steps = %v, want the two-step trace", d["steps"])
		}
		last, _ := steps[1].(map[string]any)
		if last["outcome"] != "skipped" || last["error"] != "short-circuited after deny" {
			t.Errorf("steps[1] = %v, want the skipped tail with its skip reason", last)
		}
	})

	t.Run("unknown envelope version surfaces unknown, never a clean verdict", func(t *testing.T) {
		d, _ := firstRow(t, stubWithFindings(`{"envelope_version":99}`))
		if got := findingsArray(t, d); len(got) != 0 {
			t.Errorf("findings = %v, want [] for an unknown version", got)
		}
		if v, ok := d["findings_valid"].(bool); !ok || v {
			t.Errorf("findings_valid = %v, want false", d["findings_valid"])
		}
		if d["envelope_version"].(float64) != 99 {
			t.Errorf("envelope_version = %v, want 99 (the marker stays visible)", d["envelope_version"])
		}
		if d["trace_completeness"] != "unknown" {
			t.Errorf("trace_completeness = %v, want unknown", d["trace_completeness"])
		}
		if m, ok := d["matched"]; !ok || m != nil {
			t.Errorf("matched = %v, want null (no information)", d["matched"])
		}
	})

	t.Run("legacy bare-array rows surface unknown completeness", func(t *testing.T) {
		d, _ := firstRow(t, stubWithFindings(`[{"step":"s","category":"c","severity":"low","action":"flag"}]`))
		if got := findingsArray(t, d); len(got) != 1 {
			t.Fatalf("findings = %v, want the stored array", got)
		}
		if v, ok := d["findings_valid"].(bool); !ok || !v {
			t.Errorf("findings_valid = %v, want true (a legacy array still decodes)", d["findings_valid"])
		}
		if d["trace_completeness"] != "unknown" {
			t.Errorf("trace_completeness = %v, want unknown (no trace information pre-envelope)", d["trace_completeness"])
		}
		if _, present := d["hook"]; present {
			t.Errorf("hook = %v, want the field omitted for legacy rows", d["hook"])
		}
		if m, ok := d["matched"]; !ok || m != nil {
			t.Errorf("matched = %v, want null for legacy rows", d["matched"])
		}
	})

	t.Run("envelope with corrupt finding element degrades the array, keeps the contract", func(t *testing.T) {
		envelope := `{"envelope_version":1,"findings":[` +
			`{"step":"ok","category":"c","severity":"low","action":"flag"},` +
			`{"step":123}],"trace_completeness":"partial","hook":"post_upstream"}`
		d, _ := firstRow(t, stubWithFindings(envelope))
		if got := findingsArray(t, d); len(got) != 0 {
			t.Errorf("findings = %v, want [] (partial evidence never reads as complete)", got)
		}
		if v, ok := d["findings_valid"].(bool); !ok || v {
			t.Errorf("findings_valid = %v, want false", d["findings_valid"])
		}
		if d["hook"] != "post_upstream" || d["trace_completeness"] != "partial" {
			t.Errorf("hook/completeness = %v/%v, want the envelope identity preserved", d["hook"], d["trace_completeness"])
		}
	})
}

// CORE-TRACE-02: the two-way search contract. entity=requests answers "which
// requests did this rule touch": one row per DISTINCT request behind the
// filtered decisions, totals/pagination counted in REQUESTS (a request with
// three evaluations is one row with evaluations=3, never three), decisions
// without a request id excluded from that view (no navigable request). The
// new filters (policy_version, request_id, step, created_from/created_to)
// parse, combine and pass through to the store org-scoped; unknown values
// are 400.
func TestPolicyDecisions_TwoWaySearch(t *testing.T) {
	const decisionsPath = "/api/organizations/" + polOrgA + "/policy-decisions"
	adminCookie := makeSessionCookie(t, "admin@x.test", false, polSecret)
	base := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)

	seed := func() []adminstore.PolicyDecision {
		return []adminstore.PolicyDecision{
			// req-multi: three evaluations (different policies/verdicts/steps/times).
			{ID: "d-1", OrgID: polOrgA, RequestID: "req-multi", PolicyID: "pol-1", PolicyVersion: 2,
				Mode: "enforce", Verdict: "deny", Findings: json.RawMessage(`[{"step":"in","category":"pan","severity":"high","action":"deny"}]`), CreatedAt: base},
			{ID: "d-2", OrgID: polOrgA, RequestID: "req-multi", PolicyID: "pol-2", PolicyVersion: 0,
				Mode: "shadow", Verdict: "flag", Findings: json.RawMessage(`[{"step":"redact","category":"secret","severity":"high","action":"mask"}]`), CreatedAt: base.Add(time.Minute)},
			{ID: "d-3", OrgID: polOrgA, RequestID: "req-multi", PolicyID: "pol-1", PolicyVersion: 2,
				Mode: "enforce", Verdict: "allow", Findings: json.RawMessage(`[]`), CreatedAt: base.Add(2 * time.Minute)},
			// req-single: exactly one evaluation.
			{ID: "d-4", OrgID: polOrgA, RequestID: "req-single", PolicyID: "pol-3", PolicyVersion: 1,
				Mode: "enforce", Verdict: "flag", Findings: json.RawMessage(`[{"step":"in","category":"url","severity":"low","action":"flag"}]`), CreatedAt: base.Add(3 * time.Minute)},
			// Legacy row without a request id: stays in decisions, never in requests.
			{ID: "d-5", OrgID: polOrgA, RequestID: "", PolicyID: "pol-1", PolicyVersion: 2,
				Mode: "enforce", Verdict: "deny", Findings: json.RawMessage(`[]`), CreatedAt: base.Add(4 * time.Minute)},
			// Review F2 (2026-11-01): request-less row whose step value
			// CONTAINS the shorter queries "in"/"input" as proper
			// substrings/prefixes — the CPU-side twin of the store pin pair
			// (outside the window/verdict/version pins of the other subtests,
			// so their totals stay untouched).
			{ID: "d-6", OrgID: polOrgA, RequestID: "", PolicyID: "pol-4", PolicyVersion: 3,
				Mode: "enforce", Verdict: "flag", Findings: json.RawMessage(`[{"step":"input_tokens","category":"usage","severity":"low","action":"flag"}]`), CreatedAt: base.Add(5 * time.Minute)},
		}
	}

	t.Run("entity=requests counts unique requests, not evaluations", func(t *testing.T) {
		stub := &decisionStoreStub{roles: map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin}, decisions: seed()}
		router := decisionRouter(t, stub)
		w := decisionRequest(t, router, http.MethodGet, decisionsPath+"?entity=requests", adminCookie)
		if w.Code != http.StatusOK {
			t.Fatalf("GET entity=requests = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		var body struct {
			Data []struct {
				RequestID   string `json:"request_id"`
				Evaluations int64  `json:"evaluations"`
				FirstSeenAt string `json:"first_seen_at"`
				LastSeenAt  string `json:"last_seen_at"`
				Findings    any    `json:"findings"`
				PolicyID    any    `json:"policy_id"`
			} `json:"data"`
			Pagination struct {
				Total int64 `json:"total"`
			} `json:"pagination"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode body: %v (%s)", err, w.Body.String())
		}
		if body.Pagination.Total != 2 {
			t.Errorf("requests total = %d, want 2 unique requests (five evaluations, one request-less row)", body.Pagination.Total)
		}
		if len(body.Data) != 2 {
			t.Fatalf("request rows = %d, want 2 (body: %s)", len(body.Data), w.Body.String())
		}
		if body.Data[0].RequestID != "req-single" || body.Data[1].RequestID != "req-multi" {
			t.Errorf("rows = [%s, %s], want req-single first (most recent activity), req-multi second",
				body.Data[0].RequestID, body.Data[1].RequestID)
		}
		if body.Data[1].Evaluations != 3 {
			t.Errorf("req-multi evaluations = %d, want 3 (three evaluations are still ONE request)", body.Data[1].Evaluations)
		}
		if body.Data[0].Evaluations != 1 {
			t.Errorf("req-single evaluations = %d, want 1", body.Data[0].Evaluations)
		}
		// time.Time marshals RFC3339Nano: req-multi spans d-1..d-3 (10:00..10:02).
		if got, want := body.Data[1].FirstSeenAt, "2026-11-01T10:00:00Z"; got != want {
			t.Errorf("req-multi first_seen_at = %q, want %q", got, want)
		}
		if got, want := body.Data[1].LastSeenAt, "2026-11-01T10:02:00Z"; got != want {
			t.Errorf("req-multi last_seen_at = %q, want %q", got, want)
		}
		if body.Data[0].Findings != nil || body.Data[0].PolicyID != nil {
			t.Errorf("request summary must not carry decision-only fields (findings=%v policy_id=%v)", body.Data[0].Findings, body.Data[0].PolicyID)
		}
	})

	t.Run("default entity stays the decisions list (compat)", func(t *testing.T) {
		stub := &decisionStoreStub{roles: map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin}, decisions: seed()}
		router := decisionRouter(t, stub)
		for _, url := range []string{decisionsPath, decisionsPath + "?entity=decisions"} {
			w := decisionRequest(t, router, http.MethodGet, url, adminCookie)
			if w.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200", url, w.Code)
			}
			if !strings.Contains(w.Body.String(), `"findings_valid"`) {
				t.Errorf("GET %s body lacks the decision-row contract: %s", url, w.Body.String())
			}
		}
		if stub.lastFilters == nil {
			t.Fatal("the store was never called")
		}
	})

	t.Run("new filters parse, combine and reach the store", func(t *testing.T) {
		stub := &decisionStoreStub{roles: map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin}, decisions: seed()}
		router := decisionRouter(t, stub)
		url := decisionsPath + "?request_id=req-multi&policy_id=pol-1&policy_version=2&step=in" +
			"&created_from=" + base.Add(-time.Minute).Format(time.RFC3339) +
			"&created_to=" + base.Add(time.Minute).Format(time.RFC3339) +
			"&verdict=deny&mode=enforce"
		w := decisionRequest(t, router, http.MethodGet, url, adminCookie)
		if w.Code != http.StatusOK {
			t.Fatalf("GET combined filters = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		f := stub.lastFilters
		if f == nil {
			t.Fatal("filters never reached the store")
		}
		if f.RequestID != "req-multi" || f.PolicyID != "pol-1" || f.Step != "in" || f.Verdict != "deny" || f.Mode != "enforce" {
			t.Errorf("store filters = %+v, want the parsed query values", f)
		}
		if f.PolicyVersion == nil || *f.PolicyVersion != 2 {
			t.Errorf("policy_version filter = %v, want 2", f.PolicyVersion)
		}
		if f.CreatedFrom == nil || !f.CreatedFrom.Equal(base.Add(-time.Minute)) {
			t.Errorf("created_from = %v, want %v", f.CreatedFrom, base.Add(-time.Minute))
		}
		if f.CreatedTo == nil || !f.CreatedTo.Equal(base.Add(time.Minute)) {
			t.Errorf("created_to = %v, want %v", f.CreatedTo, base.Add(time.Minute))
		}
	})

	t.Run("invalid new filter values are 400", func(t *testing.T) {
		stub := &decisionStoreStub{roles: map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin}}
		router := decisionRouter(t, stub)
		for _, tc := range []struct{ name, query string }{
			{"policy_version not a number", "?policy_version=abc"},
			{"policy_version negative", "?policy_version=-1"},
			{"created_from not RFC3339", "?created_from=01/02/2026"},
			{"created_to not RFC3339", "?created_to=yesterday"},
			{"created_from after created_to", "?created_from=" + base.Add(time.Minute).Format(time.RFC3339) + "&created_to=" + base.Format(time.RFC3339)},
			{"unknown entity", "?entity=everything"},
		} {
			if w := decisionRequest(t, router, http.MethodGet, decisionsPath+tc.query, adminCookie); w.Code != http.StatusBadRequest {
				t.Errorf("GET %s = %d, want 400 (%s)", tc.query, w.Code, tc.name)
			}
		}
		if stub.lastFilters != nil {
			t.Errorf("a rejected filter must never reach the store")
		}
	})

	// Review F1 (2026-11-01, ACCEPT-WITH-FIXES): policy_version backs a
	// Postgres integer column and is bound through pgx v5's int4 codec —
	// parsed at full int width, 99999999999999 sailed through validation and
	// died INSIDE the store ("is greater than maximum value for int4",
	// pgtype/int.go:745 in the exact compiled pgx v5.10.0), surfacing as 500
	// instead of the documented 400. The validation seam must parse in the
	// int4 range so out-of-width input is rejected here, never store-bound.
	t.Run("policy_version parses in int32 range: beyond it is 400, never a store-bound 500", func(t *testing.T) {
		stub := &decisionStoreStub{roles: map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin}, decisions: seed()}
		router := decisionRouter(t, stub)
		for _, tc := range []struct{ name, query string }{
			{"2^31 is the first value past int4", "?policy_version=2147483648"},
			{"14 digits far past int32", "?policy_version=99999999999999"},
			{"negative past int32", "?policy_version=-2147483649"},
		} {
			if w := decisionRequest(t, router, http.MethodGet, decisionsPath+tc.query, adminCookie); w.Code != http.StatusBadRequest {
				t.Errorf("GET %s = %d, want 400 (%s) — a full-width parse reaches the pgx int4 encoder and turns into a 500", tc.query, w.Code, tc.name)
			}
			if stub.lastFilters != nil {
				t.Errorf("GET %s must never reach the store (%s)", tc.query, tc.name)
				stub.lastFilters = nil
			}
		}
		// Boundary-valid: 2^31-1 IS the int4 maximum — accepted and bound.
		w := decisionRequest(t, router, http.MethodGet, decisionsPath+"?policy_version=2147483647", adminCookie)
		if w.Code != http.StatusOK {
			t.Fatalf("GET policy_version=2147483647 = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		if stub.lastFilters == nil || stub.lastFilters.PolicyVersion == nil || *stub.lastFilters.PolicyVersion != 2147483647 {
			t.Errorf("policy_version=2147483647 reached the store as %v, want the int4 maximum bound exactly", stub.lastFilters)
		}
	})

	// Review F2 (2026-11-01): the step filter is whole-value end to end — the
	// input/in superset pair proves the pin catches substring, prefix,
	// equals and direction-flipped degradation at the API seam (the stub
	// mirrors the store WHERE clause; the jsonb containment itself is pinned
	// by TestPolicyDecisions_TwoWaySearch_Integration on real Postgres).
	t.Run("step filter is whole-value: input/in superset pair", func(t *testing.T) {
		stub := &decisionStoreStub{roles: map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin}, decisions: seed()}
		router := decisionRouter(t, stub)
		for _, tc := range []struct {
			step string
			want int64
		}{
			{"in", 2},                 // own rows only — never inside 'input_tokens'/'redact'
			{"input_tokens", 1},       // the longer stored value matches its own (shorter-probe) step
			{"input", 0},              // a proper prefix of 'input_tokens' is not the value
			{"input_tokens_extra", 0}, // a superset query never matches the shorter stored value
			{"redact", 1},
			{"no-such-step", 0},
		} {
			w := decisionRequest(t, router, http.MethodGet, decisionsPath+"?step="+tc.step, adminCookie)
			if w.Code != http.StatusOK {
				t.Errorf("GET ?step=%s = %d, want 200 (body: %s)", tc.step, w.Code, w.Body.String())
				continue
			}
			var body struct {
				Pagination struct {
					Total int64 `json:"total"`
				} `json:"pagination"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Errorf("decode ?step=%s body: %v (%s)", tc.step, err, w.Body.String())
				continue
			}
			if body.Pagination.Total != tc.want {
				t.Errorf("GET ?step=%s total = %d, want %d (whole-value step matching)", tc.step, body.Pagination.Total, tc.want)
			}
		}
	})

	t.Run("requests view honors the filters on the entity totals", func(t *testing.T) {
		stub := &decisionStoreStub{roles: map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin}, decisions: seed()}
		router := decisionRouter(t, stub)
		// verdict=deny leaves d-1 (req-multi) and d-5 (no request id): ONE unique request.
		w := decisionRequest(t, router, http.MethodGet, decisionsPath+"?entity=requests&verdict=deny", adminCookie)
		if w.Code != http.StatusOK {
			t.Fatalf("GET entity=requests&verdict=deny = %d, want 200", w.Code)
		}
		var body struct {
			Data       []adminstore.PolicyDecisionRequestSummary `json:"data"`
			Pagination struct{ Total int64 }                     `json:"pagination"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode body: %v (%s)", err, w.Body.String())
		}
		if body.Pagination.Total != 1 || len(body.Data) != 1 || body.Data[0].RequestID != "req-multi" {
			t.Errorf("verdict=deny requests = %+v total %d, want exactly req-multi (the request-less deny row has no request)", body.Data, body.Pagination.Total)
		}
		if body.Data[0].Evaluations != 1 {
			t.Errorf("req-multi evaluations under verdict=deny = %d, want 1", body.Data[0].Evaluations)
		}
	})
}
