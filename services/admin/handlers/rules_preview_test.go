package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/services/admin/handlers"
)

// AUX-19: POST /api/rules/preview. The preview is root-only like every other
// /api/rules route; the org scope comes from the trusted identity header and
// never from the body; a malformed expression is an explicit machine-readable
// 400; the response carries only caller-supplied fields (no store lookups, no
// upstream credentials). The verdict must be the honest Snapshot.Evaluate
// result: matched samples route to the candidate target, misses keep the
// requested model.

const (
	previewSecret = "test-session-secret" // #nosec G101 -- test-only HMAC key
	previewCSRF   = "preview-csrf-token"  // #nosec G101 -- test-only CSRF value
)

func previewRouter(t *testing.T) http.Handler {
	t.Helper()
	return handlers.New(&stubStore{}, previewSecret, "localhost", nil).SetupRouter()
}

// postPreview performs an authenticated POST /api/rules/preview through the
// full router (session + CSRF cookies, scope header — exactly what the
// dashboard sends).
func postPreview(t *testing.T, router http.Handler, sessionCookie, orgScope, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/rules/preview", strings.NewReader(body))
	if sessionCookie != "" {
		req.AddCookie(testCookie("yabanin_admin_session", sessionCookie))
		req.AddCookie(testCookie("yabanin_csrf_token", previewCSRF))
		req.Header.Set("X-CSRF-Token", previewCSRF)
	}
	if orgScope != "" {
		req.Header.Set(handlers.OrgHeader, orgScope)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

type previewTermJSON struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
	Actual   string `json:"actual"`
	Matched  bool   `json:"matched"`
}

type previewResultJSON struct {
	Index          int               `json:"index"`
	RequestedModel string            `json:"requested_model"`
	Matched        bool              `json:"matched"`
	EffectiveModel string            `json:"effective_model"`
	Terms          []previewTermJSON `json:"terms"`
}

type previewRespJSON struct {
	OrgID       string              `json:"org_id"`
	MatchExpr   string              `json:"match_expr"`
	TargetModel string              `json:"target_model"`
	Results     []previewResultJSON `json:"results"`
	Summary     struct {
		Total   int `json:"total"`
		Matched int `json:"matched"`
	} `json:"summary"`
}

type previewErrJSON struct {
	Error  string `json:"error"`
	Reason string `json:"reason"`
}

func decodePreviewResp(t *testing.T, w *httptest.ResponseRecorder) previewRespJSON {
	t.Helper()
	var resp previewRespJSON
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode preview response: %v\nbody: %s", err, w.Body.String())
	}
	return resp
}

func rootPreviewSession(t *testing.T) string {
	t.Helper()
	return makeSessionCookie(t, "root@x.test", true, previewSecret)
}

func TestRulesPreview_MatchVerdictPerSample(t *testing.T) {
	router := previewRouter(t)
	body := `{"match_expr":"model_requested == \"gpt-4o\"","target_model":"glm-5.3","priority":100,
	          "samples":[{"model_requested":"gpt-4o"},{"model_requested":"claude-3"}]}`
	w := postPreview(t, router, rootPreviewSession(t), "org-a", body)

	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/rules/preview = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	resp := decodePreviewResp(t, w)
	if len(resp.Results) != 2 || resp.Summary.Total != 2 || resp.Summary.Matched != 1 {
		t.Fatalf("unexpected summary: %+v", resp.Summary)
	}
	hit, miss := resp.Results[0], resp.Results[1]
	if !hit.Matched || hit.EffectiveModel != "glm-5.3" {
		t.Errorf("matched sample: %+v, want matched → target glm-5.3", hit)
	}
	if len(hit.Terms) != 1 || !hit.Terms[0].Matched || hit.Terms[0].Actual != "gpt-4o" {
		t.Errorf("matched sample terms: %+v", hit.Terms)
	}
	if miss.Matched || miss.EffectiveModel != "claude-3" {
		t.Errorf("missed sample: %+v, want no match, requested model stays", miss)
	}
	if len(miss.Terms) != 1 || miss.Terms[0].Matched {
		t.Errorf("missed sample terms: %+v", miss.Terms)
	}
}

// The org scope is the trusted identity channel: a body org_id is ignored and
// the clause evaluation runs against the header org (org_id == "org-evil"
// cannot match; org_id == "org-a" does; the response names org-a).
func TestRulesPreview_OrgScopeFromIdentityNotBody(t *testing.T) {
	router := previewRouter(t)
	body := `{"org_id":"org-evil","match_expr":"org_id == \"org-evil\" || org_id == \"org-a\"","target_model":"glm-5.3","priority":1,
	          "samples":[{}]}`
	w := postPreview(t, router, rootPreviewSession(t), "org-a", body)

	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/rules/preview = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	resp := decodePreviewResp(t, w)
	if resp.OrgID != "org-a" {
		t.Errorf("org_id = %q, want the header scope org-a (body value ignored)", resp.OrgID)
	}
	if len(resp.Results) != 1 || !resp.Results[0].Matched {
		t.Fatalf("results: %+v, want one matched sample (org clause against org-a)", resp.Results)
	}
	terms := resp.Results[0].Terms
	if len(terms) != 2 {
		t.Fatalf("terms: %+v, want both org clauses traced", terms)
	}
	if terms[0].Matched || terms[0].Field != "org_id" || terms[0].Actual != "org-a" {
		t.Errorf("foreign-org clause must miss with actual = header org: %+v", terms[0])
	}
	if !terms[1].Matched || terms[1].Actual != "org-a" {
		t.Errorf("own-org clause must match: %+v", terms[1])
	}
}

// A malformed expression is an explicit, machine-readable 400 — not a 500,
// not a panic, not a silent never-match.
func TestRulesPreview_MalformedExpression_MachineReadable(t *testing.T) {
	router := previewRouter(t)
	for _, expr := range []string{"model_requested ==", "gpt-4", `model_requested == "gpt-4" || `} {
		body := `{"match_expr":` + quoteJSON(t, expr) + `,"target_model":"m","samples":[]}`
		w := postPreview(t, router, rootPreviewSession(t), "org-a", body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("malformed expr %q: status %d, want 400; body: %s", expr, w.Code, w.Body.String())
		}
		var errResp previewErrJSON
		if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
			t.Fatalf("decode error body: %v\nbody: %s", err, w.Body.String())
		}
		if errResp.Reason != "invalid_match_expression" || errResp.Error == "" {
			t.Errorf("malformed expr %q: missing machine-readable reason: %+v", expr, errResp)
		}
	}
}

func TestRulesPreview_MissingOrgScope_400(t *testing.T) {
	router := previewRouter(t)
	w := postPreview(t, router, rootPreviewSession(t), "", `{"match_expr":"model_requested == x","samples":[]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing scope header: status %d, want 400; body: %s", w.Code, w.Body.String())
	}
	var errResp previewErrJSON
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil || errResp.Reason != "missing_org_scope" {
		t.Errorf("missing scope: want reason=missing_org_scope, got %s", w.Body.String())
	}
}

// Non-root admins are rejected by the same MustBeRoot gate as the other
// rules routes — before any evaluation happens.
func TestRulesPreview_NonRoot_403(t *testing.T) {
	router := previewRouter(t)
	cookie := makeSessionCookie(t, "admin@x.test", false, previewSecret)
	w := postPreview(t, router, cookie, "org-a", `{"match_expr":"model_requested == x","target_model":"m","samples":[{"model_requested":"x"}]}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-root preview = %d, want 403; body: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "results") {
		t.Errorf("non-root must not receive evaluation results: %s", w.Body.String())
	}
}

func TestRulesPreview_SampleLimitTruncates(t *testing.T) {
	router := previewRouter(t)
	var sb strings.Builder
	sb.WriteString(`{"match_expr":"model_requested == x","target_model":"m","samples":[`)
	for i := range 30 {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"model_requested":"x"}`)
	}
	sb.WriteString(`]}`)
	w := postPreview(t, router, rootPreviewSession(t), "org-a", sb.String())
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body: %s", w.Code, w.Body.String())
	}
	resp := decodePreviewResp(t, w)
	if resp.Summary.Total != 25 || len(resp.Results) != 25 {
		t.Errorf("summary.total = %d, results = %d; want both truncated to %d", resp.Summary.Total, len(resp.Results), 25)
	}
	if resp.Summary.Matched != 25 {
		t.Errorf("all truncated samples match the clause; matched = %d", resp.Summary.Matched)
	}
}

// No store is consulted and no credential field can appear: the payload only
// echoes the caller's own samples and the candidate's fields.
func TestRulesPreview_NoServerSecretsInResponse(t *testing.T) {
	router := previewRouter(t)
	body := `{"match_expr":"session_id == \"s-1\"","target_model":"glm-5.3","priority":1,
	          "samples":[{"session_id":"s-1","client_ip":"10.0.0.1","user_agent":"ua"}]}`
	w := postPreview(t, router, rootPreviewSession(t), "org-a", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
	for _, secret := range []string{"upstream_api_key", "upstream_url", "key_hash", "password"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Errorf("response leaks %q: %s", secret, w.Body.String())
		}
	}
	resp := decodePreviewResp(t, w)
	if !resp.Results[0].Matched || resp.Results[0].EffectiveModel != "glm-5.3" {
		t.Errorf("session clause should match the caller-supplied sample: %+v", resp.Results[0])
	}
}

func TestRulesPreview_EmptySamplesValidatesExpression(t *testing.T) {
	router := previewRouter(t)
	w := postPreview(t, router, rootPreviewSession(t), "org-a", `{"match_expr":"model_requested == \"gpt-4\"","target_model":"m","samples":[]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body: %s", w.Code, w.Body.String())
	}
	resp := decodePreviewResp(t, w)
	if len(resp.Results) != 0 || resp.Summary.Total != 0 {
		t.Errorf("empty batch: %+v", resp.Summary)
	}
	if resp.OrgID != "org-a" || resp.TargetModel != "m" {
		t.Errorf("echo mismatch: %+v", resp)
	}
}

func quoteJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal %q: %v", s, err)
	}
	return string(b)
}
