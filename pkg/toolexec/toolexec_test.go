package toolexec

// Executor tests over httptest upstreams: happy path, guard deny, SSRF
// rejection, bad params, non-2xx, wrong content type, truncation, unknown
// tool, timeout.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type denyHook struct{ reason string }

func (h denyHook) Scan(_ context.Context, p []byte) ([]byte, string, string) {
	if h.reason != "" {
		return p, h.reason, "deny"
	}
	return p, "", "log"
}

func testExec(validate func(string) error, hook Hook) *Executor {
	cfg := NewDefaultConfig()
	return NewExecutor(cfg, validate, hook)
}

func TestWebFetch_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html>hello</html>"))
	}))
	t.Cleanup(srv.Close)

	res, err := testExec(func(string) error { return nil }, nil).
		Execute(context.Background(), ToolWebFetch, json.RawMessage(`{"url":"`+srv.URL+`"}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var out webFetchResult
	if err := json.Unmarshal(res.Body, &out); err != nil {
		t.Fatalf("result: %v", err)
	}
	if out.Content != "<html>hello</html>" || out.Status != 200 || out.Truncated {
		t.Fatalf("unexpected result: %+v", out)
	}
	if res.UpstreamURL != srv.URL {
		t.Fatalf("upstream url not reported")
	}
}

func TestWebFetch_GuardDeny(t *testing.T) {
	_, err := testExec(nil, denyHook{reason: "secrets in url"}).
		Execute(context.Background(), ToolWebFetch, json.RawMessage(`{"url":"https://x.test"}`))
	var e *ExecError
	if !errorsAs(err, &e) || e.Code != ErrCodeDenied {
		t.Fatalf("guard deny: got %v", err)
	}
}

func TestWebFetch_SSRFBlocked(t *testing.T) {
	_, err := testExec(func(string) error { return errSSRFFixture }, nil).
		Execute(context.Background(), ToolWebFetch, json.RawMessage(`{"url":"https://blocked.test"}`))
	var e *ExecError
	if !errorsAs(err, &e) || e.Code != ErrCodeSSRF {
		t.Fatalf("ssrf: got %v", err)
	}
}

func TestWebFetch_BadParams(t *testing.T) {
	for _, body := range []string{`{}`, `not json`, `{"nope":1}`} {
		_, err := testExec(nil, nil).Execute(context.Background(), ToolWebFetch, json.RawMessage(body))
		var e *ExecError
		if !errorsAs(err, &e) || e.Code != ErrCodeBadReq {
			t.Fatalf("params %q: got %v", body, err)
		}
	}
}

func TestWebFetch_UpstreamStatusAndContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/404") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte{0x00, 0x01})
	}))
	t.Cleanup(srv.Close)

	if _, err := testExec(nil, nil).Execute(context.Background(), ToolWebFetch,
		json.RawMessage(`{"url":"`+srv.URL+`/404"}`)); codeOf(err) != ErrCodeUpstream {
		t.Fatalf("404: got %v", err)
	}
	if _, err := testExec(nil, nil).Execute(context.Background(), ToolWebFetch,
		json.RawMessage(`{"url":"`+srv.URL+`/bin"}`)); codeOf(err) != ErrCodeUpstream {
		t.Fatalf("binary: got %v", err)
	}
}

func TestWebFetch_Truncation(t *testing.T) {
	big := strings.Repeat("a", 100)
	cfg := NewDefaultConfig()
	cfg.MaxResponseBytes = 50
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(big))
	}))
	t.Cleanup(srv.Close)

	res, err := NewExecutor(cfg, nil, nil).Execute(context.Background(), ToolWebFetch,
		json.RawMessage(`{"url":"`+srv.URL+`"}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var out webFetchResult
	_ = json.Unmarshal(res.Body, &out)
	if !out.Truncated || len(out.Content) != 50 {
		t.Fatalf("truncation: %+v", out)
	}
}

func TestWebFetch_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("late"))
	}))
	t.Cleanup(srv.Close)

	cfg := NewDefaultConfig()
	cfg.ReadTimeout = 50 * time.Millisecond
	_, err := NewExecutor(cfg, nil, nil).Execute(context.Background(), ToolWebFetch,
		json.RawMessage(`{"url":"`+srv.URL+`"}`))
	if codeOf(err) != ErrCodeTimeout {
		t.Fatalf("timeout: got %v", err)
	}
}

// TestRedirect_ReservedTargetBlocked pins the SSRF redirect posture: a 302
// is NEVER followed, so a redirect chain cannot smuggle the gateway to a
// blocked target such as the cloud metadata endpoint (169.254.169.254).
// The redirect response itself surfaces as an upstream error.
func TestRedirect_ReservedTargetBlocked(t *testing.T) {
	metadata := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, metadata, http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	cfg := NewDefaultConfig()
	cfg.ReadTimeout = 500 * time.Millisecond // bound a regression that dials the metadata IP
	x := NewExecutor(cfg, func(string) error { return nil }, nil)

	_, err := x.Execute(context.Background(), ToolWebFetch, json.RawMessage(`{"url":"`+srv.URL+`"}`))
	var e *ExecError
	if !errorsAs(err, &e) || e.Code != ErrCodeUpstream {
		t.Fatalf("redirect must surface as upstream error, got %v", err)
	}
	if !strings.Contains(e.Message, "302") {
		t.Fatalf("the 302 response itself must be returned (no follow), got %q", e.Message)
	}
}

// TestRedirect_TargetNeverContacted proves the same posture end-to-end for
// every dialing handler: the redirect target receives zero requests.
func TestRedirect_TargetNeverContacted(t *testing.T) {
	var targetHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("redirect landed here"))
	}))
	t.Cleanup(target.Close)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/secret", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	x := testExec(func(string) error { return nil }, nil)
	cases := []struct {
		tool   string
		params string
		// http_head serves non-2xx responses as data (headers-only tool):
		// the 302 is returned, not followed.
		wantErr bool
	}{
		{ToolWebFetch, `{"url":"` + srv.URL + `"}`, true},
		{ToolHTTPRequest, `{"url":"` + srv.URL + `","method":"get"}`, true},
		{ToolHTTPHead, `{"url":"` + srv.URL + `"}`, false},
	}
	for _, tc := range cases {
		res, err := x.Execute(context.Background(), tc.tool, json.RawMessage(tc.params))
		if tc.wantErr {
			if codeOf(err) != ErrCodeUpstream {
				t.Errorf("%s: redirect must be refused as upstream error, got %v", tc.tool, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: head of a 302 must be served as data, got %v", tc.tool, err)
			continue
		}
		if !strings.Contains(string(res.Body), `"status":302`) {
			t.Errorf("%s: the redirect response itself must be surfaced, got %s", tc.tool, res.Body)
		}
	}
	if hits := targetHits.Load(); hits != 0 {
		t.Fatalf("redirect target must never be contacted, hits = %d", hits)
	}
}

func TestExecute_UnknownTool(t *testing.T) {
	_, err := testExec(nil, nil).Execute(context.Background(), "shell", nil)
	if codeOf(err) != ErrCodeNotFound {
		t.Fatalf("unknown tool: got %v", err)
	}
}

// helpers

var errSSRFFixture = &ExecError{Code: ErrCodeSSRF, Message: "fixture"}

func errorsAs(err error, target **ExecError) bool {
	if e, ok := err.(*ExecError); ok {
		*target = e
		return true
	}
	return false
}

func codeOf(err error) string {
	var e *ExecError
	if errorsAs(err, &e) {
		return e.Code
	}
	return ""
}

func TestCatalog(t *testing.T) {
	cat := Catalog()
	names := map[string]bool{}
	for _, d := range cat {
		names[d.Name] = true
		if d.Description == "" {
			t.Errorf("tool %q missing description", d.Name)
		}
	}
	for _, want := range []string{"web_fetch", "http_request", "http_head", "dns_lookup", "time_now"} {
		if !names[want] {
			t.Errorf("catalog missing %q", want)
		}
	}
}

func TestHTTPRequest_EffectiveName(t *testing.T) {
	cases := map[string]string{
		`{"url":"https://x","method":"POST"}`:   "http_post",
		`{"url":"https://x","method":"delete"}`: "http_delete",
		`{"url":"https://x"}`:                   "http_get", // default method
	}
	for params, want := range cases {
		if got := EffectiveToolName(ToolHTTPRequest, json.RawMessage(params)); got != want {
			t.Errorf("EffectiveToolName(%s): got %q, want %q", params, got, want)
		}
	}
	if got := EffectiveToolName(ToolWebFetch, nil); got != "web_fetch" {
		t.Errorf("plain tool name must pass through, got %q", got)
	}
}

func TestHTTPRequest_Methods(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	t.Cleanup(srv.Close)

	x := testExec(func(string) error { return nil }, nil)

	// POST with a JSON body round-trips.
	res, err := x.Execute(context.Background(), ToolHTTPRequest, json.RawMessage(
		`{"url":"`+srv.URL+`","method":"post","body":{"k":"v"}}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	var out map[string]any
	_ = json.Unmarshal(res.Body, &out)
	if out["body"] != `{"k":"v"}` || out["status"] != float64(200) {
		t.Fatalf("post result: %+v", out)
	}

	// Unsupported method → bad_request.
	if _, err := x.Execute(context.Background(), ToolHTTPRequest, json.RawMessage(
		`{"url":"`+srv.URL+`","method":"TRACE"}`)); codeOf(err) != ErrCodeBadReq {
		t.Fatalf("trace: got %v", err)
	}
	// 405 upstream → upstream error.
	if _, err := x.Execute(context.Background(), ToolHTTPRequest, json.RawMessage(
		`{"url":"`+srv.URL+`","method":"get"}`)); codeOf(err) != ErrCodeUpstream {
		t.Fatalf("405: got %v", err)
	}
	// SSRF guard applies.
	if _, err := testExec(func(string) error { return errSSRFFixture }, nil).
		Execute(context.Background(), ToolHTTPRequest, json.RawMessage(`{"url":"https://blocked.test"}`)); codeOf(err) != ErrCodeSSRF {
		t.Fatalf("ssrf: got %v", err)
	}
}

func TestHTTPHead_SanitizedHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Set-Cookie", "session=secret")
		w.Header().Set("X-Custom", "ok")
	}))
	t.Cleanup(srv.Close)

	res, err := testExec(func(string) error { return nil }, nil).
		Execute(context.Background(), ToolHTTPHead, json.RawMessage(`{"url":"`+srv.URL+`"}`))
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	body := string(res.Body)
	if codeOf(err) != "" {
		t.Fatal(err)
	}
	if strings.Contains(body, "secret") || strings.Contains(body, "Set-Cookie") {
		t.Fatalf("credential header leaked: %s", body)
	}
	if !strings.Contains(body, "X-Custom") || !strings.Contains(body, "text/html") {
		t.Fatalf("safe headers missing: %s", body)
	}
}

func TestDNSLookup(t *testing.T) {
	// Literal IP: no DNS needed.
	res, err := testExec(nil, nil).Execute(context.Background(), ToolDNSLookup,
		json.RawMessage(`{"host":"127.0.0.1"}`))
	if err != nil {
		t.Fatalf("dns ip: %v", err)
	}
	if !strings.Contains(string(res.Body), "127.0.0.1") {
		t.Fatalf("ip result: %s", res.Body)
	}
	// Guard deny applies.
	if _, err := testExec(nil, denyHook{reason: "blocked host"}).
		Execute(context.Background(), ToolDNSLookup, json.RawMessage(`{"host":"example.com"}`)); codeOf(err) != ErrCodeDenied {
		t.Fatalf("guard: got %v", err)
	}
	// Bad params.
	if _, err := testExec(nil, nil).Execute(context.Background(), ToolDNSLookup,
		json.RawMessage(`{}`)); codeOf(err) != ErrCodeBadReq {
		t.Fatalf("params: got %v", err)
	}
}

func TestTimeNow(t *testing.T) {
	res, err := testExec(nil, nil).Execute(context.Background(), ToolTimeNow, nil)
	if err != nil {
		t.Fatalf("time: %v", err)
	}
	var out map[string]any
	_ = json.Unmarshal(res.Body, &out)
	if out["rfc3339"] == "" || out["epoch"] == nil {
		t.Fatalf("time result: %s", res.Body)
	}
	// No egress: UpstreamURL must be empty.
	if res.UpstreamURL != "" {
		t.Fatalf("time_now must not dial out, got %q", res.UpstreamURL)
	}
}
