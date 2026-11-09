package toolexec

// built-in executor. Vectors: method/case tricks on the COMPOSED effective
// name (the one normalization point — pinned on the deny side), payload
// spoofing of the guard coordinates, invalid input refused pre-dispatch,
// URL injection inside guard-checked args, redirects after a guard ALLOW
// (the transport posture must not weaken), and cancelled invokes (a cached
// deny survives; the sticky fail-closed posture denies on a cancelled
// context). Every refusal is diagnosable and leaves a zero upstream counter.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

func boundaryExecEngine(policies ...toolpolicy.Policy) *toolpolicy.Engine {
	return toolpolicy.NewEngine(&guardMemLoader{policies: policies}, 0)
}

// TestExecuteGuarded_EffectiveNameCaseAndPaddingNormalized: the composed
// name is trim+lower normalized, so a deny row for http_post cannot be
// dodged by "PoSt" / " POST " spellings of the method; the allowed method
// still egresses.
func TestExecuteGuarded_EffectiveNameCaseAndPaddingNormalized(t *testing.T) {
	up := newGuardUpstream(t)
	eng := boundaryExecEngine(toolpolicy.Policy{OrgID: "org-1", Name: "deny-post", Subject: "*",
		Server: "yabanin", Tool: "http_post", Action: toolpolicy.ActionDeny,
		Priority: 50, Enabled: true})
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(eng)

	for _, method := range []string{"PoSt", " POST", "POST "} {
		_, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolHTTPRequest,
			json.RawMessage(`{"url":"`+up.URL+`","method":"`+method+`"}`))
		var eErr *ExecError
		if !errors.As(err, &eErr) || eErr.Code != ErrCodeToolBlocked {
			t.Fatalf("method spelling %q must not dodge the http_post deny, got %v", method, err)
		}
		if up.calls.Load() != 0 {
			t.Fatalf("denied spelling must not reach the tool, got %d requests", up.calls.Load())
		}
	}

	if _, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolHTTPRequest,
		json.RawMessage(`{"url":"`+up.URL+`","method":"get"}`)); err != nil {
		t.Fatalf("allowed method must pass: %v", err)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("upstream called once, got %d", up.calls.Load())
	}
}

// TestExecuteGuarded_PayloadCannotSpoofCoordinates: the guard evaluates
// (yabanin, effectiveName) from the CALL arguments — a payload key naming
// another tool neither rescues a denied call nor sinks an allowed one.
func TestExecuteGuarded_PayloadCannotSpoofCoordinates(t *testing.T) {
	up := newGuardUpstream(t)
	eng := boundaryExecEngine(toolpolicy.Policy{OrgID: "org-1", Name: "deny-fetch", Subject: "*",
		Server: "yabanin", Tool: "web_fetch", Action: toolpolicy.ActionDeny,
		Priority: 50, Enabled: true})
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(eng)

	_, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+up.URL+`","tool":"http_get","name":"http_get"}`))
	var eErr *ExecError
	if !errors.As(err, &eErr) || eErr.Code != ErrCodeToolBlocked {
		t.Fatalf("payload keys must not rescue the denied web_fetch call, got %v", err)
	}
	if up.calls.Load() != 0 {
		t.Fatalf("denied call must not reach the tool, got %d requests", up.calls.Load())
	}

	if _, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolHTTPRequest,
		json.RawMessage(`{"url":"`+up.URL+`","method":"get","tool":"web_fetch"}`)); err != nil {
		t.Fatalf("payload keys must not sink the allowed http_get call: %v", err)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("upstream called once, got %d", up.calls.Load())
	}
}

// TestExecuteGuarded_InvalidArgsRefusedPreDispatch: truncated JSON is
// refused by the args guard (invalid_json) before dispatch; with no guard
// rules the same input is refused by the handler as bad_request — both
// diagnosable, both with zero egress and no panic.
func TestExecuteGuarded_InvalidArgsRefusedPreDispatch(t *testing.T) {
	up := newGuardUpstream(t)
	schema := `{"args":{"schema":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"],"additionalProperties":false}}}`

	eng := boundaryExecEngine(toolpolicy.Policy{OrgID: "org-1", Name: "schema", Subject: "*",
		Server: "yabanin", Tool: "web_fetch", Action: toolpolicy.ActionAllow,
		Rules: json.RawMessage(schema), Enabled: true})
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(eng)
	_, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":`))
	var eErr *ExecError
	if !errors.As(err, &eErr) || eErr.Code != ErrCodeToolBlocked {
		t.Fatalf("guarded truncated JSON must be tool_blocked, got %v", err)
	}
	if !strings.Contains(eErr.Message, "schema") {
		t.Fatalf("refusal must name the failing check: %q", eErr.Message)
	}

	bare := NewExecutor(NewDefaultConfig(), nil, nil)
	_, err = bare.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":`))
	if !errors.As(err, &eErr) || eErr.Code != ErrCodeBadReq {
		t.Fatalf("unguarded truncated JSON must be bad_request, got %v", err)
	}
	if up.calls.Load() != 0 {
		t.Fatalf("invalid input must never reach the tool, got %d requests", up.calls.Load())
	}
}

// TestExecuteGuarded_URLInjectionInArgs_BlockedByGuardRegex: the
// contract-default posture — an args deny_regex row forbidding the metadata
// IP / file scheme blocks the call pre-egress with a value-free reason.
func TestExecuteGuarded_URLInjectionInArgs_BlockedByGuardRegex(t *testing.T) {
	up := newGuardUpstream(t)
	eng := boundaryExecEngine(toolpolicy.Policy{OrgID: "org-1", Name: "no-ssrf-urls", Subject: "*",
		Server: "yabanin", Tool: "web_fetch", Action: toolpolicy.ActionAllow,
		Rules: json.RawMessage(`{"args":{"deny_regex":["169\\.254\\.169\\.254","file://"]}}`), Enabled: true})
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(eng)

	for _, params := range []string{
		`{"url":"http://169.254.169.254/latest/meta-data/"}`,
		`{"url":"file:///etc/passwd"}`,
	} {
		_, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
			json.RawMessage(params))
		var eErr *ExecError
		if !errors.As(err, &eErr) || eErr.Code != ErrCodeToolBlocked {
			t.Fatalf("injected URL must be guard-denied, got %v", err)
		}
		if strings.Contains(eErr.Message, "169.254") || strings.Contains(eErr.Message, "passwd") {
			t.Fatalf("refusal must be value-free: %q", eErr.Message)
		}
	}
	if up.calls.Load() != 0 {
		t.Fatalf("blocked calls must not reach the tool, got %d requests", up.calls.Load())
	}

	if _, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+up.URL+`/benign"}`)); err != nil {
		t.Fatalf("benign URL must pass: %v", err)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("upstream called once, got %d", up.calls.Load())
	}
}

// TestExecuteGuarded_AllowStillNoRedirectFollow: a guard ALLOW must not
// weaken the transport posture — a 302 from the (now permitted) target is
// still never followed; the redirect target sees zero requests and the 302
// itself surfaces as an upstream error.
func TestExecuteGuarded_AllowStillNoRedirectFollow(t *testing.T) {
	var targetHits int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits++
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("redirect landed here"))
	}))
	t.Cleanup(target.Close)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/secret", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	eng := boundaryExecEngine(toolpolicy.Policy{OrgID: "org-1", Name: "allow-fetch", Subject: "*",
		Server: "yabanin", Tool: "web_fetch", Action: toolpolicy.ActionAllow, Enabled: true})
	cfg := NewDefaultConfig()
	cfg.ReadTimeout = 500 * time.Millisecond // bound a regression that follows the redirect
	x := NewExecutor(cfg, nil, nil).WithToolGuard(eng)

	_, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+srv.URL+`"}`))
	var eErr *ExecError
	if !errors.As(err, &eErr) || eErr.Code != ErrCodeUpstream {
		t.Fatalf("redirect after allow must surface as upstream error, got %v", err)
	}
	if targetHits != 0 {
		t.Fatalf("redirect target must never be contacted, got %d requests", targetHits)
	}
}

// boundaryCancelLoader serves its rows on a healthy context and fails with
// the context error on a cancelled one.
type boundaryCancelLoader struct {
	policies []toolpolicy.Policy
}

func (l *boundaryCancelLoader) ListEnabled(ctx context.Context, orgID string) ([]toolpolicy.Policy, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []toolpolicy.Policy
	for _, p := range l.policies {
		if p.OrgID == orgID {
			out = append(out, p)
		}
	}
	return out, nil
}

// TestExecuteGuarded_CancelledContext_NeverReadsAsSuccess: a cached deny
// survives a cancelled context, and the sticky fail-closed posture denies a
// cancelled invoke that misses the cache — cancellation converts neither a
// deny into an allow nor the outage into a pass-through.
func TestExecuteGuarded_CancelledContext_NeverReadsAsSuccess(t *testing.T) {
	ctx := context.Background()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	t.Run("cached deny survives", func(t *testing.T) {
		up := newGuardUpstream(t)
		eng := boundaryExecEngine(toolpolicy.Policy{OrgID: "org-1", Name: "deny-fetch", Subject: "*",
			Server: "yabanin", Tool: "web_fetch", Action: toolpolicy.ActionDeny,
			Priority: 50, Enabled: true})
		x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(eng)
		if _, err := x.ExecuteGuarded(ctx, "org-1", "ag-1", ToolWebFetch,
			json.RawMessage(`{"url":"`+up.URL+`"}`)); err == nil {
			t.Fatal("warm deny expected")
		}
		_, err := x.ExecuteGuarded(cancelled, "org-1", "ag-1", ToolWebFetch,
			json.RawMessage(`{"url":"`+up.URL+`"}`))
		var eErr *ExecError
		if !errors.As(err, &eErr) || eErr.Code != ErrCodeToolBlocked {
			t.Fatalf("cached deny must survive cancellation, got %v", err)
		}
		if up.calls.Load() != 0 {
			t.Fatalf("denied calls must not reach the tool, got %d requests", up.calls.Load())
		}
	})

	t.Run("fail-closed posture denies on outage", func(t *testing.T) {
		up := newGuardUpstream(t)
		eng := toolpolicy.NewEngine(&boundaryCancelLoader{policies: []toolpolicy.Policy{{
			OrgID: "org-1", Name: "cap", Subject: "*", Server: "yabanin", Tool: "web_fetch",
			Action: toolpolicy.ActionAllow, Rules: json.RawMessage(`{"args":{"max_bytes":64}}`), Enabled: true,
		}}}, 0)
		x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(eng)
		if _, err := x.ExecuteGuarded(ctx, "org-1", "ag-1", ToolWebFetch,
			json.RawMessage(`{"url":"`+up.URL+`"}`)); err != nil {
			t.Fatalf("warm call must pass: %v", err)
		}
		eng.Invalidate("org-1") // force a cache miss under the cancelled ctx

		_, err := x.ExecuteGuarded(cancelled, "org-1", "ag-1", ToolWebFetch,
			json.RawMessage(`{"url":"`+up.URL+`"}`))
		var eErr *ExecError
		if !errors.As(err, &eErr) || eErr.Code != ErrCodeToolBlocked {
			t.Fatalf("fail-closed org must deny the cancelled invoke, got %v", err)
		}
		if !strings.Contains(eErr.Message, "fail-closed") {
			t.Fatalf("refusal must name the posture (diagnosable): %q", eErr.Message)
		}
		if up.calls.Load() != 1 { // only the warm call reached the tool
			t.Fatalf("denied invoke must not reach the tool, got %d requests", up.calls.Load())
		}
	})
}
