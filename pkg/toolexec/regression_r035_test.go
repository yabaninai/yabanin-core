package toolexec

// the working path executes exactly once, every refusal (name deny, args
// deny_regex) keeps the documented behavior with the upstream counter at
// zero, and the result post-checks (mask/deny) compose on the egressed
// body. Neutering the ExecuteGuarded guard block must flip the
// denied/refused assertions below. Boundary cases are in
// toolexec_boundary_r035_test.go.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// regBodyUpstream is a counting fetch target with a fixed secret-bearing
// body (the input of the result post-checks).
type regBodyUpstream struct {
	URL   string
	calls atomic.Int32
	body  string
}

func newRegBodyUpstream(t *testing.T, body string) *regBodyUpstream {
	t.Helper()
	u := &regBodyUpstream{body: body}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		u.calls.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(u.body))
	}))
	t.Cleanup(srv.Close)
	u.URL = srv.URL
	return u
}

const regSecret = "ghp_Abcd" + "EfghAbcdEfghAbcdEfghAbcdEfgh1"

// TestExecuteGuarded_Scenario_PerToolAndArgumentPermissions: one org, one
// policy set, the observables of the packet acceptance — the allowed call
// executes exactly once (result masked by the same row), the name-deny and
// the args-deny never egress.
func TestExecuteGuarded_Scenario_PerToolAndArgumentPermissions(t *testing.T) {
	up := newRegBodyUpstream(t, "token "+regSecret+" ok")
	eng := guardExecEngine(t,
		// Per-tool: plain deny row on the POST shape of http_request.
		toolpolicy.Policy{OrgID: "org-1", Name: "deny-post", Subject: "*",
			Server: "yabanin", Tool: "http_post", Action: toolpolicy.ActionDeny,
			Priority: 50, Enabled: true},
		// Per-argument + result: forbid secret-looking URLs in web_fetch
		// args and mask any secret in the fetched body.
		toolpolicy.Policy{OrgID: "org-1", Name: "guard-fetch", Subject: "*",
			Server: "yabanin", Tool: "web_fetch", Action: toolpolicy.ActionAllow,
			Rules:   json.RawMessage(`{"args":{"deny_regex":["secret-"]},"result":{"mode":"mask","secrets":true}}`),
			Enabled: true},
	)
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(eng)

	// Working path: valid args execute exactly once and the secret-bearing
	// body comes back masked (the same row's result rule).
	res, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+up.URL+`/page"}`))
	if err != nil {
		t.Fatalf("allowed call must pass: %v", err)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("allowed call must execute exactly once, got %d", up.calls.Load())
	}
	if strings.Contains(string(res.Body), regSecret) || !strings.Contains(string(res.Body), "[REDACTED_SECRET]") {
		t.Fatalf("result rule must mask the secret token: %s", res.Body)
	}

	// Per-tool deny: the composed POST shape refuses pre-egress.
	_, err = x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolHTTPRequest,
		json.RawMessage(`{"url":"`+up.URL+`","method":"post"}`))
	var eErr *ExecError
	if !errors.As(err, &eErr) || eErr.Code != ErrCodeToolBlocked {
		t.Fatalf("denied tool must surface tool_blocked, got %v", err)
	}

	// Per-argument deny: secret material in the URL args refuses pre-egress.
	_, err = x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+up.URL+`/secret-token"}`))
	if !errors.As(err, &eErr) || eErr.Code != ErrCodeToolBlocked {
		t.Fatalf("denied args must surface tool_blocked, got %v", err)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("denied calls must not reach the tool, got %d requests", up.calls.Load())
	}
}

// TestExecuteGuarded_Scenario_ResultDenyDropsNotBlocks: the post-egress arm
// of G1 — a result rule in deny mode drops the body of an already-executed
// call (the upstream SAW the call; the caller never sees the result).
func TestExecuteGuarded_Scenario_ResultDenyDropsNotBlocks(t *testing.T) {
	up := newRegBodyUpstream(t, "token "+regSecret+" ok")
	eng := guardExecEngine(t, toolpolicy.Policy{OrgID: "org-1", Name: "no-keys", Subject: "*",
		Server: "yabanin", Tool: "web_fetch", Action: toolpolicy.ActionAllow,
		Rules: json.RawMessage(`{"result":{"mode":"deny","secrets":true}}`), Enabled: true})
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(eng)

	_, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+up.URL+`/leak"}`))
	var eErr *ExecError
	if !errors.As(err, &eErr) || eErr.Code != ErrCodeToolBlocked {
		t.Fatalf("result-deny must surface tool_blocked, got %v", err)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("the upstream ran (the result is dropped, not the call), got %d", up.calls.Load())
	}
	if !strings.Contains(up.body, regSecret) {
		t.Fatalf("sanity: upstream must have served the secret body: %q", up.body)
	}
}
