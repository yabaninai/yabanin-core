package loopexec

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/agentloop"
	"github.com/reireirei/yabanin/pkg/toolexec"
)

func newBuiltin(t *testing.T) *BuiltinExecutor {
	t.Helper()
	x := toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil)
	b, err := NewBuiltinExecutor(x)
	if err != nil {
		t.Fatalf("NewBuiltinExecutor: %v", err)
	}
	return b
}

func builtinCall(tool string, params json.RawMessage) Call {
	return Call{
		Scope:   Scope{OrgID: "org-1", ProjectID: "proj-1", Route: "support-loop"},
		Server:  Server,
		Tool:    tool,
		Action:  ActionInvoke,
		Params:  params,
		Subject: "sub-1",
	}
}

func builtinCfg(tools ...string) Config {
	cfg := validConfig()
	cfg.AllowedTools = tools
	return cfg
}

func TestNewBuiltinExecutorNilRefused(t *testing.T) {
	if _, err := NewBuiltinExecutor(nil); err == nil {
		t.Fatal("nil toolexec executor must be refused (fail-closed wiring)")
	}
}

func TestBuiltinRefusals(t *testing.T) {
	b := newBuiltin(t)
	ctx := context.Background()

	cases := []struct {
		name string
		cfg  Config
		call Call
		want error
	}{
		{
			name: "wrong server",
			cfg:  builtinCfg("yabanin:time_now"),
			call: func() Call { c := builtinCall("time_now", nil); c.Server = "mcp-other"; return c }(),
			want: ErrNoExecutor,
		},
		{
			name: "list action unsupported in v1",
			cfg:  builtinCfg("yabanin:time_now"),
			call: func() Call { c := builtinCall("time_now", nil); c.Action = ActionList; return c }(),
			want: ErrNotPermitted,
		},
		{
			name: "empty subject",
			cfg:  builtinCfg("yabanin:time_now"),
			call: func() Call { c := builtinCall("time_now", nil); c.Subject = ""; return c }(),
			want: ErrSubjectRequired,
		},
		{
			name: "delegated-user credential refused (I54)",
			cfg:  builtinCfg("yabanin:time_now"),
			call: func() Call {
				c := builtinCall("time_now", nil)
				c.Credential = agentloop.CredentialRef{Mode: agentloop.CredentialDelegatedUser, Ref: "u-1"}
				return c
			}(),
			want: ErrNotPermitted,
		},
		{
			name: "tool not on allow-list",
			cfg:  builtinCfg("yabanin:web_fetch"),
			call: builtinCall("time_now", nil),
			want: ErrNotPermitted,
		},
		{
			name: "empty allow-list denies everything",
			cfg:  builtinCfg(),
			call: builtinCall("time_now", nil),
			want: ErrNotPermitted,
		},
		{
			name: "call scope must match config scope",
			cfg:  builtinCfg("yabanin:time_now"),
			call: func() Call {
				c := builtinCall("time_now", nil)
				c.Scope = Scope{OrgID: "org-2", ProjectID: "proj-1", Route: "support-loop"}
				return c
			}(),
			want: ErrNotPermitted,
		},
		{
			name: "unknown tool surfaces as ErrUnknownTool",
			cfg:  builtinCfg("yabanin:nope"),
			call: builtinCall("nope", nil),
			want: ErrUnknownTool,
		},
		{
			name: "invalid config refused",
			cfg: func() Config {
				cfg := builtinCfg("yabanin:time_now")
				cfg.Edition = "ga"
				return cfg
			}(),
			call: builtinCall("time_now", nil),
			want: nil, // refused via validation error, asserted textually below
		},
	}
	for _, tc := range cases {
		_, err := b.Execute(ctx, tc.cfg, tc.call)
		if err == nil {
			t.Errorf("%s: expected refusal", tc.name)
			continue
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s: want %v, got %v", tc.name, tc.want, err)
		}
	}
}

func TestBuiltinConfigEditionValidatedInsideExecute(t *testing.T) {
	b := newBuiltin(t)
	cfg := builtinCfg("yabanin:time_now")
	cfg.Edition = "ga"
	_, err := b.Execute(context.Background(), cfg, builtinCall("time_now", nil))
	if err == nil || !strings.Contains(err.Error(), "edition") {
		t.Fatalf("execute with non-experimental edition must be refused, got %v", err)
	}
}

func TestBuiltinTimeNowSuccess(t *testing.T) {
	b := newBuiltin(t)
	res, err := b.Execute(context.Background(), builtinCfg("yabanin:time_now"), builtinCall("time_now", nil))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.Server != Server || res.Tool != toolexec.ToolTimeNow {
		t.Fatalf("addressing mismatch: %+v", res)
	}
	if res.SideEffect != agentloop.SideEffectNone {
		t.Fatalf("time_now must classify as no effect, got %q", res.SideEffect)
	}
	var payload struct {
		RFC3339 string `json:"rfc3339"`
		Epoch   int64  `json:"epoch"`
	}
	if err := json.Unmarshal(res.Payload, &payload); err != nil {
		t.Fatalf("payload not the guarded tool body: %v (%s)", err, string(res.Payload))
	}
	if payload.RFC3339 == "" || payload.Epoch == 0 {
		t.Fatalf("payload incomplete: %+v", payload)
	}
}

func TestBuiltinHTTPSideEffectClassification(t *testing.T) {
	var lastMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastMethod = r.Method
		if r.URL.Path == "/ok" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"done":true}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	b := newBuiltin(t)
	ctx := context.Background()

	t.Run("mutating success is done", func(t *testing.T) {
		params := json.RawMessage(`{"url":"` + srv.URL + `/ok","method":"post"}`)
		res, err := b.Execute(ctx, builtinCfg("yabanin:http_request"), builtinCall("http_request", params))
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if lastMethod != http.MethodPost {
			t.Fatalf("expected POST on the wire, got %s", lastMethod)
		}
		if res.SideEffect != agentloop.SideEffectDone {
			t.Fatalf("confirmed mutation must classify done, got %q", res.SideEffect)
		}
	})

	t.Run("mutating upstream failure is uncertain (no blind retry input)", func(t *testing.T) {
		params := json.RawMessage(`{"url":"` + srv.URL + `/boom","method":"put"}`)
		res, err := b.Execute(ctx, builtinCfg("yabanin:http_request"), builtinCall("http_request", params))
		if err == nil {
			t.Fatal("upstream failure must be an error")
		}
		if res.SideEffect != agentloop.SideEffectUncertain {
			t.Fatalf("ambiguous mutating failure must stay uncertain, got %q", res.SideEffect)
		}
		if !strings.Contains(err.Error(), "request status 500") {
			t.Fatalf("typed toolexec error must pass through, got %v", err)
		}
	})

	t.Run("safe-method upstream failure is none", func(t *testing.T) {
		params := json.RawMessage(`{"url":"` + srv.URL + `/boom","method":"get"}`)
		res, err := b.Execute(ctx, builtinCfg("yabanin:http_request"), builtinCall("http_request", params))
		if err == nil {
			t.Fatal("upstream failure must be an error")
		}
		if res.SideEffect != agentloop.SideEffectNone {
			t.Fatalf("read-only failure must classify none, got %q", res.SideEffect)
		}
	})

	t.Run("default method is a safe get", func(t *testing.T) {
		params := json.RawMessage(`{"url":"` + srv.URL + `/ok"}`)
		res, err := b.Execute(ctx, builtinCfg("yabanin:http_request"), builtinCall("http_request", params))
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if res.SideEffect != agentloop.SideEffectNone {
			t.Fatalf("default-method http_request must classify none, got %q", res.SideEffect)
		}
	})
}

func TestBuiltinGuardRefusalClassifiesNone(t *testing.T) {
	// A mutating call refused BEFORE egress (bad method) must classify as
	// no effect: nothing external changed.
	b := newBuiltin(t)
	params := json.RawMessage(`{"url":"http://127.0.0.1:1/x","method":"banana"}`)
	res, err := b.Execute(context.Background(), builtinCfg("yabanin:http_request"), builtinCall("http_request", params))
	if err == nil {
		t.Fatal("invalid method must fail")
	}
	if res.SideEffect != agentloop.SideEffectNone {
		t.Fatalf("pre-egress refusal must classify none, got %q", res.SideEffect)
	}
	if !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("guard refusal must wrap ErrNotPermitted, got %v", err)
	}
	if !strings.Contains(err.Error(), toolexec.ErrCodeBadReq) {
		t.Fatalf("refusal message must carry the guard code for diagnostics, got %v", err)
	}
}

func TestRegistryWithBuiltinWiring(t *testing.T) {
	// The documented wiring: registry("yabanin" → builtin adapter).
	reg := NewRegistry()
	b := newBuiltin(t)
	if err := reg.Register(Server, b); err != nil {
		t.Fatalf("register builtin: %v", err)
	}
	cfg := builtinCfg("yabanin:time_now")
	res, err := reg.Execute(context.Background(), cfg, builtinCall("time_now", nil))
	if err != nil {
		t.Fatalf("registry dispatch to builtin: %v", err)
	}
	if res.Tool != toolexec.ToolTimeNow {
		t.Fatalf("unexpected result %+v", res)
	}
}
