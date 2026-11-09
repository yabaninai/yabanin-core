package loopexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/agentloop"
)

func validConfig() Config {
	return Config{
		Edition:      EditionExperimental,
		Scope:        Scope{OrgID: "org-1", ProjectID: "proj-1", Route: "support-loop"},
		AllowedTools: []string{"yabanin:time_now"},
		MaxToolCalls: 8,
	}
}

func TestScopeValidate(t *testing.T) {
	cases := []struct {
		name  string
		scope Scope
		ok    bool
	}{
		{"complete", Scope{OrgID: "o", ProjectID: "p", Route: "r"}, true},
		{"missing org", Scope{ProjectID: "p", Route: "r"}, false},
		{"missing project", Scope{OrgID: "o", Route: "r"}, false},
		{"missing route", Scope{OrgID: "o", ProjectID: "p"}, false},
		{"route uppercase", Scope{OrgID: "o", ProjectID: "p", Route: "Route"}, false},
		{"route leading dash", Scope{OrgID: "o", ProjectID: "p", Route: "-r"}, false},
		{"route with dot", Scope{OrgID: "o", ProjectID: "p", Route: "a.b"}, false},
		{"route digits ok", Scope{OrgID: "o", ProjectID: "p", Route: "r2"}, true},
		{"route dash underscore ok", Scope{OrgID: "o", ProjectID: "p", Route: "a-b_c"}, true},
	}
	for _, tc := range cases {
		err := tc.scope.Validate()
		if tc.ok && err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s: expected refusal", tc.name)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		if err := validConfig().Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("edition is load-bearing (D4)", func(t *testing.T) {
		for _, edition := range []string{"", "ga", "stable", "experimental ", "Experimental", "v1"} {
			cfg := validConfig()
			cfg.Edition = edition
			err := cfg.Validate()
			if err == nil {
				t.Errorf("edition %q must be refused", edition)
				continue
			}
			if !strings.Contains(err.Error(), EditionExperimental) {
				t.Errorf("edition %q: error should name the supported edition, got %v", edition, err)
			}
		}
	})
	t.Run("zero tool bound denies", func(t *testing.T) {
		cfg := validConfig()
		cfg.MaxToolCalls = 0
		if err := cfg.Validate(); err == nil {
			t.Fatal("zero MaxToolCalls must be refused (fail-closed bound)")
		}
		cfg.MaxToolCalls = -3
		if err := cfg.Validate(); err == nil {
			t.Fatal("negative MaxToolCalls must be refused")
		}
	})
	t.Run("invalid scope propagates", func(t *testing.T) {
		cfg := validConfig()
		cfg.Scope.Route = ""
		if err := cfg.Validate(); err == nil {
			t.Fatal("invalid scope must be refused")
		}
	})
	t.Run("allow-list entries must be server-qualified", func(t *testing.T) {
		cfg := validConfig()
		cfg.AllowedTools = []string{"yabanin:time_now", "baretool"}
		if err := cfg.Validate(); err == nil {
			t.Fatal("unqualified allow-list entry must be refused")
		}
	})
	t.Run("empty allow-list is legal", func(t *testing.T) {
		cfg := validConfig()
		cfg.AllowedTools = nil
		if err := cfg.Validate(); err != nil {
			t.Fatalf("empty allow-list must validate: %v", err)
		}
		if cfg.Allows("yabanin", "time_now") {
			t.Fatal("empty allow-list must allow nothing (fail-closed default)")
		}
	})
}

func TestConfigAllows(t *testing.T) {
	cfg := validConfig()
	if !cfg.Allows("yabanin", "time_now") {
		t.Fatal("listed tool must be allowed")
	}
	if cfg.Allows("yabanin", "web_fetch") {
		t.Fatal("unlisted tool must be refused")
	}
	if cfg.Allows("other", "time_now") {
		t.Fatal("tool on another server must be refused")
	}
}

func TestToolNameRoundTrip(t *testing.T) {
	s, tool, ok := SplitToolName(ToolName("yabanin", "time_now"))
	if !ok || s != "yabanin" || tool != "time_now" {
		t.Fatalf("round trip failed: %q %q %v", s, tool, ok)
	}
	if _, _, ok := SplitToolName("nocolon"); ok {
		t.Fatal("unqualified name must not split")
	}
}

type stubExecutor struct {
	gotCfg  Config
	gotCall Call
	result  Result
	err     error
}

func (s *stubExecutor) Execute(_ context.Context, cfg Config, call Call) (Result, error) {
	s.gotCfg, s.gotCall = cfg, call
	return s.result, s.err
}

func TestRegistryRegisterAndDispatch(t *testing.T) {
	reg := NewRegistry()
	stub := &stubExecutor{result: Result{Server: "mcp-a", Tool: "t1"}}
	if err := reg.Register("mcp-a", stub); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := reg.Register("mcp-a", &stubExecutor{}); err == nil {
		t.Fatal("duplicate registration must be refused (write-once seam)")
	}
	if err := reg.Register("Bad Server", &stubExecutor{}); err == nil {
		t.Fatal("invalid server name must be refused")
	}
	if err := reg.Register("mcp-b", nil); err == nil {
		t.Fatal("nil executor must be refused")
	}
	if _, ok := reg.Executor("mcp-b"); ok {
		t.Fatal("unregistered server must resolve to nothing")
	}

	cfg := validConfig()
	cfg.AllowedTools = []string{"mcp-a:t1"}
	got, err := reg.Execute(context.Background(), cfg, Call{
		Scope: cfg.Scope, Server: "mcp-a", Tool: "t1", Action: ActionInvoke,
		Params: json.RawMessage(`{}`), Subject: "sub-1",
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if got.Server != stub.result.Server || got.Tool != stub.result.Tool {
		t.Fatalf("dispatch returned %+v, want %+v", got, stub.result)
	}
	if stub.gotCfg.Scope != cfg.Scope || stub.gotCall.Subject != "sub-1" {
		t.Fatalf("stub received cfg=%+v call=%+v", stub.gotCfg, stub.gotCall)
	}
}

func TestRegistryExecuteUnknownServer(t *testing.T) {
	reg := NewRegistry()
	_, err := reg.Execute(context.Background(), validConfig(), Call{Server: "ghost"})
	if !errors.Is(err, ErrNoExecutor) {
		t.Fatalf("want ErrNoExecutor, got %v", err)
	}
}

func TestSentinelsDistinct(t *testing.T) {
	errs := []error{ErrNoExecutor, ErrNotPermitted, ErrUnknownTool, ErrSubjectRequired}
	seen := map[string]bool{}
	for _, e := range errs {
		if seen[e.Error()] {
			t.Fatalf("duplicate sentinel text: %v", e)
		}
		seen[e.Error()] = true
	}
	for _, e := range errs {
		if !errors.Is(fmt.Errorf("ctx: %w", e), e) {
			t.Fatalf("sentinel %v not errors.Is-able through wrap", e)
		}
	}
}

func TestActionVocabularyMirrorsGrantActions(t *testing.T) {
	// The executor action vocabulary must stay aligned with the grant
	// action dimension (pkg/mcpagg): invoke and list.
	if ActionInvoke != "invoke" || ActionList != "list" {
		t.Fatalf("action vocabulary drifted: %q %q", ActionInvoke, ActionList)
	}
}

func TestSideEffectVocabularySharedWithAgentloop(t *testing.T) {
	// Results reuse the frozen agentloop effect classes so uncertainty
	// means the same thing across the stack.
	if agentloop.SideEffectNone != "none" || agentloop.SideEffectDone != "done" || agentloop.SideEffectUncertain != "uncertain" {
		t.Fatal("agentloop side-effect vocabulary drifted")
	}
}
