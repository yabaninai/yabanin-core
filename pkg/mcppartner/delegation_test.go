package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/reireirei/yabanin/pkg/delegation"
)

func TestDelegationFromEnv_DisabledDoesNotBuildOrchestrator(t *testing.T) {
	t.Setenv("YABANIN_DELEGATION_ENABLED", "")
	t.Setenv("YABANIN_DELEGATION_BRIDGE_URL", "http://127.0.0.1:9")
	opts := DelegationFromEnv()
	if opts.Enabled || opts.Orchestrator != nil {
		t.Fatalf("disabled env must not construct orchestrator: %+v", opts)
	}
}

func TestDelegationFromEnv_EnabledUsesFakeWithoutBridge(t *testing.T) {
	t.Setenv("YABANIN_DELEGATION_ENABLED", "true")
	t.Setenv("YABANIN_DELEGATION_BRIDGE_URL", "")
	t.Setenv("YABANIN_DELEGATION_WORKSPACE", t.TempDir())
	opts := DelegationFromEnv()
	if !opts.Enabled || opts.Orchestrator == nil {
		t.Fatal("expected orchestrator")
	}
	st := opts.Orchestrator.Status(t.Context())
	if !st.Providers["codex"].Available || !st.Providers["cursor"].Available {
		t.Fatalf("fake executors missing: %+v", st)
	}
}

func TestNewMCPHandlerWithDelegation_DisabledOmitsTool(t *testing.T) {
	s := NewMCPHandlerWithDelegation(NewGatewayClient("", "", "k", "k"), nil)
	if s == nil {
		t.Fatal("server")
	}
}

func TestHandleDelegate_FakeExecutor(t *testing.T) {
	orch := delegation.NewOrchestrator(t.TempDir(), delegation.NewFakeExecutor("codex"))
	h := handleDelegate(orch)
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{
		"task":     "review the cache package",
		"mode":     "analyze",
		"provider": "codex",
	}
	res, err := h(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("unexpected error result: %+v", res)
	}
	raw, _ := json.Marshal(res)
	if !strings.Contains(string(raw), "codex") || !strings.Contains(string(raw), "ok") {
		t.Fatalf("result=%s", raw)
	}
}

func TestHandleDelegationStatus(t *testing.T) {
	orch := delegation.NewOrchestrator(t.TempDir(), delegation.NewFakeExecutor("codex"))
	res, err := handleDelegationStatus(orch)(t.Context(), mcp.CallToolRequest{})
	if err != nil || res == nil || res.IsError {
		t.Fatalf("status: %v %+v", err, res)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(strings.ToLower(string(raw)), "api_key") {
		t.Fatalf("status leaked credential field: %s", raw)
	}
}
