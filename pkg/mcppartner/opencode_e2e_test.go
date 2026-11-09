package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/reireirei/yabanin/pkg/delegation"
	"github.com/reireirei/yabanin/pkg/openai"
)

// OpenCode-compatible fixture: native tool-loop JSON still unmarshals, then
// analyze/implement fake delegates return without writing files.
func TestOpenCodeFixture_ToolLoopThenFakeDelegate(t *testing.T) {
	raw := []byte(`{
		"model":"glm-5.3",
		"messages":[
			{"role":"system","content":"You route through Yabanin."},
			{"role":"user","content":[{"type":"text","text":"hard coding task"}]},
			{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"read","arguments":"{\"path\":\"pkg/gateway/chat.go\"}"}}]},
			{"role":"tool","tool_call_id":"call_1","content":"ok"}
		]
	}`)
	var req openai.ChatCompletionRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatal(err)
	}
	if len(req.Messages) != 4 {
		t.Fatalf("messages=%d", len(req.Messages))
	}

	orch := delegation.NewOrchestrator(t.TempDir(),
		delegation.NewFakeExecutor("codex"),
		delegation.NewFakeExecutor("cursor"),
	)
	h := handleDelegate(orch)
	for _, mode := range []string{"analyze", "implement"} {
		call := mcp.CallToolRequest{}
		call.Params.Arguments = map[string]any{
			"task":     "review pkg/cache",
			"mode":     mode,
			"provider": "auto",
		}
		res, err := h(t.Context(), call)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if res == nil || res.IsError {
			t.Fatalf("%s error result: %+v", mode, res)
		}
		body, _ := json.Marshal(res)
		s := string(body)
		if !strings.Contains(s, "codex") || !strings.Contains(s, "ok") {
			t.Fatalf("%s result=%s", mode, s)
		}
		if strings.Contains(s, "/etc/") {
			t.Fatalf("leaked path: %s", s)
		}
	}

	st, err := handleDelegationStatus(orch)(t.Context(), mcp.CallToolRequest{})
	if err != nil || st == nil || st.IsError {
		t.Fatalf("status: %v %+v", err, st)
	}
}
