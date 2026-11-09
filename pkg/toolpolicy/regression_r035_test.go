package toolpolicy

// (GuardDeclaredArgs, server='*' rows only) and the MCP invoke guard
// (GuardArgs, server-qualified rows) each enforce their own scope on the
// SAME tool: a chat-passing call that violates an invoke-only schema row is
// still stopped the moment it travels the invoke path. This is the mutation
// anchor for the G2 mechanism: skipping the GuardDeclaredArgs checks must
// flip the chat-surface deny assertions below (see

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestGuardDeclaredArgs_Scenario_TwoLayerEnforcement: one tool, two rows,
// two surfaces — each surface sees exactly its own scope and the layers
// compose.
func TestGuardDeclaredArgs_Scenario_TwoLayerEnforcement(t *testing.T) {
	e := NewEngine(&orgLoader{policies: []Policy{
		// Chat-path row: secret material may not even be DECLARED to the
		// client-side executor.
		rulesPol("chat-no-keys", "*", "create_issue",
			`{"args":{"deny_regex":["BEGIN (RSA )?PRIVATE KEY"]}}`),
		// Server-qualified row: the MCP invoke path additionally pins the
		// create_issue argument shape — invisible to the chat path.
		rulesPol("gh-schema", "github", "create_issue",
			`{"args":{"schema":{"type":"object","properties":{"title":{"type":"string"}},"required":["title"],"additionalProperties":false}}}`),
	}}, 0)
	ctx := context.Background()

	// Working path: valid declared args pass the chat gate.
	if rep := e.GuardDeclaredArgs(ctx, "org-1", "ag-1", "create_issue",
		json.RawMessage(`{"title":"t"}`)); rep.Denied || rep.Degraded {
		t.Fatalf("valid declared args must pass: %+v", rep)
	}

	// Declared secret material is refused by the chat row, value-free.
	rep := e.GuardDeclaredArgs(ctx, "org-1", "ag-1", "create_issue",
		json.RawMessage(`{"body":"BEGIN RSA PRIVATE KEY MIIEpA..."}`))
	if !rep.Denied || !strings.Contains(rep.Reason, "chat-no-keys") {
		t.Fatalf("declared secret must deny naming the chat row: %+v", rep)
	}
	if strings.Contains(rep.Reason, "BEGIN RSA") || strings.Contains(rep.Reason, "MIIEpA") {
		t.Fatalf("refusal must be value-free: %q", rep.Reason)
	}

	// Layering: a title-less call passes the chat gate (the schema row is
	// server-scoped and MUST be invisible there) — and the same call is
	// denied by the second layer the moment it travels the invoke path.
	if rep := e.GuardDeclaredArgs(ctx, "org-1", "ag-1", "create_issue",
		json.RawMessage(`{"body":"no title"}`)); rep.Denied {
		t.Fatalf("server-scoped schema must not bite the chat path: %+v", rep)
	}
	if rep := e.GuardArgs(ctx, "org-1", "ag-1", "github", "create_issue",
		json.RawMessage(`{"body":"no title"}`)); !rep.Denied || !strings.Contains(rep.Reason, "gh-schema") {
		t.Fatalf("the invoke layer must enforce its own row: %+v", rep)
	}

	// On the invoke path the union applies: BOTH rows bite (the schema deny
	// short-circuits first in stable name order — chat-no-keys < gh-schema).
	rep = e.GuardArgs(ctx, "org-1", "ag-1", "github", "create_issue",
		json.RawMessage(`{"body":"BEGIN RSA PRIVATE KEY ..."}`))
	if !rep.Denied {
		t.Fatalf("invoke path must deny the secret-bearing call: %+v", rep)
	}
}
