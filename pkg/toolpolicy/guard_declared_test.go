package toolpolicy

// model-declared tool_calls. Pins the chat-path scoping (server-qualified
// rows are invisible), the deny-winner + union rules composition, and the
// outage postures.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type declaredLoader struct{ policies []Policy }

func (m *declaredLoader) ListEnabled(_ context.Context, orgID string) ([]Policy, error) {
	var out []Policy
	for _, p := range m.policies {
		if p.OrgID == orgID {
			out = append(out, p)
		}
	}
	return out, nil
}

func declaredEngine(t *testing.T, policies ...Policy) *Engine {
	t.Helper()
	return NewEngine(&declaredLoader{policies: policies}, 0)
}

// TestGuardDeclaredArgs_ChatScopeOnly: server-qualified rows are
// MCP-invoke-scoped — the chat-path args guard must not see them (Decide
// parity, pinned for names by guard_test.go).
func TestGuardDeclaredArgs_ChatScopeOnly(t *testing.T) {
	serverScoped := Policy{OrgID: "org-1", Name: "mcp-only", Subject: "*",
		Server: "github", Tool: "*",
		Rules: json.RawMessage(`{"args":{"deny_regex":["secret"]}}`), Enabled: true}
	eng := declaredEngine(t, serverScoped)

	rep := eng.GuardDeclaredArgs(context.Background(), "org-1", "ag-1", "create_issue",
		json.RawMessage(`{"title":"my secret title"}`))
	if rep.Denied || rep.Degraded {
		t.Fatalf("server-qualified rules must be invisible to the chat path: %+v", rep)
	}

	// The same row DOES bite on the MCP invoke path (GuardArgs parity).
	if rep := eng.GuardArgs(context.Background(), "org-1", "ag-1", "github", "create_issue",
		json.RawMessage(`{"title":"my secret title"}`)); !rep.Denied {
		t.Fatalf("the invoke path must still enforce the server-qualified rule: %+v", rep)
	}
}

// TestGuardDeclaredArgs_DenyWinnerAndRules: the chat-path deny winner
// blocks with the policy name before any args check; an allow row's rules
// compose over the union (the stricter of two matching rules applies).
func TestGuardDeclaredArgs_DenyWinnerAndRules(t *testing.T) {
	eng := declaredEngine(t,
		Policy{OrgID: "org-1", Name: "deny-shell", Subject: "*", Tool: "shell",
			Action: ActionDeny, Enabled: true},
		Policy{OrgID: "org-1", Name: "small-cap", Subject: "*", Tool: "web_fetch",
			Action: ActionAllow, Rules: json.RawMessage(`{"args":{"max_bytes":16}}`), Enabled: true},
		Policy{OrgID: "org-1", Name: "no-keys", Subject: "*", Tool: "web_fetch",
			Action: ActionAllow, Rules: json.RawMessage(`{"args":{"deny_regex":["sk-[A-Za-z0-9]{8,}"]}}`), Enabled: true},
	)

	// Deny winner (no rules on the row).
	rep := eng.GuardDeclaredArgs(context.Background(), "org-1", "ag-1", "shell", json.RawMessage(`{}`))
	if !rep.Denied || !strings.Contains(rep.Reason, "deny-shell") {
		t.Fatalf("deny winner must block with its name: %+v", rep)
	}

	// Union: the stricter of the two rules denies (max_bytes) ...
	rep = eng.GuardDeclaredArgs(context.Background(), "org-1", "ag-1", "web_fetch",
		json.RawMessage(`{"payload":"`+strings.Repeat("x", 32)+`"}`))
	if !rep.Denied || rep.Findings[0].Source != "max_size" {
		t.Fatalf("max_bytes rule must deny: %+v", rep)
	}

	// ... and deny_regex denies a small payload.
	rep = eng.GuardDeclaredArgs(context.Background(), "org-1", "ag-1", "web_fetch",
		json.RawMessage(`{"payload":"token sk-abcdefgh1234"}`))
	if !rep.Denied || rep.Findings[0].Source != "deny_regex" {
		t.Fatalf("deny_regex rule must deny: %+v", rep)
	}

	// Value-free invariant: the matched material never appears in the report.
	if strings.Contains(rep.Reason, "sk-abcdefgh") {
		t.Fatalf("findings must be value-free: %+v", rep)
	}
}

// TestGuardDeclaredArgs_Posture: a loader outage follows the org's sticky
// fail posture — fail-closed ⇒ deny (even across Invalidate), fail-open ⇒
// Degraded (the response surface treats that as pass-through).
func TestGuardDeclaredArgs_Posture(t *testing.T) {
	// Warm the sticky posture with a healthy load of a fail-closed rule.
	warm := declaredEngine(t, Policy{OrgID: "org-1", Name: "cap", Subject: "*",
		Tool: "*", Action: ActionAllow, Rules: json.RawMessage(`{"args":{"max_bytes":8},"fail":"closed"}`), Enabled: true})
	if rep := warm.GuardDeclaredArgs(context.Background(), "org-1", "ag-1", "t", json.RawMessage(`{}`)); rep.Denied {
		t.Fatalf("healthy store must pass: %+v", rep)
	}

	// Break the loader: the sticky fail-closed posture denies.
	warm.loader = errLoaderOnly{err: errors.New("store down")}
	warm.Invalidate("org-1")
	if rep := warm.GuardDeclaredArgs(context.Background(), "org-1", "ag-1", "t", json.RawMessage(`{}`)); !rep.Denied {
		t.Fatalf("fail-closed org must deny on outage: %+v", rep)
	}

	// A fail-open org degrades (pass-through on the response surface).
	open := NewEngine(errLoaderOnly{err: errors.New("store down")}, 0)
	if rep := open.GuardDeclaredArgs(context.Background(), "org-1", "ag-1", "t", json.RawMessage(`{}`)); !rep.Degraded || rep.Denied {
		t.Fatalf("fail-open org must degrade on outage: %+v", rep)
	}
}

type errLoaderOnly struct{ err error }

func (l errLoaderOnly) ListEnabled(context.Context, string) ([]Policy, error) {
	return nil, l.err
}
