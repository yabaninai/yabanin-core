package toolpolicy

// Vectors from the contract failure scenario — payload-coordinate spoofing
// (args claiming another tool/server), case/unicode normalization tricks on
// pattern matching, invalid input (truncated JSON / wrong types), and the
// repeat/cancel dimension (a cached deny survives a cancelled context; the
// sticky fail-closed posture denies on a cancelled-context outage — the
// invoke-path contrast to the D-15 chat-surface fail-open, which is pinned
// on the gateway side). Every refusal is diagnosable (reason names the row
// or the check) and value-free (matched material never appears).

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

const boundaryDenyRow = "deny-delete"

func boundaryEngine(t *testing.T, policies ...Policy) *Engine {
	t.Helper()
	return NewEngine(&orgLoader{policies: policies}, 0)
}

// TestGuardArgs_PayloadCannotSpoofDecisionCoordinates: the guard evaluates
// the coordinates the CALL carries (server, tool) — never anything inside
// the args payload. A deny row for one tool must not fire because the args
// merely mention that tool (or another server), and must fire exactly when
// the call coordinates match.
func TestGuardArgs_PayloadCannotSpoofDecisionCoordinates(t *testing.T) {
	e := boundaryEngine(t,
		denyPol(boundaryDenyRow, "*", "github", "delete_issue", ActionDeny, 50),
	)
	spoofing := json.RawMessage(`{"tool":"delete_issue","server":"other-org-server","name":"delete_issue"}`)

	if rep := e.GuardArgs(context.Background(), "org-1", "ag-1", "github", "search", spoofing); rep.Denied {
		t.Fatalf("args content must not shift the decision coordinates: %+v", rep)
	}
	rep := e.GuardArgs(context.Background(), "org-1", "ag-1", "github", "delete_issue",
		json.RawMessage(`{"tool":"search","id":1}`))
	if !rep.Denied || !strings.Contains(rep.Reason, boundaryDenyRow) {
		t.Fatalf("matching coordinates must deny with the row name: %+v", rep)
	}
}

// TestGuardDeclaredArgs_ArgsCannotSpoofCoordinates: the same invariant on
// tool stays evaluated under ITS declared name even when the arguments
// carry a nested tool/server payload targeting a denied tool.
func TestGuardDeclaredArgs_ArgsCannotSpoofCoordinates(t *testing.T) {
	e := boundaryEngine(t,
		denyPol("deny-shell", "*", "*", "shell", ActionDeny, 50),
	)
	spoofing := json.RawMessage(`{"tool":"shell","command":"cat /etc/passwd"}`)

	if rep := e.GuardDeclaredArgs(context.Background(), "org-1", "ag-1", "web_fetch", spoofing); rep.Denied {
		t.Fatalf("declared-name coordinates only; args content must not import another tool's deny: %+v", rep)
	}
	if rep := e.GuardDeclaredArgs(context.Background(), "org-1", "ag-1", "shell",
		json.RawMessage(`{"tool":"web_fetch"}`)); !rep.Denied || !strings.Contains(rep.Reason, "deny-shell") {
		t.Fatalf("declared shell call must deny regardless of args: %+v", rep)
	}
}

// TestGuardArgs_PatternMatchingHasNoNormalization pins the byte-exact
// pattern semantics: no case folding, no unicode normalization. A lookalike
// name never inherits a row written for the canonical name (the mcpagg
// allow-list ceiling is the family boundary and refuses variants — pinned
// at the proxy level); a name FAMILY must be written as a wildcard deny.
func TestGuardArgs_PatternMatchingHasNoNormalization(t *testing.T) {
	e := boundaryEngine(t,
		denyPol(boundaryDenyRow, "*", "github", "delete_issue", ActionDeny, 50),
	)
	ctx := context.Background()
	if rep := e.GuardArgs(ctx, "org-1", "ag-1", "github", "delete_issue", []byte(`{}`)); !rep.Denied {
		t.Fatalf("canonical name must be denied: %+v", rep)
	}
	for _, lookalike := range []string{"Delete_ISSUE", "delete＿issue"} {
		if rep := e.GuardArgs(ctx, "org-1", "ag-1", "github", lookalike, []byte(`{}`)); rep.Denied {
			t.Fatalf("lookalike %q must NOT be denied by the exact row (byte-exact match, pinned): %+v", lookalike, rep)
		}
	}

	// The wildcard form is the documented way to cover a name family: a
	// BYTE prefix (so it also catches case-glued variants sharing the
	// prefix) but never a case-changed head.
	e = boundaryEngine(t, denyPol("deny-family", "*", "github", "delete*", ActionDeny, 50))
	for _, variant := range []string{"delete_issue", "delete_issue_v2", "deleteIssue"} {
		rep := e.GuardArgs(ctx, "org-1", "ag-1", "github", variant, []byte(`{}`))
		if !rep.Denied || !strings.Contains(rep.Reason, "deny-family") {
			t.Fatalf("prefix wildcard must deny the byte-prefix variant %q: %+v", variant, rep)
		}
	}
	if rep := e.GuardArgs(ctx, "org-1", "ag-1", "github", "Delete_ISSUE", []byte(`{}`)); rep.Denied {
		t.Fatalf("case-changed head escapes the byte prefix (pinned): %+v", rep)
	}
}

// TestGuardArgs_InvalidInputDiagnosable: truncated JSON and wrong-typed
// values deny with a diagnosable, VALUE-FREE report — the reason names the
// check, findings name source + category + pointer, never the offending
// bytes.
func TestGuardArgs_InvalidInputDiagnosable(t *testing.T) {
	e := boundaryEngine(t,
		rulesPol("schema", "github", "*",
			`{"args":{"schema":{"type":"object","properties":{"title":{"type":"string"}},"required":["title"],"additionalProperties":false}}}`),
	)
	ctx := context.Background()

	// Contract §3 example 2, input В: truncated JSON.
	rep := e.GuardArgs(ctx, "org-1", "ag-1", "github", "create_issue", json.RawMessage(`{"title":`))
	if !rep.Denied || len(rep.Findings) == 0 {
		t.Fatalf("truncated JSON must deny: %+v", rep)
	}
	if rep.Findings[0].Source != "schema" || rep.Findings[0].Category != "invalid_json" {
		t.Fatalf("diagnosable invalid_json finding expected: %+v", rep.Findings)
	}

	// Wrong type: the finding is a keyword path + pointer, no value echo.
	rep = e.GuardArgs(ctx, "org-1", "ag-1", "github", "create_issue", json.RawMessage(`{"title":123}`))
	if !rep.Denied {
		t.Fatalf("wrong-typed value must deny: %+v", rep)
	}
	f := rep.Findings[0]
	if f.Source != "schema" || !strings.Contains(f.Category, "type") || f.Span != "/title" {
		t.Fatalf("schema finding must name the keyword path and pointer: %+v", f)
	}
	if strings.Contains(rep.Reason, "123") {
		t.Fatalf("reason must be value-free: %q", rep.Reason)
	}

	// The valid shape still passes (the guardrail is not a wall).
	if rep := e.GuardArgs(ctx, "org-1", "ag-1", "github", "create_issue",
		json.RawMessage(`{"title":"ok"}`)); rep.Denied {
		t.Fatalf("valid args must pass: %+v", rep)
	}
}

// cancelAwareLoader serves its rows on a healthy context and fails with the
// context error on a cancelled one — the store-outage shape an in-flight
// cancelled request meets.
type cancelAwareLoader struct {
	policies []Policy
}

func (l *cancelAwareLoader) ListEnabled(ctx context.Context, orgID string) ([]Policy, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []Policy
	for _, p := range l.policies {
		if p.OrgID == orgID {
			out = append(out, p)
		}
	}
	return out, nil
}

// TestGuardArgs_CancelledContext_DenySurvives: a deny decision served from
// the fresh cache must survive a cancelled context — cancellation converts
// neither a deny into an allow nor the answer into a degraded pass-through.
func TestGuardArgs_CancelledContext_DenySurvives(t *testing.T) {
	e := NewEngine(&cancelAwareLoader{policies: []Policy{
		denyPol(boundaryDenyRow, "*", "github", "delete_issue", ActionDeny, 50),
	}}, 0)
	ctx := context.Background()
	if rep := e.GuardArgs(ctx, "org-1", "ag-1", "github", "delete_issue", []byte(`{}`)); !rep.Denied {
		t.Fatalf("warm deny expected: %+v", rep)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	rep := e.GuardArgs(cancelled, "org-1", "ag-1", "github", "delete_issue", []byte(`{}`))
	if !rep.Denied || !strings.Contains(rep.Reason, boundaryDenyRow) {
		t.Fatalf("cached deny must survive cancellation: %+v", rep)
	}
}

// TestGuardArgs_CancelledContext_StickyFailClosed: the D-15 contrast — the
// chat response surface fails OPEN on a cancelled context (pinned on the
// gateway side); the INVOKE-side guard must not inherit that. A fail-closed
// org whose cache miss coincides with the cancellation denies (posture),
// and an org with no posture at least reports Degraded — an unknown state
// is never reported as a clean allow.
func TestGuardArgs_CancelledContext_StickyFailClosed(t *testing.T) {
	// Warm the sticky fail-closed posture on a healthy load.
	e := NewEngine(&cancelAwareLoader{policies: []Policy{
		rulesPol("cap", "github", "*", `{"args":{"max_bytes":64}}`),
	}}, 0)
	ctx := context.Background()
	if rep := e.GuardArgs(ctx, "org-1", "ag-1", "github", "search", []byte(`{"q":"x"}`)); rep.Denied {
		t.Fatalf("warm pass expected: %+v", rep)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	e.Invalidate("org-1")
	rep := e.GuardArgs(cancelled, "org-1", "ag-1", "github", "search", []byte(`{"q":"x"}`))
	if !rep.Denied || !strings.Contains(rep.Reason, "fail-closed") {
		t.Fatalf("fail-closed org must deny on a cancelled-context outage: %+v", rep)
	}

	// No posture ever loaded: the shipped default degrades — counted as an
	// error by the callers, never silently read as an allow.
	e = NewEngine(&cancelAwareLoader{}, 0)
	rep = e.GuardArgs(cancelled, "org-1", "ag-1", "github", "search", []byte(`{}`))
	if rep.Denied || !rep.Degraded {
		t.Fatalf("no-posture org must report Degraded (an error, not an allow): %+v", rep)
	}
}
