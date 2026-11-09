package toolpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// rulesPol is a guard-rules row (org-1).
func rulesPol(name, server, tool, rules string) Policy {
	return Policy{OrgID: "org-1", Name: name, Subject: "*", Server: server, Tool: tool,
		Action: ActionAllow, Rules: json.RawMessage(rules), Priority: 100, Enabled: true}
}

// orgLoader filters rows by OrgID — mirrors the store's org-scoped SQL
// (`WHERE org_id = $1`), which the shared org-agnostic memLoader ignores.
type orgLoader struct {
	policies []Policy
	err      error
}

func (m *orgLoader) ListEnabled(_ context.Context, orgID string) ([]Policy, error) {
	if m.err != nil {
		return nil, m.err
	}
	var out []Policy
	for _, p := range m.policies {
		if p.OrgID == orgID && p.Enabled {
			out = append(out, p)
		}
	}
	return out, nil
}

// denyPol is a plain allow/deny row (no guard rules).
func denyPol(name, subject, server, tool, action string, prio int) Policy {
	return Policy{OrgID: "org-1", Name: name, Subject: subject, Server: server, Tool: tool,
		Action: action, Priority: prio, Enabled: true}
}

const argsSchemaRules = `{"args":{"schema":{"type":"object","properties":{"q":{"type":"string"}},"required":["q"],"additionalProperties":false}}}`

func TestGuardArgs_DenyPolicy_NoRules(t *testing.T) {
	e := NewEngine(&memLoader{policies: []Policy{
		denyPol("deny-github", "*", "github", "*", ActionDeny, 50),
		denyPol("allow-rest", "*", "*", "*", ActionAllow, 100),
	}}, time.Second)

	if rep := e.GuardArgs(context.Background(), "org-1", "ag-1", "github", "search", []byte(`{}`)); !rep.Denied {
		t.Fatalf("github must be denied: %+v", rep)
	} else if !strings.Contains(rep.Reason, "deny-github") {
		t.Fatalf("reason must name the policy: %q", rep.Reason)
	}
	if rep := e.GuardArgs(context.Background(), "org-1", "ag-1", "other", "search", []byte(`{}`)); rep.Denied {
		t.Fatalf("other servers unaffected: %+v", rep)
	}
}

func TestGuardArgs_SchemaRule(t *testing.T) {
	e := NewEngine(&orgLoader{policies: []Policy{
		rulesPol("guard-github", "github", "*", argsSchemaRules),
	}}, time.Second)

	if rep := e.GuardArgs(context.Background(), "org-1", "ag-1", "github", "search", []byte(`{"q":"x"}`)); rep.Denied {
		t.Fatalf("valid args must pass: %+v", rep)
	}
	rep := e.GuardArgs(context.Background(), "org-1", "ag-1", "github", "search", []byte(`{"wrong":1}`))
	if !rep.Denied || len(rep.Findings) == 0 || rep.Findings[0].Source != "schema" {
		t.Fatalf("schema violation must deny with a finding: %+v", rep)
	}
	// Server-scoped: the same args on another server pass.
	if rep := e.GuardArgs(context.Background(), "org-1", "ag-1", "wiki", "search", []byte(`{"wrong":1}`)); rep.Denied {
		t.Fatalf("rule must not leak to other servers: %+v", rep)
	}
}

// TestGuardArgs_OrgIsolation pins the tenant isolation of guard rules at the
// engine boundary: orgB (no rows) never sees orgA's rules. The DB layer
// scopes every store query by org_id; the engine only ever loads one org's
// rows per cache entry.
func TestGuardArgs_OrgIsolation(t *testing.T) {
	e := NewEngine(&orgLoader{policies: []Policy{
		rulesPol("guard-github", "github", "*", argsSchemaRules),
	}}, time.Second)
	if rep := e.GuardArgs(context.Background(), "org-B", "ag-1", "github", "search", []byte(`{"wrong":1}`)); rep.Denied {
		t.Fatalf("another org's rules must be invisible: %+v", rep)
	}
}

func TestGuardArgs_SubjectScoping(t *testing.T) {
	e := NewEngine(&memLoader{policies: []Policy{
		{OrgID: "org-1", Name: "guard-agent9", Subject: "ag-9", Server: "github", Tool: "*",
			Action: ActionAllow, Rules: json.RawMessage(argsSchemaRules), Enabled: true},
	}}, time.Second)
	if rep := e.GuardArgs(context.Background(), "org-1", "ag-9", "github", "search", []byte(`{"wrong":1}`)); !rep.Denied {
		t.Fatalf("subject-specific rule must apply to its subject: %+v", rep)
	}
	if rep := e.GuardArgs(context.Background(), "org-1", "ag-1", "github", "search", []byte(`{"wrong":1}`)); rep.Denied {
		t.Fatalf("subject-specific rule must not leak to other agents: %+v", rep)
	}
}

func TestGuardArgs_MaxSizeRule(t *testing.T) {
	e := NewEngine(&orgLoader{policies: []Policy{
		rulesPol("cap", "*", "*", `{"args":{"max_bytes":8}}`),
	}}, time.Second)
	if rep := e.GuardArgs(context.Background(), "org-1", "a", "s", "t", []byte(`{"a":1}`)); rep.Denied {
		t.Fatalf("within cap passes: %+v", rep)
	}
	if rep := e.GuardArgs(context.Background(), "org-1", "a", "s", "t", []byte(`{"aaaaaaaa":1}`)); !rep.Denied {
		t.Fatalf("oversize args denied: %+v", rep)
	}
}

func TestGuardArgs_DenyBeatsRules(t *testing.T) {
	// The deny winner short-circuits: rules of other rows still matching
	// cannot loosen a deny (union is purely restrictive).
	e := NewEngine(&memLoader{policies: []Policy{
		denyPol("deny", "*", "github", "*", ActionDeny, 10),
		rulesPol("cap", "*", "*", `{"args":{"max_bytes":8}}`),
	}}, time.Second)
	rep := e.GuardArgs(context.Background(), "org-1", "a", "github", "search", []byte(`{"tiny":1}`))
	if !rep.Denied || !strings.Contains(rep.Reason, "deny") {
		t.Fatalf("deny winner must win: %+v", rep)
	}
}

func TestGuardArgs_LoaderOutage_FailPostures(t *testing.T) {
	// fail-closed posture: once the org loaded a fail-closed rule, a later
	// loader outage denies guarded invokes (sticky across Invalidate).
	loader := &orgLoader{policies: []Policy{rulesPol("cap", "*", "*", `{"args":{"max_bytes":8}}`)}}
	e := NewEngine(loader, time.Second)
	_ = e.GuardArgs(context.Background(), "org-1", "a", "s", "t", []byte(`{}`)) // posture set

	loader.err = errors.New("db down")
	e.Invalidate("org-1")
	rep := e.GuardArgs(context.Background(), "org-1", "a", "s", "t", []byte(`{}`))
	if !rep.Denied || !strings.Contains(rep.Reason, "fail-closed") {
		t.Fatalf("fail-closed posture must deny on outage: %+v", rep)
	}

	// fail-open posture: rules marked fail=open keep traffic flowing.
	loader = &orgLoader{policies: []Policy{rulesPol("cap", "*", "*", `{"args":{"max_bytes":8},"fail":"open"}`)}}
	e = NewEngine(loader, time.Second)
	_ = e.GuardArgs(context.Background(), "org-1", "a", "s", "t", []byte(`{}`))
	loader.err = errors.New("db down")
	e.Invalidate("org-1")
	rep = e.GuardArgs(context.Background(), "org-1", "a", "s", "t", []byte(`{}`))
	if rep.Denied || !rep.Degraded {
		t.Fatalf("fail-open posture must degrade without denying: %+v", rep)
	}

	// No rules ever loaded (no posture): the shipped fail-open default.
	e = NewEngine(&memLoader{err: errors.New("db down")}, time.Second)
	rep = e.GuardArgs(context.Background(), "org-1", "a", "s", "t", []byte(`{}`))
	if rep.Denied || !rep.Degraded {
		t.Fatalf("no posture defaults to fail-open: %+v", rep)
	}
}

func TestGuardResult_MaskAndDeny(t *testing.T) {
	const secret = "AKIA" + "IOSFODNN7EXAMPLE"
	e := NewEngine(&orgLoader{policies: []Policy{
		rulesPol("mask", "github", "*", `{"result":{"mode":"mask","secrets":true}}`),
	}}, time.Second)
	result := []byte(`{"text":"key ` + secret + ` end"}`)

	rep := e.GuardResult(context.Background(), "org-1", "a", "github", "search", result)
	if rep.Action != ResultMask {
		t.Fatalf("mask expected: %+v", rep)
	}
	if strings.Contains(string(rep.Masked), secret) {
		t.Fatal("masked result must not contain the secret")
	}
	// Another org is untouched.
	rep = e.GuardResult(context.Background(), "org-B", "a", "github", "search", result)
	if rep.Action != "" {
		t.Fatalf("org isolation on results: %+v", rep)
	}
	// Non-matching server untouched.
	rep = e.GuardResult(context.Background(), "org-1", "a", "wiki", "search", result)
	if rep.Action != "" {
		t.Fatalf("server scoping on results: %+v", rep)
	}

	// deny beats mask across rows (union, most-restrictive).
	e = NewEngine(&orgLoader{policies: []Policy{
		rulesPol("mask", "github", "*", `{"result":{"mode":"mask","secrets":true}}`),
		rulesPol("deny", "github", "*", `{"result":{"mode":"deny","deny_regex":["forbidden-[0-9]+"]}}`),
	}}, time.Second)
	rep = e.GuardResult(context.Background(), "org-1", "a", "github", "search",
		[]byte(`{"text":"key `+secret+` and forbidden-42"}`))
	if rep.Action != ResultDeny {
		t.Fatalf("deny must win the union: %+v", rep)
	}

	// Sequential fold: the second masking rule observes the first rule's
	// output (both redactions present).
	e = NewEngine(&orgLoader{policies: []Policy{
		rulesPol("mask-secrets", "github", "*", `{"result":{"mode":"mask","secrets":true}}`),
		rulesPol("mask-regex", "github", "*", `{"result":{"mode":"mask","deny_regex":["forbidden-[0-9]+"]}}`),
	}}, time.Second)
	rep = e.GuardResult(context.Background(), "org-1", "a", "github", "search",
		[]byte(`{"text":"key `+secret+` and forbidden-42"}`))
	if rep.Action != ResultMask || rep.Masked == nil {
		t.Fatalf("composed mask: %+v", rep)
	}
	if strings.Contains(string(rep.Masked), secret) || strings.Contains(string(rep.Masked), "forbidden-42") {
		t.Fatalf("both redactions must apply: %s", rep.Masked)
	}
}

func TestGuardResult_LoaderOutage_FailPostures(t *testing.T) {
	loader := &orgLoader{policies: []Policy{rulesPol("mask", "*", "*", `{"result":{"mode":"mask","secrets":true}}`)}}
	e := NewEngine(loader, time.Second)
	_ = e.GuardResult(context.Background(), "org-1", "a", "s", "t", []byte(`{}`))
	loader.err = errors.New("db down")
	e.Invalidate("org-1")
	rep := e.GuardResult(context.Background(), "org-1", "a", "s", "t", []byte(`{}`))
	if rep.Action != ResultDeny {
		t.Fatalf("fail-closed result posture must deny: %+v", rep)
	}
}

func TestDecideTool_ServerRanking(t *testing.T) {
	e := NewEngine(&memLoader{policies: []Policy{
		denyPol("deny-all-tools", "*", "*", "search", ActionDeny, 100),
		denyPol("allow-github", "*", "github", "search", ActionAllow, 100),
	}}, time.Second)
	if d := e.DecideTool(context.Background(), "org-1", "a", "github", "search"); d.Action != ActionAllow || d.Policy.Name != "allow-github" {
		t.Fatalf("server-specific winner: %+v", d)
	}
	if d := e.DecideTool(context.Background(), "org-1", "a", "wiki", "search"); d.Action != ActionDeny {
		t.Fatalf("server-wildcard fallback: %+v", d)
	}
}

// TestDecide_ServerQualifiedRowsInvisible pins the chat-path contract:
// server-qualified rows NEVER affect Decide (which passes server="*").
func TestDecide_ServerQualifiedRowsInvisible(t *testing.T) {
	e := NewEngine(&memLoader{policies: []Policy{
		denyPol("deny-github", "*", "github", "*", ActionDeny, 10),
		denyPol("deny-star", "*", "*", "*", ActionDeny, 100),
	}}, time.Second)
	if d := e.Decide(context.Background(), "org-1", "a", "search"); d.Action != ActionDeny || d.Policy.Name != "deny-star" {
		t.Fatalf("chat path must only see '*' rows: %+v", d)
	}
	if d := e.DecideTool(context.Background(), "org-1", "a", "github", "search"); d.Action != ActionDeny || d.Policy.Name != "deny-github" {
		t.Fatalf("invoke path: server-specific deny wins: %+v", d)
	}
}

func TestGuardArgs_UncompilableRuleRow_FailsClosed(t *testing.T) {
	// Defense in depth for out-of-band writes: the admin CRUD validates,
	// a hand-inserted bad rules row is unenforceable → fail closed.
	e := NewEngine(&memLoader{policies: []Policy{
		{OrgID: "org-1", Name: "broken", Subject: "*", Server: "*", Tool: "*",
			Action: ActionAllow, Rules: json.RawMessage(`{"args":{"deny_regex":["(["]}}`), Enabled: true},
	}}, time.Second)
	rep := e.GuardArgs(context.Background(), "org-1", "a", "s", "t", []byte(`{}`))
	if !rep.Denied || !strings.Contains(rep.Reason, "unenforceable") && !strings.Contains(rep.Reason, "uncompilable") {
		t.Fatalf("uncompilable rules must fail closed: %+v", rep)
	}
}

// TestEngine_ConcurrentGuardAndInvalidate exercises GuardArgs/GuardResult/
// DecideTool/Invalidate together under -race (the cache + postures maps are
// shared mutable state on concurrent request goroutines).
func TestEngine_ConcurrentGuardAndInvalidate(t *testing.T) {
	loader := &orgLoader{policies: []Policy{
		rulesPol("cap", "*", "*", `{"args":{"max_bytes":64},"result":{"mode":"mask","secrets":true}}`),
		denyPol("deny-github", "*", "github", "*", ActionDeny, 50),
	}}
	e := NewEngine(loader, time.Minute)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				org := fmt.Sprintf("org-%d", (g+i)%8)
				server := "github"
				if i%3 == 0 {
					server = "wiki"
				}
				_ = e.GuardArgs(context.Background(), org, "ag-1", server, "search", []byte(`{"q":"x"}`))
				_ = e.GuardResult(context.Background(), org, "ag-1", server, "search", []byte(`{"text":"hi"}`))
				_ = e.DecideTool(context.Background(), org, "ag-1", server, "search")
				_ = e.Decide(context.Background(), org, "ag-1", "search")
				if i%20 == 0 {
					e.Invalidate(org)
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestGuardArgs_EmptyArgsNormalized(t *testing.T) {
	e := NewEngine(&orgLoader{policies: []Policy{
		rulesPol("schema", "*", "*", argsSchemaRules),
	}}, time.Second)
	rep := e.GuardArgs(context.Background(), "org-1", "a", "s", "t", nil)
	if !rep.Denied {
		t.Fatalf("nil args normalize to {} which misses the required key: %+v", rep)
	}
}
