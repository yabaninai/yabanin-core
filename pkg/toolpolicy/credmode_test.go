package toolpolicy

// N05-P02-T04 tests: the credential-mode constraint lives in the rules
// document (validated vocabulary, mode-only docs allowed) and
// DecideCredMode follows the specificity winner among constrained rows —
// fail-closed on loader outages and on matching rows with uncompilable
// rules (an authorization input must never silently degrade to
// "unconstrained").

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func modePol(name, subject, server, tool, mode string, prio int) Policy {
	return Policy{
		OrgID: "org-1", Name: name, Subject: subject, Server: server, Tool: tool,
		Action: ActionAllow, Rules: []byte(`{"credential_mode":"` + mode + `"}`),
		Priority: prio, Enabled: true,
	}
}

func TestDecideCredMode_NoConstrainedRows_NoMode(t *testing.T) {
	e := NewEngine(&memLoader{policies: []Policy{
		pol("deny-all", "*", "*", ActionDeny, 100), // plain row, no rules
	}}, time.Second)
	mode, p, err := e.DecideCredMode(context.Background(), "org-1", "agent-1", "kb", "search")
	if err != nil || mode != "" || p != nil {
		t.Fatalf("no constrained rows must yield (\"\", nil, nil), got (%q, %v, %v)", mode, p, err)
	}
}

func TestDecideCredMode_SpecificityWinner(t *testing.T) {
	cases := []struct {
		name     string
		policies []Policy
		subject  string
		server   string
		tool     string
		want     string
		wantPol  string
	}{
		{
			name: "tool exact beats tool star",
			policies: []Policy{
				modePol("mode-star", "*", "*", "*", CredentialModeService, 100),
				modePol("mode-exact", "*", "*", "kb_search", CredentialModeDelegated, 100),
			},
			subject: "agent-1", server: "kb", tool: "kb_search",
			want: CredentialModeDelegated, wantPol: "mode-exact",
		},
		{
			name: "server exact beats server star",
			policies: []Policy{
				modePol("mode-any-server", "*", "*", "*", CredentialModeDelegated, 100),
				modePol("mode-kb", "*", "kb", "*", CredentialModeService, 100),
			},
			subject: "agent-1", server: "kb", tool: "anything",
			want: CredentialModeService, wantPol: "mode-kb",
		},
		{
			name: "subject-specific beats org-wide",
			policies: []Policy{
				modePol("mode-org", "*", "*", "*", CredentialModeService, 100),
				modePol("mode-agent9", "agent-9", "*", "*", CredentialModeDelegated, 100),
			},
			subject: "agent-9", server: "kb", tool: "x",
			want: CredentialModeDelegated, wantPol: "mode-agent9",
		},
		{
			name: "priority breaks same-specificity ties (lower wins)",
			policies: []Policy{
				modePol("mode-p100", "*", "*", "*", CredentialModeService, 100),
				modePol("mode-p10", "*", "*", "*", CredentialModeDelegated, 10),
			},
			subject: "agent-1", server: "kb", tool: "x",
			want: CredentialModeDelegated, wantPol: "mode-p10",
		},
		{
			name: "unconstrained matching row never loosens a constrained one",
			policies: []Policy{
				pol("plain-star", "*", "*", ActionAllow, 100), // matches, no constraint
				modePol("mode-exact", "*", "*", "kb_search", CredentialModeDelegated, 100),
			},
			subject: "agent-1", server: "kb", tool: "kb_search",
			want: CredentialModeDelegated, wantPol: "mode-exact",
		},
		{
			name: "auto is a real constraint (beats the org-wide pin)",
			policies: []Policy{
				modePol("mode-org", "*", "*", "*", CredentialModeService, 100),
				modePol("mode-auto-exact", "*", "*", "kb_search", CredentialModeAuto, 100),
			},
			subject: "agent-1", server: "kb", tool: "kb_search",
			want: CredentialModeAuto, wantPol: "mode-auto-exact",
		},
		{
			name: "disabled constrained rows are ignored",
			policies: []Policy{
				func() Policy {
					p := modePol("mode-off", "*", "*", "*", CredentialModeService, 100)
					p.Enabled = false
					return p
				}(),
			},
			subject: "agent-1", server: "kb", tool: "x",
			want: "", wantPol: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEngine(&memLoader{policies: tc.policies}, time.Second)
			mode, p, err := e.DecideCredMode(context.Background(), "org-1", tc.subject, tc.server, tc.tool)
			if err != nil {
				t.Fatalf("decideCredMode: %v", err)
			}
			if mode != tc.want {
				t.Fatalf("mode = %q, want %q", mode, tc.want)
			}
			if tc.wantPol == "" {
				if p != nil {
					t.Fatalf("policy = %v, want nil", p)
				}
				return
			}
			if p == nil || p.Name != tc.wantPol {
				t.Fatalf("policy = %v, want %q", p, tc.wantPol)
			}
		})
	}
}

func TestDecideCredMode_LoaderError_FailClosed(t *testing.T) {
	e := NewEngine(&memLoader{err: errors.New("db down")}, time.Second)
	mode, _, err := e.DecideCredMode(context.Background(), "org-1", "agent-1", "kb", "search")
	if err == nil || mode != "" {
		t.Fatalf("loader outage must fail closed with an error, got (%q, %v)", mode, err)
	}
}

func TestDecideCredMode_UncompilableMatchingRow_FailClosed(t *testing.T) {
	e := NewEngine(&memLoader{policies: []Policy{
		{OrgID: "org-1", Name: "bad-mode", Subject: "*", Server: "*", Tool: "*",
			Action: ActionAllow, Rules: []byte(`{"credential_mode":"sudo"}`),
			Priority: 100, Enabled: true},
	}}, time.Second)
	mode, _, err := e.DecideCredMode(context.Background(), "org-1", "agent-1", "kb", "search")
	if err == nil || mode != "" {
		t.Fatalf("matching row with uncompilable rules must fail closed, got (%q, %v)", mode, err)
	}
	if !strings.Contains(err.Error(), "uncompilable") {
		t.Fatalf("error must name the uncompilable row, got %v", err)
	}
}

func TestDecideCredMode_UncompilableNonMatchingRow_Ignored(t *testing.T) {
	e := NewEngine(&memLoader{policies: []Policy{
		{OrgID: "org-1", Name: "bad-other-agent", Subject: "agent-else", Server: "*", Tool: "*",
			Action: ActionAllow, Rules: []byte(`{"credential_mode":"sudo"}`),
			Priority: 100, Enabled: true},
	}}, time.Second)
	mode, _, err := e.DecideCredMode(context.Background(), "org-1", "agent-1", "kb", "search")
	if err != nil || mode != "" {
		t.Fatalf("non-matching row must not fail the decision, got (%q, %v)", mode, err)
	}
}

func TestCompileRules_ModeOnlyDoc(t *testing.T) {
	r, err := CompileRules([]byte(`{"credential_mode":"delegated"}`))
	if err != nil {
		t.Fatalf("mode-only doc must compile: %v", err)
	}
	if r.CredentialMode() != CredentialModeDelegated {
		t.Fatalf("credentialMode = %q, want %q", r.CredentialMode(), CredentialModeDelegated)
	}
	if !r.failClosed {
		t.Fatal("mode-only doc must keep the default fail-closed posture")
	}
}

func TestCompileRules_ModeWithGuards(t *testing.T) {
	r, err := CompileRules([]byte(`{"args":{"max_bytes":10},"credential_mode":"service"}`))
	if err != nil {
		t.Fatalf("mode+guards doc must compile: %v", err)
	}
	if r.CredentialMode() != "service" || r.argsMaxBytes != 10 {
		t.Fatalf("bad compile: mode=%q maxBytes=%d", r.CredentialMode(), r.argsMaxBytes)
	}
}

func TestCompileRules_UnknownModeRejected(t *testing.T) {
	for _, doc := range []string{
		`{"credential_mode":"sudo"}`,
		`{"credential_mode":"SERVICE"}`,
		`{"credential_mode":""}`,
	} {
		if _, err := CompileRules([]byte(doc)); err == nil {
			t.Fatalf("doc %s must be rejected", doc)
		}
	}
}

func TestCompileRules_UnknownFieldStillRejected(t *testing.T) {
	if _, err := CompileRules([]byte(`{"credentialmode":"service"}`)); err == nil {
		t.Fatal("unknown field (typo) must still be rejected")
	}
	if _, err := CompileRules([]byte(`{"credential_mode":"service","evil":true}`)); err == nil {
		t.Fatal("unknown sibling field must still be rejected")
	}
}

func TestValidateRulesJSON_ModeOnlyDoc(t *testing.T) {
	if err := ValidateRulesJSON([]byte(`{"credential_mode":"auto"}`)); err != nil {
		t.Fatalf("mode-only doc must validate: %v", err)
	}
	if err := ValidateRulesJSON([]byte(`{"credential_mode":"root"}`)); err == nil {
		t.Fatal("unknown mode must not validate")
	}
	if err := ValidateRulesJSON([]byte(`{}`)); err == nil {
		t.Fatal("empty doc must still be rejected (no checks, no mode)")
	}
}

func TestCompileRules_LegacyDocsUnchanged(t *testing.T) {
	r, err := CompileRules([]byte(`{"args":{"max_bytes":5}}`))
	if err != nil {
		t.Fatalf("legacy doc must compile: %v", err)
	}
	if r.CredentialMode() != "" {
		t.Fatalf("legacy doc must carry no credential mode, got %q", r.CredentialMode())
	}
}
