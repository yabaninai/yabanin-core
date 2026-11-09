package toolpolicy

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func compile(t *testing.T, raw string) *Rules {
	t.Helper()
	r, err := CompileRules(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("CompileRules(%s): %v", raw, err)
	}
	return r
}

func TestCompileRules_EmptyAndNull(t *testing.T) {
	for _, raw := range []string{``, `null`} {
		r, err := CompileRules(json.RawMessage(raw))
		if err != nil {
			t.Fatalf("CompileRules(%q): %v", raw, err)
		}
		if r == nil {
			t.Fatal("nil rules for empty doc")
		}
	}
	if err := ValidateRulesJSON(nil); err != nil {
		t.Fatalf("nil rules must validate: %v", err)
	}
}

func TestCompileRules_Invalid(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"unknown field", `{"nope":1}`, "unknown field"},
		{"no checks", `{}`, "must define args or result"},
		{"args empty", `{"args":{}}`, "defines no checks"},
		{"bad regex", `{"args":{"deny_regex":["(["]}}`, "regex[0]"},
		{"empty regex", `{"args":{"deny_regex":[""]}}`, "empty pattern"},
		{"oversize regex", `{"args":{"deny_regex":["` + strings.Repeat("a", 600) + `"]}}`, "max 512"},
		{"bad fail", `{"args":{"max_bytes":10},"fail":"whatever"}`, `rules.fail must be`},
		{"bad result mode", `{"result":{"mode":"nuke","secrets":true}}`, "result.mode must be"},
		{"result no checks", `{"result":{"mode":"deny"}}`, "result defines no checks"},
		{"negative max_bytes", `{"args":{"max_bytes":-1}}`, "max_bytes"},
		{"bad schema", `{"args":{"schema":{"type":"no-such-type"}}}`, "schema"},
		{"bad json", `{nope`, "rules"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileRules(json.RawMessage(tc.raw))
			if err == nil {
				t.Fatalf("must reject: %s", tc.raw)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q must mention %q", err, tc.want)
			}
		})
	}
	if _, err := CompileRules(json.RawMessage(`{"args":{"deny_regex":["a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a"]}}`)); err == nil {
		t.Fatal("17 regexes must exceed the per-list cap")
	}
}

func TestCheckArgs_Schema(t *testing.T) {
	r := compile(t, `{"args":{"schema":{
		"type":"object",
		"properties":{"q":{"type":"string","maxLength":3}},
		"required":["q"],
		"additionalProperties":false
	}}}`)

	if rep := r.CheckArgs([]byte(`{"q":"ok"}`)); rep.Denied {
		t.Fatalf("valid args must pass: %+v", rep)
	}

	rep := r.CheckArgs([]byte(`{"q":"toolong"}`))
	if !rep.Denied || len(rep.Findings) == 0 {
		t.Fatalf("maxLength violation must deny: %+v", rep)
	}
	f := rep.Findings[0]
	if f.Source != "schema" || f.Action != "deny" {
		t.Fatalf("finding source/action: %+v", f)
	}
	if !strings.HasPrefix(f.Span, "/q") {
		t.Fatalf("span must be the instance JSON pointer, got %q", f.Span)
	}
	// Value-free invariant: the violating VALUE ("toolong") never appears in
	// the report — only the location and the schema keyword.
	if strings.Contains(rep.Reason, "toolong") || strings.Contains(f.Category, "toolong") {
		t.Fatalf("reason/category must not carry the instance value: %+v", rep)
	}

	rep = r.CheckArgs([]byte(`{"other":1}`))
	if !rep.Denied {
		t.Fatalf("missing required must deny: %+v", rep)
	}
	rep = r.CheckArgs([]byte(`not-json`))
	if !rep.Denied || rep.Findings[0].Category != "invalid_json" {
		t.Fatalf("non-JSON args must deny as invalid_json: %+v", rep)
	}
}

func TestCheckArgs_MaxBytes(t *testing.T) {
	r := compile(t, `{"args":{"max_bytes":10}}`)
	if rep := r.CheckArgs([]byte(`{"a":"b"}`)); rep.Denied {
		t.Fatalf("within cap must pass: %+v", rep)
	}
	rep := r.CheckArgs([]byte(`{"a":"0123456789"}`))
	if !rep.Denied || rep.Findings[0].Source != "max_size" {
		t.Fatalf("oversize must deny: %+v", rep)
	}
}

func TestCheckArgs_DenyRegex(t *testing.T) {
	const secret = "sk-abcdef1234567890abcdef"
	r := compile(t, `{"args":{"deny_regex":["sk-[A-Za-z0-9_-]{16,}"]}}`)
	args := []byte(`{"note":"value ` + secret + ` here"}`)
	rep := r.CheckArgs(args)
	if !rep.Denied || rep.Findings[0].Source != "deny_regex" {
		t.Fatalf("forbidden pattern must deny: %+v", rep)
	}
	// Value-free invariant: the matched secret never appears anywhere in the
	// report (reason, categories, spans are offsets).
	if strings.Contains(rep.Reason, secret) {
		t.Fatalf("reason must not echo the matched value: %q", rep.Reason)
	}
	for _, f := range rep.Findings {
		if strings.Contains(f.Span, secret) || strings.Contains(f.Category, secret) {
			t.Fatalf("finding must not echo the matched value: %+v", f)
		}
	}
	want := strings.Index(string(args), secret)
	if rep.Findings[0].Span != fmt.Sprintf("%d:%d", want, want+len(secret)) {
		t.Fatalf("span must be byte offsets, got %q", rep.Findings[0].Span)
	}
}

func TestCheckResult_Secrets(t *testing.T) {
	const secret = "ghp_Abcd" + "EfghAbcdEfghAbcdEfghAbcdEfgh1"
	result := []byte(`{"content":[{"type":"text","text":"token is ` + secret + `"}]}`)

	flag := compile(t, `{"result":{"mode":"flag","secrets":true}}`)
	rep := flag.CheckResult(result)
	if rep.Action != ResultFlag || rep.Masked != nil {
		t.Fatalf("flag must pass unchanged: %+v", rep)
	}
	if len(rep.Findings) == 0 || rep.Findings[0].Source != "secrets" {
		t.Fatalf("secrets finding expected: %+v", rep)
	}
	if strings.Contains(string(rep.Masked), secret) || strings.Contains(rep.Reason, secret) {
		t.Fatal("flag findings/reason must not carry the secret")
	}

	mask := compile(t, `{"result":{"mode":"mask","secrets":true}}`)
	rep = mask.CheckResult(result)
	if rep.Action != ResultMask {
		t.Fatalf("mask action: %+v", rep)
	}
	if strings.Contains(string(rep.Masked), secret) {
		t.Fatalf("masked result still contains the secret: %s", rep.Masked)
	}
	if !strings.Contains(string(rep.Masked), "[REDACTED_SECRET]") {
		t.Fatalf("masked result must carry the redaction token: %s", rep.Masked)
	}
	// Unmatched parts of the result survive masking.
	if !strings.Contains(string(rep.Masked), `"type":"text"`) {
		t.Fatalf("mask must only replace the matched spans: %s", rep.Masked)
	}

	deny := compile(t, `{"result":{"mode":"deny","secrets":true}}`)
	rep = deny.CheckResult(result)
	if rep.Action != ResultDeny || rep.Masked != nil {
		t.Fatalf("deny must drop the result: %+v", rep)
	}
}

func TestCheckResult_CustomRegex(t *testing.T) {
	const token = "SUPER-SECRET-TOKEN-42"
	r := compile(t, `{"result":{"mode":"mask","deny_regex":["SUPER-SECRET-TOKEN-[0-9]+"]}}`)
	rep := r.CheckResult([]byte(`{"out":"value SUPER-SECRET-TOKEN-42 end"}`))
	if rep.Action != ResultMask {
		t.Fatalf("mask action: %+v", rep)
	}
	if strings.Contains(string(rep.Masked), token) {
		t.Fatal("masked result must not contain the matched value")
	}
	if !strings.Contains(string(rep.Masked), resultRedactedToken) {
		t.Fatalf("custom regex mask token missing: %s", rep.Masked)
	}
	if !strings.Contains(string(rep.Masked), "value") || !strings.Contains(string(rep.Masked), "end") {
		t.Fatalf("mask must preserve the rest: %s", rep.Masked)
	}
}

func TestCheckResult_NoResultRules(t *testing.T) {
	r := compile(t, `{"args":{"max_bytes":5}}`)
	if rep := r.CheckResult([]byte(`{"anything":"sk-abcdef1234567890abcdef"}`)); rep.Action != "" {
		t.Fatalf("args-only rules must not post-check results: %+v", rep)
	}
}

func TestResultAction_Rank(t *testing.T) {
	if ResultDeny.Rank() <= ResultMask.Rank() ||
		ResultMask.Rank() <= ResultFlag.Rank() ||
		ResultFlag.Rank() <= ResultAction("").Rank() {
		t.Fatal("rank order must be deny > mask > flag > none")
	}
}
