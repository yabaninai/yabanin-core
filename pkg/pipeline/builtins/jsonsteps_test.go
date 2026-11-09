package builtins

import (
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

var testSchema = map[string]any{
	"type":     "object",
	"required": []any{"answer"},
	"properties": map[string]any{
		"answer": map[string]any{"type": "string"},
	},
}

func TestJSONSchema_Positive(t *testing.T) {
	res := runOne(t, NameJSONSchema, map[string]any{"schema": testSchema}, respPayload(`{"answer":"ok","extra":1}`))
	assertRan(t, res)
	if fs := findingsOf(res, "s1"); len(fs) != 0 {
		t.Errorf("findings = %v, want none (valid output)", fs)
	}
}

func TestJSONSchema_Violations(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string // evidence prefix
	}{
		{"schema mismatch", `{"answer":42}`, "validation"},
		{"missing required", `{}`, "validation"},
		{"invalid json", `not json at all`, "invalid JSON"},
		{"multiple docs", `{"answer":"a"} {"answer":"b"}`, "invalid JSON"},
		{"json array", `[1,2,3]`, "validation"},
	}
	for _, tc := range cases {
		res := runOne(t, NameJSONSchema, map[string]any{"schema": testSchema, "action": "deny"}, respPayload(tc.text))
		assertRan(t, res)
		fs := findingsOf(res, "s1")
		if len(fs) != 1 {
			t.Errorf("%s: findings = %v, want 1", tc.name, fs)
			continue
		}
		f := fs[0]
		if f.Category != "json_schema" || f.Action != pipeline.ActionDeny {
			t.Errorf("%s: finding = %+v, want json_schema/deny", tc.name, f)
		}
		if !strings.Contains(strings.ToLower(f.Evidence), strings.ToLower(tc.want)) {
			t.Errorf("%s: evidence = %q, want to contain %q", tc.name, f.Evidence, tc.want)
		}
	}
	// Deny action composes the verdict.
	res := runOne(t, NameJSONSchema, map[string]any{"schema": testSchema, "action": "deny"}, respPayload(`{}`))
	if res.Verdict != pipeline.ActionDeny {
		t.Errorf("verdict = %q, want deny", res.Verdict)
	}
}

func TestJSONSchema_OutputOnlyByDefault(t *testing.T) {
	// Requests are skipped unless kinds opt in — the step is output-only.
	res := runOne(t, NameJSONSchema, map[string]any{"schema": testSchema}, reqPayload(`{"nope":1}`))
	assertRan(t, res)
	if fs := findingsOf(res, "s1"); len(fs) != 0 {
		t.Errorf("request findings = %v, want none (output-only default)", fs)
	}
	// Stream kinds are covered by the default.
	res = runOne(t, NameJSONSchema, map[string]any{"schema": testSchema}, &pipeline.Payload{
		Kind:        pipeline.KindStreamFinal,
		StreamChunk: `{"answer":"ok"}`,
	})
	assertRan(t, res)
	if fs := findingsOf(res, "s1"); len(fs) != 0 {
		t.Errorf("stream_final findings = %v, want none (valid)", fs)
	}
}

func TestJSONSchema_Edges(t *testing.T) {
	// Empty output: nothing to validate.
	res := runOne(t, NameJSONSchema, map[string]any{"schema": testSchema}, respPayload("   "))
	assertRan(t, res)
	if fs := findingsOf(res, "s1"); len(fs) != 0 {
		t.Errorf("empty output findings = %v, want none", fs)
	}
	// Invalid schema is a LOAD error.
	mustCompileErr(t, NameJSONSchema, map[string]any{"schema": map[string]any{"type": "nope"}})
	mustCompileErr(t, NameJSONSchema, map[string]any{})
}

func TestJSONKeys_Modes(t *testing.T) {
	cases := []struct {
		name     string
		params   map[string]any
		text     string
		wantFire bool
	}{
		{"all pass", map[string]any{"keys": []any{"a.b", "c"}}, `{"a":{"b":1},"c":2}`, false},
		{"all missing", map[string]any{"keys": []any{"a.b", "c"}}, `{"a":{}}`, true},
		{"all on array", map[string]any{"keys": []any{"a"}}, `[1,2]`, true},
		{"any present", map[string]any{"keys": []any{"x", "y"}, "mode": "any"}, `{"y":1}`, false},
		{"any absent", map[string]any{"keys": []any{"x", "y"}, "mode": "any"}, `{"z":1}`, true},
		{"none clean", map[string]any{"keys": []any{"debug"}, "mode": "none"}, `{"release":1}`, false},
		{"none fires", map[string]any{"keys": []any{"debug"}, "mode": "none"}, `{"debug":true}`, true},
		{"null counts present", map[string]any{"keys": []any{"x"}}, `{"x":null}`, false},
	}
	for _, tc := range cases {
		res := runOne(t, NameJSONKeys, tc.params, respPayload(tc.text))
		assertRan(t, res)
		fs := findingsOf(res, "s1")
		if tc.wantFire && len(fs) != 1 {
			t.Errorf("%s: findings = %v, want 1", tc.name, fs)
		}
		if !tc.wantFire && len(fs) != 0 {
			t.Errorf("%s: findings = %v, want none", tc.name, fs)
		}
		if tc.wantFire && len(fs) == 1 && fs[0].Category != "json_keys" {
			t.Errorf("%s: category = %q, want json_keys", tc.name, fs[0].Category)
		}
	}
}

func TestJSONKeys_NonObjectSemantics(t *testing.T) {
	// none-mode: a non-object cannot contain a forbidden key — passes.
	res := runOne(t, NameJSONKeys, map[string]any{"keys": []any{"a"}, "mode": "none"}, respPayload(`garbage`))
	assertRan(t, res)
	if fs := findingsOf(res, "s1"); len(fs) != 0 {
		t.Errorf("none-mode garbage findings = %v, want none", fs)
	}
	// all-mode: missing keys cannot be verified — violation.
	res = runOne(t, NameJSONKeys, map[string]any{"keys": []any{"a"}}, respPayload(`garbage`))
	assertRan(t, res)
	if fs := findingsOf(res, "s1"); len(fs) != 1 {
		t.Errorf("all-mode garbage findings = %v, want 1", fs)
	}
	// Config validation.
	mustCompileErr(t, NameJSONKeys, map[string]any{})
	mustCompileErr(t, NameJSONKeys, map[string]any{"keys": []any{"a"}, "mode": "some"})
}
