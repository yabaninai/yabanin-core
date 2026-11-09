package builtins

import (
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

func TestModelWhitelist(t *testing.T) {
	params := map[string]any{"models": []any{"gpt-4*", "claude-?"}}
	cases := []struct {
		model    string
		metaNil  bool
		wantFire bool
	}{
		{"gpt-4o", false, false},
		{"gpt-4", false, false},
		{"claude-3", false, false},
		{"claude-33", false, true}, // '?' matches exactly one char
		{"o1-mini", false, true},
		{"gpt4", false, true}, // no wildcard separator
		{"", false, true},     // empty model is fail-closed
		{"", true, true},      // nil Meta is fail-closed
	}
	for _, tc := range cases {
		in := reqPayload("irrelevant")
		if tc.metaNil {
			in.Meta = nil
		} else {
			in.Meta.Model = tc.model
		}
		res := runOne(t, NameModelWhitelist, params, in)
		assertRan(t, res)
		fs := findingsOf(res, "s1")
		if tc.wantFire && len(fs) != 1 {
			t.Errorf("model %q (metaNil=%v): findings = %v, want 1", tc.model, tc.metaNil, fs)
		}
		if !tc.wantFire && len(fs) != 0 {
			t.Errorf("model %q: findings = %v, want none", tc.model, fs)
		}
		if tc.wantFire && len(fs) == 1 && fs[0].Category != "model" {
			t.Errorf("category = %q, want model", fs[0].Category)
		}
	}
	// Action deny composes the verdict.
	in := reqPayload("irrelevant")
	in.Meta.Model = "o1"
	res := runOne(t, NameModelWhitelist, map[string]any{"models": []any{"gpt-4*"}, "action": "deny"}, in)
	if res.Verdict != pipeline.ActionDeny {
		t.Errorf("verdict = %q, want deny", res.Verdict)
	}
	mustCompileErr(t, NameModelWhitelist, map[string]any{})
}

func TestMetadataRequired(t *testing.T) {
	newMeta := func(model, team, env string) *pipeline.RequestMeta {
		labels := map[string]string{}
		if team != "" {
			labels["team"] = team
		}
		if env != "" {
			labels["env"] = env
		}
		return &pipeline.RequestMeta{Org: "org-a", Key: "key-1", Model: model, Provider: "openai", Labels: labels}
	}
	t.Run("all present", func(t *testing.T) {
		params := map[string]any{"keys": []any{"org", "model", "team"}, "labels": map[string]any{"env": "prod"}}
		in := reqPayload("x")
		in.Meta = newMeta("gpt-4o", "core", "prod")
		res := runOne(t, NameMetadataRequired, params, in)
		assertRan(t, res)
		if fs := findingsOf(res, "s1"); len(fs) != 0 {
			t.Errorf("findings = %v, want none", fs)
		}
	})
	t.Run("violations", func(t *testing.T) {
		params := map[string]any{"keys": []any{"org", "team", "owner"}, "labels": map[string]any{"env": "prod"}}
		in := reqPayload("x")
		in.Meta = newMeta("gpt-4o", "", "dev")
		res := runOne(t, NameMetadataRequired, params, in)
		assertRan(t, res)
		fs := findingsOf(res, "s1")
		if len(fs) != 3 {
			t.Fatalf("findings = %v, want 3 (missing team, missing owner, wrong env)", fs)
		}
		for _, f := range fs {
			if f.Category != "metadata" || f.Severity != sevMedium {
				t.Errorf("finding = %+v, want metadata/medium", f)
			}
		}
		joined := fs[0].Evidence + fs[1].Evidence + fs[2].Evidence
		for _, want := range []string{"team", "owner", "env"} {
			if !strings.Contains(joined, want) {
				t.Errorf("evidence %q misses %q", joined, want)
			}
		}
	})
	t.Run("nil meta is all missing", func(t *testing.T) {
		params := map[string]any{"keys": []any{"org", "team"}}
		in := reqPayload("x")
		in.Meta = nil
		res := runOne(t, NameMetadataRequired, params, in)
		assertRan(t, res)
		if fs := findingsOf(res, "s1"); len(fs) != 2 {
			t.Errorf("findings = %v, want 2 (fail-closed)", fs)
		}
	})
	t.Run("config validation", func(t *testing.T) {
		mustCompileErr(t, NameMetadataRequired, map[string]any{})
		mustCompileErr(t, NameMetadataRequired, map[string]any{"keys": []any{""}})
		mustCompileErr(t, NameMetadataRequired, map[string]any{"labels": []any{"not", "a", "map"}})
	})
}

func TestMetadataRequired_DeterministicOrder(t *testing.T) {
	// Map iteration must not leak into findings order (pipeline determinism
	// contract): identical runs produce identical findings.
	params := map[string]any{"keys": []any{"l1", "l2", "l3", "l4", "l5"}}
	in := reqPayload("x")
	in.Meta = &pipeline.RequestMeta{Org: "o"}
	run := func() []string {
		res := runOne(t, NameMetadataRequired, params, in)
		var got []string
		for _, f := range findingsOf(res, "s1") {
			got = append(got, f.Evidence)
		}
		return got
	}
	first := run()
	for i := 0; i < 20; i++ {
		next := run()
		if len(next) != len(first) {
			t.Fatalf("run %d: %d findings, want %d", i, len(next), len(first))
		}
		for j := range first {
			if next[j] != first[j] {
				t.Fatalf("run %d: evidence[%d] = %q, want %q (order must be stable)", i, j, next[j], first[j])
			}
		}
	}
}
