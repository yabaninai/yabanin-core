package cli

import (
	"encoding/json"
	"testing"

	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/resolver"
)

func newEffortTestGateway(t *testing.T, enabled bool, models string, effortModels []string) *gateway {
	t.Helper()
	return &gateway{
		cfg: config.Gateway{
			EffortRoutingEnabled: enabled,
			EffortModels:         models,
		},
		effortModels: effortModels,
	}
}

func TestInjectReasoningEffort_SetsField(t *testing.T) {
	in := []byte(`{"model":"gpt-5.2","messages":[]}`)
	out := injectReasoningEffort(in, "low")
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	if m["reasoning_effort"] != "low" {
		t.Fatalf("reasoning_effort = %v, want low", m["reasoning_effort"])
	}
	if m["model"] != "gpt-5.2" {
		t.Fatalf("model lost: %v", m["model"])
	}
}

func TestInjectReasoningEffort_OverwritesExisting(t *testing.T) {
	in := []byte(`{"model":"gpt-5.2","reasoning_effort":"high"}`)
	out := injectReasoningEffort(in, "low")
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	if m["reasoning_effort"] != "low" {
		t.Fatalf("reasoning_effort = %v, want low (overwritten)", m["reasoning_effort"])
	}
}

func TestInjectReasoningEffort_EmptyEffort_Unchanged(t *testing.T) {
	in := []byte(`{"model":"gpt-5.2"}`)
	out := injectReasoningEffort(in, "")
	if string(out) != string(in) {
		t.Fatalf("body changed with empty effort: %s", out)
	}
}

func TestInjectReasoningEffort_BrokenJSON_Unchanged(t *testing.T) {
	in := []byte(`{not json`)
	out := injectReasoningEffort(in, "low")
	if string(out) != string(in) {
		t.Fatalf("body changed with broken JSON: %s", out)
	}
}

// Non-object JSON passes through byte-for-byte, including null which decodes to a nil map.
func TestInjectReasoningEffort_NullAndNonObjectBodies_Unchanged(t *testing.T) {
	cases := []struct{ name, body string }{
		{"json_null", `null`},
		{"json_array", `[]`},
		{"json_string", `"a string"`},
		{"json_number", `42`},
		{"json_boolean", `true`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := injectReasoningEffort([]byte(tc.body), "high")
			if string(out) != tc.body {
				t.Fatalf("non-object body must stay byte-identical: in=%s out=%s", tc.body, out)
			}
		})
	}
}

func TestMaybeInjectEffort_EnabledMatchInjects(t *testing.T) {
	gw := newEffortTestGateway(t, true, "o3,o4-mini,gpt-5", []string{"o3", "o4-mini", "gpt-5"})
	body := []byte(`{"model":"gpt-5.2","messages":[]}`)
	out := gw.maybeInjectEffort(body, resolver.ModelInfo{Provider: "openai", ModelName: "gpt-5.2"}, classifier.ClassEasy)
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	if m["reasoning_effort"] != "low" {
		t.Fatalf("reasoning_effort = %v, want low for easy class", m["reasoning_effort"])
	}
}

func TestMaybeInjectEffort_AnthropicUnchanged(t *testing.T) {
	gw := newEffortTestGateway(t, true, "claude", []string{"claude"})
	body := []byte(`{"model":"claude-opus-4-6","messages":[]}`)
	out := gw.maybeInjectEffort(body, resolver.ModelInfo{Provider: "anthropic", ModelName: "claude-opus-4-6"}, classifier.ClassHard)
	if string(out) != string(body) {
		t.Fatalf("anthropic body must not be modified, got %s", out)
	}
}

func TestMaybeInjectEffort_ModelNotInListUnchanged(t *testing.T) {
	gw := newEffortTestGateway(t, true, "o3,gpt-5", []string{"o3", "gpt-5"})
	body := []byte(`{"model":"gpt-4o","messages":[]}`)
	out := gw.maybeInjectEffort(body, resolver.ModelInfo{Provider: "openai", ModelName: "gpt-4o"}, classifier.ClassEasy)
	if string(out) != string(body) {
		t.Fatalf("body for non-listed model must be unchanged, got %s", out)
	}
}

func TestMaybeInjectEffort_DisabledUnchanged(t *testing.T) {
	gw := newEffortTestGateway(t, false, "o3,gpt-5", []string{"o3", "gpt-5"})
	body := []byte(`{"model":"gpt-5.2","messages":[]}`)
	out := gw.maybeInjectEffort(body, resolver.ModelInfo{Provider: "openai", ModelName: "gpt-5.2"}, classifier.ClassEasy)
	if string(out) != string(body) {
		t.Fatalf("body must be unchanged when disabled, got %s", out)
	}
}
