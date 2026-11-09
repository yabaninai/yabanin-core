package provider

// N07-P01-T07 — boundary corpus, facet 2 (tools / structured outputs) and
// the effort field, adapter level.
//
// Card action: «Построить boundary corpus для трёх аспектов; проверить
// наблюдаемые ошибки и прежнее поведение». This file pins the adapter-level
// boundaries on the translated routes: response_format value space,
// tool_choice value space, tool parameter JSON validity, and the
// reasoning_effort empty-string boundary. Prior behavior is pinned exactly
// as it stands; the two silent-drop boundaries (unknown tool_choice values
// silently becoming "no choice", malformed tool_choice objects silently
// dropped) are RED first — the same modeled-field loss the packet's
// negative criterion forbids — and are fixed to typed rejections following
// the vertex adapter's precedent and the T05 (I51) house pattern.
//
// The wire-level half of the corpus (extension shapes, SSE boundaries, the
// same rejections end-to-end) lives in pkg/gateway/n07p1t07_boundary_corpus_test.go;
// the pinned-SDK decode boundary lives in sdks/go/compat_joint_boundary_test.go.

import (
	"encoding/json"
	"strings"
	"testing"
)

// n07t07Anthropic parses chatToAnthropicRequest output for assertions.
func n07t07Anthropic(t *testing.T, body string) map[string]any {
	t.Helper()
	out, err := chatToAnthropicRequest([]byte(body))
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("marshal output: %v\n%s", err, string(out))
	}
	return m
}

// TestN07P1T07_ResponseFormatBoundaries pins the response_format value
// space on the anthropic route: the no-guarantee shapes pass, every
// guarantee-bearing or malformed shape rejects with the exact reason (I51).
func TestN07P1T07_ResponseFormatBoundaries(t *testing.T) {
	const base = `{"model":"m","messages":[{"role":"user","content":"hi"}]}`

	passing := []string{
		"absent",
		`{"response_format":null}`,
		`{"response_format":{"type":"text"}}`,
		`{"response_format":{"type":""}}`,
	}
	for _, extra := range passing {
		body := base
		if extra != "absent" {
			body = base[:len(base)-1] + "," + strings.TrimPrefix(extra, "{")
		}
		if _, err := chatToAnthropicRequest([]byte(body)); err != nil {
			t.Errorf("no-guarantee shape %s must pass, got: %v", extra, err)
		}
	}

	rejecting := []struct {
		extra string
		want  string
	}{
		{`"response_format":{"type":"json_object"}`, `response_format "json_object" has no equivalent`},
		{`"response_format":{"type":"json_schema","json_schema":{"name":"o"}}`, `response_format "json_schema" has no equivalent`},
		{`"response_format":{"type":"banana"}`, `unsupported response_format type "banana"`},
		{`"response_format":[]`, `decode response_format`},
		{`"response_format":"text"`, `decode response_format`},
		{`"response_format":123`, `decode response_format`},
	}
	for _, tc := range rejecting {
		body := base[:len(base)-1] + "," + tc.extra + "}"
		_, err := chatToAnthropicRequest([]byte(body))
		if err == nil {
			t.Errorf("shape %s must reject loudly, got success", tc.extra)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("shape %s: error %q must name %q", tc.extra, err.Error(), tc.want)
		}
	}
}

// TestN07P1T07_AnthropicToolChoiceBoundaries pins the tool_choice value
// space on the anthropic route. Mapped values translate to the native
// shapes; unknown strings and malformed objects are RED here (they silently
// become "no choice") and must reject with the exact reason.
func TestN07P1T07_AnthropicToolChoiceBoundaries(t *testing.T) {
	const tools = `"tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object"}}}],`

	// Prior behavior: mapped strings translate to the native shapes.
	mapped := []struct {
		choice string
		want   map[string]any
	}{
		{`"auto"`, map[string]any{"type": "auto"}},
		{`"required"`, map[string]any{"type": "any"}},
		{`"none"`, map[string]any{"type": "none"}},
		{`{"type":"function","function":{"name":"get_weather"}}`, map[string]any{"type": "tool", "name": "get_weather"}},
	}
	for _, tc := range mapped {
		body := `{"model":"m","messages":[{"role":"user","content":"hi"}],` + tools + `"tool_choice":` + tc.choice + `}`
		m := n07t07Anthropic(t, body)
		got, _ := m["tool_choice"].(map[string]any)
		if len(got) != len(tc.want) {
			t.Errorf("mapped choice %s: tool_choice = %v, want %v", tc.choice, m["tool_choice"], tc.want)
			continue
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Errorf("mapped choice %s: tool_choice[%q] = %v, want %v", tc.choice, k, got[k], v)
			}
		}
	}

	// parallel_tool_calls=false adds the disable flag on every mapped shape.
	for _, choice := range []string{`"auto"`, `"required"`, `"none"`, `{"type":"function","function":{"name":"get_weather"}}`} {
		body := `{"model":"m","messages":[{"role":"user","content":"hi"}],` + tools + `"tool_choice":` + choice + `,"parallel_tool_calls":false}`
		m := n07t07Anthropic(t, body)
		got, _ := m["tool_choice"].(map[string]any)
		if got["disable_parallel_tool_use"] != true {
			t.Errorf("choice %s with parallel=false: tool_choice = %v, want disable_parallel_tool_use:true", choice, m["tool_choice"])
		}
	}

	// The defect boundary: unmapped/malformed values must reject loudly, not
	// silently become "no choice" (I51; vertex adapter precedent).
	rejecting := []struct {
		choice string
		want   string
	}{
		{`"banana"`, `unsupported tool_choice "banana"`},
		{`{"type":"function"}`, `tool_choice must be "auto"|"none"|"required" or {"type":"function","function":{"name":…}}`},
		{`{"type":"function","function":{}}`, `tool_choice must be "auto"|"none"|"required" or {"type":"function","function":{"name":…}}`},
		{`42`, `tool_choice must be "auto"|"none"|"required" or {"type":"function","function":{"name":…}}`},
		{`"missing_function"`, `unsupported tool_choice "missing_function"`},
	}
	for _, tc := range rejecting {
		body := `{"model":"m","messages":[{"role":"user","content":"hi"}],` + tools + `"tool_choice":` + tc.choice + `}`
		_, err := chatToAnthropicRequest([]byte(body))
		if err == nil {
			t.Errorf("tool_choice %s must reject loudly (was silently dropped), got success", tc.choice)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("tool_choice %s: error %q must contain %q", tc.choice, err.Error(), tc.want)
		}
	}

	// Unknown choice with parallel_tool_calls=false must still reject (the
	// old behavior silently reshaped it into auto+disable-parallel).
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}],` + tools + `"tool_choice":"banana","parallel_tool_calls":false}`
	if _, err := chatToAnthropicRequest([]byte(body)); err == nil {
		t.Errorf("unknown tool_choice with parallel_tool_calls=false must reject, got success")
	}

	// A syntactically broken body rejects at decode — the loud body-level
	// boundary, not a tool_choice-specific one.
	if _, err := chatToAnthropicRequest([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],` + tools + `"tool_choice":{"broken`)); err == nil {
		t.Errorf("broken body must reject at decode")
	}
}

// TestN07P1T07_AnthropicToolParametersBoundary pins the tool parameter JSON
// boundary: empty/null parameters get the default empty object schema, and
// a syntactically broken parameters value rejects at the body-decode
// boundary — the request JSON itself is unparseable, so the loud decode
// error (400) is the observable outcome, not a tool-specific one.
func TestN07P1T07_AnthropicToolParametersBoundary(t *testing.T) {
	// Empty and null parameters become the default empty object schema.
	for _, body := range []string{
		`{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f"}}]}`,
		`{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":null}}]}`,
	} {
		m := n07t07Anthropic(t, body)
		tools, _ := m["tools"].([]any)
		if len(tools) != 1 {
			t.Fatalf("body %s: tools = %v", body, m["tools"])
		}
		tool := tools[0].(map[string]any)
		schema, _ := tool["input_schema"].(map[string]any)
		if schema["type"] != "object" || schema["properties"] == nil {
			t.Errorf("body %s: input_schema = %v, want the default empty object schema", body, tool["input_schema"])
		}
	}

	// A valid non-object schema rides verbatim (Anthropic owns its shape).
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":[]}}]}`
	out, err := chatToAnthropicRequest([]byte(body))
	if err != nil {
		t.Fatalf("valid non-object schema must pass: %v", err)
	}
	if !strings.Contains(string(out), `"input_schema":[]`) {
		t.Errorf("non-object schema must ride verbatim:\n%s", string(out))
	}

	// A broken parameters value breaks the request JSON itself — the body
	// decode is the loud observable boundary.
	if _, err := chatToAnthropicRequest([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":{bad}}]}`)); err == nil {
		t.Errorf("broken parameters must reject at decode")
	}
}

// TestN07P1T07_EffortEmptyStringBoundary pins the effort empty-string
// boundary: an empty reasoning_effort is indistinguishable from an absent
// field (omitempty) and passes; any non-empty value rejects on the
// translated route (T05).
func TestN07P1T07_EffortEmptyStringBoundary(t *testing.T) {
	for _, effort := range []string{"", "high", "banana"} {
		body := `{"model":"m","messages":[{"role":"user","content":"hi"}],"reasoning_effort":"` + effort + `"}`
		_, err := chatToAnthropicRequest([]byte(body))
		if effort == "" {
			if err != nil {
				t.Errorf("empty effort must pass as absent, got: %v", err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), `reasoning_effort "`+effort+`" is not mapped`) {
			t.Errorf("effort %q must reject with the exact reason, got: %v", effort, err)
		}
	}
}
