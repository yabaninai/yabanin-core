package adminstore

// RenderTemplate grammar, recursive expansion, fail-closed error paths and
// the boundary validators. The DB-backed store behavior lives in
// promptstudio_int_test.go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestRenderTemplate_Vars(t *testing.T) {
	got, err := RenderTemplate(context.Background(),
		"Hello {{name}}, role {{ role }}!", map[string]string{"name": "Ada", "role": "admin"}, nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if want := "Hello Ada, role admin!"; got != want {
		t.Errorf("render = %q, want %q", got, want)
	}
}

func TestRenderTemplate_Partials(t *testing.T) {
	src := mapSource(map[string]string{"rules": "RULE-1\nRULE-2"})
	got, err := RenderTemplate(context.Background(),
		"{{partials.rules}}\nInput: {{input}}", map[string]string{"input": "x"}, src)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if want := "RULE-1\nRULE-2\nInput: x"; got != want {
		t.Errorf("render = %q, want %q", got, want)
	}
}

func TestRenderTemplate_MissingVarNamesTheVariable(t *testing.T) {
	_, err := RenderTemplate(context.Background(), "Hi {{who}}", map[string]string{}, nil)
	if err == nil || !strings.Contains(err.Error(), `"who"`) {
		t.Errorf("missing var err = %v, want an error naming %q", err, "who")
	}
}

func TestRenderTemplate_MissingPartialIsError(t *testing.T) {
	_, err := RenderTemplate(context.Background(), "{{partials.nope}}", nil, mapSource(nil))
	if err == nil || !strings.Contains(err.Error(), `"nope"`) || !strings.Contains(err.Error(), "not found") {
		t.Errorf("missing partial err = %v, want a not-found error naming the partial", err)
	}
	_, err = RenderTemplate(context.Background(), "{{partials.nope}}", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no partials source") {
		t.Errorf("nil source err = %v, want the no-source error", err)
	}
}

func TestRenderTemplate_RecursiveCycleDetection(t *testing.T) {
	src := mapSource(map[string]string{
		"self": "{{partials.self}}",
		"a":    "{{partials.b}}",
		"b":    "{{partials.a}}",
		"wrap": "[{{var}}]",
	})
	for _, token := range []string{"self", "a"} {
		_, err := RenderTemplate(context.Background(), "{{partials."+token+"}}", nil, src)
		if err == nil || !strings.Contains(err.Error(), "partial cycle") {
			t.Errorf("cycle %q err=%v", token, err)
		}
	}
	got, err := RenderTemplate(context.Background(), "A{{partials.wrap}}C", map[string]string{"var": "V"}, src)
	if err != nil || got != "A[V]C" {
		t.Errorf("nested variable render=%q err=%v", got, err)
	}
	deep := mapSource(map[string]string{"a": "{{partials.b}}", "b": "{{partials.c}}", "c": "done"})
	got, err = RenderTemplate(context.Background(), "{{partials.a}}", nil, deep)
	if err != nil || got != "done" {
		t.Errorf("deep render=%q err=%v", got, err)
	}
	tooDeep := mapSource(map[string]string{})
	for i := 0; i <= maxPartialExpansionDepth; i++ {
		tooDeep[fmt.Sprintf("p%d", i)] = fmt.Sprintf("{{partials.p%d}}", i+1)
	}
	tooDeep[fmt.Sprintf("p%d", maxPartialExpansionDepth+1)] = "done"
	_, err = RenderTemplate(context.Background(), "{{partials.p0}}", nil, tooDeep)
	if err == nil || !strings.Contains(err.Error(), "depth exceeds") {
		t.Errorf("deep expansion err=%v, want depth limit", err)
	}
}

func TestRenderTemplate_VarValueNotRescanned(t *testing.T) {
	got, err := RenderTemplate(context.Background(),
		"{{payload}}", map[string]string{"payload": "{{escaped}}"}, nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if want := "{{escaped}}"; got != want {
		t.Errorf("render = %q, want %q (values are never rescanned)", got, want)
	}
}

func TestRenderTemplate_MalformedTokensStayVerbatim(t *testing.T) {
	in := "keep {{partials.}} and {{a b}} and {{}} literal"
	got, err := RenderTemplate(context.Background(), in, nil, nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if got != in {
		t.Errorf("render = %q, want %q (tokens that match no grammar stay verbatim)", got, in)
	}
}

func TestRenderTemplate_NoTokensIsIdentity(t *testing.T) {
	got, err := RenderTemplate(context.Background(), "plain text {{", nil, nil)
	if err != nil || got != "plain text {{" {
		t.Errorf("render = %q, %v, want identity", got, err)
	}
}

func TestRenderTemplate_CtxCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := RenderTemplate(ctx, "{{partials.x}}{{partials.y}}", nil, mapSource(map[string]string{"x": "1", "y": "2"}))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestRenderTemplate_LookupErrorSurfaces(t *testing.T) {
	_, err := RenderTemplate(context.Background(), "{{partials.boom}}", nil, errSource{err: errors.New("db down")})
	if err == nil || !strings.Contains(err.Error(), "db down") {
		t.Errorf("err = %v, want the lookup error surfaced", err)
	}
}

func TestValidatePromptName(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"toxicity-ru", true},
		{"support_triage.v2", true},
		{"", false},
		{"has space", false},
		{"has@at", false},
		{"{{inject}}", false},
		{strings.Repeat("a", 257), false},
	}
	for _, c := range cases {
		err := validatePromptName(c.name)
		if (err == nil) != c.ok {
			t.Errorf("validatePromptName(%q) = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestValidatePromptParamsStored(t *testing.T) {
	if err := validatePromptParamsStored(nil); err != nil {
		t.Errorf("nil params = %v, want ok (stored as {})", err)
	}
	if err := validatePromptParamsStored(json.RawMessage(`{"model":"gpt-4o"}`)); err != nil {
		t.Errorf("object params = %v, want ok", err)
	}
	if err := validatePromptParamsStored(json.RawMessage(`[1,2]`)); err == nil {
		t.Error("array params accepted, want an object error")
	}
	if err := validatePromptParamsStored(json.RawMessage(`null`)); err == nil {
		t.Error("null params accepted, want an object error")
	}
	if err := validatePromptParamsStored(json.RawMessage(`{"a":` + strings.Repeat("1", maxPromptParamsBytes) + `}`)); err == nil {
		t.Error("oversized params accepted, want a size error")
	}
}

func TestValidatePartialBodyStored(t *testing.T) {
	if err := validatePartialBodyStored("body"); err != nil {
		t.Errorf("body = %v, want ok", err)
	}
	if err := validatePartialBodyStored(""); err == nil {
		t.Error("empty body accepted, want an error")
	}
	if err := validatePartialBodyStored(strings.Repeat("a", maxPartialBodyBytes+1)); err == nil {
		t.Error("oversized body accepted, want a size error")
	}
}

func TestValidatePromptLabel(t *testing.T) {
	for _, l := range []string{PromptLabelDraft, PromptLabelActive, PromptLabelCanary, PromptLabelCustom} {
		if err := validatePromptLabel(l); err != nil {
			t.Errorf("validatePromptLabel(%q) = %v, want ok", l, err)
		}
	}
	if err := validatePromptLabel("latest"); err == nil {
		t.Error("unknown label accepted, want an error")
	}
}

// mapSource is an in-memory PartialsSource over a map.
type mapSource map[string]string

func (m mapSource) Get(_ context.Context, name string) (string, bool, error) {
	b, ok := m[name]
	return b, ok, nil
}

// errSource is a PartialsSource that always fails.
type errSource struct{ err error }

func (e errSource) Get(_ context.Context, _ string) (string, bool, error) {
	return "", false, e.err
}
