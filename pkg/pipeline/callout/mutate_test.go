package callout

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// respondContent echoes a mutate response: {"content": raw}.
func respondContent(raw string) func(int, *http.Request) (int, string, string) {
	return func(int, *http.Request) (int, string, string) {
		return http.StatusOK, "application/json", `{"content": ` + raw + `}`
	}
}

// TestMutate_Messages pins the messages mutate contract: request = one array
// element per message, response replaces per message, Result.Mutated set.
func TestMutate_Messages(t *testing.T) {
	rec := &recorder{respond: respondContent(`["FIRST","second"]`)}
	srv := rec.server(t)
	rt := newTestRuntimeAt(t)
	comp := compileWith(t, rt, policyYAML("enforce", stepYAML(testStepID, srv.URL, "mode: mutate")))

	in := msgPayload("first", "second")
	res := runOne(t, comp, in)

	if res.Verdict != pipeline.ActionAllow || res.Mutated == nil {
		t.Fatalf("verdict=%s mutated=%v", res.Verdict, res.Mutated)
	}
	env := decodeEnvelope(t, rec.body)
	var sent []string
	if err := json.Unmarshal(env.Content, &sent); err != nil || len(sent) != 2 || sent[0] != "first" {
		t.Fatalf("request content = %s (%v)", env.Content, err)
	}
	if env.Expose != "messages" {
		t.Fatalf("expose = %s", env.Expose)
	}
	if res.Mutated.Messages[0].Content != "FIRST" || res.Mutated.Messages[1].Content != "second" {
		t.Fatalf("mutated messages = %q %q", res.Mutated.Messages[0].Content, res.Mutated.Messages[1].Content)
	}
	// The caller's payload is never touched — the engine works on a clone.
	if in.Messages[0].Content != "first" {
		t.Fatalf("caller payload mutated: %q", in.Messages[0].Content)
	}
}

// TestMutate_BoundaryMessages: the mutator cannot add or drop messages —
// a length-mismatched response is a contract error and the payload stays
// untouched.
func TestMutate_BoundaryMessages(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"dropped", `["only"]`},
		{"added", `["a","b","c"]`},
		{"not-an-array", `"whole"`},
		{"non-string-element", `[{},{}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{respond: respondContent(tc.content)}
			srv := rec.server(t)
			rt := newTestRuntimeAt(t)
			comp := compileWith(t, rt, policyYAML("enforce", stepYAML(testStepID, srv.URL, "mode: mutate")))
			in := msgPayload("a", "b")
			res := runOne(t, comp, in)
			if res.Verdict != pipeline.ActionDeny || res.Mutated != nil {
				t.Fatalf("verdict=%s mutated=%v, want fail_closed deny without mutation", res.Verdict, res.Mutated)
			}
			if !strings.Contains(res.Trace[0].Error, "boundary") && !strings.Contains(res.Trace[0].Error, "contract") {
				t.Fatalf("error = %q, want boundary/contract classification", res.Trace[0].Error)
			}
		})
	}
}

// TestMutate_Body pins the body projection: the response string replaces
// Body wholesale.
func TestMutate_Body(t *testing.T) {
	rec := &recorder{respond: respondContent(`"{\"redacted\":true}"`)}
	srv := rec.server(t)
	rt := newTestRuntimeAt(t)
	policy := fmt.Sprintf(`apiVersion: ypp/v1
kind: Policy
name: callout-test
mode: enforce
hooks: [pre_upstream]
steps:
%s
    params:
      mode: mutate
      expose: body
`, fmt.Sprintf("  - id: %s\n    callout: %q", testStepID, srv.URL))
	comp := compileWith(t, rt, []byte(policy))

	res := runOne(t, comp, bodyPayload(`{"pan":"4111"}`))
	if res.Mutated == nil || string(res.Mutated.Body) != `{"redacted":true}` {
		t.Fatalf("mutated body = %s", res.Mutated.Body)
	}
	env := decodeEnvelope(t, rec.body)
	if env.Expose != "body" {
		t.Fatalf("expose = %s", env.Expose)
	}
	var sent string
	_ = json.Unmarshal(env.Content, &sent)
	if sent != `{"pan":"4111"}` {
		t.Fatalf("sent = %q", sent)
	}
}

// TestMutate_Fields pins the fields boundary: the response may only rewrite
// exactly the projected key set — no invented fields, no silent drops — and
// unprojected fields survive the merge.
func TestMutate_Fields(t *testing.T) {
	const body = `{"comment":"user text","score":3,"org_note":"keep"}`

	t.Run("applies-and-keeps-others", func(t *testing.T) {
		rec := &recorder{respond: respondContent(`{"comment":"REDACTED","score":3}`)}
		srv := rec.server(t)
		rt := newTestRuntimeAt(t)
		comp := compileWith(t, rt, policyYAML("enforce",
			fmt.Sprintf("  - id: %s\n    callout: %q\n    params:\n      mode: mutate\n      expose: \"fields:comment,score\"", testStepID, srv.URL)))
		res := runOne(t, comp, bodyPayload(body))
		if res.Mutated == nil {
			t.Fatal("expected mutation")
		}
		var got map[string]any
		if err := json.Unmarshal(res.Mutated.Body, &got); err != nil {
			t.Fatalf("mutated body: %v", err)
		}
		if got["comment"] != "REDACTED" || got["org_note"] != "keep" {
			t.Fatalf("mutated body = %s", res.Mutated.Body)
		}
		// Number literals survive the round trip (UseNumber).
		if !strings.Contains(string(res.Mutated.Body), "3") {
			t.Fatalf("number literal lost: %s", res.Mutated.Body)
		}
	})

	t.Run("field-expansion-refused", func(t *testing.T) {
		rec := &recorder{respond: respondContent(`{"comment":"x","extra":"injected"}`)}
		srv := rec.server(t)
		rt := newTestRuntimeAt(t)
		comp := compileWith(t, rt, policyYAML("enforce",
			fmt.Sprintf("  - id: %s\n    callout: %q\n    params:\n      mode: mutate\n      expose: \"fields:comment\"", testStepID, srv.URL)))
		in := bodyPayload(body)
		res := runOne(t, comp, in)
		if res.Verdict != pipeline.ActionDeny || res.Mutated != nil {
			t.Fatalf("verdict=%s mutated=%v", res.Verdict, res.Mutated)
		}
		if !strings.Contains(res.Trace[0].Error, "expand") {
			t.Fatalf("error = %q", res.Trace[0].Error)
		}
	})

	t.Run("field-drop-refused", func(t *testing.T) {
		rec := &recorder{respond: respondContent(`{}`)}
		srv := rec.server(t)
		rt := newTestRuntimeAt(t)
		comp := compileWith(t, rt, policyYAML("enforce",
			fmt.Sprintf("  - id: %s\n    callout: %q\n    params:\n      mode: mutate\n      expose: \"fields:comment\"", testStepID, srv.URL)))
		res := runOne(t, comp, bodyPayload(body))
		if res.Verdict != pipeline.ActionDeny || !strings.Contains(res.Trace[0].Error, "dropped") {
			t.Fatalf("verdict=%s err=%q", res.Verdict, res.Trace[0].Error)
		}
	})

	t.Run("identical-echo-is-not-a-mutation", func(t *testing.T) {
		rec := &recorder{respond: respondContent(`{"comment":"user text"}`)}
		srv := rec.server(t)
		rt := newTestRuntimeAt(t)
		comp := compileWith(t, rt, policyYAML("enforce",
			fmt.Sprintf("  - id: %s\n    callout: %q\n    params:\n      mode: mutate\n      expose: \"fields:comment\"", testStepID, srv.URL)))
		res := runOne(t, comp, bodyPayload(body))
		if res.Mutated != nil {
			t.Fatalf("echo marked as mutation: %s", res.Mutated.Body)
		}
	})

	t.Run("non-object-body-is-step-error", func(t *testing.T) {
		rec := &recorder{respond: respondContent(`{"comment":"x"}`)}
		srv := rec.server(t)
		rt := newTestRuntimeAt(t)
		comp := compileWith(t, rt, policyYAML("enforce",
			fmt.Sprintf("  - id: %s\n    callout: %q\n    params:\n      mode: mutate\n      expose: \"fields:comment\"", testStepID, srv.URL)))
		res := runOne(t, comp, bodyPayload(`[1,2,3]`))
		if res.Verdict != pipeline.ActionDeny || !strings.Contains(res.Trace[0].Error, "JSON object") {
			t.Fatalf("verdict=%s err=%q", res.Verdict, res.Trace[0].Error)
		}
	})
}

// TestMutate_MissingContentKey: a mutate response without "content" is a
// contract error.
func TestMutate_MissingContentKey(t *testing.T) {
	rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
		return http.StatusOK, "application/json", `{"text": "nope"}`
	}}
	srv := rec.server(t)
	rt := newTestRuntimeAt(t)
	comp := compileWith(t, rt, policyYAML("enforce", stepYAML(testStepID, srv.URL, "mode: mutate")))
	res := runOne(t, comp, msgPayload("a"))
	if res.Verdict != pipeline.ActionDeny || !strings.Contains(res.Trace[0].Error, "content is required") {
		t.Fatalf("verdict=%s err=%q", res.Verdict, res.Trace[0].Error)
	}
}

// TestMutate_IdenticalEchoNoMutation: an echo response must not produce
// Result.Mutated (payload byte-equality preserved for messages/body).
func TestMutate_IdenticalEchoNoMutation(t *testing.T) {
	rec := &recorder{respond: respondContent(`["a","b"]`)}
	srv := rec.server(t)
	rt := newTestRuntimeAt(t)
	comp := compileWith(t, rt, policyYAML("enforce", stepYAML(testStepID, srv.URL, "mode: mutate")))
	res := runOne(t, comp, msgPayload("a", "b"))
	if res.Mutated != nil {
		t.Fatalf("echo produced mutation: %+v", res.Mutated)
	}
}

// TestMutate_ShadowMode: a shadow-mode mutate policy runs on a throwaway
// clone — the carried payload is never changed and the verdict never raises.
func TestMutate_ShadowMode(t *testing.T) {
	rec := &recorder{respond: respondContent(`["CHANGED"]`)}
	srv := rec.server(t)
	rt := newTestRuntimeAt(t)
	comp := compileWith(t, rt, policyYAML("shadow", stepYAML(testStepID, srv.URL, "mode: mutate")))
	res := runOne(t, comp, msgPayload("original"))
	if res.Mutated != nil {
		t.Fatalf("shadow mutated the payload: %+v", res.Mutated)
	}
	if res.Verdict != pipeline.ActionAllow {
		t.Fatalf("shadow verdict = %s", res.Verdict)
	}
	if res.Trace[0].Outcome != pipeline.StepRan {
		t.Fatalf("shadow trace = %+v", res.Trace[0])
	}
}

// TestMutate_ProjectionError: fields projection over a non-JSON body is a
// projection error (fail_closed), before any request leaves.
func TestMutate_ProjectionError(t *testing.T) {
	called := false
	rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
		called = true
		return http.StatusOK, "application/json", `{"content": {}}`
	}}
	srv := rec.server(t)
	rt := newTestRuntimeAt(t)
	comp := compileWith(t, rt, policyYAML("enforce",
		fmt.Sprintf("  - id: %s\n    callout: %q\n    params:\n      mode: mutate\n      expose: \"fields:a\"", testStepID, srv.URL)))
	res := runOne(t, comp, bodyPayload(`not json`))
	if res.Verdict != pipeline.ActionDeny {
		t.Fatalf("verdict = %s", res.Verdict)
	}
	if called {
		t.Fatal("upstream called despite projection error")
	}
}
