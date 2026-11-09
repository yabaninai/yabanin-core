package callout

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// TestDetect_FindingsContract pins the detector response contract end to
// end: findings mode, 200 + application/json, per-finding mapping (step id,
// category, severity, action, span, evidence) and verdict contribution.
func TestDetect_FindingsContract(t *testing.T) {
	rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
		return http.StatusOK, "application/json", findingsResponse(
			map[string]any{"category": "pan", "severity": "high", "action": "deny", "span": "10:16", "evidence": "4111"},
			map[string]any{"category": "injection", "action": "flag", "span": "0:5", "evidence": "ignore previous"},
		)
	}}
	srv := rec.server(t)
	rt := newTestRuntimeAt(t)
	comp := compileWith(t, rt, policyYAML("enforce",
		stepYAML(testStepID, srv.URL, "expose: messages")))

	res := runOne(t, comp, msgPayload("hello world"))

	if res.Verdict != pipeline.ActionDeny {
		t.Fatalf("verdict = %q, want deny", res.Verdict)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 (%+v)", len(res.Findings), res.Findings)
	}
	f := res.Findings
	if f[0].Step != testStepID || f[0].Category != "pan" || f[0].Severity != "high" ||
		f[0].Action != pipeline.ActionDeny || f[0].Span != "10:16" || f[0].Evidence != "4111" {
		t.Fatalf("finding[0] = %+v", f[0])
	}
	// Finding without severity → documented default medium; trace ran.
	if f[1].Severity != "medium" || f[1].Action != pipeline.ActionFlag {
		t.Fatalf("finding[1] = %+v, want severity medium + flag", f[1])
	}
	if len(res.Trace) != 1 || res.Trace[0].Outcome != pipeline.StepRan {
		t.Fatalf("trace = %+v, want single ran step", res.Trace)
	}
}

// TestDetect_BooleanMode pins the boolean contract: JSON true → one
// synthetic finding from the finding_* params; false → nothing.
func TestDetect_BooleanMode(t *testing.T) {
	newComp := func(t *testing.T, srvURL string) pipeline.Compiled {
		t.Helper()
		rt := newTestRuntimeAt(t)
		return compileWith(t, rt, policyYAML("enforce", stepYAML(testStepID, srvURL,
			"response: boolean\n      finding_category: toxicity\n      finding_severity: high\n      finding_action: deny")))
	}

	t.Run("true", func(t *testing.T) {
		rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
			return http.StatusOK, "application/json", "true"
		}}
		comp := newComp(t, rec.server(t).URL)
		res := runOne(t, comp, msgPayload("toxic"))
		if res.Verdict != pipeline.ActionDeny || len(res.Findings) != 1 {
			t.Fatalf("verdict=%s findings=%+v, want deny+1", res.Verdict, res.Findings)
		}
		got := res.Findings[0]
		if got.Category != "toxicity" || got.Severity != "high" || got.Action != pipeline.ActionDeny {
			t.Fatalf("finding = %+v", got)
		}
	})

	t.Run("false", func(t *testing.T) {
		rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
			return http.StatusOK, "application/json", "false"
		}}
		comp := newComp(t, rec.server(t).URL)
		res := runOne(t, comp, msgPayload("clean"))
		if res.Verdict != pipeline.ActionAllow || len(res.Findings) != 0 {
			t.Fatalf("verdict=%s findings=%d, want allow+0", res.Verdict, len(res.Findings))
		}
	})

	t.Run("not-a-boolean", func(t *testing.T) {
		rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
			return http.StatusOK, "application/json", `{"verdict": true}`
		}}
		comp := newComp(t, rec.server(t).URL)
		res := runOne(t, comp, msgPayload("x"))
		if res.Verdict != pipeline.ActionDeny { // fail_closed default
			t.Fatalf("verdict = %s, want deny on contract violation", res.Verdict)
		}
		if res.Trace[0].Outcome != pipeline.StepError {
			t.Fatalf("outcome = %s, want error", res.Trace[0].Outcome)
		}
	})
}

// TestDetect_Projections pins what leaves the gateway per params.expose:
// messages (default, joined with \n), fields:a,b (selected fields only),
// body (full content — the documented risk) — and that metadata never
// travels.
func TestDetect_Projections(t *testing.T) {
	body := `{"org_note":"internal","comment":"user text","score":3}`

	t.Run("messages-default", func(t *testing.T) {
		rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
			return http.StatusOK, "application/json", findingsResponse()
		}}
		srv := rec.server(t)
		rt := newTestRuntimeAt(t)
		comp := compileWith(t, rt, policyYAML("enforce", stepYAML(testStepID, srv.URL, "")))
		res := runOne(t, comp, msgPayload("first", "second"))
		if res.Verdict != pipeline.ActionAllow {
			t.Fatalf("verdict = %s trace=%+v", res.Verdict, res.Trace)
		}
		env := decodeEnvelope(t, rec.body)
		var content string
		_ = json.Unmarshal(env.Content, &content)
		if env.Expose != "messages" || content != "first\nsecond" {
			t.Fatalf("envelope = %+v content=%q", env, content)
		}
	})

	t.Run("fields", func(t *testing.T) {
		rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
			return http.StatusOK, "application/json", findingsResponse()
		}}
		srv := rec.server(t)
		rt := newTestRuntimeAt(t)
		comp := compileWith(t, rt, policyYAML("enforce",
			stepYAML(testStepID, srv.URL, `expose: "fields:comment,score"`)))
		runOne(t, comp, bodyPayload(body))
		env := decodeEnvelope(t, rec.body)
		if env.Expose != "fields" {
			t.Fatalf("expose = %s", env.Expose)
		}
		var content map[string]any
		_ = json.Unmarshal(env.Content, &content)
		if len(content) != 2 || content["comment"] != "user text" {
			t.Fatalf("content = %s", env.Content)
		}
		if _, leaked := content["org_note"]; leaked {
			t.Fatalf("unprojected field leaked: %s", env.Content)
		}
	})

	t.Run("body-full-content", func(t *testing.T) {
		rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
			return http.StatusOK, "application/json", findingsResponse()
		}}
		srv := rec.server(t)
		rt := newTestRuntimeAt(t)
		comp := compileWith(t, rt, policyYAML("enforce", stepYAML(testStepID, srv.URL, "expose: body")))
		runOne(t, comp, bodyPayload(body))
		env := decodeEnvelope(t, rec.body)
		var content string
		_ = json.Unmarshal(env.Content, &content)
		if env.Expose != "body" || content != body {
			t.Fatalf("content = %q, want full body", content)
		}
	})
}

// TestDetect_EmptyProjectionSkips: no messages and no body → no upstream
// call, no findings, step still traces as ran.
func TestDetect_EmptyProjectionSkips(t *testing.T) {
	rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
		t.Fatal("upstream must not be called for an empty projection")
		return 500, "application/json", ""
	}}
	srv := rec.server(t)
	rt := newTestRuntimeAt(t)
	comp := compileWith(t, rt, policyYAML("enforce", stepYAML(testStepID, srv.URL, "")))
	res := runOne(t, comp, &pipeline.Payload{Kind: pipeline.KindToolArgs})
	if res.Verdict != pipeline.ActionAllow || len(res.Findings) != 0 {
		t.Fatalf("verdict=%s findings=%d", res.Verdict, len(res.Findings))
	}
	if res.Trace[0].Outcome != pipeline.StepRan {
		t.Fatalf("outcome = %s, want ran", res.Trace[0].Outcome)
	}
}

// TestDetect_FailuresFollowOnError: 503, invalid JSON, missing findings
// array, finding without category, wrong content-type, oversized response —
// all step errors; the default fail_closed turns them into deny + error
// trace, and none of them can be mistaken for a scanner verdict.
func TestDetect_FailuresFollowOnError(t *testing.T) {
	cases := []struct {
		name   string
		status int
		ctype  string
		body   string
	}{
		{"503", http.StatusServiceUnavailable, "application/json", findingsResponse()},
		{"invalid-json", http.StatusOK, "application/json", "{nope"},
		{"missing-findings", http.StatusOK, "application/json", `{"results": []}`},
		{"null-findings", http.StatusOK, "application/json", `{"findings": null}`},
		{"finding-without-category", http.StatusOK, "application/json", findingsResponse(map[string]any{"severity": "high"})},
		{"wrong-content-type", http.StatusOK, "text/plain", findingsResponse()},
		{"boolean-in-findings-mode", http.StatusOK, "application/json", "true"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
				return tc.status, tc.ctype, tc.body
			}}
			srv := rec.server(t)
			rt := newTestRuntimeAt(t)
			comp := compileWith(t, rt, policyYAML("enforce", stepYAML(testStepID, srv.URL, "")))
			res := runOne(t, comp, msgPayload("payload"))
			if res.Verdict != pipeline.ActionDeny {
				t.Fatalf("verdict = %s, want fail_closed deny", res.Verdict)
			}
			if res.Trace[0].Outcome != pipeline.StepError || res.Trace[0].Error == "" {
				t.Fatalf("trace = %+v, want error with message", res.Trace[0])
			}
			if len(res.Findings) != 0 {
				t.Fatalf("findings = %+v, want none (error ≠ verdict)", res.Findings)
			}
		})
	}
}

// TestDetect_OversizedResponse: a response above max_response_bytes is a
// contract error (a scanner must not be able to stream arbitrary data into
// the pipeline).
func TestDetect_OversizedResponse(t *testing.T) {
	rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
		return http.StatusOK, "application/json", `{"findings":[],"padding":"` + strings.Repeat("x", 4096) + `"}`
	}}
	srv := rec.server(t)
	rt := newTestRuntimeAt(t)
	comp := compileWith(t, rt, policyYAML("enforce", stepYAML(testStepID, srv.URL, "max_response_bytes: 1024")))
	res := runOne(t, comp, msgPayload("payload"))
	if res.Verdict != pipeline.ActionDeny || !strings.Contains(res.Trace[0].Error, "exceeds") {
		t.Fatalf("verdict=%s err=%q", res.Verdict, res.Trace[0].Error)
	}
}

// TestDetect_UnknownActionFailsClosed: an unrecognized action from a
// scanner is preserved on the finding but ranks as deny via the core's
// Action.Rank — a buggy scanner can never loosen the verdict.
func TestDetect_UnknownActionFailsClosed(t *testing.T) {
	rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
		return http.StatusOK, "application/json", findingsResponse(
			map[string]any{"category": "x", "action": "shrug"})
	}}
	srv := rec.server(t)
	rt := newTestRuntimeAt(t)
	comp := compileWith(t, rt, policyYAML("enforce", stepYAML(testStepID, srv.URL, "")))
	res := runOne(t, comp, msgPayload("payload"))
	if res.Verdict != pipeline.ActionDeny {
		t.Fatalf("verdict = %s, want deny for unknown action", res.Verdict)
	}
	if res.Findings[0].Action != "shrug" {
		t.Fatalf("action = %s, want preserved", res.Findings[0].Action)
	}
}

// TestDetect_OnErrorModes: the same network failure under the three on_error
// modes — fail_closed denies, fail_open allows (error recorded), fail_open
// +flag allows with the synthetic step_error flag finding.
func TestDetect_OnErrorModes(t *testing.T) {
	rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
		return http.StatusServiceUnavailable, "application/json", ""
	}}
	srv := rec.server(t)

	newComp := func(t *testing.T, onError string) pipeline.Compiled {
		t.Helper()
		rt := newTestRuntimeAt(t)
		policy := fmt.Sprintf(`apiVersion: ypp/v1
kind: Policy
name: callout-test
mode: enforce
hooks: [pre_upstream]
steps:
%s
    on_error: %s
`, stepYAML(testStepID, srv.URL, ""), onError)
		return compileWith(t, rt, []byte(policy))
	}

	t.Run("fail_closed", func(t *testing.T) {
		res := runOne(t, newComp(t, "fail_closed"), msgPayload("p"))
		if res.Verdict != pipeline.ActionDeny || len(res.Findings) != 0 {
			t.Fatalf("verdict=%s findings=%d", res.Verdict, len(res.Findings))
		}
	})

	t.Run("fail_open", func(t *testing.T) {
		res := runOne(t, newComp(t, "fail_open"), msgPayload("p"))
		if res.Verdict != pipeline.ActionAllow || len(res.Findings) != 0 {
			t.Fatalf("verdict=%s findings=%d", res.Verdict, len(res.Findings))
		}
		if res.Trace[0].Outcome != pipeline.StepError {
			t.Fatalf("outcome = %s, want error recorded", res.Trace[0].Outcome)
		}
	})

	t.Run("fail_open_flag", func(t *testing.T) {
		res := runOne(t, newComp(t, "fail_open+flag"), msgPayload("p"))
		if res.Verdict != pipeline.ActionFlag || len(res.Findings) != 1 {
			t.Fatalf("verdict=%s findings=%+v", res.Verdict, res.Findings)
		}
		f := res.Findings[0]
		if f.Category != "step_error" || f.Action != pipeline.ActionFlag || f.Evidence == "" {
			t.Fatalf("flag finding = %+v", f)
		}
	})
}

// TestDetect_ProbeErrorIsNotVerdict: a scanner that WORKS (2xx + findings)
// is never an error even when it reports deny findings; a scanner that is
// DOWN always is. Same payload, observably different traces.
func TestDetect_ProbeErrorIsNotVerdict(t *testing.T) {
	healthy := &recorder{respond: func(int, *http.Request) (int, string, string) {
		return http.StatusOK, "application/json", findingsResponse(map[string]any{"category": "pii", "action": "deny"})
	}}
	rt := newTestRuntimeAt(t)
	ok := compileWith(t, rt, policyYAML("enforce", stepYAML(testStepID, healthy.server(t).URL, "")))
	res := runOne(t, ok, msgPayload("p"))
	if res.Trace[0].Outcome != pipeline.StepRan || len(res.Findings) != 1 {
		t.Fatalf("healthy scanner: trace=%+v findings=%d", res.Trace[0], len(res.Findings))
	}

	broken := &recorder{respond: func(int, *http.Request) (int, string, string) {
		return http.StatusInternalServerError, "application/json", ""
	}}
	down := compileWith(t, rt, policyYAML("enforce", stepYAML(testStepID, broken.server(t).URL, "")))
	res = runOne(t, down, msgPayload("p"))
	if res.Trace[0].Outcome != pipeline.StepError || len(res.Findings) != 0 {
		t.Fatalf("down scanner: trace=%+v findings=%d", res.Trace[0], len(res.Findings))
	}
}

// TestDetect_StepTimeout: the policy timeout bounds the upstream call via
// ctx — expiry is a step error (outcome timeout) and follows on_error.
func TestDetect_StepTimeout(t *testing.T) {
	release := make(chan struct{})
	rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
		<-release
		return http.StatusOK, "application/json", findingsResponse()
	}}
	srv := rec.server(t)
	t.Cleanup(func() { close(release) })

	rt := newTestRuntimeAt(t)
	policy := fmt.Sprintf(`apiVersion: ypp/v1
kind: Policy
name: callout-test
mode: enforce
hooks: [pre_upstream]
steps:
%s
    timeout: 50ms
`, stepYAML(testStepID, srv.URL, ""))
	comp := compileWith(t, rt, []byte(policy))

	start := time.Now()
	res := runOne(t, comp, msgPayload("p"))
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("step returned after %s, timeout did not clip the call", elapsed)
	}
	if res.Verdict != pipeline.ActionDeny || res.Trace[0].Outcome != pipeline.StepTimeout {
		t.Fatalf("verdict=%s outcome=%s err=%q", res.Verdict, res.Trace[0].Outcome, res.Trace[0].Error)
	}
}
