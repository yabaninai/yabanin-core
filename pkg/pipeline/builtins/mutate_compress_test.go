package builtins

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/pipeline"
)

// provider prompt-cache hints only — no text is ever altered, providers
// outside the configured set pass through untouched (OpenAI caching is
// implicit), the chat-shape system prompt is never promoted (the translate
// path would corrupt it), and every applied hint leaves its mandatory
// prompt_cache_hint finding.

// anthropicReq builds a request payload whose Meta names the routed provider.
func anthropicReq(provider string, body string) *pipeline.Payload {
	return &pipeline.Payload{
		Kind:     pipeline.KindRequest,
		Endpoint: "chat",
		Body:     []byte(body),
		Meta:     &pipeline.RequestMeta{Org: "org-a", Key: "key-1", Model: "claude-3-5-sonnet", Provider: provider},
	}
}

// bodyRoot decodes a mutated body for inspection.
func bodyRoot(t *testing.T, res *pipeline.Result) map[string]json.RawMessage {
	t.Helper()
	if res.Mutated == nil {
		t.Fatal("Mutated is nil, want a hinted body")
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(res.Mutated.Body, &root); err != nil {
		t.Fatalf("mutated body is not a JSON object: %v\n%s", err, res.Mutated.Body)
	}
	return root
}

func TestCompress_FactoryParamErrors(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]any
	}{
		{"kinds rejected", map[string]any{"kinds": []any{"request"}}},
		{"bad target", map[string]any{"targets": []any{"middle"}}},
		{"empty targets", map[string]any{"targets": []any{}}},
		{"bad ttl", map[string]any{"ttl": "90s"}},
		{"empty providers", map[string]any{"providers": []any{}}},
		{"empty provider entry", map[string]any{"providers": []any{"anthropic", ""}}},
		{"providers wrong type", map[string]any{"providers": 7}},
	}
	for _, tc := range cases {
		mustCompileErr(t, NameCompress, tc.params)
	}
}

// D2: implicit-caching providers (and unknown providers, and payloads without
// routing meta) are never hinted — the body passes through byte-untouched.
func TestCompress_NonAnthropicProvidersUntouched(t *testing.T) {
	const body = `{"model":"gpt-4o","messages":[{"role":"system","content":"sys"},{"role":"user","content":"hello"}]}`
	for _, provider := range []string{"openai", "deepseek", ""} {
		res := runMutatorOne(t, NameCompress, nil, anthropicReq(provider, body))
		if res.Mutated != nil {
			t.Errorf("provider %q: body mutated: %s", provider, res.Mutated.Body)
		}
		if len(res.Findings) != 0 {
			t.Errorf("provider %q: unexpected findings %v", provider, res.Findings)
		}
	}
}

// Main scenario on the chat shape: the last message's string content is
// promoted to a marked text part; the text survives verbatim; the system
// role message is NOT promoted (translate would corrupt it); the mandatory
// finding records the applied target.
func TestCompress_ChatShape_MarksLastTurnOnly(t *testing.T) {
	res := runMutatorOne(t, NameCompress, nil, anthropicReq("anthropic",
		`{"model":"m","messages":[{"role":"system","content":"You are careful."},{"role":"user","content":"hello world"}]}`))

	root := bodyRoot(t, res)
	var msgs []map[string]json.RawMessage
	if err := json.Unmarshal(root["messages"], &msgs); err != nil || len(msgs) != 2 {
		t.Fatalf("messages after hint: %s (%v)", root["messages"], err)
	}
	if got := string(msgs[0]["content"]); got != `"You are careful."` {
		t.Fatalf("system message content changed: %s — the chat-shape system must never be promoted", got)
	}
	var parts []map[string]json.RawMessage
	if err := json.Unmarshal(msgs[1]["content"], &parts); err != nil || len(parts) != 1 {
		t.Fatalf("last content not promoted to parts: %s (%v)", msgs[1]["content"], err)
	}
	if string(parts[0]["text"]) != `"hello world"` {
		t.Fatalf("text altered: %s", parts[0]["text"])
	}
	if string(parts[0]["cache_control"]) != `{"type":"ephemeral"}` {
		t.Fatalf("cache_control = %s", parts[0]["cache_control"])
	}

	fs := findingsOf(res, "s1")
	if len(fs) != 1 || fs[0].Category != compressCategory || fs[0].Action != pipeline.ActionFlag {
		t.Fatalf("findings = %v, want one flag prompt_cache_hint", res.Findings)
	}
	if res.Verdict != pipeline.ActionFlag {
		t.Fatalf("verdict = %s, want flag", res.Verdict)
	}
}

// An already-structured last turn gets the marker on its LAST part; text and
// all other parts survive.
func TestCompress_ChatShape_PartsContentMarkedLast(t *testing.T) {
	res := runMutatorOne(t, NameCompress, map[string]any{"targets": []any{"last"}}, anthropicReq("anthropic",
		`{"messages":[{"role":"user","content":[{"type":"text","text":"a"},{"type":"text","text":"b"}]}]}`))

	var msgs []map[string]json.RawMessage
	if err := json.Unmarshal(bodyRoot(t, res)["messages"], &msgs); err != nil {
		t.Fatal(err)
	}
	var parts []map[string]json.RawMessage
	if err := json.Unmarshal(msgs[0]["content"], &parts); err != nil || len(parts) != 2 {
		t.Fatalf("parts: %s (%v)", msgs[0]["content"], err)
	}
	if _, marked := parts[0]["cache_control"]; marked {
		t.Fatalf("first part marked: %s", msgs[0]["content"])
	}
	if string(parts[1]["cache_control"]) != `{"type":"ephemeral"}` {
		t.Fatalf("last part cache_control = %v", parts[1]["cache_control"])
	}
	if string(parts[1]["text"]) != `"b"` {
		t.Fatalf("text altered: %s", parts[1]["text"])
	}
}

// Idempotency: an already-marked target is skipped, so stacked policies and
// re-runs never double-mark (Anthropic caps cache_control blocks).
func TestCompress_AlreadyMarkedIsNoop(t *testing.T) {
	const body = `{"messages":[{"role":"user","content":[{"type":"text","text":"a","cache_control":{"type":"ephemeral"}}]}]}`
	res := runMutatorOne(t, NameCompress, nil, anthropicReq("anthropic", body))
	if res.Mutated != nil {
		t.Fatalf("already-marked body mutated again: %s", res.Mutated.Body)
	}
}

// Native shape: a string system is promoted to one marked text block; the
// system text survives verbatim.
func TestCompress_NativeSystemStringPromoted(t *testing.T) {
	res := runMutatorOne(t, NameCompress, map[string]any{"targets": []any{"system"}}, anthropicReq("anthropic",
		`{"model":"m","system":"You are careful.","messages":[{"role":"user","content":"hi"}]}`))

	root := bodyRoot(t, res)
	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(root["system"], &blocks); err != nil || len(blocks) != 1 {
		t.Fatalf("system not promoted to blocks: %s (%v)", root["system"], err)
	}
	if string(blocks[0]["text"]) != `"You are careful."` {
		t.Fatalf("system text altered: %s", blocks[0]["text"])
	}
	if string(blocks[0]["cache_control"]) != `{"type":"ephemeral"}` {
		t.Fatalf("system cache_control = %v", blocks[0]["cache_control"])
	}
	if string(root["messages"]) != `[{"content":"hi","role":"user"}]` && !strings.Contains(string(root["messages"]), `"content":"hi"`) {
		t.Fatalf("messages touched by system-only hint: %s", root["messages"])
	}
}

// Native shape: a block-array system gets the marker on its last block; a
// marker anywhere in the array keeps the whole target untouched.
func TestCompress_NativeSystemBlocksMarkedLastOrSkipped(t *testing.T) {
	res := runMutatorOne(t, NameCompress, map[string]any{"targets": []any{"system"}}, anthropicReq("anthropic",
		`{"system":[{"type":"text","text":"a"},{"type":"text","text":"b"}],"messages":[{"role":"user","content":"hi"}]}`))
	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(bodyRoot(t, res)["system"], &blocks); err != nil || len(blocks) != 2 {
		t.Fatal("system blocks")
	}
	if _, marked := blocks[0]["cache_control"]; marked {
		t.Fatalf("first system block marked: %v", blocks[0])
	}
	if string(blocks[1]["cache_control"]) != `{"type":"ephemeral"}` {
		t.Fatalf("last system block cache_control = %v", blocks[1]["cache_control"])
	}

	const marked = `{"system":[{"type":"text","text":"a","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"hi"}]}`
	res = runMutatorOne(t, NameCompress, map[string]any{"targets": []any{"system"}}, anthropicReq("anthropic", marked))
	if res.Mutated != nil {
		t.Fatalf("already-marked system mutated again: %s", res.Mutated.Body)
	}
}

// The last-turn scan skips contentless trailing messages and marks the last
// message that actually carries content.
func TestCompress_LastSkipsContentlessTrailingMessages(t *testing.T) {
	res := runMutatorOne(t, NameCompress, map[string]any{"targets": []any{"last"}}, anthropicReq("anthropic",
		`{"messages":[{"role":"user","content":"real question"},{"role":"assistant","content":""}]}`))

	var msgs []map[string]json.RawMessage
	if err := json.Unmarshal(bodyRoot(t, res)["messages"], &msgs); err != nil || len(msgs) != 2 {
		t.Fatal("messages")
	}
	var parts []map[string]json.RawMessage
	if err := json.Unmarshal(msgs[0]["content"], &parts); err != nil || len(parts) != 1 || parts[0]["cache_control"] == nil {
		t.Fatalf("content-carrying message not marked: %s (%v)", msgs[0]["content"], err)
	}
	if string(msgs[1]["content"]) != `""` {
		t.Fatalf("empty trailing content altered: %s", msgs[1]["content"])
	}
}

// ttl lands in the emitted cache_control block.
func TestCompress_TTLParameter(t *testing.T) {
	res := runMutatorOne(t, NameCompress, map[string]any{"ttl": "5m"}, anthropicReq("anthropic",
		`{"messages":[{"role":"user","content":"hi"}]}`))
	var msgs []map[string]json.RawMessage
	if err := json.Unmarshal(bodyRoot(t, res)["messages"], &msgs); err != nil {
		t.Fatal(err)
	}
	var parts []map[string]json.RawMessage
	if err := json.Unmarshal(msgs[0]["content"], &parts); err != nil {
		t.Fatal(err)
	}
	if got := string(parts[0]["cache_control"]); got != `{"type":"ephemeral","ttl":"5m"}` {
		t.Fatalf("cache_control = %s, want ttl 5m", got)
	}
}

// No messages (or an unusable array) means nothing to hint — no mutation,
// no findings, allow verdict.
func TestCompress_NoMessagesNoop(t *testing.T) {
	for _, body := range []string{`{"model":"m"}`, `{"messages":[]}`, `{"messages":"nope"}`} {
		res := runMutatorOne(t, NameCompress, nil, anthropicReq("anthropic", body))
		if res.Mutated != nil || len(res.Findings) != 0 {
			t.Errorf("body %s: mutated=%v findings=%v, want noop", body, res.Mutated, res.Findings)
		}
	}
}

// A non-object body is a step error (fail-closed by default): a malformed
// request must never pass silently.
func TestCompress_MalformedBodyFailsClosed(t *testing.T) {
	res := runMutatorOne(t, NameCompress, nil, anthropicReq("anthropic", `[1,2,3]`))
	if len(res.Trace) != 1 || res.Trace[0].Outcome != pipeline.StepError {
		t.Fatalf("trace = %+v, want step error", res.Trace)
	}
	if res.Verdict != pipeline.ActionDeny {
		t.Fatalf("verdict = %s, want deny (fail-closed default)", res.Verdict)
	}
}

// Response payloads are out of contract — the kinds gate keeps them
// untouched even with a provider match.
func TestCompress_ResponseKindSkipped(t *testing.T) {
	p := &pipeline.Payload{
		Kind: pipeline.KindResponse,
		Body: []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
		Meta: &pipeline.RequestMeta{Provider: "anthropic"},
	}
	res := runMutatorOne(t, NameCompress, nil, p)
	if res.Mutated != nil {
		t.Fatalf("response payload mutated: %s", res.Mutated.Body)
	}
}

// The providers param widens the matrix (D2 stays open): an extra provider
// becomes hintable without code changes.
func TestCompress_ProvidersParamWidensMatrix(t *testing.T) {
	res := runMutatorOne(t, NameCompress, map[string]any{"providers": []any{"vertex"}}, anthropicReq("vertex",
		`{"messages":[{"role":"user","content":"hi"}]}`))
	if res.Mutated == nil {
		t.Fatal("configured vertex provider not hinted")
	}
}

// Failure/boundary matrix: bad step params never
// produce a half-built step, wrong param TYPES are refused at compile time
// (the YAML surface can deliver numbers/bools where strings are wanted).
func TestCompress_FactoryParamTypeErrors(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]any
	}{
		{"ttl not a string", map[string]any{"ttl": 5}},
		{"ttl empty", map[string]any{"ttl": ""}},
		{"ttl bool", map[string]any{"ttl": true}},
		{"targets not a list", map[string]any{"targets": 7}},
		{"targets entry not a string", map[string]any{"targets": []any{"last", 3}}},
		{"providers entry not a string", map[string]any{"providers": []any{"anthropic", 1}}},
		{"providers not a list", map[string]any{"providers": false}},
	}
	for _, tc := range cases {
		mustCompileErr(t, NameCompress, tc.params)
	}
}

// Invalid JSON (not just a valid non-object) fails closed: the step errors
// and the verdict is deny — a corrupt request never crosses half-hinted.
func TestCompress_InvalidJSONBodyFailsClosed(t *testing.T) {
	for _, body := range []string{`{"messages":[`, `not json at all`} {
		res := runMutatorOne(t, NameCompress, nil, anthropicReq("anthropic", body))
		if len(res.Trace) != 1 || res.Trace[0].Outcome != pipeline.StepError {
			t.Fatalf("body %q: trace = %+v, want step error", body, res.Trace)
		}
		if res.Verdict != pipeline.ActionDeny {
			t.Fatalf("body %q: verdict = %s, want deny (fail-closed)", body, res.Verdict)
		}
		if res.Mutated != nil {
			t.Fatalf("body %q: a failed run must not adopt a mutated body: %s", body, res.Mutated.Body)
		}
	}
}

// Body-shape refusals (card negative: corruption is refused, never guessed):
// every shape the step cannot mark SAFELY is left untouched — the unusable
// member survives byte-identical, and when nothing is hintable at all the
// whole body passes with no findings and an allow verdict.
func TestCompress_UnusableShapesNeverCorrupted(t *testing.T) {
	noopCases := []string{
		`{"messages":[1,2]}`,                          // non-object entries
		`{"messages":[{}]}`,                           // message without role/content
		`{"messages":[{"role":"user","content":42}]}`, // numeric content
		`{"messages":[{"role":"user","content":{"type":"image","source":"x"}}]}`,   // object content
		`{"messages":[{"role":"user","content":[{"type":"text","text":"a"},17]}]}`, // mixed parts array
	}
	for _, body := range noopCases {
		res := runMutatorOne(t, NameCompress, nil, anthropicReq("anthropic", body))
		if res.Mutated != nil || len(res.Findings) != 0 || res.Verdict != pipeline.ActionAllow {
			t.Errorf("body %s: mutated=%v findings=%v verdict=%s — unusable shapes must pass untouched",
				body, res.Mutated != nil, res.Findings, res.Verdict)
		}
	}

	// An unusable system next to a usable last turn: the last turn still gets
	// its hint, the system member survives byte-identical.
	systemCases := []struct{ body, system string }{
		{`{"system":123,"messages":[{"role":"user","content":"hi"}]}`, `123`},
		{`{"system":[],"messages":[{"role":"user","content":"hi"}]}`, `[]`},
	}
	for _, tc := range systemCases {
		res := runMutatorOne(t, NameCompress, nil, anthropicReq("anthropic", tc.body))
		if res.Mutated == nil {
			t.Fatalf("body %s: the usable last turn must still be hinted", tc.body)
		}
		var root map[string]json.RawMessage
		if err := json.Unmarshal(res.Mutated.Body, &root); err != nil {
			t.Fatalf("body %s: mutated body is not JSON: %v", tc.body, err)
		}
		if string(root["system"]) != tc.system {
			t.Fatalf("body %s: unusable system corrupted to %s, want byte-identical %s", tc.body, root["system"], tc.system)
		}
		fs := findingsOf(res, "s1")
		if len(fs) != 1 || !strings.Contains(fs[0].Evidence, "last") || strings.Contains(fs[0].Evidence, "system") {
			t.Fatalf("body %s: findings %v — only the last target may report", tc.body, res.Findings)
		}
	}
}

// The idempotency oracle is marker PRESENCE, not marker validity: a part
// carrying any pre-existing cache_control value (even null or a malformed
// non-object) is skipped — the step never stacks a second marker and never
// rewrites a foreign one.
func TestCompress_MarkerPresenceIsIdempotencyOracle(t *testing.T) {
	cases := []string{
		`{"messages":[{"role":"user","content":[{"type":"text","text":"a","cache_control":null}]}]}`,
		`{"messages":[{"role":"user","content":[{"type":"text","text":"a","cache_control":"not an object"}]}]}`,
		`{"messages":[{"role":"user","content":[{"type":"text","text":"a","cache_control":{"type":"ephemeral","ttl":"1h"}}]}]}`,
	}
	for _, body := range cases {
		res := runMutatorOne(t, NameCompress, nil, anthropicReq("anthropic", body))
		if res.Mutated != nil {
			t.Errorf("pre-marked body mutated: %s", res.Mutated.Body)
		}
		if strings.Count(body, `"cache_control"`) != 1 {
			t.Errorf("case construction: want exactly one marker in %s", body)
		}
	}
}

// Double-apply equals a single marker per target (card: повтор операции):
// feeding the step's own output back through the same policy is a no-op —
// the marker count of the final body stays exactly one per target.
func TestCompress_DoubleApplySingleMarker(t *testing.T) {
	const body = `{"model":"m","system":"You are careful.","messages":[{"role":"user","content":"hello"}]}`
	res := runMutatorOne(t, NameCompress, map[string]any{"ttl": "5m"}, anthropicReq("anthropic", body))
	if res.Mutated == nil {
		t.Fatal("first apply produced no mutation")
	}
	if got := strings.Count(string(res.Mutated.Body), `"cache_control"`); got != 2 {
		t.Fatalf("first apply marker count = %d, want 2 (native system + last):\n%s", got, res.Mutated.Body)
	}
	again := runMutatorOne(t, NameCompress, map[string]any{"ttl": "5m"}, anthropicReq("anthropic", string(res.Mutated.Body)))
	if again.Mutated != nil {
		t.Fatalf("second apply mutated again: %s", again.Mutated.Body)
	}
	if len(again.Findings) != 0 {
		t.Fatalf("second apply emitted findings: %v", again.Findings)
	}

	lastOnly := runMutatorOne(t, NameCompress, map[string]any{"targets": []any{"last"}}, anthropicReq("anthropic", body))
	if lastOnly.Mutated == nil {
		t.Fatal("last-only apply produced no mutation")
	}
	if got := strings.Count(string(lastOnly.Mutated.Body), `"cache_control"`); got != 1 {
		t.Fatalf("last-only marker count = %d, want 1:\n%s", got, lastOnly.Mutated.Body)
	}
}

// Stacked policies never double-mark (Anthropic caps cache_control at four):
// two builtin/compress steps in one policy leave exactly one marker per
// target and only the first application emits its finding.
func TestCompress_StackedStepsSingleMarker(t *testing.T) {
	specs := []pipeline.StepSpec{
		{ID: "s1", Mutator: NameCompress, Params: nil},
		{ID: "s2", Mutator: NameCompress, Params: map[string]any{"ttl": "1h"}},
	}
	res := runStepSpecs(t, specs, anthropicReq("anthropic",
		`{"model":"m","messages":[{"role":"user","content":"hello world"}]}`))
	if res.Mutated == nil {
		t.Fatal("stacked steps produced no mutation")
	}
	if got := strings.Count(string(res.Mutated.Body), `"cache_control"`); got != 1 {
		t.Fatalf("stacked marker count = %d, want 1:\n%s", got, res.Mutated.Body)
	}
	if got := strings.Count(string(res.Mutated.Body), `"ttl"`); got != 0 {
		t.Fatalf("second step must not re-mark with its own ttl:\n%s", res.Mutated.Body)
	}
	if len(findingsOf(res, "s1")) != 1 || len(findingsOf(res, "s2")) != 0 {
		t.Fatalf("findings: s1=%v s2=%v — only the applying step reports", findingsOf(res, "s1"), findingsOf(res, "s2"))
	}
}

// D2 provider-gate boundaries: no routing meta, case-mismatched names and
// the providers param's REPLACE semantics (configuring [vertex] un-hints
// anthropic — it does not widen to [anthropic,vertex]).
func TestCompress_ProviderGateBoundaries(t *testing.T) {
	const body = `{"messages":[{"role":"user","content":"hi"}]}`

	noMeta := anthropicReq("anthropic", body)
	noMeta.Meta = nil
	if res := runMutatorOne(t, NameCompress, nil, noMeta); res.Mutated != nil {
		t.Errorf("nil meta mutated: %s", res.Mutated.Body)
	}

	if res := runMutatorOne(t, NameCompress, nil, anthropicReq("Anthropic", body)); res.Mutated != nil {
		t.Errorf("case-mismatched provider mutated: %s", res.Mutated.Body)
	}

	if res := runMutatorOne(t, NameCompress, map[string]any{"providers": []any{"vertex"}}, anthropicReq("anthropic", body)); res.Mutated != nil {
		t.Errorf("providers=[vertex] must not hint anthropic (replace, not add): %s", res.Mutated.Body)
	}
	if res := runMutatorOne(t, NameCompress, map[string]any{"providers": []any{"vertex"}}, anthropicReq("vertex", body)); res.Mutated == nil {
		t.Error("providers=[vertex] must hint vertex")
	}
	if res := runMutatorOne(t, NameCompress, map[string]any{"providers": []any{"anthropic", "vertex"}}, anthropicReq("vertex", body)); res.Mutated == nil {
		t.Error("explicit anthropic+vertex matrix must hint vertex")
	}
}

// Cancellation is honored by the step itself: a canceled ctx before Run
// returns ctx.Err() and leaves the body untouched (no partial marker).
func TestCompress_CtxCanceledLeavesBodyUntouched(t *testing.T) {
	step, err := NewCompress(nil)
	if err != nil {
		t.Fatalf("NewCompress: %v", err)
	}
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	const body = `{"messages":[{"role":"user","content":"hi"}]}`
	in := anthropicReq("anthropic", body)
	out := &pipeline.Result{}
	if err := step.Run(cctx, &pipeline.Pipeline{}, in, out); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	if string(in.Body) != body {
		t.Fatalf("canceled run mutated the body: %s", in.Body)
	}
	if len(out.Findings) != 0 {
		t.Fatalf("canceled run emitted findings: %v", out.Findings)
	}
}

// At the engine level a canceled context skips the step BEFORE it runs —
// the request continues with its original bytes (interrupt = no mutation,
// never a half-marked body).
func TestCompress_CtxCanceledEngineSkipsUnmutated(t *testing.T) {
	const body = `{"messages":[{"role":"user","content":"hi"}]}`
	eng := testEngine(t)
	pol := pipeline.Policy{
		APIVersion: pipeline.APIVersionYPP,
		Kind:       pipeline.KindPolicy,
		Name:       "test-policy",
		Mode:       pipeline.ModeEnforce,
		Hooks:      []pipeline.Hook{pipeline.HookPreUpstream},
		Steps:      []pipeline.StepSpec{{ID: "s1", Mutator: NameCompress}},
	}
	c, err := eng.CompilePolicy(pol)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := eng.Run(cctx, []pipeline.Compiled{c}, anthropicReq("anthropic", body))
	if out.Mutated != nil {
		t.Fatalf("canceled engine run mutated the body: %s", out.Mutated.Body)
	}
	if len(out.Findings) != 0 {
		t.Fatalf("canceled engine run emitted findings: %v", out.Findings)
	}
}

// Cache identity follows the ACTUAL content (acceptance example 4): a hinted
// body hashes differently from the unhinted one — same prompt with and
// without the policy never collides — while the deterministic injection
// keeps identical prompts on one stable identity (cache hits still work).
func TestCompress_CacheIdentityOverActualContent(t *testing.T) {
	const body = `{"messages":[{"role":"user","content":"cache me please"}]}`
	res := runMutatorOne(t, NameCompress, nil, anthropicReq("anthropic", body))
	if res.Mutated == nil {
		t.Fatal("hint missing")
	}
	res2 := runMutatorOne(t, NameCompress, nil, anthropicReq("anthropic", body))

	base, err := cache.NormalizeMessagesJSON([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	hinted, err := cache.NormalizeMessagesJSON(res.Mutated.Body)
	if err != nil {
		t.Fatal(err)
	}
	hinted2, err := cache.NormalizeMessagesJSON(res2.Mutated.Body)
	if err != nil {
		t.Fatal(err)
	}
	if cache.ComputePromptHash(base) == cache.ComputePromptHash(hinted) {
		t.Fatal("hinted and unhinted bodies must not share a cache identity")
	}
	if cache.ComputePromptHash(hinted) != cache.ComputePromptHash(hinted2) {
		t.Fatal("identical prompts must receive identical hints (stable cache identity)")
	}
}
