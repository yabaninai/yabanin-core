package cli

// RT-04 regression: the guarded raw JSON body is the single source of truth
// for everything downstream of the egress guard. The typed projection must be
// rebuilt from the guarded body, and vertical prompt patches must be applied
// to the raw JSON so that (a) secrets the guard removed never re-enter the
// upstream payload via a stale pre-guard projection, and (b) unknown provider
// fields, tools and multimodal content survive end-to-end.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/retry"
	fallbackrouter "github.com/reireirei/yabanin/pkg/router"
	"github.com/reireirei/yabanin/pkg/upstream"
	"github.com/reireirei/yabanin/pkg/verticals"
)

// rt04Secret is a synthetic provider-API-key fixture matching the guardhooks
// secret detector. It is not a real credential.
const rt04Secret = "sk-abcdefghijklmnop12345678"

// rt04MaskVertical is an active vertical for the test org. With masking on it
// always rewrites the prompt; it records the prompt it received so tests can
// assert that transforms see the guarded payload, and it can be made to fail
// to exercise the transform-error path.
type rt04MaskVertical struct {
	mu      sync.Mutex
	lastIn  verticals.Request
	masking bool
	fail    bool
}

func (v *rt04MaskVertical) ID() string            { return "rt04_mask" }
func (v *rt04MaskVertical) Region() policy.Region { return "GLOBAL" }
func (v *rt04MaskVertical) Name() string          { return "RT-04 mask" }
func (v *rt04MaskVertical) Description() string   { return "test vertical" }
func (v *rt04MaskVertical) DefaultRules() policy.ResidencyRule {
	return policy.ResidencyRule{
		AllowedJurisdictions: []policy.Region{"GLOBAL"},
		AllowedModelFamilies: []string{"*"},
		DataResidency:        "GLOBAL",
	}
}

func (v *rt04MaskVertical) Evaluate(context.Context, policy.EvalContext, *policy.ResidencyRule) policy.Decision {
	return policy.Decision{Allowed: true, Region: "GLOBAL", PackID: "rt04_mask"}
}

func (v *rt04MaskVertical) Transform(ctx context.Context, in verticals.Request) (context.Context, verticals.Response, error) {
	v.mu.Lock()
	v.lastIn = in
	fail := v.fail
	v.mu.Unlock()
	if fail {
		return ctx, verticals.Response{}, errors.New("synthetic transform failure")
	}
	out := in.Prompt
	if v.masking {
		out = "[MASKED-PROMPT]"
	}
	return ctx, verticals.Response{Model: in.ModelRequested, Prompt: out, Metadata: map[string]string{"applied": "1"}}, nil
}

func (v *rt04MaskVertical) Report(context.Context, string, string, string, string) ([]byte, error) {
	return nil, nil
}

func (v *rt04MaskVertical) received() verticals.Request {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.lastIn
}

// rt04Capture records upstream request bodies race-free.
type rt04Capture struct {
	mu     sync.Mutex
	bodies []string
}

func (c *rt04Capture) add(b string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bodies = append(c.bodies, b)
}

func (c *rt04Capture) last() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.bodies) == 0 {
		return ""
	}
	return c.bodies[len(c.bodies)-1]
}

func (c *rt04Capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bodies)
}

// rt04Gateway wires the chat pipeline with guard hooks and verticals but no
// DB/Redis/classifier, pointing the upstream pool at upstreamURL.
func rt04Gateway(upstreamURL string, mode guardhooks.Mode, reg *verticals.Registry) *gateway {
	return &gateway{
		cfg: config.Gateway{
			Provider: upstreamURL,
			APIKey:   "test-key",
			AuthMode: "fail-open",
		},
		pool:        upstream.NewPool(upstream.Options{BaseURL: upstreamURL}),
		fallback:    fallbackrouter.NewFallbackExecutor(nil, 3, nil),
		retryPolicy: retry.Policy{MaxAttempts: 1},
		log:         slog.Default(),
		guardHooks:  guardhooks.New(mode),
		verticalReg: reg,
	}
}

func rt04Registry(t *testing.T, v *rt04MaskVertical) *verticals.Registry {
	t.Helper()
	reg := verticals.NewRegistry()
	require.NoError(t, reg.Register(v))
	require.NoError(t, reg.EnableFor("org-1", v.ID()))
	return reg
}

// rt04ChatBody is a JSON chat request with a secret in a NON-last (system)
// message, unknown top-level provider fields, unknown message fields and a
// tools array — everything a narrow typed projection would destroy.
func rt04ChatBody(stream bool) []byte {
	return []byte(`{
		"model": "gpt-4o-mini",
		"messages": [
			{"role": "system", "content": "system context ` + rt04Secret + `", "x_custom_msg": "msg-keep"},
			{"role": "user", "content": "please process patient-record"}
		],
		"stream": ` + boolJSON(stream) + `,
		"my_custom_field": "keep-me",
		"tools": [{"type": "function", "function": {"name": "get_weather", "parameters": {"type": "object"}}}]
	}`)
}

func boolJSON(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// rt04AssertGuardedMaskedPayload asserts the full RT-04 contract on a captured
// upstream payload: guard redaction survived, the vertical mask was applied,
// and unknown fields/tools/other messages are intact.
func rt04AssertGuardedMaskedPayload(t *testing.T, sent string) {
	t.Helper()
	assert.NotContains(t, sent, rt04Secret,
		"secret removed by the guard must never re-enter the upstream payload")
	assert.Contains(t, sent, "[REDACTED_SECRET]",
		"guard redaction must survive downstream patching")
	assert.Contains(t, sent, "[MASKED-PROMPT]",
		"vertical mask must be applied to the last message")
	assert.NotContains(t, sent, "patient-record",
		"the original last-message text must be replaced by the mask")
	assert.Contains(t, sent, "keep-me",
		"unknown top-level provider fields must be preserved")
	assert.Contains(t, sent, "get_weather",
		"tools must be preserved")
	assert.Contains(t, sent, "msg-keep",
		"unknown fields inside messages must be preserved")
	assert.Contains(t, sent, "system context",
		"non-last messages must be preserved")
}

// TestRT04_GuardRedactVerticalMask_JSON: guard redacts a secret in a system
// message, an active vertical masks the last (user) message. The upstream
// payload must carry the guarded+masked raw JSON — never a re-serialized
// pre-guard typed projection.
func TestRT04_GuardRedactVerticalMask_JSON(t *testing.T) {
	cap := &rt04Capture{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		cap.add(string(raw))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(completeResp("gpt-4o-mini"))
	}))
	t.Cleanup(up.Close)

	vert := &rt04MaskVertical{masking: true}
	gw := rt04Gateway(up.URL, guardhooks.ModeRedact, rt04Registry(t, vert))

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(string(rt04ChatBody(false))))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	require.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())
	require.Equal(t, 1, cap.count(), "exactly one upstream call expected")
	rt04AssertGuardedMaskedPayload(t, cap.last())
}

// TestRT04_GuardRedactVerticalMask_SSE: same contract on the streaming path —
// chatCompletions guards and vertical-patches the body before serveStream
// forwards it.
func TestRT04_GuardRedactVerticalMask_SSE(t *testing.T) {
	const sse = "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\n" +
		"data: [DONE]\n\n"
	cap := &rt04Capture{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		cap.add(string(raw))
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(sse))
	}))
	t.Cleanup(up.Close)

	vert := &rt04MaskVertical{masking: true}
	gw := rt04Gateway(up.URL, guardhooks.ModeRedact, rt04Registry(t, vert))

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(string(rt04ChatBody(true))))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	require.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())
	clientOut := w.Body.String()
	assert.Contains(t, clientOut, "data: ", "client must receive SSE frames")
	assert.Contains(t, clientOut, "[DONE]", "client stream must terminate")
	require.Equal(t, 1, cap.count(), "exactly one upstream call expected")
	rt04AssertGuardedMaskedPayload(t, cap.last())
}

// TestRT04_VerticalReceivesGuardedPrompt: the vertical's Transform input must
// be built from the guarded body — a secret the guard removed must not be
// handed to downstream transforms either.
func TestRT04_VerticalReceivesGuardedPrompt(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(completeResp("gpt-4o-mini"))
	}))
	t.Cleanup(up.Close)

	vert := &rt04MaskVertical{masking: true}
	gw := rt04Gateway(up.URL, guardhooks.ModeRedact, rt04Registry(t, vert))

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"token ` + rt04Secret + ` end"}],"stream":false}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	require.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())
	got := vert.received()
	assert.NotContains(t, got.Prompt, rt04Secret,
		"the vertical must see the guarded prompt, not the pre-guard text")
	assert.Contains(t, got.Prompt, "[REDACTED_SECRET]")
}

// TestRT04_NoopVertical_PreservesGuardedBody: a vertical that leaves the
// prompt untouched must not trigger any body rewrite; the guarded raw JSON
// (secret removed, unknown fields intact) goes upstream as-is.
func TestRT04_NoopVertical_PreservesGuardedBody(t *testing.T) {
	cap := &rt04Capture{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		cap.add(string(raw))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(completeResp("gpt-4o-mini"))
	}))
	t.Cleanup(up.Close)

	vert := &rt04MaskVertical{masking: false} // returns the prompt unchanged
	gw := rt04Gateway(up.URL, guardhooks.ModeRedact, rt04Registry(t, vert))

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(string(rt04ChatBody(false))))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	require.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())
	sent := cap.last()
	assert.NotContains(t, sent, rt04Secret)
	assert.Contains(t, sent, "[REDACTED_SECRET]")
	assert.Contains(t, sent, "keep-me", "no-op vertical must not rebuild the body")
	assert.Contains(t, sent, "patient-record", "untouched prompt must survive")
	assert.Contains(t, sent, "get_weather")
}

// TestRT04_VerticalPatch_MultimodalContentPreserved: patching the last
// message of a multimodal request must keep the non-text parts (image) and
// only rewrite the text part.
func TestRT04_VerticalPatch_MultimodalContentPreserved(t *testing.T) {
	cap := &rt04Capture{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		cap.add(string(raw))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(completeResp("gpt-4o-mini"))
	}))
	t.Cleanup(up.Close)

	vert := &rt04MaskVertical{masking: true}
	gw := rt04Gateway(up.URL, guardhooks.ModeRedact, rt04Registry(t, vert))

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":[` +
		`{"type":"text","text":"scan this image for token ` + rt04Secret + `"},` +
		`{"type":"image_url","image_url":{"url":"https://example.test/img.png"}}` +
		`]}],"stream":false,"my_custom_field":"keep-me"}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	require.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())
	sent := cap.last()
	assert.NotContains(t, sent, rt04Secret)
	// The mask replaces the whole text part, so the guard's redaction token
	// no longer appears — the secret is absent either way, which is the
	// contract under test here.
	assert.Contains(t, sent, "[MASKED-PROMPT]", "text part must carry the mask")
	assert.Contains(t, sent, "image_url", "image part must survive the patch")

	var got struct {
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal([]byte(sent), &got))
	require.Len(t, got.Messages, 1)
	var parts []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(got.Messages[0].Content, &parts),
		"multimodal content must stay an array, got: %s", string(got.Messages[0].Content))
	require.Len(t, parts, 2, "both content parts must survive")
}

// TestRT04_MalformedBody_ExplicitError: a malformed JSON body is rejected with
// 400 and never forwarded.
func TestRT04_MalformedBody_ExplicitError(t *testing.T) {
	cap := &rt04Capture{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		cap.add(string(raw))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(completeResp("gpt-4o-mini"))
	}))
	t.Cleanup(up.Close)

	gw := rt04Gateway(up.URL, guardhooks.ModeRedact, nil)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o-mini","messages":[`))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, 0, cap.count(), "malformed body must not be forwarded")
}

// TestRT04_VerticalTransformError_ExplicitError: a failing vertical transform
// stops the request with 403 and does not forward.
func TestRT04_VerticalTransformError_ExplicitError(t *testing.T) {
	cap := &rt04Capture{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		cap.add(string(raw))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(completeResp("gpt-4o-mini"))
	}))
	t.Cleanup(up.Close)

	vert := &rt04MaskVertical{fail: true}
	gw := rt04Gateway(up.URL, guardhooks.ModeRedact, rt04Registry(t, vert))

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(string(rt04ChatBody(false))))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, 0, cap.count(), "transform error must not forward the request")
}

// TestRT04_NonChatGuardPath_EmbeddingsNoSecretUpstream: the non-chat admit
// path must forward the guarded body (no pre-guard Body reuse) and preserve
// unknown fields.
func TestRT04_NonChatGuardPath_EmbeddingsNoSecretUpstream(t *testing.T) {
	cap := &rt04Capture{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		cap.add(string(raw))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"embedding":[0.1,0.2]}],"usage":{"prompt_tokens":3,"total_tokens":3}}`))
	}))
	t.Cleanup(up.Close)

	gw := rt04Gateway(up.URL, guardhooks.ModeRedact, nil)

	body := `{"model":"text-embedding-3-small","input":"lookup key ` + rt04Secret + `","my_custom_field":"keep-me"}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/embeddings", strings.NewReader(body))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.embeddings(w, r)

	require.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())
	sent := cap.last()
	assert.NotContains(t, sent, rt04Secret,
		"non-chat guard path must not forward the secret")
	assert.Contains(t, sent, "[REDACTED_SECRET]")
	assert.Contains(t, sent, "keep-me",
		"non-chat guard path must preserve unknown fields")
}

// --- patchLastMessageContent unit tests (RT-04 raw-JSON patch helper) ---

func TestRT04Patch_ReplacesLastMessageAndPreservesRest(t *testing.T) {
	body := []byte(`{"model":"m","messages":[` +
		`{"role":"system","content":"keep me","x":"y"},` +
		`{"role":"user","content":"old"}],"tools":[{"type":"function"}],"custom":"keep-me"}`)
	out, err := patchLastMessageContent(body, "new prompt")
	require.NoError(t, err)

	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &got))
	assert.JSONEq(t, `"keep-me"`, string(got["custom"]))
	assert.JSONEq(t, `[{"type":"function"}]`, string(got["tools"]))

	var msgs []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(got["messages"], &msgs))
	require.Len(t, msgs, 2)
	assert.JSONEq(t, `"keep me"`, string(msgs[0]["content"]))
	assert.JSONEq(t, `"y"`, string(msgs[0]["x"]), "unknown message fields preserved")
	assert.JSONEq(t, `"new prompt"`, string(msgs[1]["content"]))
	assert.JSONEq(t, `"user"`, string(msgs[1]["role"]))
}

func TestRT04Patch_MultimodalSingleTextPartReplaced(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":[` +
		`{"type":"text","text":"old text"},{"type":"image_url","image_url":{"url":"u"}}]}]}`)
	out, err := patchLastMessageContent(body, "replaced")
	require.NoError(t, err)

	var got struct {
		Messages []struct {
			Content []map[string]json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(out, &got))
	require.Len(t, got.Messages, 1)
	require.Len(t, got.Messages[0].Content, 2, "array shape preserved")
	var text string
	var image struct {
		URL string `json:"url"`
	}
	require.NoError(t, json.Unmarshal(got.Messages[0].Content[0]["text"], &text))
	require.NoError(t, json.Unmarshal(got.Messages[0].Content[1]["image_url"], &image))
	assert.Equal(t, "replaced", text)
	assert.Equal(t, "u", image.URL)
}

func TestRT04Patch_MultimodalTwoTextPartsCollapsesToString(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":[` +
		`{"type":"text","text":"a"},{"type":"text","text":"b"}]}]}`)
	out, err := patchLastMessageContent(body, "collapsed")
	require.NoError(t, err)

	var got struct {
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(out, &got))
	assert.JSONEq(t, `"collapsed"`, string(got.Messages[0].Content))
}

func TestRT04Patch_ErrorCases(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"invalid json", `{`},
		{"no messages", `{"model":"m"}`},
		{"empty messages", `{"messages":[]}`},
		{"messages not array", `{"messages":"nope"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := patchLastMessageContent([]byte(tc.body), "x")
			assert.Error(t, err)
		})
	}
}

func TestRT04Patch_ContentNullAndMissing(t *testing.T) {
	out, err := patchLastMessageContent([]byte(`{"messages":[{"role":"user","content":null}]}`), "x")
	require.NoError(t, err)
	assert.Contains(t, string(out), `"content":"x"`)

	out, err = patchLastMessageContent([]byte(`{"messages":[{"role":"user"}]}`), "y")
	require.NoError(t, err)
	assert.Contains(t, string(out), `"content":"y"`)
}
