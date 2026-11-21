package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/apiformat"
)

// of a MOCK Codex CLI — a client that behaves the way the real codex binary
// behaves with `[model_providers.yabanin] wire_api="responses"`: it probes
// GET /v1/models with the bearer key, then drives streamed tool-calling
// turns over POST /v1/responses with the stateless full-history resend the
// gateway mandates (store=false, no previous_response_id). The real binary
// stays an owner stand (compatibility.md records it as such).
//
// The mock doubles as the regression for the ratified D1+D2 surface: the
// gateway must announce dropped fields via X-Yabanin-Unsupported and refuse
// continuation ids on every path.

// mockCodexCLI is the client-side loop of Codex against the gateway: one
// tool-calling turn, local tool execution, then the stateless resend turn.
type mockCodexCLI struct {
	baseURL string
	apiKey  string
	model   string

	patched bytes.Buffer // the local workspace the apply_patch tool edits
}

// cliResult is one fully-consumed CLI HTTP exchange (the body is read and
// closed inside do; nothing open escapes the helper).
type cliResult struct {
	status int
	header http.Header
	body   []byte
}

// do performs one request the way the CLI HTTP layer would.
func (c *mockCodexCLI) do(method, path, contentType string, body io.Reader) (cliResult, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, c.baseURL+path, body)
	if err != nil {
		return cliResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return cliResult{}, err
	}
	defer resp.Body.Close()
	raw, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		return cliResult{}, rerr
	}
	return cliResult{status: resp.StatusCode, header: resp.Header, body: raw}, nil
}

// checkModels mirrors codex startup: the configured provider must accept the
// key and list the model before any turn is attempted.
func (c *mockCodexCLI) checkModels(t *testing.T) {
	t.Helper()
	res, err := c.do(http.MethodGet, "/v1/models", "", nil)
	if err != nil {
		t.Fatalf("models probe: %v", err)
	}
	if res.status != http.StatusOK {
		t.Fatalf("models probe status %d: %s", res.status, res.body)
	}
	var doc struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res.body, &doc); err != nil {
		t.Fatalf("models body: %v", err)
	}
	found := false
	for _, m := range doc.Data {
		if m.ID == c.model {
			found = true
		}
	}
	if !found {
		t.Fatalf("model %q not listed in /v1/models: %s", c.model, res.body)
	}
}

// turn posts one /v1/responses request (stream=true, store=false — the
// stateless contract) and returns the final SSE events plus every response
// header, so the test can pin the unsupported-features indication.
func (c *mockCodexCLI) turn(t *testing.T, body string) ([]apiformat.SSEEvent, http.Header) {
	t.Helper()
	res, err := c.do(http.MethodPost, "/v1/responses", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("turn: %v", err)
	}
	if res.status != http.StatusOK {
		t.Fatalf("turn status %d: %s", res.status, res.body)
	}
	events := apiformat.ParseSSE(res.body)
	if err := apiformat.ValidateResponsesStream(events); err != nil {
		t.Fatalf("invalid responses stream: %v\n%s", err, res.body)
	}
	return events, res.header
}

func (c *mockCodexCLI) finalResponse(t *testing.T, events []apiformat.SSEEvent) map[string]any {
	t.Helper()
	data := events[len(events)-1].Data
	var doc struct {
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal([]byte(data), &doc); err != nil {
		t.Fatalf("completed event: %v (%s)", err, data)
	}
	var resp map[string]any
	if err := json.Unmarshal(doc.Response, &resp); err != nil {
		t.Fatalf("response object: %v (%s)", err, doc.Response)
	}
	return resp
}

func TestResponses_CodexCLI_MockE2E(t *testing.T) {
	const patch = "*** Begin Patch\n*** Add File: hello.txt\n+patched by codex\n*** End Patch"

	// The upstream stands in for any OpenAI-compatible chat provider: turn 1
	// (no tool message in history) answers with the apply_patch tool call;
	// turn 2 (tool output present) answers with the final text.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_, _ = raw, r
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		if !strings.Contains(string(raw), `"role":"tool"`) {
			_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_patch\",\"type\":\"function\",\"function\":{\"name\":\"apply_patch\",\"arguments\":\"\"}}]}}]}\n\n")
			flusher.Flush()
			_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":"+jsonString(patch)+"}}]}}]}\n\n")
			flusher.Flush()
			_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"finish_reason\":\"tool_calls\"}]}\n\n")
			flusher.Flush()
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
			return
		}
		_, _ = io.WriteString(w, "data: {\"id\":\"c2\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"patch applied\"}}]}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "data: {\"id\":\"c2\",\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}]}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()

	gw := responsesTestGateway(t, upstream.URL)
	// The discovery probe must see the model the CLI is configured for.
	gw.models = staticModelLister{entry: modelEntry{
		ID: "gpt-5-codex", DisplayName: "gpt-5-codex", Provider: "openai", CreatedAt: time.Now().UTC(),
	}}
	router := chi.NewRouter()
	gw.routes(router)
	gwServer := httptest.NewServer(router)
	defer gwServer.Close()

	cli := &mockCodexCLI{baseURL: gwServer.URL, apiKey: "test-key", model: "gpt-5-codex"}

	// Startup: the configured provider must accept the key and list models.
	cli.checkModels(t)

	tools := `[{"type":"function","name":"shell","description":"Run a command","parameters":{"type":"object","properties":{}}},{"type":"custom","name":"apply_patch","description":"Patch","format":{"type":"grammar","syntax":"lark","definition":"start: WORD"}}]`

	// Turn 1 — streamed tool-calling turn, stateless contract (store=false,
	// no previous_response_id), reasoning.effort set so the ratified D2
	// header must appear.
	turn1 := `{"model":"` + cli.model + `","instructions":"You are Codex.","input":[` +
		`{"type":"message","role":"user","content":"Patch hello.txt"}],` +
		`"tools":` + tools + `,"parallel_tool_calls":false,` +
		`"reasoning":{"effort":"low","summary":"auto"},"store":false,"stream":true}`
	events1, hdr1 := cli.turn(t, turn1)
	if got := hdr1.Get("X-Yabanin-Unsupported"); !strings.Contains(got, "reasoning") {
		t.Fatalf("D2: reasoning drop not announced, header %q", got)
	}
	resp1 := cli.finalResponse(t, events1)
	output1, _ := resp1["output"].([]any)
	var callID, callInput string
	for _, item := range output1 {
		m, _ := item.(map[string]any)
		if m["type"] == "custom_tool_call" && m["name"] == "apply_patch" {
			callID, _ = m["call_id"].(string)
			callInput, _ = m["input"].(string)
		}
	}
	if callID == "" || callInput != patch {
		t.Fatalf("turn1 output %#v", output1)
	}

	// Local tool execution (the real CLI writes the workspace file).
	cli.patched.WriteString(callInput)

	// Turn 2 — the stateless full-history resend D1 mandates: the whole
	// conversation rides input[] again; no continuation id exists.
	turn2 := `{"model":"` + cli.model + `","instructions":"You are Codex.","input":[` +
		`{"type":"message","role":"user","content":"Patch hello.txt"},` +
		`{"type":"custom_tool_call","call_id":"` + callID + `","name":"apply_patch","input":` + jsonString(callInput) + `},` +
		`{"type":"custom_tool_call_output","call_id":"` + callID + `","output":"done"}` +
		`],"tools":` + tools + `,"store":false,"stream":true}`
	events2, _ := cli.turn(t, turn2)
	resp2 := cli.finalResponse(t, events2)
	output2, _ := resp2["output"].([]any)
	var text string
	for _, item := range output2 {
		m, _ := item.(map[string]any)
		if m["type"] == "message" {
			for _, c := range m["content"].([]any) {
				cm, _ := c.(map[string]any)
				if cm["type"] == "output_text" {
					text, _ = cm["text"].(string)
				}
			}
		}
	}
	if text != "patch applied" {
		t.Fatalf("turn2 final text %q\n%#v", text, output2)
	}
	if cli.patched.String() != patch {
		t.Fatalf("local workspace not patched: %q", cli.patched.String())
	}

	// The stateless contract the client relies on is enforced by the
	// gateway on both routes: a continuation id is refused (uniform D1).
	prevID := `{"model":"` + cli.model + `","input":"Continue","previous_response_id":"resp_x","store":false,"stream":false}`
	res, err := cli.do(http.MethodPost, "/v1/responses", "application/json", strings.NewReader(prevID))
	if err != nil {
		t.Fatalf("prev-id probe: %v", err)
	}
	if res.status != http.StatusBadRequest || !strings.Contains(string(res.body), "previous_response_not_supported") {
		t.Fatalf("prev-id probe status %d: %s", res.status, res.body)
	}
}

// jsonString marshals s as a JSON string literal (test helper for embedding
// patch text inside SSE frames and request bodies).
func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// TestResponses_CodexCLI_MockE2E_ReasoningResendAndUsage drives the
// supported stateless scenario the real Codex CLI produces once reasoning
// items are part of the transcript: turn 2 resends the full history again —
// user turn, the model's reasoning item (with its rs_ item id), the
// custom tool call and its output. The gateway must reconstruct the turn
// from content only (the reasoning item id never reaches the upstream —
// no false history restoration keyed by item identity), surface the
// upstream usage in the final envelope, and disclose the stateless
// downgrade in the envelope itself (previous_response_id null, store
// false). The response id the gateway minted in turn 1 must not work as a
// continuation key afterwards.
func TestResponses_CodexCLI_MockE2E_ReasoningResendAndUsage(t *testing.T) {
	const reasoningID = "rs_9d2f31c0ffee"

	var turn2Chat atomic.Pointer[string]
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), `"role":"tool"`) {
			captured := string(raw)
			turn2Chat.Store(&captured)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		if !strings.Contains(string(raw), `"role":"tool"`) {
			_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"model\":\"gpt-5-codex\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Patching.\"}}]}\n\n")
			_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18}}\n\n")
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
			flusher.Flush()
			return
		}
		_, _ = io.WriteString(w, "data: {\"id\":\"c2\",\"model\":\"gpt-5-codex\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"patch applied\"}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"id\":\"c2\",\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":41,\"completion_tokens\":3,\"total_tokens\":44,\"prompt_tokens_details\":{\"cached_tokens\":9}}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()

	gw := responsesTestGateway(t, upstream.URL)
	gw.models = staticModelLister{entry: modelEntry{
		ID: "gpt-5-codex", DisplayName: "gpt-5-codex", Provider: "openai", CreatedAt: time.Now().UTC(),
	}}
	router := chi.NewRouter()
	gw.routes(router)
	gwServer := httptest.NewServer(router)
	defer gwServer.Close()

	cli := &mockCodexCLI{baseURL: gwServer.URL, apiKey: "test-key", model: "gpt-5-codex"}
	cli.checkModels(t)

	tools := `[{"type":"custom","name":"apply_patch","description":"Patch","format":{"type":"grammar","syntax":"lark","definition":"start: WORD"}}]`

	// Turn 1 — plain streamed turn; the envelope the client receives pins
	// the stateless downgrade disclosure and carries the upstream usage.
	turn1 := `{"model":"` + cli.model + `","instructions":"You are Codex.","input":[` +
		`{"type":"message","role":"user","content":"Patch hello.txt"}],` +
		`"tools":` + tools + `,"store":false,"stream":true}`
	events1, _ := cli.turn(t, turn1)
	resp1 := cli.finalResponse(t, events1)
	raw1, _ := json.Marshal(resp1)
	var envelope1 struct {
		PreviousResponseID json.RawMessage `json:"previous_response_id"`
		Store              *bool           `json:"store"`
		Usage              *struct {
			InputTokens  float64 `json:"input_tokens"`
			OutputTokens float64 `json:"output_tokens"`
			TotalTokens  float64 `json:"total_tokens"`
			InputDetails *struct {
				CachedTokens float64 `json:"cached_tokens"`
			} `json:"input_tokens_details"`
			OutputDetails *struct {
				ReasoningTokens float64 `json:"reasoning_tokens"`
			} `json:"output_tokens_details"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw1, &envelope1); err != nil {
		t.Fatalf("turn1 envelope: %v\n%s", err, raw1)
	}
	if len(envelope1.PreviousResponseID) == 0 || string(envelope1.PreviousResponseID) != "null" {
		t.Fatalf("envelope must disclose previous_response_id null, got %s", raw1)
	}
	if envelope1.Store == nil || *envelope1.Store {
		t.Fatalf("envelope must disclose store false, got %s", raw1)
	}
	if envelope1.Usage == nil || envelope1.Usage.InputTokens != 11 || envelope1.Usage.OutputTokens != 7 || envelope1.Usage.TotalTokens != 18 {
		t.Fatalf("turn1 usage not surfaced: %s", raw1)
	}
	respID, _ := resp1["id"].(string)
	if !strings.HasPrefix(respID, "resp_") {
		t.Fatalf("turn1 response id %#v", resp1["id"])
	}

	// Turn 2 — stateless full-history resend including the reasoning item.
	turn2 := `{"model":"` + cli.model + `","instructions":"You are Codex.","input":[` +
		`{"type":"message","role":"user","content":"Patch hello.txt"},` +
		`{"type":"reasoning","id":"` + reasoningID + `","summary":[{"type":"summary_text","text":"weighed patch scope"}],"encrypted_content":"ENC-7f3a"},` +
		`{"type":"custom_tool_call","id":"ctc_0a1b2c","call_id":"call_patch","name":"apply_patch","input":"*** Begin Patch"},` +
		`{"type":"custom_tool_call_output","call_id":"call_patch","output":"done"}],` +
		`"tools":` + tools + `,"store":false,"stream":true}`
	events2, _ := cli.turn(t, turn2)
	resp2 := cli.finalResponse(t, events2)
	output2, _ := resp2["output"].([]any)
	var text string
	for _, item := range output2 {
		m, _ := item.(map[string]any)
		if m["type"] == "message" {
			for _, c := range m["content"].([]any) {
				cm, _ := c.(map[string]any)
				if cm["type"] == "output_text" {
					text, _ = cm["text"].(string)
				}
			}
		}
	}
	if text != "patch applied" {
		t.Fatalf("turn2 final text %q\n%#v", text, output2)
	}
	raw2, _ := json.Marshal(resp2)
	var envelope2 struct {
		Usage *struct {
			InputTokens  float64 `json:"input_tokens"`
			OutputTokens float64 `json:"output_tokens"`
			TotalTokens  float64 `json:"total_tokens"`
			InputDetails *struct {
				CachedTokens float64 `json:"cached_tokens"`
			} `json:"input_tokens_details"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw2, &envelope2); err != nil {
		t.Fatalf("turn2 envelope: %v\n%s", err, raw2)
	}
	if envelope2.Usage == nil || envelope2.Usage.InputTokens != 41 || envelope2.Usage.OutputTokens != 3 || envelope2.Usage.TotalTokens != 44 {
		t.Fatalf("turn2 usage not surfaced: %s", raw2)
	}
	if envelope2.Usage.InputDetails == nil || envelope2.Usage.InputDetails.CachedTokens != 9 {
		t.Fatalf("turn2 cached-token detail lost: %s", raw2)
	}

	// The reasoning item identity never rides the translated chat request.
	chat2 := turn2Chat.Load()
	if chat2 == nil || *chat2 == "" {
		t.Fatal("upstream never saw the turn-2 chat body")
	}
	captured := *chat2
	if strings.Contains(captured, reasoningID) || strings.Contains(captured, "ENC-7f3a") || strings.Contains(captured, "ctc_0a1b2c") || strings.Contains(captured, "weighed patch scope") {
		t.Fatalf("item identity leaked into the upstream request:\n%s", captured)
	}
	if !strings.Contains(captured, "call_patch") {
		t.Fatalf("tool call pairing lost:\n%s", captured)
	}

	// The minted turn-1 response id is not a conversation continuation key:
	// sending it back is refused, never silently turned into a fresh turn.
	res, err := cli.do(http.MethodPost, "/v1/responses", "application/json",
		strings.NewReader(`{"model":"`+cli.model+`","input":"Continue","previous_response_id":"`+respID+`","store":false,"stream":false}`))
	if err != nil {
		t.Fatalf("minted-id probe: %v", err)
	}
	if res.status != http.StatusBadRequest || !strings.Contains(string(res.body), "previous_response_not_supported") {
		t.Fatalf("minted-id probe status %d: %s", res.status, res.body)
	}
}
