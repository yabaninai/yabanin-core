//go:build integration

package accounting

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// refusalFamily is one client-facing dispatch family: how to issue one
// authenticated request of that family, the upstream protocol path its
// healthy traffic must arrive on (proving WHICH dispatch family served
// it, e.g. native Responses rather than the chat-adapted translation),
// and the independently defined protocol validity check for a healthy
// reply. The fault windows reuse the whole-ledger and storage oracles.
type refusalFamily struct {
	name     string // case-log family name
	request  func(t *testing.T, s *stand, rid string) (status int, body string, err error)
	upstream string                                    // fixture arrival path a healthy control must use
	validate func(t *testing.T, s *stand, body string) // protocol contract of the healthy reply
}

// TestAccountingRefusalFamiliesBeforeDispatch extends the independent
// pre-dispatch refusal proof beyond buffered chat: every synchronous
// client-facing dispatch family the stand's provider serves — chat
// (buffered and SSE), embeddings, NATIVE Responses (buffered and SSE;
// the gateway env lists the seeded openai-compat provider as a native
// Responses provider), legacy completions, moderations, rerank, images
// generations and realtime (both plain-HTTP JSON/SSE per current
// implementation, see below) — must obey the same owner-approved
// contract when the durable request-accounting write path is broken:
// refuse with the documented 503 history_unavailable envelope, contact
// no provider (whole-ledger zero, no first attempt, no retry, no
// fallback hop), record no accounting of any kind, never contact the
// provider late under the refused id after recovery, and resume normal
// service per family with healthy route-specific controls before and
// after each fault window.
//
// Healthy family controls are strong, not formal: HTTP 200, an
// independently validated protocol reply (composed events/outcome and
// exact known usage — never substring spot checks), exactly one
// whole-ledger arrival/dispatch/receipt on the family's OWN upstream
// path, retained evidence, a durable request_logs row AND, on
// durable-accounting builds, a durable confirmed admission plus a
// matching request_terminal_facts row (request_logs alone can be
// legacy dual-write). Wallet-debit economics per family stay in the
// accounting suite (chat carries the exact -32 micro-USD proof); here
// the shared refusal-relevant fact is the durable start, which is
// family-independent.
//
// Classification of the remaining direct surfaces (verified against
// current implementation source, not assumed):
//
//   - /v1/realtime: a plain HTTP POST SSE family (realtime_endpoint.go
//     posts the raw body to /v1/realtime with stream semantics and
//     relays the session byte-honestly; usage comes from the last
//     usage-bearing event, top-level usage or nested response.usage).
//     WebSocket transport is EXPLICITLY refused pre-admission with 400
//     unsupported_feature (realtime_endpoint.go isWebSocketUpgrade) —
//     asserted live below as a negative discriminator with zero
//     provider contact. Realtime is therefore a covered family, not an
//     omission.
//   - /v1/images/generations: a normal JSON family — request is
//     {model, prompt, n?}; the reply carries b64_json/URL data inside
//     JSON and an optional usage block (images_endpoint.go). Covered
//     as a family below.
//   - /v1/messages: on a non-anthropic provider the gateway translates
//     via AnthropicToChat and re-enters the chat completions dispatch
//     (messages_endpoint.go) — proven live below by the arrival-path
//     probe [/v1/chat/completions]. The native branch requires a
//     registry model whose provider is "anthropic"
//     (messages_native.go); the harness seeds exactly one openai-compat
//     provider, so the native Anthropic dispatch family is a
//     provider-configuration omission, not a protocol one.
//   - /v1/messages/count_tokens: admits with SkipSpendChecks and never
//     reserves; on a non-anthropic provider it never contacts any
//     upstream — it answers 200 with a local ceil(bytes/4) estimate and
//     X-Yabanin-Estimated: true (messages_count.go). Proven live below:
//     it is a free utility surface, not a paid dispatch family on this
//     provider; the anthropic passthrough variant shares that
//     provider-configuration constraint.
//   - /v1/audio/speech and /v1/audio/transcriptions: binary response
//     and multipart request codecs respectively (gateway.go route
//     table); the JSON fixture would need non-JSON codecs before the
//     refusal window could be asserted. Omitted for codec scope, not
//     for refusal semantics.
//   - /v1/files and /v1/batches: multipart upload plus asynchronous
//     job lifecycle (files_endpoint.go spools multipart parts; batches
//     materialize later), not one synchronous dispatch whose
//     pre-dispatch refusal a single window could assert.
//
// The fault, its verification and its restoration are the original
// refusal case's real-infrastructure trigger set, unchanged. All
// requests below share the stand, one seeded model, one provider and
// one tenant credential set. Real-stand full-suite execution happens
// under the heavy lease; this case keeps the standalone baseline and
// earlier results untouched.
func TestAccountingRefusalFamiliesBeforeDispatch(t *testing.T) {
	s := startStandWithGatewayEnv(t, "YABANIN_RESPONSES_NATIVE_PROVIDERS=openai-compat")

	// Classification probes first: they are harness/route evidence, not
	// refusal assertions, so they must execute on every build (a baseline
	// defect in the sweep below must not leave them unexercised).
	s.classifyRemainingSurfaces(t)

	var targetRids []string
	for _, fam := range refusalFamilies() {
		fam := fam
		t.Run(fam.name, func(t *testing.T) {
			s.controlFamily(t, fam, "pre")

			s.armAccountingWriteOutage(t)
			defer s.disarmAccountingWriteOutage(t)

			before := s.fixture.Snapshot()
			rid := familyRequestID(s, "tgt-refusal-", fam.name)
			targetRids = append(targetRids, rid)
			status, body, err := fam.request(t, s, rid)
			s.requireRefusalEnvelope(t, fam.name, rid, status, body, err)
			s.requireZeroContact(t, fam.name, rid, before)
			s.disarmAccountingWriteOutage(t)

			s.controlFamily(t, fam, "post")
		})
	}

	s.requireNoLateContactOrRetroBilling(t, targetRids)
}

// refusalFamilies enumerates the synchronous dispatch families with
// per-protocol request builders and validators, kept as small named
// helpers (maintainability: bounded function bodies, no mega-closure).
func refusalFamilies() []refusalFamily {
	return []refusalFamily{
		{name: "chat buffered", request: requestChatBuffered, upstream: "/v1/chat/completions", validate: validateChatReply},
		{name: "chat sse", request: requestChatSSE, upstream: "/v1/chat/completions", validate: validateChatSSE},
		{name: "embeddings", request: requestEmbeddings, upstream: "/v1/embeddings", validate: validateEmbeddingsReply},
		{name: "responses native buffered", request: requestResponsesBuffered, upstream: "/v1/responses", validate: validateResponsesReply},
		{name: "responses native sse", request: requestResponsesSSE, upstream: "/v1/responses", validate: validateResponsesSSE},
		{name: "completions legacy", request: requestCompletions, upstream: "/v1/completions", validate: validateCompletionsReply},
		{name: "moderations", request: requestModerations, upstream: "/v1/moderations", validate: validateModerationsReply},
		{name: "rerank", request: requestRerank, upstream: "/v1/rerank", validate: validateRerankReply},
		{name: "images generation", request: requestImages, upstream: "/v1/images/generations", validate: validateImagesReply},
		{name: "realtime sse", request: requestRealtime, upstream: "/v1/realtime", validate: validateRealtimeSSE},
	}
}

// familyRequestID derives a run-namespaced request id from a phase and a
// family name.
func familyRequestID(s *stand, phase, family string) string {
	return s.reqPrefix + phase + strings.NewReplacer(" ", "-", "/", "-").Replace(family)
}

// --- per-family request builders -------------------------------------

func requestChatBuffered(t *testing.T, s *stand, rid string) (int, string, error) {
	return s.chat(t, rid, 45*time.Second)
}

func requestChatSSE(t *testing.T, s *stand, rid string) (int, string, error) {
	return s.chatFull(t, rid, 45*time.Second, chatOptions{stream: true})
}

func requestEmbeddings(t *testing.T, s *stand, rid string) (int, string, error) {
	payload := fmt.Sprintf(`{"model":%q,"input":"accounting acceptance embeddings probe"}`, s.model)
	return httpPostJSON(45*time.Second, s.gatewayURL+"/v1/embeddings", s.apiKey, rid, payload)
}

func requestResponsesBuffered(t *testing.T, s *stand, rid string) (int, string, error) {
	payload := fmt.Sprintf(`{"model":%q,"input":"accounting acceptance responses probe"}`, s.model)
	return httpPostJSON(45*time.Second, s.gatewayURL+"/v1/responses", s.apiKey, rid, payload)
}

func requestResponsesSSE(t *testing.T, s *stand, rid string) (int, string, error) {
	payload := fmt.Sprintf(`{"model":%q,"input":"accounting acceptance responses probe","stream":true}`, s.model)
	return httpPostJSON(45*time.Second, s.gatewayURL+"/v1/responses", s.apiKey, rid, payload)
}

func requestCompletions(t *testing.T, s *stand, rid string) (int, string, error) {
	payload := fmt.Sprintf(`{"model":%q,"prompt":"accounting acceptance completions probe"}`, s.model)
	return httpPostJSON(45*time.Second, s.gatewayURL+"/v1/completions", s.apiKey, rid, payload)
}

func requestModerations(t *testing.T, s *stand, rid string) (int, string, error) {
	payload := fmt.Sprintf(`{"model":%q,"input":"accounting acceptance moderations probe"}`, s.model)
	return httpPostJSON(45*time.Second, s.gatewayURL+"/v1/moderations", s.apiKey, rid, payload)
}

func requestRerank(t *testing.T, s *stand, rid string) (int, string, error) {
	payload := fmt.Sprintf(`{"model":%q,"query":"accounting acceptance","documents":["probe one","probe two"]}`, s.model)
	return httpPostJSON(45*time.Second, s.gatewayURL+"/v1/rerank", s.apiKey, rid, payload)
}

func requestImages(t *testing.T, s *stand, rid string) (int, string, error) {
	payload := fmt.Sprintf(`{"model":%q,"prompt":"accounting acceptance images probe","n":1}`, s.model)
	return httpPostJSON(45*time.Second, s.gatewayURL+"/v1/images/generations", s.apiKey, rid, payload)
}

func requestRealtime(t *testing.T, s *stand, rid string) (int, string, error) {
	payload := fmt.Sprintf(`{"model":%q,"input":"accounting acceptance realtime probe"}`, s.model)
	return httpPostJSON(45*time.Second, s.gatewayURL+"/v1/realtime", s.apiKey, rid, payload)
}

// --- SSE parsing (client side) ----------------------------------------

// sseFrame is one parsed server-sent-event frame.
type sseFrame struct {
	Event string
	Data  string
}

// parseSSEFrames parses an accumulated SSE body into its frames so
// validators can assert the composed event sequence, per-frame payloads
// and usage instead of substring spot checks. Data lines are joined
// with newlines per the SSE spec.
func parseSSEFrames(body string) []sseFrame {
	var frames []sseFrame
	var event string
	var data []string
	flush := func() {
		if event != "" || len(data) > 0 {
			frames = append(frames, sseFrame{Event: event, Data: strings.Join(data, "\n")})
		}
		event, data = "", nil
	}
	for _, line := range strings.Split(body, "\n") {
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data = append(data, strings.TrimPrefix(line, "data: "))
		}
	}
	flush()
	return frames
}

// requireNoDONESentinel rejects chat-style stream termination in
// protocols whose native streams do not carry [DONE]; its presence
// proves the chat-adapted path answered instead.
func requireNoDONESentinel(t *testing.T, family string, frames []sseFrame) {
	t.Helper()
	for _, fr := range frames {
		if fr.Data == "[DONE]" {
			t.Fatalf("families: %s carries a chat-style [DONE] sentinel — the ADAPTED chat path answered, not this family", family)
		}
	}
}

// requireEventSequence asserts the exact ordered event names of a
// parsed stream.
func requireEventSequence(t *testing.T, family string, frames []sseFrame, want []string) {
	t.Helper()
	var got []string
	for _, fr := range frames {
		got = append(got, fr.Event)
	}
	if len(got) != len(want) || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("families: %s event sequence = %v, want %v", family, got, want)
	}
}

// --- per-family healthy-reply validators ------------------------------

// validateChatReply asserts the buffered chat.completion contract.
func validateChatReply(t *testing.T, s *stand, body string) {
	var doc struct {
		Object  string `json:"object"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("families: chat control body is not chat.completion JSON: %v (body %s)", err, clip(body))
	}
	if doc.Object != "chat.completion" || len(doc.Choices) != 1 ||
		doc.Choices[0].FinishReason != "stop" ||
		doc.Choices[0].Message.Role != "assistant" || doc.Choices[0].Message.Content != fixtureAssistantContent {
		t.Fatalf("families: chat control reply malformed (body %s)", clip(body))
	}
	if doc.Usage.PromptTokens != fixturePromptTokens || doc.Usage.CompletionTokens != fixtureCompletionTokens {
		t.Fatalf("families: chat control usage = %d/%d, want %d/%d", doc.Usage.PromptTokens, doc.Usage.CompletionTokens, fixturePromptTokens, fixtureCompletionTokens)
	}
}

// chatChunk is one parsed chat streaming frame.
type chatChunk struct {
	Choices []struct {
		FinishReason *string `json:"finish_reason"`
		Delta        struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"delta"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// validateChatSSE asserts the composed chat stream: role frame, content
// delta frame, terminal finish frame carrying the known usage, then the
// [DONE] sentinel — parsed, in order, with exact usage.
func validateChatSSE(t *testing.T, s *stand, body string) {
	frames := parseSSEFrames(body)
	if len(frames) != 4 {
		t.Fatalf("families: chat sse control has %d frames, want 4 (role, content, finish+usage, [DONE]) (body %s)", len(frames), clip(body))
	}
	var role, content, finish chatChunk
	if err := json.Unmarshal([]byte(frames[0].Data), &role); err != nil {
		t.Fatalf("families: chat sse frame 0 is not a chunk: %v (body %s)", err, clip(body))
	}
	if err := json.Unmarshal([]byte(frames[1].Data), &content); err != nil {
		t.Fatalf("families: chat sse frame 1 is not a chunk: %v (body %s)", err, clip(body))
	}
	if err := json.Unmarshal([]byte(frames[2].Data), &finish); err != nil {
		t.Fatalf("families: chat sse frame 2 is not a chunk: %v (body %s)", err, clip(body))
	}
	if len(role.Choices) != 1 || role.Choices[0].Delta.Role != "assistant" || role.Choices[0].Delta.Content != "" {
		t.Fatalf("families: chat sse frame 0 is not the role frame (body %s)", clip(body))
	}
	if len(content.Choices) != 1 || content.Choices[0].Delta.Content != fixtureAssistantContent {
		t.Fatalf("families: chat sse frame 1 does not carry the fixture content (body %s)", clip(body))
	}
	if len(finish.Choices) != 1 || finish.Choices[0].FinishReason == nil || *finish.Choices[0].FinishReason != "stop" {
		t.Fatalf("families: chat sse frame 2 is not the finish frame (body %s)", clip(body))
	}
	if finish.Usage == nil || finish.Usage.PromptTokens != fixturePromptTokens || finish.Usage.CompletionTokens != fixtureCompletionTokens {
		t.Fatalf("families: chat sse finish frame usage malformed (body %s)", clip(body))
	}
	if frames[3].Data != "[DONE]" {
		t.Fatalf("families: chat sse terminal frame %q, want [DONE] (body %s)", frames[3].Data, clip(body))
	}
}

// validateEmbeddingsReply asserts the embeddings list contract.
func validateEmbeddingsReply(t *testing.T, s *stand, body string) {
	var doc struct {
		Object string `json:"object"`
		Data   []struct {
			Object    string    `json:"object"`
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
		Usage struct {
			PromptTokens int `json:"prompt_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("families: embeddings control body is not embeddings JSON: %v (body %s)", err, clip(body))
	}
	if doc.Object != "list" || len(doc.Data) != 2 {
		t.Fatalf("families: embeddings control envelope malformed (body %s)", clip(body))
	}
	for i, d := range doc.Data {
		if d.Object != "embedding" || len(d.Embedding) != fixtureEmbedDims {
			t.Fatalf("families: embeddings control data[%d] malformed (%d dims, want %d)", i, len(d.Embedding), fixtureEmbedDims)
		}
	}
	if doc.Usage.PromptTokens != fixturePromptTokens {
		t.Fatalf("families: embeddings control usage = %d, want %d", doc.Usage.PromptTokens, fixturePromptTokens)
	}
}

// responsesPayload is the parsed payload of one native Responses event.
type responsesPayload struct {
	Type     string `json:"type"`
	Delta    string `json:"delta"`
	Response *struct {
		Status string `json:"status"`
		Usage  *struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	} `json:"response"`
}

// validateResponsesReply asserts the buffered native response object.
func validateResponsesReply(t *testing.T, s *stand, body string) {
	var doc struct {
		Object string `json:"object"`
		Status string `json:"status"`
		Output []struct {
			Type    string `json:"type"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("families: responses control body is not a response object: %v (body %s)", err, clip(body))
	}
	if doc.Object != "response" || doc.Status != "completed" || len(doc.Output) != 1 || len(doc.Output[0].Content) != 1 {
		t.Fatalf("families: responses control envelope malformed (body %s)", clip(body))
	}
	if doc.Output[0].Content[0].Type != "output_text" || doc.Output[0].Content[0].Text != fixtureAssistantContent {
		t.Fatalf("families: responses control output text malformed (body %s)", clip(body))
	}
	if doc.Usage.InputTokens != fixturePromptTokens || doc.Usage.OutputTokens != fixtureCompletionTokens {
		t.Fatalf("families: responses control usage = %d/%d, want %d/%d", doc.Usage.InputTokens, doc.Usage.OutputTokens, fixturePromptTokens, fixtureCompletionTokens)
	}
}

// validateResponsesSSE asserts the composed native Responses stream:
// created (in_progress), one output_text.delta carrying the fixture
// content, completed with the known usage — and no [DONE] sentinel,
// whose presence would prove the chat-adapted path answered.
func validateResponsesSSE(t *testing.T, s *stand, body string) {
	frames := parseSSEFrames(body)
	requireEventSequence(t, "responses sse control", frames,
		[]string{"response.created", "response.output_text.delta", "response.completed"})
	requireNoDONESentinel(t, "responses sse control", frames)
	var created, delta, completed responsesPayload
	decode := func(fr sseFrame, dst *responsesPayload, what string) {
		if err := json.Unmarshal([]byte(fr.Data), dst); err != nil {
			t.Fatalf("families: %s payload is not JSON: %v (body %s)", what, err, clip(body))
		}
	}
	decode(frames[0], &created, "responses sse created")
	decode(frames[1], &delta, "responses sse delta")
	decode(frames[2], &completed, "responses sse completed")
	if created.Response == nil || created.Response.Status != "in_progress" {
		t.Fatalf("families: responses sse created frame malformed (body %s)", clip(body))
	}
	if delta.Delta != fixtureAssistantContent {
		t.Fatalf("families: responses sse delta frame does not carry the fixture content (body %s)", clip(body))
	}
	if completed.Response == nil || completed.Response.Status != "completed" ||
		completed.Response.Usage == nil ||
		completed.Response.Usage.InputTokens != fixturePromptTokens || completed.Response.Usage.OutputTokens != fixtureCompletionTokens {
		t.Fatalf("families: responses sse completed frame usage malformed (body %s)", clip(body))
	}
}

// validateCompletionsReply asserts the legacy text_completion contract.
func validateCompletionsReply(t *testing.T, s *stand, body string) {
	var doc struct {
		Object  string `json:"object"`
		Choices []struct {
			Text         string  `json:"text"`
			FinishReason *string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("families: completions control body is not text_completion JSON: %v (body %s)", err, clip(body))
	}
	if doc.Object != "text_completion" || len(doc.Choices) != 1 ||
		doc.Choices[0].Text != fixtureAssistantContent || doc.Choices[0].FinishReason == nil || *doc.Choices[0].FinishReason != "stop" {
		t.Fatalf("families: completions control reply malformed (body %s)", clip(body))
	}
	if doc.Usage.PromptTokens != fixturePromptTokens || doc.Usage.CompletionTokens != fixtureCompletionTokens {
		t.Fatalf("families: completions control usage = %d/%d, want %d/%d", doc.Usage.PromptTokens, doc.Usage.CompletionTokens, fixturePromptTokens, fixtureCompletionTokens)
	}
}

// validateModerationsReply asserts the moderations contract.
func validateModerationsReply(t *testing.T, s *stand, body string) {
	var doc struct {
		Results []struct {
			Flagged bool `json:"flagged"`
			Index   int  `json:"index"`
		} `json:"results"`
		Usage struct {
			PromptTokens int `json:"prompt_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("families: moderations control body is not moderations JSON: %v (body %s)", err, clip(body))
	}
	if len(doc.Results) != 2 || !doc.Results[0].Flagged == false || doc.Results[0].Index != 0 {
		t.Fatalf("families: moderations control results malformed (body %s)", clip(body))
	}
	if doc.Usage.PromptTokens != fixturePromptTokens {
		t.Fatalf("families: moderations control usage = %d, want %d", doc.Usage.PromptTokens, fixturePromptTokens)
	}
}

// validateRerankReply asserts the rerank contract.
func validateRerankReply(t *testing.T, s *stand, body string) {
	var doc struct {
		Results []struct {
			Index          int     `json:"index"`
			RelevanceScore float64 `json:"relevance_score"`
		} `json:"results"`
		Usage struct {
			PromptTokens int `json:"prompt_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("families: rerank control body is not rerank JSON: %v (body %s)", err, clip(body))
	}
	if len(doc.Results) != 2 || doc.Results[0].Index != 0 ||
		doc.Results[0].RelevanceScore <= 0 || doc.Results[0].RelevanceScore > 1 ||
		doc.Results[1].RelevanceScore <= 0 || doc.Results[1].RelevanceScore > 1 {
		t.Fatalf("families: rerank control results malformed (body %s)", clip(body))
	}
	if doc.Usage.PromptTokens != fixturePromptTokens {
		t.Fatalf("families: rerank control usage = %d, want %d", doc.Usage.PromptTokens, fixturePromptTokens)
	}
}

// validateImagesReply asserts the images-generation contract: one
// decodable non-empty b64_json datum and the exact known usage block.
func validateImagesReply(t *testing.T, s *stand, body string) {
	var doc struct {
		Created int64 `json:"created"`
		Data    []struct {
			B64JSON string  `json:"b64_json"`
			URL     *string `json:"url"`
		} `json:"data"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
			TotalTokens  int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("families: images control body is not images JSON: %v (body %s)", err, clip(body))
	}
	if doc.Created <= 0 || len(doc.Data) != 1 {
		t.Fatalf("families: images control envelope malformed (body %s)", clip(body))
	}
	raw, err := base64.StdEncoding.DecodeString(doc.Data[0].B64JSON)
	if err != nil || len(raw) == 0 {
		t.Fatalf("families: images control b64_json does not decode to a non-empty payload (body %s)", clip(body))
	}
	if doc.Usage.InputTokens != fixturePromptTokens || doc.Usage.OutputTokens != fixtureCompletionTokens ||
		doc.Usage.TotalTokens != fixturePromptTokens+fixtureCompletionTokens {
		t.Fatalf("families: images control usage = %d/%d/%d, want %d/%d/%d",
			doc.Usage.InputTokens, doc.Usage.OutputTokens, doc.Usage.TotalTokens,
			fixturePromptTokens, fixtureCompletionTokens, fixturePromptTokens+fixtureCompletionTokens)
	}
}

// validateRealtimeSSE asserts the composed realtime session: created,
// one output_text.delta with the fixture content, terminal response.done
// whose NESTED response.usage carries the known tokens — the exact
// branch realtimeUsageFromEvent bills — and no [DONE] sentinel.
func validateRealtimeSSE(t *testing.T, s *stand, body string) {
	frames := parseSSEFrames(body)
	requireEventSequence(t, "realtime sse control", frames,
		[]string{"response.created", "response.output_text.delta", "response.done"})
	requireNoDONESentinel(t, "realtime sse control", frames)
	var created, delta, done responsesPayload
	decode := func(fr sseFrame, dst *responsesPayload, what string) {
		if err := json.Unmarshal([]byte(fr.Data), dst); err != nil {
			t.Fatalf("families: %s payload is not JSON: %v (body %s)", what, err, clip(body))
		}
	}
	decode(frames[0], &created, "realtime created")
	decode(frames[1], &delta, "realtime delta")
	decode(frames[2], &done, "realtime done")
	if created.Response == nil || created.Response.Status != "in_progress" {
		t.Fatalf("families: realtime created frame malformed (body %s)", clip(body))
	}
	if delta.Delta != fixtureAssistantContent {
		t.Fatalf("families: realtime delta frame does not carry the fixture content (body %s)", clip(body))
	}
	if done.Response == nil || done.Response.Status != "completed" ||
		done.Response.Usage == nil ||
		done.Response.Usage.InputTokens != fixturePromptTokens || done.Response.Usage.OutputTokens != fixtureCompletionTokens {
		t.Fatalf("families: realtime done frame nested usage malformed (body %s)", clip(body))
	}
}

// --- refusal contract and fault-window assertions ----------------------

// requireRefusalEnvelope asserts the documented client-visible refusal.
func (s *stand) requireRefusalEnvelope(t *testing.T, family, rid string, status int, body string, err error) {
	t.Helper()
	switch {
	case err != nil:
		t.Fatalf("product: refusal %s: client transport error %v — the request must be refused with the documented 503 history_unavailable contract, not dropped", family, err)
	case status != 503:
		t.Fatalf("product: refusal %s: client status %d, want 503 (body %s) — the family was denied or served for the wrong reason; the documented history_unavailable refusal is missing", family, status, clip(body))
	}
	code, ok := decodeErrorCode(body)
	if !ok {
		t.Fatalf("product: refusal %s: 503 body is not the documented structured error envelope (body %s)", family, clip(body))
	}
	if code != "history_unavailable" {
		t.Fatalf("product: refusal %s: 503 error.code %q, want history_unavailable (body %s)", family, code, clip(body))
	}
}

// requireZeroContact asserts the fault window touched neither the
// provider ledger nor any accounting surface for the refused request.
func (s *stand) requireZeroContact(t *testing.T, family, rid string, before fixtureTotals) {
	t.Helper()
	s.fixture.VerifyEvidence()
	if delta := s.fixture.Since(before); delta.arrivals != 0 || delta.dispatches != 0 || delta.receipts != 0 {
		t.Fatalf("product: refusal %s: whole-ledger provider contact during the outage arrivals/dispatches/receipts = %d/%d/%d, want 0/0/0 — the request must never be dispatched, retried or failed over",
			family, delta.arrivals, delta.dispatches, delta.receipts)
	}
	if n := s.oracleRequestLogCount(t, rid, s.oracleDB.orgID); n != 0 {
		t.Fatalf("product: refusal %s: %d request_logs row(s) exist for the refused request", family, n)
	}
	if c := s.oracleCreditTotals(t, rid, s.oracleDB.orgID); c.UsageRows+c.TopupRows != 0 {
		t.Fatalf("product: refusal %s: credit transactions exist for the refused request (%+v)", family, c)
	}
	if n := s.oracleSettlementJobs(t, rid, s.oracleDB.orgID); n != 0 {
		t.Fatalf("product: refusal %s: %d settlement job(s) exist for the refused request", family, n)
	}
	if n := s.oracleAdmissionRowCount(t, rid, s.oracleDB.orgID); n != 0 {
		t.Fatalf("product: refusal %s: %d admission row(s) exist for the refused request", family, n)
	}
}

// requireNoLateContactOrRetroBilling asserts, after all families
// recovered, that no refused id was ever dispatched to the provider and
// no accounting appeared retroactively for it.
func (s *stand) requireNoLateContactOrRetroBilling(t *testing.T, targetRids []string) {
	t.Helper()
	for _, rid := range targetRids {
		if a, d, r := s.fixture.Counts(rid); a != 0 || d != 0 || r != 0 {
			t.Fatalf("product: refusal families: late provider contact for refused %s: arrivals/dispatches/receipts = %d/%d/%d, want 0/0/0 — the provider must never be contacted under a refused id, even after recovery",
				rid, a, d, r)
		}
		if n := s.oracleRequestLogCount(t, rid, s.oracleDB.orgID); n != 0 {
			t.Fatalf("product: refusal families: %d request_logs row(s) appeared for refused %s after restoration", n, rid)
		}
		if c := s.oracleCreditTotals(t, rid, s.oracleDB.orgID); c.UsageRows != 0 {
			t.Fatalf("product: refusal families: %d usage transaction(s) appeared for refused %s after restoration", c.UsageRows, rid)
		}
	}
}

// --- surface classification probes -------------------------------------

// classifyRemainingSurfaces proves, live, the source-verified
// classification of the direct surfaces that are not standalone paid
// dispatch families on this stand's single openai-compat provider.
func (s *stand) classifyRemainingSurfaces(t *testing.T) {
	t.Helper()
	t.Run("classification", func(t *testing.T) {
		s.classifyMessagesAdapted(t)
		s.classifyCountTokensEstimator(t)
		s.classifyRealtimeWebSocketRefused(t)
	})
}

// classifyMessagesAdapted proves /v1/messages on a non-anthropic
// provider is the chat dispatch family behind the Anthropic client
// surface: an Anthropic message envelope answered by exactly one
// arrival on /v1/chat/completions.
func (s *stand) classifyMessagesAdapted(t *testing.T) {
	t.Helper()
	before := s.fixture.Snapshot()
	rid := familyRequestID(s, "cls-", "messages-adapted")
	payload := fmt.Sprintf(`{"model":%q,"max_tokens":16,"messages":[{"role":"user","content":"messages classification probe"}]}`, s.model)
	status, body, err := httpPostJSON(45*time.Second, s.gatewayURL+"/v1/messages", s.apiKey, rid, payload)
	if err != nil || status != httpOK {
		t.Fatalf("harness: messages classification probe failed (status=%d err=%v body=%s)", status, err, clip(body))
	}
	var doc struct {
		Type    string `json:"type"`
		Role    string `json:"role"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("harness: messages classification body is not an Anthropic message envelope: %v (body %s)", err, clip(body))
	}
	if doc.Type != "message" || doc.Role != "assistant" || len(doc.Content) != 1 ||
		doc.Content[0].Type != "text" || doc.Content[0].Text != fixtureAssistantContent {
		t.Fatalf("harness: messages classification envelope malformed (body %s)", clip(body))
	}
	if doc.Usage.InputTokens != fixturePromptTokens || doc.Usage.OutputTokens != fixtureCompletionTokens {
		t.Fatalf("harness: messages classification usage = %d/%d, want %d/%d", doc.Usage.InputTokens, doc.Usage.OutputTokens, fixturePromptTokens, fixtureCompletionTokens)
	}
	if delta := s.fixture.Since(before); delta.arrivals != 1 || delta.dispatches != 1 || delta.receipts != 1 {
		t.Fatalf("harness: messages classification whole-ledger delta = %d/%d/%d, want 1/1/1", delta.arrivals, delta.dispatches, delta.receipts)
	}
	if paths := s.fixture.ArrivalPaths(rid); len(paths) != 1 || paths[0] != "/v1/chat/completions" {
		t.Fatalf("harness: messages classification arrival path(s) %v, want [/v1/chat/completions] — the chat-adapted dispatch classification failed", paths)
	}
	t.Logf("harness: /v1/messages classified: Anthropic client surface over the chat dispatch family (request id %s)", rid)
}

// classifyCountTokensEstimator proves /v1/messages/count_tokens is a
// free utility surface on this provider: answered locally (no provider
// contact at all), no accounting rows, X-Yabanin-Estimated marker set.
func (s *stand) classifyCountTokensEstimator(t *testing.T) {
	t.Helper()
	before := s.fixture.Snapshot()
	rid := familyRequestID(s, "cls-", "count-tokens")
	payload := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"count tokens classification probe"}]}`, s.model)
	status, body, hdr, err := httpPostJSONFull(45*time.Second, s.gatewayURL+"/v1/messages/count_tokens", s.apiKey, rid, payload)
	if err != nil || status != httpOK {
		t.Fatalf("harness: count_tokens classification probe failed (status=%d err=%v body=%s)", status, err, clip(body))
	}
	var doc struct {
		InputTokens int `json:"input_tokens"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil || doc.InputTokens <= 0 {
		t.Fatalf("harness: count_tokens classification body is not a positive estimate (body %s)", clip(body))
	}
	if got := hdr.Get("X-Yabanin-Estimated"); got != "true" {
		t.Fatalf("harness: count_tokens classification X-Yabanin-Estimated = %q, want true — the local-estimator classification failed", got)
	}
	if delta := s.fixture.Since(before); delta.arrivals != 0 || delta.dispatches != 0 || delta.receipts != 0 {
		t.Fatalf("harness: count_tokens classification contacted the provider (%d/%d/%d), want 0/0/0 — on this provider the estimator must be local",
			delta.arrivals, delta.dispatches, delta.receipts)
	}
	if n := s.oracleRequestLogCount(t, rid, s.oracleDB.orgID); n != 0 {
		t.Fatalf("harness: count_tokens classification created %d request_logs row(s), want 0 — a free utility surface records no paid dispatch", n)
	}
	t.Logf("harness: /v1/messages/count_tokens classified: free local estimator, no provider contact, no accounting (request id %s, estimate %d)", rid, doc.InputTokens)
}

// classifyRealtimeWebSocketRefused proves the realtime WebSocket
// transport contract: refused pre-admission with 400
// unsupported_feature and zero provider contact.
func (s *stand) classifyRealtimeWebSocketRefused(t *testing.T) {
	t.Helper()
	before := s.fixture.Snapshot()
	rid := familyRequestID(s, "cls-", "realtime-ws")
	payload := fmt.Sprintf(`{"model":%q,"input":"realtime ws probe"}`, s.model)
	status, body, _, err := httpPostJSONFull(45*time.Second, s.gatewayURL+"/v1/realtime", s.apiKey, rid, payload,
		map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"})
	if err != nil || status != http.StatusBadRequest {
		t.Fatalf("product: realtime websocket upgrade: status=%d err=%v, want 400 (body %s) — the documented SSE-only refusal is missing", status, err, clip(body))
	}
	code, ok := decodeErrorCode(body)
	if !ok || code != "unsupported_feature" {
		t.Fatalf("product: realtime websocket upgrade: error.code = %q (ok=%v), want unsupported_feature (body %s)", code, ok, clip(body))
	}
	if delta := s.fixture.Since(before); delta.arrivals != 0 || delta.dispatches != 0 || delta.receipts != 0 {
		t.Fatalf("product: realtime websocket upgrade contacted the provider (%d/%d/%d), want 0/0/0 — the refusal must precede admission and any upstream work",
			delta.arrivals, delta.dispatches, delta.receipts)
	}
	t.Logf("harness: realtime websocket transport classified: refused pre-admission, SSE-only (request id %s)", rid)
}

// httpPostJSONFull is httpPostJSON with response headers and optional
// extra request headers, for probes that must set or assert transport
// markers. extra may be nil.
func httpPostJSONFull(timeout time.Duration, url, apiKey, requestID, payload string, extra ...map[string]string) (int, string, http.Header, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(payload))
	if err != nil {
		return 0, "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("X-Request-ID", requestID)
	for _, m := range extra {
		for k, v := range m {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, "", resp.Header, err
	}
	return resp.StatusCode, string(body), resp.Header, nil
}

// controlFamily proves the family's healthy round trip around a fault
// window: HTTP 200, an independently validated protocol reply, exactly
// one whole-ledger contact on the family's OWN upstream path, retained
// evidence, a durable request_logs row AND — on durable-accounting
// builds — a durable confirmed admission plus a matching
// request_terminal_facts row (request_logs alone can be legacy
// dual-write). It is the route-specific validity oracle: without it, a
// family's refusal window could be excused as an unusable route rather
// than the product's refusal.
func (s *stand) controlFamily(t *testing.T, fam refusalFamily, phase string) {
	t.Helper()
	before := s.fixture.Snapshot()
	rid := familyRequestID(s, "ctl-"+phase+"-", fam.name)
	status, body, err := fam.request(t, s, rid)
	if err != nil || status != httpOK {
		t.Fatalf("harness: %s control %s failed (status=%d err=%v body=%s): the family's route, credentials or fixture protocol is broken; product assertions below would be meaningless",
			fam.name, phase, status, err, clip(body))
	}
	fam.validate(t, s, body)
	s.fixture.VerifyEvidence()
	delta := s.fixture.Since(before)
	if delta.arrivals != 1 || delta.dispatches != 1 || delta.receipts != 1 {
		a, d, r := s.fixture.Counts(rid)
		t.Fatalf("harness: %s control %s: whole-ledger delta arrivals/dispatches/receipts = %d/%d/%d, want 1/1/1 (id-matched %d/%d/%d); the provider-contact detector itself must be proven by a passing control before any fault window",
			fam.name, phase, delta.arrivals, delta.dispatches, delta.receipts, a, d, r)
	}
	if paths := s.fixture.ArrivalPaths(rid); len(paths) != 1 || paths[0] != fam.upstream {
		t.Fatalf("harness: %s control %s: arrival path(s) %v, want exactly [%s] — the request was not served by this family's own dispatch path",
			fam.name, phase, paths, fam.upstream)
	}
	requireEventually(t, 60*time.Second, 500*time.Millisecond, func() bool {
		return s.oracleRequestLogCount(t, rid, s.oracleDB.orgID) == 1
	}, "harness: %s control %s never became durable in request_logs", fam.name, phase)
	s.requireDurableControlEvidence(t, fam.name, phase, rid)
	t.Logf("harness: %s control %s ok (request id %s)", fam.name, phase, rid)
}

// requireDurableControlEvidence asserts the durable start of a healthy
// control on durable-accounting builds: exactly one admission row in a
// confirmed state (admitted, or reconciled once the consumer settled
// it — never voided or unresolved) and exactly one matching
// request_terminal_facts row. On baseline builds without those tables
// the durable request_logs row above is the whole available surface.
func (s *stand) requireDurableControlEvidence(t *testing.T, family, phase, rid string) {
	t.Helper()
	if !s.oracleTableExists(t, "request_admissions") {
		return
	}
	rows := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
	if len(rows) != 1 {
		t.Fatalf("product: %s control %s: %d admission row(s), want exactly 1 — the healthy dispatch was not durably confirmed", family, phase, len(rows))
	}
	a := rows[0]
	requireAdmissionVocabulary(t, a)
	if a.State != "admitted" && a.State != "reconciled" {
		t.Fatalf("product: %s control %s: admission state %q is not a confirmed outcome — a healthy dispatch must not end voided or unresolved", family, phase, a.State)
	}
	if a.InvocationID == "" {
		t.Fatalf("product: %s control %s: admission row carries no invocation id", family, phase)
	}
	if s.oracleTableExists(t, "request_terminal_facts") {
		requireEventually(t, 60*time.Second, 500*time.Millisecond, func() bool {
			return s.oracleTerminalFactsCount(t, rid, s.oracleDB.orgID) == 1
		}, "product: %s control %s never wrote exactly one matching request_terminal_facts row", family, phase)
	}
}
