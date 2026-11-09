package cli

// N03-P03-T09 consumer-compatibility evidence for the safe streaming
// mutation (streams/N03.md): the old (kill-switch off) and new (stream
// policies attached) configurations exercised through the real supported
// consumers, and the explicit refusal for the one surface that cannot honor
// stream policies.
//
// Covered here:
//   - the legacy /v1/completions stream refuses with an explicit 400 when an
//     enforce-mode org attaches a stream policy to its endpoint (the policy
//     seam lives only in the chat serveStream) — fixed in this card;
//   - the refusal is endpoint-scoped (a "chat"-attached policy leaves
//     completions alone) and shadow mode never refuses;
//   - a mutated chat stream still validates as OpenAI SSE
//     (apiformat.ValidateChatStream over the gateway wire);
//   - the Anthropic-shape /v1/messages consumer sees a valid translated
//     stream under mutation (apiformat.ValidateAnthropicStream) and a valid
//     error-closed stream under a prefix-deny abort;
//   - two pre-existing unsupported behaviors are PINNED as documented
//     findings, not silently fixed: stream policies attached to endpoint
//     "messages" are never queried (dead configuration — follow-up
//     candidate), and an upstream that terminates mid-event glues "[DONE]"
//     into the dangling SSE event the client receives (the T08 handoff
//     hazard — relay-layer behavior that predates the seam, candidate
//     follow-up card).

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/upstream"
)

const (
	n03p3t09Secret  = "ACCOUNT-778899"
	n03p3t09Trigger = "TRIGGER-WORD"
)

// n03p3t09Runtime builds a policy runtime with the given policies attached
// to a caller-chosen endpoint (chatAttachment is hardwired to "chat").
func n03p3t09Runtime(t *testing.T, mode PolicyMode, endpoint string, yamls ...string) *PolicyRuntime {
	t.Helper()
	store := newFakePolicyStore()
	for i, y := range yamls {
		store.add(testOrg, adminstore.PolicyPipeline{
			ID:             fmt.Sprintf("n03p3t09-%d", i),
			OrgID:          testOrg,
			Name:           fmt.Sprintf("n03p3t09-consumer-%d", i),
			Enabled:        true,
			CurrentVersion: 1,
		}, map[int]string{1: y}, []adminstore.PolicyAttachment{{
			KeyLabel: "", ModelPattern: "*", Endpoint: endpoint, Priority: 10 + i,
		}})
	}
	return newTestRuntime(t, store, &fakePolicyVersions{}, mode)
}

// n03p3t09CompletionsGateway is the completions router harness with a
// resolver-backed auth middleware so the policy runtime sees testOrg.
func n03p3t09CompletionsGateway(t *testing.T, upstreamURL string, rt *PolicyRuntime) *gateway {
	t.Helper()
	cfg := config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: upstreamURL}
	return &gateway{
		cfg:                  cfg,
		log:                  slog.Default(),
		auth:                 NewAuthMiddleware(cfg, newTestResolver(testOrg, nil)),
		res:                  stubModelResolver{"m": {ModelName: "fim", Provider: "openai", UpstreamURL: upstreamURL, Enabled: true}},
		pool:                 upstream.NewPool(upstream.Options{}),
		streamUsageProviders: map[string]bool{"openai": true},
		streamIdleTimeout:    0,
		policyRuntime:        rt,
	}
}

// n03p3t09MessagesGateway is the messages router harness (responses shape)
// with a policy runtime; postMessagesForOrg supplies the org-resolving auth.
func n03p3t09MessagesGateway(t *testing.T, upstreamURL string, rt *PolicyRuntime) *gateway {
	t.Helper()
	gw := responsesTestGateway(t, upstreamURL)
	gw.policyRuntime = rt
	return gw
}

func n03p3t09MessagesBody() string {
	return `{"model":"m","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"hi"}]}`
}

// --- explicit refusal: stream policies on the completions surface -------------

// TestN03P3T09_CompletionsStream_StreamPolicyAttached_Refused pins the T09
// defect fix: the /v1/completions stream cannot honor the stream_prefix /
// stream_final hooks (the policy seam exists only in the chat serveStream),
// so an enforce-mode org attaching a stream policy to the "completions"
// endpoint gets an explicit 400 before anything is forwarded — not a
// silently unprotected relay.
func TestN03P3T09_CompletionsStream_StreamPolicyAttached_Refused(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, "data: "+n03p3t09CompletionsFrame("payload "+n03p3t09Trigger+" mid")+"\n\n")
		printSSEFixture(t, w, "data: [DONE]\n\n")
	}))
	defer server.Close()

	gw := n03p3t09CompletionsGateway(t, server.URL,
		n03p3t09Runtime(t, PolicyModeEnforce, "completions", streamDenyPrefixYAML(n03p3t09Trigger)))

	rec := postCompletions(t, gw, `{"model":"m","prompt":"say something","stream":true}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 (silent stream-policy bypass on the completions surface)\n%s",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "stream_policy_unsupported_surface") {
		t.Fatalf("refusal must carry the unsupported-surface code:\n%s", rec.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("refused request reached the upstream %d time(s)", calls.Load())
	}
	if strings.Contains(rec.Body.String(), n03p3t09Trigger) || strings.Contains(rec.Body.String(), "[DONE]") {
		t.Fatalf("refusal leaked stream content:\n%s", rec.Body.String())
	}
}

// n03p3t09CompletionsFrame renders one canonical /v1/completions SSE chunk.
func n03p3t09CompletionsFrame(text string) string {
	return `{"id":"cmpl-1","object":"text_completion.chunk","choices":[{"text":` + quoteJSON(text) + `}]}`
}

// TestN03P3T09_CompletionsStream_RefusalIsScopedAndModeAware proves the
// refusal is not a blanket ban: a policy attached to the "chat" endpoint
// never blocks completions, and shadow mode never refuses (observability
// without breaking working streams).
func TestN03P3T09_CompletionsStream_RefusalIsScopedAndModeAware(t *testing.T) {
	cases := []struct {
		name     string
		mode     PolicyMode
		endpoint string
	}{
		{"chat-scoped policy leaves completions alone", PolicyModeEnforce, "chat"},
		{"shadow mode never refuses", PolicyModeShadow, "completions"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "text/event-stream")
				printSSEFixture(t, w, "data: "+n03p3t09CompletionsFrame("hello")+"\n\n")
				printSSEFixture(t, w, "data: [DONE]\n\n")
			}))
			defer server.Close()

			gw := n03p3t09CompletionsGateway(t, server.URL,
				n03p3t09Runtime(t, tc.mode, tc.endpoint, streamDenyPrefixYAML(n03p3t09Trigger)))

			rec := postCompletions(t, gw, `{"model":"m","prompt":"say hello","stream":true}`)

			if rec.Code != http.StatusOK {
				t.Fatalf("status %d, want 200\n%s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), `"text"`) || !strings.Contains(rec.Body.String(), "hello") {
				t.Fatalf("completions content missing:\n%s", rec.Body.String())
			}
			if calls.Load() != 1 {
				t.Fatalf("upstream calls = %d, want 1", calls.Load())
			}
		})
	}
}

// --- the supported chat consumer: canonical OpenAI SSE over a mutated stream ---

// TestN03P3T09_ChatMutatedStream_ValidatesAsChatSSE runs a pseudonymizing
// stream_prefix policy under the real serveStream path and validates the
// client wire with the canonical OpenAI SSE consumer validator: mutation
// must never break the event stream contract.
func TestN03P3T09_ChatMutatedStream_ValidatesAsChatSSE(t *testing.T) {
	up := newStreamPolicyUpstream(t, 10*time.Millisecond,
		streamChunkFrame("c1", "invoice "+n03p3t09Secret+" for acme"),
		streamChunkFrame("c1", " repeat "+n03p3t09Secret),
	)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamPseudonymizeYAML(n03p3t09Secret)), up.srv.URL)

	rec := streamPolicyPost(t, gw, streamRequestBody)

	body := rec.body()
	if err := apiformat.ValidateChatStream(strings.Split(body, "\n")); err != nil {
		t.Fatalf("mutated chat SSE rejected by the OpenAI consumer validator: %v\n%s", err, body)
	}
	if !strings.Contains(body, "{{YPP_1}}") {
		t.Fatalf("the pseudonym token never reached the client wire:\n%s", body)
	}
	if strings.Contains(body, n03p3t09Secret) {
		t.Fatalf("the secret leaked to the client (carry map must rewrite later chunks):\n%s", body)
	}
	if got := strings.Count(body, "data: [DONE]"); got != 1 {
		t.Fatalf("terminator count = %d, want exactly 1:\n%s", got, body)
	}
}

// --- the supported Anthropic-shape consumer: /v1/messages ----------------------

// TestN03P3T09_MessagesStream_MutatedContent_ValidAnthropicStream drives the
// full /v1/messages router with a chat-attached pseudonymize policy and
// validates the translated Anthropic stream with the canonical consumer
// validator: the new configuration is compatible with real Claude-shape
// clients (message_start … content_block_delta(alias) … message_stop).
func TestN03P3T09_MessagesStream_MutatedContent_ValidAnthropicStream(t *testing.T) {
	up := newStreamPolicyUpstream(t, 10*time.Millisecond,
		`{"id":"c1","choices":[{"index":0,"delta":{"role":"assistant"}}]}`,
		streamChunkFrame("c1", "the key is "+n03p3t09Secret+" now"),
		`{"id":"c1","choices":[{"index":0,"finish_reason":"end"}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`,
	)
	gw := n03p3t09MessagesGateway(t, up.srv.URL,
		n03p3t09Runtime(t, PolicyModeEnforce, "chat", streamPseudonymizeYAML(n03p3t09Secret)))

	rec := postMessagesForOrg(t, gw, n03p3t09MessagesBody(), testOrg)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d\n%s", rec.Code, rec.Body.String())
	}
	events := apiformat.ParseSSE(rec.Body.Bytes())
	if err := apiformat.ValidateAnthropicStream(events); err != nil {
		t.Fatalf("mutated stream rejected by the Anthropic consumer validator: %v\n%s", err, rec.Body.String())
	}
	var text strings.Builder
	for _, evn := range events {
		if evn.Event != "content_block_delta" {
			continue
		}
		var doc struct {
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(evn.Data), &doc); err != nil {
			t.Fatalf("content_block_delta payload: %v\n%s", err, evn.Data)
		}
		text.WriteString(doc.Delta.Text)
	}
	joined := text.String()
	if !strings.Contains(joined, "{{YPP_1}}") {
		t.Fatalf("the alias never reached the Anthropic consumer: %q\n%s", joined, rec.Body.String())
	}
	if strings.Contains(joined, n03p3t09Secret) || strings.Contains(rec.Body.String(), n03p3t09Secret) {
		t.Fatalf("the secret leaked to the Anthropic consumer:\n%s", rec.Body.String())
	}
}

// TestN03P3T09_MessagesStream_PrefixDeny_ClosesWithAnthropicError pins the
// abort compatibility claim from T01 for the non-OpenAI consumer: a prefix
// deny before any buffered byte closes the /v1/messages stream with a
// canonical Anthropic error event (message_start … event: error), which the
// consumer validator accepts as a complete stream — the trigger text never
// reaches the client.
func TestN03P3T09_MessagesStream_PrefixDeny_ClosesWithAnthropicError(t *testing.T) {
	up := newStreamPolicyUpstream(t, 10*time.Millisecond,
		streamChunkFrame("c1", "payload "+n03p3t09Trigger+" mid"),
		streamChunkFrame("c1", " more text"),
	)
	gw := n03p3t09MessagesGateway(t, up.srv.URL,
		n03p3t09Runtime(t, PolicyModeEnforce, "chat", streamDenyPrefixYAML(n03p3t09Trigger)))

	rec := postMessagesForOrg(t, gw, n03p3t09MessagesBody(), testOrg)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d (the abort happens after the SSE headers are committed)\n%s",
			rec.Code, rec.Body.String())
	}
	events := apiformat.ParseSSE(rec.Body.Bytes())
	if err := apiformat.ValidateAnthropicStream(events); err != nil {
		t.Fatalf("abort closure rejected by the Anthropic consumer validator: %v\n%s", err, rec.Body.String())
	}
	last := events[len(events)-1]
	if last.Event != "error" {
		t.Fatalf("last event = %q, want the terminal error event\n%s", last.Event, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), n03p3t09Trigger) {
		t.Fatalf("the trigger text leaked to the Anthropic consumer:\n%s", rec.Body.String())
	}
}

// --- pinned findings (documented, deliberately NOT fixed here) -----------------

// TestN03P3T09_MessagesAttachedStreamPolicy_NotEnforced_KnownGap pins the
// known gap: the stream policy seam queries stream plans for the "chat"
// endpoint only (newStreamPolicyWriter), so a stream policy attached to
// endpoint "messages" is dead configuration — the stream flows unmutated
// with no refusal and no event. Documented as a follow-up candidate
// (attachment validation); pinned here as evidence for the card record.
func TestN03P3T09_MessagesAttachedStreamPolicy_NotEnforced_KnownGap(t *testing.T) {
	up := newStreamPolicyUpstream(t, 10*time.Millisecond,
		streamChunkFrame("c1", "the key is "+n03p3t09Secret+" now"),
		`{"id":"c1","choices":[{"index":0,"finish_reason":"end"}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`,
	)
	gw := n03p3t09MessagesGateway(t, up.srv.URL,
		n03p3t09Runtime(t, PolicyModeEnforce, "messages", streamPseudonymizeYAML(n03p3t09Secret)))

	rec := postMessagesForOrg(t, gw, n03p3t09MessagesBody(), testOrg)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d\n%s", rec.Code, rec.Body.String())
	}
	events := apiformat.ParseSSE(rec.Body.Bytes())
	if err := apiformat.ValidateAnthropicStream(events); err != nil {
		t.Fatalf("stream rejected by the Anthropic consumer validator: %v\n%s", err, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), n03p3t09Secret) {
		t.Fatalf("expected the KNOWN GAP (unenforced attachment): the secret must flow unmutated\n%s",
			rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "{{YPP_") {
		t.Fatalf("unexpected mutation — the gap contract changed; update this pin:\n%s", rec.Body.String())
	}
}

// TestN03P3T09_MidEventDoneTermination_RelayedGlued_KnownHazard pins the
// relay-level hazard handed off by T08 (success-path variant): when the
// upstream terminates the stream by writing "data: [DONE]\n\n" while the
// previous data line is still missing its blank-line separator, the two
// lines assemble into ONE SSE event whose payload is
// "{partial-json}\n[DONE]". For the client the terminator is swallowed: no
// standalone "data: [DONE]" event is ever delivered and the glued event is
// not a valid OpenAI chunk. The seam path relays the glued event verbatim
// (splitSSEData takes the first line, whose JSON is valid, so nothing
// flags it), and the kill-switch path produces byte-identical client
// output — the behavior predates the streaming-policy seam and belongs in
// the relay layer (candidate follow-up card). NOT fixed in this card.
func TestN03P3T09_MidEventDoneTermination_RelayedGlued_KnownHazard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		printSSEFixture(t, w, "data: "+streamChunkFrame("c1", "ok")+"\n\n")     // complete event
		printSSEFixture(t, w, "data: "+streamChunkFrame("c1", "dangling")+"\n") // no blank line
		printSSEFixture(t, w, "data: [DONE]\n\n")                               // completes the dangling EVENT
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer srv.Close()

	assertGlued := func(t *testing.T, body string) {
		t.Helper()
		events := apiformat.ParseSSE([]byte(body))
		if len(events) < 2 {
			t.Fatalf("expected at least two SSE events:\n%s", body)
		}
		if got, want := events[0].Data, streamChunkFrame("c1", "ok"); got != want {
			t.Fatalf("first event = %q, want the intact earlier chunk %q", got, want)
		}
		for _, evn := range events {
			if evn.Data == "[DONE]" {
				t.Fatalf("a standalone [DONE] event reached the client — the hazard contract changed:\n%s", body)
			}
		}
		last := events[len(events)-1]
		if !strings.Contains(last.Data, "\n") || !strings.HasSuffix(last.Data, "[DONE]") {
			t.Fatalf("expected the dangling JSON and [DONE] glued into ONE multi-data-line event, got %q", last.Data)
		}
		if !strings.Contains(last.Data, "dangling") {
			t.Fatalf("dangling payload missing from the glued event: %q", last.Data)
		}
	}

	// Re-pinned at batch-B integration (FIX-11 fused-DONE fix): on the
	// policy-seam path the documented hazard NO LONGER EXISTS — the
	// unfinished event's bytes are dropped (not re-framed, not glued) and
	// the stream ends at exactly one standalone [DONE] (see
	// TestFix11_FusedDone_SuccessPathStandaloneTerminal for the owning
	// contract). The kill-switch path keeps the original glued hazard.
	t.Run("policy seam on", func(t *testing.T) {
		gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamDenyFinalYAML("never-matches")), srv.URL)
		rec := streamPolicyPost(t, gw, streamRequestBody)
		body := rec.body()
		if !strings.Contains(body, streamChunkFrame("c1", "ok")) {
			t.Fatalf("the complete earlier chunk must reach the client:\n%s", body)
		}
		if strings.Contains(body, "dangling") {
			t.Fatalf("the unfinished event's bytes must be dropped, not re-framed:\n%s", body)
		}
		if n := strings.Count(body, "[DONE]"); n != 1 {
			t.Fatalf("exactly one terminator expected, got %d:\n%s", n, body)
		}
		if !strings.HasSuffix(body, "data: [DONE]\n\n") {
			t.Fatalf("the stream must end at a standalone [DONE]:\n%s", body)
		}
	})

	t.Run("kill switch off", func(t *testing.T) {
		gw := withUpstream(streamTestGateway(srv.URL), srv.URL)
		gw.policyRuntime = nil
		rec := streamPolicyPost(t, gw, streamRequestBody)
		assertGlued(t, rec.body())
	})
}
