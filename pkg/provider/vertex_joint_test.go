package provider

// Joint Vertex AI user scenario: one shared adapter, one ambient ADC
// credential, and multi-turn OpenAI client sessions composed end-to-end —
// request translation, per-hop model override, the model/region capability
// matrix, ADC authentication (exchange, cache, mid-session refresh, source
// pinning), the real HTTP round-trip to a Vertex-shaped endpoint, response
// translation / SSE stream translation, and usage metering.
//
// Real vs mock split (integration contract): everything inside the process
// is the production code path — the ADC chain walks a real env var and key
// file, signs a real RS256 JWT, resolves the real capability matrix, runs
// both translators, and the stream handler is resolved through the same
// name-based factories the gateway uses. The only mocks are two loopback
// httptest doubles standing in for the Google OAuth token endpoint and a
// regional Vertex endpoint; no live Google endpoint is contacted. The
// scenarios are sequential and deterministic with exact call counts; the
// concurrent session assertions are order-free (set-based), so the whole
// file stays stable under -race and -shuffle.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// vertexJointTokenServer is the OAuth token endpoint double: successful
// exchanges mint fresh sequential tokens (JT-1, JT-2, …) so every binding's
// token is unique and phase assertions stay exact; a switchable status code
// turns the endpoint into a refusing one for the negative phases.
type vertexJointTokenServer struct {
	srv    *httptest.Server
	mu     sync.Mutex
	hits   int // every request, refused or not
	minted int // successful exchanges only
	status int // 0 → serve tokens; otherwise the refusal code
}

func newVertexJointTokenServer(t *testing.T) *vertexJointTokenServer {
	t.Helper()
	ts := &vertexJointTokenServer{}
	ts.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.mu.Lock()
		ts.hits++
		status := ts.status
		ts.mu.Unlock()
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		if status != 0 {
			http.Error(w, "refused", status)
			return
		}
		ts.mu.Lock()
		ts.minted++
		token := fmt.Sprintf("JT-%d", ts.minted)
		ts.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "expires_in": 3600})
	}))
	t.Cleanup(ts.srv.Close)
	return ts
}

func (ts *vertexJointTokenServer) setRefused(code int) {
	ts.mu.Lock()
	ts.status = code
	ts.mu.Unlock()
}

func (ts *vertexJointTokenServer) snapshot() (hits, minted int) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.hits, ts.minted
}

// vertexJointRequest is one captured upstream request.
type vertexJointRequest struct {
	path  string
	query url.Values
	auth  string
	body  []byte
}

// vertexJointUpstream is the Vertex endpoint double: it records every
// request and answers :generateContent calls with the configured JSON body
// and :streamGenerateContent?alt=sse calls with the configured SSE body.
type vertexJointUpstream struct {
	srv      *httptest.Server
	mu       sync.Mutex
	requests []vertexJointRequest
	reply    string // generateContent JSON
	sse      string // alt=sse event body
}

func newVertexJointUpstream(t *testing.T, reply, sse string) *vertexJointUpstream {
	t.Helper()
	up := &vertexJointUpstream{reply: reply, sse: sse}
	up.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		up.mu.Lock()
		up.requests = append(up.requests, vertexJointRequest{
			path:  r.URL.Path,
			query: r.URL.Query(),
			auth:  r.Header.Get("Authorization"),
			body:  body,
		})
		answer := up.reply
		if r.URL.Query().Get("alt") == "sse" {
			answer = up.sse
			w.Header().Set("Content-Type", "text/event-stream")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		up.mu.Unlock()
		_, _ = io.WriteString(w, answer)
	}))
	t.Cleanup(up.srv.Close)
	return up
}

func (up *vertexJointUpstream) setReplies(reply, sse string) {
	up.mu.Lock()
	up.reply = reply
	up.sse = sse
	up.mu.Unlock()
}

func (up *vertexJointUpstream) snapshot() []vertexJointRequest {
	up.mu.Lock()
	defer up.mu.Unlock()
	return append([]vertexJointRequest(nil), up.requests...)
}

// vertexJointRig wires the doubles into one adapter the way production
// does: an env-pinned service-account key file whose token_uri points at
// the token double, and the production ADC machinery riding the double's
// loopback client (the established test seam — see plainVertexADC).
type vertexJointRig struct {
	tokenSrv *vertexJointTokenServer
	upstream *vertexJointUpstream
	keyPath  string
	credsA   string
	credsB   string
	adapter  *Vertex
}

func newVertexJointRig(t *testing.T, reply, sse string) *vertexJointRig {
	t.Helper()
	rig := &vertexJointRig{}
	rig.tokenSrv = newVertexJointTokenServer(t)
	rig.keyPath, _, _ = writeVertexSAKeyFile(t, rig.tokenSrv.srv.URL)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", rig.keyPath)
	rig.upstream = newVertexJointUpstream(t, reply, sse)
	rig.adapter = NewVertexWithSource(plainVertexADC(rig.tokenSrv.srv))
	rig.credsA = `{"project":"api-proj-0001","location":"us-central1"}`
	rig.credsB = `{"project":"api-proj-0002","location":"us-central1"}`
	return rig
}

// chatTurn runs one full non-streaming user turn: OpenAI body →
// TranslateRequest → per-hop model override → PrepareRequest → real HTTP
// round-trip → TranslateResponse. It is the exact call order of the
// upstream client's forward pipeline (minus the client's own SSRF layer,
// which is provider-agnostic and covered by pkg/upstream).
func (rig *vertexJointRig) chatTurn(t *testing.T, openaiBody, servedModel, creds string) ([]byte, error) {
	t.Helper()
	envelope := mustTranslate(t, rig.adapter, openaiBody)
	if servedModel != "" {
		envelope = overrideEnvelopeModel(t, envelope, servedModel)
	}
	req, err := rig.adapter.PrepareRequest(context.Background(), rig.upstream.srv.URL, rig.adapter.Path(false), envelope, creds, false)
	if err != nil {
		return nil, err
	}
	resp, err := rig.upstream.srv.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream HTTP %d: %s", resp.StatusCode, raw)
	}
	return rig.adapter.TranslateResponse(raw)
}

// streamTurn runs one full streaming user turn and returns the raw client
// stream plus the handler-reported usage.
func (rig *vertexJointRig) streamTurn(t *testing.T, openaiBody, creds string) (string, Usage, error) {
	t.Helper()
	envelope := mustTranslate(t, rig.adapter, openaiBody)
	req, err := rig.adapter.PrepareRequest(context.Background(), rig.upstream.srv.URL, rig.adapter.Path(true), envelope, creds, true)
	if err != nil {
		return "", Usage{}, err
	}
	if !strings.Contains(req.URL.Path, ":streamGenerateContent") || req.URL.Query().Get("alt") != "sse" {
		return "", Usage{}, fmt.Errorf("stream request URL %q is not the alt=sse stream endpoint", req.URL.String())
	}
	resp, err := rig.upstream.srv.Client().Do(req)
	if err != nil {
		return "", Usage{}, err
	}
	defer resp.Body.Close()
	w, buf := newRecorder()
	usage, err := NewStreamHandler("vertex", "gemini-2.0-flash").HandleStream(context.Background(), w, w, resp)
	return buf.String(), usage, err
}

// assertJointChatCompletion decodes a translated chat.completion body and
// pins the text, model echo, finish reason and provider-reported usage
// (including the cached-token detail), then re-parses the body through
// ParseUsage — the gateway bills from the translated OpenAI shape, so the
// round-trip must reproduce the provider numbers exactly.
func assertJointChatCompletion(t *testing.T, v *Vertex, body []byte, wantText, wantModel string, prompt, completion, total, cached int64) {
	t.Helper()
	var got struct {
		Object  string `json:"object"`
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage *struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
			TotalTokens      int64 `json:"total_tokens"`
			Details          *struct {
				CachedTokens int64 `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
		} `json:"usage"`
	}
	require.NoError(t, json.Unmarshal(body, &got))
	require.Equal(t, "chat.completion", got.Object)
	require.Equal(t, wantModel, got.Model)
	require.Len(t, got.Choices, 1)
	require.Equal(t, "assistant", got.Choices[0].Message.Role)
	require.Equal(t, wantText, got.Choices[0].Message.Content)
	require.Equal(t, "stop", got.Choices[0].FinishReason)
	require.NotNil(t, got.Usage)
	require.Equal(t, prompt, got.Usage.PromptTokens)
	require.Equal(t, completion, got.Usage.CompletionTokens)
	require.Equal(t, total, got.Usage.TotalTokens)
	if cached > 0 {
		require.NotNil(t, got.Usage.Details)
		require.Equal(t, cached, got.Usage.Details.CachedTokens)
	}
	want := Usage{PromptTokens: prompt, CompletionTokens: completion, TotalTokens: total, CacheReadTokens: cached, Source: UsageSourceProvider}
	require.Equal(t, want, v.ParseUsage(body))
}

// TestVertexJointScenario_WiringFactories pins the name-based factories the
// gateway's pool and stream resolver use: "vertex" constructs the stateful
// adapter, and the stream resolver gets the translating terminator — never
// a foreign-schema passthrough.
func TestVertexJointScenario_WiringFactories(t *testing.T) {
	t.Parallel()

	p, err := New("vertex")
	require.NoError(t, err)
	v, ok := p.(*Vertex)
	require.True(t, ok, "New(vertex) = %T, want *Vertex", p)
	require.Equal(t, "vertex", v.Name())

	h := NewStreamHandler("vertex", "gemini-2.0-flash")
	_, ok = h.(vertexStreamTerminator)
	require.True(t, ok, "vertex stream handler = %T, want the translating terminator", h)
}

// TestVertexJointScenario_ChatLifecycle is the joint non-streaming user
// scenario: a multi-turn session on one adapter whose credential lifecycle
// (cold exchange → rotation away of the key file → mid-session refresh) and
// capability/region composition (a misconfigured region is rejected before
// any network work) unfold phase by phase, with the packet negative — a
// second org whose token exchange is refused — composed mid-journey without
// disturbing the live session.
func TestVertexJointScenario_ChatLifecycle(t *testing.T) {
	const geminiReply = `{"candidates":[{"content":{"role":"model","parts":[{"text":"Здравствуйте!"}]},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":20,"candidatesTokenCount":4,"totalTokenCount":24,"cachedContentTokenCount":6},"modelVersion":"gemini-2.0-flash-001"}`
	rig := newVertexJointRig(t, geminiReply, "")
	v := rig.adapter

	// Acceptance surface: the journey's (model, region) pair resolves to
	// exactly the capabilities the session relies on.
	caps, err := VertexLookup("gemini-2.0-flash", "us-central1")
	require.NoError(t, err)
	require.True(t, caps.Streaming)
	require.True(t, caps.Tools)
	require.True(t, caps.ImageInput)

	// Turn 1 — cold session: full translation → override → capability
	// gate → ADC exchange → project/location URL → round-trip → reverse
	// translation.
	out, err := rig.chatTurn(t,
		`{"model":"client-said-other","messages":[{"role":"system","content":"You are terse."},{"role":"user","content":"Привет"}],"max_tokens":64,"temperature":0.2}`,
		"gemini-2.0-flash", rig.credsA)
	require.NoError(t, err)
	assertJointChatCompletion(t, v, out, "Здравствуйте!", "gemini-2.0-flash-001", 20, 4, 24, 6)

	reqs := rig.upstream.snapshot()
	require.Len(t, reqs, 1)
	require.Equal(t, "/v1/projects/api-proj-0001/locations/us-central1/publishers/google/models/gemini-2.0-flash:generateContent", reqs[0].path)
	require.Equal(t, "Bearer JT-1", reqs[0].auth)
	// The wire body is the inner generateContent payload only: the
	// envelope and the client's original model never reach the upstream.
	require.JSONEq(t,
		`{"contents":[{"role":"user","parts":[{"text":"Привет"}]}],"systemInstruction":{"parts":[{"text":"You are terse."}]},"generationConfig":{"maxOutputTokens":64,"temperature":0.2}}`,
		string(reqs[0].body))
	hits, minted := rig.tokenSrv.snapshot()
	require.Equal(t, 1, hits)
	require.Equal(t, 1, minted)

	// Credential lifecycle: the key file is rotated away after the first
	// successful walk — the pinned source keeps serving the session with
	// no credential-file I/O and no re-exchange.
	require.NoError(t, os.Remove(rig.keyPath))
	out, err = rig.chatTurn(t, `{"model":"gemini-2.0-flash","messages":[{"role":"user","content":"turn two"}]}`, "", rig.credsA)
	require.NoError(t, err)
	assertJointChatCompletion(t, v, out, "Здравствуйте!", "gemini-2.0-flash-001", 20, 4, 24, 6)
	reqs = rig.upstream.snapshot()
	require.Len(t, reqs, 2)
	require.Equal(t, "Bearer JT-1", reqs[1].auth)
	hits, minted = rig.tokenSrv.snapshot()
	require.Equal(t, 1, hits)
	require.Equal(t, 1, minted)

	// Capability/region composition: a binding configured for a region the
	// model family is not served in is rejected with the precise matrix
	// reason BEFORE any credential or network work — the journey never
	// emits a doomed upstream call.
	_, err = rig.chatTurn(t, `{"model":"gemini-1.5-pro","messages":[{"role":"user","content":"hi"}]}`, "",
		`{"project":"api-proj-0001","location":"global"}`)
	require.Error(t, err)
	require.Contains(t, err.Error(), `location "global" is not served for model family "gemini-1.5-"`)
	require.Len(t, rig.upstream.snapshot(), 2)
	hits, minted = rig.tokenSrv.snapshot()
	require.Equal(t, 1, hits)
	require.Equal(t, 1, minted)

	// Credential lifecycle: the cached token drifts into the refresh skew
	// window mid-session — the next user turn re-exchanges exactly once
	// and continues seamlessly on the new token.
	key := vertexSoleCacheKey(t, v.adc)
	v.adc.mu.Lock()
	v.adc.tokens[key] = vertexToken{accessToken: "JT-1", tokenExp: time.Now().Add(2 * time.Minute)}
	v.adc.mu.Unlock()
	_, err = rig.chatTurn(t, `{"model":"gemini-2.0-flash","messages":[{"role":"user","content":"turn three"}]}`, "", rig.credsA)
	require.NoError(t, err)
	reqs = rig.upstream.snapshot()
	require.Len(t, reqs, 3)
	require.Equal(t, "Bearer JT-2", reqs[2].auth)
	hits, minted = rig.tokenSrv.snapshot()
	require.Equal(t, 2, hits)
	require.Equal(t, 2, minted)

	// Packet negative composed into the journey: org B (different project,
	// same ambient credential) requests while the token endpoint refuses
	// exchanges. B's turn fails on B's OWN exchange — no foreign token is
	// minted, served, or leaked — and org A's next turn is untouched.
	rig.tokenSrv.setRefused(http.StatusForbidden)
	_, err = rig.chatTurn(t, `{"model":"gemini-2.0-flash","messages":[{"role":"user","content":"org B turn"}]}`, "", rig.credsB)
	require.Error(t, err)
	require.Contains(t, err.Error(), "HTTP 403")
	require.NotContains(t, err.Error(), "JT-1")
	require.NotContains(t, err.Error(), "JT-2")
	hits, minted = rig.tokenSrv.snapshot()
	require.Equal(t, 3, hits)
	require.Equal(t, 2, minted)
	require.Len(t, rig.upstream.snapshot(), 3)

	_, err = rig.chatTurn(t, `{"model":"gemini-2.0-flash","messages":[{"role":"user","content":"turn four"}]}`, "", rig.credsA)
	require.NoError(t, err)
	reqs = rig.upstream.snapshot()
	require.Len(t, reqs, 4)
	require.Equal(t, "Bearer JT-2", reqs[3].auth)
	hits, minted = rig.tokenSrv.snapshot()
	require.Equal(t, 3, hits)
	require.Equal(t, 2, minted)

	// B heals when the endpoint recovers: its own fresh exchange, its own
	// project URL — and A stays on its own token in both directions.
	rig.tokenSrv.setRefused(0)
	out, err = rig.chatTurn(t, `{"model":"gemini-2.0-flash","messages":[{"role":"user","content":"org B retry"}]}`, "", rig.credsB)
	require.NoError(t, err)
	assertJointChatCompletion(t, v, out, "Здравствуйте!", "gemini-2.0-flash-001", 20, 4, 24, 6)
	_, err = rig.chatTurn(t, `{"model":"gemini-2.0-flash","messages":[{"role":"user","content":"turn five"}]}`, "", rig.credsA)
	require.NoError(t, err)
	reqs = rig.upstream.snapshot()
	require.Len(t, reqs, 6)
	require.Equal(t, "/v1/projects/api-proj-0002/locations/us-central1/publishers/google/models/gemini-2.0-flash:generateContent", reqs[4].path)
	require.Equal(t, "Bearer JT-3", reqs[4].auth)
	require.Equal(t, "Bearer JT-2", reqs[5].auth)
	hits, minted = rig.tokenSrv.snapshot()
	require.Equal(t, 4, hits)
	require.Equal(t, 3, minted)

	authByProject := map[string]map[string]bool{"api-proj-0001": {}, "api-proj-0002": {}}
	for _, r := range reqs {
		switch {
		case strings.Contains(r.path, "/projects/api-proj-0001/"):
			authByProject["api-proj-0001"][r.auth] = true
		case strings.Contains(r.path, "/projects/api-proj-0002/"):
			authByProject["api-proj-0002"][r.auth] = true
		default:
			t.Fatalf("upstream request outside both org projects: %s", r.path)
		}
	}
	require.Equal(t, map[string]bool{"Bearer JT-1": true, "Bearer JT-2": true}, authByProject["api-proj-0001"])
	require.Equal(t, map[string]bool{"Bearer JT-3": true}, authByProject["api-proj-0002"])
}

// TestVertexJointScenario_StreamSession is the joint streaming scenario:
// the SSE leg of the same composition — translate → override → capability
// gate → cached ADC token → alt=sse round-trip → translating handler →
// OpenAI chunks — with the terminal usage chunk re-parsed by ParseUsage
// (the billing path) and a second turn riding the same cached token.
func TestVertexJointScenario_StreamSession(t *testing.T) {
	const sseOne = "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"план: \",\"thought\":true}]},\"index\":0}],\"modelVersion\":\"gemini-2.0-flash-001\"}\n\n" +
		"data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"При\"}]},\"index\":0}]}\n\n" +
		"data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"вет\"}]},\"index\":0}]}\n\n" +
		"data: {\"candidates\":[{\"finishReason\":\"STOP\",\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":20,\"candidatesTokenCount\":6,\"totalTokenCount\":26,\"cachedContentTokenCount\":6},\"modelVersion\":\"gemini-2.0-flash-001\"}\n\n"
	const sseTwo = "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"ok\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":5,\"candidatesTokenCount\":1,\"totalTokenCount\":6},\"modelVersion\":\"gemini-2.0-flash-001\"}\n\n"
	rig := newVertexJointRig(t, "", sseOne)

	raw, usage, err := rig.streamTurn(t, `{"model":"gemini-2.0-flash","messages":[{"role":"user","content":"hi"}]}`, rig.credsA)
	require.NoError(t, err)

	chunks := parseVertexStreamFrames(t, raw)
	require.Len(t, chunks, 6, "role + reasoning + 2 content + finish + usage-only, got:\n%s", raw)
	require.Equal(t, map[string]any{"role": "assistant"}, vertexChoice(t, chunks[0])["delta"])
	require.Equal(t, map[string]any{"reasoning_content": "план: "}, vertexChoice(t, chunks[1])["delta"])
	require.Equal(t, map[string]any{"content": "При"}, vertexChoice(t, chunks[2])["delta"])
	require.Equal(t, map[string]any{"content": "вет"}, vertexChoice(t, chunks[3])["delta"])
	require.Equal(t, "stop", vertexChoice(t, chunks[4])["finish_reason"])
	require.Equal(t, Usage{PromptTokens: 20, CompletionTokens: 6, TotalTokens: 26, CacheReadTokens: 6, Source: UsageSourceProvider}, usage)

	// Billing composition: the usage-only chunk the handler emits is the
	// exact OpenAI shape ParseUsage re-parses downstream.
	usageChunk, err := json.Marshal(chunks[5])
	require.NoError(t, err)
	require.Equal(t, usage, (*Vertex)(nil).ParseUsage(usageChunk))

	// The wire request is the stream endpoint, ADC-authenticated with the
	// session's cached token.
	reqs := rig.upstream.snapshot()
	require.Len(t, reqs, 1)
	require.Equal(t, "/v1/projects/api-proj-0001/locations/us-central1/publishers/google/models/gemini-2.0-flash:streamGenerateContent", reqs[0].path)
	require.Equal(t, "sse", reqs[0].query.Get("alt"))
	require.Equal(t, "Bearer JT-1", reqs[0].auth)
	require.JSONEq(t, `{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`, string(reqs[0].body))
	hits, minted := rig.tokenSrv.snapshot()
	require.Equal(t, 1, hits)
	require.Equal(t, 1, minted)

	// Turn 2 rides the SAME cached token: no second exchange, the SSE
	// reply switches per configuration, the frames decode cleanly.
	rig.upstream.setReplies("", sseTwo)
	raw, usage, err = rig.streamTurn(t, `{"model":"gemini-2.0-flash","messages":[{"role":"user","content":"turn two"}]}`, rig.credsA)
	require.NoError(t, err)
	chunks = parseVertexStreamFrames(t, raw)
	require.Len(t, chunks, 4, "role + content + finish + usage-only, got:\n%s", raw)
	require.Equal(t, map[string]any{"content": "ok"}, vertexChoice(t, chunks[1])["delta"])
	require.Equal(t, Usage{PromptTokens: 5, CompletionTokens: 1, TotalTokens: 6, Source: UsageSourceProvider}, usage)
	reqs = rig.upstream.snapshot()
	require.Len(t, reqs, 2)
	require.Equal(t, "Bearer JT-1", reqs[1].auth)
	hits, minted = rig.tokenSrv.snapshot()
	require.Equal(t, 1, hits)
	require.Equal(t, 1, minted)
}

// TestVertexJointScenario_ConcurrentStreamSessions composes the concurrency
// dimension: two org sessions stream simultaneously on ONE adapter with ONE
// ambient credential. Order-free assertions only — each binding performs
// exactly one exchange, streams with exactly its own token, and the two
// token sets are disjoint.
func TestVertexJointScenario_ConcurrentStreamSessions(t *testing.T) {
	const sse = "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"para\"}]},\"index\":0}],\"modelVersion\":\"gemini-2.0-flash-001\"}\n\n" +
		"data: {\"candidates\":[{\"finishReason\":\"STOP\",\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":9,\"candidatesTokenCount\":2,\"totalTokenCount\":11}}\n\n"
	rig := newVertexJointRig(t, "", sse)

	type jointStreamResult struct {
		raw   string
		usage Usage
		err   error
	}
	results := make([]jointStreamResult, 2)
	bindings := []string{rig.credsA, rig.credsB}

	var wg sync.WaitGroup
	for i := range bindings {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res := &results[i]
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			envelope, err := rig.adapter.TranslateRequest([]byte(`{"model":"gemini-2.0-flash","messages":[{"role":"user","content":"concurrent"}]}`))
			if err != nil {
				res.err = err
				return
			}
			req, err := rig.adapter.PrepareRequest(ctx, rig.upstream.srv.URL, rig.adapter.Path(true), envelope, bindings[i], true)
			if err != nil {
				res.err = err
				return
			}
			resp, err := rig.upstream.srv.Client().Do(req)
			if err != nil {
				res.err = err
				return
			}
			defer resp.Body.Close()
			w, buf := newRecorder()
			res.usage, res.err = NewStreamHandler("vertex", "gemini-2.0-flash").HandleStream(ctx, w, w, resp)
			res.raw = buf.String()
		}(i)
	}
	wg.Wait()
	for i, res := range results {
		require.NoError(t, res.err, "session %d", i)
		chunks := parseVertexStreamFrames(t, res.raw)
		require.Len(t, chunks, 4, "session %d: role + content + finish + usage-only, got:\n%s", i, res.raw)
		require.Equal(t, map[string]any{"content": "para"}, vertexChoice(t, chunks[1])["delta"])
		require.Equal(t, Usage{PromptTokens: 9, CompletionTokens: 2, TotalTokens: 11, Source: UsageSourceProvider}, res.usage)
	}

	hits, minted := rig.tokenSrv.snapshot()
	require.Equal(t, 2, hits)
	require.Equal(t, 2, minted)

	authByProject := map[string]map[string]bool{"api-proj-0001": {}, "api-proj-0002": {}}
	reqs := rig.upstream.snapshot()
	require.Len(t, reqs, 2)
	for _, r := range reqs {
		require.Equal(t, "sse", r.query.Get("alt"))
		switch {
		case strings.Contains(r.path, "/projects/api-proj-0001/"):
			authByProject["api-proj-0001"][r.auth] = true
		case strings.Contains(r.path, "/projects/api-proj-0002/"):
			authByProject["api-proj-0002"][r.auth] = true
		default:
			t.Fatalf("upstream request outside both org projects: %s", r.path)
		}
	}
	require.Len(t, authByProject["api-proj-0001"], 1, "org A must stream with exactly one token")
	require.Len(t, authByProject["api-proj-0002"], 1, "org B must stream with exactly one token")
	for auth := range authByProject["api-proj-0001"] {
		require.NotContains(t, authByProject["api-proj-0002"], auth, "tokens must not cross the binding boundary")
	}
}
