package upstream

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Adapter conformance suite (W-PROV): drives EVERY adapter from the factory
// through the full upstream.Client pipeline — TranslateRequest → model
// override → ModelFinalizer → PrepareRequest → response translation — against
// an httptest mock. This catches the whole class of adapter regressions
// (double translation, override clobbering, client-pool substitution) that
// per-adapter unit tests miss.

const conformanceChatBody = `{"model":"reg-alias","messages":[{"role":"user","content":"hi"}],"max_tokens":32,"temperature":0.5}`

const conformanceOpenAIResponse = `{"id":"cmpl-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok-reply"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`

const conformanceStreamResponse = "data: {\"choices\":[{\"delta\":{\"content\":\"st\"}}]}\n\ndata: [DONE]\n\n"

const conformanceAnthropicResponse = `{"id":"msg_1","type":"message","role":"assistant","model":"claude-mock","content":[{"type":"text","text":"antho-reply"}],"stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":4}}`

// jaisModelName is the canonical served-model name the jais adapter must put
// on the wire regardless of the requested alias.
const jaisModelName = "jais-30b-chat"

// conformanceAdapter describes one factory adapter's expected wire contract.
type conformanceAdapter struct {
	name string
	// oauthPath, when non-empty, is served with a GigaChat-style token
	// exchange response (sber).
	oauthPath string
	// upstreamKey is the credential passed to the client; empty → "k".
	// (Named to avoid the gosec G101 credential-name heuristic on fixtures.)
	upstreamKey string
	// assertRequest inspects the decoded request body the adapter actually
	// put on the wire.
	assertRequest func(t *testing.T, body map[string]any, stream bool)
	// assertResponse, when set, inspects the translated (OpenAI-shape)
	// body returned by ForwardJSON.
	assertResponse func(t *testing.T, body []byte)
	// responseBody is served on the non-stream path; empty → OpenAI shape.
	responseBody string
}

func conformanceAdapters() []conformanceAdapter {
	identity := func(t *testing.T, body map[string]any, stream bool) {
		t.Helper()
		assert.Contains(t, body, "messages", "openai-compat adapters forward the chat shape")
		assert.Equal(t, "reg-alias", body["model"], "per-hop model override must survive")
	}
	return []conformanceAdapter{
		{name: "openai", assertRequest: identity},
		{name: "sakana", assertRequest: identity},
		{name: "sarvam", assertRequest: identity},
		{name: "krutrim", assertRequest: identity},
		{name: "falcon", assertRequest: identity},
		{name: "mistral", assertRequest: identity},
		{
			name:        "yandex",
			upstreamKey: "iam-token|folder-id",
			assertRequest: func(t *testing.T, body map[string]any, stream bool) {
				t.Helper()
				assert.Contains(t, body, "messages", "yandex forwards the chat shape")
				assert.Equal(t, "reg-alias", body["model"])
			},
		},
		{name: "vllm", assertRequest: identity},
		{name: "ollama", assertRequest: identity},
		{name: "llamacpp", assertRequest: identity},
		{name: "zai-coding", assertRequest: identity},
		{
			name: "anthropic",
			assertRequest: func(t *testing.T, body map[string]any, stream bool) {
				t.Helper()
				assert.Contains(t, body, "messages", "anthropic request carries messages")
				assert.Equal(t, "reg-alias", body["model"])
			},
			assertResponse: func(t *testing.T, body []byte) {
				t.Helper()
				assert.Contains(t, string(body), "antho-reply", "anthropic response must be translated to OpenAI shape")
				assert.NotContains(t, string(body), `"input_tokens"`, "raw anthropic usage must not leak to the client body")
			},
			responseBody: conformanceAnthropicResponse,
		},
		{
			name: "tgi",
			assertRequest: func(t *testing.T, body map[string]any, stream bool) {
				t.Helper()
				if stream {
					assert.Contains(t, body, "messages",
						"streaming uses the OpenAI-compat shim: the TGI generate payload must not reach it")
					assert.Equal(t, "reg-alias", body["model"])
					return
				}
				// The regression: a TranslateRequest-time translation was
				// re-translated by PrepareRequest into an empty prompt.
				inputs, _ := body["inputs"].(string)
				assert.NotEmpty(t, inputs, "non-stream /generate must receive a non-empty inputs prompt")
				assert.NotContains(t, body, "messages", "non-stream payload must be TGI generate format")
				params, ok := body["parameters"].(map[string]any)
				require.True(t, ok, "parameters object expected")
				mnt, ok := params["max_new_tokens"].(float64)
				require.True(t, ok, "max_new_tokens must survive the translation")
				assert.InDelta(t, 32, mnt, 0)
			},
			assertResponse: func(t *testing.T, body []byte) {
				t.Helper()
				assert.Contains(t, string(body), "gen-reply", "TGI generated_text must be wrapped in OpenAI shape")
				assert.Contains(t, string(body), "choices")
			},
			responseBody: `{"generated_text":"gen-reply"}`,
		},
		{
			name:        "naver",
			upstreamKey: "clova-key|apigw-key",
			assertRequest: func(t *testing.T, body map[string]any, stream bool) {
				t.Helper()
				assert.Contains(t, body, "messages", "naver forwards the chat shape")
				assert.Equal(t, "reg-alias", body["model"])
			},
		},
		{
			name:      "sber",
			oauthPath: "/api/v1/oauth",
			assertRequest: func(t *testing.T, body map[string]any, stream bool) {
				t.Helper()
				assert.Contains(t, body, "messages", "sber is openai-compat: body is forwarded verbatim")
				assert.Equal(t, "reg-alias", body["model"])
			},
		},
		{
			name: "jais",
			assertRequest: func(t *testing.T, body map[string]any, stream bool) {
				t.Helper()
				// The regression: the gateway's per-hop model override ran
				// AFTER TranslateRequest and clobbered the pinned name.
				assert.Equal(t, jaisModelName, body["model"],
					"the final model on the wire must be the canonical served name, never the registry alias")
			},
		},
	}
}

// conformanceMock is the mock upstream: it records every request (path +
// decoded JSON body) and answers with the given payload.
type conformanceMock struct {
	srv   *httptest.Server
	mu    sync.Mutex
	seen  map[string]map[string]any // path → decoded body (last wins)
	oauth chan struct{}             // closed once the token endpoint is hit
}

func newConformanceMock(t *testing.T, a conformanceAdapter, stream bool, payload string) *conformanceMock {
	t.Helper()
	m := &conformanceMock{seen: map[string]map[string]any{}, oauth: make(chan struct{})}
	mux := http.NewServeMux()
	if a.oauthPath != "" {
		mux.HandleFunc(a.oauthPath, func(w http.ResponseWriter, _ *http.Request) {
			m.mu.Lock()
			m.seen[a.oauthPath] = map[string]any{}
			m.mu.Unlock()
			select {
			case <-m.oauth:
			default:
				close(m.oauth)
			}
			_, _ = w.Write([]byte(`{"access_token":"conformance-token","expires_at":0}`))
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		decoded := map[string]any{}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &decoded)
		}
		m.mu.Lock()
		m.seen[r.URL.Path] = decoded
		m.mu.Unlock()
		if stream {
			w.Header().Set("Content-Type", "text/event-stream")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		_, _ = w.Write([]byte(payload))
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (a conformanceAdapter) apiKeyOr(def string) string {
	if a.upstreamKey == "" {
		return def
	}
	return a.upstreamKey
}

func (m *conformanceMock) bodyAt(t *testing.T, path string) map[string]any {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.seen[path]
	require.True(t, ok, "expected a request to %s, got %v", path, m.seen)
	return b
}

func TestAdapterConformance_NonStream(t *testing.T) {
	t.Parallel()
	for _, a := range conformanceAdapters() {
		t.Run(a.name, func(t *testing.T) {
			t.Parallel()
			resp := a.responseBody
			if resp == "" {
				resp = conformanceOpenAIResponse
			}
			mock := newConformanceMock(t, a, false, resp)

			client, err := newTestClientWithAdapter(Options{
				BaseURL:      mock.srv.URL,
				ProviderName: a.name,
				Timeout:      5 * time.Second,
			})
			require.NoError(t, err)

			out, err := client.ForwardJSON(context.Background(), []byte(conformanceChatBody), "reg-alias", a.apiKeyOr("k"))
			require.NoError(t, err)
			require.NotEmpty(t, out)

			adapter, err := provider.New(a.name)
			require.NoError(t, err)
			a.assertRequest(t, mock.bodyAt(t, adapter.Path(false)), false)
			if a.assertResponse != nil {
				a.assertResponse(t, out)
			}
		})
	}
}

func TestAdapterConformance_Stream(t *testing.T) {
	t.Parallel()
	for _, a := range conformanceAdapters() {
		t.Run(a.name, func(t *testing.T) {
			t.Parallel()
			mock := newConformanceMock(t, a, true, conformanceStreamResponse)

			client, err := newTestClientWithAdapter(Options{
				BaseURL:      mock.srv.URL,
				ProviderName: a.name,
				Timeout:      5 * time.Second,
			})
			require.NoError(t, err)
			require.Zero(t, client.client.Timeout,
				"the pool client must never carry http.Client.Timeout — it bounds body reads and kills streams")

			// Mirror the gateway: per-hop model rewrite happens before Stream.
			body := OverrideModel([]byte(conformanceChatBody), "reg-alias")
			resp, err := client.Stream(context.Background(), body, a.apiKeyOr("k"))
			require.NoError(t, err)
			defer resp.Body.Close()
			data, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Contains(t, string(data), "[DONE]")

			adapter, err := provider.New(a.name)
			require.NoError(t, err)
			a.assertRequest(t, mock.bodyAt(t, adapter.Path(true)), true)
		})
	}
}
