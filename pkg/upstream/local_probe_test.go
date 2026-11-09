package upstream

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/testutil/mockopenai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for the local probe executor (N08-P04-T03): the network half of the
// discovery / availability / health split. Every server is an httptest
// loopback stand-in for a local runtime — no external network, fully
// deterministic.

const probeRegistryModel = "registry-qwen"

// newProbeTestClient builds a guarded client pinned to one local fixture
// server with the named adapter.
func newProbeTestClient(t *testing.T, srv *httptest.Server, providerName string) *Client {
	t.Helper()
	c, err := newTestClientWithAdapter(Options{
		BaseURL:          srv.URL,
		ProviderName:     providerName,
		AllowedUpstreams: []string{srv.URL},
	})
	require.NoError(t, err)
	return c
}

// probeRecorder is a raw httptest handler that records every dial and
// answers with a fixed status/body, or — when respond is set — with a
// body-dependent status/body. mockopenai cannot serve the negative cases
// (it answers any path), so the 404 / validation-refusal fixtures use this
// recorder instead.
type probeRecorder struct {
	mu      sync.Mutex
	status  int
	body    string
	respond func(body string) (status int, respBody string)
	reqs    []recordedProbe
}

type recordedProbe struct {
	Method string
	Path   string
	Body   string
	Host   string
	Auth   string
}

func (r *probeRecorder) handle(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	rec := recordedProbe{
		Method: req.Method,
		Path:   req.URL.Path,
		Body:   string(body),
		Host:   req.Host,
		Auth:   req.Header.Get("Authorization"),
	}
	r.mu.Lock()
	r.reqs = append(r.reqs, rec)
	r.mu.Unlock()
	status, respBody := r.status, r.body
	if r.respond != nil {
		status, respBody = r.respond(string(body))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(respBody))
}

func (r *probeRecorder) dials() []recordedProbe {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedProbe, len(r.reqs))
	copy(out, r.reqs)
	return out
}

// TestProbeLocalModel_HealthyLocalModel is the all-positive path per local
// adapter: discovery static pass, availability probe finds the chat endpoint,
// health probe serves one token — and the wire shows exactly two dials, the
// generation-free availability probe first, the minimal chat second, with
// the registry model name overriding the probe's placeholder.
func TestProbeLocalModel_HealthyLocalModel(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"vllm", "ollama", "llamacpp"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mock := mockopenai.New()
			mock.SetResponse(http.StatusOK, localCompletionBody)
			srv := httptest.NewServer(mock)
			t.Cleanup(srv.Close)
			client := newProbeTestClient(t, srv, name)

			st := client.ProbeLocalModel(context.Background(), LocalProbeRequest{
				Provider: name,
				Model:    probeRegistryModel,
			})

			assert.True(t, st.Discovered, "row must be discovered, got %+v", st)
			assert.True(t, st.Available, "endpoint must be available, got %+v", st)
			assert.True(t, st.Healthy, "model must be healthy, got %+v", st)
			assert.True(t, st.Working, "all-positive row must be working, got %+v", st)
			assert.Equal(t, provider.LocalStateHealthy, st.State)
			assert.Empty(t, st.Reason)
			assert.Equal(t, srv.URL, st.Endpoint)
			assert.Equal(t, "/v1/chat/completions", st.ChatPath)

			reqs := mock.Requests()
			require.Len(t, reqs, 2, "exactly one availability dial + one health dial")
			for _, req := range reqs {
				assert.Equal(t, http.MethodPost, req.Method)
				assert.Equal(t, srv.Listener.Addr().String(), req.Host, "probe traffic stays on the local endpoint")
				assert.Empty(t, req.Header.Get("Authorization"), "local probes are keyless")
			}
			assert.Equal(t, "/v1/chat/completions", reqs[0].Path)
			assert.Equal(t, "{}", reqs[0].Body, "availability probe must be generation-free")

			var sent map[string]any
			require.NoError(t, json.Unmarshal([]byte(reqs[1].Body), &sent))
			assert.Equal(t, probeRegistryModel, sent["model"], "health probe must carry the registry model name")
			assert.InDelta(t, 1, sent["max_tokens"], 0, "health probe generates one token")
			assert.Equal(t, false, sent["stream"])
			assert.Contains(t, sent, "messages")
		})
	}
}

// TestProbeLocalModel_InstalledModelMissingEndpoint_NotWorking is the card's
// negative contract: an installed model whose endpoint answers but lacks the
// required chat serving endpoint is reported endpoint-missing and can never
// render as available/healthy/working. The wire must show ONE dial only —
// the generation-free availability probe — and no health attempt through a
// route that does not exist.
func TestProbeLocalModel_InstalledModelMissingEndpoint_NotWorking(t *testing.T) {
	t.Parallel()

	rec := &probeRecorder{status: http.StatusNotFound, body: `{"error":{"message":"no such route","type":"not_found_error"}}`}
	srv := httptest.NewServer(http.HandlerFunc(rec.handle))
	t.Cleanup(srv.Close)
	client := newProbeTestClient(t, srv, "vllm")

	st := client.ProbeLocalModel(context.Background(), LocalProbeRequest{
		Provider: "vllm",
		Model:    probeRegistryModel,
	})

	assert.True(t, st.Discovered, "the model IS installed — discovery stays positive")
	assert.False(t, st.Available, "missing endpoint must fail availability")
	assert.False(t, st.Healthy, "missing endpoint must never report a healthy model")
	assert.False(t, st.Working, "installed-but-unservable must never render working")
	assert.Equal(t, provider.LocalStateEndpointMissing, st.State)
	assert.Contains(t, st.Reason, "HTTP 404")
	assert.Contains(t, st.Reason, "/v1/chat/completions")
	assert.Contains(t, st.Reason, srv.URL)

	dials := rec.dials()
	require.Len(t, dials, 1, "availability probe only; health must be skipped for a missing endpoint")
	assert.Equal(t, "{}", dials[0].Body, "the only dial must be the generation-free probe")
}

// TestProbeLocalModel_DeadEndpoint_Unreachable: a closed port proves the
// unreachable state without any flaky timing (deterministic connection
// refusal on loopback).
func TestProbeLocalModel_DeadEndpoint_Unreachable(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // nothing listens anymore

	client := newProbeTestClient(t, srv, "ollama") // guard list pins the now-dead URL; no dial can succeed

	st := client.ProbeLocalModel(context.Background(), LocalProbeRequest{
		Provider: "ollama",
		Model:    probeRegistryModel,
	})

	assert.True(t, st.Discovered)
	assert.False(t, st.Available)
	assert.False(t, st.Healthy)
	assert.False(t, st.Working)
	assert.Equal(t, provider.LocalStateUnreachable, st.State)
	assert.Contains(t, st.Reason, "unreachable")
	assert.Contains(t, st.Reason, "connection refused")
}

// TestProbeLocalModel_EndpointPresentButModelNotServing_Unhealthy: the route
// exists (validation refusal on the generation-free probe) but the live
// serving check fails — the surfaced row must be unhealthy (not merely
// "unavailable") and carry the endpoint's own refusal verbatim (I51).
func TestProbeLocalModel_EndpointPresentButModelNotServing_Unhealthy(t *testing.T) {
	t.Parallel()

	upstreamBody := `{"object":"error","message":"The model 'registry-qwen' does not exist.","type":"invalid_request_error"}`
	rec := &probeRecorder{
		respond: func(body string) (int, string) {
			if strings.Contains(body, "messages") {
				return http.StatusNotFound, upstreamBody
			}
			// Generation-free probe hits the real route: schema validation
			// refuses it — proof the endpoint is present without generating.
			return http.StatusBadRequest, `{"error":{"message":"empty request"}}`
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(rec.handle))
	t.Cleanup(srv.Close)
	client := newProbeTestClient(t, srv, "vllm")

	st := client.ProbeLocalModel(context.Background(), LocalProbeRequest{
		Provider: "vllm",
		Model:    probeRegistryModel,
	})

	assert.True(t, st.Discovered)
	assert.True(t, st.Available, "route exists — availability is met")
	assert.False(t, st.Healthy, "the model is not actually serving")
	assert.False(t, st.Working)
	assert.Equal(t, provider.LocalStateUnhealthy, st.State)
	assert.Contains(t, st.Reason, "upstream error 404")
	assert.Contains(t, st.Reason, "does not exist", "endpoint's own refusal must reach the surface verbatim")

	dials := rec.dials()
	require.Len(t, dials, 2, "availability probe + failed health probe")
	assert.Equal(t, "{}", dials[0].Body)
	var sent map[string]any
	require.NoError(t, json.Unmarshal([]byte(dials[1].Body), &sent))
	assert.Equal(t, probeRegistryModel, sent["model"])
	assert.InDelta(t, 1, sent["max_tokens"], 0)
}

// TestProbeLocalModel_MinimalMode_CloudFreeRequest is the card's acceptance
// proof: with an egress allow-list containing ONLY the local endpoint
// (loopback stand-in) and no cloud model installed, a resolved local row is
// probed healthy and serves a full chat request — every wire hit on the
// loopback host, zero Authorization, provider-parsed usage, and the guarded
// pool refusing a cloud host outright.
func TestProbeLocalModel_MinimalMode_CloudFreeRequest(t *testing.T) {
	t.Parallel()

	mock := mockopenai.New()
	mock.SetResponse(http.StatusOK, localCompletionBody)
	srv := httptest.NewServer(mock)
	t.Cleanup(srv.Close)

	// Minimal-mode egress: the local endpoint only. No cloud upstreams are
	// configured, so no cloud host can be dialed through this pool.
	pool := NewPool(Options{AllowedUpstreams: []string{srv.URL}})
	client, err := pool.Get(srv.URL, "llamacpp")
	require.NoError(t, err)
	require.Equal(t, "llamacpp", client.Adapter().Name())

	// 1) The new three-state surface says the local model is working.
	st := client.ProbeLocalModel(context.Background(), LocalProbeRequest{
		Provider: "llamacpp",
		Model:    "local-qwen",
	})
	require.True(t, st.Working, "local row must be working in minimal mode, got %+v", st)
	require.Equal(t, provider.LocalStateHealthy, st.State)

	// 2) The same guarded client serves the real request, cloud-free.
	mi := resolver.ModelInfo{
		ModelName:       "local-qwen",
		DisplayName:     "Local Qwen",
		Tier:            "smart",
		UpstreamURL:     srv.URL,
		UpstreamTimeout: 2 * time.Second,
		Provider:        "llamacpp",
		Enabled:         true,
	}
	chatBody := []byte(`{"model":"any-alias","messages":[{"role":"user","content":"ping"}],"max_tokens":16}`)
	_, respBody, _, ferr := client.ForwardJSONCapturing(context.Background(), chatBody, mi.ModelName, "", mi.UpstreamTimeout)
	require.NoError(t, ferr)

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	require.NoError(t, json.Unmarshal(respBody, &out))
	require.NotEmpty(t, out.Choices)
	assert.Equal(t, "pong", out.Choices[0].Message.Content)

	// 3) Wire audit: every dial (availability, health, real request) stayed
	// on the loopback stand-in, keyless; usage came from the provider body.
	reqs := mock.Requests()
	require.Len(t, reqs, 3)
	loopback := srv.Listener.Addr().String()
	for _, req := range reqs {
		assert.Equal(t, loopback, req.Host, "zero cloud access: all traffic on the local endpoint")
		assert.Empty(t, req.Header.Get("Authorization"), "zero cloud access: no credentials anywhere")
	}
	u := client.Adapter().ParseUsage(respBody)
	assert.Equal(t, provider.UsageSourceProvider, u.Source)
	assert.Equal(t, int64(11), u.PromptTokens)
	assert.Equal(t, int64(5), u.CompletionTokens)

	// 4) Negative guard: a cloud host is refused before any dial.
	_, cloudErr := pool.Get("https://api.openai.com", "llamacpp")
	require.Error(t, cloudErr)
	assert.Contains(t, cloudErr.Error(), "not in the allowed list")
}

// TestProbeLocalModel_TGI_TranslatingAdapter completes the four-adapter
// matrix: TGI is the only local runtime whose wire bodies are NOT OpenAI
// JSON — both probe dials go through TranslateChatToTGI in PrepareRequest
// (availability: the generation-free body becomes empty inputs; health: the
// one-token chat becomes inputs+parameters on /generate) and the response
// must survive TranslateResponse's generated_text→OpenAI wrap, else Serving
// stays false. mockopenai cannot stand in for that: it would accept any body
// on any path and let a TGI-shaped check pass dishonestly, so the fixture
// validates the TGI schema itself.
func TestProbeLocalModel_TGI_TranslatingAdapter(t *testing.T) {
	t.Parallel()

	rec := &probeRecorder{
		respond: func(body string) (int, string) {
			var tgiBody struct {
				Inputs     string `json:"inputs"`
				Parameters struct {
					MaxNewTokens int `json:"max_new_tokens"`
				} `json:"parameters"`
			}
			if err := json.Unmarshal([]byte(body), &tgiBody); err != nil {
				return http.StatusBadRequest, `{"error":"not tgi-shaped"}`
			}
			if tgiBody.Parameters.MaxNewTokens == 1 {
				return http.StatusOK, `{"generated_text":"pong"}`
			}
			// Availability dial: empty inputs, zero tokens — schema-valid but
			// refused without generating (real TGI behaviour), 404 absent so
			// the route's existence is still proven.
			return http.StatusBadRequest, `{"error":{"message":"inputs must not be empty","type":"invalid_request_error"}}`
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(rec.handle))
	t.Cleanup(srv.Close)
	client := newProbeTestClient(t, srv, "tgi")

	st := client.ProbeLocalModel(context.Background(), LocalProbeRequest{
		Provider: "tgi",
		Model:    probeRegistryModel,
	})

	assert.True(t, st.Discovered)
	assert.True(t, st.Available, "validation refusal on /generate proves the route exists, got %+v", st)
	assert.True(t, st.Healthy, "generated_text must survive the translate round trip, got %+v", st)
	assert.True(t, st.Working)
	assert.Equal(t, provider.LocalStateHealthy, st.State)
	assert.Empty(t, st.Reason)
	assert.Equal(t, "/generate", st.ChatPath, "TGI serves on its own /generate endpoint, not the OpenAI path")

	dials := rec.dials()
	require.Len(t, dials, 2, "availability + health, both translated to TGI shape")
	assert.Equal(t, "/generate", dials[0].Path)
	assert.Equal(t, "/generate", dials[1].Path)

	var avail struct {
		Inputs     string `json:"inputs"`
		Parameters struct {
			MaxNewTokens int `json:"max_new_tokens"`
		} `json:"parameters"`
	}
	require.NoError(t, json.Unmarshal([]byte(dials[0].Body), &avail))
	assert.Empty(t, avail.Inputs, "availability probe must stay generation-free after TGI translation")
	assert.InDelta(t, 0, avail.Parameters.MaxNewTokens, 0)

	var health struct {
		Inputs     string `json:"inputs"`
		Parameters struct {
			MaxNewTokens int `json:"max_new_tokens"`
		} `json:"parameters"`
	}
	require.NoError(t, json.Unmarshal([]byte(dials[1].Body), &health))
	assert.Contains(t, health.Inputs, "user: ping", "chat messages must flatten into the TGI prompt")
	assert.InDelta(t, 1, health.Parameters.MaxNewTokens, 0, "health probe generates one token")
}

// TestProbeLocalModel_BoundedTimeouts: both probes are bounded; a stalled
// runtime degrades the row into its honest negative state within the
// configured budget instead of hanging the caller.
func TestProbeLocalModel_BoundedTimeouts(t *testing.T) {
	t.Parallel()

	t.Run("availability timeout", func(t *testing.T) {
		t.Parallel()

		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			<-release // stalled runtime: the probe must hit its own deadline
		}))
		t.Cleanup(srv.Close)
		t.Cleanup(func() { close(release) }) // LIFO: unblock handlers before srv.Close
		client := newProbeTestClient(t, srv, "vllm")

		start := time.Now()
		st := client.ProbeLocalModel(context.Background(), LocalProbeRequest{
			Provider:            "vllm",
			Model:               probeRegistryModel,
			AvailabilityTimeout: 150 * time.Millisecond,
		})
		elapsed := time.Since(start)

		require.Less(t, elapsed, 5*time.Second, "availability probe must respect its bounded budget")
		assert.False(t, st.Available)
		assert.False(t, st.Healthy)
		assert.False(t, st.Working)
		assert.Equal(t, provider.LocalStateUnreachable, st.State)
		assert.Contains(t, st.Reason, "unreachable")
		assert.Contains(t, st.Reason, "upstream request timeout")
	})

	t.Run("health timeout after available endpoint", func(t *testing.T) {
		t.Parallel()

		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			body, _ := io.ReadAll(req.Body)
			if strings.Contains(string(body), "messages") {
				<-release // health probe stalls: one-token chat never returns
				return
			}
			w.WriteHeader(http.StatusBadRequest) // generation-free probe passes instantly
		}))
		t.Cleanup(srv.Close)
		t.Cleanup(func() { close(release) })
		client := newProbeTestClient(t, srv, "vllm")

		start := time.Now()
		st := client.ProbeLocalModel(context.Background(), LocalProbeRequest{
			Provider:            "vllm",
			Model:               probeRegistryModel,
			AvailabilityTimeout: 2 * time.Second,
			HealthTimeout:       150 * time.Millisecond,
		})
		elapsed := time.Since(start)

		require.Less(t, elapsed, 10*time.Second, "health probe must respect its bounded budget")
		assert.True(t, st.Available)
		assert.False(t, st.Healthy)
		assert.False(t, st.Working)
		assert.Equal(t, provider.LocalStateUnhealthy, st.State)
		assert.Contains(t, st.Reason, "upstream request timeout")
	})
}
