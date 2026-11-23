package cli

// gwcov_g4_endpoints_test.go — TEST-ONLY coverage recovery (task G4).
//
// Independent behavioral and fault-injection tests for the five OpenAI-compat
// paid endpoints (completions, embeddings, images, moderations, rerank),
// covering the block spans listed in the G4 assignment. Every test drives the
// REAL route handler through the production router (auth middleware + routes)
// and asserts the externally visible contract (status, envelope, durable
// side effects in the fake invocation store, zero-provider-arrival posture),
// never a mock's own echo.
//
// Shared fixtures from the package (fakeInvocationStore, stubModelResolver,
// newTestResolver, newFakePolicyStore, newTestRuntime, chatAttachment-style
// attachments) are reused read-only; all G4-local helpers carry the g4 prefix.

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/gateway/internal/routehint"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/router"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// --- g4 fixtures -------------------------------------------------------------

// g4ErrReader fails every Read: injects the client-body read failure the
// legacy completions parser answers with plain 400.
type g4ErrReader struct{}

func (g4ErrReader) Read([]byte) (int, error) { return 0, errors.New("g4: body read failure") }

// g4NoFlush hides Flush from the handler while still recording the exchange:
// requireStreamFlusher must refuse a streaming dispatch on a non-flusher.
type g4NoFlush struct{ rec *httptest.ResponseRecorder }

func (w *g4NoFlush) Header() http.Header       { return w.rec.Header() }
func (w *g4NoFlush) Write(p []byte) (int, error) { return w.rec.Write(p) }
func (w *g4NoFlush) WriteHeader(code int)      { w.rec.WriteHeader(code) }

// g4Gateway builds the strict-key gateway over one stub model row and a live
// fake invocation store, mirroring the package's endpoint-test harness.
func g4Gateway(t *testing.T, info resolver.ModelInfo) (*gateway, *fakeInvocationStore) {
	t.Helper()
	store := &fakeInvocationStore{}
	cfg := config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: info.UpstreamURL}
	gw := &gateway{
		cfg:         cfg,
		log:         slog.New(slog.DiscardHandler),
		auth:        NewAuthMiddleware(cfg, newTestResolver("org-test", nil)),
		res:         stubModelResolver{"m": info, info.ModelName: info},
		pool:        upstream.NewPool(upstream.Options{}),
		invocations: store,
	}
	return gw, store
}

// g4Serve posts one JSON body through the production router.
func g4Serve(t *testing.T, gw *gateway, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return g4ServeCtx(t, gw, t.Context(), path, strings.NewReader(body))
}

// g4ServeCtx posts through the production router with a caller-owned context
// (route hints, client cancellation).
func g4ServeCtx(t *testing.T, gw *gateway, ctx context.Context, path string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, path, body)
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

// g4ServeW posts through the production router onto a caller-owned writer
// (the non-flusher refusal).
func g4ServeW(t *testing.T, gw *gateway, w http.ResponseWriter, path, body string) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(w, req)
}

// g4JSONUpstream serves one counted JSON reply with the given status.
func g4JSONUpstream(t *testing.T, status int, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

// g4DenyAdmission is the enforce-mode controller with nothing priced: Plan
// fails closed with ErrUnpricedModel before any upstream traffic (I3), which
// the routes answer with the 403 model_unpriced reservation denial.
func g4DenyAdmission() *budget.Admission {
	return budget.NewAdmission(nil, budget.ScopedRateSource{}, nil, "test", budget.ModeEnforce,
		func(context.Context, string) (budget.OrgSettings, error) {
			return budget.OrgSettings{Mode: budget.ModeEnforce}, nil
		}, budget.AdmissionConfig{})
}

// g4CompletionsAttachment attaches a policy to the completions endpoint for
// every key and model (plansFor matches the endpoint exactly).
func g4CompletionsAttachment(priority int) adminstore.PolicyAttachment {
	return adminstore.PolicyAttachment{KeyLabel: "", ModelPattern: "*", Endpoint: "completions", Priority: priority}
}

// g4PostDenyYAML is a post_upstream enforce policy denying bodies containing
// the trigger word.
func g4PostDenyYAML(name, word string) string {
	return "apiVersion: ypp/v1\nkind: Policy\nname: " + name + "\nmode: enforce\nhooks:\n  - post_upstream\nsteps:\n  - id: word\n    detector: builtin/contains\n    params:\n      words: [\"" + word + "\"]\n      action: deny\n"
}

// g4BadURL is a well-formed-looking upstream origin that the pool refuses:
// only http/https schemes are admitted, so client construction fails.
const g4BadURL = "ftp://upstream.invalid"

// --- completions: client-shape refusals (33, 38, 42, 95) ---------------------

func TestGWCovG4_Completions_ParseRefusals(t *testing.T) {
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "fim", Provider: "openai", UpstreamURL: "http://127.0.0.1:9", Enabled: true})

	t.Run("body read failure answers plain 400", func(t *testing.T) {
		rec := g4ServeCtx(t, gw, t.Context(), "/v1/completions", g4ErrReader{})
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "request body too large or malformed")
	})
	t.Run("malformed JSON", func(t *testing.T) {
		rec := g4Serve(t, gw, "/v1/completions", `{"model":`)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "malformed JSON")
	})
	t.Run("model is required", func(t *testing.T) {
		rec := g4Serve(t, gw, "/v1/completions", `{"prompt":"abc"}`)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "model is required")
	})
	require.Empty(t, store.admitted, "a refused parse must leave no durable trace")
}

// --- completions: unsupported provider (107) ---------------------------------

func TestGWCovG4_Completions_UnsupportedProviderRefused(t *testing.T) {
	up, hits := g4JSONUpstream(t, http.StatusOK, `{}`)
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "claude-x", Provider: "anthropic", UpstreamURL: up.URL, Enabled: true})

	rec := g4Serve(t, gw, "/v1/completions", `{"model":"m","prompt":"abc"}`)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "completions are not supported for this provider")
	require.Contains(t, rec.Body.String(), "completions_not_supported_for_provider")
	require.Zero(t, hits.Load(), "an unsupported provider must never be dialed")
	require.Empty(t, store.admitted)
}

// --- completions: foreign route hint refused before reservation (65) ---------

func TestGWCovG4_Completions_ForeignRouteHintRefused(t *testing.T) {
	up, hits := g4JSONUpstream(t, http.StatusOK, `{}`)
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "fim", Provider: "openai", UpstreamURL: up.URL, Enabled: true})

	// An enforce-mode route hint foreign to the single-candidate pipeline
	// rides the request context (the policy stage would plant it there).
	ctx := routehint.WithHint(t.Context(), "vertex")
	rec := g4ServeCtx(t, gw, ctx, "/v1/completions", strings.NewReader(`{"model":"m","prompt":"abc"}`))

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), router.HintUnsatisfiableCode)
	require.Contains(t, rec.Body.String(), "vertex")
	require.Zero(t, hits.Load(), "the refusal must precede any provider attempt")
	require.Empty(t, store.admitted, "no reservation may settle escrow for a refused hint")
}

// --- completions: reservation denial (127) ------------------------------------

func TestGWCovG4_Completions_ReserveDeniedUnpricedModel(t *testing.T) {
	up, hits := g4JSONUpstream(t, http.StatusOK, `{}`)
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "fim", Provider: "openai", UpstreamURL: up.URL, Enabled: true})
	gw.admission = g4DenyAdmission()

	rec := g4Serve(t, gw, "/v1/completions", `{"model":"m","prompt":"abc"}`)

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "model_unpriced")
	require.Contains(t, rec.Body.String(), "model pricing unavailable")
	require.Zero(t, hits.Load(), "an unpriced enforce-mode request must fail closed before dispatch")
	require.Empty(t, store.admitted)
}

// --- completions: upstream client init failure (132) --------------------------

func TestGWCovG4_Completions_UpstreamClientInitFails(t *testing.T) {
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "fim", Provider: "openai", UpstreamURL: g4BadURL, Enabled: true})

	rec := g4Serve(t, gw, "/v1/completions", `{"model":"m","prompt":"abc"}`)

	require.Equal(t, http.StatusBadGateway, rec.Code)
	require.Contains(t, rec.Body.String(), "failed to initialise upstream client")
	require.Empty(t, store.admitted, "the pool refusal precedes the durable start")
}

// --- completions: non-flusher stream refusal (135) ----------------------------

func TestGWCovG4_Completions_StreamNonFlusherRefused(t *testing.T) {
	up, hits := g4JSONUpstream(t, http.StatusOK, `{}`)
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "fim", Provider: "openai", UpstreamURL: up.URL, Enabled: true})

	rec := httptest.NewRecorder()
	g4ServeW(t, gw, &g4NoFlush{rec: rec}, "/v1/completions", `{"model":"m","prompt":"abc","stream":true}`)

	require.Equal(t, http.StatusNotImplemented, rec.Code)
	require.Contains(t, rec.Body.String(), "streaming not supported by server")
	require.Zero(t, hits.Load(), "a refused stream must have zero provider arrivals")
	require.Empty(t, store.admitted, "the refusal lands before the durable start")
}

// --- completions: post-upstream policy deny (212, 215, 221) -------------------

func TestGWCovG4_Completions_PostUpstreamPolicyDeny(t *testing.T) {
	const trigger = "g4-forbidden-token"
	up, hits := g4JSONUpstream(t, http.StatusOK,
		`{"id":"cmpl","choices":[{"text":"here is the g4-forbidden-token leak"}]}`)
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "fim", Provider: "openai", UpstreamURL: up.URL, Enabled: true})

	pstore := newFakePolicyStore()
	pstore.add("org-test", adminstore.PolicyPipeline{
		ID: "g4-deny", OrgID: "org-test", Name: "g4-deny", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: g4PostDenyYAML("g4-deny", trigger)},
		[]adminstore.PolicyAttachment{g4CompletionsAttachment(10)})
	gw.policyRuntime = newTestRuntime(t, pstore, &fakePolicyVersions{}, PolicyModeEnforce)

	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := g4Serve(t, gw, "/v1/completions", `{"model":"m","prompt":"abc"}`)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), policyDenyErrorCode)
	require.Contains(t, rec.Body.String(), "response blocked by organization policy")
	require.NotContains(t, rec.Body.String(), trigger, "denied content must not reach the client")
	require.EqualValues(t, 1, hits.Load(), "the deny runs post-upstream — the provider call happened")
	require.Len(t, store.admitted, 1)
	require.NotNil(t, ev, "the OP-9 deny record must ride a published event")
	require.Len(t, store.facts, 1, "the denial still settles terminal facts durably")
}

// --- completions: denial settle failure still answers the envelope (219) ------

func TestGWCovG4_Completions_PolicyDeniedFactsCommitFailure(t *testing.T) {
	const trigger = "g4-forbidden-token"
	up, _ := g4JSONUpstream(t, http.StatusOK,
		`{"id":"cmpl","choices":[{"text":"here is the g4-forbidden-token leak"}]}`)
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "fim", Provider: "openai", UpstreamURL: up.URL, Enabled: true})
	store.factsErr = errors.New("g4: facts store down")

	pstore := newFakePolicyStore()
	pstore.add("org-test", adminstore.PolicyPipeline{
		ID: "g4-deny2", OrgID: "org-test", Name: "g4-deny2", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: g4PostDenyYAML("g4-deny2", trigger)},
		[]adminstore.PolicyAttachment{g4CompletionsAttachment(10)})
	gw.policyRuntime = newTestRuntime(t, pstore, &fakePolicyVersions{}, PolicyModeEnforce)

	rec := g4Serve(t, gw, "/v1/completions", `{"model":"m","prompt":"abc"}`)

	// The client envelope is already the policy denial: a failed terminal
	// facts commit is logged loudly but never replaces it with the body.
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), policyDenyErrorCode)
	require.NotContains(t, rec.Body.String(), trigger)
	require.GreaterOrEqual(t, store.factsCalls, 1, "the settle must have attempted the facts commit")
	require.Empty(t, store.facts, "the failed commit leaves no facts row")
}

// --- completions: stream dial failure (265) -----------------------------------

func TestGWCovG4_Completions_StreamUpstreamDialFails(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "fim", Provider: "openai", UpstreamURL: deadURL, Enabled: true})

	rec := g4Serve(t, gw, "/v1/completions", `{"model":"m","prompt":"abc","stream":true}`)

	// SSE headers were committed before the dial; the drain answers with the
	// in-band error frame instead of a status code.
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "upstream request failed")
	require.Len(t, store.admitted, 1, "the stream dispatch was durably started")
	require.Empty(t, store.facts, "a failed dial settles no completed facts")
}

// --- completions: stream status != 200 (272) ----------------------------------

func TestGWCovG4_Completions_StreamUpstreamStatusNotOK(t *testing.T) {
	up, _ := g4JSONUpstream(t, http.StatusInternalServerError, `{"error":{"message":"model overloaded"}}`)
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "fim", Provider: "openai", UpstreamURL: up.URL, Enabled: true})

	rec := g4Serve(t, gw, "/v1/completions", `{"model":"m","prompt":"abc","stream":true}`)

	require.Equal(t, http.StatusOK, rec.Code, "the SSE headers precede the upstream status check")
	require.Contains(t, rec.Body.String(), "upstream request failed")
	require.NotContains(t, rec.Body.String(), "model overloaded", "the provider error body stays off the wire")
	require.Len(t, store.admitted, 1)
	require.Empty(t, store.facts)
}

// --- completions: idle watchdog wired (279) ------------------------------------

func TestGWCovG4_Completions_StreamIdleWatchdogWired(t *testing.T) {
	const content = "data: {\"choices\":[{\"text\":\"hi\"}]}\n\n"
	const done = "data: [DONE]\n\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, content+done)
	}))
	t.Cleanup(server.Close)

	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "fim", Provider: "openai", UpstreamURL: server.URL, Enabled: true})
	gw.streamIdleTimeout = 250 * time.Millisecond // > 0: the drain body is idle-watched

	rec := g4Serve(t, gw, "/v1/completions", `{"model":"m","prompt":"abc","stream":true}`)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `"text":"hi"`)
	require.Contains(t, rec.Body.String(), "[DONE]")
	require.NotContains(t, rec.Body.String(), "stream drain failed", "a fast clean stream must not trip the watchdog")
	require.Len(t, store.admitted, 1)
	require.Len(t, store.facts, 1, "the watched stream still settles exactly once")
}

// --- completions: client cancellation → client_cancel termination (331) -------

func TestGWCovG4_Completions_StreamClientCancelSettlesClientCancel(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"text\":\"partial\"}]}\n\n")
		fl.Flush()
		<-r.Context().Done() // hold the stream open until the gateway hangs up
	}))
	t.Cleanup(upstream.Close)

	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "fim", Provider: "openai", UpstreamURL: upstream.URL, Enabled: true})

	r := chi.NewRouter()
	gw.routes(r)
	served := make(chan struct{})
	face := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.ServeHTTP(w, req)
		defer close(served) // the gateway handler has settled its durable state
	}))
	t.Cleanup(face.Close)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, face.URL+"/v1/completions",
		strings.NewReader(`{"model":"m","prompt":"abc","stream":true}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Read frames until the relayed content arrives: the gateway is now
	// provably mid-drain (blocked awaiting further upstream frames).
	br := bufio.NewReader(resp.Body)
	var clientSaw strings.Builder
	sawFrame := false
	for range 100 {
		line, err := br.ReadString('\n')
		clientSaw.WriteString(line)
		if strings.Contains(line, "partial") {
			sawFrame = true
			break
		}
		if err != nil {
			break
		}
	}
	require.True(t, sawFrame, "the relayed frame must reach the client before the walk-away")

	cancel() // the client walks away mid-drain
	_, _ = io.Copy(io.Discard, br) // drain what still arrives; the context death ends it

	select {
	case <-served:
	case <-time.After(30 * time.Second):
		t.Fatal("the stream handler never settled after cancellation")
	}

	require.NotContains(t, clientSaw.String(), accountingCommitFailedCode, "a client walk-away is not the accounting-withhold path")
	require.Len(t, store.admitted, 1)
	require.Empty(t, store.facts, "a cancelled drain settles the escrow with no completed facts (client_cancel)")
}

// --- embeddings: client-shape refusals (46, 50, 54) ---------------------------

func TestGWCovG4_Embeddings_ParseRefusals(t *testing.T) {
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "emb", Provider: "openai", UpstreamURL: "http://127.0.0.1:9", Enabled: true})

	t.Run("malformed JSON", func(t *testing.T) {
		rec := g4Serve(t, gw, "/v1/embeddings", `{"model":`)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "malformed JSON")
	})
	t.Run("model is required", func(t *testing.T) {
		rec := g4Serve(t, gw, "/v1/embeddings", `{"input":"x"}`)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "model is required")
	})
	t.Run("input is required", func(t *testing.T) {
		for _, body := range []string{`{"model":"m"}`, `{"model":"m","input":null}`} {
			rec := g4Serve(t, gw, "/v1/embeddings", body)
			require.Equal(t, http.StatusBadRequest, rec.Code, body)
			require.Contains(t, rec.Body.String(), "input is required", body)
		}
	})
	require.Empty(t, store.admitted)
}

// --- embeddings: reservation denial (84) ---------------------------------------

func TestGWCovG4_Embeddings_ReserveDeniedUnpricedModel(t *testing.T) {
	up, hits := g4JSONUpstream(t, http.StatusOK, `{}`)
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "emb", Provider: "openai", UpstreamURL: up.URL, Enabled: true})
	gw.admission = g4DenyAdmission()

	rec := g4Serve(t, gw, "/v1/embeddings", `{"model":"m","input":"x"}`)

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "model_unpriced")
	require.Zero(t, hits.Load())
	require.Empty(t, store.admitted)
}

// --- embeddings: upstream client init failure (88) -----------------------------

func TestGWCovG4_Embeddings_UpstreamClientInitFails(t *testing.T) {
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "emb", Provider: "openai", UpstreamURL: g4BadURL, Enabled: true})

	rec := g4Serve(t, gw, "/v1/embeddings", `{"model":"m","input":"x"}`)

	require.Equal(t, http.StatusBadGateway, rec.Code)
	require.Contains(t, rec.Body.String(), "failed to initialise upstream client")
	require.Empty(t, store.admitted)
}

// --- embeddings: dial failure (125) ---------------------------------------------

func TestGWCovG4_Embeddings_UpstreamDialFails(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "emb", Provider: "openai", UpstreamURL: deadURL, Enabled: true})

	rec := g4Serve(t, gw, "/v1/embeddings", `{"model":"m","input":"x"}`)

	require.Equal(t, http.StatusBadGateway, rec.Code)
	require.Contains(t, rec.Body.String(), "upstream request failed")
	require.Len(t, store.admitted, 1, "the dispatch was durably started before the dial")
	require.Empty(t, store.facts)
}

// --- embeddings: interrupted body read (135) -----------------------------------

func TestGWCovG4_Embeddings_InterruptedBodyRead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "4096")
		_, _ = io.WriteString(w, `{"data":[{"embedding":[0.1,0.2`)
	}))
	t.Cleanup(server.Close)

	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "emb", Provider: "openai", UpstreamURL: server.URL, Enabled: true})

	rec := g4Serve(t, gw, "/v1/embeddings", `{"model":"m","input":"x"}`)

	require.Equal(t, http.StatusBadGateway, rec.Code)
	require.Contains(t, rec.Body.String(), "failed to read upstream response")
	require.Equal(t, "false", rec.Header().Get("X-Should-Retry"), "a paid answer that already left must not invite a retry")
	require.Len(t, store.admitted, 1)
	require.Empty(t, store.facts, "a truncated payload cannot establish completed usage")
}

// --- images: reservation denial (105) ------------------------------------------

func TestGWCovG4_Images_ReserveDeniedUnpricedModel(t *testing.T) {
	up, hits := g4JSONUpstream(t, http.StatusOK, `{}`)
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "img", Provider: "openai", UpstreamURL: up.URL, Enabled: true})
	gw.admission = g4DenyAdmission()

	rec := g4Serve(t, gw, "/v1/images/generations", `{"model":"m","prompt":"a cat"}`)

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "model_unpriced")
	require.Zero(t, hits.Load())
	require.Empty(t, store.admitted)
}

// --- images: media dispatch client init failure (110) --------------------------

func TestGWCovG4_Images_MediaDispatchClientInitFails(t *testing.T) {
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "img", Provider: "openai", UpstreamURL: g4BadURL, Enabled: true})

	rec := g4Serve(t, gw, "/v1/images/generations", `{"model":"m","prompt":"a cat"}`)

	require.Equal(t, http.StatusBadGateway, rec.Code)
	require.Contains(t, rec.Body.String(), "failed to initialise upstream client")
	require.Empty(t, store.admitted, "the dispatch refusal precedes the durable start")
}

// --- images: durable start refused (115) ---------------------------------------

func TestGWCovG4_Images_ConfirmPaidStartRefused(t *testing.T) {
	up, hits := g4JSONUpstream(t, http.StatusOK, `{"data":[{"url":"https://img/x.png"}]}`)
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "img", Provider: "openai", UpstreamURL: up.URL, Enabled: true})
	store.admitErr = errors.New("g4: admission store down")

	rec := g4Serve(t, gw, "/v1/images/generations", `{"model":"m","prompt":"a cat"}`)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.Contains(t, rec.Body.String(), "history_unavailable")
	require.Zero(t, hits.Load(), "an unwritten durable start refuses with zero provider arrivals")
	require.Empty(t, store.admitted)
}

// --- images: terminal facts failure withholds the reply (211) ------------------

func TestGWCovG4_Images_TerminalFactsFailureWithholdsReply(t *testing.T) {
	const payload = `{"data":[{"url":"https://img/x.png"}]}`
	up, hits := g4JSONUpstream(t, http.StatusOK, payload)
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "img", Provider: "openai", UpstreamURL: up.URL, Enabled: true})
	store.factsErr = errors.New("g4: facts store down")

	rec := g4Serve(t, gw, "/v1/images/generations", `{"model":"m","prompt":"a cat"}`)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Contains(t, rec.Body.String(), accountingCommitFailedCode)
	require.Equal(t, "false", rec.Header().Get("X-Should-Retry"), "a retry would re-bill under a new invocation")
	require.NotContains(t, rec.Body.String(), payload, "the paid body must not read as a payable success")
	require.EqualValues(t, 1, hits.Load())
	require.Len(t, store.admitted, 1)
	require.Empty(t, store.facts)
}

// --- moderations (88, 92, 138) ---------------------------------------------------

func TestGWCovG4_Moderations_ReserveDeniedUnpricedModel(t *testing.T) {
	up, hits := g4JSONUpstream(t, http.StatusOK, `{}`)
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "mod", Provider: "openai", UpstreamURL: up.URL, Enabled: true})
	gw.admission = g4DenyAdmission()

	rec := g4Serve(t, gw, "/v1/moderations", `{"model":"m","input":"x"}`)

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "model_unpriced")
	require.Zero(t, hits.Load())
	require.Empty(t, store.admitted)
}

func TestGWCovG4_Moderations_UpstreamClientInitFails(t *testing.T) {
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "mod", Provider: "openai", UpstreamURL: g4BadURL, Enabled: true})

	rec := g4Serve(t, gw, "/v1/moderations", `{"model":"m","input":"x"}`)

	require.Equal(t, http.StatusBadGateway, rec.Code)
	require.Contains(t, rec.Body.String(), "failed to initialise upstream client")
	require.Empty(t, store.admitted)
}

func TestGWCovG4_Moderations_InterruptedBodyRead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "4096")
		_, _ = io.WriteString(w, `{"results":[{"flagged":tru`)
	}))
	t.Cleanup(server.Close)

	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "mod", Provider: "openai", UpstreamURL: server.URL, Enabled: true})

	rec := g4Serve(t, gw, "/v1/moderations", `{"model":"m","input":"x"}`)

	require.Equal(t, http.StatusBadGateway, rec.Code)
	require.Contains(t, rec.Body.String(), "failed to read upstream response")
	require.Equal(t, "false", rec.Header().Get("X-Should-Retry"))
	require.Len(t, store.admitted, 1)
	require.Empty(t, store.facts)
}

// --- rerank (89, 93, 139) ---------------------------------------------------------

func TestGWCovG4_Rerank_ReserveDeniedUnpricedModel(t *testing.T) {
	up, hits := g4JSONUpstream(t, http.StatusOK, `{}`)
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "rr", Provider: "openai", UpstreamURL: up.URL, Enabled: true})
	gw.admission = g4DenyAdmission()

	rec := g4Serve(t, gw, "/v1/rerank", `{"model":"m","query":"q","documents":["a","b"]}`)

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "model_unpriced")
	require.Zero(t, hits.Load())
	require.Empty(t, store.admitted)
}

func TestGWCovG4_Rerank_UpstreamClientInitFails(t *testing.T) {
	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "rr", Provider: "openai", UpstreamURL: g4BadURL, Enabled: true})

	rec := g4Serve(t, gw, "/v1/rerank", `{"model":"m","query":"q","documents":["a","b"]}`)

	require.Equal(t, http.StatusBadGateway, rec.Code)
	require.Contains(t, rec.Body.String(), "failed to initialise upstream client")
	require.Empty(t, store.admitted)
}

func TestGWCovG4_Rerank_InterruptedBodyRead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "4096")
		_, _ = io.WriteString(w, `{"results":[{"index":0,"relevance_sco`)
	}))
	t.Cleanup(server.Close)

	gw, store := g4Gateway(t, resolver.ModelInfo{ModelName: "rr", Provider: "openai", UpstreamURL: server.URL, Enabled: true})

	rec := g4Serve(t, gw, "/v1/rerank", `{"model":"m","query":"q","documents":["a","b"]}`)

	require.Equal(t, http.StatusBadGateway, rec.Code)
	require.Contains(t, rec.Body.String(), "failed to read upstream response")
	require.Equal(t, "false", rec.Header().Get("X-Should-Retry"))
	require.Len(t, store.admitted, 1)
	require.Empty(t, store.facts)
}
