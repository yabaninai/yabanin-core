package cli

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/gateway/internal/routehint"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/router"
)

// consumer entry point (the full chatCompletions / messages handlers), not a
// direct helper call. Each test drives the complete stage pipeline —
// normalize → route → policy gate → policyPreUpstream (route_hint step) →
// hint stamp → executeChatJSON → fallback chain → a synthetic upstream over
// real HTTP — so the packet criterion ("Hint влияет на допустимый маршрут
// либо получает явный отказ") is observed at the wire boundary: which
// provider endpoint is actually dialed, or the explicit 400 refusal envelope
// with zero dials.

// r017IntUpstream is one synthetic provider endpoint. It records every
// dialed model and answers an OpenAI-shaped completion whose id names the
// endpoint (the marker is observable in the client response body, proving
// which upstream served the request).
type r017IntUpstream struct {
	srv    *httptest.Server
	id     string
	status int
	calls  atomic.Int32

	mu     sync.Mutex
	models []string
}

func newR017IntUpstream(t *testing.T, id string, status int) *r017IntUpstream {
	t.Helper()
	u := &r017IntUpstream{id: id, status: status}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.calls.Add(1)
		raw, _ := io.ReadAll(r.Body)
		var body struct {
			Model string `json:"model"`
		}
		_ = json.Unmarshal(raw, &body)
		u.mu.Lock()
		u.models = append(u.models, body.Model)
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if u.status != http.StatusOK {
			w.WriteHeader(u.status)
			_, _ = w.Write([]byte(`{"error":{"message":"upstream down","type":"api_error"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"` + u.id + `","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *r017IntUpstream) calledModels() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.models...)
}

// r017IntChainDB is the model registry behind the real resolver: a primary
// on "openai" with two failover candidates — one on "anthropic" (the hinted
// provider) and one more on "openai" — each pointing at its own endpoint.
func r017IntChainDB(openaiURL, anthropicURL string) *rt06ModelDB {
	return &rt06ModelDB{rows: map[string][]any{
		"r017-primary":   {"r017-primary", "r017-primary display", "standard", openaiURL, "", "openai", []string{"r017-secondary", "r017-tertiary"}, true, int64(0), "EU"},
		"r017-secondary": {"r017-secondary", "r017-secondary display", "standard", anthropicURL, "", "anthropic", nil, true, int64(0), "EU"},
		"r017-tertiary":  {"r017-tertiary", "r017-tertiary display", "standard", openaiURL, "", "openai", nil, true, int64(0), "EU"},
	}}
}

// r017IntChatGateway wires the full chat entry (gw.chatCompletions) over a
// real DB-backed resolver, the real fallback executor sharing it, and a real
// policy runtime loaded from store (snapshot → compiled route_hint step).
func r017IntChatGateway(t *testing.T, mode PolicyMode, store *fakePolicyStore, db *rt06ModelDB, openaiURL string) *gateway {
	t.Helper()
	res := resolver.NewResolver(db, "r017-default", time.Minute, slog.New(slog.DiscardHandler))
	gw := streamTestGateway(openaiURL)
	gw.log = slog.New(slog.DiscardHandler)
	gw.res = res
	gw.fallback = router.NewFallbackExecutor(res, 3, slog.New(slog.DiscardHandler))
	gw.policyRuntime = newTestRuntime(t, store, &fakePolicyVersions{}, mode)
	return gw
}

// r017IntChat posts a non-streaming chat completion to the real handler.
func r017IntChat(t *testing.T, gw *gateway) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"model":"r017-primary","messages":[{"role":"user","content":"hi"}]}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("X-Org-Id", testOrg)
	r.Header.Set("X-Session-Id", "sess-r017")
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)
	return rec
}

// r017MessagesAttachment is the org-wide attachment for the native messages
// endpoint (the chatAttachment shape with Endpoint "messages").
func r017MessagesAttachment(priority int) adminstore.PolicyAttachment {
	return adminstore.PolicyAttachment{KeyLabel: "", ModelPattern: "*", Endpoint: "messages", Priority: priority}
}

// Main scenario at the wire boundary: an enforce-mode route_hint policy
// steers REAL provider selection — the hinted provider's endpoint is dialed
// (and serves the client response) while the declaration-order primary is
// never called, and the decision record on the completed event shows the
// applied hint (OP-9 visibility through the full pipeline).
func TestR017Integration_ChatEntry_HintSteersProviderSelection(t *testing.T) {
	anth := newR017IntUpstream(t, "upstream-anthropic", http.StatusOK)
	openai := newR017IntUpstream(t, "upstream-openai", http.StatusOK)
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "hint-1", OrgID: testOrg, Name: "hint-route", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: routeHintYAML("hint-route", "anthropic")}, []adminstore.PolicyAttachment{chatAttachment(10)})
	gw := r017IntChatGateway(t, PolicyModeEnforce, store, r017IntChainDB(openai.srv.URL, anth.srv.URL), openai.srv.URL)

	events := captureEvents(t)
	rec := r017IntChat(t, gw)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "upstream-anthropic", "the hinted provider's endpoint must serve the response")
	assert.Equal(t, int32(1), anth.calls.Load())
	assert.Equal(t, []string{"r017-secondary"}, anth.calledModels())
	assert.Equal(t, int32(0), openai.calls.Load(), "the hint must steer away from the declaration-order primary")

	var completed *eventpub.Event
	for _, e := range events() {
		if e.EventType == "request.completed" {
			completed = e
		}
	}
	require.NotNil(t, completed, "the served request must publish its analytics event")
	decisions := parseDecisions(t, completed.Policy)
	require.Len(t, decisions, 1)
	require.Len(t, decisions[0].Findings, 1, "the decision record must surface the applied hint")
	assert.Equal(t, routehint.FindingCategory, decisions[0].Findings[0].Category)
}

// Reorder, not removal, at the wire boundary: the hinted candidate is
// attempted first, and when it fails the chain falls through in declaration
// order — the primary serves, the tertiary is never needed.
func TestR017Integration_ChatEntry_HintedCandidateFailsFallsThroughInDeclaredOrder(t *testing.T) {
	anth := newR017IntUpstream(t, "upstream-anthropic", http.StatusInternalServerError)
	openai := newR017IntUpstream(t, "upstream-openai", http.StatusOK)
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "hint-1", OrgID: testOrg, Name: "hint-route", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: routeHintYAML("hint-route", "anthropic")}, []adminstore.PolicyAttachment{chatAttachment(10)})
	gw := r017IntChatGateway(t, PolicyModeEnforce, store, r017IntChainDB(openai.srv.URL, anth.srv.URL), openai.srv.URL)

	rec := r017IntChat(t, gw)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "upstream-openai", "the chain falls through to the primary endpoint")
	assert.Equal(t, int32(1), anth.calls.Load())
	assert.Equal(t, []string{"r017-secondary"}, anth.calledModels(), "the hinted candidate is attempted first")
	assert.Equal(t, int32(1), openai.calls.Load())
	assert.Equal(t, []string{"r017-primary"}, openai.calledModels(),
		"fall-through resumes declaration order at the primary — the tertiary candidate is never dialed")
}

// Negative scenario at the wire boundary: an enforce-mode hint no candidate
// can satisfy refuses explicitly — 400 route_hint_unsatisfiable before any
// provider is dialed, and no successful request is recorded.
func TestR017Integration_ChatEntry_UnmatchedHintRefused400NoDial(t *testing.T) {
	anth := newR017IntUpstream(t, "upstream-anthropic", http.StatusOK)
	openai := newR017IntUpstream(t, "upstream-openai", http.StatusOK)
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "hint-1", OrgID: testOrg, Name: "hint-route", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: routeHintYAML("hint-route", "vertex")}, []adminstore.PolicyAttachment{chatAttachment(10)})
	gw := r017IntChatGateway(t, PolicyModeEnforce, store, r017IntChainDB(openai.srv.URL, anth.srv.URL), openai.srv.URL)

	events := captureEvents(t)
	rec := r017IntChat(t, gw)

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	body := rec.Body.String()
	assert.Contains(t, body, router.HintUnsatisfiableCode)
	assert.Contains(t, body, router.HintUnsatisfiableErrType)
	assert.Contains(t, body, "vertex", "the unsatisfiable hint is named for diagnosis")
	assert.Equal(t, int32(0), anth.calls.Load())
	assert.Equal(t, int32(0), openai.calls.Load(), "a refusal must not dial any provider")
	for _, e := range events() {
		assert.NotEqual(t, "request.completed", e.EventType, "a refused request must not complete")
	}
}

// Carried union-merge #4 note ("equal-priority hint composition order
// unpinned"), pinned at the wire boundary: equal attachment priorities are
// ordered by policy ID (the compiled-plan sort) and the Sink keeps the FIRST
// recorded hint — so policy "hint-a" (anthropic) wins over "hint-b" (openai)
// regardless of the order the store returns them in. Both insertion orders
// must produce the identical outcome.
func TestR017Integration_ChatEntry_EqualPriorityHintOrderPinned(t *testing.T) {
	targets := map[string]string{"hint-a": "anthropic", "hint-b": "openai"}
	run := func(first, second string) (*httptest.ResponseRecorder, *r017IntUpstream, *r017IntUpstream) {
		t.Helper()
		anth := newR017IntUpstream(t, "upstream-anthropic", http.StatusOK)
		openai := newR017IntUpstream(t, "upstream-openai", http.StatusOK)
		store := newFakePolicyStore()
		for _, id := range []string{first, second} {
			store.add(testOrg, adminstore.PolicyPipeline{
				ID: id, OrgID: testOrg, Name: id, Enabled: true, CurrentVersion: 1,
			}, map[int]string{1: routeHintYAML(id, targets[id])}, []adminstore.PolicyAttachment{chatAttachment(10)})
		}
		gw := r017IntChatGateway(t, PolicyModeEnforce, store, r017IntChainDB(openai.srv.URL, anth.srv.URL), openai.srv.URL)
		rec := r017IntChat(t, gw)
		return rec, anth, openai
	}

	for _, order := range [][2]string{{"hint-b", "hint-a"}, {"hint-a", "hint-b"}} {
		rec, anth, openai := run(order[0], order[1])
		require.Equal(t, http.StatusOK, rec.Code,
			"store order %v: %s", order, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "upstream-anthropic",
			"store order %v: the lexicographically-first policy's hint must win", order)
		assert.Equal(t, int32(1), anth.calls.Load(), "store order %v", order)
		assert.Equal(t, int32(0), openai.calls.Load(),
			"store order %v: the losing hint must not steer the chain", order)
	}
}

// Negative scenario on the chainless boundary: the native messages endpoint
// serves one provider with no fallback chain, so an enforce-mode hint naming
// a foreign provider refuses explicitly at the entry — 400
// route_hint_unsatisfiable before any reservation or dial.
func TestR017Integration_MessagesNative_ForeignHintRefusedNoDial(t *testing.T) {
	anth := newR017IntUpstream(t, "upstream-anthropic", http.StatusOK)
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "hint-msg", OrgID: testOrg, Name: "hint-msg", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: routeHintYAML("hint-msg", "openai")}, []adminstore.PolicyAttachment{r017MessagesAttachment(10)})
	gw := nativeMessagesGateway(t, anth.srv.URL)
	gw.policyRuntime = newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	gw.log = slog.New(slog.DiscardHandler)

	body := `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}]}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/messages", strings.NewReader(body))
	r.Header.Set("X-Org-Id", testOrg)
	rec := httptest.NewRecorder()
	gw.messages(rec, r)

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), router.HintUnsatisfiableCode)
	assert.Contains(t, rec.Body.String(), router.HintUnsatisfiableErrType)
	assert.Contains(t, rec.Body.String(), "openai")
	assert.Equal(t, int32(0), anth.calls.Load(), "a refusal must not dial the serving provider either")
}
