package cli

// the REAL consumer entry point — the production chat route (gw.routes over
// chi + httptest) — against a disposable, fully migrated Postgres stand
// (testcontainers). The runtime is wired exactly as buildPolicyRuntime wires
// it (real adminstore prompt-studio sources via the structural assertion + the
// real UpstreamJudgeClient riding the gateway's own upstream pool and
// resolver/credential chain), so every claim here crosses the boundaries
// production crosses: auth → policyPreUpstream → per-org compile over the
// store → judge transport → upstream.
//
// Pinned through this boundary ( acceptance examples):
//   - the packet criterion «Версия prompt соответствует реальному содержимому
//     запроса»: the X-Policy-Judge-Version header value and the judge system
//     prompt bytes on the wire always come from the same compiled candidate —
//     a label re-promotion alone keeps the pinned pair; only the reload swaps
//     header and bytes together;
//   - partials substitution on the completions boundary rewrites the body
//     actually forwarded upstream, and on the chat boundary propagates the
//     substituted message text into the verdict of subsequent policies;
//   - the negative scenarios — unknown ref, чужая org, циклический partial —
//     through the same endpoints: unresolvable refs answer 503
//     policy_configuration_unavailable before any upstream byte; a cyclic
//     partial is inserted once, verbatim, and terminates;
//   - foreign-org POSITIVE isolation (the contract's explicit gap): a prompt
//     stored in org B resolves for org B and stays unresolvable for org D
//     referencing the same name@label.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/pipeline/llmjudge"
	"github.com/reireirei/yabanin/pkg/upstream"
)

func TestR018OrgJudgePartialsThroughChatHTTP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	dsn := startPolicyAvailabilityPostgres(t, ctx)
	directPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated Postgres pool: %v", err)
	}
	t.Cleanup(directPool.Close)
	store := adminstore.New(directPool, slog.New(slog.DiscardHandler), nil)

	recorder := &r018UpstreamRecorder{}
	upstreamServer := httptest.NewServer(recorder.handler())
	t.Cleanup(upstreamServer.Close)

	cfg := config.Gateway{}
	cfg.AuthMode = "header"
	cfg.Provider = upstreamServer.URL
	cfg.FallbackModel = "r018-model"
	cfg.UnknownModelPolicy = "reject"

	gw := &gateway{
		gatewayCore: gatewayCore{cfg: cfg, log: slog.New(slog.DiscardHandler)},
		gatewayEgress: gatewayEgress{
			pool: upstream.NewPool(upstream.Options{BaseURL: upstreamServer.URL}),
		},
		gatewayRouting: gatewayRouting{res: stubModelResolver{
			"r018-model": {ModelName: "r018-model", Provider: "openai", Enabled: true},
		}},
	}
	runtime, err := NewPolicyRuntime(store, nil, PolicyModeEnforce, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("construct real policy runtime: %v", err)
	}
	clock := newPolicyAvailabilityClock()
	runtime.now = clock.Now
	srcs, ok := promptStudioSourcesFrom(store)
	if !ok {
		t.Fatal("*adminstore.Store must assert the prompt-studio surface (buildPolicyRuntime wiring precondition)")
	}
	runtime.sources = srcs
	runtime.orgJudgeDeps = llmjudge.Deps{Client: llmjudge.NewUpstreamJudgeClient(
		gw.pool, gatewayJudgeModels{gw: gw}, gatewayJudgeKeys{gw: gw})}
	gw.policyRuntime = runtime

	gw.auth = NewAuthMiddleware(cfg, auth.NewResolver(directPool, nil, 300, nil))
	router := chi.NewRouter()
	gw.routes(router)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 15 * time.Second

	// Org A: the positive subject — org judge prompt + partial, both wired.
	orgA, keyA := createPolicyAvailabilityIdentity(t, ctx, store, "r018-judge")
	promptA, v1, err := store.CreatePrompt(ctx, orgA, "toxicity", "R018 org judge",
		"Classify this input for toxicity: {{ .Input }}", json.RawMessage(`{}`), "r018-test")
	if err != nil {
		t.Fatalf("seed org A prompt: %v", err)
	}
	if _, err := store.PromoteLabel(ctx, orgA, promptA.ID, adminstore.PromptLabelActive, v1.Version); err != nil {
		t.Fatalf("promote org A active label: %v", err)
	}
	if _, err := store.CreatePartial(ctx, orgA, "greeting", "HELLO"); err != nil {
		t.Fatalf("seed org A partial: %v", err)
	}
	policyA := seedR018OrgPolicy(t, ctx, store, orgA, "r018-org-judge", r018JudgePolicyYAML("r018-org-judge", "org:toxicity@active"),
		adminstore.PolicyAttachment{ModelPattern: "*", Endpoint: "chat", Priority: 1})
	// The wire-visible substitution boundary: a completions payload has no
	// messages array, so the engine substitutes the Body segment and the
	// gateway forwards mutated.Body (the delivered RT-04 body-adopt path).
	seedR018OrgPolicy(t, ctx, store, orgA, "r018-partials", partialsSubstituteYAML("r018-partials"),
		adminstore.PolicyAttachment{ModelPattern: "*", Endpoint: "completions", Priority: 1})

	// Org B: owns ghost@active — the FOREIGN-org positive control.
	orgB, keyB := createPolicyAvailabilityIdentity(t, ctx, store, "r018-foreign-owner")
	promptB, vB, err := store.CreatePrompt(ctx, orgB, "ghost", "foreign owner prompt",
		"FOREIGN-ORG template: {{ .Input }}", json.RawMessage(`{}`), "r018-test")
	if err != nil {
		t.Fatalf("seed org B prompt: %v", err)
	}
	if _, err := store.PromoteLabel(ctx, orgB, promptB.ID, adminstore.PromptLabelActive, vB.Version); err != nil {
		t.Fatalf("promote org B active label: %v", err)
	}
	seedR018OrgPolicy(t, ctx, store, orgB, "r018-foreign-judge", r018JudgePolicyYAML("r018-foreign-judge", "org:ghost@active"),
		adminstore.PolicyAttachment{ModelPattern: "*", Endpoint: "chat", Priority: 1})

	// Org C: a judge-less candidate (deny-word policy only) — header absence.
	orgC, keyC := createPolicyAvailabilityIdentity(t, ctx, store, "r018-judge-less")
	seedPolicyAvailabilityPolicy(t, ctx, store, orgC)

	// Org D: references ghost@active, which exists ONLY in org B.
	orgD, keyD := createPolicyAvailabilityIdentity(t, ctx, store, "r018-unknown-ref")
	seedR018OrgPolicy(t, ctx, store, orgD, "r018-unknown-judge", r018JudgePolicyYAML("r018-unknown-judge", "org:ghost@active"),
		adminstore.PolicyAttachment{ModelPattern: "*", Endpoint: "chat", Priority: 1})

	// Org E: the cyclic partial, chat-attached ahead of a deny policy so the
	// substituted message text is observable through the composed verdict,
	// plus a completions attachment for the wire-visible insertion.
	orgE, keyE := createPolicyAvailabilityIdentity(t, ctx, store, "r018-cycle")
	if _, err := store.CreatePartial(ctx, orgE, "a", "a={{partials.a}}-CYCLED"); err != nil {
		t.Fatalf("seed org E partial: %v", err)
	}
	seedR018OrgPolicy(t, ctx, store, orgE, "r018-cycle", partialsSubstituteYAML("r018-cycle"),
		adminstore.PolicyAttachment{ModelPattern: "*", Endpoint: "chat", Priority: 1},
		adminstore.PolicyAttachment{ModelPattern: "*", Endpoint: "completions", Priority: 1})
	seedR018OrgPolicy(t, ctx, store, orgE, "r018-cycle-deny", denyWordYAML("r018-cycle-deny", "CYCLED"),
		adminstore.PolicyAttachment{ModelPattern: "*", Endpoint: "chat", Priority: 2})

	// --- positive: org prompt rendered over the real request content at the wire
	before := recorder.total()
	resp := policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions",
		`{"model":"r018-model","messages":[{"role":"user","content":"hello"}]}`, keyA)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("wired org judge status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := resp.Header.Get(judgeVersionHeaderKey); got != "1" {
		t.Fatalf("%s = %q, want %q (the stored active prompt version)", judgeVersionHeaderKey, got, "1")
	}
	judge := recorder.judgeSince(before)
	if len(judge) != 1 {
		t.Fatalf("judge calls after first request = %d, want 1", len(judge))
	}
	roles, contents := r018JudgeMessages(t, judge[0])
	if len(roles) != 2 || roles[0] != "system" || roles[1] != "user" {
		t.Fatalf("judge wire roles %v, want [system user]", roles)
	}
	if contents[0] != "Classify this input for toxicity: hello" {
		t.Fatalf("judge system prompt on the wire = %q, want the org template rendered over the request content", contents[0])
	}
	if contents[1] != "hello" {
		t.Fatalf("judge user content on the wire = %q, want the actual request content", contents[1])
	}
	traffic := recorder.trafficSince(before)
	if len(traffic) != 1 || !strings.Contains(traffic[0].body, `"hello"`) {
		t.Fatalf("forwarded client traffic %d records, want 1 carrying the request content", len(traffic))
	}

	// --- partials through the real boundaries. Completions payloads carry no
	// messages array, so the engine substitutes the Body segment and the
	// gateway forwards the mutated body: the insertion is visible on the wire.
	before = recorder.total()
	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/completions",
		`{"model":"r018-model","prompt":"Hi {{partials.greeting}}"}`, keyA)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("partials completions status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	traffic = recorder.trafficSince(before)
	if len(traffic) != 1 {
		t.Fatalf("partials forward records = %d, want 1", len(traffic))
	}
	if !strings.Contains(traffic[0].body, "Hi HELLO") || strings.Contains(traffic[0].body, "{{partials.greeting}}") {
		t.Fatalf("forwarded body was not partials-substituted: %s", traffic[0].body)
	}

	// --- cyclic partial through the boundaries: single verbatim insertion,
	// explicit cycle detection fails closed for both chat and completions.
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	before = recorder.total()
	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions",
		`{"model":"r018-model","messages":[{"role":"user","content":"X {{partials.a}} Y"}]}`, keyE)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("cyclic chat status = %d, want 400 (the deny policy must observe the substituted text); body=%s", resp.StatusCode, resp.Body)
	}
	if err := json.Unmarshal([]byte(resp.Body), &envelope); err != nil || envelope.Error.Code != policyDenyErrorCode {
		t.Fatalf("cyclic chat code = %q (err %v), want %s; body=%s", envelope.Error.Code, err, policyDenyErrorCode, resp.Body)
	}
	if got := recorder.total(); got != before {
		t.Fatalf("cyclic chat reached upstream: %d records, want unchanged %d", got, before)
	}
	before = recorder.total()
	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/completions",
		`{"model":"r018-model","prompt":"X {{partials.a}} Y"}`, keyE)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("cyclic completions status = %d, want fail-closed 400; body=%s", resp.StatusCode, resp.Body)
	}
	if got := recorder.total(); got != before {
		t.Fatalf("cyclic completions reached upstream: %d records, want unchanged %d", got, before)
	}

	// --- prompt label movement alone is pinned; explicit policy re-activation
	// resolves the new label target into a new activation snapshot.
	if _, err := store.UpdatePrompt(ctx, orgA, promptA.ID, "Classify v2: {{ .Input }}", json.RawMessage(`{}`), "r018-test", 1); err != nil {
		t.Fatalf("append org A prompt v2: %v", err)
	}
	if _, err := store.PromoteLabel(ctx, orgA, promptA.ID, adminstore.PromptLabelActive, 2); err != nil {
		t.Fatalf("re-point org A active label to v2: %v", err)
	}
	before = recorder.total()
	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions",
		`{"model":"r018-model","messages":[{"role":"user","content":"hello"}]}`, keyA)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pinned request status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := resp.Header.Get(judgeVersionHeaderKey); got != "1" {
		t.Fatalf("re-promotion header = %q, want still pinned %q", got, "1")
	}
	judge = recorder.judgeSince(before)
	if len(judge) != 1 {
		t.Fatalf("pinned judge calls = %d, want 1", len(judge))
	}
	if _, contents = r018JudgeMessages(t, judge[0]); contents[0] != "Classify this input for toxicity: hello" {
		t.Fatalf("re-promotion judge bytes = %q, want still the pinned v1 template", contents[0])
	}

	if _, err := store.CreatePolicyVersion(ctx, orgA, policyA.ID, r018JudgePolicyYAML("r018-org-judge", "org:toxicity@active"), "", "r018-test"); err != nil {
		t.Fatalf("append reactivation policy version: %v", err)
	}
	if _, err := store.SetActivePolicyVersion(ctx, orgA, policyA.ID, 2); err != nil {
		t.Fatalf("reactivate policy: %v", err)
	}
	clock.Advance(2 * policyCacheTTL)
	before = recorder.total()
	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions",
		`{"model":"r018-model","messages":[{"role":"user","content":"hello"}]}`, keyA)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post-reload request status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := resp.Header.Get(judgeVersionHeaderKey); got != "2" {
		t.Fatalf("post-reload header = %q, want %q", got, "2")
	}
	judge = recorder.judgeSince(before)
	if len(judge) != 1 {
		t.Fatalf("post-reload judge calls = %d, want 1", len(judge))
	}
	if _, contents = r018JudgeMessages(t, judge[0]); contents[0] != "Classify v2: hello" {
		t.Fatalf("post-reload judge bytes = %q, want the reloaded v2 template over the request content", contents[0])
	}

	// --- negative: unknown ref through the endpoint (nothing upstream).
	before = recorder.total()
	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions",
		`{"model":"r018-model","messages":[{"role":"user","content":"hello"}]}`, keyD)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unknown ref status = %d, want 503; body=%s", resp.StatusCode, resp.Body)
	}
	if err := json.Unmarshal([]byte(resp.Body), &envelope); err != nil {
		t.Fatalf("decode unknown-ref envelope: %v; body=%s", err, resp.Body)
	}
	if envelope.Error.Code != "policy_configuration_unavailable" {
		t.Fatalf("unknown ref code = %q, want policy_configuration_unavailable; body=%s", envelope.Error.Code, resp.Body)
	}
	if got := recorder.total(); got != before {
		t.Fatalf("unknown ref reached upstream: %d records, want unchanged %d", got, before)
	}

	// --- foreign-org positive isolation: org B resolves ITS OWN ghost@active
	// through the same endpoint while org D cannot.
	before = recorder.total()
	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions",
		`{"model":"r018-model","messages":[{"role":"user","content":"hello"}]}`, keyB)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("foreign-owner org status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := resp.Header.Get(judgeVersionHeaderKey); got != "1" {
		t.Fatalf("foreign-owner header = %q, want %q", got, "1")
	}
	judge = recorder.judgeSince(before)
	if len(judge) != 1 {
		t.Fatalf("foreign-owner judge calls = %d, want 1", len(judge))
	}
	if _, contents = r018JudgeMessages(t, judge[0]); contents[0] != "FOREIGN-ORG template: hello" {
		t.Fatalf("foreign-owner judge bytes = %q, want org B's own template", contents[0])
	}

	// --- judge-less org: the header is absent (never set empty).
	before = recorder.total()
	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions",
		`{"model":"r018-model","messages":[{"role":"user","content":"hello"}]}`, keyC)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("judge-less org status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := resp.Header.Get(judgeVersionHeaderKey); got != "" {
		t.Fatalf("judge-less org header = %q, want absent", got)
	}
	if got := recorder.total(); got != before+1 {
		t.Fatalf("judge-less org traffic = %d, want %d", got, before+1)
	}
}

// r018JudgePolicyYAML is the integration org-judge policy: a literal judge
// model resolved through the test registry (no indirection) and the org
// prompt ref under test.
func r018JudgePolicyYAML(name, promptRef string) string {
	return "apiVersion: ypp/v1\nkind: Policy\nname: " + name + "\nmode: enforce\nhooks:\n  - pre_upstream\nsteps:\n  - id: judge\n    llm_judge:\n      model: \"r018-model\"\n      prompt_ref: \"" + promptRef + "\"\n    on_error: fail_open+flag\n"
}

// seedR018OrgPolicy stores, activates, enables and attaches one policy
// version (the admin path a reload observes).
func seedR018OrgPolicy(t *testing.T, ctx context.Context, store *adminstore.Store, orgID, name, yaml string, attachments ...adminstore.PolicyAttachment) adminstore.PolicyPipeline {
	t.Helper()
	p, _, err := store.CreatePolicy(ctx, orgID, name, yaml, "r018-test", "r018-test")
	if err != nil {
		t.Fatalf("create policy %s: %v", name, err)
	}
	if _, err := store.SetActivePolicyVersion(ctx, orgID, p.ID, 1); err != nil {
		t.Fatalf("activate policy %s: %v", name, err)
	}
	if _, err := store.UpdatePolicy(ctx, orgID, p.ID, true); err != nil {
		t.Fatalf("enable policy %s: %v", name, err)
	}
	if _, err := store.SetPolicyAttachments(ctx, orgID, p.ID, attachments); err != nil {
		t.Fatalf("attach policy %s: %v", name, err)
	}
	return p
}

// r018UpstreamRecord is one request the stub upstream received.
type r018UpstreamRecord struct {
	judge bool
	path  string
	body  string
}

// r018UpstreamRecorder captures every upstream request and answers judge
// calls with an empty-findings verdict (allow) and client traffic with a
// canned completion.
type r018UpstreamRecorder struct {
	mu      sync.Mutex
	records []r018UpstreamRecord
}

func (r *r018UpstreamRecorder) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		r.mu.Lock()
		r.records = append(r.records, r018UpstreamRecord{
			judge: req.Header.Get(llmjudge.JudgeHeader) != "",
			path:  req.URL.Path,
			body:  string(body),
		})
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if req.Header.Get(llmjudge.JudgeHeader) != "" {
			_, _ = io.WriteString(w, `{"id":"r018-judge","object":"chat.completion","model":"r018-model","choices":[{"index":0,"message":{"role":"assistant","content":"{\"findings\":[]}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
			return
		}
		_, _ = io.WriteString(w, `{"id":"r018-chat","object":"chat.completion","model":"r018-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	})
}

func (r *r018UpstreamRecorder) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.records)
}

func (r *r018UpstreamRecorder) since(n int) []r018UpstreamRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]r018UpstreamRecord(nil), r.records[n:]...)
}

func (r *r018UpstreamRecorder) judgeSince(n int) []r018UpstreamRecord {
	var out []r018UpstreamRecord
	for _, rec := range r.since(n) {
		if rec.judge {
			out = append(out, rec)
		}
	}
	return out
}

func (r *r018UpstreamRecorder) trafficSince(n int) []r018UpstreamRecord {
	var out []r018UpstreamRecord
	for _, rec := range r.since(n) {
		if !rec.judge {
			out = append(out, rec)
		}
	}
	return out
}

// r018JudgeMessages decodes the chat.completions body a judge call carried.
func r018JudgeMessages(t *testing.T, rec r018UpstreamRecord) ([]string, []string) {
	t.Helper()
	var wire struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(rec.body), &wire); err != nil {
		t.Fatalf("decode judge wire body: %v; body=%s", err, rec.body)
	}
	roles := make([]string, 0, len(wire.Messages))
	contents := make([]string, 0, len(wire.Messages))
	for _, m := range wire.Messages {
		roles = append(roles, m.Role)
		contents = append(contents, m.Content)
	}
	return roles, contents
}
