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

// r018OrgJudgeStand is the shared per-test stand: the disposable migrated
// Postgres, the real policy runtime over the store and the gateway routing
// to the recorded upstream. Scenario helpers run the HTTP requests; the
// cleanup lifecycle stays wired here exactly as before.
type r018OrgJudgeStand struct {
	store    *adminstore.Store
	recorder *r018UpstreamRecorder
	clock    *policyAvailabilityClock
	client   *http.Client
	baseURL  string
}

// newR018OrgJudgeStand wires the REAL consumer entry point — the production
// chat route (gw.routes over chi + httptest) — against a disposable, fully
// migrated Postgres stand (testcontainers). The runtime is wired exactly as
// buildPolicyRuntime wires it (real adminstore prompt-studio sources via the
// structural assertion + the real UpstreamJudgeClient riding the gateway's
// own upstream pool and resolver/credential chain), so every claim crosses
// the boundaries production crosses: auth → policyPreUpstream → per-org
// compile over the store → judge transport → upstream.
func newR018OrgJudgeStand(t *testing.T, directPool *pgxpool.Pool) *r018OrgJudgeStand {
	t.Helper()
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
		gatewayCore: gatewayCore{
			// Explicit in-memory invocation store (see streamTestGateway).
			invocations: &fakeInvocationStore{}, cfg: cfg, log: slog.New(slog.DiscardHandler)},
		gatewayEgress: gatewayEgress{
			pool: upstream.NewPool(upstream.Options{BaseURL: upstreamServer.URL}),
		},
		gatewayRouting: gatewayRouting{res: stubModelResolver{
			"r018-model": {ModelName: "r018-model", Provider: "openai", Enabled: true},
		}},
	}
	runtime := newTestRuntime(t, store, nil, PolicyModeEnforce)
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

	return &r018OrgJudgeStand{store: store, recorder: recorder, clock: clock, client: client, baseURL: server.URL}
}

// seedR018SubjectOrg seeds org A: the positive subject with an org judge
// prompt + partial, both wired — the judge policy on the chat boundary and
// the partials policy on the completions boundary. The completions
// attachment is the wire-visible substitution boundary: a completions
// payload has no messages array, so the engine substitutes the Body segment
// and the gateway forwards mutated.Body (the delivered RT-04 body-adopt
// path).
func seedR018SubjectOrg(t *testing.T, ctx context.Context, store *adminstore.Store) (string, string, string, adminstore.PolicyPipeline) {
	t.Helper()
	orgID, key := createPolicyAvailabilityIdentity(t, ctx, store, "r018-judge")
	prompt, v1, err := store.CreatePrompt(ctx, orgID, "toxicity", "R018 org judge",
		"Classify this input for toxicity: {{ .Input }}", json.RawMessage(`{}`), "r018-test")
	if err != nil {
		t.Fatalf("seed org A prompt: %v", err)
	}
	if _, err := store.PromoteLabel(ctx, orgID, prompt.ID, adminstore.PromptLabelActive, v1.Version); err != nil {
		t.Fatalf("promote org A active label: %v", err)
	}
	if _, err := store.CreatePartial(ctx, orgID, "greeting", "HELLO"); err != nil {
		t.Fatalf("seed org A partial: %v", err)
	}
	policy := seedR018OrgPolicy(t, ctx, store, orgID, "r018-org-judge", r018JudgePolicyYAML("r018-org-judge", "org:toxicity@active"),
		adminstore.PolicyAttachment{ModelPattern: "*", Endpoint: "chat", Priority: 1})
	seedR018OrgPolicy(t, ctx, store, orgID, "r018-partials", partialsSubstituteYAML("r018-partials"),
		adminstore.PolicyAttachment{ModelPattern: "*", Endpoint: "completions", Priority: 1})
	return orgID, key, prompt.ID, policy
}

// seedR018ForeignOwnerOrg seeds org B, which owns ghost@active — the
// FOREIGN-org positive control.
func seedR018ForeignOwnerOrg(t *testing.T, ctx context.Context, store *adminstore.Store) string {
	t.Helper()
	orgID, key := createPolicyAvailabilityIdentity(t, ctx, store, "r018-foreign-owner")
	prompt, v, err := store.CreatePrompt(ctx, orgID, "ghost", "foreign owner prompt",
		"FOREIGN-ORG template: {{ .Input }}", json.RawMessage(`{}`), "r018-test")
	if err != nil {
		t.Fatalf("seed org B prompt: %v", err)
	}
	if _, err := store.PromoteLabel(ctx, orgID, prompt.ID, adminstore.PromptLabelActive, v.Version); err != nil {
		t.Fatalf("promote org B active label: %v", err)
	}
	seedR018OrgPolicy(t, ctx, store, orgID, "r018-foreign-judge", r018JudgePolicyYAML("r018-foreign-judge", "org:ghost@active"),
		adminstore.PolicyAttachment{ModelPattern: "*", Endpoint: "chat", Priority: 1})
	return key
}

// seedR018JudgelessOrg seeds org C: a judge-less candidate (deny-word
// policy only) — its judge header must be absent.
func seedR018JudgelessOrg(t *testing.T, ctx context.Context, store *adminstore.Store) string {
	t.Helper()
	orgID, key := createPolicyAvailabilityIdentity(t, ctx, store, "r018-judge-less")
	seedPolicyAvailabilityPolicy(t, ctx, store, orgID)
	return key
}

// seedR018UnknownRefOrg seeds org D, which references ghost@active — a
// prompt that exists ONLY in org B.
func seedR018UnknownRefOrg(t *testing.T, ctx context.Context, store *adminstore.Store) string {
	t.Helper()
	orgID, key := createPolicyAvailabilityIdentity(t, ctx, store, "r018-unknown-ref")
	seedR018OrgPolicy(t, ctx, store, orgID, "r018-unknown-judge", r018JudgePolicyYAML("r018-unknown-judge", "org:ghost@active"),
		adminstore.PolicyAttachment{ModelPattern: "*", Endpoint: "chat", Priority: 1})
	return key
}

// seedR018CyclicOrg seeds org E: the cyclic partial, chat-attached ahead of
// a deny policy so the substituted message text is observable through the
// composed verdict, plus a completions attachment for the wire-visible
// insertion.
func seedR018CyclicOrg(t *testing.T, ctx context.Context, store *adminstore.Store) string {
	t.Helper()
	orgID, key := createPolicyAvailabilityIdentity(t, ctx, store, "r018-cycle")
	if _, err := store.CreatePartial(ctx, orgID, "a", "a={{partials.a}}-CYCLED"); err != nil {
		t.Fatalf("seed org E partial: %v", err)
	}
	seedR018OrgPolicy(t, ctx, store, orgID, "r018-cycle", partialsSubstituteYAML("r018-cycle"),
		adminstore.PolicyAttachment{ModelPattern: "*", Endpoint: "chat", Priority: 1},
		adminstore.PolicyAttachment{ModelPattern: "*", Endpoint: "completions", Priority: 1})
	seedR018OrgPolicy(t, ctx, store, orgID, "r018-cycle-deny", denyWordYAML("r018-cycle-deny", "CYCLED"),
		adminstore.PolicyAttachment{ModelPattern: "*", Endpoint: "chat", Priority: 2})
	return key
}

// assertR018JudgeWirePrompt decodes one judge record and pins the exact
// wire shape: [system user] roles with the rendered org prompt over the
// request content.
func assertR018JudgeWirePrompt(t *testing.T, rec r018UpstreamRecord, wantSystem, wantUser string) {
	t.Helper()
	roles, contents := r018JudgeMessages(t, rec)
	if len(roles) != 2 || roles[0] != "system" || roles[1] != "user" {
		t.Fatalf("judge wire roles %v, want [system user]", roles)
	}
	if contents[0] != wantSystem {
		t.Fatalf("judge system prompt on the wire = %q, want %q", contents[0], wantSystem)
	}
	if contents[1] != wantUser {
		t.Fatalf("judge user content on the wire = %q, want the actual request content", contents[1])
	}
}

// assertR018JudgeSystemPrompt pins only the judge system bytes, matching
// the narrower per-scenario checks.
func assertR018JudgeSystemPrompt(t *testing.T, rec r018UpstreamRecord, want string) {
	t.Helper()
	_, contents := r018JudgeMessages(t, rec)
	if contents[0] != want {
		t.Fatalf("judge bytes = %q, want %q", contents[0], want)
	}
}

// runR018PositiveOrgJudge pins the positive scenario: the org judge prompt
// renders over the real request content at the wire, the version header and
// the judge bytes come from the same compiled candidate, and the client
// traffic still reaches the upstream.
func runR018PositiveOrgJudge(t *testing.T, ctx context.Context, stand *r018OrgJudgeStand, key string) {
	t.Helper()
	before := stand.recorder.total()
	resp := policyAvailabilityRequest(t, ctx, stand.client, stand.baseURL, "/v1/chat/completions",
		`{"model":"r018-model","messages":[{"role":"user","content":"hello"}]}`, key)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("wired org judge status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := resp.Header.Get(judgeVersionHeaderKey); got != "1" {
		t.Fatalf("%s = %q, want %q (the stored active prompt version)", judgeVersionHeaderKey, got, "1")
	}
	judge := stand.recorder.judgeSince(before)
	if len(judge) != 1 {
		t.Fatalf("judge calls after first request = %d, want 1", len(judge))
	}
	assertR018JudgeWirePrompt(t, judge[0], "Classify this input for toxicity: hello", "hello")
	traffic := stand.recorder.trafficSince(before)
	if len(traffic) != 1 || !strings.Contains(traffic[0].body, `"hello"`) {
		t.Fatalf("forwarded client traffic %d records, want 1 carrying the request content", len(traffic))
	}
}

// runR018PartialsCompletionsForward pins partials substitution on the
// completions boundary: the engine substitutes the Body segment and the
// gateway forwards the mutated body, so the insertion is visible on the
// wire.
func runR018PartialsCompletionsForward(t *testing.T, ctx context.Context, stand *r018OrgJudgeStand, key string) {
	t.Helper()
	before := stand.recorder.total()
	resp := policyAvailabilityRequest(t, ctx, stand.client, stand.baseURL, "/v1/completions",
		`{"model":"r018-model","prompt":"Hi {{partials.greeting}}"}`, key)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("partials completions status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	traffic := stand.recorder.trafficSince(before)
	if len(traffic) != 1 {
		t.Fatalf("partials forward records = %d, want 1", len(traffic))
	}
	if !strings.Contains(traffic[0].body, "Hi HELLO") || strings.Contains(traffic[0].body, "{{partials.greeting}}") {
		t.Fatalf("forwarded body was not partials-substituted: %s", traffic[0].body)
	}
}

// runR018CyclicPartialFailClosed pins the cyclic partial through both
// boundaries: a single verbatim insertion cannot loop — explicit cycle
// detection fails closed with the deny envelope for chat (the deny policy
// observes the substituted text) and a bare 400 for completions, and no
// request reaches upstream.
func runR018CyclicPartialFailClosed(t *testing.T, ctx context.Context, stand *r018OrgJudgeStand, key string) {
	t.Helper()
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	before := stand.recorder.total()
	resp := policyAvailabilityRequest(t, ctx, stand.client, stand.baseURL, "/v1/chat/completions",
		`{"model":"r018-model","messages":[{"role":"user","content":"X {{partials.a}} Y"}]}`, key)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("cyclic chat status = %d, want 400 (the deny policy must observe the substituted text); body=%s", resp.StatusCode, resp.Body)
	}
	if err := json.Unmarshal([]byte(resp.Body), &envelope); err != nil || envelope.Error.Code != policyDenyErrorCode {
		t.Fatalf("cyclic chat code = %q (err %v), want %s; body=%s", envelope.Error.Code, err, policyDenyErrorCode, resp.Body)
	}
	if got := stand.recorder.total(); got != before {
		t.Fatalf("cyclic chat reached upstream: %d records, want unchanged %d", got, before)
	}
	before = stand.recorder.total()
	resp = policyAvailabilityRequest(t, ctx, stand.client, stand.baseURL, "/v1/completions",
		`{"model":"r018-model","prompt":"X {{partials.a}} Y"}`, key)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("cyclic completions status = %d, want fail-closed 400; body=%s", resp.StatusCode, resp.Body)
	}
	if got := stand.recorder.total(); got != before {
		t.Fatalf("cyclic completions reached upstream: %d records, want unchanged %d", got, before)
	}
}

// runR018PromptLabelStaysPinned pins that a prompt label re-promotion alone
// keeps the pinned pair: the header stays on the stored v1 activation and
// the judge bytes stay the v1 template.
func runR018PromptLabelStaysPinned(t *testing.T, ctx context.Context, stand *r018OrgJudgeStand, orgID, promptID, key string) {
	t.Helper()
	if _, err := stand.store.UpdatePrompt(ctx, orgID, promptID, "Classify v2: {{ .Input }}", json.RawMessage(`{}`), "r018-test", 1); err != nil {
		t.Fatalf("append org A prompt v2: %v", err)
	}
	if _, err := stand.store.PromoteLabel(ctx, orgID, promptID, adminstore.PromptLabelActive, 2); err != nil {
		t.Fatalf("re-point org A active label to v2: %v", err)
	}
	before := stand.recorder.total()
	resp := policyAvailabilityRequest(t, ctx, stand.client, stand.baseURL, "/v1/chat/completions",
		`{"model":"r018-model","messages":[{"role":"user","content":"hello"}]}`, key)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pinned request status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := resp.Header.Get(judgeVersionHeaderKey); got != "1" {
		t.Fatalf("re-promotion header = %q, want still pinned %q", got, "1")
	}
	judge := stand.recorder.judgeSince(before)
	if len(judge) != 1 {
		t.Fatalf("pinned judge calls = %d, want 1", len(judge))
	}
	assertR018JudgeSystemPrompt(t, judge[0], "Classify this input for toxicity: hello")
}

// runR018PolicyReactivationReload pins that explicit policy re-activation
// resolves the new label target into a new activation snapshot after the
// cache window: the header and the judge bytes swap to v2 together.
func runR018PolicyReactivationReload(t *testing.T, ctx context.Context, stand *r018OrgJudgeStand, orgID string, policy adminstore.PolicyPipeline, key string) {
	t.Helper()
	if _, err := stand.store.CreatePolicyVersion(ctx, orgID, policy.ID, r018JudgePolicyYAML("r018-org-judge", "org:toxicity@active"), "", "r018-test"); err != nil {
		t.Fatalf("append reactivation policy version: %v", err)
	}
	if _, err := stand.store.SetActivePolicyVersion(ctx, orgID, policy.ID, 2); err != nil {
		t.Fatalf("reactivate policy: %v", err)
	}
	stand.clock.Advance(2 * policyCacheTTL)
	before := stand.recorder.total()
	resp := policyAvailabilityRequest(t, ctx, stand.client, stand.baseURL, "/v1/chat/completions",
		`{"model":"r018-model","messages":[{"role":"user","content":"hello"}]}`, key)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post-reload request status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := resp.Header.Get(judgeVersionHeaderKey); got != "2" {
		t.Fatalf("post-reload header = %q, want %q", got, "2")
	}
	judge := stand.recorder.judgeSince(before)
	if len(judge) != 1 {
		t.Fatalf("post-reload judge calls = %d, want 1", len(judge))
	}
	assertR018JudgeSystemPrompt(t, judge[0], "Classify v2: hello")
}

// runR018UnknownRefNegative pins the negative scenario: an unresolvable
// prompt ref answers 503 policy_configuration_unavailable before any
// upstream byte.
func runR018UnknownRefNegative(t *testing.T, ctx context.Context, stand *r018OrgJudgeStand, key string) {
	t.Helper()
	before := stand.recorder.total()
	resp := policyAvailabilityRequest(t, ctx, stand.client, stand.baseURL, "/v1/chat/completions",
		`{"model":"r018-model","messages":[{"role":"user","content":"hello"}]}`, key)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unknown ref status = %d, want 503; body=%s", resp.StatusCode, resp.Body)
	}
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &envelope); err != nil {
		t.Fatalf("decode unknown-ref envelope: %v; body=%s", err, resp.Body)
	}
	if envelope.Error.Code != "policy_configuration_unavailable" {
		t.Fatalf("unknown ref code = %q, want policy_configuration_unavailable; body=%s", envelope.Error.Code, resp.Body)
	}
	if got := stand.recorder.total(); got != before {
		t.Fatalf("unknown ref reached upstream: %d records, want unchanged %d", got, before)
	}
}

// runR018ForeignOrgPositiveIsolation pins the foreign-org POSITIVE control
// (the contract's explicit gap): org B resolves ITS OWN ghost@active
// through the same endpoint.
func runR018ForeignOrgPositiveIsolation(t *testing.T, ctx context.Context, stand *r018OrgJudgeStand, key string) {
	t.Helper()
	before := stand.recorder.total()
	resp := policyAvailabilityRequest(t, ctx, stand.client, stand.baseURL, "/v1/chat/completions",
		`{"model":"r018-model","messages":[{"role":"user","content":"hello"}]}`, key)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("foreign-owner org status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := resp.Header.Get(judgeVersionHeaderKey); got != "1" {
		t.Fatalf("foreign-owner header = %q, want %q", got, "1")
	}
	judge := stand.recorder.judgeSince(before)
	if len(judge) != 1 {
		t.Fatalf("foreign-owner judge calls = %d, want 1", len(judge))
	}
	assertR018JudgeSystemPrompt(t, judge[0], "FOREIGN-ORG template: hello")
}

// runR018JudgelessHeaderAbsent pins that a judge-less org never gets the
// judge header — absent, never set empty — while its client traffic still
// reaches the upstream exactly once.
func runR018JudgelessHeaderAbsent(t *testing.T, ctx context.Context, stand *r018OrgJudgeStand, key string) {
	t.Helper()
	before := stand.recorder.total()
	resp := policyAvailabilityRequest(t, ctx, stand.client, stand.baseURL, "/v1/chat/completions",
		`{"model":"r018-model","messages":[{"role":"user","content":"hello"}]}`, key)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("judge-less org status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := resp.Header.Get(judgeVersionHeaderKey); got != "" {
		t.Fatalf("judge-less org header = %q, want absent", got)
	}
	if got := stand.recorder.total(); got != before+1 {
		t.Fatalf("judge-less org traffic = %d, want %d", got, before+1)
	}
}

// TestR018OrgJudgePartialsThroughChatHTTP is the scenario orchestrator: the
// stand and the five orgs are seeded once, then every pinned scenario runs
// in the original order over the real HTTP boundary.
func TestR018OrgJudgePartialsThroughChatHTTP(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, startPolicyAvailabilityPostgres(t, ctx))
	if err != nil {
		t.Fatalf("open isolated Postgres pool: %v", err)
	}
	t.Cleanup(pool.Close)
	stand := newR018OrgJudgeStand(t, pool)
	orgA, keyA, promptA, policyA := seedR018SubjectOrg(t, ctx, stand.store)
	keyB := seedR018ForeignOwnerOrg(t, ctx, stand.store)
	keyC := seedR018JudgelessOrg(t, ctx, stand.store)
	keyD := seedR018UnknownRefOrg(t, ctx, stand.store)
	keyE := seedR018CyclicOrg(t, ctx, stand.store)

	runR018PositiveOrgJudge(t, ctx, stand, keyA)
	runR018PartialsCompletionsForward(t, ctx, stand, keyA)
	runR018CyclicPartialFailClosed(t, ctx, stand, keyE)
	runR018PromptLabelStaysPinned(t, ctx, stand, orgA, promptA, keyA)
	runR018PolicyReactivationReload(t, ctx, stand, orgA, policyA, keyA)
	runR018UnknownRefNegative(t, ctx, stand, keyD)
	runR018ForeignOrgPositiveIsolation(t, ctx, stand, keyB)
	runR018JudgelessHeaderAbsent(t, ctx, stand, keyC)
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
