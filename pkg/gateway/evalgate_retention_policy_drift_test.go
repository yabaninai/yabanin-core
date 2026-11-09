package cli

// OBS-02 reproduction (FIX-07 input) — the evalgate judge-prompt retention
// resolution drifts from the retention-policy seam.
//
// OBS-02 variant suite. Technical provenance: identical to
// pkg/gateway/evalgate_retention_policy_drift_test.go @ 25b9b14b apart from
// this header and the two HEAD-drift fingerprint assertions marked below.
// Failing-before on HEAD (43cdf5cf) was confirmed with the pristine file
// before the fix; post-fix the matrix below must PASS and the fingerprints
// encode the unified-seam contract.
//
// Claim under test: the PRODUCER boundary (RedisPublisher.Publish) resolves
// original retention through the T04 seam (installed RetentionPolicyResolver
// first, boolean default otherwise — eventpublisher.ResolveOriginalRetention),
// but the in-process evalgate call point (chat.go InsertVerdict, via
// gw.originalRetentionEnabled) consulted ONLY the boolean resolver
// (RedisPublisher.OriginalRetention — the getter's own doc calls this the
// "recorded remainder"). With the org boolean ON and an installed custom
// policy answering DENY, the wire strips the captures while the evalgate
// judge-prompt persistence stores the PRE-MASK ORIGINAL prompt anyway.
//
// The tests below use the RetentionPolicyResolver seam with test doubles
// (the same stand-in pattern pkg/eventpublisher/retention_policy_test.go
// uses for the Enterprise module) and an unreachable Redis client: the
// detached publish goroutine still consults the installed policy before the
// XADD (the resolution precedes the wire write), so the policy/boolean call
// split is observable without a live Redis. The judge-goroutine prompt
// argument is captured by a recording verdictStore.
//
// Failing-before matrix on HEAD (43cdf5cf) — PASSING-after the FIX-07 seam
// unification:
//   - TestOBS02_BooleanOnCustomPolicyDeny_EvalgateMustNotPersistOriginalPrompt — FAIL (prompt persisted)
//   - TestOBS02_PolicyFlipBetweenPublisherAndEvalgateCallPoints — FAIL (post-flip prompt persisted)
//   - TestOBS02_ResolverErrorAtEvalgate/store_error_under_installed_policy_ALLOW — FAIL (prompt withheld: broken boolean overrides healthy policy)
//   - TestOBS02_ResolverErrorAtEvalgate/store_error_under_policy_DENY — PASS (the safe direction already holds)
//   - TestOBS02_StrictProfilePolicyDeny_StrictWinsAtWireButEvalgateStillPersists — FAIL (prompt persisted under strict + DENY;
//     strict wins structurally at the producer — the policy is never consulted there)

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/evalgate"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
)

// --- OBS-02 test doubles -----------------------------------------------------

// obs02PromptStore is a verdictStore that records the prompt argument of
// every InsertVerdict (the value the retention gate is supposed to govern).
// Every call signals calls (non-blocking) so tests synchronize on the verdict
// instead of polling.
type obs02PromptStore struct {
	mu      sync.Mutex
	prompts []string
	calls   chan struct{}
}

func newObs02PromptStore() *obs02PromptStore {
	return &obs02PromptStore{calls: make(chan struct{}, 8)}
}

func (s *obs02PromptStore) InsertVerdict(_ context.Context, _, _, prompt, _, _ string, _ *evalgate.Verdict, _ float64) error {
	s.mu.Lock()
	s.prompts = append(s.prompts, prompt)
	s.mu.Unlock()
	select {
	case s.calls <- struct{}{}:
	default:
	}
	return nil
}

func (s *obs02PromptStore) recorded() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.prompts...)
}

func (s *obs02PromptStore) waitFor(t *testing.T, n int) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		if len(s.recorded()) >= n {
			return
		}
		select {
		case <-s.calls:
		case <-timer.C:
			t.Fatalf("only %d of %d expected verdicts stored", len(s.recorded()), n)
		}
	}
}

// obs02BooleanStore is a configurable OriginalRetentionStore fake (the org
// boolean toggle source) with a lookup counter.
type obs02BooleanStore struct {
	mu        sync.Mutex
	lookups   int
	found     bool
	effective bool
	err       error
}

func (s *obs02BooleanStore) GetOrgOriginalRetention(_ context.Context, orgID string) (*adminstore.OrgOriginalRetention, error) {
	s.mu.Lock()
	s.lookups++
	found, effective, err := s.found, s.effective, s.err
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("org not found: %s: %w", orgID, adminstore.ErrNotFound)
	}
	return &adminstore.OrgOriginalRetention{OrgID: orgID, Effective: effective}, nil
}

func (s *obs02BooleanStore) lookupCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lookups
}

// obs02PolicyDouble is the RetentionPolicyResolver test double: the stand-in
// for an installed Enterprise module. The answer is an atomically flippable
// bool so a test can move the policy between the publisher and the evalgate
// call points; every resolution is logged for the drift fingerprint.
type obs02PolicyDouble struct {
	answer  atomic.Bool
	mu      sync.Mutex
	reqs    []eventpublisher.RetentionPolicyRequest
	answers []bool
}

func newObs02PolicyDouble(initial bool) *obs02PolicyDouble {
	p := &obs02PolicyDouble{}
	p.answer.Store(initial)
	return p
}

func (p *obs02PolicyDouble) RetainOriginal(_ context.Context, req eventpublisher.RetentionPolicyRequest) bool {
	ans := p.answer.Load()
	p.mu.Lock()
	p.reqs = append(p.reqs, req)
	p.answers = append(p.answers, ans)
	p.mu.Unlock()
	return ans
}

func (p *obs02PolicyDouble) flip(to bool) { p.answer.Store(to) }

func (p *obs02PolicyDouble) resolutionCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.answers)
}

func (p *obs02PolicyDouble) everAnswered(want bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, a := range p.answers {
		if a == want {
			return true
		}
	}
	return false
}

// attachObs02Retention wires a retention-enabled publisher into a minimal
// evalgate test gateway: a boolean store (the org toggle source) and an
// optional installed policy through the SetRetentionPolicy seam. The Redis
// client points at ":0" — unreachable, so the detached publish errors after
// its bounded retries; the retention resolution itself happens BEFORE the
// XADD and stays fully observable through the doubles.
func attachObs02Retention(gw *gateway, store *obs02BooleanStore, policy *obs02PolicyDouble) {
	gw.publisher = eventpublisher.NewRedisPublisher(redis.NewClient(&redis.Options{Addr: ":0"}), "obs02-repro-stream")
	gw.publisher.SetOriginalRetentionStore(store)
	if policy != nil {
		gw.publisher.SetRetentionPolicy(policy)
	}
}

// waitPolicyResolutions waits (bounded) for the detached publish goroutine to
// consult the installed policy at least n times.
func waitPolicyResolutions(t *testing.T, policy *obs02PolicyDouble, n int) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for policy.resolutionCount() < n {
		select {
		case <-timer.C:
			t.Fatalf("the installed policy was consulted only %d times (want >= %d)", policy.resolutionCount(), n)
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

// runObs02ChatRequest drives one non-stream chat completion through the full
// pipeline (medium prompt ⇒ evalgate sampling eligible at rate 1.0).
func runObs02ChatRequest(t *testing.T, gw *gateway, orgID, prompt string) *httptest.ResponseRecorder {
	t.Helper()
	body := nonStreamBody("gpt-4o-mini", prompt)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", orgID)
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)
	return w
}

// --- the reproduction --------------------------------------------------------

// TestOBS02_BooleanOnCustomPolicyDeny_EvalgateMustNotPersistOriginalPrompt:
// the base case. Org boolean retention ON + an installed custom policy that
// answers DENY for everything. The publisher consults the installed policy
// (authoritative DENY — captures stripped pre-XADD), but the evalgate call
// point consults only the boolean and persists the PRE-MASK ORIGINAL judge
// prompt. Post-fix contract: the evalgate persistence must route through the
// same seam and withhold the prompt.
func TestOBS02_BooleanOnCustomPolicyDeny_EvalgateMustNotPersistOriginalPrompt(t *testing.T) {
	var judgeHits int32
	judgeSrv, judgeHit, _ := judgeHitServer(t, &judgeHits)
	store := newObs02PromptStore()

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(completeResp("gpt-4o-mini"))
	}))
	t.Cleanup(primary.Close)

	gw := evalgateTestGateway(t, primary.URL, judgeSrv.URL, store)
	boolean := &obs02BooleanStore{found: true, effective: true} // org toggle ON
	policy := newObs02PolicyDouble(false)                       // installed custom policy: DENY all
	attachObs02Retention(gw, boolean, policy)

	const secretPrompt = "OBS-02 secret original: " + mediumPrompt
	w := runObs02ChatRequest(t, gw, "org-obs02", secretPrompt)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	// The judge ran and a verdict reached the store.
	waitJudgeHit(t, judgeHit)
	store.waitFor(t, 1)

	// The installed policy is authoritative at BOTH call points: the producer
	// (pre-XADD) and the evalgate persistence boundary. Waiting for 2
	// resolutions proves the evalgate call point actually routed through the
	// seam instead of silently failing closed for an unrelated reason.
	waitPolicyResolutions(t, policy, 2)
	if !policy.everAnswered(false) {
		t.Fatalf("sanity: the installed policy never answered DENY")
	}

	// Seam fingerprint (FIX-07): behind an installed policy NO call point
	// consults the boolean store. (On HEAD this read "want 1" — the drift
	// fingerprint of the evalgate call point being the only boolean consumer;
	// the unified seam decision replaced that boolean-only lookup.)
	if got := boolean.lookupCalls(); got != 0 {
		t.Fatalf("boolean store lookups = %d, want 0 (behind an installed policy the seam answers at both call points)", got)
	}

	// THE OBS-02 ASSERTION: under an installed DENY policy the original
	// prompt must not reach the verdict store.
	prompts := store.recorded()
	if len(prompts) != 1 {
		t.Fatalf("stored verdicts = %d, want 1", len(prompts))
	}
	if prompts[0] != "" {
		t.Fatalf("OBS-02 reproduced: original judge prompt persisted despite installed policy DENY "+
			"(boolean ON drift): %q", prompts[0])
	}
}

// TestOBS02_PolicyFlipBetweenPublisherAndEvalgateCallPoints: the installed
// policy is resolved on every boundary call and owns its caching (T04 seam
// contract) — so flipping its answer between the publisher's resolution and
// the evalgate call point MUST flip the evalgate persistence decision too.
// On HEAD it does not: the evalgate call point never consults the policy, so
// the flip is unobservable there and the original prompt keeps flowing after
// the policy turned DENY.
func TestOBS02_PolicyFlipBetweenPublisherAndEvalgateCallPoints(t *testing.T) {
	var judgeHits int32
	judgeSrv, _, _ := judgeHitServer(t, &judgeHits)
	store := newObs02PromptStore()

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(completeResp("gpt-4o-mini"))
	}))
	t.Cleanup(primary.Close)

	gw := evalgateTestGateway(t, primary.URL, judgeSrv.URL, store)
	boolean := &obs02BooleanStore{found: true, effective: true} // org toggle ON throughout
	policy := newObs02PolicyDouble(true)                        // round 1: the policy answers ALLOW
	attachObs02Retention(gw, boolean, policy)

	// Round 1 — policy ALLOW: the prompt may persist (correct on HEAD and
	// post-fix alike; the boolean agrees).
	if w := runObs02ChatRequest(t, gw, "org-obs02", "OBS-02 round one: "+mediumPrompt); w.Code != http.StatusOK {
		t.Fatalf("round 1 status = %d, want 200", w.Code)
	}
	store.waitFor(t, 1)
	waitPolicyResolutions(t, policy, 1)

	// FLIP the installed policy to DENY between the two call points.
	policy.flip(false)

	// Round 2 — policy DENY: the publisher strips; the evalgate persistence
	// must withhold the prompt through the same authoritative answer.
	if w := runObs02ChatRequest(t, gw, "org-obs02", "OBS-02 round two secret: "+mediumPrompt); w.Code != http.StatusOK {
		t.Fatalf("round 2 status = %d, want 200", w.Code)
	}
	store.waitFor(t, 2)
	waitPolicyResolutions(t, policy, 2)

	prompts := store.recorded()
	if len(prompts) != 2 {
		t.Fatalf("stored verdicts = %d, want 2", len(prompts))
	}
	if !policy.everAnswered(false) {
		t.Fatalf("sanity: the policy flip to DENY was never recorded")
	}
	if prompts[1] != "" {
		t.Fatalf("OBS-02 reproduced: policy flip ALLOW→DENY is unobservable at the evalgate call point — "+
			"original prompt persisted after the flip: %q", prompts[1])
	}
}

// TestOBS02_ResolverErrorAtEvalgate pins which source the evalgate call point
// trusts when the boolean resolver breaks.
//
//   - store error under an installed policy ALLOW: the policy is the
//     authoritative source and answers retain — the publisher keeps captures
//     while the evalgate call point (boolean-only) fails closed on the store
//     error and withholds the prompt. Not a leak, but the drift in the
//     availability direction: a broken boolean overrides a healthy policy.
//     Post-fix the prompt must persist (the installed policy answers ALLOW).
//   - store error under a policy DENY: the safe direction — withheld on HEAD
//     and post-fix alike (guard half, must keep passing).
func TestOBS02_ResolverErrorAtEvalgate(t *testing.T) {
	cases := []struct {
		name         string
		policyAllow  bool
		wantPrompt   string // the assertion target: "" withheld, non-empty persisted
		failsOnHead  bool
		headContrary string
	}{
		{
			name:         "store error under installed policy ALLOW",
			policyAllow:  true,
			wantPrompt:   "OBS-02 err/allow secret: " + mediumPrompt,
			failsOnHead:  true,
			headContrary: `got "" — the errored boolean store overrides the healthy ALLOW policy at the evalgate call point`,
		},
		{
			name:        "store error under policy DENY",
			policyAllow: false,
			wantPrompt:  "",
			failsOnHead: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var judgeHits int32
			judgeSrv, _, _ := judgeHitServer(t, &judgeHits)
			store := newObs02PromptStore()

			primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(completeResp("gpt-4o-mini"))
			}))
			t.Cleanup(primary.Close)

			gw := evalgateTestGateway(t, primary.URL, judgeSrv.URL, store)
			boolean := &obs02BooleanStore{err: errors.New("obs02: boolean store down")}
			policy := newObs02PolicyDouble(tc.policyAllow)
			attachObs02Retention(gw, boolean, policy)

			wantPrompt := tc.wantPrompt
			if wantPrompt == "" {
				wantPrompt = "OBS-02 err/deny secret: " + mediumPrompt
			}
			w := runObs02ChatRequest(t, gw, "org-obs02", wantPrompt)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			store.waitFor(t, 1)
			waitPolicyResolutions(t, policy, 1)

			// Seam authority fingerprint (FIX-07): behind an installed
			// policy the seam is authoritative — the errored boolean store
			// is never consulted and the healthy policy decides (V3a).
			// (On HEAD this read "want 1": the evalgate call point consulted
			// the errored boolean store as the only source it trusted.)
			if got := boolean.lookupCalls(); got != 0 {
				t.Fatalf("boolean store lookups = %d, want 0 (the installed policy is authoritative; the errored boolean store must not be consulted)", got)
			}

			prompts := store.recorded()
			if len(prompts) != 1 {
				t.Fatalf("stored verdicts = %d, want 1", len(prompts))
			}
			if tc.wantPrompt == "" {
				if prompts[0] != "" {
					t.Fatalf("guard broken: prompt persisted under policy DENY despite the store error: %q", prompts[0])
				}
				return
			}
			if prompts[0] != wantPrompt {
				if tc.failsOnHead {
					t.Fatalf("OBS-02 variant reproduced: expected the installed ALLOW policy to govern the evalgate "+
						"persistence, %s (persisted %q)", tc.headContrary, prompts[0])
				}
				t.Fatalf("prompt = %q, want %q", prompts[0], wantPrompt)
			}
		})
	}
}

// TestOBS02_StrictProfilePolicyDeny_StrictWinsAtWireButEvalgateStillPersists:
// the strict-profile interplay. Under the metadata-only local profile the
// content-profile contract drops captures upstream of any retention decision
// ("strict wins over ANY policy" — proven at the publisher in
// pkg/eventpublisher). The same request shows the split: the wire event is
// strict-sanitized (empty payload, profile stamped), while the evalgate call
// point — which consults neither the strict profile nor the installed policy,
// only the boolean — persists the PRE-MASK ORIGINAL prompt anyway. The code's
// own contract language (chat.go N02-P06 T06) classes the judge prompt as
// "the PRE-MASK original … retention-gated like every other original
// capture", so a DENY policy must withhold it here too.
func TestOBS02_StrictProfilePolicyDeny_StrictWinsAtWireButEvalgateStillPersists(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", string(config.LogContentProfileMetadataOnly))
	// Sanity: the strict profile is actually in force for this process.
	if got := config.EffectiveLogContentProfile(config.LogContentProfileFromEnv(), "", false); got != config.LogContentProfileMetadataOnly {
		t.Fatalf("sanity: local content profile = %q, want metadata-only", got)
	}

	var judgeHits int32
	judgeSrv, judgeHit, _ := judgeHitServer(t, &judgeHits)
	store := newObs02PromptStore()

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(completeResp("gpt-4o-mini"))
	}))
	t.Cleanup(primary.Close)

	gw := evalgateTestGateway(t, primary.URL, judgeSrv.URL, store)
	boolean := &obs02BooleanStore{found: true, effective: true} // org toggle ON
	policy := newObs02PolicyDouble(false)                       // installed custom policy: DENY all
	attachObs02Retention(gw, boolean, policy)
	cap := captureAll(t)

	const secretPrompt = "OBS-02 strict secret original: " + mediumPrompt
	w := runObs02ChatRequest(t, gw, "org-obs02", secretPrompt)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	// The strict profile wins at the event boundary: the observed event is
	// sanitized before any retention resolution.
	cap.waitFor(t, 1)
	ev := cap.last(t)
	if ev.Payload != "" || ev.ContentProfile != string(config.LogContentProfileMetadataOnly) {
		t.Fatalf("sanity: strict profile not applied to the wire event (payload=%q, profile=%q)",
			ev.Payload, ev.ContentProfile)
	}

	// The judge ran; a verdict reached the store.
	waitJudgeHit(t, judgeHit)
	store.waitFor(t, 1)

	// THE OBS-02 ASSERTION: strict + installed DENY must leave no original
	// text in durable persistence — the judge prompt included.
	prompts := store.recorded()
	if len(prompts) != 1 {
		t.Fatalf("stored verdicts = %d, want 1", len(prompts))
	}
	if prompts[0] != "" {
		t.Fatalf("OBS-02 reproduced: original judge prompt persisted under strict profile + policy DENY "+
			"(the evalgate call point consults neither): %q", prompts[0])
	}

	// Structural fingerprint of "strict wins over ANY policy" (mirrors
	// TestPublish_RetentionPolicySeam_StrictWinsOverAnyPolicy): under the
	// strict branch Publish drops the captures BEFORE any retention
	// resolution, so the installed policy is never even consulted at the
	// producer. The evalgate persistence is then the only remaining original
	// sink in the process — and on HEAD it answers to the boolean alone.
	if got := policy.resolutionCount(); got != 0 {
		t.Fatalf("installed policy resolutions = %d, want 0 (strict drops captures before the policy is consulted)", got)
	}
}

// TestFIX07_EvalgateDefaultBooleanPathUnchanged pins the FREE-core default
// contract through the unified seam (FIX-07 acceptance): with NO installed
// policy the evalgate persistence behaves byte-identically to the pre-seam
// boolean lookup — same resolver instance (so the same TTL cache), same
// ON/OFF matrix, same fail-closed on a resolver error. Nothing about the
// default core changes; only the seam-conditional behavior differs.
func TestFIX07_EvalgateDefaultBooleanPathUnchanged(t *testing.T) {
	cases := []struct {
		name string
		// boolean is the org-toggle source (no policy installed anywhere).
		boolean *obs02BooleanStore
		// wantLookups is the exact post-request store-lookup count when
		// exactLookups is set. ON is exact (1: the shared resolver's TTL
		// cache dedupes the producer and evalgate consults into a single
		// store read, whichever runs first — the pre-seam shape). Error and
		// not-found lookups are NOT cached by the resolver, so the detached
		// publish goroutine's consult may or may not have landed by
		// assertion time (1 or 2, identical to HEAD) — only >= 1 (the
		// evalgate consult, which precedes the verdict insert) is pinned.
		wantLookups  int
		exactLookups bool
		wantPrompt   string
	}{
		{
			name:         "boolean ON persists the prompt byte-identically",
			boolean:      &obs02BooleanStore{found: true, effective: true},
			wantLookups:  1,
			exactLookups: true,
			wantPrompt:   "OBS-02 default/on secret: " + mediumPrompt,
		},
		{
			name:        "boolean OFF (org not found) withholds, metadata intact",
			boolean:     &obs02BooleanStore{found: false},
			wantLookups: 1,
			wantPrompt:  "",
		},
		{
			name:        "boolean lookup error fails closed",
			boolean:     &obs02BooleanStore{err: errors.New("obs02: default-path store down")},
			wantLookups: 1,
			wantPrompt:  "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var judgeHits int32
			judgeSrv, judgeHit, _ := judgeHitServer(t, &judgeHits)
			store := newObs02PromptStore()

			primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(completeResp("gpt-4o-mini"))
			}))
			t.Cleanup(primary.Close)

			gw := evalgateTestGateway(t, primary.URL, judgeSrv.URL, store)
			// Boolean source wired, NO installed policy: the FREE-core
			// BooleanRetentionPolicy default answers through the same
			// resolver instance.
			attachObs02Retention(gw, tc.boolean, nil)

			wantPrompt := tc.wantPrompt
			if wantPrompt == "" {
				wantPrompt = "OBS-02 default/withheld secret: " + mediumPrompt
			}
			w := runObs02ChatRequest(t, gw, "org-obs02-default", wantPrompt)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}

			// The verdict reached the store in every case (metadata intact —
			// only the prompt text is governed).
			waitJudgeHit(t, judgeHit)
			store.waitFor(t, 1)

			// The evalgate call point consulted the boolean resolver exactly
			// once per request (the verdict insert follows the gate call),
			// through the seam's boolean default.
			got := tc.boolean.lookupCalls()
			if got < tc.wantLookups || (tc.exactLookups && got != tc.wantLookups) {
				t.Fatalf("boolean store lookups = %d, want %d (byte-identical default path)", got, tc.wantLookups)
			}

			prompts := store.recorded()
			if len(prompts) != 1 {
				t.Fatalf("stored verdicts = %d, want 1", len(prompts))
			}
			if prompts[0] != tc.wantPrompt {
				t.Fatalf("prompt = %q, want %q", prompts[0], tc.wantPrompt)
			}
		})
	}
}
