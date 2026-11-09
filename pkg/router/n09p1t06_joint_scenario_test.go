package router_test

// N09-P01-T06 joint integration scenario (hermetic MOCK stand): one client
// request walks the composed no-repeat stack end to end — the request
// identity is minted once at the boundary (T04 carrier), every hop runs the
// retry loop over transport evidence classified at the boundary (T02), the
// fallback executor gates every advance on the repetition-permission rule
// with the verified dedup contract as the only silence escape (T03), the
// typed SuppressedError explains a refused repeat (T04), and the consumer
// layers stay consistent with the seam: per-endpoint circuit breakers
// (pkg/circuit) record exactly what was dialed and never penalize a route
// the refusal protected, the sovereignty/region failover consumers
// (pkg/sovereign, pkg/regionrouter) keep their rights refusals terminal and
// precise beside the repeat refusals, and the agent-eval journal contract
// (pkg/agenteval/contracts) joins every attempt on the one request identity
// while never journaling an unknown outcome as exact zero or success.
//
// The unit guarantees themselves are pinned by T02–T05 (outcome_test,
// fallback_outcome_test, fallback_identity_test, suppressed_test,
// negative_battery_test in pkg/retry and pkg/router); nothing here re-proves
// them in isolation — this file proves the seams hold together as one user
// story (the n06p7t06 joint-scenario pattern).
//
// Environment: fully in-process. The upstream transport is a scripted
// closure (no network); the region health checker pings loopback
// httptest servers only. Production callers (pkg/gateway) may pre-wrap
// unknown transport errors into a 502 upstream_outcome_unknown PolicyError
// before the executor; that wiring is the gateway packet's scope. This
// scenario composes the delivered executor/retry/identity layers whose
// typed chain refusal is *retry.SuppressedError, exactly as T02–T05
// delivered them.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/agenteval/contracts"
	"github.com/reireirei/yabanin/pkg/circuit"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/regionrouter"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/router"
	"github.com/reireirei/yabanin/pkg/sovereign"
)

// jointStoryIdentity is the one client-request identity for the story:
// minted once at the boundary, presented unchanged by every attempt of
// every hop.
var jointStoryIdentity = retry.RequestIdentity{
	RequestID:      "req-n09p1t06-joint",
	IdempotencyKey: "idem-n09p1t06-joint",
}

// jointUnknownOutcomeError mirrors the caller-side evidence loss at the hop
// boundary: the transport error stays reachable via Unwrap, but it carries
// no HTTP status, so the chain-facing classification of (0, err) is
// unknown.
type jointUnknownOutcomeError struct{ cause error }

func (e jointUnknownOutcomeError) Error() string {
	return "upstream outcome unknown: " + e.cause.Error()
}

func (e jointUnknownOutcomeError) Unwrap() error { return e.cause }

// jointPartialStreamError is an error from a stream that produced bytes and
// then broke mid-body: execution was observed, so nothing about it is
// silence — but it arrives at the chain with no HTTP answer.
type jointPartialStreamError struct{ bytes int }

func (e jointPartialStreamError) Error() string {
	return fmt.Sprintf("stream produced %d bytes then failed mid-body", e.bytes)
}

// jointEndpoint is one upstream probe endpoint: it counts every transport
// call and scripts its answers by call number (1-based).
type jointEndpoint struct {
	calls  atomic.Int64
	behave func(call int64) retry.Result
}

func (e *jointEndpoint) result(_ context.Context, _ resolver.ModelInfo) retry.Result {
	call := e.calls.Add(1)
	return e.behave(call)
}

func (e *jointEndpoint) count() int64 { return e.calls.Load() }

// jointStack is the composed per-hop call path, mirroring the production
// gateway hop shape (breaker admission → retry loop over classified
// transport evidence → breaker bookkeeping per hop): circuit consumer, T02
// classification and T03/T04 seam rules in one closure handed to the real
// FallbackExecutor. probes keys the scripted upstreams by endpoint URL.
type jointStack struct {
	circuits    *circuit.Map
	policy      retry.Policy
	probes      map[string]*jointEndpoint
	identityLog []retry.RequestIdentity // one entry per transport call
}

// attempt is the AttemptFunc for one candidate: exactly the production
// order — cancellation, breaker admission, classified retry loop, hop-level
// breaker bookkeeping. The identity is read inside the transport closure so
// the log shows what every attempt of every retry actually presented.
func (s *jointStack) attempt(ctx context.Context, mi resolver.ModelInfo) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	key := circuit.EndpointKey(mi.UpstreamURL)
	if err := s.circuits.Allow(key); err != nil {
		return http.StatusServiceUnavailable,
			fmt.Errorf("circuit breaker open for endpoint %s: %w", key, err)
	}
	probe := s.probes[mi.UpstreamURL]
	if probe == nil {
		return http.StatusInternalServerError,
			fmt.Errorf("joint stack: no scripted upstream for %s", mi.UpstreamURL)
	}
	res := retry.Do(ctx, s.policy, func(ctx context.Context) retry.Result {
		out := probe.result(ctx, mi)
		s.identityLog = append(s.identityLog, retry.RequestIdentityFrom(ctx))
		if out.Err != nil {
			// The caller-observed-evidence channel: only a caller that saw
			// execution (or an HTTP answer) may keep an explicit Safety; a
			// bare transport failure with no answer and no non-execution
			// proof loses its evidence class the way production callers
			// surface it — silent until proven otherwise.
			if out.Safety != retry.OutcomeUnknown {
				return out
			}
			if out.StatusCode > 0 || retry.DefinitelyNotSent(out.Err) {
				out.Safety = retry.OutcomeNotExecuted
			} else {
				out.Err = jointUnknownOutcomeError{cause: out.Err}
			}
		}
		return out
	})
	if res.Err == nil && res.StatusCode < 500 {
		s.circuits.RecordSuccess(key)
		return res.StatusCode, nil
	}
	s.circuits.RecordFailure(key)
	errOut := res.Err
	if errOut == nil {
		errOut = fmt.Errorf("upstream error %d", res.StatusCode)
	}
	return res.StatusCode, errOut
}

// newJointStack builds the composed stack: a fresh per-endpoint breaker map
// (threshold 1 so a single recorded failure opens that endpoint's circuit —
// deterministic), a fast deterministic retry policy, the scripted upstream
// probes, and the story identity carried in the context.
func newJointStack(probes map[string]*jointEndpoint) (*context.Context, *jointStack) {
	ctx := retry.WithRequestIdentity(context.Background(), jointStoryIdentity)
	return &ctx, &jointStack{
		circuits: circuit.NewMap(circuit.Config{
			Name:             "joint",
			Enabled:          true,
			FailureThreshold: 1,
			SuccessThreshold: 1,
			OpenTimeout:      time.Minute,
			Window:           time.Minute,
		}, 0, nil),
		policy: retry.Policy{
			MaxAttempts: 3,
			BaseDelay:   time.Millisecond,
			MaxDelay:    time.Millisecond,
			RetryOn:     retry.DefaultClassifier,
		},
		probes: probes,
	}
}

// jointPrimary is the story chain head: primary ep-a with failovers on
// ep-b and ep-c, each a distinct endpoint (its own breaker key).
func jointPrimary() resolver.ModelInfo {
	return resolver.ModelInfo{
		ModelName:      "joint-primary",
		Provider:       "prov-a",
		UpstreamURL:    "http://ep-a-joint",
		FailoverModels: []string{"joint-second", "joint-third"},
	}
}

// jointResolver stubs the registry with the story's three-candidate chain.
func jointResolver() *fakeResolver {
	return newFakeResolver(map[string]resolver.ModelInfo{
		"joint-second": {ModelName: "joint-second", Provider: "prov-b", UpstreamURL: "http://ep-b-joint", Enabled: true},
		"joint-third":  {ModelName: "joint-third", Provider: "prov-c", UpstreamURL: "http://ep-c-joint", Enabled: true},
	})
}

// jointProbes wires the scripted endpoints onto the story's endpoint URLs.
func jointProbes(a, b, c func(call int64) retry.Result) map[string]*jointEndpoint {
	return map[string]*jointEndpoint{
		"http://ep-a-joint": {behave: a},
		"http://ep-b-joint": {behave: b},
		"http://ep-c-joint": {behave: c},
	}
}

// jointProof is the verified provider/action deduplication contract: it
// counts every consult so the story can pin that only the silent attempt
// ever reaches it.
type jointProof struct {
	consults atomic.Int64
}

func (p *jointProof) AllowsRetry() bool {
	p.consults.Add(1)
	return true
}

// jointJournal is the agent-eval journal consumer: it turns the chain's
// AttemptOutcome trace and final error into the contracts.CallRecord /
// EpisodeRecord DTOs the way a journal writer at the API boundary would.
//
// Mapping rules (the consumer-consistency contract under test):
//   - attempt_index joins 1:1 with the chain-stamped Attempt; model_actual
//     is the candidate that actually served the attempt;
//   - a failed attempt is status "error" and never "ok";
//   - the chain's typed refusal renders its stable machine-readable code on
//     exactly the suppressed candidate's record;
//   - an unknown-outcome attempt is Cost.Uncertain=true with a nil
//     EstimatedUSD — unknown is not zero and not success (the contracts'
//     "nil means unknown — never zero" discipline);
//   - the episode is "completed" only when the chain reported success; a
//     suppressed story is "failed", and the running→X transition is
//     validated against the journal state machine.
type jointJournal struct {
	records []contracts.CallRecord
}

func (j *jointJournal) fromAttempts(attempts []router.AttemptOutcome) {
	for _, o := range attempts {
		rec := contracts.CallRecord{
			CallID:         fmt.Sprintf("%s-attempt-%d", o.RequestID, o.Attempt),
			AttemptIndex:   o.Attempt,
			ModelRequested: "joint-primary",
			Endpoint:       o.UpstreamURL,
			Status:         "ok",
		}
		model := o.ModelName
		rec.ModelActual = &model
		if !o.Success {
			rec.Status = "error"
			rec.Error = &contracts.CallError{Code: "upstream_error", Message: o.Error}
		}
		if o.Outcome == retry.OutcomeUnknown.String() {
			// Unknown outcome: uncertain billing, never a claimed exact
			// zero and never a silent success.
			rec.Cost = contracts.CallCost{Uncertain: true}
		}
		j.records = append(j.records, rec)
	}
}

// finalize renders the chain-level refusal onto the suppressed attempt's
// record and closes the episode. chainErr may be nil (success story).
func (j *jointJournal) finalize(t *testing.T, epID string, chainErr error) contracts.EpisodeRecord {
	t.Helper()
	if chainErr != nil {
		var suppressed *retry.SuppressedError
		require.ErrorAs(t, chainErr, &suppressed,
			"the composed chain refusal must stay typed for the journal writer")
		matched := false
		for i := range j.records {
			rec := &j.records[i]
			if rec.ModelActual != nil && *rec.ModelActual == suppressed.Model {
				rec.Error.Code = suppressed.Code()
				matched = true
			}
		}
		require.True(t, matched, "the suppressed candidate must have a journal record")
	}
	status := contracts.StatusCompleted
	if chainErr != nil {
		status = contracts.StatusFailed
	}
	require.True(t, contracts.StatusRunning.CanTransitionTo(status),
		"the journal state machine must accept the story's terminal transition")
	return contracts.EpisodeRecord{
		EpisodeID:       epID,
		RootID:          jointStoryIdentity.RequestID,
		ExecutionStatus: status,
	}
}

// TestN09P1T06_JointScenario_SilentPrimaryIsTerminalEverywhere composes the
// default story: the primary goes silent after its bytes were written (a
// first-byte timeout — not a non-execution proof), no dedup contract
// exists. Expected composition: the hop's retry loop refuses a second call
// by itself, the executor refuses the chain advance, the typed refusal
// surfaces, the breaker consumer records the one real failure, the
// never-dialed candidates' breakers are never even created, and the journal
// keeps the story honestly failed-and-uncertain.
func TestN09P1T06_JointScenario_SilentPrimaryIsTerminalEverywhere(t *testing.T) {
	ctx, stack := newJointStack(jointProbes(
		func(int64) retry.Result { return retry.Result{Err: firstByteTimeout{}} },
		func(int64) retry.Result { return retry.Result{StatusCode: http.StatusOK} },
		func(int64) retry.Result { return retry.Result{StatusCode: http.StatusOK} },
	))

	exec := router.NewFallbackExecutor(jointResolver(), 5, nil)
	info, code, attempts, err := exec.Execute(*ctx, jointPrimary(), stack.attempt)

	require.Error(t, err, "a silenced billable attempt must not end in success")
	require.Equal(t, 0, code)
	var suppressed *retry.SuppressedError
	require.ErrorAs(t, err, &suppressed, "the refusal must be the typed explanation")
	assert.Equal(t, retry.SuppressedUnknownCode, suppressed.Code(),
		"the machine-readable refusal code is the unknown-outcome code")
	assert.Equal(t, "joint-primary", suppressed.Model)
	var fbt firstByteTimeout
	require.ErrorAs(t, err, &fbt,
		"the original terminal cause stays reachable through the typed refusal")
	assert.True(t, fbt.Timeout(), "the cause is the first-byte timeout itself")
	assert.Equal(t, "joint-primary", info.ModelName,
		"finalInfo resolves to the last attempted candidate — the chain stopped here")
	require.Len(t, attempts, 1, "the chain must not advance past the silenced primary")

	// The retry seam refused on its own: exactly one transport call against
	// a MaxAttempts=3 policy — silence never became a retry.
	assert.Equal(t, int64(1), stack.probes["http://ep-a-joint"].count(),
		"the hop retry loop must not re-call a silent attempt")
	assert.Zero(t, stack.probes["http://ep-b-joint"].count(), "candidate B is never dialed")
	assert.Zero(t, stack.probes["http://ep-c-joint"].count(), "candidate C is never dialed")

	// The chain stamp joins the one identity and the evidence class.
	assert.Equal(t, jointStoryIdentity.RequestID, attempts[0].RequestID)
	assert.Equal(t, 1, attempts[0].Attempt)
	assert.Equal(t, retry.OutcomeUnknown.String(), attempts[0].Outcome)
	assert.False(t, attempts[0].Success, "no false successful status")

	// Circuit consumer consistency: the dialed endpoint recorded exactly one
	// failure; the protected routes never had a breaker created at all.
	assert.Equal(t, 1, stack.circuits.Len(),
		"the refusal protects the other endpoints even from breaker admission")
	a := stack.circuits.Breaker(circuit.EndpointKey("http://ep-a-joint"))
	assert.Equal(t, 1, a.Metrics().FailureCount)
	assert.Equal(t, circuit.StateOpen, a.State(),
		"threshold-1 breaker: the recorded failure opened the silenced endpoint")

	// Journal consumer consistency: one honest record, uncertain billing, no
	// false success, stable refusal code rendered.
	journal := &jointJournal{}
	journal.fromAttempts(attempts)
	ep := journal.finalize(t, "ep-silent", err)
	require.Len(t, journal.records, 1)
	rec := journal.records[0]
	assert.Equal(t, 1, rec.AttemptIndex)
	require.NotNil(t, rec.ModelActual)
	assert.Equal(t, "joint-primary", *rec.ModelActual)
	assert.Equal(t, "error", rec.Status)
	require.NotNil(t, rec.Error)
	assert.Equal(t, retry.SuppressedUnknownCode, rec.Error.Code,
		"the journal renders the seam's stable refusal code")
	assert.True(t, rec.Cost.Uncertain, "an unknown outcome is journaled uncertain")
	assert.Nil(t, rec.Cost.EstimatedUSD, "unknown is never journalized as exact zero")
	assert.Equal(t, contracts.StatusFailed, ep.ExecutionStatus,
		"the episode is failed, never completed")
	assert.Equal(t, jointStoryIdentity.RequestID, ep.RootID,
		"the episode joins on the boundary-minted request identity")
}

// TestN09P1T06_JointScenario_ContractPermitsAdvanceKeepsOneIdentity
// composes the contract story: the same silenced primary, now with a
// verified provider dedup contract attached to the executor. The chain may
// advance; candidate B answers a definitive 503 (retried intra-hop by the
// ordinary policy — a definitive answer is ordinary business, unlike
// silence), candidate C completes the request. One identity reaches every
// transport call of every hop; the contract is consulted exactly once.
func TestN09P1T06_JointScenario_ContractPermitsAdvanceKeepsOneIdentity(t *testing.T) {
	ctx, stack := newJointStack(jointProbes(
		func(int64) retry.Result { return retry.Result{Err: firstByteTimeout{}} },
		func(int64) retry.Result { return retry.Result{StatusCode: http.StatusServiceUnavailable} },
		func(int64) retry.Result { return retry.Result{StatusCode: http.StatusOK} },
	))

	proof := &jointProof{}
	exec := router.NewFallbackExecutor(jointResolver(), 5, nil).
		WithIdempotencyProof(proof)
	info, code, attempts, err := exec.Execute(*ctx, jointPrimary(), stack.attempt)

	require.NoError(t, err, "the verified contract permits the advance and C completes")
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "joint-third", info.ModelName)
	require.Len(t, attempts, 3, "primary, second and third candidates all ran")

	// Transport call counts: the silent primary exactly once (the contract
	// lives at the chain, not inside the hop), the definitive 503 retried
	// intra-hop until the hop's MaxAttempts budget is exhausted, C once.
	assert.Equal(t, int64(1), stack.probes["http://ep-a-joint"].count(),
		"silence is never retried intra-hop even under an allowing contract")
	assert.Equal(t, int64(3), stack.probes["http://ep-b-joint"].count(),
		"a definitive 503 follows the ordinary retry policy to the hop budget")
	assert.Equal(t, int64(1), stack.probes["http://ep-c-joint"].count())

	// The contract was consulted exactly once — only for the silent attempt;
	// definitive answers never reach it.
	assert.Equal(t, int64(1), proof.consults.Load())
	// Five transport calls happened (A×1, B×3, C×1) and every one of them
	// presented the one boundary-minted identity.
	require.Len(t, stack.identityLog, 5)
	for i, id := range stack.identityLog {
		assert.Equal(t, jointStoryIdentity, id,
			"transport call %d must present the unchanged request identity", i+1)
	}

	// Chain stamps: contiguous 1-based attempts, one RequestID, honest
	// evidence classes per attempt.
	for i, o := range attempts {
		assert.Equal(t, i+1, o.Attempt)
		assert.Equal(t, jointStoryIdentity.RequestID, o.RequestID)
	}
	assert.Equal(t, retry.OutcomeUnknown.String(), attempts[0].Outcome)
	assert.Equal(t, retry.OutcomeExecuted.String(), attempts[1].Outcome)
	assert.Equal(t, retry.OutcomeExecuted.String(), attempts[2].Outcome)

	// Circuit consumer consistency: one recorded failure per failed hop (the
	// breaker bookkeeping is per hop, not per intra-hop retry), one success
	// on the completing endpoint.
	assert.Equal(t, 3, stack.circuits.Len())
	assert.Equal(t, 1, stack.circuits.Breaker(circuit.EndpointKey("http://ep-a-joint")).Metrics().FailureCount)
	assert.Equal(t, 1, stack.circuits.Breaker(circuit.EndpointKey("http://ep-b-joint")).Metrics().FailureCount)
	c := stack.circuits.Breaker(circuit.EndpointKey("http://ep-c-joint"))
	assert.Equal(t, circuit.StateClosed, c.State())
	assert.Equal(t, 0, c.Metrics().FailureCount,
		"the completing endpoint carries no recorded failure")

	// Journal consumer consistency: three records on one root identity; only
	// the silent attempt is uncertain; the completed story is completed.
	journal := &jointJournal{}
	journal.fromAttempts(attempts)
	ep := journal.finalize(t, "ep-contract", nil)
	require.Len(t, journal.records, 3)
	for i, rec := range journal.records {
		assert.Equal(t, i+1, rec.AttemptIndex)
		require.NotNil(t, rec.ModelActual)
	}
	assert.True(t, journal.records[0].Cost.Uncertain,
		"the advanced-past silent attempt stays uncertain — never zero-claimed")
	assert.False(t, journal.records[1].Cost.Uncertain)
	assert.False(t, journal.records[2].Cost.Uncertain)
	assert.Equal(t, "ok", journal.records[2].Status)
	require.NotNil(t, journal.records[0].Error,
		"the failed silent attempt still journals its hop-level error")
	assert.Equal(t, "upstream_error", journal.records[0].Error.Code,
		"an advanced-past attempt carries the hop error, not the chain refusal code")
	assert.NotEqual(t, retry.SuppressedUnknownCode, journal.records[0].Error.Code,
		"only a chain-stopping refusal renders the suppression code")
	assert.Equal(t, contracts.StatusCompleted, ep.ExecutionStatus)
}

// TestN09P1T06_JointScenario_PartialStreamNeverReplaysThroughTheStack
// composes the executed-evidence story: the transport observed a partial
// stream (bytes flowed, then the body broke). The retry seam holds by the
// caller-observed evidence (OutcomeExecuted), and the chain — which faces
// (0, err) with no answer and no non-execution proof — refuses the advance
// under the conservative unknown class. Exactly one upstream call happens
// anywhere in the composed stack; the typed refusal surfaces.
func TestN09P1T06_JointScenario_PartialStreamNeverReplaysThroughTheStack(t *testing.T) {
	ctx, stack := newJointStack(jointProbes(
		func(int64) retry.Result {
			// The caller observed execution: it may set the executed class
			// explicitly (the T02 evidence contract).
			return retry.Result{Err: jointPartialStreamError{bytes: 128}, Safety: retry.OutcomeExecuted}
		},
		func(int64) retry.Result { return retry.Result{StatusCode: http.StatusOK} },
		func(int64) retry.Result { return retry.Result{StatusCode: http.StatusOK} },
	))

	exec := router.NewFallbackExecutor(jointResolver(), 5, nil)
	_, code, attempts, err := exec.Execute(*ctx, jointPrimary(), stack.attempt)

	require.Error(t, err)
	assert.Equal(t, 0, code)
	assert.Equal(t, int64(1), stack.probes["http://ep-a-joint"].count(),
		"the partial stream is never replayed inside the hop (MaxAttempts=3 policy)")
	assert.Zero(t, stack.probes["http://ep-b-joint"].count(), "the chain never advances past it")
	assert.Zero(t, stack.probes["http://ep-c-joint"].count())
	require.Len(t, attempts, 1)
	var suppressed *retry.SuppressedError
	require.ErrorAs(t, err, &suppressed,
		"the composed stack still refuses with the typed explanation")
	assert.Equal(t, retry.SuppressedUnknownCode, suppressed.Code(),
		"chain-facing evidence (0, err) classifies unknown — the conservative refusal code")
	var pse jointPartialStreamError
	require.ErrorAs(t, err, &pse, "the stream cause stays reachable")
	assert.Equal(t, 128, pse.bytes)

	// Belt and suspenders, pinned honestly: the hop knew "executed" while the
	// chain DTO shows the unknown class. Both layers refuse — the negative
	// guarantee (no replay) does not depend on which evidence survives the
	// hop boundary.
	assert.Equal(t, retry.OutcomeUnknown.String(), attempts[0].Outcome)
	assert.False(t, attempts[0].Success)

	journal := &jointJournal{}
	journal.fromAttempts(attempts)
	ep := journal.finalize(t, "ep-partial", err)
	assert.True(t, journal.records[0].Cost.Uncertain)
	assert.Equal(t, contracts.StatusFailed, ep.ExecutionStatus)
}

// TestN09P1T06_JointScenario_OpenCircuitRoutesWithoutRepeating composes the
// circuit consumer across two consecutive requests. Request 1 silences and
// opens the primary endpoint's threshold-1 breaker (the default story
// above). Request 2 meets the open circuit: the breaker's local 503 refusal
// is a definitive answer (classified executed, retryable) — the chain
// advances and completes on B, and the silenced upstream is never dialed
// again. The open breaker adds no second failure to itself.
func TestN09P1T06_JointScenario_OpenCircuitRoutesWithoutRepeating(t *testing.T) {
	ctx, stack := newJointStack(jointProbes(
		func(int64) retry.Result { return retry.Result{Err: firstByteTimeout{}} },
		func(int64) retry.Result { return retry.Result{StatusCode: http.StatusOK} },
		func(int64) retry.Result { return retry.Result{StatusCode: http.StatusOK} },
	))

	exec := router.NewFallbackExecutor(jointResolver(), 5, nil)

	// Request 1: silence → suppression → breaker records one failure → open.
	_, _, attempts1, err1 := exec.Execute(*ctx, jointPrimary(), stack.attempt)
	require.Error(t, err1)
	var suppressed *retry.SuppressedError
	require.ErrorAs(t, err1, &suppressed)
	require.Len(t, attempts1, 1)
	require.Equal(t, int64(1), stack.probes["http://ep-a-joint"].count())
	keyA := circuit.EndpointKey("http://ep-a-joint")
	require.Equal(t, circuit.StateOpen, stack.circuits.Breaker(keyA).State())

	// Request 2: the same chain, same breakers, a fresh identity per request
	// lifetime (a new client request mints a new identity at the boundary).
	second := retry.RequestIdentity{RequestID: "req-n09p1t06-joint-2"}
	ctx2 := retry.WithRequestIdentity(context.Background(), second)
	stack.identityLog = nil
	info2, code2, attempts2, err2 := exec.Execute(ctx2, jointPrimary(), stack.attempt)

	require.NoError(t, err2, "the open primary circuit is retryable; B completes")
	assert.Equal(t, http.StatusOK, code2)
	assert.Equal(t, "joint-second", info2.ModelName)
	require.Len(t, attempts2, 2)

	// The silenced upstream was never dialed again — the open circuit
	// pre-empts the attempt entirely.
	assert.Equal(t, int64(1), stack.probes["http://ep-a-joint"].count(),
		"request 2 must not re-dispatch the silenced endpoint")
	assert.Equal(t, int64(1), stack.probes["http://ep-b-joint"].count())

	// The open-rejection attempt is a definitive local answer: executed
	// class, HTTP status, not an unknown silence.
	assert.Equal(t, http.StatusServiceUnavailable, attempts2[0].StatusCode)
	assert.Equal(t, retry.OutcomeExecuted.String(), attempts2[0].Outcome)
	assert.Equal(t, retry.OutcomeExecuted.String(), attempts2[1].Outcome)
	assert.Equal(t, second.RequestID, attempts2[0].RequestID,
		"request 2 carries its own identity across its attempts")
	assert.Equal(t, second.RequestID, attempts2[1].RequestID)

	// Breaker consistency: no double penalty for the rejected hop, and C was
	// never admitted (its breaker does not exist).
	assert.Equal(t, 2, stack.circuits.Len(),
		"only the two dialed endpoints ever held breakers")
	assert.Equal(t, 1, stack.circuits.Breaker(keyA).Metrics().FailureCount,
		"the open-circuit rejection must not add a second failure")

	journal := &jointJournal{}
	journal.fromAttempts(attempts2)
	ep := journal.finalize(t, "ep-after-open", nil)
	assert.False(t, journal.records[0].Cost.Uncertain,
		"a definitive local 503 refusal is not an unknown outcome")
	assert.Equal(t, contracts.StatusCompleted, ep.ExecutionStatus)
}

// TestN09P1T06_JointScenario_RightsRefusalsStayTerminalBesideRepeatRefusals
// composes the rights consumers. Region layer: the org's home region is
// down; the only healthy failover peer sits in a country the org's
// sovereign inference-egress policy excludes — the evaluator refuses with
// the precise structured reason instead of redirecting, and the same stack
// redirects when the policy permits. Chain layer: an RT-03-shaped policy
// denial on the primary stays terminal even beside an allowing dedup
// contract — the rights refusal wins before any repetition question.
func TestN09P1T06_JointScenario_RightsRefusalsStayTerminalBesideRepeatRefusals(t *testing.T) {
	// ---- Region failover consumer (sovereign policy × regionrouter). -----
	livePeer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(livePeer.Close)

	regions := config.RegionMap{
		"reg-a": {Name: "reg-a", Country: "DE", GatewayURL: "http://127.0.0.1:1", Priority: 1},
		"reg-c": {Name: "reg-c", Country: "AU", GatewayURL: livePeer.URL, Priority: 3},
	}
	orgRouter := regionrouter.New(jointOrgStore{home: "reg-a"}, jointKV{})
	checker := regionrouter.NewHealthChecker([]regionrouter.PeerURL{
		{Region: "reg-a", URL: "http://127.0.0.1:1"},
		{Region: "reg-c", URL: livePeer.URL},
	})

	t.Run("denied peer is never used even when it is the only one", func(t *testing.T) {
		denying := jointPolicySource{policy: sovereign.Policy{
			Egress: map[sovereign.EgressKind]sovereign.EgressProfile{
				sovereign.EgressInference: {ExcludedCountries: []string{"AU"}},
			},
		}}
		eval := regionrouter.NewFailoverEvaluator(orgRouter, checker, regions, "reg-b", nil).
			WithPolicySource(denying).
			WithEgressKind(sovereign.EgressInference)
		err := eval.Decide(context.Background(), "org-n09p1t06")
		require.Error(t, err, "no permitted peer: the evaluator must refuse, not redirect")
		assert.Contains(t, err.Error(), "denied by egress policy",
			"the refusal names the egress rule")
		assert.Contains(t, err.Error(), "kind=inference")
		// N09-P05-T04 upgraded the refusal to *ErrFailoverPeersDenied with
		// one reason record per denied peer; the single denied peer (reg-c,
		// AU) must still be accounted for explicitly.
		var peerDenied *regionrouter.ErrFailoverPeersDenied
		require.ErrorAs(t, err, &peerDenied)
		require.Len(t, peerDenied.Denied, 1)
		assert.Equal(t, "reg-c", peerDenied.Denied[0].Region)
		assert.Equal(t, sovereign.DenialKindExcluded, peerDenied.Denied[0].Rule)
		assert.NotContains(t, err.Error(), "redirect to",
			"no redirect into the excluded jurisdiction")
	})

	t.Run("the same stack redirects when the policy permits", func(t *testing.T) {
		permitting := jointPolicySource{policy: sovereign.DefaultPolicy()}
		eval := regionrouter.NewFailoverEvaluator(orgRouter, checker, regions, "reg-b", nil).
			WithPolicySource(permitting).
			WithEgressKind(sovereign.EgressInference)
		err := eval.Decide(context.Background(), "org-n09p1t06")
		require.Error(t, err) // the redirect is delivered as the decision error
		assert.Contains(t, err.Error(), "redirect to reg-c",
			"with rights granted, the failover proceeds to the healthy peer")
	})

	// ---- Chain layer: rights refusal wins over an allowing contract. -----
	t.Run("policy denial is terminal beside an allowing dedup contract", func(t *testing.T) {
		ctx, stack := newJointStack(jointProbes(
			func(int64) retry.Result {
				return retry.Result{
					StatusCode: http.StatusForbidden,
					Err: &router.PolicyError{
						Status:  http.StatusForbidden,
						ErrType: "invalid_request_error",
						ErrCode: "policy_denied",
						Message: "denied by the per-attempt policy gate",
					},
				}
			},
			func(int64) retry.Result { return retry.Result{StatusCode: http.StatusOK} },
			func(int64) retry.Result { return retry.Result{StatusCode: http.StatusOK} },
		))
		proof := &jointProof{}
		exec := router.NewFallbackExecutor(jointResolver(), 5, nil).
			WithIdempotencyProof(proof)

		_, code, attempts, err := exec.Execute(*ctx, jointPrimary(), stack.attempt)

		require.Error(t, err)
		assert.Equal(t, http.StatusForbidden, code)
		require.Len(t, attempts, 1, "the rights refusal is chain-terminal")
		assert.Zero(t, stack.probes["http://ep-b-joint"].count())
		assert.Zero(t, stack.probes["http://ep-c-joint"].count())
		assert.Equal(t, int64(0), proof.consults.Load(),
			"the dedup contract is never consulted for a policy outcome")
		var suppressed *retry.SuppressedError
		assert.NotErrorAs(t, err, &suppressed,
			"a rights refusal is not a repeat refusal — it surfaces unchanged")
		var policyErr *router.PolicyError
		require.ErrorAs(t, err, &policyErr)
		assert.Equal(t, "policy_denied", policyErr.ErrCode)
	})
}

// jointOrgStore is the hermetic region read contract: one org, one home.
type jointOrgStore struct{ home string }

func (s jointOrgStore) LookupRegion(context.Context, string) (string, bool, error) {
	return s.home, false, nil
}

// jointKV is a cache that always misses and swallows writes: the router
// falls through to the store deterministically.
type jointKV struct{}

func (jointKV) Get(context.Context, string) (string, error) {
	return "", errors.New("jointKV: miss")
}

func (jointKV) Set(context.Context, string, string, time.Duration) error { return nil }

func (jointKV) Del(context.Context, string) error { return nil }

// jointPolicySource is the per-org sovereignty policy source.
type jointPolicySource struct{ policy sovereign.Policy }

func (s jointPolicySource) Get(context.Context, string) sovereign.Policy { return s.policy }
