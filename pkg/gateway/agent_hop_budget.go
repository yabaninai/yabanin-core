package cli

// N06-P07-T03: policy-invoked detector hops and internal model/tool loops
// ride the SAME budget as interactive traffic. The packaged
// llmjudge.UpstreamJudgeClient dials upstream.Pool directly — no §5
// admission, no reservation, no settlement event — so judge spend was
// invisible to the wallet, the budget areas and the consumer. Gateways wire
// budgetedJudgeClient instead (see gw.newBudgetedJudgeClient and the
// buildPolicyRuntime handoff note): every judge hop is
//
//  1. loop-bounded   — one external request cannot trigger internal model
//     hops past budget.LoopBudget's per-episode cap (fail-closed),
//  2. agent-budget checked — the same G2 CheckAgentBudget admissionCore
//     runs for interactive traffic (fail-closed),
//  3. §5-admitted    — Admission.Plan + Reserve against the same scopes
//     (wallet/team/agent/session) with the same estimator bounds,
//  4. settled        — exactly one request.completed event per hop carrying
//     EXACT upstream usage, the computed cost and the Finalize tuples, so
//     the consumer charges it like any other usage.
//
// Denials surface as judge-step errors, so the policy's on_error mode
// governs the request outcome (the engine default fail_closed denies; the
// recommended fail_open+flag serves with a flagged finding).
//
// The transport below intentionally mirrors llmjudge.UpstreamJudgeClient's
// wire behavior (judge-marker refusal, ModelResolver/KeyResolver, judge
// header, per-target timeout, SSRF-guarded pool client) and adds usage
// capture: llmjudge.ChatResponse carries only the verdict content, and
// pkg/pipeline is outside this card's write scope, so exact-usage settlement
// requires this client to own the round trip. If the packaged client gains a
// usage-bearing response, this reimplementation can shrink onto it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/reireirei/yabanin/pkg/budget"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/pipeline/llmjudge"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// agentHopEndpoint labels the judge hop's analytics events and keeps them
// distinct from every client-facing endpoint in the settlement pipeline.
const agentHopEndpoint = "policy_judge"

// agentHopMethod is the transport method of every judge hop.
const agentHopMethod = http.MethodPost

// Body-capture bounds, mirroring the packaged judge client: verdicts are
// small and error pages must not eat memory.
const (
	agentHopMaxErrorBody = 8 << 10
	agentHopMaxRespBody  = 4 << 20
)

// defaultLoopBudget is the process-wide internal-loop budget used when the
// wiring does not inject one. It lives here (not on the gateway struct)
// because the gateway facets are outside this card's write scope; the
// sync.Once keeps the constructor race-free under parallel policy loads.
var (
	defaultLoopBudgetOnce sync.Once
	defaultLoopBudget     *budget.LoopBudget
)

// sharedLoopBudget returns the process-wide loop budget, creating it on
// first use with the package defaults.
func sharedLoopBudget() *budget.LoopBudget {
	defaultLoopBudgetOnce.Do(func() {
		defaultLoopBudget = budget.NewLoopBudget(budget.DefaultLoopMaxHops, budget.DefaultLoopTTL)
	})
	return defaultLoopBudget
}

// budgetedJudgeClient is the admission- and settlement-bearing judge
// transport. It implements llmjudge.JudgeClient and is safe for concurrent
// use (the engine may run judge steps in parallel groups); all shared state
// lives in the injected collaborators.
type budgetedJudgeClient struct {
	pool   *upstream.Pool
	models llmjudge.ModelResolver
	keys   llmjudge.KeyResolver

	// loop bounds the internal hops per external request. nil = accounting
	// off (budget.LoopBudget's own nil-safety allows everything).
	loop *budget.LoopBudget

	// admission runs the §5 Plan/Reserve/Finalize for the hop. nil =
	// reservations off for this deploy (legacy behavior for the hop too).
	admission *budget.Admission

	// invocations is the Preview2 durable request-accounting store. nil =
	// fail closed: a judge hop is a paid provider dispatch, so an
	// unbindable durable start refuses the hop outright (the central
	// gateway binding's posture — no ungated internal traffic).
	invocations invocationStore

	// agentEnforcer mirrors admissionCore's G2 per-agent check. nil-safe.
	agentEnforcer agentBudgetChecker

	publisher *eventpub.RedisPublisher
	log       *slog.Logger
	// now lets tests pin the clock on the settle event's duration.
	now func() time.Time
}

// NewBudgetedJudgeClient builds the judge client gateways wire into
// llmjudge.SetDefaultDeps. pool is required; models/keys may be nil for
// plain openai-compatible key-less endpoints; admission/loop/agentEnforcer
// and publisher are nil-safe and disable their respective accounting.
//
// Preview2 durable accounting: the store is NOT a positional parameter
// (an internal interface must not sit in the required signature slot —
// upstream callers compile unchanged). Without the additive option a nil
// store fails every hop closed: a judge hop is a paid dispatch, so it
// mirrors the central binding (no unrecorded paid starts).
func NewBudgetedJudgeClient(pool *upstream.Pool, models llmjudge.ModelResolver, keys llmjudge.KeyResolver, admission *budget.Admission, loop *budget.LoopBudget, agentEnforcer agentBudgetChecker, publisher *eventpub.RedisPublisher, log *slog.Logger, opts ...BudgetedJudgeClientOption) llmjudge.JudgeClient {
	if log == nil {
		log = slog.Default()
	}
	c := &budgetedJudgeClient{
		pool:          pool,
		models:        models,
		keys:          keys,
		loop:          loop,
		admission:     admission,
		agentEnforcer: agentEnforcer,
		publisher:     publisher,
		log:           log,
		now:           time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// BudgetedJudgeClientOption is the additive wiring surface for the judge
// client (kept out of the positional signature for source compatibility).
type BudgetedJudgeClientOption func(*budgetedJudgeClient)

// WithJudgeInvocationStore wires the durable invocation store the hop's
// confirmed start and terminal facts commit through.
func WithJudgeInvocationStore(store invocationStore) BudgetedJudgeClientOption {
	return func(c *budgetedJudgeClient) { c.invocations = store }
}

// newBudgetedJudgeClient builds the client from the gateway's own
// collaborators. This is the drop-in replacement for
// llmjudge.NewUpstreamJudgeClient at the buildPolicyRuntime wiring site:
//
//	Client: gw.newBudgetedJudgeClient(gatewayJudgeModels{gw: gw}, gatewayJudgeKeys{gw: gw})
//
// buildPolicyRuntime (gateway_policy.go) installs it as the process-wide
// llmjudge.DefaultDeps client (N06-P07-T03 wiring landed).
func (gw *gateway) newBudgetedJudgeClient(models llmjudge.ModelResolver, keys llmjudge.KeyResolver) llmjudge.JudgeClient {
	return NewBudgetedJudgeClient(gw.pool, models, keys, gw.admission, sharedLoopBudget(), gw.agentEnforcer, gw.publisher, gw.log,
		WithJudgeInvocationStore(gw.invocations))
}

// JudgeChat implements llmjudge.JudgeClient: admit, call, settle.
func (c *budgetedJudgeClient) JudgeChat(ctx context.Context, req llmjudge.ChatRequest) (llmjudge.ChatResponse, error) {
	// Recursion-exclusion contract: the judge marker must ride the meta —
	// the client is the last line of defense before the wire (the packaged
	// client refuses unmarked calls; so does this one).
	if !llmjudge.IsJudgeMeta(req.Meta) {
		return llmjudge.ChatResponse{}, fmt.Errorf("judge call refused: meta lacks the %s=%s marker (recursion-exclusion contract, see llmjudge package doc)", llmjudge.MetaLabelJudge, llmjudge.JudgeLabelValue)
	}
	if c.pool == nil {
		return llmjudge.ChatResponse{}, errors.New("judge upstream client: pool is not wired")
	}
	start := c.now()

	// Steps 1–4 — loop bound, agent budget, workload cap, model resolution
	// and §5 admission — run in admitJudgeHop, which preserves this
	// sequence verbatim.
	target, rsv, err := c.admitJudgeHop(ctx, req)
	if err != nil {
		return llmjudge.ChatResponse{}, err
	}

	// 4b. Preview2 durable accounting: mint the hop's invocation identity
	// here so settlement can close it, but commit the confirmed start only
	// inside call — immediately before the actual upstream Do, after every
	// fallible local step (key lookup, client setup, translation, method
	// and header prep). A purely local failure must never strand a paid
	// durable admission for a hop that never dispatched: those paths
	// release the reservation at zero spend below and settle nothing.
	holder := newInvocationIdentity(req.Meta.Org, logctx.RequestID(ctx), "", req.Meta.Key, agentHopSessionKey(ctx), req.ModelRef)
	ctx = withInvocationIdentity(ctx, holder)

	// 5. The wire round trip with usage capture. dispatched tells whether
	// the confirmed start committed (the hop is durably admitted from that
	// point on, whatever the wire does next).
	dispatched, respBody, usage, statusCode, callErr := c.call(ctx, req, target, holder)
	if !dispatched {
		// Never-dispatched local failure: release the reserved escrow at
		// zero spend and publish nothing — no terminal billed for a hop
		// the provider never saw.
		return llmjudge.ChatResponse{}, c.releaseUndispatched(rsv, callErr)
	}

	// 6. Settlement: exactly one request.completed per hop, on success AND
	// failure, with the reservation tuples + Finalize actuals attached. A
	// terminal-facts commit failure withholds the event (the funnel's
	// contract); the provider error, when present, keeps precedence.
	serr := c.settle(ctx, req, target, start, usage, statusCode, callErr, rsv)

	if callErr != nil {
		return llmjudge.ChatResponse{}, callErr
	}
	if serr != nil {
		return llmjudge.ChatResponse{}, serr
	}
	content, err := judgeHopContent(respBody)
	if err != nil {
		return llmjudge.ChatResponse{}, err
	}
	return llmjudge.ChatResponse{Content: content, Model: target.Model}, nil
}

// admitJudgeHop runs the hop's pre-dispatch admission sequence (JudgeChat
// steps 1–4), in order: loop bound, agent budget (G2), workload cap,
// model resolution and §5 Plan/Reserve. Every check is fail-closed — over
// any cap or on any denial the hop does not run and the policy's on_error
// mode governs the outcome. It returns the resolved target and the §5
// reservation (nil when the deploy admits without reservations — the same
// shape the interactive reservationPlan uses); an error is terminal for
// the hop.
func (c *budgetedJudgeClient) admitJudgeHop(ctx context.Context, req llmjudge.ChatRequest) (llmjudge.Target, *budget.Reservation, error) {
	// 1. Loop bound: one external request cannot spin internal model hops
	// unboundedly.
	if err := c.loop.Admit(agentHopEpisode(ctx)); err != nil {
		return llmjudge.Target{}, nil, fmt.Errorf("judge loop budget: %w", err)
	}

	// 2. Agent budget (G2): the same fail-closed check admissionCore runs
	// for interactive traffic, over the parent request's agent identity.
	if p, ok := principalFrom(ctx); ok && c.agentEnforcer != nil && p.AgentID != "" {
		if err := c.agentEnforcer.CheckAgentBudget(ctx, p.AgentID); err != nil {
			return llmjudge.Target{}, nil, fmt.Errorf("judge agent budget: %w", err)
		}
	}

	// 2b. Workload cap (N06-P07-T04): the hop rides the parent request's
	// workload identity (the label admissionCore stamped on the context)
	// under the same opt-in per-replica cap, namespaced by the parent's org
	// (req.Meta.Org — the same identity channel hopBudgetRequest uses) so
	// that identical workload names across orgs never share a window.
	if err := sharedWorkloadLedger().Admit(req.Meta.Org, hopWorkloadScope(ctx), 0); err != nil {
		return llmjudge.Target{}, nil, fmt.Errorf("judge workload budget: %w", err)
	}

	// 3. Model resolution: "$(indirection)" refs resolve through the
	// gateway's registry path; bare refs are served literally.
	target, err := c.resolveTarget(ctx, req.ModelRef)
	if err != nil {
		return llmjudge.Target{}, nil, err
	}

	// 4. §5 admission: estimate + reserve the hop against the SAME scopes
	// the parent request was admitted under. An enforce-mode denial is
	// terminal for the hop; shadow records would-deny and proceeds.
	rsv, _, err := c.admitHop(ctx, req, target) // admitted=false always carries err != nil
	if err != nil {
		return llmjudge.Target{}, nil, err
	}
	return target, rsv, nil
}

// releaseUndispatched closes a hop whose confirmed start never committed:
// it releases the reserved escrow at zero spend (no Finalize tuples are
// published — nothing was billed) and surfaces the local failure, or a
// sentinel when the transport reported success without dispatching.
func (c *budgetedJudgeClient) releaseUndispatched(rsv *budget.Reservation, callErr error) error {
	if rsv != nil {
		walletActual, budgetActual := reservationActuals(0, 0)
		c.admission.Finalize(rsv, walletActual, budgetActual)
	}
	if callErr != nil {
		return callErr
	}
	return errors.New("judge hop never dispatched")
}

// agentHopEpisode keys the loop budget by the parent request's request id;
// an unattributable context has no loop accounting (empty key allows).
func agentHopEpisode(ctx context.Context) string {
	return logctx.RequestID(ctx)
}

// resolveTarget mirrors the packaged client's resolution: a wired
// ModelResolver (the gateway registry path, indirections included) or the
// literal model name.
func (c *budgetedJudgeClient) resolveTarget(ctx context.Context, ref string) (llmjudge.Target, error) {
	if c.models == nil {
		return llmjudge.Target{Model: ref}, nil
	}
	target, err := c.models.ResolveJudgeModel(ctx, ref)
	if err != nil {
		return llmjudge.Target{}, fmt.Errorf("judge model resolve: %w", err)
	}
	return target, nil
}

// admitHop runs the §5 sections for one internal hop: Plan (estimate the
// per-scope bounds from the judge payload + max tokens) then Reserve (the
// hop is never cached, so there is no cache branch). Shadow would-deny
// refusals land on the same metrics reservationPlan uses; enforce
// refusals fail the hop. It reports
// (reservation, admitted, err): admitted=false with err!=nil is a terminal
// denial; admitted=true with a nil reservation is the unreserved proceed
// (off mode / no controller / shadow refusal) — the same shape the
// interactive reservationPlan uses.
func (c *budgetedJudgeClient) admitHop(ctx context.Context, req llmjudge.ChatRequest, target llmjudge.Target) (*budget.Reservation, bool, error) {
	if c.admission == nil {
		return nil, true, nil
	}
	breq := c.hopBudgetRequest(ctx, req, target)
	plan, err := c.admission.Plan(ctx, breq)
	if plan != nil {
		for _, d := range plan.WouldDeny {
			metrics.ReservationsWouldDenyTotal.WithLabelValues(reservationScopeLabel(d.Scope)).Inc()
		}
		plan.WouldDeny = nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("judge hop budget admission: %w", err)
	}
	if plan == nil || plan.Mode == budget.ModeOff {
		return nil, true, nil
	}
	rsv, rerr := c.admission.Reserve(ctx, plan)
	if rsv == nil {
		for _, d := range plan.WouldDeny { // reserve-time shadow refusals
			metrics.ReservationsWouldDenyTotal.WithLabelValues(reservationScopeLabel(d.Scope)).Inc()
		}
		plan.WouldDeny = nil
	}
	if rerr != nil && !errors.Is(rerr, budget.ErrNotReserved) {
		return nil, false, fmt.Errorf("judge hop budget reserve: %w", rerr)
	}
	return rsv, true, nil
}

// hopBudgetRequest assembles the §4.3 estimation input for one hop: the
// parent's identity (org and team from the policy meta, agent/session from
// the request-scoped principal), the resolved judge hop as the single
// planned chain hop, and the payload profile. Judge prompts carry no
// images; the input bytes are the rendered message contents (the estimator
// applies its own margin and cap semantics).
func (c *budgetedJudgeClient) hopBudgetRequest(ctx context.Context, req llmjudge.ChatRequest, target llmjudge.Target) budget.Request {
	breq := budget.Request{
		OrgID:  req.Meta.Org,
		TeamID: hopTeamScope(req.Meta),
		Chain:  []budget.ChainHop{{Provider: target.Provider, Model: target.Model}},
	}
	var input int64
	for _, m := range req.Messages {
		input += int64(len(m.Content))
	}
	breq.InputBytes = input
	if req.MaxTokens > 0 {
		max := int64(req.MaxTokens)
		breq.MaxTokens = &max
	}
	if p, ok := principalFrom(ctx); ok {
		breq.AgentID = p.AgentID
		breq.SessionKeyID = reservationSessionKey(ctx, p.SessionKeyID)
	}
	return breq
}

// hopTeamScope reads the team identity the request path stamped on the
// parent meta labels (policyMetaWithTeam, gateway_policy.go). The judge hop
// context carries the request principal but never the team identity, so
// this label — carried onto the hop meta by llmjudge's judgeMeta — is the
// channel through which team-scoped judge hops attribute and budget.
// A team-scoped hop requests the §4.3 ScopeTeamMonth bound and settles with
// the canonical event team_id, exactly like interactive traffic with the
// same team key. (judgeMeta currently rebuilds the hop meta without the
// parent labels; this reader activates once it copies them — T03 record
// addendum.)
func hopTeamScope(meta *pipeline.RequestMeta) string {
	if meta == nil {
		return ""
	}
	return meta.Labels[metaLabelTeamScope]
}

// judgeHopBody is the openai chat.completions payload sent to the judge
// model (same shape as the packaged llmjudge client's chatBody).
type judgeHopBody struct {
	Model          string                  `json:"model"`
	Messages       []pipeline.Message      `json:"messages"`
	Temperature    float64                 `json:"temperature"`
	MaxTokens      int                     `json:"max_tokens,omitempty"`
	ResponseFormat *judgeHopResponseFormat `json:"response_format,omitempty"`
}

type judgeHopResponseFormat struct {
	Type string `json:"type"`
}

// buildJudgeHopBody maps the ChatRequest onto the wire payload (same
// mapping as the packaged llmjudge buildChatBody).
func buildJudgeHopBody(req llmjudge.ChatRequest, model string) judgeHopBody {
	b := judgeHopBody{
		Model:       model,
		Messages:    req.Messages,
		Temperature: req.Temperature,
		MaxTokens:   req.MaxTokens,
	}
	if req.ResponseJSON {
		b.ResponseFormat = &judgeHopResponseFormat{Type: "json_object"}
	}
	return b
}

// prepareJudgeHop runs every fallible local step of the wire round trip
// (key lookup, client setup, request encoding, translation) BEFORE any
// paid dispatch: a failure here means the hop never reached the provider,
// so the caller releases the reservation at zero spend and settles
// nothing. It mirrors the packaged judge client's setup sequence.
func (c *budgetedJudgeClient) prepareJudgeHop(ctx context.Context, req llmjudge.ChatRequest, target llmjudge.Target) (*upstream.Client, provider.Provider, []byte, string, error) {
	key := ""
	if c.keys != nil {
		var err error
		key, err = c.keys.ResolveJudgeKey(ctx, req.Meta.Org, target)
		if err != nil {
			return nil, nil, nil, "", fmt.Errorf("judge key resolve: %w", err)
		}
	}

	cl, err := c.pool.Get(target.UpstreamURL, target.Provider)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("judge upstream client: %w", err)
	}
	prov := cl.Adapter()

	body, err := json.Marshal(buildJudgeHopBody(req, target.Model))
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("judge request encode: %w", err)
	}
	native, err := prov.TranslateRequest(body)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("judge request translate: %w", err)
	}
	return cl, prov, native, key, nil
}

// call performs one translated chat.completions round trip against the
// pooled upstream client for target, mirroring the packaged judge client
// and returning the raw response body plus its EXACT parsed usage (the
// provider adapter's own extractor — the settlement contract never estimates
// from sizes).
//
// dispatched is false for every failure BEFORE the confirmed durable start
// (local key lookup, client setup, translation, header prep — and the start
// commit itself): those hops never reached the provider, so the caller
// releases the reservation and settles nothing. Once the start commits,
// dispatched stays true through any later wire failure — the hop is
// durably admitted and settles exactly once. There is no redispatch: the
// confirmed start commits immediately before the single upstream Do.
func (c *budgetedJudgeClient) call(ctx context.Context, req llmjudge.ChatRequest, target llmjudge.Target, holder *invocationIdentity) (dispatched bool, respBody []byte, usage provider.Usage, statusCode int, callErr error) {
	cl, prov, native, key, err := c.prepareJudgeHop(ctx, req, target)
	if err != nil {
		return false, nil, provider.Usage{}, 0, err
	}

	extra := http.Header{}
	extra.Set(llmjudge.JudgeHeader, llmjudge.JudgeLabelValue)

	timeout := target.Timeout
	if timeout <= 0 {
		timeout = llmjudge.DefaultJudgeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Preview2 durable accounting: the confirmed start commits immediately
	// BEFORE the actual paid dispatch — every fallible local step (key
	// lookup, client setup, translation, method/header prep) has run in
	// prepareJudgeHop, so a local failure never strands a durable
	// admission for a hop that never dispatched. Fail closed: an
	// unwritten start (write error, timeout or lost ACK — outcome
	// unknown) fails the hop with ZERO provider arrivals; the caller
	// releases the reserved escrow at zero spend and the hop identity
	// never dispatches later under this id.
	if err := holder.beginPaidDispatch(ctx, c.invocations, invocationKindJudge); err != nil {
		return false, nil, provider.Usage{}, 0, fmt.Errorf("judge hop durable start: %w", err)
	}
	dispatched = true

	resp, err := cl.Do(ctx, prov.Path(false), native, key, false, extra)
	if err != nil {
		return dispatched, nil, provider.Usage{}, 0, fmt.Errorf("judge upstream call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, agentHopMaxErrorBody))
		upErr := upstream.Error{Status: resp.StatusCode, Body: string(errBody)}
		return dispatched, nil, provider.Usage{}, resp.StatusCode, fmt.Errorf("judge upstream status %d: %s", resp.StatusCode, upErr.Error())
	}

	respBody, err = io.ReadAll(io.LimitReader(resp.Body, agentHopMaxRespBody))
	if err != nil {
		return dispatched, nil, provider.Usage{}, resp.StatusCode, fmt.Errorf("judge upstream read: %w", err)
	}
	// Translate (and discard) here exactly like the packaged client, so a
	// provider the gateway cannot translate fails the hop before the
	// verdict parser ever sees it.
	if _, err := prov.TranslateResponse(respBody); err != nil {
		return dispatched, nil, provider.Usage{}, resp.StatusCode, fmt.Errorf("judge upstream translate response: %w", err)
	}
	return dispatched, respBody, prov.ParseUsage(respBody), resp.StatusCode, nil
}

// judgeHopContent extracts choices[0].message.content from an
// openai-shaped completion (same extraction as the packaged client's
// choiceContent).
func judgeHopContent(body []byte) (string, error) {
	var resp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("judge upstream response parse: %w", err)
	}
	if len(resp.Choices) == 0 {
		return "", errors.New("judge upstream response has no choices")
	}
	return resp.Choices[0].Message.Content, nil
}

// settle publishes exactly one request.completed event for the hop and
// finalizes its reservation. The event carries the EXACT upstream usage and
// the computed cost, so the consumer charges the hop like any other usage;
// a failed hop settles zero spend with the error on the event. Resale is
// not computed on this pipeline — the wallet actual falls back to the base
// quote (the consumer's own rule, as on the completions pipeline). It
// returns the terminal-facts commit error: the event is withheld from the
// consumer then (a published completion whose facts row is absent parks in
// the consumer; the reconciler's grace sweep owns the admitted row).
func (c *budgetedJudgeClient) settle(ctx context.Context, req llmjudge.ChatRequest, target llmjudge.Target, start time.Time, usage provider.Usage, statusCode int, callErr error, rsv *budget.Reservation) error {
	providerName := target.Provider
	if providerName == "" {
		providerName = "openai"
	}
	ext := provider.ComputeCost(usage, providerName, target.Model)

	ev := c.hopSettleEvent(ctx, req, target, start, usage, statusCode, callErr, ext)

	// §5.3 Finalize: record the hop's actual spend in the local escrow and
	// stamp the reserve tuples on the event before publish.
	if rsv != nil {
		walletActual, budgetActual := reservationActuals(0, ext.EstimatedCostUSD)
		c.admission.Finalize(rsv, walletActual, budgetActual)
		ev.Reservations = rsv.TuplesJSON()
	}

	chargeHopWorkload(ctx, req.Meta.Org, ext.EstimatedCostUSD)
	ev.Termination = hopTermination(ctx, callErr)

	c.log.Debug("judge hop settled",
		slog.String("endpoint", agentHopEndpoint),
		slog.String("model", target.Model),
		slog.Int64("tokens_in", usage.PromptTokens),
		slog.Int64("tokens_out", usage.CompletionTokens),
	)

	// Preview2 durable accounting: stamp the hop's identity and commit the
	// terminal facts BEFORE the publish — the finishRequest funnel order.
	// A commit failure withholds the event entirely (never a published
	// completion without its facts row); the escrow above already settled,
	// and the reconciler's grace sweep owns the admitted row.
	if h := invocationIdentityFrom(ctx); h != nil {
		ev.InvocationID = h.ID()
		if h.Admitted() {
			if err := c.commitHopTerminal(ctx, h, ev); err != nil {
				return err
			}
		}
	}
	publishEventWithContext(ctx, c.publisher, c.log, ev)
	return nil
}

// hopSettleEvent assembles the hop's request.completed event: the shared
// analytics shape carrying the EXACT upstream usage, the computed cost
// (ext — computed once by the caller) and the source flags, with a failed
// hop's error stamped on the event.
func (c *budgetedJudgeClient) hopSettleEvent(ctx context.Context, req llmjudge.ChatRequest, target llmjudge.Target, start time.Time, usage provider.Usage, statusCode int, callErr error, ext provider.ExtendedUsage) *eventpub.Event {
	ev := eventBase{
		EventType:        "request.completed",
		RequestID:        logctx.RequestID(ctx),
		OrgID:            req.Meta.Org,
		APIKeyID:         req.Meta.Key,
		TeamID:           hopTeamScope(req.Meta),
		AgentID:          agentHopAgent(ctx),
		SessionKeyID:     agentHopSessionKey(ctx),
		ModelRequested:   req.ModelRef,
		ModelUsed:        target.Model,
		UpstreamURL:      target.UpstreamURL,
		StatusCode:       int64(statusCode),
		DurationMs:       c.now().Sub(start).Milliseconds(),
		Method:           agentHopMethod,
		Endpoint:         agentHopEndpoint,
		TokensIn:         usage.PromptTokens,
		TokensOut:        usage.CompletionTokens,
		CacheReadTokens:  usage.CacheReadTokens,
		EstimatedCostUSD: ext.EstimatedCostUSD,
		UsageSource:      usageSourceOrNone(usage.Source),
		CostStatus:       costStatus(false, usage.Source, ext.PriceKnown),
		Labels:           labelsFrom(ctx),
	}.build()
	if callErr != nil {
		ev.Error = callErr.Error()
	}
	return ev
}

// chargeHopWorkload applies the workload chargeback (N06-P07-T04): the
// hop's settled actual counts against its workload's windowed cap,
// namespaced by the parent's org (org) exactly like the Admit check in
// admitJudgeHop. Same quote rule as the consumer: positive or
// exactly-zero quotes charge; unknown quotes contribute nothing. The
// settle event already carries the workload label, so the durable
// attribution does not depend on this in-memory ledger.
func chargeHopWorkload(ctx context.Context, org string, costUSD float64) {
	workload := hopWorkloadScope(ctx)
	if workload == "" {
		return
	}
	if quote, state := money.QuoteFromUSD(costUSD, true); state == money.QuotePositive || state == money.QuoteZero {
		sharedWorkloadLedger().Charge(org, workload, quote)
	}
}

// hopTermination resolves the hop's settle termination: an upstream error
// wins (even when usage is known — the hop's terminal class is the wire
// failure); otherwise the parent request's completion termination applies.
// completionTermination's range is confined to the valid Finalize set, so
// no defensive fallthrough is needed.
func hopTermination(ctx context.Context, callErr error) string {
	if callErr != nil {
		return string(budget.TerminationUpstreamErr)
	}
	return string(completionTermination(ctx))
}

// commitHopTerminal is the judge-hop seam of the finishRequest funnel
// (gw.stampAndCommitInvocationTerminal), local to this client because the
// hop does not ride finishRequest: stamps one TS so the facts row and the
// published event agree, then commits the content-free terminal facts with
// a BOUNDED INDEPENDENT context (client cancellation must not kill the
// accounting write) and the shared transient-class retry ladder. Returns
// the commit error so settle can withhold the event from the consumer.
func (c *budgetedJudgeClient) commitHopTerminal(ctx context.Context, h *invocationIdentity, ev *eventpub.Event) error {
	if err := nilInvocationStore(c.invocations); err != nil {
		return fmt.Errorf("%w: admitted invocation %s: %w", ErrInvocationStoreUnavailable, h.ID(), err)
	}
	if ev.TS == 0 {
		ev.TS = time.Now().UnixMilli()
	}
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), terminalFactsTimeout)
	defer cancel()
	// Same retry posture as the funnel: the write is idempotent under
	// exact equality, so ambiguous outcomes (serialization, transport)
	// recommit the same invocation in the same bounded window;
	// deterministic failures fail closed for the reconciler to own.
	var err error
	for attempt := 0; attempt < terminalFactsAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(terminalFactsRetryBackoff << uint(attempt-1)):
			case <-fctx.Done():
			}
		}
		err = h.commitInvocationTerminal(fctx, c.invocations, ev)
		if err == nil {
			return nil
		}
		if !shouldRetryTerminalCommit(err) {
			break
		}
	}
	c.log.Error("terminal facts commit failed after judge hop; withholding event from consumer",
		"invocation_id", h.ID(), "error", err)
	return err
}

// agentHopAgent resolves the parent request's agent identity (G2 scope).
func agentHopAgent(ctx context.Context) string {
	if p, ok := principalFrom(ctx); ok {
		return p.AgentID
	}
	return ""
}

// agentHopSessionKey resolves the parent request's session scope key under
// the same D14 rule reservationSessionKey enforces (only capped keys).
func agentHopSessionKey(ctx context.Context) string {
	if p, ok := principalFrom(ctx); ok {
		return reservationSessionKey(ctx, p.SessionKeyID)
	}
	return ""
}

// hopWorkloadScope resolves the parent request's workload identity for the
// hop's cap check and chargeback charge: the key admissionCore merged into
// the request's label context (metaLabelWorkload — explicit
// X-Yabanin-Workload or the agent/team/task derivation). The window is
// namespaced by the parent's org, which the callers take from req.Meta.Org.
// The settle event carries the same label via labelsFrom, so the hop's
// spend attributes to the parent's workload exactly like interactive
// traffic. An empty key is unattributable and skips the cap check.
func hopWorkloadScope(ctx context.Context) string {
	return labelsFrom(ctx)[metaLabelWorkload]
}
