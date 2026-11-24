package cli

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/classifier"

	"github.com/reireirei/yabanin/pkg/clientip"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/openai"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/router"
	evaluator "github.com/reireirei/yabanin/pkg/rulesengine"
	"github.com/reireirei/yabanin/pkg/upstream"
	validator "github.com/reireirei/yabanin/pkg/validation/openai"
	"github.com/reireirei/yabanin/pkg/verticals"
)

// responseCache is the cache surface the request path uses. *cache.CacheService
// satisfies it in production; tests substitute a stub so a warm entry can be
// exercised without Redis. RT-02: any cache hit may only be served after the
// final-candidate gate passed. RT-05: lookups and writes carry the full
// cache.RouteIdentity (org, current route model, namespace version,
// generation parameters) — the entry's provenance must match it to serve.
type responseCache interface {
	LookupWithResult(ctx context.Context, ri cache.RouteIdentity, promptJSON []byte) (*cache.CacheHit, error)
	Write(ctx context.Context, ri cache.RouteIdentity, promptJSON, response json.RawMessage, tokensIn, tokensOut int) error
}

// chatContext carries one request through the pipeline stages (AF-17). The
// stages run strictly in the documented order — normalize/transform →
// candidate → policy → cache/execute → account/event — and every field below
// is written by exactly one stage and only read by later ones, so the order
// of the old monolithic handler is preserved verbatim.
type chatContext struct {
	w     http.ResponseWriter
	r     *http.Request
	l     *slog.Logger
	reqID string

	// normalize/transform: the raw body (guarded, then vertical-patched in
	// place) and the typed projection rebuilt from the GUARDED payload (RT-04:
	// every downstream consumer must agree with what is actually forwarded).
	body []byte
	req  openai.ChatCompletionRequest

	// Identity, read from the verified headers once.
	orgID, teamID, apiKeyID            string
	sessionID, taskID, agentID, userID string

	// invocation is the Preview2 durable-accounting holder minted at the
	// shared admission core; stashed on the request context below.
	invocation *invocationIdentity

	// Candidate state: what the client asked for and what will be called.
	requestedModel  string
	unknownFallback bool
	model           string
	info            resolver.ModelInfo

	// Routing decision accumulator (v18 R1) and tier/classifier observables.
	dec                  routingDecision
	classifierClass      string
	classifierConfidence float64
	classifierSource     string
	tierUsed             string
	// selected model is pinned here — a later activation/rollback changes
	// only NEW requests; an already-routed request (stream included) keeps
	// its arm and model to completion.
	canary router.CanaryDecision

	// P4: a client no-store skips the cache entirely (lookup AND write).
	cacheDisabled bool

	// OP-8: the decision-record JSON of this request's policy runs (pre +
	// post merged; "" when the pipeline is off or nothing matched). Stamped
	// on the analytics events (Event.Policy, the OP-9 contract).
	policyEvent string

	// RATELIMIT-FALLBACK F1: release handle for the admitted fair-admission
	// slot (nil when the feature is off). chatCompletions releases it
	// synchronously on return — the AfterFunc anchor in admissionCore fires
	// in its own goroutine, which cannot order the release before the batch
	// executor's next in-process line.
	fairTicket *router.FairTicket
}

// chatCompletions is the POST /v1/chat/completions orchestrator. It only
// sequences the pipeline stages; each stage owns its behavior:
//
//	normalizeChatRequest  read/guard/validate the payload and identity
//	routeChatCandidate    resolve + tier/classifier/rule/time routing
//	enforceChatPolicy     residency + RT-02 final-candidate gate + header
//	serveChatCache        RT-05 route-identity cache branch (may answer)
//	executeChatJSON       breaker + per-model retry + fallback chain
//	finalizeChatJSON      usage/accounting, events, cache write, response
func (gw *gateway) chatCompletions(w http.ResponseWriter, r *http.Request) {
	// Keep the entry context; admission updates *r with request-scoped labels.
	ctx := r.Context()
	cc, ok := gw.normalizeChatRequest(w, r)
	if !ok {
		return
	}
	// RATELIMIT-FALLBACK F1: synchronous fair-admission release at request
	// end (nil-safe when the feature is off; exactly-once with the AfterFunc
	// backstop in admissionCore). The async AfterFunc alone cannot order the
	// release before the batch executor's next in-process line, which made
	// every N>Capacity line shed on the batch path.
	defer cc.fairTicket.Release()
	ctx, gate, ok := gw.prepareChatDispatch(ctx, w, r, cc)
	if !ok {
		return
	}
	if gw.serveChatCache(ctx, cc) {
		return
	}
	if !gw.confirmChatDispatch(ctx, cc, gate) {
		return
	}
	gw.dispatchChatCompletion(ctx, cc)
}

func (gw *gateway) prepareChatDispatch(ctx context.Context, w http.ResponseWriter, r *http.Request, cc *chatContext) (context.Context, *reservationGate, bool) {
	if !gw.routeChatCandidate(ctx, cc) || !gw.enforceChatPolicy(ctx, cc) || !gw.policyPreChat(ctx, cc) {
		return nil, nil, false
	}
	ctx = withInvocationIdentity(ctx, cc.invocation)
	ctx = withRequestPolicyEntryOutcome(ctx, cc.r, gw.policyRuntime, cc.orgID)
	ctx = withRequestRouteHint(ctx, cc.r)
	gw.setJudgeVersionHeader(ctx, w, cc.orgID)
	// Plan before cache lookup so cache hits cannot bypass exhausted budgets.
	gate, ok := gw.reservationPlan(w, r, "chat.completions",
		gw.reservationRequest(ctx, cc.orgID, cc.teamID, cc.agentID, headerSessionKeyID(r), cc.info, cc.body, reservationMaxTokens(cc.req.MaxTokens), false))
	if !ok {
		return nil, nil, false
	}
	return withReservationGate(ctx, gate), gate, true
}

func (gw *gateway) confirmChatDispatch(ctx context.Context, cc *chatContext, gate *reservationGate) bool {
	if !gate.reserve(ctx) {
		return false
	}
	// Confirm the start after reservation and before the first paid provider call.
	if err := gw.confirmPaidInvocation(ctx, invocationKindForChat(cc.req.Stream)); err != nil {
		// A failed or unknown start must release the local reservation before refusal.
		gate.finalizeNoEvent(budget.TerminationPolicyDenied)
		cc.l.Warn("refusing paid dispatch: durable start unwritten", "error", err)
		writeInvocationStartRefusal(cc.w, err)
		return false
	}
	return true
}

func (gw *gateway) dispatchChatCompletion(ctx context.Context, cc *chatContext) {
	if cc.req.Stream {
		// Cache hits (including for streaming clients) were served in the
		// RT-05 cache branch above; here the request always goes upstream.
		gw.serveStream(cc.w, ctx, cc.info, cc.body, isRawBody(cc.r), cc.sessionID, cc.orgID, cc.teamID, cc.taskID, cc.reqID, cc.l, cc.dec, cc.classifierClass, cc.classifierConfidence, cc.tierUsed, cc.classifierSource, agentSubject(cc.r), cc.cacheDisabled)
		return
	}
	ex, ok := gw.executeChatJSON(ctx, cc)
	if !ok {
		return
	}
	gw.finalizeChatJSON(ctx, cc, ex)
}

// headerSessionKeyID reads the trusted session key id (the auth middleware
// strips client copies of the identity headers).
func headerSessionKeyID(r *http.Request) string {
	return r.Header.Get("X-Session-Key-Id")
}

// policyPreChat is the OP-8 pre-upstream hook for the chat JSON path: run the
// pre_upstream policies, adopt a masked body as the payload every downstream
// consumer sees (RT-04), and stamp the decision record for the events. A
// false result means the request was answered terminally (the hook wrote the
// 400 content_policy_violation envelope).
func (gw *gateway) policyPreChat(_ context.Context, cc *chatContext) bool {
	body, policyEvent, ok := gw.policyPreUpstream(cc.w, cc.r, "chat", cc.model, cc.info.Provider, cc.body)
	if !ok {
		return false
	}
	cc.body = body
	cc.policyEvent = policyEvent
	return true
}

// normalizeChatRequest admits the guarded body, validates its typed projection,
// and applies the chat-specific vertical transform before routing.
func (gw *gateway) normalizeChatRequest(w http.ResponseWriter, r *http.Request) (*chatContext, bool) {
	l := logctx.From(r.Context(), gw.log)
	reqID := logctx.RequestID(r.Context())
	raw, req, ok := readChatRequest(w, r)
	if !ok {
		return nil, false
	}
	core, ok := gw.admitChatProjection(w, r, l, raw, &req)
	if !ok {
		return nil, false
	}

	cc := &chatContext{
		w:               w,
		r:               r,
		l:               l,
		reqID:           reqID,
		body:            core.Body,
		req:             req,
		unknownFallback: core.Fallback,
		model:           core.Info.ModelName,
		info:            core.Info,
		// requestedModel is what the client asked for (canonical, but BEFORE
		// tier routing / rule overrides rewrite `model`). Analytics events
		// must carry it: ModelRequested showed the post-routing model, so the
		// explorer and the savings breakdown silently attributed routed
		// spend to the wrong requested model.
		requestedModel: core.Info.ModelName,
		sessionID:      core.SessionID,
		orgID:          core.OrgID,
		apiKeyID:       core.APIKeyID,
		teamID:         core.TeamID,
		taskID:         core.TaskID,
		agentID:        core.AgentID,
		userID:         core.UserID,
		fairTicket:     core.FairTicket,
		invocation:     core.Invocation,
	}

	l.Debug("chat request", "model", cc.model, "session", cc.sessionID, "org", cc.orgID, "msgs", len(req.Messages))

	if !gw.validateChatProjection(r.Context(), l, reqID, cc) {
		return nil, false
	}
	if !gw.transformChatProjection(r.Context(), w, cc) {
		return nil, false
	}
	return cc, true
}

func readChatRequest(w http.ResponseWriter, r *http.Request) ([]byte, openai.ChatCompletionRequest, bool) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"request body too large or malformed")
		return nil, openai.ChatCompletionRequest{}, false
	}
	var req openai.ChatCompletionRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"malformed JSON: "+err.Error())
		return nil, openai.ChatCompletionRequest{}, false
	}
	return raw, req, true
}

func (gw *gateway) admitChatProjection(w http.ResponseWriter, r *http.Request, l *slog.Logger, raw []byte, req *openai.ChatCompletionRequest) (admissionCore, bool) {
	// Rebuild the typed view from guarded bytes before downstream consumers run.
	return gw.admissionCore(w, r, l, admissionCoreInput{
		Model: req.Model,
		Body:  raw,
		Rebuild: func(body []byte) error {
			return json.Unmarshal(body, req)
		},
		BudgetEventUser: true,
	})
}

func (gw *gateway) validateChatProjection(ctx context.Context, l *slog.Logger, reqID string, cc *chatContext) bool {
	apiErr, statusCode := validator.ValidateRequest(cc.req)
	if apiErr == nil {
		return true
	}
	validator.WriteError(cc.w, apiErr, statusCode)
	publishEventWithContext(ctx, gw.publisher, l, eventBase{
		EventType:      "request.invalid",
		RequestID:      reqID,
		SessionID:      cc.sessionID,
		Payload:        string(cc.body),
		OrgID:          cc.orgID,
		TeamID:         cc.teamID,
		ModelRequested: cc.requestedModel,
		Error:          apiErr.Error.Message,
		Labels:         labelsFrom(ctx),
	}.build())
	return false
}

func (gw *gateway) transformChatProjection(ctx context.Context, w http.ResponseWriter, cc *chatContext) bool {
	if gw.verticalReg == nil || cc.orgID == "" {
		return true
	}
	request := verticals.Request{
		OrgID:          cc.orgID,
		ModelRequested: cc.requestedModel,
		Prompt:         extractUserPrompt(cc.req.Messages),
		SystemPrompt:   extractSystemMessage(cc.req.Messages),
		Metadata:       make(map[string]string),
	}
	newCtx, transformed, err := gw.verticalReg.PreTransform(ctx, cc.orgID, request)
	if err != nil {
		cc.l.Warn("vertical transform denied request", "error", err, "org_id", cc.orgID)
		apierrors.Write(w, http.StatusForbidden, apierrors.ErrorCodePermissionDenied,
			fmt.Sprintf("compliance check failed: %s", err))
		return false
	}
	cc.r = cc.r.WithContext(newCtx)
	return applyChatVerticalResult(w, cc, transformed)
}

func applyChatVerticalResult(w http.ResponseWriter, cc *chatContext, transformed verticals.Request) bool {
	originalPrompt := extractUserPrompt(cc.req.Messages)
	if transformed.Prompt == originalPrompt {
		return true
	}
	// Patch only message content so guarded fields and unknown provider keys survive.
	patched, err := patchLastMessageContent(cc.body, transformed.Prompt)
	if err != nil {
		cc.l.Warn("vertical prompt patch failed", "error", err, "org_id", cc.orgID)
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"failed to apply vertical transform to request body")
		return false
	}
	if err := json.Unmarshal(patched, &cc.req); err != nil {
		cc.l.Warn("vertically patched body is not a valid chat completion request", "error", err, "org_id", cc.orgID)
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"malformed JSON: "+err.Error())
		return false
	}
	cc.body = patched
	for key, value := range transformed.Metadata {
		cc.r.Header.Set("X-Vertical-"+key, value)
	}
	return true
}

// routeChatCandidate (stage 2) resolves the candidate that will be called:
// prompt classification + tier routing (per-org routing modes, A/B control,
// session affinity), org rule overrides and the opt-in cheap-hours downgrade.
// Each branch re-resolves its model so the candidate carries its own
// upstream_url / upstream_api_key. A false result means a tier-selected or
// rule-overridden model could not be resolved and the request was answered
// terminally inside the stage.
func (gw *gateway) routeChatCandidate(ctx context.Context, cc *chatContext) bool {
	r, req, l := cc.r, cc.req, cc.l

	// P4/CACHE-01: skip the cache entirely if the client sent a Cache-Control
	// no-store directive — in any directive-list position, any letter case
	// and across several header lines (RFC 9111 §5.2). This one gate covers
	// lookup, stream recording and the post-upstream write symmetrically; a
	// single Header.Get byte comparison used to leak every non-verbatim
	// spelling into the shared cache.
	cc.cacheDisabled = clientNoStore(r)

	orgID, sessionID, model := cc.orgID, cc.sessionID, cc.model

	// W-BYOK-CORE: org custom models. A model the global registry does not
	// know (admission resolved a fallback substitution) may be the org's own
	// org_custom_models entry — the org sees global models plus its own.
	// Tier routing and rule overrides are skipped for a matched org model
	// (beta contract: org models are explicit-only and never enter tier
	// pools), while the downstream policy gate still applies.
	// NOTE: resolve by the CLIENT's raw model name (req.Model), not
	// cc.requestedModel — for an unknown model the resolver has already
	// substituted the fallback name into Info.ModelName, so requestedModel
	// can never name an org model.
	if cc.info.Fallback && orgID != "" && req.Model != "" {
		nfo, matched, nerr := gw.resolveOrgModelInfo(ctx, orgID, req.Model)
		if nerr != nil {
			l.Warn("org custom model resolution unavailable, denying request", "error", nerr, "requested", req.Model)
			writeResolutionUnavailable(cc.w)
			return false
		}
		if matched {
			l.Debug("org custom model matched", "org_id", orgID, "requested", req.Model, "model", nfo.ModelName)
			cc.info = nfo
			cc.model = nfo.ModelName
			cc.unknownFallback = false
			cc.dec = routingDecision{Source: "org_custom_model", From: req.Model, To: cc.model, Reason: "org_custom_model"}
			return true
		}
	}

	// v18 R1: routing decision accumulator (see decision.go). Populated
	// across the routing branches below (and carried by cache hits); written
	// as the X-Yabanin-Decision header before response bytes and (when
	// enabled) carried on the analytics event.

	// P5: Classify prompt complexity and route to appropriate model tier.
	// Populated by the routing pipeline below; the RT-05 cache branch (after
	// the gate) carries them on cache-hit events like every other path.

	if gw.classifier != nil && gw.tierRouter != nil && orgID != "" {
		// Per-org routing_mode check (P5.5): load mode + threshold, decide behavior.
		routingMode := "auto"
		routingThreshold := 0.6
		if gw.routingModeLoader != nil {
			rs := gw.routingModeLoader(ctx, orgID)
			// rs is *OrgRoutingSettings — check effective mode and threshold.
			routingMode = string(rs.RoutingMode)
			routingThreshold = rs.DefaultRoutingThreshold()
		}

		switch routingMode {
		case "always_premium":
			// Skip classifier — always route to premium model. No affinity
			// by design, but the canary split applies (it is session-hash
			// sticky, not warm-cache sticky).
			selected, canaryDec, selErr := gw.tierRouter.SelectModelForSession(ctx, classifier.ClassHard, orgID, "", sessionID)
			if selErr == nil && selected.Name != "" {
				l.Debug("routing_mode: always_premium", "org_id", orgID, "selected_model", selected.Name)
				nfo, nerr := gw.resolveModelInfo(ctx, selected.Name)
				if nerr != nil {
					l.Warn("tier-selected model resolution unavailable, denying request", "error", nerr, "selected", selected.Name)
					writeResolutionUnavailable(cc.w)
					return false
				}
				cc.tierUsed = selected.Name
				cc.model = selected.Name
				cc.info = nfo
			}
			metrics.TierRoutingTotal.WithLabelValues(string(classifier.ClassHard), cc.model, cc.tierUsed).Inc()
			metrics.TierRoutingSkippedTotal.WithLabelValues("always_premium").Inc()
			cc.dec = routingDecision{Source: decisionSourceTierRouter, Class: "hard", Threshold: routingThreshold, From: req.Model, To: cc.model, Reason: "always_premium"}
			cc.stampCanary(canaryDec)

		case "always_cheap":
			// Skip classifier — always route to cheapest model (canary split
			// applies, see always_premium).
			selected, canaryDec, selErr := gw.tierRouter.SelectModelForSession(ctx, classifier.ClassEasy, orgID, "", sessionID)
			if selErr == nil && selected.Name != "" {
				l.Debug("routing_mode: always_cheap", "org_id", orgID, "selected_model", selected.Name)
				nfo, nerr := gw.resolveModelInfo(ctx, selected.Name)
				if nerr != nil {
					l.Warn("tier-selected model resolution unavailable, denying request", "error", nerr, "selected", selected.Name)
					writeResolutionUnavailable(cc.w)
					return false
				}
				cc.tierUsed = selected.Name
				cc.model = selected.Name
				cc.info = nfo
			}
			metrics.TierRoutingTotal.WithLabelValues(string(classifier.ClassEasy), cc.model, cc.tierUsed).Inc()
			metrics.TierRoutingSkippedTotal.WithLabelValues("always_cheap").Inc()
			cc.dec = routingDecision{Source: decisionSourceTierRouter, Class: "easy", Threshold: routingThreshold, From: req.Model, To: cc.model, Reason: "always_cheap"}
			cc.stampCanary(canaryDec)

		default: // auto, aggressive_cost, classifier_only, disabled
			if routingMode == "disabled" {
				metrics.TierRoutingSkippedTotal.WithLabelValues("disabled").Inc()
				return gw.applyChatRuleOverrides(ctx, cc)
			}

			// P5.12: Check A/B assignment — if control group, skip classifier routing entirely.
			if gw.abAssigner != nil {
				variant := gw.abAssigner.GetVariant(orgID, "classifier-ab", 50) // 50% traffic for experiments
				if variant == "control" {
					metrics.TierRoutingSkippedTotal.WithLabelValues("ab_control").Inc()
					return gw.applyChatRuleOverrides(ctx, cc) // skip classifier, use original model
				}
			}

			start := time.Now()
			classResult := gw.classifier.Classify(ctx, classifier.Input{
				Prompt:         extractUserPrompt(req.Messages),
				Messages:       extractAllMessages(req.Messages),
				ContextTokens:  estimateContextTokens(req.Messages),
				ModelRequested: cc.requestedModel,
				OrgID:          orgID,
			})
			cc.classifierClass = string(classResult.Class)
			cc.classifierConfidence = classResult.Confidence
			cc.classifierSource = classResult.Source

			// Record classifier metrics.
			metrics.ClassifierClassTotal.WithLabelValues(cc.classifierClass, cc.classifierSource).Inc()
			metrics.ClassifierConfidence.Observe(cc.classifierConfidence)
			metrics.ClassifierLatencySeconds.WithLabelValues(cc.classifierSource).Observe(time.Since(start).Seconds())

			if classResult.Confidence >= routingThreshold {
				// KV-cache-aware routing (v15 K2): prefer this session's warm
				// model when it exists. always_premium/always_cheap above use
				// no preferred model on purpose — they must stay non-sticky.
				// sticky, applied inside SelectModelForSession).
				preferred := ""
				if gw.sessionAffinity != nil && orgID != "" && sessionID != "" {
					preferred = gw.sessionAffinity.Preferred(ctx, orgID, sessionID)
				}
				// (canary-aware) unless the org is in routing_mode=quality
				// with a wired, owner-approved snapshot (quality_routing.go);
				// residency/RT-02/reservation still run afterwards, unchanged.
				selected, qOutcome, canaryDec, selErr := gw.selectTierModel(ctx, classResult.Class, orgID, preferred, sessionID, routingMode)
				if selErr == nil && selected.Name != "" {
					l.Debug("tier routing", "class", classResult.Class, "original_model", model, "selected_model", selected.Name, "confidence", classResult.Confidence, "threshold", routingThreshold)
					// Re-resolve the tier-selected model so we pick up its
					// own upstream_url / upstream_api_key (same pattern as routing rules).
					nfo, nerr := gw.resolveModelInfo(ctx, selected.Name)
					if nerr != nil {
						l.Warn("tier-selected model resolution unavailable, denying request", "error", nerr, "selected", selected.Name)
						writeResolutionUnavailable(cc.w)
						return false
					}
					cc.tierUsed = selected.Name
					cc.model = selected.Name
					cc.info = nfo
				} else if selErr != nil {
					l.Warn("tier router selection failed, keeping original model", "error", selErr)
				}
				metrics.TierRoutingTotal.WithLabelValues(cc.classifierClass, req.Model, cc.tierUsed).Inc()
				aff := "miss"
				if preferred != "" && selected.Name == preferred {
					aff = "used"
				}
				cc.dec = routingDecision{
					Source:     decisionSourceTierRouter,
					Class:      cc.classifierClass,
					Confidence: cc.classifierConfidence,
					Threshold:  routingThreshold,
					Affinity:   aff,
					Preferred:  preferred,
					From:       req.Model,
					To:         cc.model,
				}
				applyQualityOutcome(&cc.dec, qOutcome)
				cc.stampCanary(canaryDec)
			} else {
				l.Debug("classifier confidence below threshold, skipping routing",
					"confidence", classResult.Confidence, "threshold", routingThreshold)
				metrics.TierRoutingSkippedTotal.WithLabelValues("low_confidence").Inc()
			}
		}
	}

	return gw.applyChatRuleOverrides(ctx, cc)
}

// applyChatRuleOverrides applies the org rule snapshot and the opt-in
// cheap-hours downgrade — the last routing steps before the policy gate.
func (gw *gateway) applyChatRuleOverrides(ctx context.Context, cc *chatContext) bool {
	r, l := cc.r, cc.l
	orgID, sessionID, model := cc.orgID, cc.sessionID, cc.model

	if gw.ruleStore != nil && orgID != "" {
		rules, err := gw.ruleStore.GetByOrg(ctx, orgID)
		if err != nil {
			// Explicit degradation: the request continues without org rule
			// overrides (fail-open is the deliberate policy), but the cause
			// must be visible in logs.
			l.Error("rule load failed, degrading without rule overrides", "org_id", orgID, "error", err)
		} else if len(rules) > 0 {
			// RT-01: rules are compiled into an immutable per-org snapshot.
			// A concurrent request from another org (or a rule replacement)
			// cannot mutate the snapshot this request evaluates against.
			// CORE-TRACE-04: EvaluateMatch also returns the matched rule's
			// identity, stamped onto the decision before serialization.
			target, match := gw.ruleSnapshot(orgID, rules).EvaluateMatch(evaluator.Context{
				OrgID:          orgID,
				ModelRequested: cc.requestedModel,
				SessionID:      sessionID,
				ClientIP:       clientip.Extract(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-Ip"), gw.trustedProxies),
				UserAgent:      r.UserAgent(),
			}, model)
			if target != "" {
				l.Debug("routing rule matched", "org_id", orgID, "original_model", model, "target_model", target)
				cc.dec = routingDecision{Source: decisionSourceRuleOverride, From: model, To: target}
				if match != nil {
					cc.dec.Rule = &DecisionRuleRef{Namespace: evaluator.NamespaceRouting, ID: match.RuleID, Version: match.Version}
				}
				// Re-resolve the rule-overridden model so we pick up its
				// own upstream_url / upstream_api_key.
				nfo, nerr := gw.resolveModelInfo(ctx, target)
				if nerr != nil {
					l.Warn("rule-overridden model resolution unavailable, denying request", "error", nerr, "target", target)
					writeResolutionUnavailable(cc.w)
					return false
				}
				cc.info = nfo
				cc.model = nfo.ModelName
			}
		}
	}

	// R2: opt-in cheap-hours / batch tier downgrade. Runs after routing + rule
	// override (so it is the final tier choice) and before residency. A hard
	// request is never moved; Medium → easy. Batch always downgrades; the
	// cheap window does so unless the client marked it high-priority.
	if gw.timeRoutingEnabled && gw.tierRouter != nil && orgID != "" {
		batch := r.Header.Get("X-Yabanin-Batch") == "true"
		highPriority := strings.EqualFold(r.Header.Get("X-Yabanin-Priority"), "high")
		inWindow := gw.timeCheapWindow.Contains(gw.now(), nil) // R2: injectable clock
		if router.ShouldDowngrade(inWindow, batch, highPriority) {
			fromClass := cc.classifierClass
			if fromClass == "" {
				fromClass = "medium"
			}
			targetClass := router.DowngradeClass(fromClass)
			if targetClass != fromClass {
				if sel, selErr := gw.tierRouter.SelectModel(ctx, classifier.Class(targetClass), orgID); selErr == nil && sel.Name != "" && sel.Name != cc.model {
					l.Debug("time-window downgrade", "from_class", fromClass, "to_class", targetClass, "from_model", cc.model, "to_model", sel.Name, "batch", batch, "in_window", inWindow)
					nfo, nerr := gw.resolveModelInfo(ctx, sel.Name)
					if nerr != nil {
						l.Warn("downgraded model resolution unavailable, denying request", "error", nerr, "selected", sel.Name)
						writeResolutionUnavailable(cc.w)
						return false
					}
					cc.tierUsed = sel.Name
					cc.model = sel.Name
					cc.info = nfo
					cc.dec = routingDecision{Source: decisionSourceTierRouter, Class: targetClass, From: cc.req.Model, To: cc.model, Reason: "time_window_downgrade", Downgrade: "time_window"}
				}
			}
		}
	}

	return true
}

// enforceChatPolicy (stage 3) runs the post-routing policy chain:
// residency enforcement (fail-closed, may remap the model) and the RT-02
// final-candidate gate (whitelist/ZAI re-check of the candidate that will
// actually be called — JSON and SSE share this point). Then the v18 R1
// decision header is emitted before any response bytes. A false result means
// the request was answered terminally inside the stage.
func (gw *gateway) enforceChatPolicy(ctx context.Context, cc *chatContext) bool {
	r, w, l := cc.r, cc.w, cc.l
	orgID, model, info := cc.orgID, cc.model, cc.info

	// PA.5: residency enforcement — region-pin per request (fail-closed).
	if gw.residencyEnforcer != nil && orgID != "" {
		resDec := gw.residencyEnforcer.Enforce(ctx, orgID, model, policy.Region(info.Region), info.Provider)
		if !resDec.Allowed {
			l.Warn("residency enforcement denied",
				"org_id", orgID, "region", resDec.Region,
				"pack", resDec.PackID, "reason", resDec.Reason,
				"violations", resDec.Violations)
			metrics.ResidencyEnforcementTotal.WithLabelValues(string(resDec.Region), "denied").Inc()
			apierrors.Write(w, http.StatusForbidden, "residency_policy_violation",
				"request violates organization residency policy: "+resDec.Reason)
			return false
		}
		if resDec.RemappedModel != "" {
			l.Debug("residency remap", "org_id", orgID, "from", model, "to", resDec.RemappedModel)
			nfo, nerr := gw.resolveModelInfo(ctx, resDec.RemappedModel)
			if nerr != nil {
				l.Warn("remapped model resolution unavailable, denying request", "error", nerr, "target", resDec.RemappedModel)
				writeResolutionUnavailable(w)
				return false
			}
			cc.info = nfo
			cc.model = nfo.ModelName
			metrics.ResidencyRemapTotal.WithLabelValues(string(resDec.Region)).Inc()
		}
		metrics.ResidencyEnforcementTotal.WithLabelValues(string(resDec.Region), "allowed").Inc()
		w.Header().Set("X-Residency-Region", string(resDec.Region))
		if resDec.PackID != "" && resDec.PackID != "none" {
			w.Header().Set("X-Residency-Pack", resDec.PackID)
		}
	}

	// RT-02: final-candidate policy gate. Classifier/tier routing, org rule
	// overrides, time-window downgrade, unknown-model fallback and residency
	// remap may each have replaced the model after the pre-routing whitelist;
	// the candidate that will actually be called is re-checked here. JSON and
	// SSE share this point, and the ZAI/data-boundary contract stays applied
	// (it moved inside the gate).
	if !gw.enforceFinalCandidateGate(w, r, candidateIdentity{OrgID: cc.orgID, TeamID: cc.teamID, APIKeyID: cc.apiKeyID}, cc.req.Model, cc.info) {
		return false
	}

	// v18 R1: assemble the final decision (passthrough when routing did not
	// move the model) and emit the machine-readable header before any
	// response bytes.
	if cc.dec.Source == "" {
		cc.dec = routingDecision{Source: decisionSourcePassthrough, From: cc.req.Model}
		if cc.unknownFallback {
			cc.dec.Reason = "unknown_model_fallback"
		}
	}
	if gw.cfg.DecisionHeaderEnabled {
		cc.dec.set(w)
	}

	return true
}

// policyJudgeVersion reports the judge prompt/template version identifier
// runtime is off/unwired, the org has no snapshot, or no judge resolved.
func (gw *gateway) policyJudgeVersion(ctx context.Context, orgID string) string {
	rt := gw.policyRuntime
	if rt == nil || orgID == "" {
		return ""
	}
	return rt.judgePromptVersion(ctx, orgID)
}

// D2). Observability only: it never gates the response and stays absent when
// no judge template resolved. Called once per chat request, before any
// response bytes.
func (gw *gateway) setJudgeVersionHeader(ctx context.Context, w http.ResponseWriter, orgID string) {
	if v := gw.policyJudgeVersion(ctx, orgID); v != "" {
		w.Header().Set(judgeVersionHeaderKey, v)
	}
}

// chatExecution is the outcome of the JSON execution stage: the winning
// attempt's response, the payload that actually went upstream, and the chain
// observables the accounting stage reports.
type chatExecution struct {
	// body is the winning response (possibly tool-call-stripped later);
	// sent is what was actually forwarded upstream (post model override).
	body, sent   []byte
	headers      http.Header
	finalInfo    resolver.ModelInfo
	finalURL     string
	durationMs   int64
	attempts     int
	totalRetries int
	lastCode     int
	// usedOrgKey reports whether the WINNING hop authenticated with an
	// org credential (BYOK) instead of a per-model or global key.
	usedOrgKey bool
	// ("" when the winning hop used no org credential).
	orgCredRef string
}

type unknownOutcomeErrorType struct {
	policy *router.PolicyError
	cause  error
}

func (e *unknownOutcomeErrorType) Error() string {
	return "upstream outcome unknown: " + e.cause.Error()
}

func (e *unknownOutcomeErrorType) Unwrap() error { return e.policy }

func unknownOutcomeError(cause error) error {
	return &unknownOutcomeErrorType{
		policy: &router.PolicyError{
			Status:  http.StatusBadGateway,
			ErrType: apierrors.ErrorCodeAPI,
			ErrCode: "upstream_outcome_unknown",
			Message: "upstream outcome unknown; automatic retry and fallback suppressed",
		},
		cause: cause,
	}
}

// chatRetryPolicy wraps the configured retry classifier with the refusal
// rule (CONTRACT §1: "The refusal is final: no retry"): an adapter refusal —
// the terminal capability carrier (*router.PolicyError rendered from a
// CapabilityError) or a typed unsupported-feature rejection — is a
// deterministic client-shaped answer. Re-invoking the identical attempt
// cannot change it: the adapter proved the refusal before any byte left the
// process, so the extra loop iterations are pure wasted work and a latent
// same-model retry of a "final" answer. Everything else delegates to the
// configured classifier unchanged (transport errors, 429/5xx).
func chatRetryPolicy(base retry.Policy) retry.Policy {
	inner := base.RetryOn
	if inner == nil {
		inner = retry.DefaultClassifier
	}
	base.RetryOn = func(statusCode int, err error) bool {
		if err != nil {
			var policyErr *router.PolicyError
			if errors.As(err, &policyErr) {
				return false
			}
			if provider.IsUnsupportedFeature(err) {
				return false
			}
		}
		return inner(statusCode, err)
	}
	return base
}

// executeChatJSON (stage 4a) runs the circuit-breaker-gated upstream
// execution for non-streaming requests: per-model retry against one upstream,
// then the fallback chain across failover_models. Every actual attempt
// re-passes the RT-03 shared gate (a policy denial is chain-terminal and is
// answered here with the gate envelope — the transport must not route around
// a policy decision). A false result means the request was answered
// terminally inside the stage.
func (gw *gateway) executeChatJSON(ctx context.Context, cc *chatContext) (*chatExecution, bool) {
	w, l := cc.w, cc.l

	if err := gw.checkBreaker(); err != nil {
		l.Error("circuit breaker open, rejecting request", "error", err)
		reservationGateFrom(ctx).finalizeNoEvent(budget.TerminationPolicyDenied)
		gw.voidUndispatchedInvocation(ctx, l)
		apierrors.Write(w, http.StatusServiceUnavailable, apierrors.ErrorCodeServiceUnavailable, "upstream provider unavailable")
		return nil, false
	}

	ex := new(chatExecution)
	var openRejections atomic.Int32
	perModel := func(ctx context.Context, mi resolver.ModelInfo) (int, error) {
		return gw.tryChatModel(ctx, cc, mi, ex, &openRejections)
	}

	start := time.Now()
	finalInfo, lastCode, attempts, lastErr := gw.executeFallback(ctx, cc.info, perModel)

	// Emit fallback metrics: when the chain has >1 attempt, each transition
	// from one model to the next is a fallback event (P3.19).
	for i := 1; i < len(attempts); i++ {
		from := attempts[i-1].ModelName
		to := attempts[i].ModelName
		reason := "transport"
		if !attempts[i-1].Success && attempts[i-1].StatusCode > 0 {
			reason = strconv.Itoa(attempts[i-1].StatusCode)
		}
		metrics.FallbackTotal.WithLabelValues(from, to, reason).Inc()
	}

	durationMs := eventpub.ComputeDurationMs(start)
	finalURL := gw.upstreamURL(finalInfo)

	if lastErr != nil {
		if gw.rejectChatAttempt(ctx, cc, lastErr, lastCode, len(attempts), int(openRejections.Load())) {
			return nil, false
		}

		gw.recordBreakerFailure()
		l.Error("upstream error (all fallback attempts exhausted)",
			"error", lastErr, "attempts", len(attempts))

		errBase := eventBase{
			EventType:            "request.failed",
			RequestID:            cc.reqID,
			SessionID:            cc.sessionID,
			Payload:              string(cc.body),
			OrgID:                cc.orgID,
			TeamID:               cc.teamID,
			ModelRequested:       cc.requestedModel,
			UpstreamURL:          finalURL,
			StatusCode:           int64(lastCode),
			DurationMs:           durationMs,
			Method:               "POST",
			Endpoint:             endpointFrom(ctx, "chat.completions"),
			UsageSource:          "none",
			CostStatus:           costStatus(false, "none", false),
			Error:                fmt.Sprintf("upstream failed: %v", lastErr),
			TierUsed:             cc.tierUsed,
			ClassifierClass:      cc.classifierClass,
			ClassifierConfidence: cc.classifierConfidence,
			ClassifierSource:     cc.classifierSource,
			AttemptCount:         len(attempts),
			RetryCount:           ex.totalRetries,
			Labels:               labelsFrom(ctx),
		}
		// NEXT-18c: the reserve tuples ride the failure event (§5.3
		// Finalize); no usage accrued — the worker bills nothing and the
		// idle return sweeps the escrow.
		gw.finishRequestLogged(ctx, cc.l, requestFinish{
			base:        errBase,
			attestModel: finalInfo.ModelName,
			info:        finalInfo,
			termination: budget.TerminationUpstreamErr,
		})

		httpStatus, errType, errCode, errMsg := gw.mapProviderUpstream(finalInfo.Provider, lastCode, lastErr)
		// RATELIMIT-FALLBACK P2: on a decision-bearing upstream rate limit,
		// surface the provider's own Retry-After hint to the caller (whole
		// seconds). Unknown hints omit the header — never fabricated.
		if secs := clientRetryAfterSeconds(lastCode, lastErr); secs > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(secs))
		}
		if errCode != "" {
			apierrors.WriteWithCode(w, httpStatus, errType, errMsg, errCode)
			return nil, false
		}
		apierrors.Write(w, httpStatus, errType, errMsg)
		return nil, false
	}

	ex.finalInfo, ex.finalURL = finalInfo, finalURL
	ex.durationMs, ex.attempts, ex.lastCode = durationMs, len(attempts), lastCode
	return ex, true
}

func (gw *gateway) tryChatModel(ctx context.Context, cc *chatContext, mi resolver.ModelInfo, ex *chatExecution, openRejections *atomic.Int32) (int, error) {
	// Cancellation is terminal before anything else: gating with a dead
	// context would misreport the cancel as a policy-store outage.
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	// RT-03: every actual provider attempt re-passes the shared gate. A
	// policy denial/unavailable is chain-terminal (router.PolicyError) —
	// the transport fallback must not route around a policy decision.
	mi, pol := gw.gateAttemptCandidate(ctx, candidateIdentity{OrgID: cc.orgID, TeamID: cc.teamID, APIKeyID: cc.apiKeyID}, cc.req.Model, mi)
	if pol != nil {
		return pol.Status, pol
	}
	url := gw.upstreamURL(mi)
	// breaker. An open primary circuit fails this hop immediately
	// (retryable) so the chain advances to a candidate on another
	// endpoint, whose breaker is independent; only when every candidate's
	// breaker is open does the request terminate with 503. In global
	// scope this is a no-op (the entry checkBreaker gate rules).
	if berr := gw.allowEndpoint(url); berr != nil {
		openRejections.Add(1)
		return http.StatusServiceUnavailable, berr
	}
	// W-BYOK-CORE: request path resolves the credential in priority
	// order — org credential (BYOK) → this candidate's per-model
	// upstream_api_key → global default (see resolveUpstreamKey). An
	// infrastructure failure while the org plausibly holds a credential
	// for this endpoint is fail-closed (never route the GLOBAL key to an
	// org-registered endpoint).
	key, use, kerr := gw.resolveUpstreamKey(ctx, cc.orgID, mi)
	if kerr != nil {
		return 0, kerr
	}

	// Reasoning-effort injection (v15 E1, opt-in): per-model body, after
	// the cache lookup, so the cache key is unchanged. The retry body
	// stays fwdBody for this attempt.
	fwdBody := gw.maybeInjectEffort(cc.body, mi, classifier.Class(cc.classifierClass))
	if eff := gw.effortForModel(mi.ModelName); eff != "" {
		cc.dec.Effort = eff
	}

	start := time.Now()
	client, perr := gw.pool.Get(url, mi.Provider)
	if perr != nil {
		// Pool initialisation failure (unknown provider / SSRF-allowlist
		// violation) is a configuration error, not transient: no retries —
		return http.StatusBadGateway, fmt.Errorf("upstream client for %s: %w", mi.Provider, perr)
	}
	var attemptNum int // tracks how many times the retry loop has run
	res := retry.Do(ctx, chatRetryPolicy(gw.retryPolicy), func(ctx context.Context) retry.Result {
		attemptNum++
		return forwardChatAttempt(ctx, client, fwdBody, mi, key, ex)
	})

	// Capability refusals ride the terminal policy carrier: nothing was
	// sent, the chain stops here, and no upstream accounting applies —
	// skip the metrics/quarantine/breaker path below entirely.
	var capPolicyErr *router.PolicyError
	if res.Err != nil && errors.As(res.Err, &capPolicyErr) {
		return res.StatusCode, res.Err
	}

	gw.recordChatAttemptMetrics(client, mi, res, attemptNum, start)
	ex.totalRetries += attemptNum - 1

	gw.recordOrgCredOutcome(ctx, cc.orgID, mi.Provider, use, res.StatusCode)

	return gw.finishChatHop(url, res, use, ex)
}

func forwardChatAttempt(ctx context.Context, client *upstream.Client, fwdBody []byte, mi resolver.ModelInfo, key string, ex *chatExecution) retry.Result {
	hdrs, b, sentBody, ferr := client.ForwardJSONCapturing(ctx, fwdBody, mi.ModelName, key, mi.UpstreamTimeout)
	if ferr != nil {
		return chatRetryError(ferr)
	}
	ex.sent = sentBody
	return retry.Result{StatusCode: http.StatusOK, Headers: hdrs, Body: b}
}

func chatRetryError(ferr error) retry.Result {
	if capErr, ok := provider.Refusal(ferr); ok {
		// Adapter capability refusal: the feature check failed
		// before any byte left the gateway. Client-shaped 400 on
		// a terminal policy carrier — no retry, no failover to
		// another model (no silent downgrade), no breaker or
		// credential penalty, no upstream accounting.
		return retry.Result{
			StatusCode: http.StatusBadRequest,
			Err:        capabilityPolicy(capErr),
			Safety:     retry.OutcomeNotExecuted,
		}
	}
	// Real upstream/transport failure. Carry the failed attempt's
	// headers (nil for refusals / not-sent) so Retry-After hints
	// feed the retry scheduler; Status/Err/Safety semantics below
	// are unchanged.
	result := retry.Result{StatusCode: extractUpstreamStatus(ferr), Err: ferr, Headers: upstreamFailureHeaders(ferr)}
	switch {
	case result.StatusCode > 0 || retry.DefinitelyNotSent(ferr):
		result.Safety = retry.OutcomeNotExecuted
	case provider.IsUnsupportedFeature(ferr):
		// N07-P05-T02: a deterministic pre-flight capability
		// rejection (image part / unmapped content-part type).
		// Proof of non-execution, but never same-candidate
		// retryable (the answer cannot change) — keep the typed
		// error unwrapped so the terminal handler answers an
		// explicit 400 unsupported_feature instead of the opaque
		// upstream_outcome_unknown 502.
	case retry.IsRequestNotSent(ferr):
		// Translate-layer refusal (N07-P01-T05): typed proof the
		// request never left this process. Safety intentionally
		// stays Unknown — MayRepeat forbids repeating Unknown
		// attempts (a deterministic refusal must not be retried),
		// while the router classifier still sees NotExecuted via
		// retry.Classify and advances the fallback chain. The
		// error stays unwrapped so the terminal render can
		// errors.As the typed proof and surface the exact reason.
	default:
		result.Err = unknownOutcomeError(ferr)
	}
	return result
}

func (gw *gateway) recordChatAttemptMetrics(client *upstream.Client, mi resolver.ModelInfo, res retry.Result, attemptNum int, start time.Time) {
	// Emit metrics for the attempt. Usage is parsed from body on success.
	var u provider.Usage
	if res.Err == nil && len(res.Body) > 0 {
		u = client.Adapter().ParseUsage(res.Body)
	}
	ext := provider.ComputeCost(u, mi.Provider, mi.ModelName)
	gw.emitUpstreamMetrics(mi.Provider, mi.ModelName, res.StatusCode, time.Since(start), u, ext.EstimatedCostUSD)

	// Emit retry_total for retries that occurred (attemptNum > 1 means
	// at least one retry was performed). The attempt label is the number
	// of the retry (1 = first retry, 2 = second retry, ...).
	for n := 1; n < attemptNum; n++ {
		metrics.RetryTotal.WithLabelValues(strconv.Itoa(n), strconv.Itoa(res.StatusCode)).Inc()
	}
}

func (gw *gateway) finishChatHop(url string, res retry.Result, use orgCredentialUse, ex *chatExecution) (int, error) {
	if res.Err == nil && res.StatusCode < 500 {
		// (per-endpoint scope; no-op in global scope).
		gw.recordEndpointSuccess(url)
		ex.body = res.Body
		ex.headers = res.Headers
		ex.usedOrgKey, ex.orgCredRef = use.used, use.ref()
		return res.StatusCode, nil
	}
	// endpoint the chain touches (per-endpoint scope; no-op in global).
	// A translate-layer refusal (N07-P01-T05) never contacted the
	// endpoint — counting it as an endpoint failure would trip the
	// breaker on a client-side request problem.
	if !retry.IsRequestNotSent(res.Err) {
		gw.recordEndpointFailure(url)
	}
	errOut := res.Err
	if errOut == nil {
		errOut = fmt.Errorf("upstream error %d", res.StatusCode)
	}
	return res.StatusCode, errOut
}

func (gw *gateway) rejectChatAttempt(ctx context.Context, cc *chatContext, lastErr error, lastCode, attemptCount, openRejections int) bool {
	w, l := cc.w, cc.l
	// N07-P05-T02 (order restored by N07-RECON): a media-capability
	// rejection (image part on an adapter without image input, unmapped
	// content-part type) is a CLIENT format error the adapter raised
	// before any byte left the gateway. The typed branch is matched
	// BEFORE the plain request-not-sent branch: the translate seam wraps
	// the refusal in retry.RequestNotSentError, and the refusal must
	// render 400 unsupported_feature with the adapter's exact reason —
	// never an opaque 5xx, no breaker penalty, and no analytics event
	// (the escrow settles locally; parity with the policy-denial path).
	var unsupportedFeatureErr *provider.UnsupportedFeatureError
	if errors.As(lastErr, &unsupportedFeatureErr) {
		reservationGateFrom(ctx).finalizeNoEvent(budget.TerminationPolicyDenied)
		l.Warn("provider adapter rejected unsupported request feature",
			"error", lastErr, "attempts", attemptCount)
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			unsupportedFeatureErr.Error(), apierrors.CodeUnsupportedFeature)
		return true
	}
	// N07-P01-T05: a translate-layer refusal is a client-side request
	// problem — the request never reached any endpoint, so the exact
	// reason (which modeled field was lost, and why) renders as 400
	// invalid_request_error, never disguised as a generic upstream
	// failure (I51: no silent drop, and no misleading status). Typed
	// unsupported-feature refusals are matched by the dedicated branch
	// above.
	var notSentErr *retry.RequestNotSentError
	if errors.As(lastErr, &notSentErr) {
		reservationGateFrom(ctx).finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, notSentErr.Error())
		return true
	}
	// RT-03: a terminal policy outcome from a fallback hop ends the
	// request with the gate envelope. The denied candidate was never
	// called, so this is not an upstream failure: no provider error
	// mapping and no circuit-breaker penalty.
	var policyErr *router.PolicyError
	var unknownErr *unknownOutcomeErrorType
	if errors.As(lastErr, &unknownErr) {
		reservationGateFrom(ctx).finalizeNoEvent(budget.TerminationUpstreamErr)
		status := lastCode
		if status < 400 {
			status = http.StatusBadGateway
		}
		apierrors.Write(w, status, apierrors.ErrorCodeAPI, "upstream outcome unknown; request was not retried")
		return true
	}
	if errors.As(lastErr, &policyErr) {
		// NEXT-18c: no analytics event is published on this path — settle
		// the local escrow (zero spend, in-flight bound released).
		reservationGateFrom(ctx).finalizeNoEvent(budget.TerminationPolicyDenied)
		writeGateDenial(w, gateResultFromPolicy(policyErr))
		return true
	}

	// parity of the global-scope entry rejection: same 503 envelope, no
	// analytics event, the escrow settles locally. No endpoint was
	// dialed, so this is not an upstream failure to record.
	if allCircuitsOpen(lastCode, openRejections, attemptCount) {
		reservationGateFrom(ctx).finalizeNoEvent(budget.TerminationPolicyDenied)
		gw.voidUndispatchedInvocation(ctx, l)
		l.Error("circuit breaker open, rejecting request (all candidate endpoints open)",
			"attempts", attemptCount)
		apierrors.Write(w, http.StatusServiceUnavailable, apierrors.ErrorCodeServiceUnavailable, "upstream provider unavailable")
		return true
	}

	return false
}

// serveChatCache (stage 4b) tries the RT-05 cache branch after the full
// routing pipeline and the final-candidate gate. A warm entry is only served
// for the CURRENT route: the lookup identity carries the routed model and the
// generation parameters this route would inject, so an entry generated by
// another route (changed rule override, retargeted alias, residency remap,
// different effort) degrades to a miss — never a response from an old route.
// The gate above ran the same policy checks an upstream call passes
// (whitelist/ZAI + residency before it); a deny/unavailable stays terminal
// (403/503) — a policy failure must not become a silent refetch around the
// policy. The current post-upstream content policy re-governs the cached
// replay past the live control. Generation still happens only on a miss.
// true = the request was answered from the cache (including a terminal
// policy denial of the cached document).
func (gw *gateway) serveChatCache(ctx context.Context, cc *chatContext) bool {
	if !gw.chatCacheEligible(cc) {
		return false
	}
	l := cc.l
	orgID := cc.orgID

	ri := cache.RouteIdentity{
		OrgID:     orgID,
		Model:     cc.model,
		GenParams: gw.effortForCandidate(cc.info, classifier.Class(cc.classifierClass)),
		Upstream:  gw.cacheUpstreamFP(cc.info), // H1: endpoint revision — a re-pointed upstream is a miss
	}
	hit, err := gw.cache.LookupWithResult(ctx, ri, cc.body)
	var sseBody []byte
	if err == nil && hit != nil {
		if gw.governChatCacheHit(ctx, cc, hit) {
			return true
		}
		var usable bool
		sseBody, usable = validateChatCacheReplay(l, orgID, hit, cc.req.Stream)
		if !usable {
			hit = nil
		}
	}
	if err == nil && hit != nil {
		gw.finishChatCacheHit(ctx, cc, hit, sseBody)
		return true
	}
	l.Debug("cache miss — forwarding to upstream", "org_id", orgID)
	return false
}

// validateChatCacheReplay enforces that a governed hit is servable before
// any header is written, degrading to a miss (ok=false) instead of broken
// bytes; the upstream refetch re-serves fresh and the writer overwrites the
// broken value at the same key (self-healing). Both guards sit AFTER
// enforcement on purpose: a corrupt entry whose governed verdict is a
// terminal deny never reaches this point, so corruption cannot bypass
// enforcement and a denial does not trigger an upstream refetch.
func validateChatCacheReplay(l *slog.Logger, orgID string, hit *cache.CacheHit, stream bool) (sseBody []byte, ok bool) {
	// N03-P02-T08: the entry survived governance and is about to be served —
	// it must decode as a completion document. A torn cache value (sealed
	// envelope and provenance intact, completion document truncated or
	// corrupted inside) never serves broken bytes.
	// FIX-10 (N03-P02-T10): the probe uses the shared usable-completion
	// contract, so a document that decodes but carries no choices
	// (`{}`, `{"choices":[]}`) degrades to a miss on the nonstream path
	// exactly like the streaming replay always did — never served with
	// X-Cache attribution.
	if _, probeErr := cachedCompletionUsable(hit.Data); probeErr != nil {
		l.Warn("cache hit is not a usable completion document — serving from upstream",
			"error", probeErr, "org_id", orgID)
		return nil, false
	}
	if !stream {
		return nil, true
	}
	// Streaming clients must receive SSE frames, never a raw JSON completion
	// document — OpenAI-compatible SDKs block waiting for `data:` lines and
	// the caller appears hung. Convert before any header is written; on
	// conversion failure treat the entry as a miss so the request is served
	// fresh instead of broken.
	sseBody, err := sseReplayFrames(hit.Data)
	if err != nil {
		l.Warn("cache hit is not a replayable completion document — serving from upstream",
			"error", err, "org_id", orgID)
		return nil, false
	}
	return sseBody, true
}

// chatCacheEligible is the cache lookup gate: no cache service, no org
// tenant, an org that disabled caching, or — W-STCACHE — a streaming request
// while cache_stream_enabled is off (streaming must never be answered from
// possibly stale, pre-fix stream-cache entries; non-stream lookups are
// unaffected).
func (gw *gateway) chatCacheEligible(cc *chatContext) bool {
	return gw.cache != nil && cc.orgID != "" && !cc.cacheDisabled &&
		(!cc.req.Stream || gw.cfg.CacheStreamEnabled)
}

// governChatCacheHit re-governs a cached document with the CURRENT
// post-upstream policy: a cache entry was written under an earlier policy
// regime and must never bypass it. The cached document (exact, semantic,
// and the SSE replay of either) is evaluated exactly like a fresh upstream
// body: a mask replaces what the client sees, a deny answers the terminal
// content_policy_violation envelope and no cached byte is written. This
// closes the "entry created before a policy change" gap — the tenant
// boundary itself is already enforced below this point (the cache service
// verified the sealed provenance against this request's org, so a foreign
// org's entry degrades to a miss). Returns true when the request was
// answered terminally (policy denial); the hit's Data carries the governed
// body otherwise.
func (gw *gateway) governChatCacheHit(ctx context.Context, cc *chatContext, hit *cache.CacheHit) bool {
	served, postEvent, denied := gw.policyPostUpstream(cc.r, "chat", cc.model, cc.info.Provider, hit.Data)
	if postEvent != "" {
		cc.policyEvent = appendPolicyEvents(cc.policyEvent, postEvent)
	}
	if denied {
		gw.serveChatCachePolicyDenied(ctx, cc, hit, postEvent)
		return true
	}
	hit.Data = served
	if cc.req.Stream {
		// Stream-attached policies (stream_prefix/stream_final) never run at
		// post_upstream — re-govern the replay with them before any frame is
		// converted, or a deny tightened after the entry was cached would
		// serve forbidden content (N03-P02-T02). A replay has issued no
		// bytes, so a stream_final deny stays terminal here (live streams
		// can only flag after issuance).
		streamServed, streamEvents, streamDenied := gw.policyReplayStreamCheck(cc.r, "chat", cc.model, cc.info.Provider, hit.Data)
		if streamEvents != "" {
			cc.policyEvent = appendPolicyEvents(cc.policyEvent, streamEvents)
		}
		if streamDenied {
			gw.serveChatCachePolicyDenied(ctx, cc, hit, cc.policyEvent)
			return true
		}
		hit.Data = streamServed
	}
	return false
}

// finishChatCacheHit serves a governed cache hit: honest attribution headers
// (the model that actually generated the response, the entry's source type),
// the payload (SSE frames for streaming clients), and the cache-aware
// request.completed event. Cache hits never reserve: publish without a
// settle. Cache hits are counted by pkg/cache itself — do not double-count.
func (gw *gateway) finishChatCacheHit(ctx context.Context, cc *chatContext, hit *cache.CacheHit, sseBody []byte) {
	w, l := cc.w, cc.l
	orgID := cc.orgID

	// Honest attribution: provenance of the entry — the model that
	// actually generated the cached response (verified against this
	// route by the cache service).
	modelUsed := hit.ModelUsed
	if modelUsed == "" {
		modelUsed = cc.model
	}
	if eff := gw.effortForCandidate(cc.info, classifier.Class(cc.classifierClass)); eff != "" {
		cc.dec.Effort = eff
	}
	l.Debug("cache hit", "org_id", orgID, "model", cc.model, "model_used", modelUsed, "source", hit.SourceType, "stream", cc.req.Stream)
	// Counterfactual for a cache hit: what the request would have cost had
	// it gone upstream. The cached completion document carries the original
	// usage, so price it with the winning model's adapter. Without usable
	// usage the counterfactual stays 0 — the savings percentage degrades
	// to 0 instead of lying.
	cacheCounterfactual := cachedUsageCounterfactual(hit.Data, cc.info.Provider, modelUsed)
	if cc.req.Stream {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("X-Cache", strings.ToUpper(hit.SourceType))
	if hit.Similarity > 0 {
		w.Header().Set("X-Cache-Similarity", fmt.Sprintf("%.4f", hit.Similarity))
	}
	w.WriteHeader(http.StatusOK)
	payload := hit.Data
	if cc.req.Stream {
		payload = sseBody
	}
	if _, err := w.Write(payload); err != nil {
		l.Error("cache hit write failed", "error", err, "org_id", orgID)
	}
	if cc.req.Stream {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}

	// P4.13: Publish cache-aware analytics event for savings tracking.
	gw.finishRequestLogged(ctx, cc.l, requestFinish{
		base: eventBase{
			EventType: "request.completed",
			RequestID: cc.reqID,
			SessionID: cc.sessionID,
			Payload:   string(cc.body),
			// FIX-20: the served document IS the processed response on a
			// cache hit (stream replay and JSON alike) — envelope from it.
			ProcessedResponse:     envelopeFromCompletionDoc(hit.Data, modelUsed).marshal(),
			OrgID:                 orgID,
			TeamID:                cc.teamID,
			ModelRequested:        cc.requestedModel,
			ModelUsed:             modelUsed,
			UpstreamURL:           cc.info.UpstreamURL,
			StatusCode:            http.StatusOK,
			Method:                "POST",
			Endpoint:              endpointFrom(ctx, "chat.completions"),
			UsageSource:           "none",
			CostStatus:            costStatus(true, "none", false),
			CacheHitType:          hit.SourceType,
			CacheSimilarity:       hit.Similarity,
			CounterfactualCostUSD: cacheCounterfactual,
			TierUsed:              cc.tierUsed,
			ClassifierClass:       cc.classifierClass,
			ClassifierConfidence:  cc.classifierConfidence,
			ClassifierSource:      cc.classifierSource,
			RoutingDecision:       gw.decisionJSON(decisionSourceCacheHit(hit.SourceType), cc.dec),
			Policy:                cc.policyEvent,
			Labels:                labelsFrom(ctx),
		},
		// Cache hits never reserve: publish without a settle.
		noSettle: true,
		info:     cc.info,
	})
}

// serveChatCachePolicyDenied ends a cache-hit request whose document the
// CURRENT post-upstream policy denied: the client receives the same
// 400 content_policy_violation envelope as the upstream denial path, the
// request.failed event carries the decision record plus the cache-hit
// attribution, and no cached byte reaches the client. Cache hits never
// reserve — the event publishes without a settle.
func (gw *gateway) serveChatCachePolicyDenied(ctx context.Context, cc *chatContext, hit *cache.CacheHit, policyJSON string) {
	w, l := cc.w, cc.l
	modelUsed := hit.ModelUsed
	if modelUsed == "" {
		modelUsed = cc.model
	}
	l.Warn("policy denied cache hit", "org_id", cc.orgID, "request_id", cc.reqID,
		"model", cc.model, "source", hit.SourceType, "mode", string(gw.policyRuntime.mode))
	gw.finishRequestLogged(ctx, l, requestFinish{
		base: eventBase{
			EventType:            "request.failed",
			RequestID:            cc.reqID,
			SessionID:            cc.sessionID,
			Payload:              string(cc.body),
			OrgID:                cc.orgID,
			TeamID:               cc.teamID,
			ModelRequested:       cc.requestedModel,
			ModelUsed:            modelUsed,
			UpstreamURL:          cc.info.UpstreamURL,
			StatusCode:           http.StatusBadRequest,
			Method:               "POST",
			Endpoint:             endpointFrom(ctx, "chat.completions"),
			UsageSource:          "none",
			CostStatus:           costStatus(true, "none", false),
			CacheHitType:         hit.SourceType,
			Error:                "response blocked by organization policy",
			TierUsed:             cc.tierUsed,
			ClassifierClass:      cc.classifierClass,
			ClassifierConfidence: cc.classifierConfidence,
			ClassifierSource:     cc.classifierSource,
			RoutingDecision:      gw.decisionJSON(decisionSourceCacheHit(hit.SourceType), cc.dec),
			Policy:               policyJSON,
			Labels:               labelsFrom(ctx),
		},
		// Cache hits never reserve: publish without a settle.
		noSettle: true,
		info:     cc.info,
	})
	apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
		"response blocked by organization policy", policyDenyErrorCode)
}

// finalizeChatJSON (stage 5) accounts for the winning response and completes
// the request: usage parsing via the final attempt's adapter, task/session
// budget recording, session-affinity warming, resale pricing, evalgate
// sampling, lineage attestation, the analytics event, tool-call gating, the
// async cache write (post-gate, under the WINNING candidate's route identity),
// the client response and the detached shadow mirror.
func (gw *gateway) finalizeChatJSON(ctx context.Context, cc *chatContext, ex *chatExecution) {
	r, w, l := cc.r, cc.w, cc.l
	orgID, sessionID, taskID := cc.orgID, cc.sessionID, cc.taskID

	resp := ex.body
	finalInfo := ex.finalInfo
	finalModelName := finalInfo.ModelName

	// Parse usage via the final-attempt provider's adapter (P3.11). This
	// works for both OpenAI (usage.prompt_tokens) and Anthropic
	// (usage.input_tokens) shapes since the adapter knows its provider's
	// response schema. ComputeCost turns tokens into an estimated USD amount
	// using pkg/pricing.
	usage := chatUsageAdapter(finalInfo, l).ParseUsage(resp)
	ext := provider.ComputeCost(usage, finalInfo.Provider, finalModelName)

	// OP-8: post-upstream policy hook — a deny answers 400 and finishes the
	// request with the spend accounted (see applyChatPostUpstreamPolicy).
	resp, handled := gw.applyChatPostUpstreamPolicy(ctx, cc, ex, usage, ext, resp)
	if handled {
		return
	}

	// G3: record final token usage against task/session budgets, correct the
	// TPM reservation and warm the session affinity (usage is final here —
	// post-attempt, pre-event).
	gw.accountUsage(ctx, w, usageRecord{
		orgID:         orgID,
		taskID:        taskID,
		sessionID:     sessionID,
		affinityModel: finalModelName,
		usage:         usage,
		costUSD:       ext.EstimatedCostUSD,
		priceKnown:    ext.PriceKnown,
	})

	// Compute resale cost with markup for reseller billing.
	resaleCostUSD := gw.resaleCostUSD(ctx, orgID, finalInfo.Provider, finalModelName, usage)

	// TOOL-02: strip tool_calls the org policy denies BEFORE the client (or
	// the cache) sees them. No deny policies → one cached bool, zero parsing.
	// FIX-20: the gate runs above the event build so the processed-response
	// envelope captures the POST-gate body — the envelope must describe what
	// the client receives, and denied tool calls never reach it.
	resp = gw.gateChatToolCalls(ctx, r, l, orgID, resp)

	// P5.9: Evalgate sampling hook (see buildEvalgateHook). Built after the
	// tool gate on purpose: the hook's judge arguments were previously
	// evaluated when the hook ran inside finishRequest — i.e. on the
	// post-gate body — and resp is never reassigned after the gate, so
	// building here with the post-gate resp is behaviorally identical.
	evalgateHook := gw.buildEvalgateHook(ctx, cc, finalModelName, resp)

	// Build the completed-request event (the single builder) and finish:
	// evalgate hook → lineage attestation → reservation settle → publish.
	var upResp *http.Response
	if len(ex.headers) > 0 {
		upResp = &http.Response{Header: ex.headers}
	}
	base := eventBase{
		EventType:        "request.completed",
		RequestID:        cc.reqID,
		SessionID:        sessionID,
		Payload:          string(cc.body),
		UpstreamPayload:  boundedSample(ex.sent, upstreamCaptureLimit),
		UpstreamResponse: boundedSample(ex.body, upstreamCaptureLimit),
		// FIX-20: the processed client-facing response — parsed from the
		// post-gate body; "" when it does not parse as a completion document
		// (honest absence, never a fabricated answer).
		ProcessedResponse:     envelopeFromCompletionDoc(resp, finalModelName).marshal(),
		OrgID:                 orgID,
		TeamID:                cc.teamID,
		AgentID:               cc.agentID, // G2
		UserID:                cc.userID,  // RM-44
		APIKeyID:              cc.apiKeyID,
		SessionKeyID:          r.Header.Get("X-Session-Key-Id"),
		TaskID:                taskID, // G2
		ModelRequested:        cc.requestedModel,
		ModelUsed:             finalModelName,
		UpstreamURL:           ex.finalURL,
		StatusCode:            http.StatusOK,
		DurationMs:            ex.durationMs,
		TokensIn:              usage.PromptTokens,
		TokensOut:             usage.CompletionTokens,
		CacheReadTokens:       usage.CacheReadTokens,
		CacheCreationTokens:   usage.CacheCreationTokens,
		EstimatedCostUSD:      ext.EstimatedCostUSD,
		Endpoint:              endpointFrom(ctx, "chat.completions"),
		UsageSource:           usageSourceOrNone(usage.Source),
		CostStatus:            costStatus(false, usage.Source, ext.PriceKnown),
		ResaleCostUSD:         resaleCostUSD,
		Method:                "POST",
		CounterfactualCostUSD: gw.effectiveCounterfactual(ctx, cc.req.Model, cc.tierUsed, cc.classifierClass, usage, ext.EstimatedCostUSD),
		TierUsed:              cc.tierUsed,
		ClassifierClass:       cc.classifierClass,
		ClassifierConfidence:  cc.classifierConfidence,
		ClassifierSource:      cc.classifierSource,
		RoutingDecision:       gw.decisionJSON(cc.dec.Source, cc.dec),
		AttemptCount:          ex.attempts,
		RetryCount:            ex.totalRetries,
		UsedOrgKey:            ex.usedOrgKey, // W-BYOK-CORE: BYOK attribution (no secret material)
		OrgCredentialRef:      ex.orgCredRef,
		Policy:                cc.policyEvent, // OP-8: decision record (OP-9 contract)

		// PB1: Jurisdictional lineage attestation fields.
		// When LineageEnabled=true these get overwritten by attachLineage() with
		// post-fallback values; when disabled they still reflect the *winning* model.
		InferenceRegion:            finalInfo.Region,
		ModelOriginCountry:         finalInfo.Provider,
		LogStorageRegion:           gw.cfg.Region,
		ProviderEntityJurisdiction: finalInfo.Provider,
		Labels:                     labelsFrom(ctx),
	}
	_, ferr := gw.finishRequest(ctx, requestFinish{
		base:        base,
		info:        finalInfo,
		resp:        upResp,
		termination: budget.TerminationCompleted,
	}, evalgateHook)
	// Central binding: client success is ordered after persistence. A
	// failed terminal write (even after transient-PG retries) must not
	// surface the upstream body as a payable success — and the event is
	// already withheld inside the funnel. No cache write, no shadow
	// mirror: the response being failed must not outlive this call.
	if ferr != nil {
		writeTerminalAccountingFailure(w)
		return
	}

	// P4/RT-05: write to cache asynchronously under the route identity of
	// the model that ACTUALLY generated the response (see
	// writeChatCacheAsync).
	gw.writeChatCacheAsync(ctx, cc, finalInfo, finalModelName, resp, usage)

	writeChatJSONClient(w, l, usage, resp, finalModelName)

	gw.recordBreakerSuccess()

	// V9: shadow-mode. The response above is already fully written to the
	// client; the detached shadow call below cannot affect it (mandatory
	// passthrough). It only mirrors the request to a candidate model for
	// real-cost/latency accounting.
	gw.maybeShadow(r, cc.body, finalModelName, orgID, cc.teamID, sessionID, cc.reqID)
}

// chatUsageAdapter resolves the usage parser for the final-attempt provider
// (P3.11: the adapter knows its provider's response schema), falling back to
// the OpenAI shape when the provider is unknown so usage accounting degrades
// instead of disappearing.
func chatUsageAdapter(finalInfo resolver.ModelInfo, l *slog.Logger) provider.Provider {
	adapter, err := provider.New(finalInfo.Provider)
	if err != nil {
		l.Warn("usage accounting skipped: unknown provider", "provider", finalInfo.Provider, "error", err)
		return provider.OpenAI{}
	}
	return adapter
}

// applyChatPostUpstreamPolicy runs the OP-8 post-upstream hook. Usage was
// parsed from the ORIGINAL upstream body (the tokens were consumed
// regardless of the verdict); a mask replaces the body every downstream
// consumer sees (client, cache, tool gate); a deny answers 400 instead of the
// upstream body while the accounting still records the spend that left the
// org (finishPolicyDeniedJSON carries that terminal path). Returns the
// governed body and whether the request was answered terminally.
func (gw *gateway) applyChatPostUpstreamPolicy(ctx context.Context, cc *chatContext, ex *chatExecution, usage provider.Usage, ext provider.ExtendedUsage, resp []byte) ([]byte, bool) {
	if gw.policyRuntime == nil {
		return resp, false
	}
	masked, postEvent, denied := gw.policyPostUpstream(cc.r, "chat", ex.finalInfo.ModelName, ex.finalInfo.Provider, resp)
	if postEvent != "" {
		cc.policyEvent = appendPolicyEvents(cc.policyEvent, postEvent)
	}
	if denied {
		gw.finishPolicyDeniedJSON(ctx, cc, ex.finalInfo, usage, ext, ex, masked)
		return masked, true
	}
	return masked, false
}

// gateChatToolCalls applies TOOL-02: strip tool_calls the org policy denies
// before the client (or the cache) sees them. No deny policies → one cached
// bool, zero parsing inside the gate.
func (gw *gateway) gateChatToolCalls(ctx context.Context, r *http.Request, l *slog.Logger, orgID string, resp []byte) []byte {
	if gw.toolPolicies == nil {
		return resp
	}
	var deniedTools []string
	resp, deniedTools = gw.gateToolCallsJSON(ctx, orgID, agentSubject(r), resp)
	if len(deniedTools) > 0 {
		l.Warn("tool policy denied model tool_calls", "org", orgID, "tools", toolNamesFromDenied(deniedTools))
	}
	return resp
}

// buildEvalgateHook returns the P5.9 Evalgate sampling hook — for
// Medium/low-confidence requests, sample a fraction to run LLM-as-judge
// comparing cheap vs premium responses. Results feed into evalgate_results
// table and calibration refresher. Runs through the finishRequest
// pre-attestation hook: EvalgateSampled is stamped synchronously before
// lineage/publish (no race with publishEvent). Returns nil when evalgate is
// not configured for this request; finishRequest treats a nil hook as absent.
func (gw *gateway) buildEvalgateHook(ctx context.Context, cc *chatContext, finalModelName string, resp []byte) func(*eventpub.Event) {
	if gw.judge == nil || gw.evalStore == nil || cc.orgID == "" {
		return nil
	}
	return func(ev *eventpub.Event) {
		gw.maybeEvalgateSample(ctx, cc, finalModelName, resp, ev)
	}
}

// evalgateSample uses 53 random bits so every draw is exactly representable
// as a float64 in [0, 1).
func evalgateSample(rate float64) bool {
	if !(rate > 0) {
		return false
	}
	if rate >= 1 {
		return true
	}
	var bits [8]byte
	_, _ = rand.Read(bits[:])
	const fractionBits = 53
	draw := binary.BigEndian.Uint64(bits[:]) >> (64 - fractionBits)
	return float64(draw)/(1<<fractionBits) < rate
}

// maybeEvalgateSample applies the P5.9 sampling criteria — Medium class,
// low confidence, configured rate — and spawns the detached judge
// evaluation. EvalgateSampled is stamped synchronously here, before
// lineage/publish, to avoid a data race with publishEvent.
func (gw *gateway) maybeEvalgateSample(ctx context.Context, cc *chatContext, finalModelName string, resp []byte, ev *eventpub.Event) {
	orgID, l := cc.orgID, cc.l
	classLabel := cc.classifierClass
	conf := cc.classifierConfidence

	// Check if this request matches sampling criteria: Medium class, low confidence
	isMediumLowConf := classLabel == "medium" && conf < 0.7
	if isMediumLowConf && evalgateSample(gw.cfg.EvalgateSampleRate) {
		// TP-04: a judge pair needs the cheap answer as full comparable
		// text. Tool-only, empty or unparseable bodies must not produce a
		// fabricated verdict — skip judging and record why.
		cheapAnswer, ok := comparableResponseText(resp)
		if !ok {
			l.Debug("evalgate: cheap response unavailable (tool-only, empty or unparseable), judge skipped",
				"org_id", orgID, "request_id", cc.reqID)
			return
		}
		l.Debug("evalgate sampling triggered", "org_id", orgID, "class", classLabel, "confidence", conf)

		// Store original prompt for judge
		userPrompt := extractUserPrompt(cc.req.Messages)
		cheapModelName := finalModelName

		// Determine premium model from tier router
		var premiumModelName string
		if gw.tierRouter != nil {
			premiumSel, perr := gw.tierRouter.SelectModel(ctx, classifier.ClassHard, orgID)
			if perr == nil && premiumSel.Name != "" {
				premiumModelName = premiumSel.Name
			} else {
				premiumModelName = "gpt-4o" // fallback
			}
		} else {
			premiumModelName = "gpt-4o"
		}

		// Mark as sampled synchronously to avoid data race with publishEvent.
		ev.EvalgateSampled = true

		// RT-03: the optional premium comparison runs under the same
		// trusted identity as the main chain (captured once here).
		gateID := candidateIdentity{OrgID: cc.orgID, TeamID: cc.teamID, APIKeyID: cc.apiKeyID}

		// Run judge evaluation asynchronously (non-blocking).
		go gw.evalgateJudge(context.WithoutCancel(ctx), cc, gateID, userPrompt, cheapAnswer, cheapModelName, premiumModelName, conf)
	}
}

// evalgateJudge is the detached evalgate comparison: a real premium provider
// attempt under the request's trusted identity, judged against the served
// cheap response, with the verdict persisted for calibration.
func (gw *gateway) evalgateJudge(ctx context.Context, cc *chatContext, gateID candidateIdentity, prompt, cheapResp, cheapModelName, premiumModelName string, conf float64) {
	orgID, l := cc.orgID, cc.l
	judgeCtx, jcancel := context.WithTimeout(ctx, 15*time.Second)
	defer jcancel()

	// RT-03: the optional premium comparison is a real provider attempt —
	// gate it like every other candidate. A denied/unavailable premium
	// target makes no call and no verdict (nothing is fabricated from a
	// missing response — the TP-03/04 contract is preserved).
	premiumInfo, perr2 := gw.resolveModelInfo(judgeCtx, premiumModelName)
	if perr2 != nil {
		l.Debug("evalgate: premium model resolution failed", "error", perr2)
		return
	}
	premiumInfo, pol := gw.gateAttemptCandidate(judgeCtx, gateID, cc.req.Model, premiumInfo)
	if pol != nil {
		return
	}

	// Call premium model for comparison
	premiumID := newInvocationIdentity(orgID, cc.reqID, cc.sessionID, cc.apiKeyID, eventSessionID(ctx), premiumInfo.ModelName)
	premiumCtx := withInvocationIdentity(judgeCtx, premiumID)
	premiumResp, perr := gw.callUpstreamSingle(premiumCtx, premiumInfo, cc.body)
	if perr != nil {
		l.Debug("evalgate: premium response failed", "error", perr)
		return
	}

	premiumAnswer, ok := comparableResponseText(premiumResp)
	if !ok {
		l.Debug("evalgate: premium response has no comparable text", "request_id", cc.reqID)
		return
	}
	v, _, err := gw.judge.EvaluateMeasured(judgeCtx, prompt, cheapResp, premiumAnswer, func(ctx context.Context, model string) error {
		judgeID := newInvocationIdentity(orgID, cc.reqID, cc.sessionID, cc.apiKeyID, eventSessionID(ctx), model)
		return judgeID.beginPaidDispatch(ctx, gw.invocations, invocationKindJudge)
	})
	if err != nil {
		l.Debug("evalgate judge failed", "error", err)
		return
	}

	// Store verdict (including ShouldUpgrade flag for calibration).
	// N02-P06 T06: the judge prompt is the PRE-MASK original — its
	// persistence is retention-gated like every other original capture
	// (fail-closed OFF stores the verdict metadata without the prompt
	// text). The gate routes through the retention-policy seam (gw's one
	// in-process boundary decision: strict profile first, then the
	// installed policy / boolean default — FIX-07/OBS-02).
	storedPrompt := prompt
	if !gw.originalRetentionEnabled(judgeCtx, orgID) {
		storedPrompt = ""
	}
	err = gw.evalStore.InsertVerdict(judgeCtx, orgID, cc.reqID, storedPrompt, cheapModelName, premiumInfo.ModelName, v, conf)
	if err != nil {
		l.Debug("evalgate store failed", "error", err)
	}
}

// writeChatCacheAsync implements P4/RT-05: write to cache asynchronously
// (non-blocking) under the route identity of the model that ACTUALLY
// generated the response (the winning fallback candidate, not the routed
// primary) — an entry may only ever be served under the identity it was
// generated with. Skip caching for error responses, no-store headers, or
// disabled orgs. RT-07: no-store must also skip the WRITE — the lookup guard
// at serve time is not enough, or a response the client forbade storing
// still lands in the shared cache and is served to the next request without
// the header. A warm hit is re-governed by the CURRENT post-upstream policy
// at lookup, so a stale entry never bypasses enforcement.
func (gw *gateway) writeChatCacheAsync(ctx context.Context, cc *chatContext, finalInfo resolver.ModelInfo, finalModelName string, resp []byte, usage provider.Usage) {
	if gw.cache == nil || cc.orgID == "" || cc.cacheDisabled || !shouldCache(resp) {
		return
	}
	ri := cache.RouteIdentity{
		OrgID:     cc.orgID,
		Model:     finalModelName,
		GenParams: gw.effortForCandidate(finalInfo, classifier.Class(cc.classifierClass)),
		Upstream:  gw.cacheUpstreamFP(finalInfo), // H1: bind the entry to the endpoint that generated it
	}
	if usage.PromptTokens < 0 || usage.PromptTokens > math.MaxInt || usage.CompletionTokens < 0 || usage.CompletionTokens > math.MaxInt {
		cc.l.Debug("cache write skipped for invalid provider token counts", "request_id", cc.reqID)
		return
	}
	if err := gw.cache.Write(ctx, ri, cc.body, resp, int(usage.PromptTokens), int(usage.CompletionTokens)); err != nil {
		cc.l.Debug("chat cache write failed", "request_id", cc.reqID, "error", err)
	}
}

// writeChatJSONClient answers the JSON client after the terminal event has
// been persisted: the prompt-cache outcome header (hit|miss from the same
// usage fields that bill, CacheReadTokens; absent when no provider usage was
// parsed) and the governed body.
func writeChatJSONClient(w http.ResponseWriter, l *slog.Logger, usage provider.Usage, resp []byte, finalModelName string) {
	if outcome := promptCacheOutcome(usage); outcome != "" {
		w.Header().Set(PromptCacheHeader, outcome)
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(resp); err != nil {
		l.Error("write response failed", "error", err, "final_model", finalModelName)
	}
}

// finishPolicyDeniedJSON ends a chat JSON request whose post-upstream policy
// run denied: the spend that already left the org is accounted (the usage
// above was parsed from the real upstream body), the analytics event carries
// the decision record with a policy_denied termination, and the client gets
// the 400 content_policy_violation envelope instead of the upstream body. No
// cache write, tool gate or shadow mirror runs — the response the policies
// rejected must not outlive this call anywhere.
func (gw *gateway) finishPolicyDeniedJSON(ctx context.Context, cc *chatContext, finalInfo resolver.ModelInfo, usage provider.Usage, ext provider.ExtendedUsage, ex *chatExecution, maskedBody []byte) {
	w, l := cc.w, cc.l
	finalModelName := finalInfo.ModelName

	gw.accountUsage(ctx, w, usageRecord{
		orgID:         cc.orgID,
		taskID:        cc.taskID,
		sessionID:     cc.sessionID,
		affinityModel: finalModelName,
		usage:         usage,
		costUSD:       ext.EstimatedCostUSD,
		priceKnown:    ext.PriceKnown,
	})

	l.Warn("policy denied upstream response", "org_id", cc.orgID, "request_id", cc.reqID, "policy_event", cc.policyEvent)
	// N03-P06-T09: the denial bill below is the cache-discounted quote, so the
	// event must carry the same provider-reported cache columns the bill
	// consumed — a discounted EstimatedCostUSD with zero CacheReadTokens makes
	// the analytics ledger irreproducible from its own fields (the invariant
	// documented at completions_endpoint.go:295–299). Parity with the
	// completed path in finalizeChatJSON.
	if _, ferr := gw.finishRequest(ctx, requestFinish{
		base: eventBase{
			EventType:                  "request.failed",
			RequestID:                  cc.reqID,
			SessionID:                  cc.sessionID,
			Payload:                    string(cc.body),
			UpstreamPayload:            boundedSample(ex.sent, upstreamCaptureLimit),
			UpstreamResponse:           boundedSample(maskedBody, upstreamCaptureLimit),
			OrgID:                      cc.orgID,
			TeamID:                     cc.teamID,
			AgentID:                    cc.agentID,
			UserID:                     cc.userID,
			APIKeyID:                   cc.apiKeyID,
			SessionKeyID:               cc.r.Header.Get("X-Session-Key-Id"),
			TaskID:                     cc.taskID,
			ModelRequested:             cc.requestedModel,
			ModelUsed:                  finalModelName,
			UpstreamURL:                ex.finalURL,
			StatusCode:                 http.StatusBadRequest,
			DurationMs:                 ex.durationMs,
			TokensIn:                   usage.PromptTokens,
			TokensOut:                  usage.CompletionTokens,
			CacheReadTokens:            usage.CacheReadTokens,
			CacheCreationTokens:        usage.CacheCreationTokens,
			EstimatedCostUSD:           ext.EstimatedCostUSD,
			Endpoint:                   endpointFrom(ctx, "chat.completions"),
			UsageSource:                usageSourceOrNone(usage.Source),
			CostStatus:                 costStatus(false, usage.Source, ext.PriceKnown),
			Method:                     "POST",
			Error:                      "response blocked by organization policy",
			TierUsed:                   cc.tierUsed,
			ClassifierClass:            cc.classifierClass,
			ClassifierConfidence:       cc.classifierConfidence,
			ClassifierSource:           cc.classifierSource,
			RoutingDecision:            gw.decisionJSON(cc.dec.Source, cc.dec),
			AttemptCount:               ex.attempts,
			RetryCount:                 ex.totalRetries,
			UsedOrgKey:                 ex.usedOrgKey,
			OrgCredentialRef:           ex.orgCredRef,
			Policy:                     cc.policyEvent,
			InferenceRegion:            finalInfo.Region,
			ModelOriginCountry:         finalInfo.Provider,
			LogStorageRegion:           gw.cfg.Region,
			ProviderEntityJurisdiction: finalInfo.Provider,
			Labels:                     labelsFrom(ctx),
		},
		attestModel: finalModelName,
		info:        finalInfo,
		termination: budget.TerminationPolicyDenied,
	}, nil); ferr != nil {
		// Facts gate the client outcome for dispatched-then-denied
		// responses too: without the durable record the withheld
		// response cannot be reconciled — fail instead of answering 400.
		writeTerminalAccountingFailure(w)
		return
	}

	apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
		"response blocked by organization policy", policyDenyErrorCode)
}

// upstreamCaptureLimit bounds the in-flight capture copied into events;
// loggerd applies its own PH.1 storage truncation on top.
const upstreamCaptureLimit = 16 * 1024

// routingCounterfactualCost prices the request's usage at the model the
// client originally requested — the honest "no tier routing" baseline.
// ok=false when the baseline model is unknown; callers fall back to the
// actual cost instead of inventing one.
func (gw *gateway) routingCounterfactualCost(ctx context.Context, baselineModel string, usage provider.Usage) (float64, bool) {
	if baselineModel == "" {
		return 0, false
	}
	info, err := gw.resolveModelInfo(ctx, baselineModel)
	if err != nil || info.ModelName == "" {
		// Unresolvable baseline (registry outage / cancelled context) — the
		// counterfactual degrades to the actual cost instead of guessing.
		return 0, false
	}
	return provider.ComputeCost(usage, info.Provider, info.ModelName).EstimatedCostUSD, true
}

// effectiveCounterfactual returns the savings baseline for a request:
//   - tier-routed rows baseline at the requested model's price — the honest
//     "what routing changed" comparison (routed to a cheaper model saves;
//     routed to a pricier model reads as negative, which is true);
//   - everything else baselines at the actual cost (uncached parity: no
//     claimed savings without an optimization).
func (gw *gateway) effectiveCounterfactual(ctx context.Context, baselineModel, tierUsed, classifierClass string, usage provider.Usage, actual float64) float64 {
	if tierUsed == "" || classifierClass == "" {
		return actual
	}
	if cf, ok := gw.routingCounterfactualCost(ctx, baselineModel, usage); ok {
		return cf
	}
	return actual
}

// errEmptyCachedCompletion marks a document that decodes as JSON but is
// semantically empty: no completion choices to serve or replay.
var errEmptyCachedCompletion = errors.New("cache hit document has no choices")

// errTruncatedCachedCompletion marks the truncated-stream shape (H3,
// audit extra §R-1): a stream cut before its terminal event never emits
// the finish chunk, so its recorded document carries finish_reason null
// on every choice. Both replay seams (SSE replay and the non-stream read
// probe) refuse it as a miss; the write gate (shouldCache) refuses the
// same shape so such an entry is never stored in the first place.
var errTruncatedCachedCompletion = errors.New("cache hit document has no finish_reason (truncated stream refused)")

// cachedCompletionUsable decodes hit.Data under the shared FIX-10 cache
// contract (N03-P02-T09/T10): a cacheable/servable completion document is
// decodable JSON that carries at least one choice. The write gate
// (shouldCache) and the read probe both enforce this minimal shape, and the
// streaming replay already rejected empty choices — one contract, three
// consistent paths.
//
// H3: the contract also refuses the truncated-stream shape (choices without
// finish_reason) — see errTruncatedCachedCompletion.
func cachedCompletionUsable(data []byte) (cachedCompletion, error) {
	var doc cachedCompletion
	if err := json.Unmarshal(data, &doc); err != nil {
		return cachedCompletion{}, err
	}
	if len(doc.Choices) == 0 {
		return cachedCompletion{}, errEmptyCachedCompletion
	}
	for _, ch := range doc.Choices {
		if ch.FinishReason == nil {
			return cachedCompletion{}, errTruncatedCachedCompletion
		}
	}
	return doc, nil
}

// cachedUsageCounterfactual prices a cached completion document's original
// usage as if the request had gone upstream. Returns 0 when the document has
// no usable usage object — an unknown counterfactual must read as 0 savings,
// never as a negative or fabricated figure. Documents the read path treats
// as a miss (undecodable or semantically empty, FIX-10) are never priced.
func cachedUsageCounterfactual(data []byte, providerName, modelName string) float64 {
	doc, err := cachedCompletionUsable(data)
	if err != nil {
		return 0
	}
	if doc.Usage == nil || (doc.Usage.PromptTokens == 0 && doc.Usage.CompletionTokens == 0) {
		return 0
	}
	return provider.ComputeCost(provider.Usage{
		PromptTokens:     int64(doc.Usage.PromptTokens),
		CompletionTokens: int64(doc.Usage.CompletionTokens),
	}, providerName, modelName).EstimatedCostUSD
}

func boundedSample(b []byte, limit int) string {
	if len(b) > limit {
		return string(b[:limit]) + "\n…[truncated in flight]"
	}
	return string(b)
}

// emitUpstreamMetrics records Prometheus counters/histograms for one upstream
// attempt (P3.19). Callers invoke this after a successful or failed attempt
// so that per-provider/model/status metrics are always consistent.
func (gw *gateway) emitUpstreamMetrics(provider, model string, statusCode int, duration time.Duration, usage provider.Usage, costUSD float64) {
	statusLabel := strconv.Itoa(statusCode)
	if statusCode == 0 {
		statusLabel = "0" // transport error — no HTTP status
	}

	metrics.UpstreamRequestsTotal.WithLabelValues(provider, model, statusLabel).Inc()
	metrics.UpstreamDurationSeconds.WithLabelValues(provider, model).Observe(duration.Seconds())

	if usage.PromptTokens > 0 {
		metrics.UpstreamTokensTotal.WithLabelValues(provider, model, "prompt").Add(float64(usage.PromptTokens))
	}
	if usage.CompletionTokens > 0 {
		metrics.UpstreamTokensTotal.WithLabelValues(provider, model, "completion").Add(float64(usage.CompletionTokens))
	}
	if usage.CacheReadTokens > 0 {
		metrics.UpstreamTokensTotal.WithLabelValues(provider, model, "cache_read").Add(float64(usage.CacheReadTokens))
	}
	if usage.CacheCreationTokens > 0 {
		metrics.UpstreamTokensTotal.WithLabelValues(provider, model, "cache_creation").Add(float64(usage.CacheCreationTokens))
	}
	if costUSD > 0 {
		metrics.UpstreamCostUSD.WithLabelValues(provider, model).Add(costUSD)
	}
}

// extractUpstreamStatus returns the HTTP status code of a typed upstream
// client failure (*upstream.Error). Returns 0 when the error carries no
// upstream status (e.g. transport-level failure).
func extractUpstreamStatus(err error) int {
	if err == nil {
		return 0
	}
	var uerr *upstream.Error
	if errors.As(err, &uerr) {
		return uerr.Status
	}
	return 0
}

// upstreamFailureHeaders returns the failed attempt's captured response
// headers (e.g. Retry-After on a 429) cloned by the upstream client, so the
// decision layer can hand the hint to retry scheduling and the terminal
// render can surface it to the caller. Returns nil for refusals,
// request-not-sent errors and transport failures — they never produced a
// response to quote.
func upstreamFailureHeaders(err error) http.Header {
	if err == nil {
		return nil
	}
	var uerr *upstream.Error
	if errors.As(err, &uerr) {
		return uerr.Header
	}
	return nil
}

// clientRetryAfterCeiling bounds the client-facing Retry-After hint. The
// gateway's own admission limits never hint beyond 60s (tokenbudget, key
// rate limits); a provider hint must not exceed that on our clients either,
// so a hostile or misconfigured upstream cannot serialize callers for
// minutes.
const clientRetryAfterCeiling = 60

// clientRetryAfterSeconds converts the last upstream attempt's Retry-After
// hint into whole seconds for the client-facing response header.
//
// A hint is surfaced ONLY where a provider legitimately rate-limited this
// request (the last upstream status is 429) and that attempt's response
// carried a parseable positive hint (seconds or future HTTP-date). The hint
// rounds up to whole seconds so the client never retries before the provider
// window, and it is bounded by clientRetryAfterCeiling. 0 means "unknown":
// callers then OMIT the header — a hint is never fabricated.
func clientRetryAfterSeconds(lastCode int, lastErr error) int {
	if lastCode != http.StatusTooManyRequests || lastErr == nil {
		return 0
	}
	d := retry.After(upstreamFailureHeaders(lastErr))
	if d <= 0 {
		return 0
	}
	secs := int(math.Ceil(d.Seconds()))
	if secs > clientRetryAfterCeiling {
		secs = clientRetryAfterCeiling
	}
	return secs
}

// whitelistModel is the registry name a key is allowed to call. An alias is
// checked as its target; a direct name is checked as the client sent it.
func whitelistModel(info resolver.ModelInfo, requested string) string {
	if info.Alias != "" {
		return info.ModelName
	}
	return requested
}

// comparableResponseText reports whether a non-stream completion body
// carries a full comparable text answer for the evalgate judge. Tool-only
// responses (content null/empty with tool_calls), empty or unparseable
// bodies must not be judged: they would fabricate a calibration pair
// (TP-04).
func comparableResponseText(body []byte) (string, bool) {
	var doc struct {
		Choices []struct {
			Message struct {
				Content *string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || len(doc.Choices) == 0 {
		return "", false
	}
	content := doc.Choices[0].Message.Content
	if content == nil || strings.TrimSpace(*content) == "" {
		return "", false
	}
	return *content, true
}
