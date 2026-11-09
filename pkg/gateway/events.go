package cli

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
)

var eventPublishSem = make(chan struct{}, 50)

// eventObserver, when set, sees every analytics event before publish.
// Production leaves it nil. Tests must restore it through observeEvent.
var (
	eventObserverMu sync.Mutex
	eventObserver   func(*eventpub.Event)
)

func observeEvent(fn func(*eventpub.Event)) func() {
	eventObserverMu.Lock()
	prev := eventObserver
	eventObserver = fn
	eventObserverMu.Unlock()
	return func() {
		eventObserverMu.Lock()
		eventObserver = prev
		eventObserverMu.Unlock()
	}
}

// publishEvent fires an event on a background context with its own per-attempt
// timeout. It deliberately detaches from the caller context: an audit/telemetry
// publish must outlive the request (and must not fail just because the client
// connection closed mid-publish), so the retry loop runs against
// context.Background() with a bounded 2s per-attempt timeout.
//
// Callers that hold a request context pass it for the contextcheck analyzer
// (see the //nolint:contextcheck comments at the call sites); the function does
// not use the caller context for the actual publish.
// the single funnel every gateway event passes through. Legacy mode (the
// default, and any local+wire resolution that stays permissive) returns the
// returns a sanitized shallow COPY: the content captures are stripped, the
// error text is replaced by the fixed redaction notice, and the prompt
// digest is stamped from the raw body before it is dropped. The caller's
// event (finishRequest's return value, in-process hooks) is never mutated:
// the policy governs only what the observer and the wire stream see.
func sanitizeEventForContentProfile(event *eventpub.Event) *eventpub.Event {
	if event == nil {
		return nil
	}
	local := config.LogContentProfileFromEnv()
	if config.EffectiveLogContentProfile(local, event.ContentProfile, event.ContentProfile != "") !=
		config.LogContentProfileMetadataOnly {
		return event
	}
	sanitized := *event
	sanitized.ContentProfile = string(config.LogContentProfileMetadataOnly)
	sanitized.PromptHash = eventpub.ResolvePromptHash(event.PromptHash, event.Payload)
	sanitized.Payload = ""
	sanitized.UpstreamPayload = ""
	sanitized.UpstreamResponse = ""
	sanitized.ProcessedResponse = ""
	if sanitized.Error != "" {
		sanitized.Error = eventpub.ContentProfileRedactedError
	}
	return &sanitized
}

// mediaHygienicEvent applies the I62 media-history rule (StripInlineMedia)
// to one event's in-flight captures without mutating the caller's event:
// it returns the same pointer when no capture carries inline media, and a
// sanitized shallow copy otherwise. The funnel-level complement of the
// build-time strip — it also covers producers that stamp raw captures onto
// built events after construction (the tool-execution audit trail).
func mediaHygienicEvent(event *eventpub.Event) *eventpub.Event {
	if event == nil {
		return nil
	}
	payload := eventpub.StripInlineMedia(event.Payload)
	upPayload := eventpub.StripInlineMedia(event.UpstreamPayload)
	upResponse := eventpub.StripInlineMedia(event.UpstreamResponse)
	processed := eventpub.StripInlineMedia(event.ProcessedResponse)
	if payload == event.Payload && upPayload == event.UpstreamPayload && upResponse == event.UpstreamResponse && processed == event.ProcessedResponse {
		return event
	}
	sanitized := *event
	sanitized.Payload = payload
	sanitized.UpstreamPayload = upPayload
	sanitized.UpstreamResponse = upResponse
	sanitized.ProcessedResponse = processed
	return &sanitized
}

func publishEvent(p *eventpub.RedisPublisher, l *slog.Logger, event *eventpub.Event) {
	eventObserverMu.Lock()
	obs := eventObserver
	eventObserverMu.Unlock()
	event = mediaHygienicEvent(event)
	event = sanitizeEventForContentProfile(event)
	if obs != nil && event != nil {
		obs(event)
	}
	if p == nil || event == nil {
		return
	}
	select {
	case eventPublishSem <- struct{}{}:
		go func() {
			defer func() { <-eventPublishSem }()

			const (
				maxRetries = 3
				baseDelay  = 50 * time.Millisecond
				maxDelay   = 300 * time.Millisecond
			)
			var err error
			for attempt := 0; attempt <= maxRetries; attempt++ {
				if attempt > 0 {
					delay := baseDelay << uint(attempt-1) // safe: attempt is bounded by maxRetries (3)
					if delay > maxDelay {
						delay = maxDelay
					}
					time.Sleep(delay)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				err = p.Publish(ctx, event)
				cancel()
				if err == nil {
					traceStampObservePublished(event.RequestID)
					return
				}
				l.Debug("event publish attempt failed",
					slog.Int("attempt", attempt+1),
					slog.String("event_type", event.EventType),
					slog.String("error", err.Error()),
				)
			}
			l.Warn("event publish permanently failed after retries",
				slog.String("event_type", event.EventType),
				slog.String("error", err.Error()),
			)
			// A producer-side drop is the start of a history gap (N12-P02,
			// I40): make it visible beyond the log line — queue/Redis
			// outages must be observable on /metrics.
			metrics.SilentFailure("event_publish", "publish_failed")
			// G4: the same fact must cite the request-row stamp — the
			// sibling cohort is not provably complete (owner arm 1).
			traceStampObserveDrop(event.RequestID, traceStampDropPublishFailed)
		}()
	default:
		l.Debug("event publish skipped, backlog full")
		metrics.SilentFailure("event_publish", "backlog_full")
		// G4: sibling drop on the request-row stamp (owner arm 1).
		traceStampObserveDrop(event.RequestID, traceStampDropBacklogFull)
	}
}

// eventBase is the single builder input for the gateway's analytics events
// native messages/responses, the admission denials and the MCP/A2A audit
// surfaces — describes its request here exactly once, and build() performs
// the only eventpub.Event field mapping in the gateway. (pkg/shadow's mirror
// event keeps its own builder: it is a shadow-discriminated row, not a
// request row.)
//
// Zero values stay zero: the wire event omits empty optional fields, so an
// unset capture, tier or counterfactual must not be defaulted here.
type eventBase struct {
	EventType string

	// Trusted identity. Chat JSON reads the headers through the admission
	// core; SSE reads the API/session key from the principal; the native
	// pipelines carry admitted fields; audit events carry agent/task only.
	RequestID    string
	SessionID    string
	OrgID        string
	TeamID       string
	AgentID      string
	UserID       string
	APIKeyID     string
	SessionKeyID string
	TaskID       string

	// Model + transport outcome.
	ModelRequested string
	ModelUsed      string
	UpstreamURL    string
	StatusCode     int64
	DurationMs     int64
	Method         string
	Endpoint       string
	Error          string

	// Usage + money. EstimatedCostUSD is ComputeCost's quote;
	// CostStatus/UsageSource keep $0-unknown distinct from $0-free.
	TokensIn              int64
	TokensOut             int64
	CacheReadTokens       int64
	CacheCreationTokens   int64
	EstimatedCostUSD      float64
	ResaleCostUSD         float64
	CounterfactualCostUSD float64
	UsageSource           string
	CostStatus            string

	// In-flight captures (bounded by upstreamCaptureLimit). Media hygiene
	// (I62, StripInlineMedia): inline base64/data-URL spans and carrier
	// values are stripped at build — built events carry media metadata and
	// references only, under every content profile.
	Payload          string
	UpstreamPayload  string
	UpstreamResponse string
	// ProcessedResponse is the FIX-20 processed client-facing response
	// envelope (pkg/gateway/response_history.go): what the client actually
	// received, post tool gate and policy. Same media-hygiene and
	// metadata-only rules as the raw captures; PROCESSED retention class.
	ProcessedResponse string

	// Routing observability (P5/v18 R1).
	TierUsed             string
	ClassifierClass      string
	ClassifierConfidence float64
	ClassifierSource     string
	RoutingDecision      string
	AttemptCount         int
	RetryCount           int
	FirstTokenMs         int64

	// W-BYOK-CORE: the winning upstream hop authenticated with an org
	// credential (BYOK) instead of a per-model or global key. Attribution
	// only — no secret material ever rides the event.
	UsedOrgKey bool

	// ("<first-8-of-id>:<last4>", see orgCredentialUse.ref). Empty when the
	// hop used a per-model/global key or the legacy BYOK path.
	OrgCredentialRef string

	// OP-8: the policy-pipeline decision record (Event.Policy contract —
	// JSON array of decision objects; the OP-9 decisions table parses it).
	// Stamped by the pipelines through policyEventFrom / chatContext.
	Policy string

	// Cache provenance (P4.13): which cache layer served, and the hit's
	// provenance model in ModelUsed.
	CacheHitType    string
	CacheSimilarity float32

	// Shadow discriminator (v9): "shadow" only on mirror events.
	ABGroup string

	// PB1: Jurisdictional lineage fields as the pipeline knows them pre-
	// attestation (the winning candidate's region/provider). attachLineage
	// overwrites them with post-fallback evidence when wired.
	InferenceRegion            string
	ModelOriginCountry         string
	LogStorageRegion           string
	ProviderEntityJurisdiction string

	// Labels is the effective attribution set; nil on the audit surfaces.
	Labels map[string]string
}

// build maps the request observables onto the wire event. Source is always
// the gateway; Labels pass through nil-able.
func (b eventBase) build() *eventpub.Event {
	return &eventpub.Event{
		EventType:                  b.EventType,
		Source:                     "gateway",
		RequestID:                  b.RequestID,
		SessionID:                  b.SessionID,
		Payload:                    eventpub.StripInlineMedia(b.Payload),
		OrgID:                      b.OrgID,
		TeamID:                     b.TeamID,
		ModelRequested:             b.ModelRequested,
		ModelUsed:                  b.ModelUsed,
		UpstreamURL:                b.UpstreamURL,
		StatusCode:                 b.StatusCode,
		DurationMs:                 b.DurationMs,
		TokensIn:                   b.TokensIn,
		TokensOut:                  b.TokensOut,
		CacheReadTokens:            b.CacheReadTokens,
		CacheCreationTokens:        b.CacheCreationTokens,
		EstimatedCostUSD:           b.EstimatedCostUSD,
		ResaleCostUSD:              b.ResaleCostUSD,
		Method:                     b.Method,
		Error:                      b.Error,
		CacheHitType:               b.CacheHitType,
		CacheSimilarity:            b.CacheSimilarity,
		CounterfactualCostUSD:      b.CounterfactualCostUSD,
		TierUsed:                   b.TierUsed,
		ClassifierClass:            b.ClassifierClass,
		ClassifierConfidence:       b.ClassifierConfidence,
		ClassifierSource:           b.ClassifierSource,
		RoutingDecision:            b.RoutingDecision,
		UpstreamPayload:            eventpub.StripInlineMedia(b.UpstreamPayload),
		UpstreamResponse:           eventpub.StripInlineMedia(b.UpstreamResponse),
		ProcessedResponse:          eventpub.StripInlineMedia(b.ProcessedResponse),
		AgentID:                    b.AgentID,
		UserID:                     b.UserID,
		APIKeyID:                   b.APIKeyID,
		SessionKeyID:               b.SessionKeyID,
		TaskID:                     b.TaskID,
		Labels:                     b.Labels,
		ABGroup:                    b.ABGroup,
		Endpoint:                   b.Endpoint,
		UsageSource:                b.UsageSource,
		CostStatus:                 b.CostStatus,
		FirstTokenMs:               b.FirstTokenMs,
		AttemptCount:               b.AttemptCount,
		RetryCount:                 b.RetryCount,
		UsedOrgKey:                 b.UsedOrgKey,
		OrgCredentialRef:           b.OrgCredentialRef,
		Policy:                     b.Policy,
		InferenceRegion:            b.InferenceRegion,
		ModelOriginCountry:         b.ModelOriginCountry,
		LogStorageRegion:           b.LogStorageRegion,
		ProviderEntityJurisdiction: b.ProviderEntityJurisdiction,
	}
}

// usageRecord is the shared input of accountUsage: one request's final usage
// and the identity it is recorded against.
type usageRecord struct {
	orgID     string
	taskID    string
	sessionID string
	// affinityModel records the session's warm model ("" = skip affinity).
	affinityModel string
	usage         provider.Usage
	// costUSD/priceKnown feed recordSessionSpend; the drain-error path
	// reports (0, false) — no settled price for a partial stream.
	costUSD    float64
	priceKnown bool
}

// accountUsage records one request's final usage in the shared order:
// task/session token budgets → token-window reconcile → session spend →
// session affinity. Every spend-recording pipeline funnels through here.
func (gw *gateway) accountUsage(ctx context.Context, w http.ResponseWriter, rec usageRecord) {
	tokens := rec.usage.PromptTokens + rec.usage.CompletionTokens
	gw.recordTokenBudgetSpend(rec.orgID, rec.taskID, rec.sessionID, tokens)
	// /: correct the token-window reservations to the actual
	// usage (total + prompt/completion split for ITPM/OTPM).
	reconcileRateLimitUsage(ctx, rec.usage.PromptTokens, rec.usage.CompletionTokens)
	gw.recordSessionSpend(ctx, w, tokens, rec.costUSD, rec.priceKnown)
	// KV-cache-aware routing (v15 K2): record the session's warm model from
	// the final usage.
	if rec.affinityModel != "" && gw.sessionAffinity != nil && rec.orgID != "" && rec.sessionID != "" {
		gw.sessionAffinity.Record(ctx, rec.orgID, rec.sessionID, rec.affinityModel, rec.usage.CacheReadTokens)
	}
}

// resaleCostUSD is the markup price of the winning usage for reseller
// billing; zero when no pricer is wired or the org is unknown.
func (gw *gateway) resaleCostUSD(ctx context.Context, orgID, providerName, modelName string, usage provider.Usage) float64 {
	if gw.markupPricer == nil || orgID == "" {
		return 0
	}
	resale, _ := gw.markupPricer.ComputeResaleAmount(
		ctx, orgID, providerName, modelName,
		usage.PromptTokens, usage.CompletionTokens,
		usage.CacheCreationTokens, usage.CacheReadTokens,
	)
	return resale
}

// retentionWiring caches the process-local retention store adapter. The
// gateway facets do not carry *adminstore.Store, so the adapter is built
// over the shared DB pool — the same construction the loggerd retention
// wiring uses (a retention-only adminstore view, nil encryptor: the toggle
// read never touches secret columns). Keyed by pool identity so a pool
// replacement (tests, hot swap) rebuilds instead of leaking the old pool.
var (
	retentionWiringMu   sync.Mutex
	retentionWiringPool *pgxpool.Pool
	retentionWiring     eventpub.OriginalRetentionStore
)

// attachRetentionGate lazily wires the org original-retention store into the
// shared event publisher (N02-P06 T03/T06 PRODUCER boundary). From the first
// request completion onward, RedisPublisher.Publish strips the upstream
// captures pre-XADD for every org whose effective retention is OFF (the
// fail-closed default: an unwired store, an empty org or a lookup error all
// resolve OFF, so originals can never slip into the durable buffer). No-op
// when the publisher or the DB pool is absent (minimal test gateways) — the
// publisher-side nil resolver already fails closed. Idempotent: the
// publisher keeps the first wiring (re-wiring would drop its warm cache).
func (gw *gateway) attachRetentionGate() {
	if gw.publisher == nil || gw.dbPool == nil {
		return
	}
	retentionWiringMu.Lock()
	if retentionWiring == nil || retentionWiringPool != gw.dbPool {
		retentionWiring = eventpub.AdminOriginalRetentionStore{
			Store: adminstore.New(gw.dbPool, gw.log.With("component", "adminstore-retention"), nil),
		}
		retentionWiringPool = gw.dbPool
	}
	store := retentionWiring
	retentionWiringMu.Unlock()
	gw.publisher.SetOriginalRetentionStore(store)
}

// originalRetentionEnabled resolves the org original-retention decision for
// in-process producers that must apply the SAME resolution outside the wire
// path (the evalgate judge-prompt persistence — the pre-mask original,
// N02-P06 T06). The boundary order is the retention seam's own contract
// (pkg/eventpublisher/retention_policy.go): the strict (metadata-only)
// content profile drops original captures BEFORE any retention decision —
// under strict this call consults nothing and answers OFF, mirroring the
// producer pre-XADD strip where an installed policy is never even consulted
// — and the decision itself routes through the shared T04 seam
// (ResolveOriginalRetention): an installed policy is authoritative, the
// FREE-core boolean default answers otherwise — the same rule as the
// producer and the loggerd durable-history writer, so the in-process sink
// cannot drift from the wire (FIX-07 / OBS-02). The typed request rides the
// associated request.completed event's attributes; EventTS stays zero — the
// producer stamp is applied later, at publish. Fail-closed: an empty org, a
// nil or unwired resolver, a lookup error all resolve OFF. The default path
// (no installed policy) is byte-identical to the pre-seam boolean lookup:
// RetentionPolicy() is nil-safe and wraps the SAME resolver instance, so the
// cache, the TTL and the fail-closed matrix are unchanged.
func (gw *gateway) originalRetentionEnabled(ctx context.Context, orgID string) bool {
	if config.LogContentProfileFromEnv() == config.LogContentProfileMetadataOnly {
		return false
	}
	req := eventpub.RetentionPolicyRequest{OrgID: orgID, EventType: "request.completed"}
	return eventpub.ResolveOriginalRetention(ctx, gw.publisher.RetentionPolicy(), gw.publisher.OriginalRetention(), req)
}

// requestFinish is one request end handed to finishRequest: the event
// fields, the winning candidate (for lineage) and how the reservation
// settles.
type requestFinish struct {
	base eventBase
	// attestModel names the candidate recorded in the lineage attestation.
	// It defaults to base.ModelUsed; the chat failure event keeps ModelUsed
	// empty but still attests the winning candidate.
	attestModel string
	// info is the WINNING model info (post-fallback) — jurisdictional fields
	// reflect the candidate that actually served (PB1/F8.2).
	info resolver.ModelInfo
	// resp is the upstream response when one exists (region evidence).
	resp *http.Response
	// termination settles the reservation (§5.3 Finalize, NEXT-18c).
	termination budget.Termination
	// noSettle marks request ends that never reserved (cache hits): the
	// event publishes without a reservation settle.
	noSettle bool
	// eventNote keeps the historical hook order of the native/completions/
	// embeddings finishers, which observe the event via gw.eventNote before
	// publish. Chat and stream never call the hook.
	eventNote bool
}

// analytics event, runs the optional pre-attestation hook (chat's evalgate
// sampling), attaches the lineage attestation, settles the reservation,
// fires the eventNote hook where the pipeline historically does, and
// publishes. It returns the built event.
func (gw *gateway) finishRequest(ctx context.Context, fin requestFinish, beforeAttest func(*eventpub.Event)) *eventpub.Event {
	l := logctx.From(ctx, gw.log)
	// N02-P06 producer boundary: the retention gate must be wired before the
	// first publish so the pre-XADD strip is active for every capture-bearing
	// event (all of them funnel through here).
	gw.attachRetentionGate()
	ev := fin.base.build()
	// G4 (owner decision 2026-11-04): stamp the per-request trace-
	// completeness envelope before any hook can enrich or rewrite the
	// event, so every downstream consumer of this event — attest, lineage,
	// reservation finalize, eventNote — observes the stamped form.
	traceStampEvent(ev)
	if beforeAttest != nil {
		beforeAttest(ev)
	}
	attestModel := fin.base.ModelUsed
	if fin.attestModel != "" {
		attestModel = fin.attestModel
	}
	// PB1: jurisdictional lineage attestation (no-op unless wired + org).
	gw.attachLineage(ctx, fin.base.OrgID, fin.base.RequestID, attestModel, fin.info, fin.resp, ev, l)
	// NEXT-18c: settle the reservation with the actual spend and stamp the
	// tuples + termination on the event (§5.3 Finalize).
	if !fin.noSettle {
		reservationGateFrom(ctx).finalize(ev, fin.base.ResaleCostUSD, fin.base.EstimatedCostUSD, fin.termination)
	}
	if fin.eventNote && gw.eventNote != nil {
		gw.eventNote(ev)
	}
	publishEvent(gw.publisher, l, ev) //nolint:contextcheck // publishEvent creates its own timeout context internally — standard pattern in gateway
	return ev
}
