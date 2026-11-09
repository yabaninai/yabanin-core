package consumer

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/money"
)

// This file is the event/storage mapper (AF-17): the single place that turns
// one Redis stream field map into typed, validated values and renders the
// request_logs INSERT projection. The consumer handlers (stream.go) only
// orchestrate delivery; every field read, unit and nullable decision lives
// here so the four event shapes stay byte-compatible with the pre-refactor
// column/argument contracts pinned by the package tests.

// eventFields is the typed accessor layer over a Redis stream field map.
// go-redis v9 returns every stream field as a string; the accessors accept
// the published string values plus the numeric shapes the fixtures use.
// A missing key, a wrong type or an unparseable value takes the same
// fallback the pre-refactor parse helpers took (documented per accessor).
type eventFields struct {
	m map[string]interface{}
}

func fieldsOf(m map[string]interface{}) eventFields {
	return eventFields{m: m}
}

// String reads a string field; non-string values (or missing keys) become
// "" — wrong types take the same path as absent values.
func (f eventFields) String(key string) string {
	return eventString(f.m, key)
}

// StringDefault reads a string field with a fallback for absent/empty values.
func (f eventFields) StringDefault(key, fallback string) string {
	return fieldStringDefault(f.m, key, fallback)
}

// Float64 reads a unit-bearing decimal field; missing/unparseable → 0.
func (f eventFields) Float64(key string) float64 {
	return parseFloat64(f.m, key)
}

// Int64 reads a unit-bearing integer field; missing/unparseable → 0.
func (f eventFields) Int64(key string) int64 {
	return parseInt64(f.m, key)
}

// Bool reads a boolean field; missing/unparseable → false.
func (f eventFields) Bool(key string) bool {
	return parseBool(f.m, key)
}

// NullableString maps an absent, empty or non-string value to SQL NULL.
func (f eventFields) NullableString(key string) any {
	return nullableString(f.m, key)
}

// NullableInt64 maps an absent or zero observability measurement to SQL NULL
// ("unknown", never a fake zero in AVG/percentile aggregates).
func (f eventFields) NullableInt64(key string) any {
	return nullableInt64(f.m, key)
}

// QuoteRaw validates a money field at the event boundary (AF-05) and also
// returns the raw USD value exactly as parsed — the reconcile seam needs it
// to tell a collapsed sub-µUSD positive apart from a genuine zero. Missing,
// unparseable, non-finite, negative or out-of-range values are QuoteUnknown;
// a valid zero is QuoteZero; chargeable values are QuotePositive.
func (f eventFields) QuoteRaw(key string) (money.MicroUSD, money.QuoteState, float64) {
	return eventQuoteRaw(f.m, key)
}

// Raw returns the underlying field map for consumers that need the verbatim
// values (tool-call extraction reads the pre-truncation sample).
func (f eventFields) Raw() map[string]interface{} {
	return f.m
}

// requestAccounting groups the RM-10 accounting columns. Absent fields keep
// the defaults that old events already in the stream must insert without
// failing.
type requestAccounting struct {
	endpoint    string
	usageSource string
	costStatus  string
	cacheRead   any
	cacheCreate any
}

func parseRequestAccounting(fields map[string]interface{}) requestAccounting {
	return requestAccounting{
		endpoint:    fieldStringDefault(fields, "endpoint", "chat.completions"),
		usageSource: fieldStringDefault(fields, "usage_source", "provider"),
		costStatus:  fieldStringDefault(fields, "cost_status", "legacy"),
		cacheRead:   nullableInt64(fields, "cache_read_tokens"),
		cacheCreate: nullableInt64(fields, "cache_creation_tokens"),
	}
}

// g2Fields holds the G2 request_logs tagging columns parsed from an event
// payload: task_id, agent_id (nullable), and routing_decision (validated as
// JSON before storage). Shared by all three request_logs inserts so they stay
// identical.
type g2Fields struct {
	taskIDStr       interface{} // string or nil
	agentIDStr      interface{} // string or nil
	userIDStr       interface{} // string or nil (developer user, RM-44)
	routingDecision interface{} // string or nil (nil unless a valid JSON document)
}

// parseG2Fields extracts the G2 tagging fields from an event payload.
//
//   - task_id: stored verbatim when present and non-empty, else NULL.
//   - agent_id: mapped through uuidField — a valid UUID passes through, any
//     other string becomes a deterministic v5 UUID (agent principals are
//     "yag_" UUIDs; a junk agent_id must not wedge the insert, but it should
//     still group consistently).
//   - routing_decision: the consumer already receives a JSON-serialized
//     decision object (the gateway marshals it). We re-validate it with
//     json.Valid before persisting; an empty value becomes NULL, and a
//     non-empty but malformed value is stored as NULL so a bad producer can
//     never wedge the JSONB column (fail-open to NULL, never a crash).
func parseG2Fields(fields map[string]interface{}) g2Fields {
	var g g2Fields
	if t, ok := fields["task_id"].(string); ok && t != "" {
		g.taskIDStr = t
	}
	g.agentIDStr = uuidField(eventString(fields, "agent_id"))
	g.userIDStr = uuidField(eventString(fields, "user_id"))
	if rd, ok := fields["routing_decision"].(string); ok && rd != "" {
		if json.Valid([]byte(rd)) {
			g.routingDecision = rd
		}
	}
	return g
}

var labelDecodeErrors atomic.Uint64

// reservationDecodeErrors counts reservation-tuple payloads that failed to
// decode (ADR-0001 §5.3 Finalize). A malformed payload must never wedge the
// delivery: the event is stored, it simply carries no reserve linkage (the
// allowance settle falls back to the reconcile path).
var reservationDecodeErrors atomic.Uint64

// terminationKind is how a reserved request ended (ADR-0001 §5.3 Finalize).
// The consumer bills partial usage for the interrupt kinds exactly as for
// upstream errors — termination only refines observability, the usage and
// quote gates decide money.
type terminationKind string

// The termination set of the Finalize contract (§5.3).
const (
	TerminationCompleted    terminationKind = "completed"
	TerminationClientCancel terminationKind = "client_cancel"
	TerminationIdleTimeout  terminationKind = "idle_timeout"
	TerminationUpstreamErr  terminationKind = "upstream_error"
	TerminationPolicyDenied terminationKind = "policy_denied"
)

// validTermination reports whether s is a member of the Finalize set.
func validTermination(s string) bool {
	switch terminationKind(s) {
	case TerminationCompleted, TerminationClientCancel, TerminationIdleTimeout, TerminationUpstreamErr, TerminationPolicyDenied:
		return true
	default:
		return false
	}
}

// reservationTuple is one per-scope reserve tuple the gateway Finalize
// attaches to a request event (§5.3): the area that was reserved, the
// allocation carrying the reserve, and the request's cost bound for that
// area. It is the settlement worker's input for the reserve decrement
// (reserved -= min(actual, bound)).
type reservationTuple struct {
	ScopeKind     string
	ScopeKey      string
	Period        string
	AllowanceID   int64
	BoundMicroUSD int64
}

// parseReservationTuples decodes the event's `reservations` JSON array.
// Tolerant by contract: a missing field is the legacy (off-mode) event, an
// undecodable or wrong-typed payload counts the decode error and yields nil
// — a bad producer must never break the delivery, only lose the reserve
// linkage (the reconcile path still releases those reserves). Entries with
// an unknown scope kind, an empty scope key or a non-positive allowance id
// are dropped individually.
func parseReservationTuples(fields map[string]interface{}) []reservationTuple {
	raw, ok := fields["reservations"]
	if !ok || raw == nil {
		return nil
	}
	text, ok := raw.(string)
	if !ok || text == "" {
		return nil
	}
	var decoded []struct {
		ScopeKind     string `json:"scope_kind"`
		ScopeKey      string `json:"scope_key"`
		Period        string `json:"period"`
		AllowanceID   int64  `json:"allowance_id"`
		BoundMicroUSD int64  `json:"bound_micro_usd"`
	}
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		reservationDecodeErrors.Add(1)
		metrics.SilentFailure("audit_ingest_decode", "reservations")
		return nil
	}
	out := make([]reservationTuple, 0, len(decoded))
	for _, d := range decoded {
		switch d.ScopeKind {
		case "wallet", "team_month", "agent_day", "session":
		default:
			continue
		}
		if d.ScopeKey == "" || d.AllowanceID <= 0 || d.BoundMicroUSD < 0 {
			continue
		}
		out = append(out, reservationTuple{
			ScopeKind:     d.ScopeKind,
			ScopeKey:      d.ScopeKey,
			Period:        d.Period,
			AllowanceID:   d.AllowanceID,
			BoundMicroUSD: d.BoundMicroUSD,
		})
	}
	return out
}

// requestEvent is the typed projection of one request.* stream event (AF-17).
// Every field is read and validated exactly once, at the event boundary;
// nullable columns are typed as any carrying nil, unit-bearing fields keep
// their declared unit in the name. The raw map stays reachable for the two
// consumers that need verbatim values (tool-call extraction) and for the
// attribution columns whose strict-UUID warning is logged by the consumer.
type requestEvent struct {
	raw map[string]interface{}

	// Identity.
	orgID          string
	orgIDValue     any // nil when org_id is absent/empty
	modelRequested string
	modelUsed      string
	upstreamURL    string
	requestID      string
	requestIDValue any    // nil when request_id is absent/empty
	method         string // defaulted to POST
	sessionID      string // raw client session id; resolved against the registry per delivery
	errorMsg       string // verbatim error field ("" when absent/non-string)

	// createdAt is the event's business time (W-LOGG): the producer's ts
	// field (Unix milliseconds) when present and parseable, else the parse
	// moment. It lands in request_logs.created_at and the team_month period
	// bucket, so delayed delivery (outage backlog, DLQ replay) attributes the
	// event to the period the REQUEST happened in, not the delivery one.
	createdAt time.Time

	// Timing/tokens (units in the names).
	statusCode int64 // raw; each shape applies its own default policy
	durationMs int64
	tokensIn   int64
	tokensOut  int64

	// Cache/classifier analytics. The nullable categoricals are nil for
	// ordinary requests — binding "" made every row look like a classified
	// cache hit in the savings sub-queries.
	cacheHitType          any
	cacheSimilarity       float64
	counterfactualCostUSD float64
	costInUSD             float64
	tierUsed              any
	classifierClass       any
	classifierConfidence  float64
	classifierSource      any
	abGroup               string
	evalgateSampled       bool

	teamIDValue any // uuid string or nil (deterministic v5 mapping)

	// Privacy-shaped samples (PH.1). promptHash binds the SQL value: legacy
	// always a SHA-256 hex digest string; metadata-only a digest string or
	// nil (SQL NULL) — the strict mapper trusts only the boundary-verified
	// digest.
	promptHash       any
	responseJSON     any
	upstreamReqJSON  any
	upstreamRespJSON any
	upstreamResponse string // verbatim upstream sample for tool-call extraction

	g2     g2Fields
	acct   requestAccounting
	labels []byte

	// Money (AF-05): validated quotes for billing plus the raw floats the
	// analytics columns and intent diagnostics carry.
	resaleCostUSD    float64
	resaleQuote      money.MicroUSD
	resaleQuoteState money.QuoteState
	costQuote        money.MicroUSD
	costQuoteState   money.QuoteState

	// Reservations (NEXT-18d, ADR-0001 §5.3): the per-scope reserve tuples
	// the gateway Finalize attached, and how the request ended. Empty
	// tuples = legacy event (off mode); the intent paths treat them as the
	// authoritative per-scope charge plan when present.
	termination  terminationKind
	reservations []reservationTuple
}

// parseRequestEvent reads every field the request.* handlers consume in one
// pass under the legacy (full content) profile. It is pure (no DB, no
// logging); shape-specific default policies (status fallbacks, forced
// shadow values, the budget error text) stay with the handlers.
func parseRequestEvent(raw map[string]interface{}) requestEvent {
	return parseRequestEventPolicy(raw, legacyDeliveryPolicy())
}

// parseRequestEventPolicy maps one request.* event under its delivery
// policy. Three storage modes:
//
//   - metadata-only profile: the message boundary already stripped the
//     content captures; the mapper never consults the debug switch or a raw
//     payload — it binds SQL NULL for every content column and trusts only
//     the boundary-verified prompt_hash digest. YABANIN_DEBUG_LOG_RESPONSE
//     cannot resurrect content the profile dropped.
//   - legacy profile with original retention OFF (N02-P06 T03 default): the
//     PROCESSED representation persists — the `response` snapshot of the
//     (guarded/masked) payload and the prompt digest — while the
//     full-fidelity ORIGINAL captures bind SQL NULL: upstream_request,
//     upstream_response, and (via the emptied verbatim sample) the
//     tool-call extraction. A stray capture that survived the buffer is
//     dropped here, fail closed.
//   - legacy profile with explicit org opt-in: full captures persist
//     exactly as before this gate; the read side (payload.read_originals +
//     effective retention) governs exposure.
func parseRequestEventPolicy(raw map[string]interface{}, policy deliveryPolicy) requestEvent {
	return parseRequestEventProfile(raw, policy.profile, policy.retainOriginal)
}

func parseRequestEventProfile(raw map[string]interface{}, profile config.LogContentProfile, retainOriginal bool) requestEvent {
	f := fieldsOf(raw)
	ev := requestEvent{raw: raw}

	ev.orgID = f.String("org_id")
	if ev.orgID != "" {
		ev.orgIDValue = ev.orgID
	}
	ev.modelRequested = f.String("model_requested")
	ev.modelUsed = f.String("model_used")
	ev.upstreamURL = f.String("upstream_url")
	ev.requestID = f.String("request_id")
	if ev.requestID != "" {
		ev.requestIDValue = ev.requestID
	}
	ev.method = f.StringDefault("method", "POST")
	ev.sessionID = f.String("session_id")
	ev.errorMsg = f.String("error")

	ev.statusCode = f.Int64("status_code")
	ev.durationMs = f.Int64("duration_ms")
	ev.tokensIn = f.Int64("tokens_in")
	ev.tokensOut = f.Int64("tokens_out")
	ev.createdAt = eventCreatedAt(raw)

	ev.cacheHitType = f.NullableString("cache_hit_type")
	ev.cacheSimilarity = f.Float64("cache_similarity")
	ev.counterfactualCostUSD = f.Float64("counterfactual_cost_usd")
	ev.costInUSD = f.Float64("estimated_cost_usd")
	ev.tierUsed = f.NullableString("tier_used")
	ev.classifierClass = f.NullableString("classifier_class")
	ev.classifierConfidence = f.Float64("classifier_confidence")
	ev.classifierSource = f.NullableString("classifier_source")
	ev.abGroup = f.String("ab_group")
	ev.evalgateSampled = f.Bool("evalgate_sampled")

	ev.teamIDValue = uuidField(f.String("team_id"))

	if profile == config.LogContentProfileMetadataOnly {
		// Strict storage contract: content columns bind SQL NULL and the
		// prompt digest-or-NULL — even when a stray payload survived the
		// boundary (fail closed).
		if digest := eventpublisher.ResolvePromptHash(f.String("prompt_hash"), ""); digest != "" {
			ev.promptHash = digest
		}
	} else {
		payload := f.String("payload")
		ev.promptHash = RedactPrompt(payload)
		// FIX-20: the processed client-facing response envelope, when the
		// producer supplied a valid one, IS the `response` column content —
		// the column's name finally matches its meaning. The envelope
		// arrives bounded by the producer's capture budget, so it is stored
		// verbatim (no TruncateResponse — cutting would mangle the JSON).
		// Absent or malformed → the legacy binding below, byte-identical to
		// the pre-FIX-20 rows: old producers mid-rollout and torn values
		// must never lose the row its response snapshot.
		if processed := f.String("processed_response"); adminstore.ParseResponseEnvelope(json.RawMessage(processed)) != nil {
			ev.responseJSON = ResponseForStorage(processed)
		} else if debugLogResponse() {
			ev.responseJSON = ResponseForStorage(payload)
		} else {
			ev.responseJSON = ResponseForStorage(TruncateResponse(payload, maxResponseChars))
		}
		if retainOriginal {
			// Explicit org opt-in (N02-P06 T03): the full-fidelity captures
			// persist and stay read-gated by requests.read_originals.
			ev.upstreamReqJSON = shapeUpstream(f.String("upstream_payload"))
			ev.upstreamRespJSON = shapeUpstream(f.String("upstream_response"))
			ev.upstreamResponse = f.String("upstream_response")
		}
		// Original retention OFF (the default): upstream_request /
		// upstream_response stay nil and the verbatim tool-call sample
		// stays empty — the original captures and the tool-call arguments
		// derived from them never reach the durable write. The processed
		// response snapshot and the prompt digest above still persist.
	}

	ev.g2 = parseG2Fields(raw)
	ev.acct = parseRequestAccounting(raw)
	ev.labels = labelsJSON(raw)

	ev.resaleCostUSD = f.Float64("resale_cost_usd")
	var resaleRawUSD, costRawUSD float64
	ev.resaleQuote, ev.resaleQuoteState, resaleRawUSD = f.QuoteRaw("resale_cost_usd")
	ev.costQuote, ev.costQuoteState, costRawUSD = f.QuoteRaw("estimated_cost_usd")
	// Boundary reconciliation: the sub-µUSD policy rounds a positive
	// quote that collapsed to 0 µUSD UP to the 1 µUSD minimum (owner
	// decision 2026-10-12 — no invisible zeros, billing always visible),
	// and the hidden-zero gate settles an unknown_price zero placeholder
	// as QuoteUnknown.
	ev.resaleQuote, ev.resaleQuoteState = reconcileQuoteState(ev.resaleQuote, ev.resaleQuoteState, resaleRawUSD, ev.acct.costStatus)
	ev.costQuote, ev.costQuoteState = reconcileQuoteState(ev.costQuote, ev.costQuoteState, costRawUSD, ev.acct.costStatus)

	// Reservations (NEXT-18d): tuples and termination are optional — a
	// missing field is a legacy event, an invalid termination string is
	// treated as absent (observability only, never a delivery failure).
	if t := f.String("termination"); validTermination(t) {
		ev.termination = terminationKind(t)
	}
	ev.reservations = parseReservationTuples(raw)

	return ev
}

// errorOptional binds the error column the request.completed way: NULL unless
// the field is a present, non-empty string.
func (ev requestEvent) errorOptional() any {
	if ev.errorMsg == "" {
		return nil
	}
	return ev.errorMsg
}

// eventCreatedAt resolves the event's business time (W-LOGG): the producer
// `ts` field (Unix milliseconds) when present and positive, else the moment
// of parsing (delivery time — the legacy behavior for events predating the
// field). Delayed delivery therefore keeps the original event clock.
func eventCreatedAt(fields map[string]interface{}) time.Time {
	if ts := parseInt64(fields, "ts"); ts > 0 {
		return time.UnixMilli(ts).UTC()
	}
	return time.Now().UTC()
}

// businessPeriod is the budget period ("2006-01") the event belongs to.
// A zero createdAt (a hand-built requestEvent that skipped the parser)
// falls back to the current month.
func (ev requestEvent) businessPeriod() string {
	if ev.createdAt.IsZero() {
		return time.Now().UTC().Format("2006-01")
	}
	return ev.createdAt.Format("2006-01")
}

// logColumn is one declared request_logs column. value is bound as a query
// argument; a non-empty literal is rendered as inline SQL text (the budget
// shape binds its constants inline, exactly as before).
type logColumn struct {
	name    string
	value   any
	literal string
}

// requestLogRow is the ordered request_logs storage projection: columns are
// declared in canonical table order once and insertSQL renders the INSERT,
// numbering placeholders over the bound columns in declaration order. The
// position contracts pinned by the package tests (values[N]) are the
// declaration order below.
type requestLogRow struct {
	cols []logColumn
}

func (r *requestLogRow) set(name string, value any) {
	r.cols = append(r.cols, logColumn{name: name, value: value})
}

func (r *requestLogRow) setLiteral(name, sqlText string) {
	r.cols = append(r.cols, logColumn{name: name, literal: sqlText})
}

func (r *requestLogRow) setAttribution(apiKeyID, sessionKeyID any) {
	r.set("api_key_id", apiKeyID)
	r.set("session_key_id", sessionKeyID)
}

// args returns the bound values in declaration order (literals skipped).
func (r *requestLogRow) args() []any {
	out := make([]any, 0, len(r.cols))
	for _, col := range r.cols {
		if col.literal == "" {
			out = append(out, col.value)
		}
	}
	return out
}

// insertSQL renders INSERT INTO request_logs (...) VALUES (...) with $N
// placeholders over the bound columns; literal columns keep inline text.
func (r *requestLogRow) insertSQL() string {
	var cols strings.Builder
	var vals strings.Builder
	placeholder := 0
	for i, col := range r.cols {
		if i > 0 {
			cols.WriteString(", ")
			vals.WriteString(", ")
		}
		cols.WriteString(col.name)
		if col.literal != "" {
			vals.WriteString(col.literal)
			continue
		}
		placeholder++
		fmt.Fprintf(&vals, "$%d", placeholder)
	}
	return "INSERT INTO request_logs (" + cols.String() + ")\n\t\t VALUES (" + vals.String() + ")"
}

// fullRequestLogRow is the canonical 42-column projection shared by
// request.completed and request.failed. errorValue is verbatim for failed
// events and nil-when-empty for completed ones; statusCode carries the
// shape-specific default policy (failed keeps 0, completed defaults 200).
func fullRequestLogRow(ev requestEvent, sessionID, errorValue any, statusCode int64) *requestLogRow {
	r := &requestLogRow{}
	r.set("session_id", sessionID)
	r.set("org_id", ev.orgIDValue)
	r.set("model_requested", ev.modelRequested)
	r.set("model_used", ev.modelUsed)
	r.set("upstream_url", ev.upstreamURL)
	r.set("method", ev.method)
	r.set("status_code", statusCode)
	r.set("duration_ms", ev.durationMs)
	r.set("tokens_in", ev.tokensIn)
	r.set("tokens_out", ev.tokensOut)
	r.set("error", errorValue)
	r.set("request_id", ev.requestIDValue)
	r.set("cache_hit_type", ev.cacheHitType)
	r.set("cache_similarity", ev.cacheSimilarity)
	r.set("counterfactual_cost_usd", ev.counterfactualCostUSD)
	r.set("cost_in_usd", ev.costInUSD)
	r.set("classifier_class", ev.classifierClass)
	r.set("classifier_confidence", ev.classifierConfidence)
	r.set("classifier_source", ev.classifierSource)
	r.set("tier_used", ev.tierUsed)
	r.set("ab_group", ev.abGroup)
	r.set("evalgate_sampled", ev.evalgateSampled)
	r.set("team_id", ev.teamIDValue)
	r.set("prompt_hash", ev.promptHash)
	r.set("response", ev.responseJSON)
	r.set("upstream_request", ev.upstreamReqJSON)
	r.set("upstream_response", ev.upstreamRespJSON)
	r.set("task_id", ev.g2.taskIDStr)
	r.set("agent_id", ev.g2.agentIDStr)
	r.set("routing_decision", ev.g2.routingDecision)
	r.set("first_token_ms", nullableInt64(ev.raw, "first_token_ms"))
	r.set("attempt_count", nullableInt64(ev.raw, "attempt_count"))
	r.set("retry_count", nullableInt64(ev.raw, "retry_count"))
	r.set("endpoint", ev.acct.endpoint)
	r.set("usage_source", ev.acct.usageSource)
	r.set("cost_status", ev.acct.costStatus)
	r.set("cache_read_tokens", ev.acct.cacheRead)
	r.set("cache_creation_tokens", ev.acct.cacheCreate)
	r.set("labels", ev.labels)
	r.set("user_id", ev.g2.userIDStr)
	// W-LOGG: the event's business time, appended after the pre-existing
	// builder columns so every pinned argument position (0..39) is
	// unchanged; attribution (set at delivery) follows it.
	r.set("created_at", ev.createdAt)
	return r
}

// shadowRequestLogRow is the 37-column shadow-mirror projection. Shadow rows
// are non-cache, non-classified: those columns stay NULL so cache/routing
// savings sub-queries can never pick them up, ab_group is forced to "shadow"
// (the analytics discriminator), error stays NULL and the upstream samples /
// observability columns are not written at all — exactly the pre-refactor
// shape existing tooling reads.
func shadowRequestLogRow(ev requestEvent, sessionID any, statusCode int64) *requestLogRow {
	r := &requestLogRow{}
	r.set("session_id", sessionID)
	r.set("org_id", ev.orgIDValue)
	r.set("model_requested", ev.modelRequested)
	r.set("model_used", ev.modelUsed)
	r.set("upstream_url", ev.upstreamURL)
	r.set("method", ev.method)
	r.set("status_code", statusCode)
	r.set("duration_ms", ev.durationMs)
	r.set("tokens_in", ev.tokensIn)
	r.set("tokens_out", ev.tokensOut)
	r.set("error", nil)
	r.set("request_id", ev.requestIDValue)
	r.set("cache_hit_type", nil)
	r.set("cache_similarity", nil)
	r.set("counterfactual_cost_usd", ev.counterfactualCostUSD)
	r.set("cost_in_usd", ev.costInUSD)
	r.set("classifier_class", nil)
	r.set("classifier_confidence", nil)
	r.set("classifier_source", nil)
	r.set("tier_used", nil)
	r.set("ab_group", "shadow")
	r.set("evalgate_sampled", nil)
	r.set("team_id", ev.teamIDValue)
	r.set("prompt_hash", ev.promptHash)
	r.set("response", ev.responseJSON)
	r.set("task_id", ev.g2.taskIDStr)
	r.set("agent_id", ev.g2.agentIDStr)
	r.set("routing_decision", ev.g2.routingDecision)
	r.set("endpoint", ev.acct.endpoint)
	r.set("usage_source", ev.acct.usageSource)
	r.set("cost_status", ev.acct.costStatus)
	r.set("cache_read_tokens", ev.acct.cacheRead)
	r.set("cache_creation_tokens", ev.acct.cacheCreate)
	r.set("labels", ev.labels)
	r.set("user_id", ev.g2.userIDStr)
	r.set("created_at", ev.createdAt) // W-LOGG: event business time
	return r
}

// budgetRequestLogRow is the 20-column request.budget_exceeded projection
// (status 429). The constant columns stay inline SQL literals, mirroring the
// pre-refactor statement, so the bound-argument positions are unchanged.
func budgetRequestLogRow(ev requestEvent, sessionID any, errorMsg string) *requestLogRow {
	const budgetBlockedStatus = 429
	r := &requestLogRow{}
	r.set("session_id", sessionID)
	r.set("org_id", ev.orgIDValue)
	r.set("model_requested", ev.modelRequested)
	r.setLiteral("model_used", "''")
	r.setLiteral("method", "'POST'")
	r.set("status_code", budgetBlockedStatus)
	r.setLiteral("duration_ms", "0")
	r.setLiteral("tokens_in", "0")
	r.setLiteral("tokens_out", "0")
	r.set("error", "budget_exceeded: "+errorMsg)
	r.set("request_id", ev.requestIDValue)
	r.set("team_id", ev.teamIDValue)
	r.set("prompt_hash", ev.promptHash)
	r.set("task_id", ev.g2.taskIDStr)
	r.set("agent_id", ev.g2.agentIDStr)
	r.set("routing_decision", ev.g2.routingDecision)
	r.set("labels", ev.labels)
	r.set("user_id", ev.g2.userIDStr)
	r.set("created_at", ev.createdAt) // W-LOGG: event business time
	return r
}

// parseFloat64 extracts a float64 from a Redis stream field map.
// go-redis v9 returns all stream field values as strings, so we must parse.
func parseFloat64(fields map[string]interface{}, key string) float64 {
	v, ok := fields[key]
	if !ok {
		return 0
	}
	switch val := v.(type) {
	case float64:
		return val
	case int:
		return float64(val)
	case int64:
		return float64(val)
	case string:
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return 0
		}
		return f
	default:
		return 0
	}
}

// parseInt64 extracts an int64 from a Redis stream field map.
// go-redis v9 returns all stream field values as strings, so we must parse.
func parseInt64(fields map[string]interface{}, key string) int64 {
	v, ok := fields[key]
	if !ok {
		return 0
	}
	switch val := v.(type) {
	case int64:
		return val
	case float64:
		return int64(val)
	case string:
		i, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return 0
		}
		return i
	default:
		return 0
	}
}

// parseBool extracts a bool from a Redis stream field map.
// go-redis v9 returns all stream field values as strings, so we must parse.
func parseBool(fields map[string]interface{}, key string) bool {
	v, ok := fields[key]
	if !ok {
		return false
	}
	switch val := v.(type) {
	case bool:
		return val
	case string:
		b, err := strconv.ParseBool(val)
		if err != nil {
			return false
		}
		return b
	default:
		return false
	}
}

// nullableInt64 returns nil when the stream field is absent or zero, else
// the value. Used for observability columns where 0 was never a meaningful
// measurement (first_token_ms: non-streaming requests; attempt_count:
// legacy events predating the field), so those rows read as "unknown"
// rather than a fake zero in AVG/percentile aggregates.
func nullableInt64(fields map[string]interface{}, key string) interface{} {
	if _, ok := fields[key]; !ok {
		return nil
	}
	v := parseInt64(fields, key)
	if v == 0 {
		return nil
	}
	return v
}

func fieldStringDefault(fields map[string]interface{}, key, fallback string) string {
	v, ok := fields[key]
	if !ok {
		return fallback
	}
	s, _ := v.(string)
	if s == "" {
		return fallback
	}
	return s
}

// nullableString maps an absent or empty string field to SQL NULL. Categorical
// columns (cache_hit_type, tier_used, classifier_class/source) are filtered on
// IS NOT NULL by the savings sub-queries — binding ” instead of NULL made
// every ordinary request look like a classified cache hit there.
func nullableString(fields map[string]interface{}, key string) interface{} {
	v, _ := fields[key].(string)
	if v == "" {
		return nil
	}
	return v
}

// eventQuote reads a money field from a Redis stream field map and validates
// it at the event boundary (AF-05): go-redis v9 returns stream field values
// as strings, so we parse, then classify with pkg/money — missing,
// unparseable, non-finite, negative or out-of-range values are QuoteUnknown
// (a distinct state, never conflated with a genuine zero quote), valid zeros
// are QuoteZero, chargeable values are QuotePositive with exact µUSD.
func eventQuote(fields map[string]interface{}, key string) (money.MicroUSD, money.QuoteState) {
	m, state, _ := eventQuoteRaw(fields, key)
	return m, state
}

// eventQuoteRaw is the single parse point for a boundary money field: the
// classification and the raw USD float come from the same parse, so the
// reconcile seam never re-reads (or re-interprets) the wire value.
func eventQuoteRaw(fields map[string]interface{}, key string) (money.MicroUSD, money.QuoteState, float64) {
	v, ok := fields[key]
	if !ok || v == nil {
		return 0, money.QuoteUnknown, 0
	}
	var f float64
	switch val := v.(type) {
	case float64:
		f = val
	case float32:
		f = float64(val)
	case int:
		f = float64(val)
	case int64:
		f = float64(val)
	case string:
		parsed, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return 0, money.QuoteUnknown, 0
		}
		f = parsed
	default:
		return 0, money.QuoteUnknown, 0
	}
	m, state := money.QuoteFromUSD(f, true)
	return m, state, f
}

// costStatusUnknownPrice is the producer marker for a request whose
// (provider, model) pair has no price (pkg/gateway costStatus).
const costStatusUnknownPrice = "unknown_price"

// minBillableQuoteMicroUSD is the floor the sub-µUSD policy rounds a
// collapsed positive quote up to: no invisible zeros — a positive price is
// always visible at the settlement boundary (owner decision, 2026-10-12).
const minBillableQuoteMicroUSD = money.MicroUSD(1)

// reconcileQuoteState applies the boundary policies to a raw
// event-boundary classification. Sub-µUSD round-up: a present, valid,
// strictly positive quote below half a micro-USD collapses to QuoteZero in
// QuoteFromUSD; it rounds UP to the 1 µUSD minimum and settles as a known,
// billable price (QuotePositive) — the unknown_price gate below never applies
// to it, because a rounded quote is a known price, not an unknown one.
// Hidden-zero gate: an unpriced model is published as estimated_cost_usd=0
// with cost_status="unknown_price", so a genuine raw zero (rawUSD exactly 0)
// under that status is the published placeholder for "no price" — it settles
// as QuoteUnknown (no charge, never reported as a genuine zero). Every other
// cost_status, including the "legacy" default for events without the field,
// keeps the raw classification unchanged. rawUSD is read only when state is
// QuoteZero; it is then the exact value the classification was built from.
func reconcileQuoteState(quote money.MicroUSD, state money.QuoteState, rawUSD float64, costStatus string) (money.MicroUSD, money.QuoteState) {
	if state == money.QuoteZero && rawUSD > 0 {
		return minBillableQuoteMicroUSD, money.QuotePositive
	}
	if costStatus == costStatusUnknownPrice && state == money.QuoteZero {
		return quote, money.QuoteUnknown
	}
	return quote, state
}

func labelsJSON(fields map[string]interface{}) []byte {
	raw, ok := fields["labels"]
	if !ok || raw == nil || raw == "" {
		return []byte("{}")
	}
	text, ok := raw.(string)
	if !ok || text == "" {
		labelDecodeErrors.Add(1)
		metrics.SilentFailure("audit_ingest_decode", "labels")
		return []byte("{}")
	}
	var obj map[string]string
	if err := json.Unmarshal([]byte(text), &obj); err != nil {
		labelDecodeErrors.Add(1)
		metrics.SilentFailure("audit_ingest_decode", "labels")
		return []byte("{}")
	}

	// G4 (owner decision 2026-11-04): the trace-completeness stamp is
	// producer-authoritative request telemetry. Validate it before the
	// normalization loop and reserve it a slot, so the label cap cannot
	// evict it nondeterministically; an uninterpretable stamp is stripped
	// and counted, never stored (CORE-TRACE-05).
	stampValue, stampOK, stampFailure := traceCompletenessLabel(obj)
	if stampFailure != "" {
		metrics.SilentFailure("audit_ingest_trace_completeness", stampFailure)
	}
	limit := 32
	if stampOK {
		limit-- // the stamp reserves one slot deterministically
	}

	out := map[string]string{}
	for key, value := range obj {
		if key == traceStampLabelKey {
			continue // validated above; the raw form never wins
		}
		normKey, ok := labels.NormalizeKey(key)
		if !ok {
			continue
		}
		normVal, reason := labels.NormalizeValue(value)
		if reason != "" {
			continue
		}
		if len(out) >= limit {
			break
		}
		out[normKey] = normVal
	}
	if stampOK {
		out[traceStampLabelKey] = stampValue
	}
	body, err := json.Marshal(out)
	if err != nil {
		return []byte("{}")
	}
	return body
}
