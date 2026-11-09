package consumer

// the OTLP logs exporter (pkg/tracing) as GenAI semconv LogRecords.
//
// Contracts:
//   - The sink is OPTIONAL (nil = feature off): with no endpoint configured
//     services/run never wires one and the consumer behaves bit-for-bit as
//     before — the hot path only sees one nil check.
//   - Export is fire-and-forget: Enqueue MUST NOT block (bounded queue +
//     drop counter live inside the exporter), so the consumer delivery loop
//     never waits on the collector.
//   - Export happens ONLY after the delivery transaction committed, so a
//     retried delivery cannot duplicate a log record (the durable inbox
//     makes the retry a no-op, hence no second export).
//   - NO CONTENT by default: payload text is attached only when the sink
//     reports IncludeContent() (operator opt-in) AND the event's effective
//     resurrected by the sink opt-in; the exporter drops it regardless, this
//     gate just avoids copying content at all.
//   - policy_verdict reuses the OP-9 policy parse: absent/malformed `policy`
//     silently exports no verdict, never an error.

import (
	"context"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/tracing"
)

// requestEventTypesOTel are the event shapes that become request_logs rows;
// only these are mirrored to OTLP (all other stream events are skipped).
var requestEventTypesOTel = map[string]struct{}{
	"request.completed":        {},
	"request.failed":           {},
	"request.budget_exceeded":  {},
	"request.shadow_completed": {},
}

// otelContentMaxChars bounds the optional prompt sample at the source (the
// exporter applies its own tighter cap as well).
const otelContentMaxChars = 4096

// OTelLogSink receives content-free request-log records for OTLP export.
// *tracing.LogExporter satisfies it; tests use recording fakes.
type OTelLogSink interface {
	// IncludeContent reports whether prompt samples may be copied at all.
	IncludeContent() bool
	// ExportRequestLog enqueues one record; implementations MUST NOT block.
	ExportRequestLog(rec tracing.RequestLog)
	// Shutdown flushes pending records to the collector.
	Shutdown(ctx context.Context) error
}

// SetOTelSink wires the side-sink. Optional; nil (the default) disables
// export entirely.
func (c *StreamConsumer) SetOTelSink(s OTelLogSink) { c.otelSink = s }

// exportOTelLogProfile mirrors one successfully persisted request event to
// the OTLP sink. Called after delivery success only; non-request event
// types return immediately. The event's effective content profile gates the
func (c *StreamConsumer) exportOTelLogProfile(eventType string, fields map[string]interface{}, profile config.LogContentProfile) {
	if c.otelSink == nil {
		return
	}
	if _, ok := requestEventTypesOTel[eventType]; !ok {
		return
	}

	f := fieldsOf(fields)
	ev := tracing.RequestLog{
		EventType:      trimRequestPrefix(eventType),
		Timestamp:      eventCreatedAt(fields),
		RequestID:      f.String("request_id"),
		OrgID:          f.String("org_id"),
		SessionID:      f.String("session_id"),
		ModelRequested: f.String("model_requested"),
		ModelUsed:      f.String("model_used"),
		UpstreamURL:    f.String("upstream_url"),
		StatusCode:     f.Int64("status_code"),
		DurationMs:     f.Int64("duration_ms"),
		TokensIn:       f.Int64("tokens_in"),
		TokensOut:      f.Int64("tokens_out"),
		CostUSD:        f.Float64("estimated_cost_usd"),
		CacheHit:       f.String("cache_hit_type") != "",
		HasError:       f.String("error") != "",
	}
	// One span per request carries the FIRST executed policy's verdict (the
	// array is priority-ordered; the full per-policy log is policy_decisions).
	if decisions := parsePolicyDecision(fields); len(decisions) > 0 {
		ev.PolicyVerdict = decisions[0].Verdict
	}
	// effective profile is legacy AND the sink opted in.
	if profile == config.LogContentProfileLegacy && c.otelSink.IncludeContent() {
		ev.Content = TruncateResponse(f.String("payload"), otelContentMaxChars)
	}

	c.otelSink.ExportRequestLog(ev)
}

// trimRequestPrefix renders yabanin.event_type ("request.completed" →
// "completed"); the prefix is constant, so a plain slice-off is exact.
func trimRequestPrefix(eventType string) string {
	if len(eventType) > len("request.") && eventType[:len("request.")] == "request." {
		return eventType[len("request."):]
	}
	return eventType
}
