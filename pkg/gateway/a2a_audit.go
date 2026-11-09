package cli

// a2aAuditLogger adapts a2aagg.AuditEvent to the loggerd request-event
// stream — the exact mapping of mcpAuditLogger: ok → request.completed,
// anything else → request.failed, with the a2a: label pair in model_used
// so the analytics surfaces distinguish A2A sends from model traffic.

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/reireirei/yabanin/pkg/a2aagg"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

type a2aAuditLogger struct {
	publisher *eventpub.RedisPublisher
	log       *slog.Logger
}

// Log implements a2aagg.AuditLogger. A publish failure is non-fatal to the
// caller (same contract as MCP-05).
func (a *a2aAuditLogger) Log(_ context.Context, e a2aagg.AuditEvent) error {
	if a.publisher == nil {
		return nil
	}
	publishEvent(a.publisher, a.log, a2aAuditEvent(e)) //nolint:contextcheck // publishEvent detaches from the caller context by design
	return nil
}

// a2aAuditEvent converts one A2A message send into the request event that
// loggerd persists to request_logs. Split from Log so the mapping is unit
// testable without a live publisher (mirrors mcpAuditEvent).
func a2aAuditEvent(e a2aagg.AuditEvent) *eventpub.Event {
	eventType := "request.completed"
	status := e.UpstreamStatus
	errStr := ""
	if e.Outcome != a2aagg.OutcomeOK {
		eventType = "request.failed"
		errStr = fmt.Sprintf("a2a:%s", e.Outcome)
		if e.UpstreamStatus > 0 {
			errStr = fmt.Sprintf("a2a:%s (upstream %d)", e.Outcome, e.UpstreamStatus)
		}
	}

	ev := eventBase{
		EventType:      eventType,
		RequestID:      e.RequestID,
		OrgID:          e.OrgID,
		TeamID:         e.TeamID,
		ModelRequested: "a2a",
		ModelUsed:      fmt.Sprintf("a2a:%s", e.TargetName),
		UpstreamURL:    e.UpstreamURL,
		StatusCode:     int64(status),
		DurationMs:     e.LatencyMS,
		Method:         "POST",
		AgentID:        e.AgentID,
		TaskID:         e.TaskID,
		Error:          errStr,
	}.build()
	// The redacted params go in the payload so the audit trail shows WHAT
	// the agent sent (secrets/PII already stripped by the guard hook).
	if len(e.ParamsRedacted) > 0 {
		ev.Payload = string(e.ParamsRedacted)
	}
	return ev
}
