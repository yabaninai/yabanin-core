package cli

import (
	"context"
	"fmt"
	"log/slog"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/mcpagg"
)

// mcpAuditLogger is the gateway's mcpagg.AuditLogger (MCP-03). It records one
// MCP tool invocation by publishing a request event to the loggerd stream —
// the SAME pipeline that persists ordinary chat requests to request_logs. The
// loggerd consumer already handles task_id + agent_id + upstream_url, so each
// tool call lands as a request_logs row tagged with the invoking agent and
// task, without the gateway writing request_logs directly.
//
// The tool call is labeled ModelUsed="mcp:<server>:<tool>" so the row is
// distinguishable from a model inference and readable by existing tooling.
// Params are already redacted by the proxy's guard hook (MCP-06) before they
// reach here; the original client params never reach the audit trail.
type mcpAuditLogger struct {
	publisher *eventpub.RedisPublisher
	log       *slog.Logger
}

// Log implements mcpagg.AuditLogger. A publish failure is non-fatal to the
// caller (the proxy swallows the returned error and counts the drop, MCP-05).
// publishEvent detaches from the request context by design (a telemetry publish
// must outlive the request), so the unused ctx is expected here.
func (a *mcpAuditLogger) Log(_ context.Context, e mcpagg.AuditEvent) error {
	if a.publisher == nil {
		return nil
	}
	publishEvent(a.publisher, a.log, mcpAuditEvent(e)) //nolint:contextcheck // publishEvent detaches from the caller context by design
	return nil
}

// mcpAuditEvent converts one MCP tool invocation into the request event that
// loggerd persists to request_logs. Split from Log so the mapping is unit
// testable without a live publisher.
//
// ok → request.completed; anything else → request.failed with the outcome as
// the error so loggerd's failed-row path stores it. (loggerd keys on these
// literal strings — see services/loggerd/consumer/stream.go.)
func mcpAuditEvent(e mcpagg.AuditEvent) *eventpub.Event {
	eventType := "request.completed"
	status := e.UpstreamStatus
	errStr := ""
	if e.Outcome != mcpagg.OutcomeOK {
		eventType = "request.failed"
		errStr = fmt.Sprintf("mcp:%s", e.Outcome)
		if e.UpstreamStatus > 0 {
			errStr = fmt.Sprintf("mcp:%s (upstream %d)", e.Outcome, e.UpstreamStatus)
		}
	}

	// MCP tool calls carry no token usage or cost — those columns stay zero
	// (loggerd distinguishes $0-unknown via the model label + mcp: prefix).
	// Labels stay unset on the audit surface.
	ev := eventBase{
		EventType:      eventType,
		RequestID:      e.RequestID,
		OrgID:          e.OrgID,
		TeamID:         e.TeamID,
		ModelRequested: "mcp",
		ModelUsed:      fmt.Sprintf("mcp:%s:%s", e.ServerName, e.Tool),
		UpstreamURL:    e.UpstreamURL,
		StatusCode:     int64(status),
		DurationMs:     e.LatencyMS,
		Method:         "POST",
		AgentID:        e.AgentID,
		TaskID:         e.TaskID,
		Error:          errStr,
	}.build()
	// The redacted params go in the payload so the audit trail shows WHAT the
	// agent asked for (secrets/PII already stripped by the guard hook).
	if len(e.ParamsRedacted) > 0 {
		ev.Payload = string(e.ParamsRedacted)
	}
	return ev
}
