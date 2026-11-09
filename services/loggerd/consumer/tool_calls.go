package consumer

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/reireirei/yabanin/pkg/metrics"
)

// Tool-call extraction from the captured upstream response sample. The sample
// is one of:
//   - a complete chat.completion document (non-streaming): the calls live at
//     choices[].message.tool_calls[].function.name;
//   - an SSE capture (streaming): data: frames with choices[].delta.
//     tool_calls[] fragments — the name appears on the first fragment per
//     index, later fragments only extend arguments.
//
// Truncated samples may yield nothing or a partial set; that is honest — the
// explorer inspector still shows whatever was captured, and this table is the
// aggregate view, never a fabricated one.

// extractToolCallNames returns the distinct tool names the model requested.
func extractToolCallNames(sample string) []string {
	if strings.TrimSpace(sample) == "" {
		return nil
	}
	var doc interface{}
	if err := json.Unmarshal([]byte(sample), &doc); err == nil {
		return namesFromDoc(doc)
	}
	// Not one JSON document — a streamed SSE capture: scan data: frames.
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(sample, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		if payload == "[DONE]" {
			continue
		}
		var frame interface{}
		if err := json.Unmarshal([]byte(payload), &frame); err != nil {
			metrics.SilentFailure("audit_ingest_decode", "tool_frame")
			continue
		}
		for _, name := range namesFromDoc(frame) {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

// namesFromDoc walks a decoded JSON document and collects the tool-call
// function names from both the message (completion) and delta (stream chunk)
// positions.
func namesFromDoc(doc interface{}) []string {
	root, ok := doc.(map[string]interface{})
	if !ok {
		return nil
	}
	choices, ok := root["choices"].([]interface{})
	if !ok {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	addFrom := func(holder interface{}) {
		m, ok := holder.(map[string]interface{})
		if !ok {
			return
		}
		if m["tool_calls"] == nil {
			return
		}
		calls, ok := m["tool_calls"].([]interface{})
		if !ok {
			return
		}
		for _, c := range calls {
			call, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			fn, ok := call["function"].(map[string]interface{})
			if !ok {
				continue
			}
			if name, ok := fn["name"].(string); ok && name != "" && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	for _, ch := range choices {
		choice, ok := ch.(map[string]interface{})
		if !ok {
			continue
		}
		addFrom(choice["message"]) // completion shape
		addFrom(choice["delta"])   // stream chunk shape
	}
	return out
}

// insertToolCalls persists one row per distinct tool name the model requested
// in this response, plus one tool_call_invocations row per occurrence with
// the reassembled arguments (0014). Fail-soft by contract: analytics
// aggregation must never fail the request-log write. Runs inside the delivery
// transaction (AF-04) so a replay never duplicates rows that already
// committed; failures here are swallowed (telemetry, best-effort).
func (c *StreamConsumer) insertToolCalls(ctx context.Context, tx InboxTx, requestID, orgID, taskID, modelUsed, sample interface{}) {
	sampleStr := toString(sample)
	names := extractToolCallNames(sampleStr)
	if len(names) == 0 {
		return
	}
	reqStr, _ := requestID.(string)
	if reqStr == "" {
		return
	}
	for _, name := range names {
		if _, err := tx.Exec(ctx,
			`INSERT INTO tool_calls (request_id, org_id, task_id, model_used, tool_name)
			 VALUES ($1, $2, $3, $4, $5)`,
			reqStr, orgID, nullableStringAny(taskID), modelUsed, name,
		); err != nil {
			c.logger.Warn("tool_calls insert failed",
				slog.String("request_id", reqStr), slog.String("error", err.Error()))
			return
		}
	}
	c.insertToolCallInvocations(ctx, tx, reqStr, orgID, extractToolCallInvocations(sampleStr))
}

// insertToolCallInvocations persists per-occurrence rows (arguments capped).
// Fail-soft: the distinct-name table above already recorded the aggregate.
func (c *StreamConsumer) insertToolCallInvocations(ctx context.Context, tx InboxTx, reqStr string, orgID interface{}, invocations []toolCallInvocation) {
	for _, inv := range invocations {
		args := TruncateResponse(ScrubSecrets(inv.Args), maxInvocationArgsChars)
		if _, err := tx.Exec(ctx,
			`INSERT INTO tool_call_invocations (request_id, org_id, seq, call_id, tool_name, arguments)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			reqStr, orgID, inv.Seq, nullIfEmpty(inv.CallID), inv.Name, nullIfEmpty(args),
		); err != nil {
			c.logger.Warn("tool_call_invocations insert failed",
				slog.String("request_id", reqStr), slog.Int("seq", inv.Seq), slog.String("error", err.Error()))
			return
		}
	}
}

// nullIfEmpty maps an empty string to SQL NULL for nullable columns.
func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func toString(v interface{}) string {
	s, _ := v.(string)
	return s
}

// nullableStringAny maps a nil/empty interface string field to SQL NULL.
func nullableStringAny(v interface{}) interface{} {
	s, _ := v.(string)
	if s == "" {
		return nil
	}
	return s
}
