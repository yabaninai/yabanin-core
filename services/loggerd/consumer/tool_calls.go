package consumer

import (
	"context"
	"encoding/json"
	"fmt"
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

// Tool-fact INSERT statements come in two shapes and the exact bytes must
// match the live schema's indexes (mirroring the settlement intent
// convention at stream.go's settlementIntentStatements):
//   - bare legacy bytes: the only valid form on a pre-0030 schema — there
//     the invocation_id column is a 42703 error before index inference runs;
//   - invocation bytes carrying the identity column with the 0030 partial
//     arbiter "WHERE invocation_id IS NOT NULL", valid once
//     uniq_tool_calls_invocation / uniq_tool_call_invocations_occurrence
//     exist, making every entry its own redelivery no-op.
//
// The legacy domain has no arbiter in either schema: legacy redelivery
// semantics (delivery-inbox dedupe, the coarse enrichment probe) stay
// exactly what they were before 0030.
const (
	toolCallInsertLegacyQuery = `INSERT INTO tool_calls (request_id, org_id, task_id, model_used, tool_name)
		 VALUES ($1, $2, $3, $4, $5)`
	toolCallInsertInvocationQuery = `INSERT INTO tool_calls (request_id, org_id, task_id, model_used, tool_name, invocation_id)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (org_id, request_id, invocation_id, tool_name) WHERE invocation_id IS NOT NULL DO NOTHING`
	toolCallInvocationInsertLegacyQuery = `INSERT INTO tool_call_invocations (request_id, org_id, seq, call_id, tool_name, arguments)
		 VALUES ($1, $2, $3, $4, $5, $6)`
	toolCallInvocationInsertInvocationQuery = `INSERT INTO tool_call_invocations (request_id, org_id, seq, call_id, tool_name, arguments, invocation_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (org_id, request_id, invocation_id, seq) WHERE invocation_id IS NOT NULL DO NOTHING`
)

// toolCallInsertStatements selects the exact INSERT bytes for the two
// tool-fact tables from the live schema (hasToolFactInvocation — the cached
// 0030 probe) and the event's identity domain (invocation nil = legacy).
//
// An invocation-domain event on a pre-0030 schema keeps the legacy bytes:
// unlike settlement money, tool facts are fail-soft analytics — the rows
// still land, in the NULL domain, exactly as the pre-0030 writer wrote
// them. No linkage is guessed: the identity is simply absent until the
// schema carries it, and a later 0030 deployment never backfills it.
func toolCallInsertStatements(hasToolFactInvocation bool, invocation any) (names, occurrences string) {
	if invocation == nil || !hasToolFactInvocation {
		return toolCallInsertLegacyQuery, toolCallInvocationInsertLegacyQuery
	}
	return toolCallInsertInvocationQuery, toolCallInvocationInsertInvocationQuery
}

// toolFactSchemaProbeQuery reports whether the live schema carries the
// invocation_id column on tool_calls (migration 0030+; tool_call_invocations
// ships its column in the same migration, so one probe governs both).
// column_name is a bind parameter so schema-less test doubles answer 0
// (int scan) instead of echoing a probe row back as truth.
const toolFactSchemaProbeQuery = `SELECT count(*) FROM information_schema.columns
	WHERE table_schema = current_schema() AND table_name = 'tool_calls' AND column_name = $1`

// toolFactInvocationSchemaTx resolves whether the tool-fact tables carry
// invocation_id (0030+), using the delivery's own transaction — a pool-level
// probe could wait on a connection the caller already holds, fatal at
// MaxConns=1. Mirrors settlementInvocationSchemaTx in mechanics but not in
// caching: only an AFFIRMATIVE probe is cached. A negative result is a
// property of the schema version, not of the deployment — one live consumer
// routinely spans the migration window (first paid call pre-0030, the next
// one after the migrator ran), and this writer degrades fail-soft to legacy
// bytes, so a cached negative would silently keep unbound inserts forever.
// A cached affirmative is safe: 0030 never rolls back under a live consumer
// in a supported rollout, and if an operator did downgrade, the invocation
// bytes fail loudly instead of silently reverting. Probe errors propagate
// (delivery retries, probe re-runs); absence is revalidated next delivery.
func (c *StreamConsumer) toolFactInvocationSchemaTx(ctx context.Context, tx InboxTx) (bool, error) {
	c.schemaMu.Lock()
	defer c.schemaMu.Unlock()
	if c.schemaToolFactResolved && c.schemaToolFactHasInvocationID {
		return true, nil
	}
	var n int
	if err := tx.QueryRow(ctx, toolFactSchemaProbeQuery, "invocation_id").Scan(&n); err != nil {
		return false, err
	}
	if n > 0 {
		c.schemaToolFactResolved, c.schemaToolFactHasInvocationID = true, true
		return true, nil
	}
	return false, nil
}

// insertToolCalls persists one row per distinct tool name the model requested
// in this response, plus one tool_call_invocations row per occurrence with
// the reassembled arguments (0014). Runs inside the delivery transaction
// (AF-04). An insert error is returned, not swallowed: PostgreSQL aborts
// the whole transaction on the first failed statement (later statements
// would only collect 25P02), so "fail-soft inside the tx" cannot exist —
// the honest contract is a failed delivery (rollback, no ack, redelivery),
// and convergence on replay is structural: post-0030 every entry carries
// its own ON CONFLICT arbiter so a partially written prior attempt cannot
// suppress missing names or occurrences, and pre-0030 the rollback left no
// rows behind for the coarse probe to trip over.
//
// invocationValue is the delivery's own invocation identity (nil for legacy
// events). When present and the schema carries the 0030 shape, both tables
// record it and two invocations sharing a client request-id keep
// independent rows; the linkage is never guessed — a nil identity (or a
// pre-0030 schema) binds the legacy NULL domain with the exact legacy
// statement bytes: no request-id correlation, no backfill from sibling rows.
func (c *StreamConsumer) insertToolCalls(ctx context.Context, tx InboxTx, requestID, orgID, taskID, modelUsed, sample interface{}, invocationValue any) error {
	sampleStr := toString(sample)
	names := extractToolCallNames(sampleStr)
	if len(names) == 0 {
		return nil
	}
	reqStr, _ := requestID.(string)
	if reqStr == "" {
		return nil
	}
	hasToolFactInvocation := false
	if invocationValue != nil {
		var err error
		if hasToolFactInvocation, err = c.toolFactInvocationSchemaTx(ctx, tx); err != nil {
			return fmt.Errorf("probe tool-fact invocation schema: %w", err)
		}
	}
	nameStmt, _ := toolCallInsertStatements(hasToolFactInvocation, invocationValue)
	for _, name := range names {
		args := []any{reqStr, orgID, nullableStringAny(taskID), modelUsed, name}
		if invocationValue != nil && hasToolFactInvocation {
			args = append(args, invocationValue)
		}
		if _, err := tx.Exec(ctx, nameStmt, args...); err != nil {
			c.logger.Warn("tool_calls insert failed",
				slog.String("request_id", reqStr), slog.String("error", err.Error()))
			return fmt.Errorf("insert tool_calls: %w", err)
		}
	}
	return c.insertToolCallInvocations(ctx, tx, reqStr, orgID, extractToolCallInvocations(sampleStr), invocationValue, hasToolFactInvocation)
}

// insertToolCallInvocations persists per-occurrence rows (arguments capped).
// Errors return for the same rollback-redelivery contract as the names.
func (c *StreamConsumer) insertToolCallInvocations(ctx context.Context, tx InboxTx, reqStr string, orgID interface{}, invocations []toolCallInvocation, invocationValue any, hasToolFactInvocation bool) error {
	_, occurrenceStmt := toolCallInsertStatements(hasToolFactInvocation, invocationValue)
	for _, inv := range invocations {
		args := TruncateResponse(ScrubSecrets(inv.Args), maxInvocationArgsChars)
		bind := []any{reqStr, orgID, inv.Seq, nullIfEmpty(inv.CallID), inv.Name, nullIfEmpty(args)}
		if invocationValue != nil && hasToolFactInvocation {
			bind = append(bind, invocationValue)
		}
		if _, err := tx.Exec(ctx, occurrenceStmt, bind...); err != nil {
			c.logger.Warn("tool_call_invocations insert failed",
				slog.String("request_id", reqStr), slog.Int("seq", inv.Seq), slog.String("error", err.Error()))
			return fmt.Errorf("insert tool_call_invocations: %w", err)
		}
	}
	return nil
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
