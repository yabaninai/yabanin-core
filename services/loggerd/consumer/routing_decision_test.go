package consumer

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CORE-TRACE-04: a routing_decision payload carrying the routing rule
// identity ref must survive the consumer unchanged — the json.Valid gate
// accepts it and the stored TEXT column receives the exact bytes. The
// consumer stays schema-agnostic (fail-open on malformed docs, unchanged).
func TestRoutingDecision_WithRuleRefPersistsVerbatim(t *testing.T) {
	const extended = `{"source":"rule_override","from":"auto","to":"premium",` +
		`"rule":{"namespace":"routing","id":"aaaa1111-0000-0000-0000-000000000001","version":"9b1deb4d3b7d4bec"}}`

	// Gate check: the extended doc is valid JSON by construction and passes
	// the parse gate unchanged.
	require.True(t, json.Valid([]byte(extended)))
	g := parseG2Fields(map[string]interface{}{
		"routing_decision": extended,
	})
	got, ok := g.routingDecision.(string)
	require.True(t, ok, "extended routing_decision must pass the parse gate")
	assert.Equal(t, extended, got) //nolint:testifylint // golden: exact wire bytes are the assertion (parse gate must not rewrite the document)

	// Storage check: the INSERT binds the same verbatim string.
	var query string
	var values []any
	pool := &mockDB{
		ExecFn: func(_ context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			query = q
			values = args
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	sc := New(nil, pool, "events:queue", slog.Default())
	msg := redis.XMessage{Values: map[string]interface{}{
		"event_type":       "request.completed",
		"source":           "gateway",
		"session_id":       "sess-123",
		"org_id":           "org-abc",
		"model_requested":  "auto",
		"model_used":       "premium",
		"upstream_url":     "https://api.openai.com/v1/chat/completions",
		"status_code":      float64(200),
		"duration_ms":      float64(1500),
		"tokens_in":        float64(100),
		"tokens_out":       float64(250),
		"method":           "POST",
		"routing_decision": extended,
	}}
	require.NoError(t, sc.handleRequestComplete(context.Background(), msg))

	assert.Contains(t, query, "routing_decision")
	// The G2 columns bind last: task_id (27), agent_id (28), routing_decision (29).
	require.GreaterOrEqual(t, len(values), 30)
	assert.Equal(t, extended, values[29], "the stored TEXT column must receive the exact bytes") //nolint:testifylint // golden: exact wire bytes are the assertion
}
