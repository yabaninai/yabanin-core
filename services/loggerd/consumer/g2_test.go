package consumer

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseG2Fields(t *testing.T) {
	t.Run("all present, valid json", func(t *testing.T) {
		g := parseG2Fields(map[string]interface{}{
			"task_id":          "task-1",
			"agent_id":         testAgentUUID,
			"routing_decision": `{"source":"rule_tier","class":"easy"}`,
		})
		assert.Equal(t, "task-1", g.taskIDStr)
		assert.Equal(t, testAgentUUID, g.agentIDStr)
		got, ok := g.routingDecision.(string)
		require.True(t, ok)
		assert.JSONEq(t, `{"source":"rule_tier","class":"easy"}`, got)
	})

	t.Run("non-uuid agent_id maps to deterministic v5 uuid", func(t *testing.T) {
		g := parseG2Fields(map[string]interface{}{
			"agent_id": "agent-1",
		})
		assert.Equal(t, "b4ab9ff7-ba58-5335-b854-a6019297d024", g.agentIDStr)
	})

	t.Run("empty values become nil", func(t *testing.T) {
		g := parseG2Fields(map[string]interface{}{
			"task_id":          "",
			"agent_id":         "",
			"routing_decision": "",
		})
		assert.Nil(t, g.taskIDStr)
		assert.Nil(t, g.agentIDStr)
		assert.Nil(t, g.routingDecision)
	})

	t.Run("absent keys become nil", func(t *testing.T) {
		g := parseG2Fields(map[string]interface{}{})
		assert.Nil(t, g.taskIDStr)
		assert.Nil(t, g.agentIDStr)
		assert.Nil(t, g.routingDecision)
	})

	t.Run("malformed routing_decision -> nil (fail-open)", func(t *testing.T) {
		g := parseG2Fields(map[string]interface{}{
			"task_id":          "task-1",
			"routing_decision": "not-json{",
		})
		assert.Equal(t, "task-1", g.taskIDStr)
		assert.Nil(t, g.routingDecision)
	})
}

func TestHandleRequestComplete_G2Columns(t *testing.T) {
	var query string
	var values []any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			query = q
			values = args
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	consumer := New(nil, pool, "events:queue", slog.Default())

	msg := redis.XMessage{
		Values: map[string]interface{}{
			"event_type":       "request.completed",
			"source":           "gateway",
			"session_id":       "sess-123",
			"org_id":           "org-abc",
			"model_requested":  "gpt-4",
			"model_used":       "gpt-4-turbo",
			"upstream_url":     "https://api.openai.com/v1/chat/completions",
			"status_code":      float64(200),
			"duration_ms":      float64(1500),
			"tokens_in":        float64(100),
			"tokens_out":       float64(250),
			"method":           "POST",
			"task_id":          "task-42",
			"agent_id":         testAgentUUID,
			"routing_decision": `{"source":"rule_tier"}`,
		},
	}

	err := consumer.handleRequestComplete(context.Background(), msg)
	require.NoError(t, err)

	assert.Contains(t, query, "upstream_request, upstream_response, task_id, agent_id, routing_decision")
	assert.Contains(t, query, "$28, $29, $30")
	require.Len(t, values, 43)
	assert.Equal(t, "task-42", values[27])
	assert.Equal(t, testAgentUUID, values[28])
	assert.JSONEq(t, `{"source":"rule_tier"}`, values[29].(string))
}

// AF-06: the delivery path no longer calls the spender directly — it writes
// the durable agent_spend intent; the settlement worker executes
// RecordAgentSpendExact. The fake records exact-path calls only.
type fakeAgentSpender struct {
	calls []struct {
		agent  string
		micro  int64
		tokens int64
	}
}

func (f *fakeAgentSpender) RecordAgentSpendExact(_ context.Context, _ budget.SpendExecutor, agent string, amount money.MicroUSD, tokensIn, _ int64) error {
	f.calls = append(f.calls, struct {
		agent  string
		micro  int64
		tokens int64
	}{agent, int64(amount), tokensIn})
	return nil
}

// The delivery path persists the agent_spend intent and never charges
// directly: spend execution belongs to the settlement worker.
func TestHandleRequestComplete_RecordsAgentSpend(t *testing.T) {
	var intentArgs []any
	var values []any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			if strings.Contains(q, "INSERT INTO request_logs") {
				values = args
			}
			if strings.Contains(q, "INSERT INTO settlement_jobs") {
				intentArgs = args
				return pgconn.NewCommandTag("INSERT 0 1"), nil
			}
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	spender := &fakeAgentSpender{}
	sc := New(nil, pool, "events:queue", slog.Default())
	sc.SetAgentSpender(spender)

	msg := redis.XMessage{Values: map[string]interface{}{
		"event_type": "request.completed", "org_id": "org-abc",
		"model_requested": "gpt-4", "model_used": "gpt-4",
		"status_code": float64(200), "tokens_in": float64(100), "tokens_out": float64(50),
		"agent_id": testAgentUUID, "estimated_cost_usd": float64(0.0123),
	}}
	require.NoError(t, sc.handleRequestComplete(context.Background(), msg))
	require.Len(t, values, 43)

	// Durable intent, exact micro amount ($0.0123 = 12_300 µUSD).
	require.Len(t, intentArgs, 6)
	assert.Equal(t, "org-abc", intentArgs[0])
	assert.Equal(t, ChargeKindAgentSpend, intentArgs[2])
	assert.Equal(t, int64(12300), intentArgs[4], "intent carries the exact micro amount")

	// No direct charge on the delivery path.
	assert.Empty(t, spender.calls, "handleRequestComplete must not call the spender; the settlement worker does")
}

func TestHandleRequestComplete_NoAgentNoSpend(t *testing.T) {
	pool := &mockDB{ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}}
	spender := &fakeAgentSpender{}
	sc := New(nil, pool, "events:queue", slog.Default())
	sc.SetAgentSpender(spender)

	msg := redis.XMessage{Values: map[string]interface{}{
		"event_type": "request.completed", "org_id": "org-abc",
		"model_requested": "gpt-4", "model_used": "gpt-4",
		"status_code": float64(200), "tokens_in": float64(1), "tokens_out": float64(1),
	}}
	require.NoError(t, sc.handleRequestComplete(context.Background(), msg))
	assert.Empty(t, spender.calls, "untagged rows must not touch the agent spender")
}

func TestHandleRequestComplete_UserIDColumn(t *testing.T) {
	const user = "22222222-2222-4222-8222-222222222222"
	var query string
	var values []any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			query = q
			values = args
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	sc := New(nil, pool, "events:queue", slog.Default())
	msg := redis.XMessage{Values: map[string]interface{}{
		"event_type": "request.completed", "org_id": "org-abc",
		"model_requested": "gpt-4", "model_used": "gpt-4",
		"status_code": float64(200), "tokens_in": float64(1), "tokens_out": float64(1),
		"user_id": user,
	}}
	require.NoError(t, sc.handleRequestComplete(context.Background(), msg))
	assert.Contains(t, query, "user_id")
	assert.Contains(t, query, "api_key_id")
	assert.Contains(t, query, "session_key_id")
	require.GreaterOrEqual(t, len(values), 3)
	// W-LOGG: created_at is inserted before the attribution columns.
	assert.Equal(t, user, values[len(values)-4])
	assert.IsType(t, time.Time{}, values[len(values)-3])
	assert.Nil(t, values[len(values)-2])
	assert.Nil(t, values[len(values)-1])
}
