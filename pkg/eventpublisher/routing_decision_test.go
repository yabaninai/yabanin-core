package eventpublisher

import (
	"testing"

	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPublish_routingDecisionRidesTheStreamWire pins the CORE-TRACE-04
// producer→wire field — the exact field the loggerd consumer validates and
// stores into request_logs.routing_decision — for the EXTENDED payload
// carrying the routing rule identity ref. The event schema change is none:
// RoutingDecision stays a verbatim JSON string, so old and new payloads ride
// the same field (the policy-field precedent, OP-8 / CORE-TRACE-02).
func TestPublish_routingDecisionRidesTheStreamWire(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)

	stream := "eventpublisher-routing-decision-stream"
	p := NewRedisPublisher(rdb, stream)

	// The extended decision payload: rule_override with the identity triple
	// (namespace routing / rule id / content version at match time).
	extended := `{"source":"rule_override","from":"auto","to":"premium",` +
		`"rule":{"namespace":"routing","id":"aaaa1111-0000-0000-0000-000000000001","version":"9b1deb4d3b7d4bec"}}`
	require.NoError(t, p.Publish(testCtx, &Event{
		EventType:       "request.completed",
		Source:          "gateway",
		RequestID:       "req-rule-wire",
		OrgID:           "org-wire",
		RoutingDecision: extended,
	}))

	vals, err := rdb.XRange(testCtx, stream, "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 1)
	assert.Equal(t, extended, vals[0].Values["routing_decision"],
		"Event.RoutingDecision must reach the wire verbatim, rule ref included")

	// Legacy shape: a decision without the ref (and a decision-less request)
	// rides the same field unchanged.
	require.NoError(t, p.Publish(testCtx, &Event{
		EventType:       "request.completed",
		Source:          "gateway",
		RequestID:       "req-rule-wire-legacy",
		OrgID:           "org-wire",
		RoutingDecision: `{"source":"passthrough","from":"gpt-4o-mini"}`,
	}))
	require.NoError(t, p.Publish(testCtx, &Event{
		EventType: "request.completed",
		Source:    "gateway",
		RequestID: "req-rule-wire-none",
		OrgID:     "org-wire",
	}))
	vals, err = rdb.XRange(testCtx, stream, "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 3)
	assert.Equal(t, `{"source":"passthrough","from":"gpt-4o-mini"}`, vals[1].Values["routing_decision"]) //nolint:testifylint // golden: exact wire bytes are the assertion (decision rides verbatim)
	assert.Empty(t, vals[2].Values["routing_decision"], "no decision: the field stays empty (legacy shape)")
}
