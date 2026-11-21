package eventpublisher

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

const invocationFixtureID = "e014bc0e-48c8-4e81-bf3a-3efaedc60a2d"

func accountingFixture() Event {
	return Event{
		InvocationID: invocationFixtureID, EventType: "request.completed", OrgID: "org-a",
		RequestID: "shared-client-id", TS: 1777712345678, TokensIn: 7, TokensOut: 3,
		EstimatedCostUSD: 0.000032, ResaleCostUSD: 0.000037, UsageSource: "provider",
		CostStatus: "priced", Termination: "completed", StatusCode: 200,
		APIKeyID: "41", SessionKeyID: "52", TeamID: "team-a", UserID: "user-a",
		Payload: "confidential-initial", ProcessedResponse: "confidential-processed",
		UpstreamPayload: "confidential-request", UpstreamResponse: "confidential-response",
		Labels: map[string]string{"note": "confidential-label"}, Error: "confidential-error",
		RoutingDecision: "confidential-routing", UpstreamURL: "confidential-url",
	}
}

func TestTerminalAccountingFields(t *testing.T) {
	event := accountingFixture()
	const tuples = `[{"scope_kind":"wallet","scope_key":"org-a","period":"","allowance_id":71,"bound_micro_usd":100}]`
	event.Reservations = tuples
	fields, err := event.TerminalAccountingFields()
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"event_type": "request.completed", "invocation_id": invocationFixtureID, "org_id": "org-a", "request_id": "shared-client-id",
		"ts": "1777712345678", "model_requested": "", "model_used": "", "status_code": "200", "duration_ms": "0", "tokens_in": "7", "tokens_out": "3",
		"estimated_cost_usd": "0.000032", "resale_cost_usd": "0.000037", "cost_status": "priced", "usage_source": "provider",
		"termination": "completed", "session_id": "", "api_key_id": "41", "session_key_id": "52", "user_id": "user-a", "team_id": "team-a",
		"agent_id": "", "task_id": "", "endpoint": "", "cache_hit_type": "", "cache_read_tokens": "0", "cache_creation_tokens": "0", "ab_group": "",
		"tier_used": "", "counterfactual_cost_usd": "0", "reservations": tuples, "first_token_ms": "0", "attempt_count": "0", "retry_count": "0",
		"used_org_key": "", "prompt_hash": "cb0ef9d7c29a4577ff3c6cf3394616f16f8fcf2241fdcb4b7d88fe12d6a7fa71",
	}, fields)
	body, err := json.Marshal(fields)
	require.NoError(t, err)
	require.NotContains(t, string(body), "confidential")
}

func TestTerminalAccountingRejectsInvalidEvidence(t *testing.T) {
	for name, change := range map[string]func(*Event){
		"missing invocation":      func(e *Event) { e.InvocationID = "" },
		"noncanonical invocation": func(e *Event) { e.InvocationID = "urn:uuid:" + invocationFixtureID },
		"zero UUID":               func(e *Event) { e.InvocationID = "00000000-0000-0000-0000-000000000000" },
		"no timestamp":            func(e *Event) { e.TS = 0 },
		"no tenant":               func(e *Event) { e.OrgID = "" },
		"nonterminal":             func(e *Event) { e.EventType = "request.started" },
		"nonfinite cost":          func(e *Event) { e.ResaleCostUSD = math.NaN() },
		"negative cost":           func(e *Event) { e.EstimatedCostUSD = -1 },
		"null reservation":        func(e *Event) { e.Reservations = `[null]` },
		"unrecognized scope":      func(e *Event) { e.Reservations = `[{"scope_kind":"confidential prompt text"}]` },
		"wrong wallet": func(e *Event) {
			e.Reservations = `[{"scope_kind":"wallet","scope_key":"org-b","period":"","allowance_id":1,"bound_micro_usd":10}]`
		},
		"unexpected reservation field": func(e *Event) { e.Reservations = `[{"payload":"confidential"}]` },
		"trailing reservation JSON":    func(e *Event) { e.Reservations = `[] {"extra":"confidential"}` },
	} {
		t.Run(name, func(t *testing.T) {
			event := accountingFixture()
			change(&event)
			fields, err := event.TerminalAccountingFields()
			require.Error(t, err)
			require.Nil(t, fields)
		})
	}
}

func TestTerminalAccountingReservationDoesNotRetainOverwrittenValue(t *testing.T) {
	event := accountingFixture()
	event.Reservations = `[{"scope_kind":"wallet","scope_key":"confidential","scope_key":"org-a","period":"","allowance_id":71,"bound_micro_usd":100}]`
	fields, err := event.TerminalAccountingFields()
	require.NoError(t, err)
	require.NotContains(t, fields["reservations"], "confidential")
	require.Contains(t, fields["reservations"], `"scope_key":"org-a"`)
}

func TestInvocationAccountingRedisParity(t *testing.T) {
	rdb := testdb.Redis(t)
	stream := "invocation-accounting-wire"
	p := NewRedisPublisher(rdb, stream)
	event := accountingFixture()
	require.NoError(t, p.Publish(t.Context(), &event))
	rows, err := rdb.XRevRangeN(t.Context(), stream, "+", "-", 1).Result()
	require.NoError(t, err)
	require.Len(t, rows, 1)
	fields, err := event.TerminalAccountingFields()
	require.NoError(t, err)
	for key, value := range fields {
		require.Equal(t, value, rows[0].Values[key], key)
	}
	event.InvocationID = ""
	event.TS = 0
	require.NoError(t, p.Publish(t.Context(), &event))
	rows, err = rdb.XRevRangeN(t.Context(), stream, "+", "-", 1).Result()
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.NotContains(t, rows[0].Values, "invocation_id")
	require.Contains(t, rows[0].Values, "ts")
	require.NotEqual(t, "0", rows[0].Values["ts"])
}

func TestTerminalAccountingDecodedIdentity(t *testing.T) {
	for _, raw := range []string{`""`, "null", "1", `"invalid"`} {
		var event Event
		require.Error(t, json.Unmarshal([]byte(`{"invocation_id":`+raw+`}`), &event))
	}
	var legacy Event
	require.NoError(t, json.Unmarshal([]byte(`{"event_type":"request.completed"}`), &legacy))
	values, err := legacy.accountingForPublish(1)
	require.NoError(t, err)
	require.NotContains(t, values, "invocation_id")
	event := accountingFixture()
	event.UsedOrgKey = true
	raw, err := json.Marshal(event)
	require.NoError(t, err)
	var decoded Event
	require.NoError(t, json.Unmarshal(raw, &decoded))
	fields, err := decoded.TerminalAccountingFields()
	require.NoError(t, err)
	require.Equal(t, "true", fields["used_org_key"])
}

func TestTerminalAccountingProducerReservations(t *testing.T) {
	event := accountingFixture()
	event.AgentID = "agent-a"
	admission := &budget.Reservation{Scopes: []budget.ScopeReserve{
		{Scope: budget.ScopeWallet, Key: event.OrgID, AllowanceID: 7, Bound: 100},
		{Scope: budget.ScopeTeamMonth, Key: event.TeamID, Period: "2026-11", AllowanceID: 8, Bound: 100},
		{Scope: budget.ScopeAgentDay, Key: event.AgentID, Period: "2026-11-21", AllowanceID: 9, Bound: 100},
		{Scope: budget.ScopeSession, Key: event.SessionKeyID, AllowanceID: 10, Bound: 100},
	}}
	event.Reservations = admission.TuplesJSON()
	fields, err := event.TerminalAccountingFields()
	require.NoError(t, err)
	require.Equal(t, event.Reservations, fields["reservations"])
}
