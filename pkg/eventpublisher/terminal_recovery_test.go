package eventpublisher

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeTerminalAccounting(t *testing.T) {
	event := accountingFixture()
	event.UsedOrgKey = true
	facts, err := event.TerminalAccountingFields()
	require.NoError(t, err)
	raw, err := json.Marshal(facts)
	require.NoError(t, err)
	got, err := DecodeTerminalAccounting(raw, event.InvocationID, event.OrgID)
	require.NoError(t, err)
	require.Equal(t, "true", got["used_org_key"])
	require.Equal(t, "7", got["tokens_in"])
	require.Equal(t, "0.000032", got["estimated_cost_usd"])
	require.NotContains(t, got, "payload")
	for _, k := range []string{"used_org_key", "reservations", "tokens_out"} {
		t.Run("missing "+k, func(t *testing.T) {
			var m map[string]string
			require.NoError(t, json.Unmarshal(raw, &m))
			delete(m, k)
			blob, err := json.Marshal(m)
			require.NoError(t, err)
			_, err = DecodeTerminalAccounting(blob, event.InvocationID, event.OrgID)
			require.Error(t, err)
		})
	}
	for k, v := range map[string]any{"org_id": "other-tenant", "invocation_id": "unknown", "used_org_key": nil, "estimated_cost_usd": "NaN", "tokens_out": "-1", "payload": "not-for-recovery", "reservations": "[null]", "ts": "0", "event_type": "request.started"} {
		t.Run("reject "+k, func(t *testing.T) {
			var m map[string]any
			require.NoError(t, json.Unmarshal(raw, &m))
			m[k] = v
			blob, err := json.Marshal(m)
			require.NoError(t, err)
			_, err = DecodeTerminalAccounting(blob, event.InvocationID, event.OrgID)
			require.Error(t, err)
		})
	}
}

func TestTerminalFactsCannotCommitNegativeUsage(t *testing.T) {
	event := accountingFixture()
	event.TokensOut = -1
	_, err := event.TerminalAccountingFields()
	require.Error(t, err)
}

func TestTerminalSettlementQuoteRange(t *testing.T) {
	// One more whole USD than fits in a signed 64-bit micro-USD ledger.
	const outside = 9223372036855
	for _, tc := range []struct {
		field string
		set   func(*Event, float64)
	}{
		{"estimated_cost_usd", func(e *Event, n float64) { e.EstimatedCostUSD = n }},
		{"resale_cost_usd", func(e *Event, n float64) { e.ResaleCostUSD = n }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			event := accountingFixture()
			facts, err := event.TerminalAccountingFields()
			require.NoError(t, err)
			tc.set(&event, outside)
			_, writeErr := event.TerminalAccountingFields()
			assert.Error(t, writeErr)

			facts[tc.field] = "9223372036855"
			raw, err := json.Marshal(facts)
			require.NoError(t, err)
			_, readErr := DecodeTerminalAccounting(raw, event.InvocationID, event.OrgID)
			assert.Error(t, readErr)
		})
	}
}
