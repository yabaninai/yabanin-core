package eventpublisher

import (
	"encoding/json"
	"testing"

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
