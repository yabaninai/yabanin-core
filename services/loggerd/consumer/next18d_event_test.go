package consumer

import (
	"encoding/json"
	"testing"

	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NEXT-18d event-boundary parsing: the §5.3 Finalize tuples and the
// termination kind are optional, validated, and never break the delivery.

func TestParseReservationTuples_Valid(t *testing.T) {
	tuples := parseReservationTuples(map[string]interface{}{
		"reservations": `[{"scope_kind":"wallet","scope_key":"org-1","period":"","allowance_id":7,"bound_micro_usd":12000},
		                  {"scope_kind":"session","scope_key":"9c0f","period":"","allowance_id":8,"bound_micro_usd":3000}]`,
	})
	require.Len(t, tuples, 2)
	assert.Equal(t, "wallet", tuples[0].ScopeKind)
	assert.Equal(t, "org-1", tuples[0].ScopeKey)
	assert.Equal(t, int64(7), tuples[0].AllowanceID)
	assert.Equal(t, int64(12000), tuples[0].BoundMicroUSD)
	assert.Equal(t, "session", tuples[1].ScopeKind)
}

func TestParseReservationTuples_AbsentLegacyEvent(t *testing.T) {
	assert.Nil(t, parseReservationTuples(map[string]interface{}{}))
	assert.Nil(t, parseReservationTuples(map[string]interface{}{"reservations": ""}))
	assert.Nil(t, parseReservationTuples(map[string]interface{}{"reservations": 42}))
}

func TestParseReservationTuples_MalformedNeverBreaksDelivery(t *testing.T) {
	assert.Nil(t, parseReservationTuples(map[string]interface{}{"reservations": "{not json"}))
	assert.Nil(t, parseReservationTuples(map[string]interface{}{"reservations": `"a string"`}))
	assert.GreaterOrEqual(t, reservationDecodeErrors.Load(), uint64(2), "decode errors counted, not swallowed")
}

func TestParseReservationTuples_InvalidEntriesDropped(t *testing.T) {
	tuples := parseReservationTuples(map[string]interface{}{
		"reservations": `[{"scope_kind":"galaxy","scope_key":"x","allowance_id":1,"bound_micro_usd":5},
		                  {"scope_kind":"wallet","scope_key":"","allowance_id":2,"bound_micro_usd":5},
		                  {"scope_kind":"wallet","scope_key":"o","allowance_id":0,"bound_micro_usd":5},
		                  {"scope_kind":"wallet","scope_key":"o","allowance_id":3,"bound_micro_usd":-5},
		                  {"scope_kind":"team_month","scope_key":"t","period":"2026-10","allowance_id":9,"bound_micro_usd":500}]`,
	})
	require.Len(t, tuples, 1, "only the valid team tuple survives")
	assert.Equal(t, "team_month", tuples[0].ScopeKind)
	assert.Equal(t, int64(9), tuples[0].AllowanceID)
}

func TestTerminationParsing(t *testing.T) {
	require.True(t, validTermination("completed"))
	require.True(t, validTermination("client_cancel"))
	require.True(t, validTermination("idle_timeout"))
	require.True(t, validTermination("upstream_error"))
	require.True(t, validTermination("policy_denied"))
	assert.False(t, validTermination("exploded"))
	assert.False(t, validTermination(""))
}

func TestParseRequestEvent_ReservationFields(t *testing.T) {
	tuples := []map[string]any{{
		"scope_kind": "wallet", "scope_key": "org", "period": "",
		"allowance_id": 5, "bound_micro_usd": 1000,
	}}
	raw, err := json.Marshal(tuples)
	require.NoError(t, err)
	ev := parseRequestEvent(map[string]interface{}{
		"termination":  "client_cancel",
		"reservations": string(raw),
	})
	assert.Equal(t, TerminationClientCancel, ev.termination)
	require.Len(t, ev.reservations, 1)
	assert.Equal(t, "wallet", ev.reservations[0].ScopeKind)

	// An invalid termination is treated as absent, the event stays well-formed.
	ev = parseRequestEvent(map[string]interface{}{"termination": "spontaneous_combustion"})
	assert.Empty(t, terminationKind(ev.termination))
	assert.Nil(t, ev.reservations)
}

// The scope plan derives one charge per reserve area; the wallet requires a
// positive charge, budget areas count attributed requests even at zero.
func TestScopeChargePlan_TuplesAreAuthoritative(t *testing.T) {
	ev := parseRequestEvent(map[string]interface{}{
		"estimated_cost_usd": "0.012",
		"team_id":            "legacy-team",
		"agent_id":           "legacy-agent",
		"reservations": `[{"scope_kind":"team_month","scope_key":"tuple-team","period":"2026-10","allowance_id":11,"bound_micro_usd":12000},
		                  {"scope_kind":"session","scope_key":"tuple-key","period":"","allowance_id":12,"bound_micro_usd":12000},
		                  {"scope_kind":"wallet","scope_key":"org","period":"","allowance_id":13,"bound_micro_usd":12000}]`,
	})
	charge, state := money.QuoteFromUSD(0.012, true)
	require.Equal(t, money.QuotePositive, state)

	plan := scopeChargePlan(ev, charge, state)
	byKind := map[string]scopeCharge{}
	for _, sc := range plan {
		byKind[sc.kind] = sc
	}
	require.Len(t, plan, 4)

	assert.Equal(t, "tuple-team", byKind[ChargeKindTeamSpend].key, "tuple key wins over the attribution")
	assert.Equal(t, "2026-10", byKind[ChargeKindTeamSpend].period)
	assert.Equal(t, int64(11), byKind[ChargeKindTeamSpend].link.AllowanceID)
	assert.Equal(t, "tuple-key", byKind[ChargeKindSessionSpend].key, "session scope is tuple-driven")
	assert.Equal(t, int64(12), byKind[ChargeKindSessionSpend].link.AllowanceID)
	assert.Equal(t, int64(13), byKind[ChargeKindResaleDeduction].link.AllowanceID, "wallet link carried verbatim")
}

// ScopeKeyPlaceholder keeps the assertion above honest about the wallet
// link carrying the tuple verbatim.
func TestScopeChargePlan_UnknownPriceWalletDropped(t *testing.T) {
	ev := parseRequestEvent(map[string]interface{}{
		"team_id": "team",
		"reservations": `[{"scope_kind":"wallet","scope_key":"org","period":"","allowance_id":1,"bound_micro_usd":1000},
		                  {"scope_kind":"team_month","scope_key":"team","period":"2026-10","allowance_id":2,"bound_micro_usd":1000}]`,
	})
	plan := scopeChargePlan(ev, 0, money.QuoteUnknown)
	for _, sc := range plan {
		assert.NotEqual(t, ChargeKindResaleDeduction, sc.kind, "unknown price never bills the wallet")
	}
	require.Len(t, plan, 1, "the zero-amount team count intent remains (IMP-13)")
	assert.Equal(t, ChargeKindTeamSpend, plan[0].kind)
}
