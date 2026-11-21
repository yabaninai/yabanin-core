package consumer

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/stretchr/testify/require"
)

// The five reproduced review findings, ported from the reviewer tree: BYOK
// survival through the recovery mapping, the cache-kind gate, budget-refusal
// admission binding, first-delivery admission resolution, and exact
// facts/wire accounting parity.
func TestReviewInvocationEvidence(t *testing.T) {
	t.Run("BYOK survives recovery mapping", func(t *testing.T) {
		ev := eventpublisher.Event{InvocationID: testInvocationID, OrgID: "org-abc", EventType: "request.completed", TS: 1, UsedOrgKey: true}
		facts, err := ev.TerminalAccountingFields()
		require.NoError(t, err)
		wire := map[string]interface{}{}
		for k, v := range facts {
			wire[k] = v
		}
		require.Equal(t, "true", wire["used_org_key"])
		recovered := parseTerminalFactsEvent(wire)
		require.Equal(t, "true", recovered.raw["used_org_key"])
	})
	t.Run("unknown cache kind never excuses missing admission", func(t *testing.T) {
		msg := invocationCacheHitMsg("41-99")
		msg.Values["cache_hit_type"] = "other"
		c := NewWithCreditStore(&mockRedis{}, &mockDB{QueryRowFn: admissionRow(1, nil, nil)}, "events", silentLogger(), nil)
		require.Error(t, c.processMessage(t.Context(), msg))
	})
	t.Run("cross tenant budget refusal cannot claim paid identity", func(t *testing.T) {
		msg := invocationChargedMsg("42-99")
		msg.Values["event_type"] = "request.budget_exceeded"
		db := &mockDB{QueryRowFn: admissionRow(1, &fakeRow{vals: []any{"other-org", "admitted"}}, nil)}
		c := NewWithCreditStore(&mockRedis{}, db, "events", silentLogger(), nil)
		require.Error(t, c.processMessage(t.Context(), msg))
	})
	t.Run("primary failed delivery resolves once", func(t *testing.T) {
		msg := invocationChargedMsg("43-99")
		msg.Values["event_type"] = "request.failed"
		msg.Values["termination"] = "upstream_error"
		msg.Values["usage_source"] = "none"
		facts := chargedTerminalFacts()
		facts["event_type"] = "request.failed"
		facts["termination"] = "upstream_error"
		facts["usage_source"] = "none"
		transitions := 0
		db := &mockDB{QueryRowFn: admissionRow(1, &fakeRow{vals: []any{"org-abc", "admitted"}}, facts), ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(q, "UPDATE request_admissions") {
				transitions++
			}
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		}}
		c := NewWithCreditStore(&mockRedis{}, db, "events", silentLogger(), nil)
		require.NoError(t, c.processMessage(t.Context(), msg))
		require.Equal(t, 1, transitions)
	})
	t.Run("partial facts cannot authenticate added payer", func(t *testing.T) {
		msg := invocationChargedMsg("44-99")
		msg.Values["used_org_key"] = "true"
		_, ok := compareAccountingFields(chargedTerminalFacts(), msg.Values)
		require.False(t, ok)
	})
}
