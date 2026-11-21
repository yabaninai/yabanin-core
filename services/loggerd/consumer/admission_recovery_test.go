package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/stretchr/testify/require"
)

type recoveryScan struct {
	fakeSettlementDB
	rows   [][]any
	cursor string
}

func (s *recoveryScan) Query(_ context.Context, _ string, args ...any) (pgx.Rows, error) {
	s.cursor = args[0].(string)
	return &fakeRows{vals: s.rows}, nil
}
func TestAdmissionRecoveryBatchPastInvalidFact(t *testing.T) {
	const org = "org-abc"
	const rid = "shared-correlation"
	const badID = "00000001-0000-4000-8000-000000000001"
	ev := eventpublisher.Event{OrgID: org, InvocationID: testInvocationID, RequestID: rid, EventType: "request.completed", TS: 1777712345678, UsageSource: "provider", TokensIn: 7, TokensOut: 3, EstimatedCostUSD: 0.000032, ResaleCostUSD: 0.000032, CostStatus: "priced", StatusCode: 200, ModelUsed: "m"}
	fields, err := ev.TerminalAccountingFields()
	require.NoError(t, err)
	raw, err := json.Marshal(fields)
	require.NoError(t, err)
	scan := &recoveryScan{rows: [][]any{
		{badID, org, "stream", "stream", rid, rid, []byte(`{"payload":"incomplete"}`)},
		{ev.InvocationID, org, "chat", "chat", rid, rid, raw},
	}}
	scan.failNext = map[string]int{"UPDATE request_admissions": 2}
	scan.failErr = errors.New("expiry trigger rejected stale row")
	var logRows, intents, inbox int
	delivery := &mockDB{
		QueryRowFn: func(_ context.Context, q string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(q, "information_schema"):
				return &fakeRow{vals: []any{1}}
			case strings.Contains(q, "FROM request_admissions"):
				return &fakeRow{vals: []any{org, "admitted"}}
			case strings.Contains(q, "FROM request_terminal_facts"):
				return &fakeRow{vals: []any{string(raw)}}
			}
			return errRow{err: pgx.ErrNoRows}
		},
		ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
			switch {
			case strings.Contains(q, "INSERT INTO request_logs"):
				logRows++
			case strings.Contains(q, "INSERT INTO settlement_jobs"):
				intents++
			case strings.Contains(q, "INSERT INTO event_inbox"):
				inbox++
			}
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	c := NewWithCreditStore(nil, delivery, "events", silentLogger(), credits.NewStore(nil, silentLogger()))
	require.False(t, c.expireAdmissionBatch(t.Context(), scan).IsZero(), "failed expiry must be rate-limited")
	cursor, more, err := c.recoverAdmissionBatch(t.Context(), scan, initialRecoveryCursor)
	require.NoError(t, err)
	require.False(t, more)
	require.Equal(t, initialRecoveryCursor, scan.cursor)
	require.Equal(t, initialRecoveryCursor, cursor)
	require.Equal(t, 1, logRows)
	require.Equal(t, 1, intents)
	require.Zero(t, inbox)
}
func TestAdmissionRecoveryExpiryFailureIsRetried(t *testing.T) {
	scan := &recoveryScan{}
	scan.failNext = map[string]int{"UPDATE request_admissions": 1}
	scan.failErr = errors.New("database temporarily unavailable")
	c := New(nil, nil, "events", silentLogger())
	require.False(t, c.expireAdmissionBatch(t.Context(), scan).IsZero())
	require.False(t, c.expireAdmissionBatch(t.Context(), scan).IsZero())
	require.Len(t, scan.execsBySubstring("UPDATE request_admissions"), 1)
}
