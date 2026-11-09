package approvals

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/agentloop"
)

// Hermetic unit tests: the fail-closed posture, the Request/Decision
// validation contracts, the self-approval invariants and the record
// reconstruction algebra — all on queryRow/exec doubles, no server. The
// Postgres acceptance flows (five-state lifecycle, atomic
// decision-vs-expiry race, restart durability) live in store_int_test.go on
// the Docker stand.

// stubRow answers one Scan with captured values, mirroring a pgx.Row.
type stubRow struct {
	scan func(dest ...any) error
}

func (r stubRow) Scan(dest ...any) error { return r.scan(dest...) }

func errRow(err error) pgx.Row {
	return stubRow{scan: func(...any) error { return err }}
}

// approvalColumns is the fetch projection width store.go scans; a projection
// change must break this stub loudly rather than mis-scan (21 columns).
func approvalStubRow(t *testing.T, r row) pgx.Row {
	t.Helper()
	return stubRow{scan: func(dest ...any) error {
		if len(dest) != 21 {
			t.Fatalf("fetch projection changed: %d dests, want 21", len(dest))
		}
		*(dest[0].(*string)) = r.ID
		*(dest[1].(*string)) = r.OperationID
		*(dest[2].(*string)) = r.OrgID
		*(dest[3].(*string)) = r.ProjectID
		*(dest[4].(*int32)) = r.StepIndex
		*(dest[5].(*string)) = r.TurnID
		*(dest[6].(*string)) = r.Initiator
		*(dest[7].(*string)) = r.InitiatorKind
		*(dest[8].(*string)) = r.Server
		*(dest[9].(*string)) = r.Tool
		*(dest[10].(*string)) = r.ArgsDigest
		*(dest[11].(*string)) = r.PolicyRef
		*(dest[12].(*float64)) = r.TTLSecs
		*(dest[13].(*bool)) = r.RequiresDifferentHuman
		*(dest[14].(*agentloop.ApprovalState)) = r.State
		*(dest[15].(**string)) = r.Outcome
		*(dest[16].(**string)) = r.Approver
		*(dest[17].(**time.Time)) = r.DecidedAt
		*(dest[18].(*bool)) = r.RecheckRequired
		*(dest[19].(*time.Time)) = r.ExpiresAt
		*(dest[20].(*time.Time)) = r.CreatedAt
		return nil
	}}
}

// lazyStore builds a store that passes the ready() guard (never-connected
// pool, jitaccess pattern) with the given doubles swapped in, so guards past
// ready can be probed without a server.
func lazyStore(t *testing.T, ctx context.Context) *Store {
	t.Helper()
	pool, err := pgxpool.New(ctx, "postgres://127.0.0.1:1/unused")
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return NewStore(pool)
}

// refusedStore reaches storage only if the code under test skips validation.
func refusedStore(t *testing.T, ctx context.Context) *Store {
	t.Helper()
	s := lazyStore(t, ctx)
	s.queryRow = func(ctx context.Context, sql string, args ...any) pgx.Row {
		t.Helper()
		t.Fatalf("validation must refuse before any storage call (%s)", sql)
		return nil
	}
	s.exec = func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
		t.Helper()
		t.Fatalf("validation must refuse before any storage call (%s)", sql)
		return pgconn.CommandTag{}, nil
	}
	return s
}

// validRequest is the fully-bound happy-path request every validation case
// mutates one field of.
func validRequest() agentloop.ApprovalRequest {
	return agentloop.ApprovalRequest{
		OperationID:   "op-1",
		StepIndex:     2,
		TurnID:        "turn-7",
		Initiator:     "user-1",
		InitiatorKind: agentloop.SubjectHuman,
		Server:        "github",
		Tool:          "create_issue",
		ArgsDigest:    "aa11",
		PolicyRef:     "toolpolicy@3",
	}
}

var testOrgID = "00000000-0000-0000-0000-000000000001"

func TestStore_NilPoolFailsClosed(t *testing.T) {
	s := NewStore(nil)
	ctx := context.Background()
	op := agentloop.Operation{ID: "op-1", OrgID: testOrgID}

	_, err := s.Request(ctx, op, validRequest())
	require.ErrorIs(t, err, ErrNoPool)
	_, err = s.Decision(ctx, agentloop.ApprovalDecision{ApprovalID: "a", Outcome: agentloop.DecisionApproved, Approver: "h"})
	require.ErrorIs(t, err, ErrNoPool)
	_, err = s.Cancel(ctx, "a")
	require.ErrorIs(t, err, ErrNoPool)
	_, err = s.ExpirePast(ctx)
	require.ErrorIs(t, err, ErrNoPool)
	_, err = s.Get(ctx, "a")
	require.ErrorIs(t, err, ErrNoPool)
	_, err = s.PendingByOperation(ctx, "op-1")
	require.ErrorIs(t, err, ErrNoPool)
}

func TestRequest_ValidationMatrix(t *testing.T) {
	ctx := context.Background()
	op := agentloop.Operation{ID: "op-1", OrgID: testOrgID}

	mut := func(f func(*agentloop.ApprovalRequest)) agentloop.ApprovalRequest {
		r := validRequest()
		f(&r)
		return r
	}
	cases := []struct {
		name string
		op   agentloop.Operation
		req  agentloop.ApprovalRequest
	}{
		{"missing operation id", agentloop.Operation{OrgID: testOrgID}, validRequest()},
		{"missing org", agentloop.Operation{ID: "op-1"}, validRequest()},
		{"blank initiator", op, mut(func(r *agentloop.ApprovalRequest) { r.Initiator = " " })},
		{"empty initiator kind", op, mut(func(r *agentloop.ApprovalRequest) { r.InitiatorKind = "" })},
		{"unknown initiator kind", op, mut(func(r *agentloop.ApprovalRequest) { r.InitiatorKind = "root" })},
		{"missing server", op, mut(func(r *agentloop.ApprovalRequest) { r.Server = "" })},
		{"missing tool", op, mut(func(r *agentloop.ApprovalRequest) { r.Tool = "" })},
		{"missing args digest", op, mut(func(r *agentloop.ApprovalRequest) { r.ArgsDigest = "" })},
		{"negative ttl", op, mut(func(r *agentloop.ApprovalRequest) { r.TTL = -time.Second })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := refusedStore(t, ctx)
			_, err := s.Request(ctx, tc.op, tc.req)
			require.ErrorIs(t, err, ErrInvalidRequest)
		})
	}
}

func TestDecision_ValidationMatrix(t *testing.T) {
	ctx := context.Background()
	s := refusedStore(t, ctx)

	cases := []agentloop.ApprovalDecision{
		{ApprovalID: "", Outcome: agentloop.DecisionApproved, Approver: "h1"},
		{ApprovalID: "a1", Outcome: "maybe", Approver: "h1"},
		{ApprovalID: "a1", Outcome: agentloop.DecisionApproved, Approver: ""},
		{ApprovalID: "a1", Outcome: agentloop.DecisionApproved, Approver: "  "},
	}
	for i, dec := range cases {
		_, err := s.Decision(ctx, dec)
		require.ErrorIs(t, err, ErrInvalidDecision, "case %d (%+v)", i, dec)
	}
	_, err := s.Cancel(ctx, "")
	require.ErrorIs(t, err, ErrInvalidDecision)
}

func TestRequest_TTLDefaultIsSpiDefault(t *testing.T) {
	ctx := context.Background()
	op := agentloop.Operation{ID: "op-1", OrgID: testOrgID}

	s := lazyStore(t, ctx)
	var capturedSecs float64
	s.queryRow = func(ctx context.Context, sql string, args ...any) pgx.Row {
		require.Contains(t, sql, "make_interval(secs => $13)",
			"expires_at must derive from the same parameter as ttl_secs (one clock, one insert)")
		capturedSecs = args[12].(float64)
		return stubRow{scan: func(dest ...any) error {
			*(dest[0].(*time.Time)) = time.Now().UTC().Add(time.Duration(capturedSecs) * time.Second)
			return nil
		}}
	}

	rec, err := s.Request(ctx, op, validRequest()) // TTL zero → default
	require.NoError(t, err)
	require.InDelta(t, agentloop.DefaultApprovalTTL.Seconds(), capturedSecs, 1e-9,
		"zero TTL must resolve to DefaultApprovalTTL")
	require.Equal(t, agentloop.ApprovalPending, rec.State)
	require.Equal(t, agentloop.DefaultApprovalTTL, rec.Request.TTL,
		"the returned record must carry the RESOLVED ttl, not the zero the caller passed")

	explicit := validRequest()
	explicit.TTL = 90 * time.Second
	_, err = s.Request(ctx, op, explicit)
	require.NoError(t, err)
	require.InDelta(t, float64(90), capturedSecs, 1e-9, "explicit TTL must pass through unchanged")
}

func TestDecision_SelfApprovalInvariants(t *testing.T) {
	ctx := context.Background()

	pendingRow := func(initiator string, kind agentloop.SubjectKind, diffHuman bool) row {
		return row{
			ID: "a-1", OperationID: "op-1", OrgID: testOrgID, Initiator: initiator,
			InitiatorKind: string(kind), Server: "github", Tool: "create_issue",
			ArgsDigest: "aa11", State: agentloop.ApprovalPending,
			RequiresDifferentHuman: diffHuman, TTLSecs: 900,
			ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
		}
	}

	cases := []struct {
		name   string
		r      row
		forbid bool
	}{
		{"agent initiator cannot self-approve", pendingRow("agent-1", agentloop.SubjectAgent, false), true},
		{"ci initiator cannot self-approve", pendingRow("ci-1", agentloop.SubjectCI, false), true},
		{"different-human mandate overrides self-approval permission", pendingRow("user-1", agentloop.SubjectHuman, true), true},
		{"human initiator without mandate is a T03 boundary", pendingRow("user-1", agentloop.SubjectHuman, false), false},
		{"service initiator without mandate is a T03 boundary", pendingRow("svc-1", agentloop.SubjectService, false), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sawUpdate bool
			s := lazyStore(t, ctx)
			s.queryRow = func(ctx context.Context, sql string, args ...any) pgx.Row {
				if sawUpdate {
					// The post-UPDATE re-fetch sees the resolved row.
					decided := tc.r
					decided.State = agentloop.ApprovalApproved
					decidedAt := time.Now().UTC()
					decided.DecidedAt = &decidedAt
					return approvalStubRow(t, decided)
				}
				return approvalStubRow(t, tc.r)
			}
			s.exec = func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
				sawUpdate = true
				return pgconn.NewCommandTag("UPDATE 1"), nil
			}
			dec := agentloop.ApprovalDecision{
				ApprovalID: "a-1",
				Outcome:    agentloop.DecisionApproved,
				Approver:   tc.r.Initiator, // self
			}
			rec, err := s.Decision(ctx, dec)
			if tc.forbid {
				require.ErrorIs(t, err, ErrSelfApproval)
				require.False(t, sawUpdate,
					"a forbidden self-approval must never reach the terminal UPDATE")
				require.Equal(t, agentloop.ApprovalPending, rec.State,
					"the forbidden decision must leave the row pending")
				return
			}
			require.NoError(t, err)
			require.True(t, sawUpdate,
				"the terminal UPDATE must run for an admissible decision")
			require.Equal(t, agentloop.ApprovalApproved, rec.State)
		})
	}
}

func TestDecision_DuplicateResolvesOnce(t *testing.T) {
	ctx := context.Background()
	approver := "human-2"
	outcome := string(agentloop.DecisionApproved)
	decidedAt := time.Now().UTC()
	decided := row{
		ID: "a-1", OperationID: "op-1", OrgID: testOrgID, Initiator: "user-1",
		InitiatorKind: string(agentloop.SubjectHuman), Server: "github", Tool: "t",
		ArgsDigest: "aa11", State: agentloop.ApprovalApproved,
		Outcome: &outcome, Approver: &approver, DecidedAt: &decidedAt,
		TTLSecs: 900, ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
	}
	s := lazyStore(t, ctx)
	s.queryRow = func(ctx context.Context, sql string, args ...any) pgx.Row {
		return approvalStubRow(t, decided)
	}
	s.exec = func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
		t.Error("a decision on an already-resolved row must not run any UPDATE")
		return pgconn.CommandTag{}, nil
	}

	rec, err := s.Decision(ctx, agentloop.ApprovalDecision{ApprovalID: "a-1", Outcome: agentloop.DecisionApproved, Approver: "human-2"})
	require.ErrorIs(t, err, ErrNotPending,
		"a duplicate decision resolves once: nothing flips, the resolution is reported")
	require.Equal(t, agentloop.ApprovalApproved, rec.State)
	require.NotNil(t, rec.Decision)
	require.Equal(t, "human-2", rec.Decision.Approver)
}

func TestDecision_UnknownIDIsNotFound(t *testing.T) {
	ctx := context.Background()
	s := lazyStore(t, ctx)
	s.queryRow = func(ctx context.Context, sql string, args ...any) pgx.Row {
		return errRow(pgx.ErrNoRows)
	}
	_, err := s.Decision(ctx, agentloop.ApprovalDecision{ApprovalID: "nope", Outcome: agentloop.DecisionApproved, Approver: "h"})
	require.ErrorIs(t, err, ErrNotFound)
	_, err = s.Get(ctx, "nope")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDecision_LateDecisionOnSweptRowIsApprovalExpired(t *testing.T) {
	ctx := context.Background()
	swept := row{
		ID: "a-1", OperationID: "op-1", OrgID: testOrgID, Initiator: "user-1",
		InitiatorKind: string(agentloop.SubjectHuman), Server: "github", Tool: "t",
		ArgsDigest: "aa11", State: agentloop.ApprovalExpired, TTLSecs: 900,
		ExpiresAt: time.Now().UTC().Add(-time.Minute), CreatedAt: time.Now().UTC().Add(-16 * time.Minute),
	}
	s := lazyStore(t, ctx)
	s.queryRow = func(ctx context.Context, sql string, args ...any) pgx.Row {
		return approvalStubRow(t, swept)
	}
	s.exec = func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
		t.Error("a decision on an already-swept row must not run any UPDATE")
		return pgconn.CommandTag{}, nil
	}

	rec, err := s.Decision(ctx, agentloop.ApprovalDecision{ApprovalID: "a-1", Outcome: agentloop.DecisionApproved, Approver: "human-2"})
	require.ErrorIs(t, err, agentloop.ErrApprovalExpired,
		"a late decision is classified ErrApprovalExpired per the SPI (I59)")
	require.Equal(t, agentloop.ApprovalExpired, rec.State,
		"the resulting ApprovalState comes back with the error, either way")
}

func TestRecordFromRow_RoundTrip(t *testing.T) {
	created := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	expires := created.Add(15 * time.Minute)
	decidedAt := created.Add(2 * time.Minute)
	approver := "human-9"
	outcome := string(agentloop.DecisionApproved)

	pending := row{
		ID: "a-1", OperationID: "op-42", OrgID: testOrgID, ProjectID: "proj-1",
		StepIndex: 3, TurnID: "turn-8", Initiator: "agent-7",
		InitiatorKind: string(agentloop.SubjectAgent), Server: "github",
		Tool: "create_issue", ArgsDigest: "aa11", PolicyRef: "tp@5",
		TTLSecs: 900, RequiresDifferentHuman: true,
		State: agentloop.ApprovalPending, ExpiresAt: expires, CreatedAt: created,
	}
	rec := recordFromRow(pending)
	require.Equal(t, "a-1", rec.ApprovalID)
	require.Equal(t, agentloop.ApprovalPending, rec.State)
	req := rec.Request
	require.Equal(t, agentloop.OperationID("op-42"), req.OperationID)
	require.Equal(t, 3, req.StepIndex)
	require.Equal(t, "turn-8", req.TurnID)
	require.Equal(t, "agent-7", req.Initiator)
	require.Equal(t, agentloop.SubjectAgent, req.InitiatorKind)
	require.Equal(t, "github", req.Server)
	require.Equal(t, "create_issue", req.Tool)
	require.Equal(t, "aa11", req.ArgsDigest)
	require.Equal(t, "tp@5", req.PolicyRef)
	require.True(t, req.RequiresDifferentHuman)
	require.Equal(t, 15*time.Minute, req.TTL, "ttl must reconstruct from ttl_secs")
	require.Nil(t, rec.Decision, "pending row must carry no decision")
	require.True(t, rec.ExpiresAt.Equal(expires))

	decided := pending
	decided.State = agentloop.ApprovalApproved
	decided.Outcome = &outcome
	decided.Approver = &approver
	decided.DecidedAt = &decidedAt
	decided.RecheckRequired = true
	rec = recordFromRow(decided)
	require.Equal(t, agentloop.ApprovalApproved, rec.State)
	require.NotNil(t, rec.Decision)
	require.Equal(t, "a-1", rec.Decision.ApprovalID)
	require.Equal(t, agentloop.DecisionApproved, rec.Decision.Outcome)
	require.Equal(t, "human-9", rec.Decision.Approver)
	require.True(t, rec.Decision.DecidedAt.Equal(decidedAt))
	require.True(t, rec.Decision.RecheckRequired)
}

// TestDecisionUpdateSQL_GuardShape pins the guarded statements' WHERE
// clauses hermetically (review B-1 hardening, also closing N-1): the
// terminal decision UPDATE must keep the pending guard, the persisted
// deadline guard and the full immutable binding tuple re-assert, and the
// expiry-fold UPDATE must stay pending-only. Dropping any of these guards
// from the SQL now breaks this test deterministically — teeth that timing
// alone cannot provide. Predicates are matched position-agnostically so
// benign bind renumbering does not weaken the pin.
func TestDecisionUpdateSQL_GuardShape(t *testing.T) {
	flat := func(sql string) string { return strings.Join(strings.Fields(sql), " ") }

	decision := flat(decisionUpdateSQL)
	require.Regexp(t, `^UPDATE approval_operations SET state = \$1, outcome = \$1, approver = \$2, decided_at = now\(\), recheck_required = \$\d+, updated_at = now\(\) WHERE id = \$\d+ AND state = 'pending' AND expires_at > now\(\) AND `, decision,
		"the human decision triple is written by exactly this one statement, guarded by pending + persisted deadline (single DB clock)")
	for _, col := range []string{
		"operation_id", "org_id", "initiator", "initiator_kind",
		"server_name", "tool_name", "args_digest", "policy_ref",
		"requires_different_human",
	} {
		require.Regexp(t, regexp.QuoteMeta(col)+` = \$\d+`, decision,
			"binding column "+col+" must be re-asserted in the terminal WHERE (drift must fail closed)")
	}

	fold := flat(materializeExpiredSQL)
	require.Regexp(t, `^UPDATE approval_operations SET state = 'expired'`, fold)
	require.Regexp(t, ` WHERE id = \$\d+ AND state = 'pending'$`, fold,
		"the expiry fold must never demote a decided or cancelled row")
}
