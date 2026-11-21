//go:build integration

package accounting

import (
	"context"
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Both cuts happen after the paid provider has returned known usage. Only
// the selected gateway database session is interrupted. Its transaction
// rolls back in the first cut and is independently visible in the second.
func TestAccountingTerminalConnectionLoss(t *testing.T) {
	s := startStand(t)
	relay, dsn := s.installGatewayAckRelay(t)
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	defer db.Close()
	sibling, err := db.Conn(t.Context())
	require.NoError(t, err)
	defer sibling.Close()
	require.NoError(t, sibling.PingContext(t.Context()))
	s.controlRequest(t, "terminal-transport-pre")
	s.oracleExec(t, "install selected terminal insert barrier", `
		CREATE TABLE acc_terminal_transport_target (rid text PRIMARY KEY, change_facts boolean NOT NULL);
		CREATE FUNCTION acc_hold_terminal() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF EXISTS (SELECT 1 FROM acc_terminal_transport_target WHERE rid=NEW.client_request_id) THEN
				PERFORM pg_advisory_xact_lock(1921,113);
				IF (SELECT change_facts FROM acc_terminal_transport_target WHERE rid=NEW.client_request_id) THEN
					NEW.event := jsonb_set(NEW.event, '{ts}', to_jsonb(((NEW.event->>'ts')::bigint + 1)::text));
				END IF;
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER acc_hold_terminal BEFORE INSERT ON request_terminal_facts
		FOR EACH ROW EXECUTE FUNCTION acc_hold_terminal()`)
	start := s.fixture.Snapshot()
	modes := []string{"forward", "before-commit", "after-commit", "divergent"}
	for _, mode := range modes {
		rid := s.reqPrefix + "terminal-" + mode
		s.exerciseTerminalTransport(t, relay, sibling, rid, mode)
	}
	s.controlRequest(t, "terminal-transport-post")
	s.requireGroupDrainedWithin(t, s.redisClient(t), 2*time.Minute)
	for _, mode := range modes {
		s.verifyTerminalTransport(t, s.reqPrefix+"terminal-"+mode)
	}
	require.Equal(t, fixtureTotals{5, 5, 5}, s.fixture.Since(start))
	s.fixture.VerifyEvidence()
}

func (s *stand) exerciseTerminalTransport(t *testing.T, relay *ackRelay, sibling *sql.Conn, rid, mode string) {
	t.Helper()
	s.oracleExec(t, "select terminal transport target", "INSERT INTO acc_terminal_transport_target VALUES ($1,$2)", rid, mode == "divergent")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	lock, err := s.oracleDB.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer lock.Rollback()
	_, err = lock.ExecContext(ctx, "SELECT pg_advisory_xact_lock(1921,113)")
	require.NoError(t, err)
	result := make(chan ackResponse, 1)
	done := make(chan struct{})
	go func() { defer close(done); result <- s.ackRequest(ctx, rid) }()
	defer func() { cancel(); <-done }()
	var pid uint32
	requireEventually(t, 8*time.Second, 10*time.Millisecond, func() bool {
		return s.oracleDB.db.QueryRowContext(ctx, `SELECT l.pid FROM pg_locks l JOIN pg_stat_activity a USING(pid)
			WHERE a.application_name='acceptance_ack_gateway' AND l.locktype='advisory'
			AND l.classid=1921 AND l.objid=113 AND NOT l.granted`).Scan(&pid) == nil && pid > 0
	}, "gateway did not reach the scoped terminal insert")
	a, d, r := s.fixture.Counts(rid)
	require.Equal(t, []int{1, 1, 1}, []int{a, d, r})
	require.Zero(t, s.oracleTerminalFactsCount(t, rid, s.oracleDB.orgID))
	before := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
	require.Len(t, before, 1)
	var cutAt time.Time
	if mode == "before-commit" {
		var killed bool
		require.NoError(t, s.oracleDB.db.QueryRowContext(ctx, "SELECT pg_terminate_backend($1, 1000)", pid).Scan(&killed))
		require.True(t, killed)
		require.NoError(t, lock.Commit())
	} else {
		cut := relay.arm(pid)
		require.NoError(t, lock.Commit())
		select {
		case command := <-cut.held:
			require.Equal(t, "COMMIT", command)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		require.Equal(t, 1, s.oracleTerminalFactsCount(t, rid, s.oracleDB.orgID))
		require.Empty(t, result, "client completed before commit acknowledgment")
		cut.forward <- mode == "forward"
		if mode != "forward" {
			select {
			case cutAt = <-cut.discarded:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
	}
	require.NoError(t, sibling.PingContext(ctx))
	resp := <-result
	require.NoError(t, resp.err)
	require.False(t, resp.at.IsZero())
	require.False(t, resp.at.Before(cutAt))
	s.requireTerminalTransportResponse(t, rid, mode, resp)
	s.verifyTerminalTransport(t, rid)
	after := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
	require.Len(t, after, 1)
	require.Equal(t, before[0].InvocationID, after[0].InvocationID)
}

// Once the acknowledgment is lost, a fresh connection can verify the actual
// committed row. Opposite payload controls must yield opposite client outcomes.
func (s *stand) requireTerminalTransportResponse(t *testing.T, rid, mode string, resp ackResponse) {
	t.Helper()
	if mode == "divergent" {
		require.GreaterOrEqual(t, resp.status, 500, resp.body)
		code, ok := decodeErrorCode(resp.body)
		require.True(t, ok)
		require.Equal(t, "accounting_commit_failed", code)
		return
	}
	require.Equal(t, http.StatusOK, resp.status, resp.body)
	require.Contains(t, resp.body, fixtureAssistantContent)
	require.Equal(t, 1, s.oracleTerminalFactsCount(t, rid, s.oracleDB.orgID))
}

func (s *stand) verifyTerminalTransport(t *testing.T, rid string) {
	t.Helper()
	org := s.oracleDB.orgID
	requireEventually(t, 90*time.Second, 200*time.Millisecond, func() bool {
		return s.oracleCreditTotals(t, rid, org).UsageRows > 0
	}, "known post-dispatch usage did not settle after socket fault")
	id := s.requireUUIDKeyedCharge(t, rid, org, "terminal transport")
	require.Equal(t, 1, s.oracleCount(t, `SELECT count(*) FROM request_admissions a
		JOIN request_terminal_facts f USING (invocation_id,org_id,client_request_id)
		JOIN request_logs l ON l.invocation_id=a.invocation_id AND l.request_id=a.client_request_id AND l.org_id::text=a.org_id
		WHERE a.invocation_id=$1::uuid AND a.org_id=$2 AND a.client_request_id=$3 AND a.state='reconciled'
		AND f.event->>'tokens_in'='7' AND f.event->>'tokens_out'='3' AND l.tokens_in=7 AND l.tokens_out=3`, id, org, rid))
	require.Equal(t, 1, s.oracleRequestLogCount(t, rid, org))
	a, d, r := s.fixture.Counts(rid)
	require.Equal(t, []int{1, 1, 1}, []int{a, d, r})
}
