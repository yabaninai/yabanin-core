//go:build integration

package accounting

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A serialization failure aborts the first terminal INSERT after the
// provider supplied known usage. Recovery must retry the accounting write
// under the original invocation without calling the provider again.
func TestAccountingTransientTerminalWrite(t *testing.T) {
	s := startStand(t)
	org := s.oracleDB.orgID
	rid := s.reqPrefix + "terminal-write-retry"
	s.assertWalletConfigured(t, org, "terminal fault pre-control")
	s.controlRequest(t, "terminal-fault-pre")
	s.armTransientTerminalWrite(t, rid)

	before := s.fixture.Snapshot()
	status, body, err := s.chat(t, rid, 45*time.Second)
	require.NoError(t, err)
	attempts := func() int {
		return s.oracleCount(t, "SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM acc_terminal_attempts")
	}
	require.Positive(t, attempts(), "the terminal insert fault never fired")
	delta := s.fixture.Since(before)
	require.EqualValues(t, 1, delta.arrivals)
	require.EqualValues(t, 1, delta.dispatches)
	require.EqualValues(t, 1, delta.receipts)
	if status == http.StatusOK {
		require.Contains(t, body, fixtureAssistantContent)
		require.Equal(t, 1, s.oracleTerminalFactsCount(t, rid, org), "success returned without durable terminal usage")
	} else {
		require.GreaterOrEqual(t, status, http.StatusInternalServerError)
		var envelope errorEnvelope
		require.NoError(t, json.Unmarshal([]byte(body), &envelope))
		require.NotEmpty(t, envelope.Error.Message)
	}
	requireEventually(t, 2*time.Minute, 200*time.Millisecond, func() bool {
		return attempts() >= 2 && s.oracleCreditTotals(t, rid, org).UsageRows > 0
	}, "known terminal usage must survive the failed insert and settle")
	verify := func() {
		admissions := s.oracleAdmissions(t, rid, org)
		require.Len(t, admissions, 1)
		id := admissions[0].InvocationID
		require.Equal(t, "reconciled", admissions[0].State)
		require.NotEmpty(t, id)
		require.Equal(t, 1, s.oracleCount(t, `SELECT count(*) FROM request_terminal_facts WHERE invocation_id=$1::uuid AND org_id=$2 AND client_request_id=$3 AND event->>'tokens_in'='7' AND event->>'tokens_out'='3'`, id, org, rid))
		require.Equal(t, 1, s.oracleCount(t, `SELECT count(*) FROM request_logs WHERE invocation_id=$1::uuid AND org_id=$2::uuid AND request_id=$3`, id, org, rid))
		require.Equal(t, 1, s.oracleCount(t, `SELECT count(*) FROM credit_transactions WHERE invocation_id=$1::uuid AND org_id=$2 AND request_id=$3 AND type='usage'`, id, org, rid))
		require.Equal(t, 1, s.oracleRequestLogCount(t, rid, org))
		s.requireBilledRow(t, rid, org, "recovered terminal write")
		s.requireWalletChargedExactlyOnce(t, rid, org, "recovered terminal write")
		s.requireWalletIntentPresent(t, rid, org, "recovered terminal write")
		require.Equal(t, 1, s.oracleCount(t, `SELECT count(*) FROM settlement_jobs WHERE invocation_id=$1::uuid AND org_id=$2 AND request_id=$3 AND charge_kind='resale_deduction'`, id, org, rid))
	}
	verify()
	require.Equal(t, delta, s.fixture.Since(before), "provider contacted again while recovering the target")
	s.controlRequest(t, "terminal-fault-post")
	s.requireGroupDrainedWithin(t, s.redisClient(t), 2*time.Minute)
	verify()
	require.Equal(t, fixtureTotals{arrivals: 2, dispatches: 2, receipts: 2}, s.fixture.Since(before), "only target and post-control may reach the provider")
	s.fixture.VerifyEvidence()
	arrivals, dispatches, receipts := s.fixture.Counts(rid)
	require.EqualValues(t, 1, arrivals)
	require.EqualValues(t, 1, dispatches)
	require.EqualValues(t, 1, receipts)
}

func (s *stand) armTransientTerminalWrite(t *testing.T, rid string) {
	t.Helper()
	s.oracleExec(t, "create terminal fault selector", `CREATE TABLE acc_terminal_target (rid text PRIMARY KEY)`)
	s.oracleExec(t, "configure terminal fault selector", `INSERT INTO acc_terminal_target VALUES ($1)`, rid)
	s.oracleExec(t, "create nontransactional attempt witness", `CREATE SEQUENCE acc_terminal_attempts`)
	s.oracleExec(t, "arm terminal fault", `
		CREATE FUNCTION acc_terminal_fault() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF EXISTS (SELECT 1 FROM acc_terminal_target WHERE rid=NEW.client_request_id) THEN
				IF nextval('acc_terminal_attempts')=1 THEN
					RAISE EXCEPTION 'injected terminal write failure' USING ERRCODE='40001';
				END IF;
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER acc_terminal_fault BEFORE INSERT ON request_terminal_facts
		FOR EACH ROW EXECUTE FUNCTION acc_terminal_fault()`)
	t.Cleanup(func() {
		s.oracleExec(t, "remove terminal write fault", `
			DROP TRIGGER acc_terminal_fault ON request_terminal_facts;
			DROP FUNCTION acc_terminal_fault();
			DROP TABLE acc_terminal_target;
			DROP SEQUENCE acc_terminal_attempts`)
	})
}
