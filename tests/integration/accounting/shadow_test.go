//go:build integration

package accounting

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Two independent provider ledgers distinguish a refused mirror from a mirror
// accidentally dispatched under the primary request's admission.
func TestAccountingShadowAdmission(t *testing.T) {
	s := startStand(t)
	s.controlRequest(t, "before-shadow")
	mirror := startFixture(t, filepath.Join(s.tempDir, "shadow"), s.fixtureTok)
	t.Cleanup(mirror.stop)
	model := "shadow-" + s.runID
	s.oracleExec(t, "seed mirror model", `INSERT INTO models_registry(model_name,display_name,upstream_url) VALUES ($1,$1,$2)`, model, mirror.baseURL())
	s.stopProc("gateway", s.gatewayCmd)
	s.gatewayCmd = nil
	s.gatewayEnv = append(s.gatewayEnv, "YABANIN_SHADOW_ENABLED=true", "YABANIN_SHADOW_MODEL="+model, "YABANIN_SHADOW_SAMPLE_RATE=1", "YABANIN_SHADOW_UPSTREAM_URL="+mirror.baseURL(), "YABANIN_SHADOW_API_KEY="+s.fixtureTok)
	s.restartGateway()
	before := s.fixture.Snapshot()
	chat := func(phase string) string {
		rid := s.reqPrefix + "shadow-" + phase
		status, body, err := s.chatFull(t, rid, 45*time.Second, chatOptions{content: rid})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status, body)
		require.Contains(t, body, fixtureAssistantContent)
		return rid
	}
	pre := chat("pre")
	s.requireSettledShadowPair(t, pre, model)
	s.oracleExec(t, "refuse only mirror admission", `
		CREATE SEQUENCE acc_shadow_refusals;
		CREATE FUNCTION acc_shadow_refuse() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM nextval('acc_shadow_refusals');
			RAISE EXCEPTION 'mirror admission refused';
		END $$;
		CREATE TRIGGER acc_shadow_refuse BEFORE INSERT ON request_admissions
		FOR EACH ROW WHEN (NEW.kind='shadow') EXECUTE FUNCTION acc_shadow_refuse()`)
	target := chat("refused")
	requireEventually(t, time.Minute, 100*time.Millisecond, func() bool {
		return s.oracleCount(t, "SELECT CASE WHEN is_called THEN 1 ELSE 0 END FROM acc_shadow_refusals") == 1
	}, "the detached mirror must reach its own admission barrier")
	require.Equal(t, fixtureTotals{arrivals: 1, dispatches: 1, receipts: 1}, mirror.Snapshot())
	s.oracleExec(t, "restore mirror admission", "DROP TRIGGER acc_shadow_refuse ON request_admissions")
	post := chat("post")
	s.requireSettledShadowPair(t, post, model)
	s.requireGroupDrainedWithin(t, s.redisClient(t), 2*time.Minute)
	s.requireSettledShadowPair(t, pre, model)
	requireEventually(t, time.Minute, 200*time.Millisecond, func() bool {
		return s.oracleCreditTotals(t, target, s.oracleDB.orgID).UsageRows == 1
	}, "the primary must settle despite the mirror refusal")
	s.requireUUIDKeyedCharge(t, target, s.oracleDB.orgID, "primary while mirror refused")
	require.Equal(t, 1, s.oracleRequestLogCount(t, target, s.oracleDB.orgID))
	require.Equal(t, 1, s.oracleTerminalFactsCount(t, target, s.oracleDB.orgID))
	require.Equal(t, fixtureTotals{arrivals: 3, dispatches: 3, receipts: 3}, s.fixture.Since(before))
	require.Equal(t, fixtureTotals{arrivals: 2, dispatches: 2, receipts: 2}, mirror.Snapshot())
	mirror.VerifyEvidence()
	s.fixture.VerifyEvidence()
}

func (s *stand) requireSettledShadowPair(t *testing.T, rid, model string) {
	t.Helper()
	org := s.oracleDB.orgID
	const joined = `SELECT count(*) FROM request_admissions a
		JOIN request_terminal_facts f USING (invocation_id,org_id,client_request_id)
		JOIN request_logs l ON l.invocation_id=a.invocation_id AND l.org_id::text=a.org_id AND l.request_id=a.client_request_id
		WHERE a.org_id=$1 AND a.client_request_id=$2 AND a.state='reconciled'
		AND f.event->>'tokens_in'='7' AND f.event->>'tokens_out'='3'
		AND l.tokens_in=7 AND l.tokens_out=3 AND l.model_used=$3 AND a.kind=$4`
	requireEventually(t, 2*time.Minute, 200*time.Millisecond, func() bool {
		return s.oracleCount(t, joined+" AND l.ab_group='shadow'", org, rid, model, "shadow") == 1 &&
			s.oracleCount(t, joined+" AND l.ab_group IS DISTINCT FROM 'shadow'", org, rid, s.model, "chat") == 1 &&
			s.oracleCreditTotals(t, rid, org).UsageRows > 0
	}, "both paid provider responses must reconcile under their respective UUIDs")
	require.Len(t, s.oracleAdmissions(t, rid, org), 2)
	id, ok := s.oracleQueryRowString(t, "SELECT invocation_id::text FROM request_admissions WHERE org_id=$1 AND client_request_id=$2 AND kind='chat'", org, rid)
	require.True(t, ok)
	c := s.oracleUsageByInvocation(t, id, org)
	require.EqualValues(t, 1, c.UsageRows)
	require.EqualValues(t, -fixtureMicroUSDCost, c.SumMicroUSD)
	s.requireWalletChargedExactlyOnce(t, rid, org, "mirror paired with primary")
	require.Positive(t, s.oracleCount(t, "SELECT count(*) FROM settlement_jobs WHERE invocation_id=$1::uuid AND org_id=$2", id, org))
	require.Zero(t, s.oracleCount(t, "SELECT count(*) FROM settlement_jobs WHERE org_id=$1 AND request_id=$2 AND invocation_id IS DISTINCT FROM $3::uuid", org, rid, id))
}
