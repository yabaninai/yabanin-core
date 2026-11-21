//go:build integration

package accounting

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Refuse one supplemental start at a time in PostgreSQL. The primary remains
// independently observable, as do the two distinct supplemental providers.
func TestAccountingEvalgateAdmission(t *testing.T) {
	s := startStand(t)
	premium := startFixture(t, filepath.Join(s.tempDir, "premium"), s.fixtureTok)
	t.Cleanup(premium.stop)
	var evaluatorCalls atomic.Int64
	evaluator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evaluatorCalls.Add(1)
		var body struct{ Model string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Model != "fixture-evaluator" || r.Header.Get("Authorization") != "Bearer evaluator-token" {
			http.Error(w, "incorrect evaluator request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"cheap_quality\":0.5,\"premium_quality\":0.7,\"should_upgrade\":true,\"reason\":\"fixture\"}"}}],"usage":{"prompt_tokens":11,"completion_tokens":3}}`))
	}))
	defer evaluator.Close()

	s.configureEvalgate(t, premium.baseURL(), evaluator.URL)
	s.oracleExec(t, "install optional admission fault", `
		CREATE SEQUENCE acc_eval_refusals;
		CREATE FUNCTION acc_eval_refuse() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF (NEW.client_request_id LIKE '%-no-premium' AND NEW.model_requested='fixture-premium') OR
			   (NEW.client_request_id LIKE '%-no-evaluator' AND NEW.model_requested='fixture-evaluator') THEN
				PERFORM nextval('acc_eval_refusals');
				RAISE EXCEPTION 'supplemental admission refused';
			END IF;
			RETURN NEW;
		END $$;
		GRANT USAGE ON SEQUENCE acc_eval_refusals TO yabanin_app;
		CREATE TRIGGER acc_eval_refuse BEFORE INSERT ON request_admissions
		FOR EACH ROW WHEN (NEW.kind='judge') EXECUTE FUNCTION acc_eval_refuse()`)
	primaryStart, premiumStart := s.fixture.Snapshot(), premium.Snapshot()
	for i, tc := range []struct {
		phase                                string
		starts, premiumCalls, evaluatorCalls int
	}{
		{"healthy", 3, 1, 1}, {"no-premium", 1, 1, 1}, {"no-evaluator", 2, 2, 1}, {"restored", 3, 3, 2},
	} {
		phase := tc.phase
		rid := s.reqPrefix + phase
		status, body, err := s.chatFull(t, rid, 30*time.Second, chatOptions{content: "Tell me about AI"})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status, body)
		require.Contains(t, body, fixtureAssistantContent)
		switch phase {
		case "healthy", "restored":
			requireEventually(t, time.Minute, 100*time.Millisecond, func() bool {
				return s.oracleCount(t, "SELECT count(*) FROM evalgate_results WHERE org_id=$1 AND request_id=$2", s.oracleDB.orgID, rid) == 1
			}, "the two observed model calls must produce a verdict for %s", phase)
		default:
			requireEventually(t, time.Minute, 100*time.Millisecond, func() bool {
				return s.oracleCount(t, "SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM acc_eval_refusals") == i
			}, "missing independent admission refusal witness for %s", phase)
		}
		require.Len(t, s.oracleAdmissions(t, rid, s.oracleDB.orgID), tc.starts)
		require.Equal(t, fixtureTotals{arrivals: i + 1, dispatches: i + 1, receipts: i + 1}, s.fixture.Since(primaryStart))
		require.Equal(t, fixtureTotals{arrivals: tc.premiumCalls, dispatches: tc.premiumCalls, receipts: tc.premiumCalls}, premium.Since(premiumStart))
		require.EqualValues(t, tc.evaluatorCalls, evaluatorCalls.Load())
	}
	require.Zero(t, s.oracleCount(t, "SELECT count(*) FROM evalgate_results WHERE org_id=$1 AND request_id IN ($2,$3)", s.oracleDB.orgID, s.reqPrefix+"no-premium", s.reqPrefix+"no-evaluator"))
	premium.VerifyEvidence()
	s.fixture.VerifyEvidence()
}

func (s *stand) configureEvalgate(t *testing.T, premiumURL, evaluatorURL string) {
	t.Helper()
	s.stopProc("gateway", s.gatewayCmd)
	s.gatewayCmd = nil
	s.oracleExec(t, "isolate fixture tiers", "UPDATE models_registry SET enabled=false WHERE model_name<>$1", s.model)
	s.oracleExec(t, "assign primary to medium tier", "UPDATE models_registry SET tier_pool='{medium}' WHERE model_name=$1", s.model)
	s.oracleExec(t, "register isolated premium tier", `INSERT INTO models_registry
		(model_name,display_name,tier,provider,upstream_url,upstream_api_key,tier_pool,enabled)
		SELECT 'fixture-premium','fixture premium',tier,provider,$2,upstream_api_key,'{hard}',true
		FROM models_registry WHERE model_name=$1`, s.model, premiumURL)
	s.gatewayEnv = append(s.gatewayEnv, "YABANIN_EVALGATE_URL="+evaluatorURL, "YABANIN_EVALGATE_MODEL=fixture-evaluator", "YABANIN_EVALGATE_API_KEY=evaluator-token", "YABANIN_EVALGATE_SAMPLE_RATE=1")
	s.restartGateway()
}
