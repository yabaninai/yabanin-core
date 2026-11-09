//go:build integration

package consumer

// N01-P02 T06 — THE joint two-org tenant-isolation matrix (the packet
// deliverable). ONE scenario — org A and org B provisioned, each "writing"
// requests through the real worker boundary — asserted at every layer on
// real stands (disposable testdb Postgres + Redis, no mocks):
//
//	worker: one StreamConsumer instance processes A's and B's events; each
//	        request_logs / tool_calls / policy_decisions row lands under its
//	        own org (no cross-tenant envelope mixing); the poison A/B pair
//	        extends the DLQ matrix on the REAL Redis DLQ stream (the previous
//	        A/B DLQ regression used a recording mock; the live test covered a
//	        single strict poison event).
//	db:     A's org-scoped queries never return B rows (explicit org
//	        predicates), and the org_isolation FORCE RLS posture of
//	        policy_decisions is verified under the real application role
//	        (yabanin_app + app.current_org GUC). request_logs carries a
//	        region_isolation RLS policy by design — its org dimension is the
//	        explicit predicate, which this matrix pins at both postures.
//	api:    A's session cannot list/read/export/archive-search B's requests
//	        (the merged n04rights2 explorer endpoints), and the existence
//	        oracle is absent: B's real request id through A's own-org path
//	        returns the byte-identical 404 of a nonexistent id. Negative
//	        packet result: «угаданный ID чужой org не раскрывает данные или
//	        existence».
//	cache:  org-keyed caches are isolated on real Redis + real org policy
//	        rows — A's exact-cache answer is never served to B for the same
//	        prompt, and per-org cache policies never cross-contaminate.
//
// The handlers package is imported TEST-ONLY to drive the real admin API
// surface over the same store; production code in this package never
// imports it (no cycle, verified: handlers does not import loggerd).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/services/admin/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// twoOrgJointTest is the shared provisioning of the ONE joint scenario:
// disposable stands, org A + org B (real store rows, real memberships, real
// signed sessions), and per-org sentinel content so any cross-tenant
// attribution is observable by string search.
type twoOrgJointTest struct {
	ctx      context.Context
	pool     *pgxpool.Pool // region GUC pool the worker delivers through
	appPool  *pgxpool.Pool // yabanin_app role + region GUC (real RLS posture)
	rdb      *redis.Client
	store    *adminstore.Store
	router   http.Handler
	orgA     string
	orgB     string
	cookieA  *http.Cookie // org-admin of A (no role anywhere else)
	reqA     string
	reqB     string
	markerA  string
	markerB  string
	secret   string
	deliverA redis.XMessage
	deliverB redis.XMessage
}

const (
	twoOrgSecret    = "twoorg-joint-test-secret" // #nosec G101 -- test-only HMAC key
	twoOrgSessionA  = "sess-twoorg-joint-a"
	twoOrgSessionB  = "sess-twoorg-joint-b"
	twoOrgToolA     = "to_tool_a_lookup"
	twoOrgToolB     = "to_tool_b_lookup"
	twoOrgPolicyA   = "to-joint-policy-a"
	twoOrgPolicyB   = "to-joint-policy-b"
	twoOrgDLQEntryA = "twoorg-joint-dlq-a"
	twoOrgDLQEntryB = "twoorg-joint-dlq-b"
)

// newTwoOrgJoint provisions the shared scenario. Tests own table cleanup by
// truncating the shared per-binary stand at setup (services/loggerd parity
// with inbox_live_test.go); organizations rows are never truncated (the
// request_logs FK has no CASCADE) — slugs are namespaced per calling test,
// so several two-org tests may share one binary-wide stand.
func newTwoOrgJoint(t *testing.T) *twoOrgJointTest {
	t.Helper()
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "") // legacy env for the happy path; subtests may override

	pool := testdb.PostgresRegion(t, "e2e")
	appPool := testdb.PostgresApp(t, "e2e")
	rdb := testdb.Redis(t)
	creditsIntegrationMu.Lock()
	t.Cleanup(creditsIntegrationMu.Unlock)

	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		TRUNCATE request_logs, sessions, messages, tool_calls, tool_call_invocations,
		         event_inbox, settlement_jobs, policy_decisions CASCADE`)
	require.NoError(t, err)
	require.NoError(t, rdb.FlushDB(ctx).Err())

	// The stand is shared binary-wide: DB-failure suites exercise the wallet
	// error path by dropping org_credits and never recreate it (deductor
	// teardown). The joint scenario needs the REAL production shape —
	// CreateOrganization initializes a wallet inside the same transaction —
	// so restore it (no-op on a healthy stand) before creating orgs.
	_, err = pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS org_credits (
			org_id text PRIMARY KEY,
			balance_cents bigint DEFAULT 0 NOT NULL,
			updated_at timestamptz DEFAULT now() NOT NULL,
			remainder_micro_usd bigint DEFAULT 0 NOT NULL
				CHECK (remainder_micro_usd >= 0 AND remainder_micro_usd < 10000),
			reserved_micro_usd bigint DEFAULT 0 NOT NULL
				CHECK (reserved_micro_usd >= 0),
			grace_floor_cents bigint
				CHECK (grace_floor_cents >= -100000 AND grace_floor_cents <= 0)
		)`)
	require.NoError(t, err)

	slug := "twoorg-joint-" + twoOrgSlugSuffix(t)
	store := adminstore.New(pool, silentLogger(), nil)
	orgA, err := store.CreateOrganization(ctx, "twoorg joint A "+slug, slug+"-a")
	require.NoError(t, err)
	orgB, err := store.CreateOrganization(ctx, "twoorg joint B "+slug, slug+"-b")
	require.NoError(t, err)

	env := &twoOrgJointTest{
		ctx:     ctx,
		pool:    pool,
		appPool: appPool,
		rdb:     rdb,
		store:   store,
		orgA:    orgA.ID,
		orgB:    orgB.ID,
		reqA:    "req-twoorg-joint-a",
		reqB:    "req-twoorg-joint-b",
		markerA: "TWOORG-A JOINT SECRET",
		markerB: "TWOORG-B JOINT SECRET",
		secret:  twoOrgSecret,
	}

	// Org-admin of A only — the actor every cross-org denial is measured on.
	userA, err := store.CreateAdminUser(ctx,
		fmt.Sprintf("twoorg-joint-a-%d@sweep.test", time.Now().UnixNano()),
		"twoorg joint admin A", "integration-hash-not-used-for-login", false)
	require.NoError(t, err)
	_, err = store.CreateOrgMembership(ctx, adminstore.OrgMembership{
		UserID: userA.ID, OrgID: orgA.ID, Role: adminstore.RoleOrgAdmin,
	})
	require.NoError(t, err)
	env.cookieA = twoOrgSessionCookie(t, twoOrgSecret, userA.ID, userA.Email)

	// Each org "writes" its request: the real worker boundary persists the
	// completed event (content sentinels, tool calls, a policy decision).
	env.deliverA = redis.XMessage{ID: "twoorg-joint-a-1",
		Values: twoOrgCompletedEvent(env.reqA, env.orgA, env.markerA, twoOrgSessionA, twoOrgToolA, twoOrgPolicyA)}
	env.deliverB = redis.XMessage{ID: "twoorg-joint-b-1",
		Values: twoOrgCompletedEvent(env.reqB, env.orgB, env.markerB, twoOrgSessionB, twoOrgToolB, twoOrgPolicyB)}

	h := handlers.New(store, twoOrgSecret, "twoorg.test", []string{})
	t.Cleanup(h.Stop)
	env.router = h.SetupRouter()
	return env
}

// twoOrgSlugSuffix renders a slug-safe, per-test suffix so several two-org
// tests can share the binary-wide stand whose organizations rows are never
// truncated (slug is unique; the calling test's name is unique per binary).
func twoOrgSlugSuffix(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, r := range strings.ToLower(t.Name()) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	s := b.String()
	if len(s) > 40 {
		s = s[len(s)-40:]
	}
	return s
}

// twoOrgSessionCookie signs a real admin session cookie for a seeded user
// (the router's TP-02 revalidation resolves it through the real store).
func twoOrgSessionCookie(t *testing.T, secret, userID, email string) *http.Cookie {
	t.Helper()
	cookie, err := adminauth.CreateAdminSessionCookie(adminauth.AdminSession{
		UserID: userID, Email: email, IsRoot: false,
		SessionID: "twoorg-" + userID, ExpiresAt: time.Now().Add(time.Hour),
	}, secret)
	require.NoError(t, err)
	return cookie
}

// twoOrgCompletedEvent builds a producer-wire request.completed event: full
// content captures carrying the org's sentinel, a per-org tool call in the
// upstream sample, a per-org policy decision, and a malformed supplied
// digest (the delivery recomputes it — see the content-profile contract).
func twoOrgCompletedEvent(requestID, orgID, marker, session, tool, policyID string) map[string]interface{} {
	return map[string]interface{}{
		"event_type":         "request.completed",
		"source":             "gateway",
		"ts":                 "1759800000000",
		"request_id":         requestID,
		"org_id":             orgID,
		"session_id":         session,
		"model_requested":    "gpt-5-mini",
		"model_used":         "gpt-5",
		"upstream_url":       "https://api.anthropic.com/v1/messages",
		"method":             "POST",
		"status_code":        "200",
		"duration_ms":        "321",
		"tokens_in":          "11",
		"tokens_out":         "7",
		"estimated_cost_usd": "0.0125",
		"payload":            marker + " PROMPT BODY",
		"upstream_payload":   marker + " UPSTREAM REQUEST",
		"upstream_response": fmt.Sprintf(
			`{"choices":[{"message":{"content":%q,"tool_calls":[{"function":{"name":%q,"arguments":"{}"}}]}}]}`,
			marker+" COMPLETION", tool),
		"error":       marker + " ERROR TEXT",
		"prompt_hash": "definitely-not-a-valid-digest",
		"labels":      `{"lane":"n01p2c"}`,
		"policy": fmt.Sprintf(
			`[{"policy_id":%q,"version":1,"mode":"enforce","verdict":"allow","duration_ms":2}]`, policyID),
	}
}

// twoOrgDeliver runs one message through the real worker boundary and fails
// the test unless the row landed (handleMessage retries/DLQs internally, so
// the persisted row IS the success signal).
func twoOrgDeliver(t *testing.T, env *twoOrgJointTest, c *StreamConsumer, msg redis.XMessage, requestID string) {
	t.Helper()
	c.handleMessage(env.ctx, msg)
	var orgID string
	require.NoError(t, env.pool.QueryRow(env.ctx,
		"SELECT org_id::text FROM request_logs WHERE request_id = $1", requestID).Scan(&orgID),
		"request_logs row must exist for %s", requestID)
	require.Equal(t, msg.Values["org_id"], orgID, "row must land under the event's declared org")
}

// twoOrgRowJSON returns the full stored row as decoded JSON for sentinel
// searches (string-search over the whole row catches ANY column mixing).
func twoOrgRowJSON(t *testing.T, env *twoOrgJointTest, requestID string) map[string]interface{} {
	t.Helper()
	var raw []byte
	require.NoError(t, env.pool.QueryRow(env.ctx,
		"SELECT row_to_json(rl.*) FROM request_logs rl WHERE request_id = $1", requestID).Scan(&raw))
	var row map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &row))
	return row
}

// twoOrgGetFull runs one API probe through the real router and returns
// code+body plus the response header map (the no-oracle comparison pins the
// header maps too — a distinguishing header would be the same oracle over a
// side channel).
func twoOrgGetFull(t *testing.T, env *twoOrgJointTest, path string, cookie *http.Cookie) (int, string, http.Header) {
	t.Helper()
	req := httptest.NewRequestWithContext(env.ctx, http.MethodGet, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	return w.Code, w.Body.String(), w.Header()
}

// twoOrgGet runs one API probe through the real router and returns code+body.
func twoOrgGet(t *testing.T, env *twoOrgJointTest, path string, cookie *http.Cookie) (int, string) {
	code, body, _ := twoOrgGetFull(t, env, path, cookie)
	return code, body
}

// TestTwoOrg_JointIsolationMatrix is the T06 deliverable: one scenario,
// four layers, real stands. Subtests are sequential — each layer asserts on
// the state the previous one produced.
func TestTwoOrg_JointIsolationMatrix(t *testing.T) {
	env := newTwoOrgJoint(t)

	// ── worker: one consumer, A then B, no cross-tenant mixing. ──────────
	t.Run("worker", func(t *testing.T) {
		// The production consumer wiring (run.Loggerd): the original-text
		// retention store rides on the consumer, and an OPTED-IN org keeps
		// original captures — the fail-closed default would strip the
		// upstream sample before tool-call extraction (N02-P06 contract),
		// so the fixture opts both orgs in through the real store.
		on := true
		require.NoError(t, env.store.UpdateOrgOriginalRetention(env.ctx, env.orgA, &on))
		require.NoError(t, env.store.UpdateOrgOriginalRetention(env.ctx, env.orgB, &on))
		c := New(NewRedisOps(env.rdb), NewDBOps(env.pool), "events:queue", silentLogger())
		c.SetOriginalRetentionStore(AdminOriginalRetentionStore{Store: env.store})
		twoOrgDeliver(t, env, c, env.deliverA, env.reqA)
		twoOrgDeliver(t, env, c, env.deliverB, env.reqB)

		rowA := twoOrgRowJSON(t, env, env.reqA)
		rowB := twoOrgRowJSON(t, env, env.reqB)
		assert.Equal(t, env.orgA, rowA["org_id"], "worker keeps A's attribution on A's event")
		assert.Equal(t, env.orgB, rowB["org_id"], "worker keeps B's attribution on B's event")
		bodyA, err := json.Marshal(rowA)
		require.NoError(t, err)
		bodyB, err := json.Marshal(rowB)
		require.NoError(t, err)
		assert.NotContains(t, string(bodyA), env.markerB, "A's row must never carry B's content sentinel")
		assert.NotContains(t, string(bodyB), env.markerA, "B's row must never carry A's content sentinel")

		// Tool-call attribution: the per-org tool names land under the
		// event's own org — one worker, no mixing.
		var toolOrgA, toolNameA string
		require.NoError(t, env.pool.QueryRow(env.ctx,
			"SELECT org_id::text, tool_name FROM tool_calls WHERE request_id = $1", env.reqA).
			Scan(&toolOrgA, &toolNameA))
		assert.Equal(t, env.orgA, toolOrgA)
		assert.Equal(t, twoOrgToolA, toolNameA)
		var toolOrgB, toolNameB string
		require.NoError(t, env.pool.QueryRow(env.ctx,
			"SELECT org_id::text, tool_name FROM tool_calls WHERE request_id = $1", env.reqB).
			Scan(&toolOrgB, &toolNameB))
		assert.Equal(t, env.orgB, toolOrgB)
		assert.Equal(t, twoOrgToolB, toolNameB)

		// Policy decisions commit with the log, under the event's own org.
		decisionsA, totalA, err := env.store.ListPolicyDecisions(env.ctx, env.orgA, adminstore.PolicyDecisionFilters{})
		require.NoError(t, err)
		require.EqualValues(t, 1, totalA, "A's policy log holds exactly A's decision")
		assert.Equal(t, twoOrgPolicyA, decisionsA[0].PolicyID)
		assert.Equal(t, env.reqA, decisionsA[0].RequestID)
		decisionsB, totalB, err := env.store.ListPolicyDecisions(env.ctx, env.orgB, adminstore.PolicyDecisionFilters{})
		require.NoError(t, err)
		require.EqualValues(t, 1, totalB)
		assert.Equal(t, twoOrgPolicyB, decisionsB[0].PolicyID)
		assert.Equal(t, env.reqB, decisionsB[0].RequestID)
	})

	// ── db: org-scoped store queries + the real RLS posture. ─────────────
	t.Run("db", func(t *testing.T) {
		// Explicit org predicates: A's queries never return B rows and vice
		// versa, at list, filter and detail granularity.
		rowsA, totalA, err := env.store.ListRequests(env.ctx, adminstore.RequestListFilters{OrgID: env.orgA})
		require.NoError(t, err)
		require.EqualValues(t, 1, totalA)
		assert.Equal(t, env.reqA, rowsA[0].RequestID)
		rowsB, totalB, err := env.store.ListRequests(env.ctx, adminstore.RequestListFilters{OrgID: env.orgB})
		require.NoError(t, err)
		require.EqualValues(t, 1, totalB)
		assert.Equal(t, env.reqB, rowsB[0].RequestID)

		_, totalFiltered, err := env.store.ListRequests(env.ctx, adminstore.RequestListFilters{
			OrgID: env.orgA, RequestID: env.reqB, PayloadAuthorizationSet: true,
		})
		require.NoError(t, err)
		assert.Zero(t, totalFiltered, "A's org predicate must exclude B's request id")

		orgWide := adminstore.WithRequestPayloadAccess(env.ctx,
			adminstore.RequestPayloadAccess{OrgWideMetadata: true})
		_, err = env.store.GetRequestDetail(orgWide, env.orgA, env.reqB)
		assert.ErrorIs(t, err, adminstore.ErrNotFound,
			"B's request id through A's org scope is indistinguishable from a missing row")
		_, err = env.store.GetRequestDetail(orgWide, env.orgB, env.reqA)
		assert.ErrorIs(t, err, adminstore.ErrNotFound)

		// policy_decisions: statement-level org scope (same as above)…
		_, pdTotal, err := env.store.ListPolicyDecisions(env.ctx, env.orgA, adminstore.PolicyDecisionFilters{})
		require.NoError(t, err)
		assert.EqualValues(t, 1, pdTotal, "A's policy log never contains B's rows")

		// …and the FORCE RLS posture under the REAL application role:
		// yabanin_app sees nothing without the org GUC, and only the pinned
		// org's rows with it. The GUC is reset before the connection returns
		// to the shared pool.
		conn, err := env.appPool.Acquire(env.ctx)
		require.NoError(t, err)
		// Reset the org GUC BEFORE the connection returns to the shared
		// pool: a lingering pin would change what the next borrower sees.
		defer func() {
			_, _ = conn.Exec(env.ctx, "SELECT set_config('app.current_org', '', false)")
			conn.Release()
		}()

		var visible int
		require.NoError(t, conn.QueryRow(env.ctx, "SELECT count(*) FROM policy_decisions").Scan(&visible))
		assert.Zero(t, visible, "application role without the org GUC sees zero policy rows (FORCE RLS)")
		require.NoError(t, pinOrgGUC(env.ctx, conn, env.orgA))
		require.NoError(t, conn.QueryRow(env.ctx, "SELECT count(*) FROM policy_decisions").Scan(&visible))
		assert.Equal(t, 1, visible, "org A GUC reveals exactly A's policy row")
		require.NoError(t, pinOrgGUC(env.ctx, conn, env.orgB))
		require.NoError(t, conn.QueryRow(env.ctx, "SELECT count(*) FROM policy_decisions").Scan(&visible))
		assert.Equal(t, 1, visible, "org B GUC reveals exactly B's policy row")

		// request_logs under the application role: the explicit org
		// predicate scopes at the app posture too (region RLS is separate by
		// design and covered by the regionrouter suites).
		var appOrgA, appOrgB int
		require.NoError(t, env.pool.QueryRow(env.ctx,
			"SELECT count(*) FROM request_logs WHERE org_id = $1::uuid", env.orgA).Scan(&appOrgA))
		require.NoError(t, env.pool.QueryRow(env.ctx,
			"SELECT count(*) FROM request_logs WHERE org_id = $1::uuid", env.orgB).Scan(&appOrgB))
		require.Equal(t, 1, appOrgA)
		require.Equal(t, 1, appOrgB)
		var appVisible int
		require.NoError(t, conn.QueryRow(env.ctx,
			"SELECT count(*) FROM request_logs WHERE org_id = $1::uuid", env.orgA).Scan(&appVisible))
		assert.Equal(t, 1, appVisible, "application role + org predicate sees A's row")
		require.NoError(t, pinOrgGUC(env.ctx, conn, env.orgB))
		require.NoError(t, conn.QueryRow(env.ctx,
			"SELECT count(*) FROM request_logs WHERE org_id = $1::uuid", env.orgB).Scan(&appVisible))
		assert.Equal(t, 1, appVisible, "application role + org predicate sees B's row")
	})

	// ── api: A's session against every B explorer route + the oracle. ────
	t.Run("api", func(t *testing.T) {
		// Foreign-org routes: the RequireOrgPermission gate denies A's
		// member on every explorer surface with exactly 403.
		for _, tc := range []struct{ name, path string }{
			{"list", "/api/organizations/" + env.orgB + "/requests"},
			{"detail", "/api/organizations/" + env.orgB + "/requests/" + env.reqB},
			{"export", "/api/organizations/" + env.orgB + "/requests/export"},
			{"archive-search", "/api/organizations/" + env.orgB + "/requests/archive-search"},
			{"stats", "/api/organizations/" + env.orgB + "/requests/stats"},
		} {
			t.Run("foreign org "+tc.name+" is 403", func(t *testing.T) {
				code, body := twoOrgGet(t, env, tc.path, env.cookieA)
				require.Equal(t, http.StatusForbidden, code, "body: %s", body)
				assert.NotContains(t, body, env.reqB, "deny body must not carry B's request id")
				assert.NotContains(t, body, env.markerB)
			})
		}

		// Positive control on A's own org: the gate passes and the payload
		// stays scoped — B's ids/sentinels are absent everywhere.
		code, body := twoOrgGet(t, env, "/api/organizations/"+env.orgA+"/requests", env.cookieA)
		require.Equal(t, http.StatusOK, code, "body: %s", body)
		assert.Contains(t, body, env.reqA)
		assert.NotContains(t, body, env.reqB)
		assert.NotContains(t, body, env.markerB)

		// IDOR query probe: B's request id as the exact filter on A's list.
		code, body = twoOrgGet(t, env,
			"/api/organizations/"+env.orgA+"/requests?request_id="+env.reqB, env.cookieA)
		require.Equal(t, http.StatusOK, code)
		assert.NotContains(t, body, env.reqB, "org predicate outranks a guessed request id")

		// A's own detail: metadata only (payloads need ownership or a
		// grant), and never any B identifier or sentinel.
		code, body = twoOrgGet(t, env, "/api/organizations/"+env.orgA+"/requests/"+env.reqA, env.cookieA)
		require.Equal(t, http.StatusOK, code, "body: %s", body)
		assert.Contains(t, body, env.reqA)
		assert.NotContains(t, body, env.reqB)
		assert.NotContains(t, body, env.markerA, "org-wide metadata view redacts payload content")
		assert.NotContains(t, body, env.markerB)

		// Existence oracle absent: B's REAL request id through A's own-org
		// path and a fabricated id return the byte-identical 404 shape —
		// bodies and full response header maps alike.
		codeReal, bodyReal, hdrReal := twoOrgGetFull(t, env,
			"/api/organizations/"+env.orgA+"/requests/"+env.reqB, env.cookieA)
		codeFake, bodyFake, hdrFake := twoOrgGetFull(t, env,
			"/api/organizations/"+env.orgA+"/requests/req-twoorg-does-not-exist", env.cookieA)
		require.Equal(t, http.StatusNotFound, codeReal)
		require.Equal(t, http.StatusNotFound, codeFake)
		assert.Equal(t, bodyFake, bodyReal,
			"a guessed foreign id must be indistinguishable from a nonexistent id")
		assert.Equal(t, hdrFake, hdrReal,
			"the 404 header map must not distinguish a foreign id from a nonexistent one")

		// Export on the own org streams exactly A's record.
		code, body = twoOrgGet(t, env, "/api/organizations/"+env.orgA+"/requests/export", env.cookieA)
		require.Equal(t, http.StatusOK, code, "body: %s", body)
		assert.Equal(t, 1, strings.Count(body, "\n"), "export streams exactly A's one record")
		assert.Contains(t, body, env.reqA)
		assert.NotContains(t, body, env.reqB)
		assert.NotContains(t, body, env.markerB)

		// Archive search shares the list authorization and the org scope.
		code, body = twoOrgGet(t, env,
			"/api/organizations/"+env.orgA+"/requests/archive-search", env.cookieA)
		require.Equal(t, http.StatusOK, code, "body: %s", body)
		assert.Contains(t, body, `"total":1`)
		assert.Contains(t, body, env.reqA)
		assert.NotContains(t, body, env.reqB)
	})

	// ── cache: org-keyed caches never cross on real Redis + real policy. ─
	t.Run("cache", func(t *testing.T) {
		_, err := env.pool.Exec(env.ctx,
			"UPDATE organizations SET cache_enabled = true, cache_mode = 'exact' WHERE id::text = ANY($1)",
			[]string{env.orgA, env.orgB})
		require.NoError(t, err)

		// Redis exact keys: same tier + same prompt hash stay distinct values.
		rs := cache.NewRedisStore(env.rdb, time.Minute)
		require.NoError(t, rs.Put(env.ctx, env.orgA, "tier-joint", "hash-joint", []byte("answer-A")))
		require.NoError(t, rs.Put(env.ctx, env.orgB, "tier-joint", "hash-joint", []byte("answer-B")))
		gotA, err := rs.Get(env.ctx, env.orgA, "tier-joint", "hash-joint")
		require.NoError(t, err)
		assert.Equal(t, "answer-A", string(gotA))
		gotB, err := rs.Get(env.ctx, env.orgB, "tier-joint", "hash-joint")
		require.NoError(t, err)
		assert.Equal(t, "answer-B", string(gotB))
		assert.NotEqual(t, cache.MakeKey(env.orgA, "tier-joint", "hash-joint"),
			cache.MakeKey(env.orgB, "tier-joint", "hash-joint"))

		// Service-level probe with the REAL policy loader: A writes, B must
		// miss — A's cached answer is never served to B for the same prompt.
		cs := cache.NewCacheService(env.ctx, env.pool, env.rdb, nil, silentLogger(), false)
		cs.SetOrgPolicyLoader(cache.NewDBPolicyLoader(env.pool, silentLogger()).LoadOrgPolicy)
		riA := cache.RouteIdentity{OrgID: env.orgA, Model: "tier-joint"}
		riB := cache.RouteIdentity{OrgID: env.orgB, Model: "tier-joint"}
		prompt := []byte(`{"messages":[{"role":"user","content":"joint prompt"}]}`)
		respA := []byte(`{"id":"joint-a","choices":[{"message":{"content":"A ONLY"}}]}`)
		require.NoError(t, cs.Write(env.ctx, riA, prompt, respA, 1, 1))

		hitA, err := cs.LookupWithResult(env.ctx, riA, prompt)
		require.NoError(t, err)
		require.NotNil(t, hitA, "A's own lookup must hit A's entry")
		assert.Equal(t, "exact", hitA.SourceType)
		assert.JSONEq(t, string(respA), string(hitA.Data))

		hitB, err := cs.LookupWithResult(env.ctx, riB, prompt)
		require.NoError(t, err)
		assert.Nil(t, hitB, "B's lookup of A's prompt must MISS — never serve A's answer")

		// Per-org cache policies: B's org row can never disable A's caching.
		pc := cache.NewPolicyCache(time.Minute)
		loader := cache.NewDBPolicyLoader(env.pool, silentLogger()).LoadOrgPolicy
		polA := pc.Get(env.ctx, env.orgA, loader)
		assert.Equal(t, cache.PrivacyEnabled, polA.Mode)
		polB := pc.Get(env.ctx, env.orgB, loader)
		assert.Equal(t, cache.PrivacyEnabled, polB.Mode)
		_, err = env.pool.Exec(env.ctx,
			"UPDATE organizations SET cache_enabled = false WHERE id::text = $1", env.orgB)
		require.NoError(t, err)
		polAfter := pc.Get(env.ctx, env.orgB, loader)
		assert.Equal(t, cache.PrivacyEnabled, polAfter.Mode,
			"the cached B policy is served until invalidated — per-org, never re-read globally")
		pc.Invalidate(env.orgB)
		polInvalidated := pc.Get(env.ctx, env.orgB, loader)
		assert.Equal(t, cache.PrivacyDisabled, polInvalidated.Mode, "B's own invalidation applies to B")
		assert.Equal(t, cache.PrivacyEnabled, pc.Get(env.ctx, env.orgA, loader).Mode,
			"B's disablement must never disable A")
	})

	// ── worker DLQ: poison A/B through the REAL Redis DLQ stream. ────────
	// Legacy profile: envelopes retain payload/error captures, so the
	// cross-reveal check is strong (strict redaction is already pinned by
	// the strict DLQ unit matrix and the single-event live test).
	t.Run("dlq", func(t *testing.T) {
		t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
		poisonOrgA, poisonOrgB := uuid.NewString(), uuid.NewString() // no organizations row → FK violation
		reqDLQA, reqDLQB := "req-twoorg-joint-dlq-a", "req-twoorg-joint-dlq-b"
		markerDLQA, markerDLQB := "TWOORG-A DLQ POISON MARKER", "TWOORG-B DLQ POISON MARKER"

		c := New(NewRedisOps(env.rdb), NewDBOps(env.pool), "events:queue", silentLogger())
		msgA := redis.XMessage{ID: twoOrgDLQEntryA,
			Values: twoOrgCompletedEvent(reqDLQA, poisonOrgA, markerDLQA, twoOrgSessionA, twoOrgToolA, twoOrgPolicyA)}
		msgB := redis.XMessage{ID: twoOrgDLQEntryB,
			Values: twoOrgCompletedEvent(reqDLQB, poisonOrgB, markerDLQB, twoOrgSessionB, twoOrgToolB, twoOrgPolicyB)}

		// Real retry loop: only the attempt past maxRetries archives.
		for i := 0; i <= maxRetries; i++ {
			c.handleMessage(env.ctx, msgA)
		}
		for i := 0; i <= maxRetries; i++ {
			c.handleMessage(env.ctx, msgB)
		}

		fieldsA, envA := twoOrgFindDLQEnvelope(t, env.rdb, reqDLQA)
		fieldsB, envB := twoOrgFindDLQEnvelope(t, env.rdb, reqDLQB)

		// Each envelope keeps its OWN tenant identity.
		assert.Equal(t, poisonOrgA, envA.Values["org_id"])
		assert.Equal(t, reqDLQA, envA.Values["request_id"])
		assert.Equal(t, twoOrgDLQEntryA, envA.EntryID)
		assert.Equal(t, poisonOrgB, envB.Values["org_id"])
		assert.Equal(t, reqDLQB, envB.Values["request_id"])
		assert.Equal(t, twoOrgDLQEntryB, envB.EntryID)

		// No cross-tenant envelope mixing: A's markers only in A's archive.
		payloadA, _ := fieldsA["payload"].(string)
		payloadB, _ := fieldsB["payload"].(string)
		assert.Contains(t, payloadA, markerDLQA, "legacy archive keeps A's own captures for replay")
		assert.NotContains(t, payloadA, markerDLQB, "A's envelope must never carry B's content")
		assert.NotContains(t, payloadA, reqDLQB)
		assert.Contains(t, payloadB, markerDLQB)
		assert.NotContains(t, payloadB, markerDLQA, "B's envelope must never carry A's content")
		assert.NotContains(t, payloadB, reqDLQA)

		// Exactly one DLQ entry per poisoned event on the shared stream.
		msgs, err := env.rdb.XRange(env.ctx, dlqStreamName, "-", "+").Result()
		require.NoError(t, err)
		countA, countB := 0, 0
		for _, m := range msgs {
			payload, _ := m.Values["payload"].(string)
			countA += strings.Count(payload, reqDLQA)
			countB += strings.Count(payload, reqDLQB)
		}
		assert.Equal(t, 1, countA, "exactly one archived envelope for A's poison event")
		assert.Equal(t, 1, countB, "exactly one archived envelope for B's poison event")
	})
}

// twoOrgFindDLQEnvelope mirrors cprFindDLQEnvelope: the flat DLQ fields and
// the decoded envelope of the entry whose structured payload carries the
// given unique request id.
func twoOrgFindDLQEnvelope(t *testing.T, rdb *redis.Client, requestID string) (map[string]interface{}, eventpublisher.DLQEnvelope) {
	t.Helper()
	msgs, err := rdb.XRange(context.Background(), dlqStreamName, "-", "+").Result()
	require.NoError(t, err, "XRANGE over the DLQ stream")
	for _, m := range msgs {
		payload, _ := m.Values["payload"].(string)
		var env eventpublisher.DLQEnvelope
		if json.Unmarshal([]byte(payload), &env) != nil {
			continue
		}
		if env.Values["request_id"] == requestID {
			return m.Values, env
		}
	}
	t.Fatalf("no DLQ entry found for request %s", requestID)
	return nil, eventpublisher.DLQEnvelope{}
}

// pinOrgGUC pins app.current_org for the RLS probes on one acquired
// application-role connection.
func pinOrgGUC(ctx context.Context, conn *pgxpool.Conn, orgID string) error {
	_, err := conn.Exec(ctx, "SELECT set_config('app.current_org', $1, false)", orgID)
	return err
}
