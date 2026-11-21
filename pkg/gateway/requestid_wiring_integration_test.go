//go:build integration

package cli

// REQID integration tier — the request-ID contract on the real plumbing:
// real Postgres + real Redis (testdb containers), the REAL production auth
// middleware resolving a real Bearer key against the real api_keys table,
// the REAL event publisher writing to the real stream consumed by the real
// loggerd consumer (accEnsureShared's shared worker), and the REAL
// production middleware chain (newGatewayHTTPRouter — the exact helper
// RunGatewayServerWithJWT mounts), not a test-local chi re-declaration. The
// oracle of record is SQL over request_logs.
//
//	REQID-I1  two orgs, client-supplied IDs: the response echoes the client
//	          ID verbatim, the upstream hop carries the same ID, and each
//	          org's request_logs row carries it — no generated or different
//	          ID counts as success, and neither org sees the other's row.
//	REQID-I2  absent header: an ID is generated (req_ format), echoed,
//	          propagated upstream and persisted under the SAME generated
//	          identity; distinct requests get distinct IDs.
//	REQID-I3  duplicate client ID within one org (the transport side of the
//	          ACC-R3 boundary): every response echoes the ID verbatim, each
//	          request persists its own row, the upstream is called once per
//	          request. The money layer's per-ID dedup stays pinned by the ACC
//	          suite — this change does not touch accounting.
//	REQID-I4  tenant denial is not weakened: an invalid key answers 401
//	          (with the ID still on the response) and persists nothing.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/config"
	eventpublisher "github.com/reireirei/yabanin/pkg/eventpublisher"
)

// reqidIntEnv owns the live pipeline: the shared consumer's pool/redis, the
// recording mock upstream, a gateway mounted on the production middleware
// chain, and a real TCP server.
type reqidIntEnv struct {
	pool *pgxpool.Pool
	rdb  *redis.Client
	gw   *gateway
	srv  *httptest.Server
	up   *reqidRecordingUpstream
	log  *slog.Logger
}

func reqidIntSetup(t *testing.T) *reqidIntEnv {
	t.Helper()
	accEnsureShared(t) // real shared loggerd consumer on the e2e-region Postgres + Redis
	pool, rdb, log := accShared.pool, accShared.rdb, accShared.log

	up := startReqidUpstream(t)
	// budget off: this change must not touch accounting; the ACC suite
	// owns the money-layer behavior.
	gw := newReservationGateway(t, pool, up.srv, budget.ModeOff)
	// Real production auth: resolver-only ("header" mode with no static
	// key), so the org comes from the resolved Bearer key, exactly like a
	// production deployment without static keys.
	gw.auth = NewAuthMiddleware(config.Gateway{AuthMode: "header"},
		auth.NewResolver(pool, rdb, 300, nil))
	gw.publisher = eventpublisher.NewRedisPublisher(rdb, accStream)

	router, _, _ := newGatewayHTTPRouter(gw.cfg, gw.log)
	gw.routes(router)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return &reqidIntEnv{pool: pool, rdb: rdb, gw: gw, srv: srv, up: up, log: log}
}

// reqidNewOrg seeds a real organization (adminstore: org + wallet) with a
// real API key and returns (orgID, plaintextKey).
func reqidNewOrg(t *testing.T, env *reqidIntEnv, suffix string) (string, string) {
	t.Helper()
	ctx := context.Background()
	store := adminstore.New(env.pool, env.log, nil)
	slug := fmt.Sprintf("reqid-%s-%d", suffix, time.Now().UnixNano())
	org, err := store.CreateOrganization(ctx, "REQID "+suffix, slug)
	require.NoError(t, err, "create synthetic org")
	// api_keys.team_id is NOT NULL: every key belongs to a team.
	team, err := store.CreateTeam(ctx, org.ID, "REQID team", slug+"-team", nil)
	require.NoError(t, err, "create synthetic team")
	key, err := auth.GeneratePersonalKey()
	require.NoError(t, err, "generate synthetic API key")
	_, err = store.CreateAPIKey(ctx, auth.HashKey(key), "reqid integration key", &org.ID, &team.ID)
	require.NoError(t, err, "create synthetic API key row")
	return org.ID, key
}

// reqidIntPost drives a real HTTP client POST /v1/chat/completions with the
// given Bearer key and request ID ("" = header absent). Body is drained.
func reqidIntPost(t *testing.T, env *reqidIntEnv, key, requestID string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		env.srv.URL+"/v1/chat/completions",
		strings.NewReader(`{"model":"stub-model","messages":[{"role":"user","content":"hi"}]}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	if requestID != "" {
		req.Header.Set("X-Request-ID", requestID)
	}
	resp, err := env.srv.Client().Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	t.Logf("POST request-id=%q -> %d %s", requestID, resp.StatusCode, body)
	return resp
}

// reqidLogRowsQuiet is the Eventually-safe oracle probe.
func reqidLogRowsQuiet(env *reqidIntEnv, orgID, requestID string) (int, bool) {
	var n int
	err := env.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM request_logs WHERE org_id::text = $1 AND request_id = $2`,
		orgID, requestID).Scan(&n)
	return n, err == nil
}

func reqidLogRows(t *testing.T, env *reqidIntEnv, orgID, requestID string) int {
	t.Helper()
	n, ok := reqidLogRowsQuiet(env, orgID, requestID)
	require.True(t, ok, "count request_logs rows")
	return n
}

// reqidWaitLogRows polls the SQL oracle until exactly `want` rows exist for
// (org, request_id) — the consumer writes asynchronously via the stream.
func reqidWaitLogRows(t *testing.T, env *reqidIntEnv, orgID, requestID string, want int) {
	t.Helper()
	require.Eventually(t, func() bool {
		n, ok := reqidLogRowsQuiet(env, orgID, requestID)
		return ok && n == want
	}, 20*time.Second, 100*time.Millisecond,
		"request_logs rows for org %s / request %s never reached %d", orgID, requestID, want)
}

// reqidGroupPending mirrors accEnv.groupPending: -1 while the consumer
// group does not exist yet.
func reqidGroupPending(rdb *redis.Client) int64 {
	res, err := rdb.XPending(context.Background(), accStream, accConsumerGroup).Result()
	if err != nil {
		return -1
	}
	return res.Count
}

// REQID-I1: two orgs with client-supplied IDs — exact-identity echo,
// upstream propagation and persisted rows, tenant-isolated.
func TestRequestIDWiring_Integration_ClientIDTwoOrgs(t *testing.T) {
	env := reqidIntSetup(t)
	orgA, keyA := reqidNewOrg(t, env, "a")
	orgB, keyB := reqidNewOrg(t, env, "b")
	idA := "reqid-int-a-" + uuid.NewString()[:8]
	idB := "reqid-int-b-" + uuid.NewString()[:8]

	respA := reqidIntPost(t, env, keyA, idA)
	require.Equal(t, http.StatusOK, respA.StatusCode)
	require.Equal(t, idA, respA.Header.Get("X-Request-ID"),
		"org A: the response must echo the client ID verbatim")
	ids := env.up.requestIDs()
	require.NotEmpty(t, ids)
	assert.Equal(t, idA, ids[len(ids)-1], "org A: the upstream hop carries the same ID")
	reqidWaitLogRows(t, env, orgA, idA, 1)

	respB := reqidIntPost(t, env, keyB, idB)
	require.Equal(t, http.StatusOK, respB.StatusCode)
	require.Equal(t, idB, respB.Header.Get("X-Request-ID"),
		"org B: the response must echo the client ID verbatim")
	ids = env.up.requestIDs()
	assert.Equal(t, idB, ids[len(ids)-1], "org B: the upstream hop carries the same ID")
	reqidWaitLogRows(t, env, orgB, idB, 1)

	// Tenant isolation: org A's ID is persisted only under org A.
	require.Equal(t, 1, reqidLogRows(t, env, orgA, idA))
	var foreign int
	require.NoError(t, env.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM request_logs WHERE request_id = $1 AND org_id::text <> $2`,
		idA, orgA).Scan(&foreign))
	assert.Equal(t, 0, foreign, "no other org may own org A's request row")
}

// REQID-I2: absent header — generated identity, same identity echoed,
// propagated upstream and persisted; distinct per request.
func TestRequestIDWiring_Integration_GeneratedWhenAbsent(t *testing.T) {
	env := reqidIntSetup(t)
	org, key := reqidNewOrg(t, env, "gen")

	resp1 := reqidIntPost(t, env, key, "")
	require.Equal(t, http.StatusOK, resp1.StatusCode)
	gen1 := resp1.Header.Get("X-Request-ID")
	require.NotEmpty(t, gen1, "an ID must be generated when the client sends none")
	assert.True(t, strings.HasPrefix(gen1, "req_"), "generated ID format, got %q", gen1)
	ids := env.up.requestIDs()
	require.NotEmpty(t, ids)
	assert.Equal(t, gen1, ids[len(ids)-1], "the upstream hop carries the generated ID")
	reqidWaitLogRows(t, env, org, gen1, 1)

	resp2 := reqidIntPost(t, env, key, "")
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	gen2 := resp2.Header.Get("X-Request-ID")
	require.NotEmpty(t, gen2)
	assert.NotEqual(t, gen1, gen2, "distinct requests must not share a generated ID")
	reqidWaitLogRows(t, env, org, gen2, 1)
}

// REQID-I3: duplicate client ID within one org — transport honors the ID
// verbatim on every response, one upstream call and one persisted row per
// request. Money-layer per-ID dedup is ACC-R3's contract, unchanged here.
func TestRequestIDWiring_Integration_DuplicateClientIDReplay(t *testing.T) {
	env := reqidIntSetup(t)
	org, key := reqidNewOrg(t, env, "dup")
	dup := "reqid-int-dup-" + uuid.NewString()[:8]
	callsBefore := len(env.up.requestIDs())

	r1 := reqidIntPost(t, env, key, dup)
	require.Equal(t, http.StatusOK, r1.StatusCode)
	require.Equal(t, dup, r1.Header.Get("X-Request-ID"))
	r2 := reqidIntPost(t, env, key, dup)
	require.Equal(t, http.StatusOK, r2.StatusCode)
	require.Equal(t, dup, r2.Header.Get("X-Request-ID"),
		"replay: the transport honors the client ID verbatim")

	ids := env.up.requestIDs()
	require.Equal(t, callsBefore+2, len(ids), "one upstream call per request")
	assert.Equal(t, dup, ids[len(ids)-1])
	assert.Equal(t, dup, ids[len(ids)-2])
	reqidWaitLogRows(t, env, org, dup, 2)
}

// REQID-I4: tenant denial — invalid key stays 401 (ID still echoed on the
// response) and persists nothing.
func TestRequestIDWiring_Integration_TenantDenialPersistsNothing(t *testing.T) {
	env := reqidIntSetup(t)
	org, key := reqidNewOrg(t, env, "deny")
	denied := "reqid-int-denied-" + uuid.NewString()[:8]

	resp := reqidIntPost(t, env, "reqid-invalid-key", denied)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "invalid key must stay denied")
	assert.Equal(t, denied, resp.Header.Get("X-Request-ID"), "a denial still carries the request ID")

	// Advance the stream with one accepted request and wait for its row
	// plus a drained consumer group; the denied ID — rejected before the
	// handler, so no event was ever published — must then have no row.
	accepted := "reqid-int-deny-ok-" + uuid.NewString()[:8]
	ok := reqidIntPost(t, env, key, accepted)
	require.Equal(t, http.StatusOK, ok.StatusCode)
	reqidWaitLogRows(t, env, org, accepted, 1)
	require.Eventually(t, func() bool { return reqidGroupPending(env.rdb) == 0 },
		10*time.Second, 100*time.Millisecond, "consumer group never drained")
	assert.Equal(t, 0, reqidLogRows(t, env, org, denied), "a denied request must persist nothing")
}
