package handlers

// DB-backed pins against the REAL adminstore on the disposable
// testcontainers Postgres stand (testdb.Postgres — Docker is required
// outside -short; a missing stand is a hard failure, not a skip):
//
//   - the agent-subject request-DETAIL contract: on DETAIL an agent/CI
//     subject must see 404 — pkg/adminstore/request_detail.go answers
//     ErrNotFound for a subject that is not human without a verified grant
//     or org-wide metadata (the same no-existence-oracle shape as
//     cross-org; PRODUCT-CONTRACT §5 closes stored history to agent/CI by
//     default). With a bearer grant token the caller is refused loudly
//     instead: 403 grant_unusable (FIX-08 detail symmetry (a+), the same
//     fail-closed refusal as export — a bearer grant is a root self-grant,
//     never a delegation) and the token stays redeemable. The handler test
//     mock embedded the opposite contract once and was corrected; this test
//     pins the REAL store so the handler/store contract cannot drift again.
//
//   - two concurrent redemptions of one durable grant — the single
//     conditional UPDATE … consumed_at IS NULL must yield exactly one
//     winner, even across two Store instances that share no process-local
//     state.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

// gapPinReal bundles one seeded real-store scenario: a real handler stack on
// a real adminstore, an org, a root identity (the grant issuer/grantee), a
// human row owner, and one request_logs row that carries payload content.
type gapPinReal struct {
	h       *AdminHandlers
	store   *adminstore.Store
	pool    *pgxpool.Pool
	orgID   string
	rootID  string
	ownerID string
	reqID   string
}

func gapPinSeedReal(t *testing.T) gapPinReal {
	t.Helper()
	pool := testdb.Postgres(t)
	store := adminstore.New(pool, slog.Default(), nil)
	h := New(store, "", "", []string{})
	t.Cleanup(h.Stop)

	ctx := context.Background()
	run := fmt.Sprintf("%d", time.Now().UnixNano())
	g := gapPinReal{h: h, store: store, pool: pool, reqID: "gappin-req-" + run}

	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		"gappin org "+run, "gappin-org-"+run).Scan(&g.orgID))
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO admin_users (email, password_hash, is_root) VALUES ($1, 'gappin-not-a-hash', true) RETURNING id::text`,
		"gappin-root-"+run+"@test.local").Scan(&g.rootID))
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO admin_users (email, password_hash, is_root) VALUES ($1, 'gappin-not-a-hash', false) RETURNING id::text`,
		"gappin-owner-"+run+"@test.local").Scan(&g.ownerID))
	// The request belongs to the human owner (NOT to the root): a root must
	// not own it, so every payload disclosure below travels through the grant.
	_, err := pool.Exec(ctx, `INSERT INTO request_logs
		(org_id, home_region, model_requested, model_used, status_code, duration_ms,
		 tokens_in, tokens_out, request_id, user_id, response, upstream_request, upstream_response, created_at)
		VALUES ($1::uuid, 'sg', 'gpt-4o-mini', 'gpt-4o-mini', 200, 5, 1, 1, $2, $3::uuid,
		 '{"choices":[{"message":{"content":"payload-secret"}}]}',
		 '{"messages":[{"content":"original-secret"}]}',
		 '{"id":"up-original"}', now())`,
		g.orgID, g.reqID, g.ownerID)
	require.NoError(t, err)
	t.Cleanup(func() {
		// Tidy the shared stand; rows would die with the container anyway.
		_, _ = pool.Exec(ctx, `DELETE FROM request_payload_grants WHERE org_id=$1::uuid`, g.orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM admin_audit_logs WHERE resource=$1`, "request:"+g.reqID)
		_, _ = pool.Exec(ctx, `DELETE FROM request_logs WHERE org_id=$1::uuid AND request_id=$2`, g.orgID, g.reqID)
		_, _ = pool.Exec(ctx, `DELETE FROM admin_users WHERE id IN ($1::uuid, $2::uuid)`, g.rootID, g.ownerID)
		_, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1::uuid`, g.orgID)
	})
	return g
}

// gapPinRootRequest is an authenticated root request whose user id is a real
// admin_users row (the durable grant binds grantee to that uuid).
func gapPinRootRequest(rootID, method, target string) *http.Request {
	ctx := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, rootID)
	ctx = context.WithValue(ctx, adminauth.ContextKeyIsRoot{}, true)
	return httptest.NewRequestWithContext(ctx, method, target, nil)
}

func gapPinAgentContext(rootID string) context.Context {
	ctx := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, rootID)
	return adminstore.WithRequestPayloadSubject(ctx, adminstore.RequestPayloadSubject{
		Type: adminstore.RequestPayloadAgent, AgentID: "agent-1", APIKeyID: "key-1",
	})
}

// GAP-A1 (real-store half): the agent-subject DETAIL contract on the real
// store, through the full handler stack.
func TestGapPinAgentDetailContractOnRealStore(t *testing.T) {
	g := gapPinSeedReal(t)
	base := "/api/organizations/" + g.orgID + "/requests/" + g.reqID
	detail := func(ctx context.Context, target string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		wrapWithParams(g.h.apiOrgRequestDetail(), "/api/organizations/{id}/requests/{request_id}")(
			rec, httptest.NewRequestWithContext(ctx, http.MethodGet, target, nil))
		return rec
	}

	// (1) Agent subject, no token: the row does not exist for an agent —
	// 404 with no existence oracle and no payload content.
	rec := detail(gapPinAgentContext(g.rootID), base)
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), "payload-secret")

	// (2) Agent subject + a VALID, unconsumed grant: loud 403 grant_unusable
	// (FIX-08 detail symmetry (a+): a bearer grant is a root self-grant,
	// never a delegation to an agent subject — the same fail-closed refusal
	// as the export endpoint, never a silent token ignore). The denial must
	// not burn the token.
	grant, err := g.store.CreateRequestPayloadGrantScope(g.orgID, g.reqID, g.rootID,
		adminstore.RequestPayloadScopeRead, time.Minute, time.Now().UTC())
	require.NoError(t, err)
	rec = detail(gapPinAgentContext(g.rootID), base+"?payload_grant="+grant.Token)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "request payload grant cannot be used")
	require.NotContains(t, rec.Body.String(), "payload-secret")

	// (3) Contrast: the ISSUING ROOT redeems the same, still-alive token and
	// receives the processed payload — the agent 403 is a subject contract,
	// not a broken grant path (the token survived the agent's denial).
	rec = detail(gapPinRootRequest(g.rootID, http.MethodGet, "/").Context(),
		base+"?payload_grant="+grant.Token)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "payload-secret")

	// (4) One-use on the real store: after the redemption the grant is gone,
	// and the root — who does not own the row — no longer sees anything
	// (the real store has no metadata-only fallback for a foreign row).
	rec = detail(gapPinRootRequest(g.rootID, http.MethodGet, "/").Context(),
		base+"?payload_grant="+grant.Token)
	require.NotContains(t, rec.Body.String(), "payload-secret",
		"a consumed grant must never re-open the payload")
}

// GAP-A2: concurrent redemption ×2 of ONE durable grant on the REAL database.
// Two separate adminstore.Store instances (each with its own handler stack)
// share the same Postgres but deliberately NOT the process-local
// consumed-cache, so the durable conditional UPDATE … consumed_at IS NULL is
// the only arbiter: exactly one 200 with payload, one 403, one durable
// consumption.
func TestGapPinConcurrentGrantRedemptionExactlyOneWinner(t *testing.T) {
	g := gapPinSeedReal(t)
	grant, err := g.store.CreateRequestPayloadGrantScope(g.orgID, g.reqID, g.rootID,
		adminstore.RequestPayloadScopeRead, time.Minute, time.Now().UTC())
	require.NoError(t, err)

	// A second, independent handler stack on the same database.
	store2 := adminstore.New(g.pool, slog.Default(), nil)
	h2 := New(store2, "", "", []string{})
	t.Cleanup(h2.Stop)

	target := "/api/organizations/" + g.orgID + "/requests/export?request_id=" + g.reqID +
		"&payload_grant=" + grant.Token
	stacks := []*AdminHandlers{g.h, h2}

	type result struct {
		code int
		body string
	}
	results := make([]result, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			wrapWithParams(stacks[i].apiOrgRequestExport(), "/api/organizations/{id}/requests/export")(
				rec, gapPinRootRequest(g.rootID, http.MethodGet, target))
			results[i] = result{code: rec.Code, body: rec.Body.String()}
		}(i)
	}
	wg.Wait()

	require.ElementsMatch(t, []int{http.StatusOK, http.StatusForbidden},
		[]int{results[0].code, results[1].code},
		"exactly one concurrent redemption may win, got %+v", results)
	for i, r := range results {
		if r.code == http.StatusOK {
			require.Contains(t, r.body, "payload-secret", "winner %d must stream the granted payload", i)
		} else {
			require.Contains(t, r.body, "grant is invalid or unavailable", "loser %d must fail closed", i)
		}
	}

	// Durable exactly-once: the grant row carries exactly one consumption.
	hash := sha256.Sum256([]byte(grant.Token))
	var consumed int
	require.NoError(t, g.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM request_payload_grants WHERE token_hash=$1 AND consumed_at IS NOT NULL`,
		hash[:]).Scan(&consumed))
	require.Equal(t, 1, consumed, "the durable row must record exactly one consumption")
}
