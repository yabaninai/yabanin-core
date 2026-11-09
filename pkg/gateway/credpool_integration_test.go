//go:build integration

package cli

// entry point (gateway chat handler) on a REAL, fully migrated Postgres
// stand — the concrete adminstore.Store behind OrgCredsPoolStore, not the
// in-memory stub. Acceptance legs per card: 2+ credentials of one endpoint,
// upstream 401 → persisted quarantine row + the second key continues
// serving, masked org_credential_ref attribution on the analytics events
// end-to-end, all-quarantined fail-closed, rotation return. Synthetic data
// only; nothing is published and no live provider is called.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/encryption"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// credPoolIntFixture is the real-Postgres stand of the pool integration
// legs: one org, two enabled credentials of one endpoint.
type credPoolIntFixture struct {
	pool  *pgxpool.Pool
	store *adminstore.Store
	orgID string
	k1    adminstore.OrgCredential
	k2    adminstore.OrgCredential
}

func newCredPoolIntFixture(t *testing.T, upstreamURL string) credPoolIntFixture {
	t.Helper()
	pool := testdb.Postgres(t)
	enc := encryption.MustNew(encryption.EncodeKey())
	store := adminstore.New(pool, slog.New(slog.DiscardHandler), enc)
	ctx := context.Background()

	suffix := time.Now().UnixNano()
	org, err := store.CreateOrganization(ctx, fmt.Sprintf("r107-pool-%d", suffix), fmt.Sprintf("r107-pool-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id::text = $1", org.ID)
	})

	k1, err := store.Create(ctx, org.ID, "int-key-1", zaiCodingProvider, upstreamURL, "sk-pool-int-key-00000001")
	require.NoError(t, err)
	k2, err := store.Create(ctx, org.ID, "int-key-2", zaiCodingProvider, upstreamURL, "sk-pool-int-key-00000002")
	require.NoError(t, err)
	return credPoolIntFixture{pool: pool, store: store, orgID: org.ID, k1: k1, k2: k2}
}

// credPoolIntGateway wires the gateway with the REAL adminstore.Store as
// both the org-key resolver surface and the pool store, and an org model
// row bound to the fixture's real org id.
func credPoolIntGateway(t *testing.T, upstreamURL string, fx credPoolIntFixture) *gateway {
	t.Helper()
	gw := streamTestGateway(upstreamURL)
	gw.res = &byokModelResolver{
		global:    map[string]resolver.ModelInfo{"smart": {ModelName: "smart", Tier: "smart", Enabled: true}},
		orgModels: map[string]resolver.ModelInfo{fx.orgID + "|glm-5.3": byokOrgModel(upstreamURL)},
	}
	gw.cfg.ZAICodingEnabled = true
	gw.cfg.ZAICodingBaseURL = upstreamURL
	gw.retryPolicy = retry.Policy{MaxAttempts: 1}
	gw.orgCreds = fx.store
	gw.credPool = newOrgCredsPool(fx.store, nil, orgCredsPoolTTL, slog.New(slog.DiscardHandler))
	return gw
}

// TestCredPoolIntegration_RealPostgres401QuarantineAndContinuation: the
// card's acceptance through the real boundary — the upstream rejects key 1
// with 401; the quarantine lands in org_credential_pool_state (version-
// scoped, deadline exactly the next UTC midnight); every later request is
// served by key 2; the analytics events carry key 2's masked ref and never
// key material.
func TestCredPoolIntegration_RealPostgres401QuarantineAndContinuation(t *testing.T) {
	up := newPoolUpstream(t, "sk-pool-int-key-00000001", false)
	fx := newCredPoolIntFixture(t, up.srv.URL)
	gw := credPoolIntGateway(t, up.srv.URL, fx)

	var mu sync.Mutex
	var events []*eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})
	defer restore()

	// Request 1 draws key 1 (created_at ASC) → 401 → its own request fails.
	rec := byokChatRequest(gw, fx.orgID, "glm-5.3", "int-401-first", false)
	assert.NotEqual(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), "sk-pool-int-key-", "no key material to the client")

	// The quarantine row is PERSISTED in the real database.
	var keyVersion int
	var until time.Time
	err := fx.pool.QueryRow(context.Background(),
		`SELECT key_version, quarantined_until FROM org_credential_pool_state WHERE credential_id = $1::uuid`, fx.k1.ID).
		Scan(&keyVersion, &until)
	require.NoError(t, err, "the 401 must leave a persisted quarantine row")
	assert.Equal(t, 1, keyVersion, "the row pins the credential's current key_version")
	h, m, s := until.UTC().Clock()
	assert.Zero(t, h)
	assert.Zero(t, m)
	assert.Zero(t, s, "deadline is exactly the next UTC midnight (D-3 day granularity)")
	assert.True(t, until.After(time.Now().UTC()))

	// Every later request is served by key 2 and attributed to it.
	for i := 0; i < 6; i++ {
		marker := fmt.Sprintf("int-after-%d", i)
		rec := byokChatRequest(gw, fx.orgID, "glm-5.3", marker, false)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, []string{"sk-pool-int-key-00000002"}, up.keysFor(marker),
			"the surviving credential serves all new requests")
	}

	mu.Lock()
	defer mu.Unlock()
	completed := 0
	for _, ev := range events {
		if !ev.UsedOrgKey {
			continue
		}
		completed++
		assert.Equal(t, first8(fx.k2.ID)+":0002", ev.OrgCredentialRef, "masked id8:last4 attribution of the serving credential")
		raw, err := json.Marshal(ev)
		require.NoError(t, err)
		assert.NotContains(t, string(raw), "sk-pool-int-key-00000001")
		assert.NotContains(t, string(raw), "sk-pool-int-key-00000002", "plaintext never rides the event")
	}
	assert.Positive(t, completed, "the winning hops produced attributed events end-to-end")
}

// TestCredPoolIntegration_AllQuarantinedFailsClosedAndRotationReturns: with
// the real store, rejecting the second key too leaves the endpoint with
// every credential quarantined — the request fails closed (no dial, no
// global-key leak to the org endpoint); rotating key 1 through the frozen
// admin surface (Update + newPlaintextKey) lifts the quarantine via the
// version scope and service resumes with the new key.
func TestCredPoolIntegration_AllQuarantinedFailsClosedAndRotationReturns(t *testing.T) {
	up := newPoolUpstream(t, "sk-pool-int-key-00000001", false)
	fx := newCredPoolIntFixture(t, up.srv.URL)
	gw := credPoolIntGateway(t, up.srv.URL, fx)
	ctx := context.Background()

	// Quarantine both credentials through the real 401 feedback path.
	rec := byokChatRequest(gw, fx.orgID, "glm-5.3", "int-q1", false)
	assert.NotEqual(t, http.StatusOK, rec.Code)
	up.setReject("sk-pool-int-key-00000002")
	rec = byokChatRequest(gw, fx.orgID, "glm-5.3", "int-q2", false)
	assert.NotEqual(t, http.StatusOK, rec.Code)

	var quarantined int
	require.NoError(t, fx.pool.QueryRow(ctx,
		`SELECT count(*) FROM org_credential_pool_state WHERE org_id::text = $1 AND quarantined_until > now()`, fx.orgID).Scan(&quarantined))
	require.Equal(t, 2, quarantined, "both credentials carry live quarantine rows")

	// All quarantined → fail closed on the real store: no upstream dial.
	dialsBefore := up.dials()
	rec = byokChatRequest(gw, fx.orgID, "glm-5.3", "int-failclosed", false)
	assert.GreaterOrEqual(t, rec.Code, 500)
	assert.NotContains(t, rec.Body.String(), "sk-pool-int-key-")
	assert.Equal(t, dialsBefore, up.dials(), "no dial at all — in particular no global-key dial")

	// Rotation through the frozen admin surface: key_version++ lifts the
	// version-scoped quarantine implicitly.
	rotated, err := fx.store.Update(ctx, fx.orgID, fx.k1.ID, adminstore.OrgCredential{
		Name: "int-key-1", Provider: zaiCodingProvider, BaseURL: up.srv.URL, Enabled: true,
	}, "sk-pool-int-key-ROTATED-0011")
	require.NoError(t, err)
	assert.Equal(t, 2, rotated.KeyVersion)
	// The admin CRUD contract bumps the org version; with no Redis in this
	// stand the pool re-lists on invalidation/TTL — apply the bump's local
	// effect directly (documented stand-in for orgcreds:ver:<org>).
	gw.credPool.invalidate(fx.orgID, zaiCodingProvider, up.srv.URL)

	up.setReject("")
	rec = byokChatRequest(gw, fx.orgID, "glm-5.3", "int-rotated", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{"sk-pool-int-key-ROTATED-0011"}, up.keysFor("int-rotated"),
		"the rotated credential returns with its new key")
}

// first8 is the id8 share of the masked attribution ref.
func first8(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
