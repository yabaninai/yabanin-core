package mcpagg

// Adversarial pin for the FIRST grant layer, store-level. Prior review
// state: the chain layer (delegationChainSQL) is pinned by
// TestAuth02ChainAllowance_RealSQL/org_mismatch; the FIRST layer
// (GetEnabledGrant) was pinned by NOTHING — this file pins it explicitly.
//
// Why a DIRECT store-level test and not the proxy path: a proven sabotage
// finding showed that removing the org predicate from GetEnabledGrant alone
// leaves every proxy-level cross-org test GREEN — the second SQL layer
// (delegationChainSQL, 3 org_id refs) happens to also scope, masking the
// first layer's regression. Defense-in-depth must not mean
// assurance-by-accident: this file calls Store.GetEnabledGrant DIRECTLY, so
// the ONLY org scoping in the exercised path is the SQL predicate under
// pin (store.go: `WHERE org_id = $1 AND agent_id = $2 AND server_name = $3
// AND enabled`). Removing that predicate in a scratch copy makes these
// arms RED with no other layer to catch it — the sabotage transcript in
// the delivery record proves it.
//
// REAL legs throughout (W02 fake-vs-real doctrine): the app-role store over
// testdb.PostgresApp, real org/agent/server/grant rows written through the
// real admin store. No mocks. Docker-backed; skips under -short like every
// testdb stand.
//
// Mandatory variants (adversarial card W05-C01):
//   - allowed: own-org grant resolves through the first layer;
//   - rights-denial + cross-org: foreign-org grant is invisible even with
//     the SAME agent id, server name and enabled flag;
//   - replay/delay (revocation): a disabled grant is ErrNotFound — the
//     replay-after-revoke story at the first layer;
//   - rollback (of the disable): re-enabling restores resolution;
//   - empty/unavailable upstream: N/A at this layer — GetEnabledGrant has
//     no upstream; the store IS the layer under test (documented, not
//     instantiated).

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetEnabledGrantOrgPredicatePin_Int is the REAL first-layer pin. Two
// orgs run identically-named servers with identically-enabled grants; the
// ONLY thing distinguishing them in the WHERE clause is org_id = $1.
func TestGetEnabledGrantOrgPredicatePin_Int(t *testing.T) {
	orgA := newGrantIntOrg(t, "w05flp-a", "knowledge", nil)
	orgB := newGrantIntOrg(t, "w05flp-b", "knowledge", nil)
	ctx := context.Background()

	t.Run("own-org grant resolves (allowed baseline)", func(t *testing.T) {
		g, err := orgA.store.GetEnabledGrant(ctx, orgA.org, orgA.agent, "knowledge")
		require.NoError(t, err, "the own-org enabled grant must resolve at the first layer")
		require.NotNil(t, g)
		assert.Equal(t, "knowledge", g.ServerName, "the resolved grant is for the asked server")
	})

	t.Run("foreign-org grant invisible under own-org context (cross-org pin)", func(t *testing.T) {
		// org-b's agent id under org-a's caller context: agent_id, server
		// name and enabled all MATCH a real row — org_id = $1 is the only
		// predicate standing between this caller and org-b's grant. This
		// is the exact arm the W02-review refinement says is pinned by
		// nothing else: no proxy, no chain walk, no second layer.
		g, err := orgA.store.GetEnabledGrant(ctx, orgA.org, orgB.agent, "knowledge")
		require.ErrorIs(t, err, ErrNotFound, "the first layer alone must refuse a foreign-org grant")
		assert.Nil(t, g, "no grant row content may leak on refusal")
	})

	t.Run("foreign-org context with own agent id is equally refused", func(t *testing.T) {
		// The mirror arm: org-b's context asking for org-a's agent. Same
		// single-predicate story from the other side — pins that the
		// predicate scopes the CALLER context, not the agent's home.
		g, err := orgB.store.GetEnabledGrant(ctx, orgB.org, orgA.agent, "knowledge")
		require.ErrorIs(t, err, ErrNotFound)
		assert.Nil(t, g)
	})

	t.Run("disabled grant is ErrNotFound (replay-after-revoke)", func(t *testing.T) {
		// The revocation story at the first layer: flipping enabled=false
		// must make the grant unresolvable through GetEnabledGrant — a
		// replayed call after revocation finds nothing. mcp_server_grants
		// is predicate posture (no RLS — W04 decision record fact 2), so
		// the superuser fixture pool flips the flag directly.
		// fixture bootstrap API takes testing.TB, not ctx (testdb contract)
		pool := testdb.Postgres(t) //nolint:contextcheck // fixture bootstrap: testdb.Postgres signature is (testing.TB)
		_, err := pool.Exec(ctx,
			`UPDATE mcp_server_grants SET enabled = false WHERE org_id = $1::uuid AND agent_id = $2::uuid`,
			orgA.org, orgA.agent)
		require.NoError(t, err, "fixture: disable the grant row")

		g, err := orgA.store.GetEnabledGrant(ctx, orgA.org, orgA.agent, "knowledge")
		require.ErrorIs(t, err, ErrNotFound, "a disabled grant must behave exactly like a missing one")
		assert.Nil(t, g)
	})

	t.Run("re-enabled grant resolves again (rollback of the disable)", func(t *testing.T) {
		pool := testdb.Postgres(t) //nolint:contextcheck // fixture bootstrap: testdb.Postgres signature is (testing.TB)
		_, err := pool.Exec(ctx,
			`UPDATE mcp_server_grants SET enabled = true WHERE org_id = $1::uuid AND agent_id = $2::uuid`,
			orgA.org, orgA.agent)
		require.NoError(t, err, "fixture: re-enable the grant row")

		g, err := orgA.store.GetEnabledGrant(ctx, orgA.org, orgA.agent, "knowledge")
		require.NoError(t, err, "re-enabling restores first-layer resolution")
		require.NotNil(t, g)
	})

	t.Run("server-name predicate refuses a grant on another server", func(t *testing.T) {
		// Cheap adjacency pin: the same agent, same org, but a server the
		// grant is NOT for must not resolve either (the WHERE's third leg).
		g, err := orgA.store.GetEnabledGrant(ctx, orgA.org, orgA.agent, "not-the-granted-server")
		require.ErrorIs(t, err, ErrNotFound)
		assert.Nil(t, g)
	})
}
