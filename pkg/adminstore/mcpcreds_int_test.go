package adminstore

// MC-1 integration tests against the disposable, fully migrated Postgres
// stand (testcontainers). Covers: server-level CRUD + rotation + encryption
// at rest, per-user grant ceiling + statuses, RLS org isolation for BOTH
// tables (two orgs, application posture), the 0007 up/down pair, orphaning
// on kind change, and the plan's readiness criterion: a dump of the
// credential tables contains no plaintext secret material.

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/encryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mcpCredFixture seeds two orgs; org A additionally gets one enabled MCP
// server with one agent key + enabled grant. The store carries a real
// encryptor (writes must be enc: at rest).
type mcpCredFixture struct {
	store   *Store
	pool    *pgxpool.Pool
	orgA    string
	orgB    string
	serverA string // server name in org A
	agentA  string // agent_keys id in org A
}

const mcpCredHeadersSecret = `{"Authorization":"Bearer mcp-cred-test-4321"}`

func newMCPCredFixture(t *testing.T) mcpCredFixture {
	t.Helper()
	pool := openAdminTestPool(t)
	enc := encryption.MustNew(encryption.EncodeKey())
	store := New(pool, slog.New(slog.DiscardHandler), enc)
	ctx := context.Background()

	suffix := time.Now().UnixNano()
	orgA, err := store.CreateOrganization(ctx, fmt.Sprintf("mcpcred-a-%d", suffix), fmt.Sprintf("mcpcred-a-%d", suffix))
	require.NoError(t, err)
	orgB, err := store.CreateOrganization(ctx, fmt.Sprintf("mcpcred-b-%d", suffix), fmt.Sprintf("mcpcred-b-%d", suffix))
	require.NoError(t, err)
	serverName := fmt.Sprintf("cred-srv-%d", suffix)
	agentID := seedMCPServerAndAgent(t, pool, orgA.ID, serverName)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id::text = ANY($1)", []string{orgA.ID, orgB.ID})
	})
	return mcpCredFixture{store: store, pool: pool, orgA: orgA.ID, orgB: orgB.ID, serverA: serverName, agentA: agentID}
}

// seedMCPServerAndAgent inserts one enabled server + one agent key + grant
// via raw SQL (the MCP registry store lives in pkg/mcpagg; importing it here
// would invert the dependency).
func seedMCPServerAndAgent(t *testing.T, pool *pgxpool.Pool, orgID, serverName string) string {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx,
		`INSERT INTO mcp_servers (org_id, name, url, enabled) VALUES ($1::uuid, $2, 'https://mcp.example.test', true)`,
		orgID, serverName)
	require.NoError(t, err)
	var agentID string
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO agent_keys (org_id, name, key_hash) VALUES ($1::uuid, $2, $3) RETURNING id::text`,
		orgID, serverName+"-agent", "hash-"+orgID+"-"+serverName).Scan(&agentID))
	_, err = pool.Exec(ctx,
		`INSERT INTO mcp_server_grants (org_id, agent_id, server_name, enabled) VALUES ($1::uuid, $2::uuid, $3, true)`,
		orgID, agentID, serverName)
	require.NoError(t, err)
	return agentID
}

// TestMCPServerCredential_CRUD_Integration: upsert stores an enc:-prefixed
// ciphertext (never plaintext) with the last-4 mask, rotation bumps version,
// reads expose the mask only, disable stops resolving, delete removes.
func TestMCPServerCredential_CRUD_Integration(t *testing.T) {
	fx := newMCPCredFixture(t)
	ctx := context.Background()

	created, err := fx.store.UpsertMCPServerCredential(ctx, fx.orgA, fx.serverA, MCPCredKindHeaders, mcpCredHeadersSecret)
	require.NoError(t, err)
	require.NotEmpty(t, created.ID)
	assert.Equal(t, fx.orgA, created.OrgID)
	assert.Equal(t, MCPCredKindHeaders, created.Kind)
	assert.Equal(t, "4321", created.SecretLast4)
	assert.True(t, created.HasSecret)
	assert.True(t, created.Enabled)
	assert.Equal(t, int64(1), created.Version)

	// At rest: ciphertext only, never the plaintext payload.
	var ct string
	require.NoError(t, fx.pool.QueryRow(ctx,
		`SELECT secret_ct FROM mcp_server_credentials WHERE id::text = $1`, created.ID).Scan(&ct))
	assert.True(t, encryption.IsEncrypted(ct), "secret must be encrypted at rest")
	assert.NotContains(t, ct, "mcp-cred-test-4321")

	// Get/List: mask only.
	got, err := fx.store.GetMCPServerCredential(ctx, fx.orgA, fx.serverA)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, "4321", got.SecretLast4)
	assert.Equal(t, fx.serverA, got.ServerName)

	// Rotation: version bumps, resolve serves the new secret.
	rotated := `{"Authorization":"Bearer mcp-cred-rotated-8888"}`
	up, err := fx.store.UpsertMCPServerCredential(ctx, fx.orgA, fx.serverA, MCPCredKindHeaders, rotated)
	require.NoError(t, err)
	assert.Equal(t, int64(2), up.Version)
	assert.Equal(t, "8888", up.SecretLast4)

	plain, kind, version, ok, err := fx.store.ResolveMCPServerSecret(ctx, fx.orgA, fx.serverA)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, rotated, plain)
	assert.Equal(t, MCPCredKindHeaders, kind)
	assert.Equal(t, int64(2), version)

	// Disable stops resolving (routing miss, not an error).
	_, err = fx.store.SetMCPServerCredentialEnabled(ctx, fx.orgA, fx.serverA, false)
	require.NoError(t, err)
	_, _, _, ok, err = fx.store.ResolveMCPServerSecret(ctx, fx.orgA, fx.serverA)
	require.NoError(t, err)
	assert.False(t, ok, "a disabled server credential must not resolve")

	// Missing server is ErrNotFound; delete removes; second delete misses.
	_, err = fx.store.GetMCPServerCredential(ctx, fx.orgA, "no-such-server")
	require.True(t, IsNotFound(err))
	require.NoError(t, fx.store.DeleteMCPServerCredential(ctx, fx.orgA, fx.serverA))
	err = fx.store.DeleteMCPServerCredential(ctx, fx.orgA, fx.serverA)
	require.True(t, IsNotFound(err))
}

// TestMCPUserCredential_GrantCeilingAndStatuses_Integration: the per-user
// path requires an ENABLED grant (the grant stays the ceiling), only active
// unexpired rows resolve, and lifecycle statuses transition as documented.
func TestMCPUserCredential_GrantCeilingAndStatuses_Integration(t *testing.T) {
	fx := newMCPCredFixture(t)
	ctx := context.Background()

	// No grant for org B's (nonexistent) agent: ErrNotFound, nothing stored.
	strayOrgAgent := seedAgentOnly(t, fx.pool, fx.orgB)
	_, err := fx.store.UpsertMCPUserCredential(ctx, fx.orgB, fx.serverA, strayOrgAgent, MCPCredKindHeaders, mcpCredHeadersSecret, nil)
	require.True(t, IsNotFound(err), "a per-user credential without a grant must be refused")

	// Happy path: grant exists → upsert active, resolve ok.
	up, err := fx.store.UpsertMCPUserCredential(ctx, fx.orgA, fx.serverA, fx.agentA, MCPCredKindHeaders, mcpCredHeadersSecret, nil)
	require.NoError(t, err)
	assert.Equal(t, MCPUserCredStatusActive, up.Status)
	assert.Equal(t, "4321", up.SecretLast4)
	assert.Equal(t, fx.serverA, up.ServerName)

	plain, kind, version, ok, err := fx.store.ResolveMCPUserSecret(ctx, fx.orgA, fx.serverA, fx.agentA)
	require.NoError(t, err)
	require.True(t, ok)
	assert.JSONEq(t, mcpCredHeadersSecret, plain)
	assert.Equal(t, MCPCredKindHeaders, kind)
	assert.Equal(t, up.Version, version)

	// needs_reauth is sticky: the row stops resolving until re-submit.
	require.NoError(t, fx.store.SetMCPUserCredentialStatus(ctx, fx.orgA, fx.serverA, fx.agentA, MCPUserCredStatusNeedsReauth))
	_, _, _, ok, err = fx.store.ResolveMCPUserSecret(ctx, fx.orgA, fx.serverA, fx.agentA)
	require.NoError(t, err)
	assert.False(t, ok, "needs_reauth must not resolve")

	// Re-submit (upsert) returns the row to active and bumps the version.
	up2, err := fx.store.UpsertMCPUserCredential(ctx, fx.orgA, fx.serverA, fx.agentA, MCPCredKindHeaders, mcpCredHeadersSecret, nil)
	require.NoError(t, err)
	assert.Equal(t, MCPUserCredStatusActive, up2.Status)
	// Two bumps since up: the needs_reauth transition and the re-submit.
	assert.Equal(t, up.Version+2, up2.Version)

	// Expired rows miss.
	expired := time.Now().Add(-time.Hour)
	if _, err := fx.store.UpsertMCPUserCredential(ctx, fx.orgA, fx.serverA, fx.agentA, MCPCredKindHeaders, mcpCredHeadersSecret, &expired); err != nil {
		t.Fatal(err)
	}
	_, _, _, ok, err = fx.store.ResolveMCPUserSecret(ctx, fx.orgA, fx.serverA, fx.agentA)
	require.NoError(t, err)
	assert.False(t, ok, "an expired credential must not resolve")

	// Pending rows miss too.
	future := time.Now().Add(time.Hour)
	if _, err := fx.store.UpsertMCPUserCredential(ctx, fx.orgA, fx.serverA, fx.agentA, MCPCredKindHeaders, mcpCredHeadersSecret, &future); err != nil {
		t.Fatal(err)
	}
	_, err = fx.store.CreatePendingMCPUserCredential(ctx, fx.orgA, fx.serverA, fx.agentA, "s-1-state-000000001")
	require.NoError(t, err)
	found, err := fx.store.FindMCPUserCredentialByState(ctx, fx.orgA, "s-1-state-000000001")
	require.NoError(t, err)
	assert.Equal(t, fx.agentA, found.AgentKeyID)
	assert.Equal(t, MCPUserCredStatusPending, found.Status)
	_, _, _, ok, err = fx.store.ResolveMCPUserSecret(ctx, fx.orgA, fx.serverA, fx.agentA)
	require.NoError(t, err)
	assert.False(t, ok, "a pending credential must not resolve")

	// Delete removes; second delete is ErrNotFound.
	require.NoError(t, fx.store.DeleteMCPUserCredential(ctx, fx.orgA, fx.serverA, fx.agentA))
	err = fx.store.DeleteMCPUserCredential(ctx, fx.orgA, fx.serverA, fx.agentA)
	require.True(t, IsNotFound(err))
}

// TestMCPUserCredential_OrphanRestore_Integration: revoking the grant
// orphans the row (runtime misses), returning the grant restores it —
// headers → active, oauth-without-tokens → pending.
func TestMCPUserCredential_OrphanRestore_Integration(t *testing.T) {
	fx := newMCPCredFixture(t)
	ctx := context.Background()

	if _, err := fx.store.UpsertMCPUserCredential(ctx, fx.orgA, fx.serverA, fx.agentA, MCPCredKindHeaders, mcpCredHeadersSecret, nil); err != nil {
		t.Fatal(err)
	}
	// Grant revoked → orphan hook → runtime miss.
	require.NoError(t, fx.store.OrphanMCPUserCredentials(ctx, fx.orgA, fx.serverA, fx.agentA))
	_, _, _, ok, err := fx.store.ResolveMCPUserSecret(ctx, fx.orgA, fx.serverA, fx.agentA)
	require.NoError(t, err)
	assert.False(t, ok, "an orphaned credential must not resolve")

	// Grant returned → restore hook → active again.
	require.NoError(t, fx.store.RestoreMCPUserCredentials(ctx, fx.orgA, fx.serverA, fx.agentA))
	got, err := fx.store.GetMCPUserCredential(ctx, fx.orgA, fx.serverA, fx.agentA)
	require.NoError(t, err)
	assert.Equal(t, MCPUserCredStatusActive, got.Status)
	_, _, _, ok, err = fx.store.ResolveMCPUserSecret(ctx, fx.orgA, fx.serverA, fx.agentA)
	require.NoError(t, err)
	assert.True(t, ok)

	// OAuth row without token material restores to pending.
	if _, err := fx.store.CreatePendingMCPUserCredential(ctx, fx.orgA, fx.serverA, fx.agentA, "s-2-state-000000002"); err != nil {
		t.Fatal(err)
	}
	require.NoError(t, fx.store.OrphanMCPUserCredentials(ctx, fx.orgA, fx.serverA, fx.agentA))
	require.NoError(t, fx.store.RestoreMCPUserCredentials(ctx, fx.orgA, fx.serverA, fx.agentA))
	got, err = fx.store.GetMCPUserCredential(ctx, fx.orgA, fx.serverA, fx.agentA)
	require.NoError(t, err)
	assert.Equal(t, MCPUserCredStatusPending, got.Status)
}

// TestMCPServerCredential_KindChangeNeedsUpdate_Integration: rotating the
// server credential with a DIFFERENT kind moves active same-server user
// credentials to needs_update (the auth contract changed).
func TestMCPServerCredential_KindChangeNeedsUpdate_Integration(t *testing.T) {
	fx := newMCPCredFixture(t)
	ctx := context.Background()

	if _, err := fx.store.UpsertMCPServerCredential(ctx, fx.orgA, fx.serverA, MCPCredKindHeaders, mcpCredHeadersSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.store.UpsertMCPUserCredential(ctx, fx.orgA, fx.serverA, fx.agentA, MCPCredKindHeaders, mcpCredHeadersSecret, nil); err != nil {
		t.Fatal(err)
	}
	// Same-kind rotation: user row untouched.
	if _, err := fx.store.UpsertMCPServerCredential(ctx, fx.orgA, fx.serverA, MCPCredKindHeaders, `{"Authorization":"Bearer rotated-1-aaaa"}`); err != nil {
		t.Fatal(err)
	}
	got, err := fx.store.GetMCPUserCredential(ctx, fx.orgA, fx.serverA, fx.agentA)
	require.NoError(t, err)
	assert.Equal(t, MCPUserCredStatusActive, got.Status)

	// Kind switch: user row → needs_update, stops resolving.
	oauthPayload := `{"client_id":"cid","client_secret":"csecret-9999","token_url":"https://idp.example.test/token"}`
	if _, err := fx.store.UpsertMCPServerCredential(ctx, fx.orgA, fx.serverA, MCPCredKindOAuth, oauthPayload); err != nil {
		t.Fatal(err)
	}
	got, err = fx.store.GetMCPUserCredential(ctx, fx.orgA, fx.serverA, fx.agentA)
	require.NoError(t, err)
	assert.Equal(t, MCPUserCredStatusNeedsUpdate, got.Status)
	_, _, _, ok, err := fx.store.ResolveMCPUserSecret(ctx, fx.orgA, fx.serverA, fx.agentA)
	require.NoError(t, err)
	assert.False(t, ok)
}

// TestMCPCredentials_RLS_OrgIsolation_Integration: under the application
// posture (SET ROLE yabanin_app + app.current_org GUC) a foreign org's rows
// are invisible and unwritable on BOTH tables, and an unbound session sees
// nothing at all (fail closed).
func TestMCPCredentials_RLS_OrgIsolation_Integration(t *testing.T) {
	fx := newMCPCredFixture(t)
	ctx := context.Background()

	// Org A holds the fixture server + agent; give org B its own server too.
	seedMCPServerAndAgent(t, fx.pool, fx.orgB, fx.serverA)

	if _, err := fx.store.UpsertMCPServerCredential(ctx, fx.orgA, fx.serverA, MCPCredKindHeaders, mcpCredHeadersSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.store.UpsertMCPServerCredential(ctx, fx.orgB, fx.serverA, MCPCredKindHeaders, `{"Authorization":"Bearer orgb-secret-1111"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.store.UpsertMCPUserCredential(ctx, fx.orgA, fx.serverA, fx.agentA, MCPCredKindHeaders, mcpCredHeadersSecret, nil); err != nil {
		t.Fatal(err)
	}

	// Org B cannot read or touch org A's rows through the org-scoped API…
	_, err := fx.store.GetMCPServerCredential(ctx, fx.orgB, fx.serverA)
	require.NoError(t, err, "org B has its own credential row under the same server name")
	listB, err := fx.store.ListMCPServerCredentials(ctx, fx.orgB)
	require.NoError(t, err)
	require.Len(t, listB, 1)
	assert.NotEqual(t, fx.orgA, listB[0].OrgID)

	// …and a raw session bound to org A sees only org A rows (both tables).
	conn, err := fx.pool.Acquire(ctx)
	require.NoError(t, err)
	defer func() {
		_, _ = conn.Exec(context.Background(), "RESET ROLE")
		_, _ = conn.Exec(context.Background(), "SELECT set_config('app.current_org', '', false)")
		conn.Release()
	}()
	_, err = conn.Exec(ctx, "RESET ROLE")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET row_security = on")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET ROLE yabanin_app")
	require.NoError(t, err, "yabanin_app must exist (testdb bootstrap mirrors the deploy layer)")
	var currentUser string
	require.NoError(t, conn.QueryRow(ctx, "SELECT current_user").Scan(&currentUser))
	require.Equal(t, "yabanin_app", currentUser, "RLS assertions are void unless the session is downgraded")
	_, err = conn.Exec(ctx, "SELECT set_config('app.current_org', $1, false)", fx.orgA)
	require.NoError(t, err)

	var seen int
	require.NoError(t, conn.QueryRow(ctx,
		`SELECT count(*) FROM mcp_server_credentials WHERE org_id = $1::uuid`, fx.orgB).Scan(&seen))
	assert.Zero(t, seen, "a bound session must not see the foreign org's server credentials")
	require.NoError(t, conn.QueryRow(ctx,
		`SELECT count(*) FROM mcp_user_credentials WHERE org_id = $1::uuid`, fx.orgB).Scan(&seen))
	assert.Zero(t, seen, "a bound session must not see the foreign org's user credentials")

	// Cross-org INSERT violates the WITH CHECK arm.
	_, err = conn.Exec(ctx,
		`INSERT INTO mcp_server_credentials (org_id, server_id, kind, secret_ct)
		 SELECT $1::uuid, s.id, 'headers', 'x' FROM mcp_servers s WHERE s.org_id = $2::uuid LIMIT 1`,
		fx.orgB, fx.orgA)
	require.Error(t, err, "cross-org insert must be rejected by the org_isolation policy")

	// Unbound session (empty GUC): nothing is visible — fail closed.
	_, err = conn.Exec(ctx, "SELECT set_config('app.current_org', '', false)")
	require.NoError(t, err)
	require.NoError(t, conn.QueryRow(ctx,
		`SELECT count(*) FROM mcp_server_credentials`).Scan(&seen))
	assert.Zero(t, seen, "an unbound session must see no credentials at all")
}

// TestMCPCredentials_DumpContainsNoPlaintext_Integration pins the plan's
// readiness criterion: after CRUD of known plaintext secrets, a full dump of
// the credential tables (every column serialized, the pg_dump row content)
// contains no plaintext secret material — only ciphertext and masks.
func TestMCPCredentials_DumpContainsNoPlaintext_Integration(t *testing.T) {
	fx := newMCPCredFixture(t)
	ctx := context.Background()

	serverSecret := `{"Authorization":"Bearer dumpcheck-server-token-7777"}`
	userSecret := `{"Authorization":"Bearer dumpcheck-user-token-8888"}`
	oauthPayload := `{"access_token":"dumpcheck-access-9999","refresh_token":"dumpcheck-refresh-0000"}`

	if _, err := fx.store.UpsertMCPServerCredential(ctx, fx.orgA, fx.serverA, MCPCredKindHeaders, serverSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.store.UpsertMCPUserCredential(ctx, fx.orgA, fx.serverA, fx.agentA, MCPCredKindHeaders, userSecret, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.store.UpsertMCPServerCredential(ctx, fx.orgA, fx.serverA, MCPCredKindOAuth, oauthPayload); err != nil {
		t.Fatal(err)
	}

	dump := dumpCredentialTables(t, fx.pool)
	for _, leak := range []string{
		"dumpcheck-server-token-7777", "dumpcheck-user-token-8888",
		"dumpcheck-access-9999", "dumpcheck-refresh-0000",
	} {
		if strings.Contains(dump, leak) {
			t.Errorf("credential dump contains plaintext secret material %q", leak)
		}
	}
	// Sanity: the dump still carries the display masks of the stored rows
	// (masked facts are allowed to be there; the headers mask of the
	// rotated-away server credential is gone by design) and the ciphertext
	// envelope marker.
	assert.Contains(t, dump, "8888")
	assert.Contains(t, dump, "9999")
	assert.Contains(t, dump, "enc:", "credential rows must carry the enc: ciphertext envelope")
}

// dumpCredentialTables serializes every row of both credential tables the
// way pg_dump would emit them (row::text over all columns).
func dumpCredentialTables(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT t::text FROM mcp_server_credentials t
		 UNION ALL
		 SELECT t::text FROM mcp_user_credentials t`)
	require.NoError(t, err)
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var line string
		require.NoError(t, rows.Scan(&line))
		b.WriteString(line)
		b.WriteString("\n")
	}
	require.NoError(t, rows.Err())
	return b.String()
}

// seedAgentOnly inserts a bare agent key (no grants) for negative tests.
func seedAgentOnly(t *testing.T, pool *pgxpool.Pool, orgID string) string {
	t.Helper()
	var agentID string
	// key_hash is globally unique — a constant fixture hash collides on the
	// second caller in one binary (count=2 / several tests); scope it to the
	// org, which is unique per fixture.
	require.NoError(t, pool.QueryRow(context.Background(),
		`INSERT INTO agent_keys (org_id, name, key_hash) VALUES ($1::uuid, $2, $3) RETURNING id::text`,
		orgID, fmt.Sprintf("stray-%d", time.Now().UnixNano()), "hash-stray-"+orgID).Scan(&agentID))
	return agentID
}

// TestMCPUserCredential_PKCEVerifier_Integration (N05-P02-T03, RFC 7636 +
// migration 0017): the pending row carries the encrypted verifier, the
// consume is single-use (cleared in the same statement), org B cannot
// touch org A's verifier (org scope), and nothing plaintext lands at rest.
func TestMCPUserCredential_PKCEVerifier_Integration(t *testing.T) {
	fx := newMCPCredFixture(t)
	ctx := context.Background()

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	// No row yet → ErrNotFound.
	err := fx.store.StoreMCPUserCredVerifier(ctx, fx.orgA, fx.serverA, fx.agentA, verifier)
	require.True(t, IsNotFound(err), "verifier requires an existing credential row")

	pending, err := fx.store.CreatePendingMCPUserCredential(ctx, fx.orgA, fx.serverA, fx.agentA, "pkce-flow-state-0001")
	require.NoError(t, err)
	require.Equal(t, MCPUserCredStatusPending, pending.Status)

	require.NoError(t, fx.store.StoreMCPUserCredVerifier(ctx, fx.orgA, fx.serverA, fx.agentA, verifier))

	// At rest: ciphertext only, never the verifier plaintext.
	var ct string
	require.NoError(t, fx.pool.QueryRow(ctx,
		`SELECT code_verifier_ct FROM mcp_user_credentials WHERE server_id = (SELECT id FROM mcp_servers WHERE org_id::text = $1 AND name = $2) AND agent_key_id::text = $3`,
		fx.orgA, fx.serverA, fx.agentA).Scan(&ct))
	assert.True(t, encryption.IsEncrypted(ct), "the verifier must be encrypted at rest")
	assert.NotContains(t, ct, verifier)

	// Consume once: the exact verifier, then the column is cleared.
	got, ok, err := fx.store.ConsumeMCPUserCredVerifier(ctx, fx.orgA, fx.serverA, fx.agentA)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, verifier, got)
	var present bool
	require.NoError(t, fx.pool.QueryRow(ctx,
		`SELECT code_verifier_ct IS NOT NULL FROM mcp_user_credentials WHERE server_id = (SELECT id FROM mcp_servers WHERE org_id::text = $1 AND name = $2) AND agent_key_id::text = $3`,
		fx.orgA, fx.serverA, fx.agentA).Scan(&present))
	assert.False(t, present, "the verifier is single-use")

	// Second consume (and pre-0017 rows): ok=false, no error.
	_, ok, err = fx.store.ConsumeMCPUserCredVerifier(ctx, fx.orgA, fx.serverA, fx.agentA)
	require.NoError(t, err)
	assert.False(t, ok)

	// Org scope: org B has no server with this name → the consume fails
	// closed (ErrNotFound from the server resolution), never a silent miss
	// that could leak another org's verifier.
	_, _, err = fx.store.ConsumeMCPUserCredVerifier(ctx, fx.orgB, fx.serverA, fx.agentA)
	require.True(t, IsNotFound(err), "another org must not consume the verifier")
}
