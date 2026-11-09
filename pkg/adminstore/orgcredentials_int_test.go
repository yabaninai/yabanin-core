package adminstore

// W-BYOK-DB integration tests against the disposable, fully migrated
// Postgres stand (testcontainers). Covers: CRUD + encryption at rest,
// ResolveKey routing semantics, key rotation, per-org name uniqueness,
// up/down migration cleanliness, and org RLS isolation (a foreign org sees
// nothing — the 0022-era posture with the app.current_org GUC).

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/encryption"
	"github.com/reireirei/yabanin/pkg/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// orgCredFixture seeds two orgs and a credential store with a real
// encryptor. Cleanup removes the orgs; credentials cascade (FK policy).
type orgCredFixture struct {
	store *Store
	enc   *encryption.Encryptor
	pool  *pgxpool.Pool
	orgA  string
	orgB  string
}

func newOrgCredFixture(t *testing.T) orgCredFixture {
	t.Helper()
	pool := openAdminTestPool(t)
	enc := encryption.MustNew(encryption.EncodeKey())
	store := New(pool, slog.New(slog.DiscardHandler), enc)
	ctx := context.Background()

	suffix := time.Now().UnixNano()
	orgA, err := store.CreateOrganization(ctx, fmt.Sprintf("byok-a-%d", suffix), fmt.Sprintf("byok-a-%d", suffix))
	require.NoError(t, err)
	orgB, err := store.CreateOrganization(ctx, fmt.Sprintf("byok-b-%d", suffix), fmt.Sprintf("byok-b-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id::text = ANY($1)", []string{orgA.ID, orgB.ID})
	})
	return orgCredFixture{store: store, enc: enc, pool: pool, orgA: orgA.ID, orgB: orgB.ID}
}

// TestOrgCredential_CRUD_Integration: create stores an enc:-prefixed
// ciphertext (never plaintext), reads expose only the mask, update without a
// new key keeps the stored key, update with a key rotates it and bumps
// key_version, disabled credentials stop resolving, delete removes.
func TestOrgCredential_CRUD_Integration(t *testing.T) {
	fx := newOrgCredFixture(t)
	ctx := context.Background()

	key1 := "sk-byok-openai-KEY-1234"
	created, err := fx.store.Create(ctx, fx.orgA, "prod-key", "openai-compat", "https://api.openai.test/v1", key1)
	require.NoError(t, err)
	require.NotEmpty(t, created.ID)
	assert.Equal(t, fx.orgA, created.OrgID)
	assert.Equal(t, "1234", created.KeyLast4)
	assert.Equal(t, 1, created.KeyVersion)
	assert.True(t, created.Enabled)

	// At rest: ciphertext only, never the plaintext key.
	var ct string
	var last4 string
	var version int
	row := fx.pool.QueryRow(ctx,
		`SELECT api_key_ct, key_last4, key_version FROM org_provider_credentials WHERE id::text = $1`, created.ID)
	require.NoError(t, row.Scan(&ct, &last4, &version))
	assert.True(t, encryption.IsEncrypted(ct), "key must be encrypted at rest")
	assert.NotContains(t, ct, key1)
	assert.Equal(t, "1234", last4)
	assert.Equal(t, 1, version)

	// List: mask only.
	list, err := fx.store.List(ctx, fx.orgA)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, created.ID, list[0].ID)
	assert.Equal(t, "1234", list[0].KeyLast4)

	// Rotation: version bumps, ct changes, ResolveKey serves the new key.
	key2 := "sk-byok-openai-ROTATED-5678"
	rotated, err := fx.store.Update(ctx, fx.orgA, created.ID, OrgCredential{
		Name: "prod-key", Provider: "openai-compat", BaseURL: "https://api.openai.test/v2", Enabled: true,
	}, key2)
	require.NoError(t, err)
	assert.Equal(t, 2, rotated.KeyVersion)
	assert.Equal(t, "5678", rotated.KeyLast4)
	assert.Equal(t, "https://api.openai.test/v2", rotated.BaseURL)

	got, ok, err := fx.store.ResolveKey(ctx, fx.orgA, "openai-compat", "https://api.openai.test/v2")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, key2, got)

	// Update without a key: stored key untouched, version stays.
	same, err := fx.store.Update(ctx, fx.orgA, created.ID, OrgCredential{
		Name: "prod-key", Provider: "openai-compat", BaseURL: "https://api.openai.test/v2", Enabled: true,
	}, "")
	require.NoError(t, err)
	assert.Equal(t, 2, same.KeyVersion)
	assert.Equal(t, "5678", same.KeyLast4)

	// Disabled credentials stop resolving (routing miss, not an error).
	_, err = fx.store.Update(ctx, fx.orgA, created.ID, OrgCredential{
		Name: "prod-key", Provider: "openai-compat", BaseURL: "https://api.openai.test/v2", Enabled: false,
	}, "")
	require.NoError(t, err)
	_, ok, err = fx.store.ResolveKey(ctx, fx.orgA, "openai-compat", "https://api.openai.test/v2")
	require.NoError(t, err)
	assert.False(t, ok, "a disabled credential must not resolve")

	// Resolve misses: wrong provider / wrong base URL.
	_, ok, err = fx.store.ResolveKey(ctx, fx.orgA, "anthropic", "https://api.openai.test/v2")
	require.NoError(t, err)
	assert.False(t, ok)
	_, ok, err = fx.store.ResolveKey(ctx, fx.orgA, "openai-compat", "https://other.test/v1")
	require.NoError(t, err)
	assert.False(t, ok)

	// Delete removes; second delete is ErrNotFound.
	require.NoError(t, fx.store.Delete(ctx, fx.orgA, created.ID))
	err = fx.store.Delete(ctx, fx.orgA, created.ID)
	require.True(t, IsNotFound(err))
	_, ok, err = fx.store.ResolveKey(ctx, fx.orgA, "openai-compat", "https://api.openai.test/v2")
	require.NoError(t, err)
	assert.False(t, ok)
}

// TestOrgCredential_UniqueNamePerOrg: UNIQUE(org_id, name) — same name is a
// conflict inside one org and fine across orgs.
func TestOrgCredential_UniqueNamePerOrg(t *testing.T) {
	fx := newOrgCredFixture(t)
	ctx := context.Background()

	_, err := fx.store.Create(ctx, fx.orgA, "shared", "openai-compat", "", "sk-byok-key-orgA-1111")
	require.NoError(t, err)
	_, err = fx.store.Create(ctx, fx.orgA, "shared", "openai-compat", "", "sk-byok-key-orgA-2222")
	require.Error(t, err, "duplicate name within one org must be rejected")
	assert.Contains(t, err.Error(), "already exists")

	_, err = fx.store.Create(ctx, fx.orgB, "shared", "openai-compat", "", "sk-byok-key-orgB-3333")
	require.NoError(t, err, "the same name must be allowed in a different org")
}

// rlsConnAdapter binds one checked-out connection (session role + org GUC
// already set) into the pgxdb surface so a store can run under the exact
// application RLS posture.
type rlsConnAdapter struct{ conn *pgx.Conn }

func (a rlsConnAdapter) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return a.conn.Query(ctx, sql, args...)
}

func (a rlsConnAdapter) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	return a.conn.QueryRow(ctx, sql, args...)
}

func (a rlsConnAdapter) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	return a.conn.Exec(ctx, sql, args...)
}

func (a rlsConnAdapter) BeginAuditTx(ctx context.Context) (auditTx, error) {
	tx, err := a.conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	// *pgx.Tx satisfies auditTx (Query/QueryRow/Exec/Commit/Rollback).
	return tx, nil
}

// TestOrgCredential_RLS_OrgIsolation_Integration: under the application
// posture (SET ROLE yabanin_app + app.current_org GUC) a foreign org's
// credentials are invisible and unwritable, and an unbound session sees
// nothing at all (fail closed).
func TestOrgCredential_RLS_OrgIsolation_Integration(t *testing.T) {
	fx := newOrgCredFixture(t)
	ctx := context.Background()

	credA, err := fx.store.Create(ctx, fx.orgA, "rls-a", "openai-compat", "https://a.test/v1", "sk-byok-rls-orgA-0000")
	require.NoError(t, err)
	credB, err := fx.store.Create(ctx, fx.orgB, "rls-b", "openai-compat", "https://b.test/v1", "sk-byok-rls-orgB-1111")
	require.NoError(t, err)

	conn, err := fx.pool.Acquire(ctx)
	require.NoError(t, err)
	// Reset the session posture while the connection is still checked out,
	// then return it to the pool (LIFO: this defer runs before anything that
	// must not see a downgraded pooled connection).
	defer func() {
		_, _ = conn.Exec(context.Background(), "RESET ROLE")
		_, _ = conn.Exec(context.Background(), "SELECT set_config('app.current_org', '', false)")
		conn.Release()
	}()

	// Downgrade to the NOBYPASSRLS application role and bind org A. The
	// shared stand's migration session leaks row_security=off (pg_dump
	// artifact in the 0001 header); production sessions default to on, so
	// pin the production posture explicitly — under off, PostgreSQL refuses
	// every RLS-affected query with 42501 instead of applying policies.
	_, err = conn.Exec(ctx, "RESET ROLE")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET row_security = on")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET ROLE yabanin_app")
	require.NoError(t, err, "yabanin_app must exist (testdb bootstrap mirrors the deploy layer)")
	var currentUser string
	require.NoError(t, conn.QueryRow(ctx, "SELECT current_user").Scan(&currentUser))
	require.Equal(t, "yabanin_app", currentUser, "RLS assertions are void unless the session is downgraded")
	bindOrg := func(orgID string) {
		_, err := conn.Exec(ctx, "SELECT set_config('app.current_org', $1, false)", orgID)
		require.NoError(t, err)
	}

	rlsAdapter := rlsConnAdapter{conn.Conn()}
	rls := newForTest(rlsAdapter, slog.New(slog.DiscardHandler), fx.enc)

	bindOrg(fx.orgA)
	// Org A sees only its own row (store pins the tx GUC to the requested
	// org — W-VER RLS model, same as org_custom_models).
	seen, err := rls.List(ctx, fx.orgA)
	require.NoError(t, err)
	require.Len(t, seen, 1)
	assert.Equal(t, credA.ID, seen[0].ID)

	// Cross-org writes through the store are ErrNotFound: the WHERE clause
	// pins (id, org) and the org_isolation policy denies the foreign row.
	_, err = rls.Update(ctx, fx.orgA, credB.ID, OrgCredential{Name: "hijack", Provider: "openai-compat"}, "")
	require.True(t, IsNotFound(err), "cross-org update must not touch the foreign row")

	err = rls.Delete(ctx, fx.orgA, credB.ID)
	require.True(t, IsNotFound(err), "cross-org delete must not touch the foreign row")

	// Raw SQL WITHOUT the org GUC (only role downgrade): nothing is visible
	// and nothing resolves — the FORCE policy is the isolation boundary.
	rawForeign, err := rlsAdapter.Query(ctx,
		`SELECT id FROM org_provider_credentials WHERE org_id = $1::uuid`, fx.orgB)
	require.NoError(t, err)
	assert.False(t, rawForeign.Next(), "an unbound raw session must not see any org's rows")
	rawForeign.Close()

	// Direct cross-org INSERT violates the WITH CHECK arm.
	_, err = rlsAdapter.Exec(ctx,
		`INSERT INTO org_provider_credentials (org_id, name, provider, api_key_ct) VALUES ($1::uuid, 'evil', 'openai-compat', 'x')`,
		fx.orgB)
	require.Error(t, err, "cross-org insert must be rejected by the org_isolation policy")

	// Enabled org A credential still resolves under the app posture.
	got, ok, err := rls.ResolveKey(ctx, fx.orgA, "openai-compat", "https://a.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "sk-byok-rls-orgA-0000", got)

	// Unbound raw session (empty GUC): nothing is visible — fail closed.
	bindOrg("")
	none, err := rlsAdapter.Query(ctx,
		`SELECT id FROM org_provider_credentials WHERE org_id = $1::uuid`, fx.orgA)
	require.NoError(t, err)
	assert.False(t, none.Next(), "an unbound session must see no credentials at all")
	none.Close()
}

// readStoredCredCT reads (api_key_ct, key_version) straight from the table
// (admin posture): the at-rest inspection the no-clobber assertions need.
func readStoredCredCT(t *testing.T, pool *pgxpool.Pool, ctx context.Context, credID, orgID string) (string, int) {
	t.Helper()
	var ct string
	var version int
	err := pool.QueryRow(ctx,
		`SELECT api_key_ct, key_version FROM org_provider_credentials WHERE id = $1::uuid AND org_id = $2::uuid`,
		credID, orgID).Scan(&ct, &version)
	require.NoError(t, err)
	return ct, version
}

// TestOrgCredential_VersionedAdoption_CASMigratorCannotClobberRotation_Integration:
// real-DB check of the guarded envelope-migration UPDATE (`... AND
// api_key_ct = $4`). Two legs:
//
//  1. forced interleave: the migrator probes the envelope in an open tx, a
//     key rotation commits from another connection, and the guarded UPDATE
//     in the still-open tx must affect ZERO rows — the rotation's envelope
//     survives untouched;
//  2. sustained race: metadata writers (key kept ⇒ probe + guarded CAS)
//     interleave with key rotators for many rounds. Whatever the ordering,
//     the row ends with exactly one version bump per rotation and its
//     envelope decrypts to the LAST rotated key. A lost CAS guard would let
//     a metadata write overwrite a rotation's envelope with the old key's
//     re-sealed value — old plaintext under a bumped version.
func TestOrgCredential_VersionedAdoption_CASMigratorCannotClobberRotation_Integration(t *testing.T) {
	fx := newOrgCredFixture(t)
	ctx := context.Background()

	ring, err := kms.NewVersioned(kms.Keyset{Current: 1, Versions: []kms.VersionedKey{
		{Version: 1, Key: verCredRingKey(0xE0)},
		{Version: 2, Key: verCredRingKey(0xE1)},
	}})
	require.NoError(t, err)
	fx.store.AdoptCredentialKMS(ring)

	cred, err := fx.store.Create(ctx, fx.orgA, "cas-race", "openai-compat", "https://api.example.test/v1", "sk-cas-initial-0000")
	require.NoError(t, err)
	require.Equal(t, 1, cred.KeyVersion)
	// Enabled stays true: the credential must remain rotation-eligible
	// while the metadata writes flow.
	metadata := OrgCredential{Name: "cas-race", Provider: "openai-compat",
		BaseURL: "https://api.example.test/v1", Enabled: true}

	// --- Leg 1: forced probe → rotate → stale guarded CAS is a no-op. ---
	tx, err := fx.pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, "SELECT set_config('app.current_org', $1, true)", fx.orgA)
	require.NoError(t, err)
	var probed string
	err = tx.QueryRow(ctx,
		`SELECT api_key_ct FROM org_provider_credentials WHERE id = $1::uuid AND org_id = $2::uuid`,
		cred.ID, fx.orgA).Scan(&probed)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(probed, versionedCredPrefix))

	// The replacement a migrator would write: the OLD plaintext re-sealed
	// under the current keyset version.
	sealedOld, _, err := fx.store.encryptOrgCredentialKey(ctx, "sk-cas-initial-0000")
	require.NoError(t, err)

	rotated, err := fx.store.Update(ctx, fx.orgA, cred.ID, metadata, "sk-cas-forced-0042")
	require.NoError(t, err)
	require.Equal(t, 2, rotated.KeyVersion)

	// The migration UPDATE in the still-open tx pins the value it probed:
	// the column moved underneath, so ZERO rows may change.
	tag, err := tx.Exec(ctx,
		`UPDATE org_provider_credentials SET api_key_ct = $3
		  WHERE id = $1::uuid AND org_id = $2::uuid AND api_key_ct = $4`,
		cred.ID, fx.orgA, sealedOld, probed)
	require.NoError(t, err)
	require.Zero(t, tag.RowsAffected(), "the CAS pin must make the stale migration a no-op after a concurrent rotation")
	require.NoError(t, tx.Rollback(ctx))

	stored, version := readStoredCredCT(t, fx.pool, ctx, cred.ID, fx.orgA)
	require.Equal(t, 2, version)
	got, err := fx.store.decryptOrgCredentialKey(ctx, stored)
	require.NoError(t, err)
	require.Equal(t, "sk-cas-forced-0042", got, "the rotation's envelope must survive the stale migration attempt")

	// --- Leg 2: sustained concurrent rotations vs metadata migrations. ---
	const rounds = 24
	var (
		wg      sync.WaitGroup
		start   = make(chan struct{})
		mu      sync.Mutex
		lastKey = "sk-cas-forced-0042" // last rotation applied so far
		opErrs  []error
	)
	wg.Add(2)
	go func() { // rotator: bumps key_version and rewrites the envelope
		defer wg.Done()
		<-start
		for i := 0; i < rounds; i++ {
			key := fmt.Sprintf("sk-cas-rot-%04d", i)
			if _, err := fx.store.Update(ctx, fx.orgA, cred.ID, metadata, key); err != nil {
				mu.Lock()
				opErrs = append(opErrs, fmt.Errorf("rotation %d: %w", i, err))
				mu.Unlock()
				return
			}
			mu.Lock()
			lastKey = key
			mu.Unlock()
		}
	}()
	go func() { // migrator: metadata-only writes drive the lazy re-seal
		defer wg.Done()
		<-start
		for i := 0; i < rounds; i++ {
			if _, err := fx.store.Update(ctx, fx.orgA, cred.ID, metadata, ""); err != nil {
				mu.Lock()
				opErrs = append(opErrs, fmt.Errorf("metadata %d: %w", i, err))
				mu.Unlock()
				return
			}
		}
	}()
	close(start)
	wg.Wait()
	require.Empty(t, opErrs)

	stored, version = readStoredCredCT(t, fx.pool, ctx, cred.ID, fx.orgA)
	require.Equal(t, 2+rounds, version, "exactly one version bump per rotation; a CAS migration must never look like a rotation")
	require.True(t, strings.HasPrefix(stored, versionedCredPrefix))
	got, err = fx.store.decryptOrgCredentialKey(ctx, stored)
	require.NoError(t, err)
	assert.Equal(t, lastKey, got, "the final envelope must decrypt to the LAST rotated key — no metadata write may clobber a rotation")

	resolved, ok, err := fx.store.ResolveKey(ctx, fx.orgA, "openai-compat", "https://api.example.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, lastKey, resolved)
}
