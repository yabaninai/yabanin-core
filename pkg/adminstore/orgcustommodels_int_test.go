package adminstore

// W-BYOK-CORE: live-PG acceptance for the org_custom_models store — encrypted
// key writes (enc:- envelope, fail-closed without an encryptor), CRUD
// round-trips with key_version bumping, secret-free listing, and org
// isolation (a second org cannot read another org's model).

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/encryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ptr is the test helper for optional params.
func ptr[T any](v T) *T { return &v }

// seedByokOrg inserts an organization and returns its id (cascade-cleaned).
func seedByokOrg(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	var id string
	require.NoError(t, pool.QueryRow(context.Background(),
		`INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		"BYOK Store "+slug, fmt.Sprintf("%s-%d", slug, time.Now().UnixNano()),
	).Scan(&id))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, id)
	})
	return id
}

func TestStore_OrgCustomModelCRUD_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	enc := encryption.MustNew(encryption.EncodeKey())
	store := New(pool, slog.Default(), enc)
	ctx := context.Background()
	orgID := seedByokOrg(t, pool, "crud")

	secret := "sk-org-model-secret-4242" //nolint:gosec // test fixture
	created, err := store.CreateOrgCustomModel(ctx, orgID, "glm-store-org", OrgCustomModelParams{
		DisplayName:       ptr("Store Org GLM"),
		UpstreamURL:       ptr("https://org-endpoint.example"),
		UpstreamAPIKey:    &secret,
		Provider:          ptr("zai-coding"),
		UpstreamTimeoutMs: func() *int { v := 2500; return &v }(),
		Region:            ptr("SG"),
	})
	require.NoError(t, err)
	require.NotEmpty(t, created.ID)
	assert.Equal(t, 1, created.KeyVersion)
	assert.Equal(t, "4242", created.KeyLast4)
	assert.True(t, created.Enabled)

	// At rest the key is enc:-prefixed ciphertext, never plaintext.
	var stored string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT upstream_api_key::text FROM org_custom_models WHERE id::text = $1`, created.ID).Scan(&stored))
	require.True(t, encryption.IsEncrypted(stored), "stored key must be enc:-prefixed ciphertext")
	assert.NotContains(t, stored, secret)

	// The single-model read decrypts; the list never carries plaintext keys.
	got, err := store.GetOrgCustomModel(ctx, orgID, "glm-store-org")
	require.NoError(t, err)
	assert.Equal(t, secret, got.UpstreamAPIKey)
	assert.Equal(t, "4242", got.KeyLast4)
	assert.Equal(t, "SG", got.Region)
	assert.Equal(t, 2500, got.UpstreamTimeoutMs)

	models, err := store.ListOrgCustomModels(ctx, orgID)
	require.NoError(t, err)
	require.Len(t, models, 1)
	assert.Empty(t, models[0].UpstreamAPIKey, "the list must never decrypt or return keys")
	assert.Equal(t, "4242", models[0].KeyLast4)

	// Update without a key keeps the stored key; key_version does not move.
	updated, err := store.UpdateOrgCustomModel(ctx, orgID, "glm-store-org", OrgCustomModelParams{
		DisplayName: ptr("Renamed Org GLM"),
	})
	require.NoError(t, err)
	assert.Equal(t, "Renamed Org GLM", updated.DisplayName)
	assert.Equal(t, 1, updated.KeyVersion)
	got, err = store.GetOrgCustomModel(ctx, orgID, "glm-store-org")
	require.NoError(t, err)
	assert.Equal(t, secret, got.UpstreamAPIKey, "an update without a key must not touch the key")

	// A new key re-encrypts and bumps key_version.
	rotated := "sk-org-model-rotated-9999"
	updated, err = store.UpdateOrgCustomModel(ctx, orgID, "glm-store-org", OrgCustomModelParams{
		UpstreamAPIKey: &rotated,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, updated.KeyVersion)
	assert.Equal(t, "9999", updated.KeyLast4)
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT upstream_api_key::text FROM org_custom_models WHERE id::text = $1`, created.ID).Scan(&stored))
	require.True(t, encryption.IsEncrypted(stored))
	got, err = store.GetOrgCustomModel(ctx, orgID, "glm-store-org")
	require.NoError(t, err)
	assert.Equal(t, rotated, got.UpstreamAPIKey)

	// Disable, then delete; unknown names are errors everywhere.
	_, err = store.UpdateOrgCustomModel(ctx, orgID, "glm-store-org", OrgCustomModelParams{
		Enabled: ptr(false),
	})
	require.NoError(t, err)
	got, err = store.GetOrgCustomModel(ctx, orgID, "glm-store-org")
	require.NoError(t, err)
	assert.False(t, got.Enabled)

	_, err = store.UpdateOrgCustomModel(ctx, orgID, "glm-store-org", OrgCustomModelParams{})
	require.Error(t, err, "an empty update is rejected")

	require.NoError(t, store.DeleteOrgCustomModel(ctx, orgID, "glm-store-org"))
	_, err = store.GetOrgCustomModel(ctx, orgID, "glm-store-org")
	require.Error(t, err, "a deleted model must be gone")
	err = store.DeleteOrgCustomModel(ctx, orgID, "glm-store-org")
	require.Error(t, err, "deleting an unknown model is a not-found error")
}

func TestStore_OrgCustomModelFailClosedWrite_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil) // no encryptor
	ctx := context.Background()
	orgID := seedByokOrg(t, pool, "failclosed")

	restore := encryption.SetPlaintextPolicyForTest(func() bool { return false })
	defer restore()

	secret := "sk-org-model-plaintext-refused" //nolint:gosec // test fixture
	_, err := store.CreateOrgCustomModel(ctx, orgID, "glm-locked", OrgCustomModelParams{
		UpstreamAPIKey: &secret,
	})
	require.Error(t, err, "production must refuse org model key writes without an encryptor")
	assert.Contains(t, err.Error(), "plaintext")

	var count int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM org_custom_models WHERE org_id::text = $1 AND model_name = 'glm-locked'`, orgID).Scan(&count))
	assert.Zero(t, count, "a refused write must not leave a row behind")

	// A keyless create stays legal (the credential chain supplies the key).
	m, err := store.CreateOrgCustomModel(ctx, orgID, "glm-keyless", OrgCustomModelParams{})
	require.NoError(t, err)
	assert.Empty(t, m.KeyLast4)

	// The same refusal guards updates: the stored key must not be replaced
	// with plaintext (or dropped) when the write is refused.
	_, err = store.UpdateOrgCustomModel(ctx, orgID, "glm-keyless", OrgCustomModelParams{
		UpstreamAPIKey: &secret,
	})
	require.Error(t, err)
}

func TestStore_OrgCustomModelOrgIsolation_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), encryption.MustNew(encryption.EncodeKey()))
	ctx := context.Background()
	orgA := seedByokOrg(t, pool, "iso-a")
	orgB := seedByokOrg(t, pool, "iso-b")

	secret := "sk-org-a-only" //nolint:gosec // test fixture
	_, err := store.CreateOrgCustomModel(ctx, orgA, "glm-iso", OrgCustomModelParams{
		UpstreamURL:    ptr("https://org-a-endpoint.example"),
		UpstreamAPIKey: &secret,
	})
	require.NoError(t, err)

	// Org-b cannot read, list, update, or delete org-a's model through the
	// store (explicit org_id predicate + the org-isolation GUC).
	_, err = store.GetOrgCustomModel(ctx, orgB, "glm-iso")
	require.Error(t, err, "org-b must not read org-a's model")

	modelsB, err := store.ListOrgCustomModels(ctx, orgB)
	require.NoError(t, err)
	assert.Empty(t, modelsB, "org-b's list must not contain org-a's model")

	_, err = store.UpdateOrgCustomModel(ctx, orgB, "glm-iso", OrgCustomModelParams{DisplayName: ptr("hijack")})
	require.Error(t, err, "org-b must not update org-a's model")

	err = store.DeleteOrgCustomModel(ctx, orgB, "glm-iso")
	require.Error(t, err, "org-b must not delete org-a's model")

	// Org-a still sees its model; org-a's list shows exactly one.
	got, err := store.GetOrgCustomModel(ctx, orgA, "glm-iso")
	require.NoError(t, err)
	assert.Equal(t, secret, got.UpstreamAPIKey)
	modelsA, err := store.ListOrgCustomModels(ctx, orgA)
	require.NoError(t, err)
	assert.Len(t, modelsA, 1)

	// The same model name is legal for both orgs (UNIQUE (org_id, model_name)).
	_, err = store.CreateOrgCustomModel(ctx, orgB, "glm-iso", OrgCustomModelParams{
		UpstreamURL: ptr("https://org-b-endpoint.example"),
	})
	require.NoError(t, err, "another org may register the same model name")

	// A duplicate name within ONE org is rejected.
	_, err = store.CreateOrgCustomModel(ctx, orgA, "glm-iso", OrgCustomModelParams{})
	require.Error(t, err, "UNIQUE (org_id, model_name) must reject an org-local duplicate")
}
