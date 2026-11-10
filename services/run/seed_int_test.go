package run

// W-SEED acceptance on a disposable, fully migrated Postgres (testcontainers,
// skipped in -short like every pkg/testdb stand): double-run idempotency with
// ON CONFLICT DO NOTHING, the API key plaintext printed exactly once, enc:
// upstream key storage, and the gateway auth resolver chain — the same
// resolver the gateway puts in front of every request — accepting the seeded
// smoke key without any manual SQL.

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/encryption"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// seedTestEncryptor builds a valid 32-byte AES key (hex-encoded sha256 is
// random-looking enough to pass the weak-key rejection).
func seedTestEncryptor(t *testing.T, seed string) *encryption.Encryptor {
	t.Helper()
	sum := sha256.Sum256([]byte("w-seed-test:" + seed))
	enc, err := encryption.New(hex.EncodeToString(sum[:]))
	require.NoError(t, err)
	return enc
}

func seedTestOptions(t *testing.T, mock bool) SeedOptions {
	t.Helper()
	// The disposable stand is shared by the whole test binary: every test
	// seeds its own org (unique slug/email) so runs stay order-independent.
	uniq := strings.NewReplacer("/", "_", " ", "_", "(", "", ")", "", "=", "_").Replace(t.Name())
	opts := SeedOptions{
		OrgName:       "Seed Stand " + uniq,
		Slug:          seedSlug("Seed Stand " + uniq),
		AdminEmail:    "seed-admin+" + uniq + "@example.com",
		AdminPassword: strPtr("pw-bootstrap"),
		Provider:      "openai-compat",
		// Same literal pin as the production mock default (seed.go resolve):
		// models_registry rows are keyed by model_name and the stand is
		// shared by the binary, so every mock-profile writer must use the
		// same URL or the first-insert row depends on -shuffle order.
		UpstreamURL: "http://10.207.0.9:8081",
		ModelName:   "mock-model",
	}
	if !mock {
		opts.ModelName = "seed-model"
		opts.UpstreamURL = "https://api.example.com/v1"
		opts.UpstreamKeyPlaintext = strPtr("sk-upstream-secret")
	}
	return opts
}

func strPtr(s string) *string { return &s }

func countRow(t *testing.T, pool *pgxpool.Pool, query string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, pool.QueryRow(t.Context(), query, args...).Scan(&n))
	return n
}

func TestApplySeed_IdempotentAndKeyPrintedOnce(t *testing.T) {
	pool := testdb.Postgres(t)
	// W-CRED: pin the starter grant to the default so the balance expectation
	// below is deterministic regardless of the ambient environment.
	t.Setenv(credits.StarterGrantEnvVar, strconv.FormatInt(credits.DefaultStarterGrantCents, 10))
	ctx := t.Context()
	opts := seedTestOptions(t, true)
	enc := seedTestEncryptor(t, "mock") // unused by mock (no upstream key)

	var firstOut, secondOut strings.Builder
	first, err := ApplySeed(ctx, pool, enc, opts, slog.Default(), &firstOut)
	require.NoError(t, err)

	second, err := ApplySeed(ctx, pool, enc, opts, slog.Default(), &secondOut)
	require.NoError(t, err)

	// The plaintext key appears exactly once across both runs, and only the
	// first run reports issuing it.
	require.Equal(t, 1, strings.Count(firstOut.String(), "API key (shown once, store it now):"),
		"first run output: %s", firstOut.String())
	require.NotEmpty(t, first.KeyPlaintext)
	require.True(t, first.KeyIssued)
	require.False(t, second.KeyIssued)
	require.Empty(t, second.KeyPlaintext)
	require.Equal(t, 0, strings.Count(secondOut.String(), first.KeyPlaintext),
		"second run must not reprint the key: %s", secondOut.String())
	require.Contains(t, secondOut.String(), "already exists")

	// Same identities on both runs.
	require.Equal(t, first.OrgID, second.OrgID)
	require.Equal(t, first.TeamID, second.TeamID)
	require.Equal(t, first.APIKeyID, second.APIKeyID)
	require.False(t, second.AdminCreated)
	require.True(t, second.AdminExists)

	// Exactly one row everywhere, and the starting credit grant was not
	// re-applied (DO NOTHING, not a top-up).
	require.Equal(t, int64(1), countRow(t, pool, `SELECT count(*) FROM organizations WHERE slug = $1`, opts.Slug))
	require.Equal(t, int64(1), countRow(t, pool, `SELECT count(*) FROM organizations_teams WHERE org_id = $1::uuid`, first.OrgID))
	require.Equal(t, int64(1), countRow(t, pool, `SELECT count(*) FROM team_budgets WHERE team_id = $1::uuid`, first.TeamID))
	require.Equal(t, int64(1), countRow(t, pool, `SELECT count(*) FROM api_keys WHERE org_id = $1::uuid AND name = 'seed'`, first.OrgID))
	require.Equal(t, int64(1), countRow(t, pool, `SELECT count(*) FROM models_registry WHERE model_name = $1`, opts.ModelName))
	require.Equal(t, int64(1), countRow(t, pool, `SELECT count(*) FROM org_credits WHERE org_id = $1`, first.OrgID))
	require.Equal(t, int64(1), countRow(t, pool, `SELECT count(*) FROM admin_users WHERE email = $1`, opts.AdminEmail))

	// W-CRED: the beta starter grant lands exactly once across both runs.
	require.Equal(t, int64(1), countRow(t, pool,
		`SELECT count(*) FROM credit_transactions WHERE org_id = $1 AND type = 'topup' AND invoice_ref = $2`,
		first.OrgID, credits.StarterGrantReason))

	var balance int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT balance_cents FROM org_credits WHERE org_id = $1`, first.OrgID).Scan(&balance))
	require.Equal(t, int64(seedCreditsCents+credits.DefaultStarterGrantCents), balance)
	require.Equal(t, int64(1), countRow(t, pool,
		`SELECT count(*) FROM credit_transactions WHERE org_id = $1 AND invoice_ref = 'seed-opening-balance'`, first.OrgID))
	var ledgerCents, ledgerMicro int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT sum(amount_cents), sum(amount_micro_usd) FROM credit_transactions WHERE org_id = $1`,
		first.OrgID).Scan(&ledgerCents, &ledgerMicro))
	require.Equal(t, balance, ledgerCents, "fresh seed wallet and ledger must reconcile after repeated seeding")
	require.Equal(t, balance*10000, ledgerMicro)

	var hardLimit bool
	var monthly string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT monthly_limit_usd::text, hard_limit FROM team_budgets WHERE team_id = $1`, first.TeamID).Scan(&monthly, &hardLimit))
	require.Equal(t, "50.00", monthly)
	require.True(t, hardLimit)
}

func TestApplySeed_PreservesExistingWalletHistory(t *testing.T) {
	pool := testdb.Postgres(t)
	t.Setenv(credits.StarterGrantEnvVar, "0")
	opts := seedTestOptions(t, true)
	orgID, err := seedOrg(t.Context(), pool, opts)
	require.NoError(t, err)
	_, err = pool.Exec(t.Context(), `INSERT INTO org_credits (org_id, balance_cents) VALUES ($1, 77)`, orgID)
	require.NoError(t, err)
	var output strings.Builder
	_, err = ApplySeed(t.Context(), pool, seedTestEncryptor(t, "existing"), opts, slog.Default(), &output)
	require.NoError(t, err)
	require.Equal(t, int64(77), countRow(t, pool, `SELECT balance_cents FROM org_credits WHERE org_id = $1`, orgID))
	require.Zero(t, countRow(t, pool, `SELECT count(*) FROM credit_transactions WHERE org_id = $1`, orgID),
		"seeding must not fabricate an opening transaction for an existing wallet")
}

func TestApplySeed_ProviderProfileStoresEncryptedUpstreamKey(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := t.Context()
	enc := seedTestEncryptor(t, "provider")
	opts := seedTestOptions(t, false)

	var out strings.Builder
	_, err := ApplySeed(ctx, pool, enc, opts, slog.Default(), &out)
	require.NoError(t, err)

	var stored *string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT upstream_api_key::text FROM models_registry WHERE model_name = $1`,
		opts.ModelName).Scan(&stored))
	require.NotNil(t, stored)
	require.True(t, encryption.IsEncrypted(*stored), "upstream key must be enc:-prefixed, got %q", *stored)

	decrypted, err := enc.Decrypt(*stored)
	require.NoError(t, err)
	require.Equal(t, *opts.UpstreamKeyPlaintext, string(decrypted))
}

func TestApplySeed_MockProfileHasNoUpstreamKey(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := t.Context()
	opts := seedTestOptions(t, true)

	var out strings.Builder
	_, err := ApplySeed(ctx, pool, nil, opts, slog.Default(), &out)
	require.NoError(t, err)

	var stored *string
	var provider, upstreamURL string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT upstream_api_key::text, provider, upstream_url::text FROM models_registry WHERE model_name = $1`,
		opts.ModelName).Scan(&stored, &provider, &upstreamURL))
	require.Nil(t, stored)
	require.Equal(t, "openai-compat", provider)
	require.Equal(t, opts.UpstreamURL, upstreamURL)
}

func TestApplySeed_RequiresEncryptionKeyForProviderOutsideDev(t *testing.T) {
	pool := testdb.Postgres(t)
	// Simulate production: the dev/`go test` plaintext escape hatch is off.
	restore := encryption.SetPlaintextPolicyForTest(func() bool { return false })
	t.Cleanup(restore)

	opts := seedTestOptions(t, false)
	var out strings.Builder
	_, err := ApplySeed(t.Context(), pool, nil, opts, slog.Default(), &out)
	require.Error(t, err, "a provider key without an encryptor must be refused outside the dev escape hatch")
	require.Contains(t, err.Error(), "refusing to store provider API key as plaintext")
}

func TestApplySeed_AdminWithoutPasswordFailsUnlessExisting(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := t.Context()
	opts := seedTestOptions(t, true)
	opts.AdminPassword = nil

	var out strings.Builder
	_, err := ApplySeed(ctx, pool, nil, opts, slog.Default(), &out)
	require.Error(t, err, "a missing admin needs a password")
	require.Contains(t, err.Error(), "--admin-password-stdin")

	// Create the admin, then re-run without a password: the existing root
	// admin is left untouched and the run succeeds (idempotent re-seed).
	optsWithPass := seedTestOptions(t, true)
	_, err = ApplySeed(ctx, pool, nil, optsWithPass, slog.Default(), &out)
	require.NoError(t, err)

	opts.AdminEmail = optsWithPass.AdminEmail
	res, err := ApplySeed(ctx, pool, nil, opts, slog.Default(), &out)
	require.NoError(t, err)
	require.True(t, res.AdminExists)
	require.False(t, res.AdminCreated)
}

func TestApplySeed_DistinctOrgNamesDoNotCollide(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := t.Context()

	var out strings.Builder
	first, err := ApplySeed(ctx, pool, nil, seedTestOptions(t, true), slog.Default(), &out)
	require.NoError(t, err)

	other := seedTestOptions(t, true)
	other.OrgName = "Other Stand"
	other.Slug = seedSlug(other.OrgName)
	other.AdminEmail = "other-admin@example.com"
	second, err := ApplySeed(ctx, pool, nil, other, slog.Default(), &out)
	require.NoError(t, err)

	require.NotEqual(t, first.OrgID, second.OrgID)
	require.NotEqual(t, first.APIKeyID, second.APIKeyID)
	require.Equal(t, int64(1), countRow(t, pool, `SELECT count(*) FROM api_keys WHERE name = 'seed' AND org_id = $1::uuid`, first.OrgID))
	require.Equal(t, int64(1), countRow(t, pool, `SELECT count(*) FROM api_keys WHERE name = 'seed' AND org_id = $1::uuid`, second.OrgID))
}

// TestSeedRunner_BootstrapsStandEndToEnd exercises the full `yabanin seed`
// runner (flag resolve → password stdin → DB), not just the core: the admin
// password must actually travel from stdin to the seeded root admin.
func TestSeedRunner_BootstrapsStandEndToEnd(t *testing.T) {
	pool := testdb.Postgres(t)
	opts := seedTestOptions(t, true)
	flags := SeedFlags{
		Profile:            SeedProfileMock,
		AdminEmail:         opts.AdminEmail,
		OrgName:            opts.OrgName,
		AdminPasswordStdin: true,
	}

	var out strings.Builder
	err := Seed(t.Context(), cfgForPG(pool.Config().ConnString()), slog.Default(), flags,
		strings.NewReader("pw-from-stdin\n"), &out)
	require.NoError(t, err)

	var isRoot, active bool
	require.NoError(t, pool.QueryRow(t.Context(),
		`SELECT is_root, active FROM admin_users WHERE email = $1`, opts.AdminEmail).Scan(&isRoot, &active))
	require.True(t, isRoot)
	require.True(t, active)
	require.Contains(t, out.String(), "API key (shown once, store it now): yb_")
	require.Equal(t, 1, strings.Count(out.String(), "API key (shown once, store it now):"))
}

// cfgForPG builds the minimal service config Seed consumes (pg_uri; the
// encryption key stays empty for the mock profile).
func cfgForPG(uri string) config.All {
	return config.All{Gateway: config.Gateway{
		GatewayServer: config.GatewayServer{PGURI: uri},
	}}
}

// TestApplySeed_GatewayResolverAcceptsSeededKey proves the bootstrap chain
// end-to-end at the same seam the gateway uses: the auth resolver resolves
// the printed plaintext key to the seeded org/team without any manual SQL.
func TestApplySeed_GatewayResolverAcceptsSeededKey(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := t.Context()
	opts := seedTestOptions(t, true)

	var out strings.Builder
	res, err := ApplySeed(ctx, pool, seedTestEncryptor(t, "resolver"), opts, slog.Default(), &out)
	require.NoError(t, err)
	require.True(t, res.KeyIssued)

	resolver := auth.NewResolver(pool, nil, 0, nil)
	resolved, err := resolver.Resolve(ctx, res.KeyPlaintext)
	require.NoError(t, err)
	require.NotNil(t, resolved)
	require.Equal(t, res.OrgID, resolved.OrgID)
	require.Equal(t, res.TeamID, resolved.TeamID)
	require.Equal(t, res.APIKeyID, resolved.APIKeyID)

	// An unknown key must not resolve (the smoke key is not a master key).
	unknown, err := resolver.Resolve(ctx, "yb_"+strings.Repeat("0", 64))
	require.Error(t, err, "unknown keys must not resolve")
	require.Nil(t, unknown)
}
