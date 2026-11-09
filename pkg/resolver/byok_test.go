package resolver

// W-BYOK-CORE: org custom model resolution (ResolveOrgChecked) — global
// visibility plus the org's own org_custom_models rows, org isolation, and
// the W-PROV fail-closed key policy mirrored onto org rows.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
)

// fakeTx scripts one org-model lookup transaction: Exec records the
// org-isolation GUC, QueryRow answers by model name for a single org.
type fakeTx struct {
	orgID    string
	rows     map[string][]any // name → SELECT column order
	execErr  error
	execStmt []string
}

func (t *fakeTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	t.execStmt = append(t.execStmt, sql)
	if t.execErr != nil {
		return pgconn.NewCommandTag(""), t.execErr
	}
	return pgconn.NewCommandTag("SELECT 1"), nil
}

func (t *fakeTx) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	orgID, _ := args[0].(string)
	name, _ := args[1].(string) // $1 = org id, $2 = model name
	if t.orgID != "" && orgID != t.orgID {
		return errRow{err: pgx.ErrNoRows} // org-scoped fake: other orgs see nothing
	}
	vals, ok := t.rows[name]
	if !ok {
		return errRow{err: pgx.ErrNoRows}
	}
	v := vals
	return errRow{scanFn: func(dest ...any) error {
		for i, d := range dest {
			if i >= len(v) {
				break
			}
			switch dp := d.(type) {
			case *string:
				*dp = v[i].(string)
			case *int64:
				*dp = v[i].(int64)
			}
		}
		return nil
	}}
}

func (t *fakeTx) Begin(context.Context) (pgx.Tx, error) { return nil, errors.New("nested tx") }
func (t *fakeTx) Commit(context.Context) error          { return nil }
func (t *fakeTx) Rollback(context.Context) error        { return nil }
func (t *fakeTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("not implemented")
}
func (t *fakeTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return nil
}
func (t *fakeTx) Conn() *pgx.Conn { return nil }
func (t *fakeTx) LargeObjects() pgx.LargeObjects {
	return pgx.LargeObjects{}
}
func (t *fakeTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("not implemented")
}
func (t *fakeTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errors.New("not implemented")
}

// orgTxPool adapts fakeTx to the resolver's orgModelPool surface.
type orgTxPool struct {
	tx  *fakeTx
	err error
}

func (p *orgTxPool) Begin(context.Context) (pgx.Tx, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.tx, nil
}

// TestResolveOrgChecked_GlobalWins: a global registry row always wins over
// an org row of the same name.
func TestResolveOrgChecked_GlobalWins(t *testing.T) {
	global := &mockPool{rows: map[string][]any{
		"shared": {"shared", "Shared", "standard", "https://global", "", "openai", nil, true, int64(0), "EU"},
	}}
	org := &orgTxPool{tx: &fakeTx{rows: map[string][]any{
		"shared": {"shared", "Org shadow", "smart", "https://org", "", "zai", int64(5), "SG"},
	}}}
	r := NewResolver(global, "fb", time.Minute, nil)
	r.UseOrgModels(org)

	got, err := r.ResolveOrgChecked(context.Background(), "org-a", "shared")
	require.NoError(t, err)
	assert.Equal(t, "shared", got.ModelName)
	assert.Equal(t, "https://global", got.UpstreamURL)
	assert.False(t, got.Fallback)
}

// TestResolveOrgChecked_OrgHitOnGlobalMiss: the org's own model resolves with
// its decrypted key and row data, under a genuine global miss.
func TestResolveOrgChecked_OrgHitOnGlobalMiss(t *testing.T) {
	global := &mockPool{rows: map[string][]any{}} // nothing global
	org := &orgTxPool{tx: &fakeTx{rows: map[string][]any{
		"glm-org": {"glm-org", "Org GLM", "smart", "https://org-endpoint", "enc:cipher", "zai-coding", int64(2500), "SG"},
	}}}
	r := NewResolver(global, "fb", time.Minute, nil, fakeDecrypter{val: "sk-org-plain"})
	r.UseOrgModels(org)

	got, err := r.ResolveOrgChecked(context.Background(), "org-a", "glm-org")
	require.NoError(t, err)
	assert.Equal(t, "glm-org", got.ModelName)
	assert.Equal(t, "https://org-endpoint", got.UpstreamURL)
	assert.Equal(t, "sk-org-plain", got.UpstreamAPIKey)
	assert.Equal(t, "zai-coding", got.Provider)
	assert.Equal(t, "SG", got.Region)
	assert.Equal(t, 2500*time.Millisecond, got.UpstreamTimeout)
	assert.True(t, got.Enabled)
	assert.False(t, got.Fallback)

	// Never cached: the second resolve consults the org table again (the
	// plaintext key is produced per request).
	got2, err := r.ResolveOrgChecked(context.Background(), "org-a", "glm-org")
	require.NoError(t, err)
	assert.Equal(t, "sk-org-plain", got2.UpstreamAPIKey)
}

// TestResolveOrgChecked_SecondOrgCannotResolveForeignModel: another org gets
// not-found for a model it does not own; the global fallback stands.
func TestResolveOrgChecked_SecondOrgCannotResolveForeignModel(t *testing.T) {
	global := &mockPool{rows: map[string][]any{
		"fb": {"fb", "Fallback", "smart", "https://global", "", "openai", nil, true, int64(0), "GLOBAL"},
	}}
	org := &orgTxPool{tx: &fakeTx{orgID: "org-a", rows: map[string][]any{
		"glm-org": {"glm-org", "Org GLM", "smart", "https://org-endpoint", "", "zai-coding", int64(0), "SG"},
	}}}
	r := NewResolver(global, "fb", time.Minute, nil)
	r.UseOrgModels(org)

	got, err := r.ResolveOrgChecked(context.Background(), "org-b", "glm-org")
	require.NoError(t, err)
	assert.True(t, got.Fallback, "org-b must not resolve org-a's model")
	assert.Equal(t, "https://global", got.UpstreamURL)
}

// TestResolveOrgChecked_FailClosedOnEncryptedOrgKey mirrors the W-PROV
// policy: an encrypted org key without a decrypter refuses the route.
func TestResolveOrgChecked_FailClosedOnEncryptedOrgKey(t *testing.T) {
	global := &mockPool{rows: map[string][]any{}}
	org := &orgTxPool{tx: &fakeTx{rows: map[string][]any{
		"glm-org": {"glm-org", "Org GLM", "smart", "https://org-endpoint", "enc:cipher", "zai-coding", int64(0), "SG"},
	}}}

	r := NewResolver(global, "fb", time.Minute, nil) // no decrypter
	r.UseOrgModels(org)
	_, err := r.ResolveOrgChecked(context.Background(), "org-a", "glm-org")
	require.ErrorIs(t, err, ErrModelUnavailable)

	// A failing decrypter fails closed too.
	r2 := NewResolver(global, "fb", time.Minute, nil, fakeDecrypter{err: errors.New("bad key")})
	r2.UseOrgModels(org)
	_, err = r2.ResolveOrgChecked(context.Background(), "org-a", "glm-org")
	require.ErrorIs(t, err, ErrModelUnavailable)
}

// outagePool makes every lookup fail (registry outage).
type outagePool struct{}

func (outagePool) QueryRow(context.Context, string, ...any) pgx.Row {
	return errRow{err: errors.New("db down")}
}
func (outagePool) Close() {}

type errRow struct {
	err    error
	scanFn func(dest ...any) error
}

func (r errRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if r.scanFn != nil {
		return r.scanFn(dest...)
	}
	return nil
}

// TestResolveOrgChecked_GlobalOutageStaysTerminal: a global registry outage
// must not degrade into an org lookup (AF-03/RT-06: an outage is never a
// not-found and never routed around).
func TestResolveOrgChecked_GlobalOutageStaysTerminal(t *testing.T) {
	global := &outagePool{}
	org := &orgTxPool{tx: &fakeTx{rows: map[string][]any{}}}
	r := NewResolver(global, "fb", time.Minute, nil)
	r.UseOrgModels(org)

	_, err := r.ResolveOrgChecked(context.Background(), "org-a", "glm-org")
	require.ErrorIs(t, err, ErrModelUnavailable)
}

// TestResolveOrgChecked_OrgTableOutageIsUnavailable: an org-table failure is
// an outage (ErrModelUnavailable), never a silent global fallback.
func TestResolveOrgChecked_OrgTableOutageIsUnavailable(t *testing.T) {
	global := &mockPool{rows: map[string][]any{}}
	org := &orgTxPool{err: errors.New("db down")}
	r := NewResolver(global, "fb", time.Minute, nil)
	r.UseOrgModels(org)

	_, err := r.ResolveOrgChecked(context.Background(), "org-a", "glm-org")
	require.ErrorIs(t, err, ErrModelUnavailable)

	org2 := &orgTxPool{tx: &fakeTx{execErr: errors.New("guc failed")}}
	r2 := NewResolver(global, "fb", time.Minute, nil)
	r2.UseOrgModels(org2)
	_, err = r2.ResolveOrgChecked(context.Background(), "org-a", "glm-org")
	require.ErrorIs(t, err, ErrModelUnavailable)
}

// TestResolveOrgChecked_IntegrationIsolation runs the isolation scenario
// against the disposable stand: org-a's zai model resolves for org-a only —
// under the superuser pool (explicit org_id predicate alone) and under the
// app-role pool (RLS + org GUC posture).
func TestResolveOrgChecked_IntegrationIsolation(t *testing.T) {
	pool := testdb.Postgres(t)
	app := testdb.PostgresApp(t, "eu")
	ctx := context.Background()

	orgA := seedOrgForBYOK(t, pool, "byok-res-a")
	orgB := seedOrgForBYOK(t, pool, "byok-res-b")
	seedOrgModelForBYOK(t, pool, orgA, "glm-org", "", "zai-coding", "https://org-endpoint")

	// Superuser pool (RLS bypassed): the explicit org_id predicate alone
	// must isolate orgs.
	r := NewResolver(pool, "fb", time.Minute, nil)
	r.UseOrgModels(pool)
	got, err := r.ResolveOrgChecked(ctx, orgA, "glm-org")
	require.NoError(t, err)
	assert.Equal(t, "glm-org", got.ModelName)
	assert.Equal(t, "https://org-endpoint", got.UpstreamURL)
	assert.Empty(t, got.UpstreamAPIKey, "the row carries no key: the gateway credential chain decides")

	got, err = r.ResolveOrgChecked(ctx, orgB, "glm-org")
	require.NoError(t, err, "not-found is not an outage")
	assert.True(t, got.Fallback, "org-b must not resolve org-a's model (explicit predicate)")

	// App-role pool (SET ROLE yabanin_app, NOBYPASSRLS): the RLS policy + org
	// GUC must hide the foreign org's row; the org's own row resolves.
	rApp := NewResolver(app, "fb", time.Minute, nil)
	rApp.UseOrgModels(app)
	got, err = rApp.ResolveOrgChecked(ctx, orgA, "glm-org")
	require.NoError(t, err)
	assert.Equal(t, "glm-org", got.ModelName)

	got, err = rApp.ResolveOrgChecked(ctx, orgB, "glm-org")
	require.NoError(t, err)
	assert.True(t, got.Fallback, "org-b must not resolve org-a's model under the RLS posture")
}

// seedOrgForBYOK seeds an organization and returns its id.
func seedOrgForBYOK(t *testing.T, pool interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}, slug string) string {
	t.Helper()
	var id string
	require.NoError(t, pool.QueryRow(context.Background(),
		`INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		"BYOK "+slug, slug+"-"+time.Now().Format("150405.000000000"),
	).Scan(&id))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, id)
	})
	return id
}

// seedOrgModelForBYOK inserts one org_custom_models row (as the test
// superuser; RLS is bypassed for fixtures on purpose).
func seedOrgModelForBYOK(t *testing.T, pool interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, orgID, modelName, encryptedKey, provider, upstreamURL string) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO org_custom_models
		    (org_id, model_name, display_name, tier, upstream_url,
		     upstream_api_key, provider, region, enabled)
		VALUES ($1::uuid, $2, $2, 'smart', $5, NULLIF($3, ''), $4, 'SG', true)
		ON CONFLICT (org_id, model_name) DO UPDATE
		SET upstream_api_key = EXCLUDED.upstream_api_key,
		    provider = EXCLUDED.provider,
		    upstream_url = EXCLUDED.upstream_url,
		    enabled = true`,
		orgID, modelName, encryptedKey, provider, upstreamURL,
	)
	require.NoError(t, err)
}
