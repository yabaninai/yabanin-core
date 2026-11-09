package adminstore

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/reireirei/yabanin/pkg/encryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// W-BYOK-DB contract tests: the org credential store must never leak key
// material through any read surface (JSON, log-shaped fields, or the
// OrgCredential struct itself), and key writes must fail closed without a

const (
	orgCredProbeKey   = "sk-byok-probe-0123456789abcdef-SECRET-TAIL" // #nosec G101 -- test probe value
	orgCredProbeLast4 = "TAIL"
	orgCredProbeCT    = "enc:QnJvYWRjYXN0LWNpcGhlcnRleHQtcHJvYmUtMTIzNDU2Nzg5MA==" // #nosec G101 -- fake ciphertext shape
)

// orgCredRow is a scannable org_provider_credentials RETURNING row (the
// api_key_ct column is deliberately absent — reads never select it).
func orgCredRow() []interface{} {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	return []interface{}{
		"cred-1", "org-1", "probe", "openai-compat", "https://api.example.test/v1",
		orgCredProbeLast4, true, 1, now, now,
	}
}

// orgCredFixtureStore returns a store backed by mockDB whose single-row
// queries scan orgCredRow(); all SQL and args are recorded.
func orgCredFixtureStore(t *testing.T, enc *encryption.Encryptor) (*Store, *[]string, *[][]interface{}) {
	t.Helper()
	var sqls []string
	var argsLog [][]interface{}
	db := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			sqls = append(sqls, sql)
			argsLog = append(argsLog, args)
			return &mockPGXRow{data: [][]interface{}{orgCredRow()}}
		},
		// W-VER RLS fix: every credential operation now runs inside the
		// org-isolation tx, so the fixture must provide a passthrough tx.
		beginAuditTxFn: func(ctx context.Context) (auditTx, error) {
			return &orgCredTxStub{
				queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
					sqls = append(sqls, sql)
					argsLog = append(argsLog, args)
					return &mockPGXRow{data: [][]interface{}{orgCredRow()}}
				},
				execFn: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
					sqls = append(sqls, sql)
					argsLog = append(argsLog, args)
					return pgconn.NewCommandTag("DELETE 1"), nil
				},
			}, nil
		},
	}
	return newForTest(db, newTestLogger(), enc), &sqls, &argsLog
}

// statically (the runtime pair lives in orgcredentials.go).
func TestOrgCredential_InterfaceCompliance(t *testing.T) {
	var _ OrgCredentialStore = (*Store)(nil)
}

// TestOrgCredential_JSONNeverCarriesKeyMaterial: marshaling any read result
// (single or list) must not contain the plaintext key or any ciphertext
// blob; the only key-derived field is key_last4.
func TestOrgCredential_JSONNeverCarriesKeyMaterial(t *testing.T) {
	enc := encryption.MustNew(encryption.EncodeKey())
	store, _, _ := orgCredFixtureStore(t, enc)

	created, err := store.Create(context.Background(), "org-1", "probe", "openai-compat", "https://api.example.test/v1", orgCredProbeKey)
	require.NoError(t, err)

	single, err := json.Marshal(created)
	require.NoError(t, err)
	assert.NotContains(t, string(single), orgCredProbeKey, "created record must not serialize the plaintext key")
	assert.NotContains(t, string(single), "api_key", "no api_key field may exist on the read model")
	assert.Equal(t, orgCredProbeLast4, created.KeyLast4)

	list, err := json.Marshal([]OrgCredential{created})
	require.NoError(t, err)
	assert.NotContains(t, string(list), orgCredProbeKey)
	assert.NotContains(t, string(list), orgCredProbeCT)
}

// TestOrgCredential_Create_FailClosedWithoutEncryptor: simulating production
// (plaintext writes refused), Create/Update-with-key without an encryptor
// must error BEFORE any statement reaches the database.
func TestOrgCredential_Create_FailClosedWithoutEncryptor(t *testing.T) {
	restore := encryption.SetPlaintextPolicyForTest(func() bool { return false })
	defer restore()

	store, sqls, _ := orgCredFixtureStore(t, nil)

	_, err := store.Create(context.Background(), "org-1", "probe", "openai-compat", "https://api.example.test/v1", orgCredProbeKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to store org provider API key as plaintext")
	assert.Empty(t, *sqls, "a refused key write must never reach the database")

	_, err = store.Update(context.Background(), "org-1", "cred-1", OrgCredential{Name: "probe", Provider: "openai-compat"}, orgCredProbeKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to store org provider API key as plaintext")
	assert.Empty(t, *sqls, "a refused key rotation must never reach the database")
}

// TestOrgCredential_Create_DevPlaintextFallback: under the dev/test escape
// hatch the write goes through with a loud warning path — pin that the
// fallback stores the value (never empty) and computes the mask.
func TestOrgCredential_Create_DevPlaintextFallback(t *testing.T) {
	var capturedArgs []interface{}
	db := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			capturedArgs = args
			return &mockPGXRow{data: [][]interface{}{orgCredRow()}}
		},
	}
	store := newForTest(db, slog.New(slog.DiscardHandler), nil)

	_, err := store.Create(context.Background(), "org-1", "probe", "openai-compat", "https://api.example.test/v1", orgCredProbeKey)
	require.NoError(t, err)
	require.Len(t, capturedArgs, 6)
	assert.Equal(t, orgCredProbeKey, capturedArgs[4], "dev fallback stores the plaintext (documented, warned)")
	assert.Equal(t, orgCredProbeLast4, capturedArgs[5])
}

// TestOrgCredential_Update_KeepKeyNilCiphertext: newPlaintextKey "" must
// bind NULL ciphertext args (key preserved, no re-encryption) while the
// version CASE stays in the statement; a non-empty key re-encrypts.
func TestOrgCredential_Update_KeepKeyNilCiphertext(t *testing.T) {
	enc := encryption.MustNew(encryption.EncodeKey())
	store, _, argsLog := orgCredFixtureStore(t, enc)

	_, err := store.Update(context.Background(), "org-1", "cred-1",
		OrgCredential{Name: "renamed", Provider: "openai-compat", BaseURL: "https://api.example.test/v1", Enabled: false}, "")
	require.NoError(t, err)
	// argsLog[0] is the org-isolation set_config GUC call, [1] the UPDATE.
	require.Len(t, *argsLog, 2)
	keepArgs := (*argsLog)[1]
	require.Len(t, keepArgs, 8)
	assert.Nil(t, keepArgs[6], "empty newPlaintextKey must bind NULL (keep existing key)")
	assert.Nil(t, keepArgs[7])

	_, err = store.Update(context.Background(), "org-1", "cred-1",
		OrgCredential{Name: "renamed", Provider: "openai-compat"}, orgCredProbeKey)
	require.NoError(t, err)
	require.Len(t, *argsLog, 4)
	rotateArgs := (*argsLog)[3]
	ct, ok := rotateArgs[6].(*string)
	require.True(t, ok)
	require.NotNil(t, ct)
	assert.True(t, encryption.IsEncrypted(*ct), "rotated key must be encrypted at rest")
	assert.NotContains(t, *ct, orgCredProbeKey)
	last4, ok := rotateArgs[7].(*string)
	require.True(t, ok)
	require.NotNil(t, last4)
	assert.Equal(t, orgCredProbeLast4, *last4)
}

// TestOrgCredential_Update_NotFound: a missing row surfaces as the canonical
// ErrNotFound sentinel (handlers map it to 404).
func TestOrgCredential_Update_NotFound(t *testing.T) {
	db := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &mockPGXRow{err: pgx.ErrNoRows}
		},
	}
	store := newForTest(db, newTestLogger(), nil)

	_, err := store.Update(context.Background(), "org-1", "cred-missing", OrgCredential{Name: "x", Provider: "p"}, "")
	require.True(t, IsNotFound(err), "expected ErrNotFound, got %v", err)

	err = store.Delete(context.Background(), "org-1", "cred-missing")
	require.True(t, IsNotFound(err))
}

// TestOrgCredential_Create_UniqueViolation: a duplicate (org_id, name) is
// reported as a name conflict, not a raw driver error.
func TestOrgCredential_Create_UniqueViolation(t *testing.T) {
	db := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &mockPGXRow{err: &pgconn.PgError{Code: "23505", Message: "duplicate key"}}
		},
	}
	store := newForTest(db, newTestLogger(), nil)

	_, err := store.Create(context.Background(), "org-1", "dup", "openai-compat", "", orgCredProbeKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

// TestOrgCredential_ResolveKey_Decrypts: ResolveKey is the single plaintext
// egress; the decrypted value comes back only through the return value.
func TestOrgCredential_ResolveKey_Decrypts(t *testing.T) {
	enc := encryption.MustNew(encryption.EncodeKey())
	ct, err := enc.Encrypt(orgCredProbeKey)
	require.NoError(t, err)

	db := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{{ct}}}
		},
	}
	store := newForTest(db, newTestLogger(), enc)

	got, ok, err := store.ResolveKey(context.Background(), "org-1", "openai-compat", "https://api.example.test/v1")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, orgCredProbeKey, got)
}

// TestOrgCredential_ResolveKey_FailClosedEncryptedWithoutEncryptor: an
// enc:-prefixed row with no configured encryptor is a hard error — serving
// silently would misroute traffic with an empty credential.
func TestOrgCredential_ResolveKey_FailClosedEncryptedWithoutEncryptor(t *testing.T) {
	db := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{{orgCredProbeCT}}}
		},
	}
	store := newForTest(db, newTestLogger(), nil)

	_, ok, err := store.ResolveKey(context.Background(), "org-1", "openai-compat", "")
	require.Error(t, err)
	assert.False(t, ok)
	assert.Contains(t, err.Error(), "encrypted but no encryption_key is configured")
}

// TestOrgCredential_ResolveKey_NoMatch: no matching enabled credential is
// (ok=false, err=nil) — a routing miss, not a store failure.
func TestOrgCredential_ResolveKey_NoMatch(t *testing.T) {
	db := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &mockPGXRow{err: pgx.ErrNoRows}
		},
	}
	store := newForTest(db, newTestLogger(), nil)

	got, ok, err := store.ResolveKey(context.Background(), "org-1", "openai-compat", "")
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Empty(t, got)
}

// TestOrgCredential_Create_Validation: required-field validation fires before
// any statement is prepared.
func TestOrgCredential_Create_Validation(t *testing.T) {
	enc := encryption.MustNew(encryption.EncodeKey())
	store, sqls, _ := orgCredFixtureStore(t, enc)
	ctx := context.Background()

	calls := map[string]func() error{
		"missing org":      func() error { _, err := store.Create(ctx, "", "n", "p", "", orgCredProbeKey); return err },
		"missing name":     func() error { _, err := store.Create(ctx, "org-1", "", "p", "", orgCredProbeKey); return err },
		"missing provider": func() error { _, err := store.Create(ctx, "org-1", "n", "", "", orgCredProbeKey); return err },
		"missing key":      func() error { _, err := store.Create(ctx, "org-1", "n", "p", "", ""); return err },
	}
	for name, call := range calls {
		require.Error(t, call(), "%s must be rejected", name)
	}
	assert.Empty(t, *sqls, "validation failures must not reach the database")
}

// TestOrgCredential_Update_Validation mirrors the Create checks.
func TestOrgCredential_Update_Validation(t *testing.T) {
	enc := encryption.MustNew(encryption.EncodeKey())
	store, sqls, _ := orgCredFixtureStore(t, enc)
	ctx := context.Background()

	_, err := store.Update(ctx, "", "id", OrgCredential{Name: "n", Provider: "p"}, "")
	require.Error(t, err)
	_, err = store.Update(ctx, "org-1", "id", OrgCredential{Name: "", Provider: "p"}, "")
	require.Error(t, err)
	_, err = store.Update(ctx, "org-1", "id", OrgCredential{Name: "n", Provider: ""}, "")
	require.Error(t, err)
	assert.Empty(t, *sqls)
}

// TestOrgCredentialKeyLast4: the mask reveals at most the final 4 chars and
// masks short keys to "" instead of leaking most of the secret.
func TestOrgCredentialKeyLast4(t *testing.T) {
	assert.Empty(t, orgCredentialKeyLast4(""))
	assert.Empty(t, orgCredentialKeyLast4("short"))
	assert.Empty(t, orgCredentialKeyLast4("12345678"))
	assert.Equal(t, "6789", orgCredentialKeyLast4("123456789"))
	assert.Equal(t, "TAIL", orgCredentialKeyLast4("sk-very-long-key-SECRET-TAIL"))
}

// TestOrgCredential_List_SelectsNoCiphertext: the read column list — the only
// surface rows reach Go structs through — must not select api_key_ct.
func TestOrgCredential_List_SelectsNoCiphertext(t *testing.T) {
	var seen []string
	db := &mockDB{
		queryFn: func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
			seen = append(seen, sql)
			return &mockPGXRows{}, nil
		},
	}
	store := newForTest(db, newTestLogger(), nil)

	_, err := store.List(context.Background(), "org-1")
	require.NoError(t, err)
	require.Len(t, seen, 1)
	assert.NotContains(t, seen[0], "api_key_ct", "reads must never select the ciphertext column")
}

// TestOrgCredential_DevPlaintextReadStillServes: legacy plaintext rows (dev
// fallback writes) stay resolvable so a misconfigured environment does not
// brick serving mid-flight — read side only.
func TestOrgCredential_DevPlaintextReadStillServes(t *testing.T) {
	db := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{{orgCredProbeKey}}}
		},
	}
	store := newForTest(db, slog.New(slog.DiscardHandler), nil)

	got, ok, err := store.ResolveKey(context.Background(), "org-1", "openai-compat", "")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, orgCredProbeKey, got)
}

// TestOrgCredential_NilDB: every operation reports an error instead of
// panicking when no database is wired.
func TestOrgCredential_NilDB(t *testing.T) {
	store := newForTest(nil, newTestLogger(), nil)
	ctx := context.Background()

	_, err := store.List(ctx, "org-1")
	require.Error(t, err)
	_, err = store.Create(ctx, "org-1", "n", "p", "", orgCredProbeKey)
	require.Error(t, err)
	_, err = store.Update(ctx, "org-1", "id", OrgCredential{Name: "n", Provider: "p"}, "")
	require.Error(t, err)
	require.Error(t, store.Delete(ctx, "org-1", "id"))
	_, _, err = store.ResolveKey(ctx, "org-1", "p", "")
	require.Error(t, err)
}

// orgCredTxStub is the passthrough tx for the org-isolation helper: unit
// tests only assert SQL shapes, so it forwards to function hooks.
type orgCredTxStub struct {
	queryRowFn func(ctx context.Context, sql string, args ...interface{}) pgx.Row
	execFn     func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
}

func (t *orgCredTxStub) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	return t.queryRowFn(ctx, sql, args...)
}
func (t *orgCredTxStub) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	return nil, pgx.ErrNoRows
}
func (t *orgCredTxStub) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	return t.execFn(ctx, sql, args...)
}
func (t *orgCredTxStub) Commit(context.Context) error   { return nil }
func (t *orgCredTxStub) Rollback(context.Context) error { return nil }
