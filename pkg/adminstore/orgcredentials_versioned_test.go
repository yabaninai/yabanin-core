package adminstore

// N01-P04 successor: store-level adoption of VersionedKMS at the org
// credential seam. The contract pinned here:
//
//   - config-driven adoption: a store WITHOUT an adopted keyset is
//     byte-identical to the legacy single-key deployment (enc: envelopes,
//     unchanged statement shapes); a store WITH an adopted keyset writes
//     versioned envelopes ("ykm1:" + hex kms envelope) and keeps reading
//     legacy enc: rows (dual-trust read) — no data migration required;
//   - lazy re-encrypt on write: any credential Update re-seals the stored
//     value under the keyset's current version (guarded by a CAS on the
//     value it read, so a metadata write can never clobber a concurrent key
//     rotation with the old key's envelope);
//   - KMS failure ⇒ no plaintext fallback anywhere at the seam: encrypt
//     failures are hard errors before any SQL, decrypt failures return
//     errors (never empty plaintext, never a legacy or dev-plaintext
//     downgrade), and migration skips keep the stored value byte-identical;
//   - rotation mid-traffic never stops at the store seam (the -race no-stop
//     scenario at the bottom extends pkg/kms/versioned_race_test.go).
//
// Mock-grade unit scenarios with deterministic test keys, in-process; the
// ring lifecycle itself is covered exhaustively in pkg/kms.

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/reireirei/yabanin/pkg/encryption"
	"github.com/reireirei/yabanin/pkg/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// verCredRingKey builds deterministic 32-byte key material for one ring
// version (mock-grade test material, same pattern as pkg/kms tests).
func verCredRingKey(b byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = b
	}
	return key
}

// verCredRing builds a one- or two-version ring for the seam tests.
func verCredRing(t *testing.T) *kms.VersionedKMS {
	t.Helper()
	v, err := kms.NewVersioned(kms.Keyset{
		Current: 1,
		Versions: []kms.VersionedKey{
			{Version: 1, Key: verCredRingKey(0xC0)},
			{Version: 2, Key: verCredRingKey(0xC1)},
		},
	})
	require.NoError(t, err)
	return v
}

// failingKMS is a kms.Provider whose every operation fails: the seam must
// treat that as a hard error and never fall back to the legacy cipher or to
// plaintext.
type failingKMS struct{}

func (failingKMS) Encrypt(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("kms: injected failure")
}

func (failingKMS) Decrypt(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("kms: injected failure")
}

// versionedCredTx is the passthrough tx for the versioned-seam tests: the
// org-isolation GUC and the credential UPDATE scan the RETURNING row, the
// migration probe SELECT serves seededCT, and the guarded migration UPDATE
// records its args for inspection.
type versionedCredTx struct {
	seededCT string // value served for SELECT api_key_ct
	sqls     []string
	argsLog  [][]interface{}
	execSQLs []string
	execArgs [][]interface{}
}

func (t *versionedCredTx) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	t.sqls = append(t.sqls, sql)
	t.argsLog = append(t.argsLog, args)
	if strings.Contains(sql, "SELECT api_key_ct") {
		return &mockPGXRow{data: [][]interface{}{{t.seededCT}}}
	}
	return &mockPGXRow{data: [][]interface{}{orgCredRow()}}
}

func (t *versionedCredTx) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	return &mockPGXRows{}, nil
}

func (t *versionedCredTx) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	t.sqls = append(t.sqls, sql)
	t.argsLog = append(t.argsLog, args)
	t.execSQLs = append(t.execSQLs, sql)
	t.execArgs = append(t.execArgs, args)
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (t *versionedCredTx) Commit(context.Context) error   { return nil }
func (t *versionedCredTx) Rollback(context.Context) error { return nil }

// versionedCredStore wires a store over versionedCredTx with the given
// encryptor and adopted keyset; it returns the tx for statement inspection.
func versionedCredStore(t *testing.T, enc *encryption.Encryptor, ring kms.Provider, seededCT string) (*Store, *versionedCredTx) {
	t.Helper()
	tx := &versionedCredTx{seededCT: seededCT}
	db := &mockDB{
		beginAuditTxFn: func(context.Context) (auditTx, error) { return tx, nil },
	}
	s := newForTest(db, newTestLogger(), enc)
	if ring != nil {
		s.AdoptCredentialKMS(ring)
	}
	return s, tx
}

func TestOrgCredential_VersionedAdoption_NewWritesUseKeyset(t *testing.T) {
	ctx := context.Background()
	ring := verCredRing(t)
	enc := encryption.MustNew(encryption.EncodeKey())
	store, tx := versionedCredStore(t, enc, ring, orgCredProbeCT)

	// Create: the bound at-rest value is a versioned envelope that decrypts
	// under the ring — never the legacy enc: format while a keyset is
	// adopted, even though a legacy encryptor is also configured.
	_, err := store.Create(ctx, "org-1", "probe", "openai-compat", "https://api.example.test/v1", orgCredProbeKey)
	require.NoError(t, err)
	require.Len(t, tx.argsLog, 2) // GUC + INSERT
	insertArgs := tx.argsLog[1]
	require.Len(t, insertArgs, 6)
	ct, ok := insertArgs[4].(string)
	require.True(t, ok)
	require.True(t, strings.HasPrefix(ct, versionedCredPrefix), "keyset write must carry the versioned framing, got %q", ct[:8])
	raw, err := hex.DecodeString(ct[len(versionedCredPrefix):])
	require.NoError(t, err)
	plain, err := ring.Decrypt(ctx, raw)
	require.NoError(t, err)
	assert.Equal(t, orgCredProbeKey, string(plain))
	assert.Equal(t, orgCredProbeLast4, insertArgs[5])

	// Update with a new key: versioned envelope again, no migration probe
	// (a rotation carries its own key material).
	before := len(tx.sqls)
	_, err = store.Update(ctx, "org-1", "cred-1", OrgCredential{Name: "probe", Provider: "openai-compat"}, orgCredProbeKey)
	require.NoError(t, err)
	require.Len(t, tx.sqls, before+2) // GUC + UPDATE only — no probe SELECT
	updateArgs := tx.argsLog[before+1]
	bound, ok := updateArgs[6].(*string)
	require.True(t, ok)
	require.NotNil(t, bound)
	assert.True(t, strings.HasPrefix(*bound, versionedCredPrefix))

	// ResolveKey over a versioned row round-trips the plaintext.
	tx.seededCT = *bound
	got, ok, err := store.ResolveKey(ctx, "org-1", "openai-compat", "")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, orgCredProbeKey, got)
}

func TestOrgCredential_VersionedAdoption_DualTrustRead(t *testing.T) {
	ctx := context.Background()
	ring := verCredRing(t)
	enc := encryption.MustNew(encryption.EncodeKey())
	store, _ := versionedCredStore(t, enc, ring, "")

	// A legacy enc: row stays readable while the keyset is adopted (the
	// dual-trust window) — this is what makes adoption a no-downtime,
	// no-data-migration change.
	legacyCT, err := enc.Encrypt(orgCredProbeKey)
	require.NoError(t, err)
	got, err := store.decryptOrgCredentialKey(ctx, legacyCT)
	require.NoError(t, err)
	assert.Equal(t, orgCredProbeKey, got)

	// A versioned row is readable by the same store.
	sealed, _, err := store.encryptOrgCredentialKey(ctx, orgCredProbeKey)
	require.NoError(t, err)
	got, err = store.decryptOrgCredentialKey(ctx, sealed)
	require.NoError(t, err)
	assert.Equal(t, orgCredProbeKey, got)
}

func TestOrgCredential_VersionedAdoption_LazyMigrationOnWrite(t *testing.T) {
	ctx := context.Background()
	ring := verCredRing(t)
	enc := encryption.MustNew(encryption.EncodeKey())
	legacyCT, err := enc.Encrypt(orgCredProbeKey)
	require.NoError(t, err)

	store, tx := versionedCredStore(t, enc, ring, legacyCT)
	// Metadata-only Update (key kept): the write lazily re-seals the stored
	// legacy envelope under the keyset's current version.
	_, err = store.Update(ctx, "org-1", "cred-1",
		OrgCredential{Name: "probe", Provider: "openai-compat", Enabled: false}, "")
	require.NoError(t, err)

	// Statement shape: GUC + probe SELECT + main UPDATE + guarded migration.
	require.Len(t, tx.sqls, 4)
	assert.Contains(t, tx.sqls[1], "SELECT api_key_ct")

	// The main UPDATE kept the key (NULL ct args ⇒ key_version unchanged).
	updateArgs := tx.argsLog[2]
	require.Len(t, updateArgs, 8)
	assert.Nil(t, updateArgs[6], "lazy migration must not look like a rotation")

	// The guarded migration bound the re-sealed envelope and pinned the
	// value it read (CAS against a concurrent rotation). execArgs[0] is the
	// org-isolation GUC Exec, [1] the guarded migration UPDATE.
	require.Len(t, tx.execArgs, 2)
	migArgs := tx.execArgs[1]
	require.Len(t, migArgs, 4)
	migrated, ok := migArgs[2].(string)
	require.True(t, ok)
	require.True(t, strings.HasPrefix(migrated, versionedCredPrefix))
	raw, err := hex.DecodeString(migrated[len(versionedCredPrefix):])
	require.NoError(t, err)
	plain, err := ring.Decrypt(ctx, raw)
	require.NoError(t, err)
	assert.Equal(t, orgCredProbeKey, string(plain))
	assert.Equal(t, legacyCT, migArgs[3], "migration is guarded by the value it read")

	// Already-migrated rows are a no-op on the next write (header probe, no
	// rewrite): simulate the column now holding the migrated envelope, so
	// the next Update probes an already-current value and never re-writes.
	tx.seededCT = migrated
	_, err = store.Update(ctx, "org-1", "cred-1",
		OrgCredential{Name: "probe", Provider: "openai-compat"}, "")
	require.NoError(t, err)
	require.Len(t, tx.sqls, 7) // +GUC, +probe SELECT, +UPDATE — no second CAS
	assert.Len(t, tx.execArgs, 3, "an already-current envelope must not be re-written")
}

func TestOrgCredential_VersionedAdoption_LegacyModeStatementShapes(t *testing.T) {
	ctx := context.Background()
	enc := encryption.MustNew(encryption.EncodeKey())
	legacyCT, err := enc.Encrypt(orgCredProbeKey)
	require.NoError(t, err)

	// Without an adopted keyset the seam is byte-identical to the legacy
	// deployment: no probe SELECT, no guarded migration, enc: envelopes.
	store, tx := versionedCredStore(t, enc, nil, legacyCT)
	_, err = store.Update(ctx, "org-1", "cred-1",
		OrgCredential{Name: "probe", Provider: "openai-compat"}, "")
	require.NoError(t, err)
	require.Len(t, tx.sqls, 2) // GUC + UPDATE, nothing else
	assert.NotContains(t, tx.sqls[1], "SELECT api_key_ct")
	for _, sql := range tx.execSQLs {
		assert.NotContains(t, sql, "api_key_ct", "legacy mode never issues the guarded migration")
	}

	_, _, err = store.encryptOrgCredentialKey(ctx, orgCredProbeKey)
	require.NoError(t, err)
	// (The envelope format itself is pinned by the pre-existing legacy tests:
	// TestOrgCredential_Update_KeepKeyNilCiphertext asserts the enc: prefix.)
}

func TestOrgCredential_VersionedAdoption_MigrationSkipCases(t *testing.T) {
	ctx := context.Background()

	t.Run("already current version is a no-op", func(t *testing.T) {
		ring := verCredRing(t)
		store := newForTest(&mockDB{}, newTestLogger(), nil)
		store.AdoptCredentialKMS(ring)
		sealed, _, err := store.encryptOrgCredentialKey(ctx, orgCredProbeKey)
		require.NoError(t, err)
		migrated, ok := store.migrateOrgCredentialEnvelope(ctx, sealed)
		assert.False(t, ok, "an already-current envelope must not be rewritten")
		assert.Empty(t, migrated)
	})

	t.Run("undecryptable legacy row skips without touching the value", func(t *testing.T) {
		ring := verCredRing(t)
		// No legacy encryptor configured: the enc: row cannot be decrypted,
		// so migration must skip (loudly) and keep the value byte-identical —
		// never a plaintext downgrade or an empty credential.
		store := newForTest(&mockDB{}, newTestLogger(), nil)
		store.AdoptCredentialKMS(ring)
		migrated, ok := store.migrateOrgCredentialEnvelope(ctx, orgCredProbeCT)
		assert.False(t, ok)
		assert.Empty(t, migrated)
	})

	t.Run("failing KMS skips migration and keeps the stored envelope", func(t *testing.T) {
		enc := encryption.MustNew(encryption.EncodeKey())
		store := newForTest(&mockDB{}, newTestLogger(), enc)
		store.AdoptCredentialKMS(failingKMS{})
		migrated, ok := store.migrateOrgCredentialEnvelope(ctx, orgCredProbeCT)
		assert.False(t, ok, "a KMS failure must not produce a replacement value")
		assert.Empty(t, migrated)
	})

	t.Run("corrupted versioned framing skips without touching the value", func(t *testing.T) {
		ring := verCredRing(t)
		store := newForTest(&mockDB{}, newTestLogger(), nil)
		store.AdoptCredentialKMS(ring)
		// A ykm1: value whose hex payload does not parse claims the framing
		// but is corrupt. Migration must skip it (loud decrypt refusal) —
		// re-sealing would launder the corrupted string into a valid-looking
		// envelope whose plaintext is the garbage itself.
		migrated, ok := store.migrateOrgCredentialEnvelope(ctx, versionedCredPrefix+"abc")
		assert.False(t, ok, "a corrupted framing must not be re-sealed")
		assert.Empty(t, migrated)
	})

	t.Run("dev plaintext row upgrades to a versioned envelope on write", func(t *testing.T) {
		ring := verCredRing(t)
		store := newForTest(&mockDB{}, newTestLogger(), nil)
		store.AdoptCredentialKMS(ring)
		migrated, ok := store.migrateOrgCredentialEnvelope(ctx, orgCredProbeKey)
		require.True(t, ok, "a dev plaintext row must be upgraded at rest")
		raw, err := hex.DecodeString(strings.TrimPrefix(migrated, versionedCredPrefix))
		require.NoError(t, err)
		plain, err := ring.Decrypt(ctx, raw)
		require.NoError(t, err)
		assert.Equal(t, orgCredProbeKey, string(plain))
	})
}

func TestOrgCredential_VersionedAdoption_KMSFailureNoPlaintextFallback(t *testing.T) {
	ctx := context.Background()

	// A failing KMS on the WRITE path: hard error BEFORE any SQL — no legacy
	// cipher fallback, no plaintext write, no partial row.
	t.Run("encrypt failure refuses before the database", func(t *testing.T) {
		enc := encryption.MustNew(encryption.EncodeKey())
		store, tx := versionedCredStore(t, enc, failingKMS{}, orgCredProbeCT)
		restore := encryption.SetPlaintextPolicyForTest(func() bool { return false })
		defer restore()

		_, err := store.Create(ctx, "org-1", "probe", "openai-compat", "https://api.example.test/v1", orgCredProbeKey)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt org credential API key")
		assert.NotContains(t, err.Error(), orgCredProbeKey)
		assert.Empty(t, tx.sqls, "a failed keyset write must never reach the database")

		ct, last4, err := store.encryptOrgCredentialKey(ctx, orgCredProbeKey)
		assert.Empty(t, ct)
		assert.Empty(t, last4)
		require.Error(t, err)
	})

	// Versioned artifacts that cannot be opened: every one fails closed with
	// an empty plaintext and a material-free error.
	t.Run("unreadable envelopes fail closed", func(t *testing.T) {
		ring := verCredRing(t)
		store := newForTest(&mockDB{}, newTestLogger(), encryption.MustNew(encryption.EncodeKey()))
		store.AdoptCredentialKMS(ring)

		// Retired version: seal under v1, rotate to v2, retire v1 (this
		// probe copy deliberately skips the drain — it pins the refusal).
		sealed, _, err := store.encryptOrgCredentialKey(ctx, orgCredProbeKey)
		require.NoError(t, err)
		require.NoError(t, ring.Rotate(7, verCredRingKey(0xC7)))
		require.NoError(t, ring.Retire(1))
		got, err := store.decryptOrgCredentialKey(ctx, sealed)
		require.Error(t, err)
		require.ErrorIs(t, err, kms.ErrRetiredKeyVersion)
		assert.Empty(t, got, "a failed decrypt must not return a value")
		assert.NotContains(t, err.Error(), orgCredProbeKey)

		// Tampered envelope: the framing survives, the AEAD open must not.
		raw, err := hex.DecodeString(sealed[len(versionedCredPrefix):])
		require.NoError(t, err)
		raw[len(raw)-1] ^= 0xFF
		got, err = store.decryptOrgCredentialKey(ctx, versionedCredPrefix+hex.EncodeToString(raw))
		require.Error(t, err)
		assert.Empty(t, got)

		// Unknown key version (the "this deployment lost the key" shape).
		foreign := append([]byte("ykm1"), 0, 0, 0, 0, 0, 0, 0, 99, 1, 2, 3)
		got, err = store.decryptOrgCredentialKey(ctx, versionedCredPrefix+hex.EncodeToString(foreign))
		require.Error(t, err)
		require.ErrorIs(t, err, kms.ErrUnknownKeyVersion)
		assert.Empty(t, got)

		// ResolveKey surfaces the refusal as (ok=false, err) — the caller
		// moves on, no credential is served from a broken envelope.
		db := &mockDB{
			queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
				return &mockPGXRow{data: [][]interface{}{{sealed}}}
			},
		}
		noKeyset := newForTest(db, newTestLogger(), encryption.MustNew(encryption.EncodeKey()))
		resolved, ok, err := noKeyset.ResolveKey(ctx, "org-1", "openai-compat", "")
		require.Error(t, err)
		assert.False(t, ok)
		assert.Empty(t, resolved)
		assert.Contains(t, err.Error(), "no keyset is configured")
	})
}

// TestOrgCredential_VersionedAdoption_ReAdoptionRefused pins the structural
// guard of the startup-only adoption contract: the first keyset stays bound.
// A second adoption with a DIFFERENT ring would strand every envelope sealed
// under the first (their key versions vanish from the store's view); an
// unguarded swap would also race the unsynchronized request-path reads.
// Rotation belongs to the provider (VersionedKMS.Rotate), never to
// re-adoption.
func TestOrgCredential_VersionedAdoption_ReAdoptionRefused(t *testing.T) {
	ctx := context.Background()
	ring := verCredRing(t)
	enc := encryption.MustNew(encryption.EncodeKey())
	store := newForTest(&mockDB{}, newTestLogger(), enc)
	store.AdoptCredentialKMS(ring)

	// Seal an envelope under the first keyset, then attempt re-adoption
	// with a foreign ring: refused, first keyset stays bound.
	sealed, _, err := store.encryptOrgCredentialKey(ctx, orgCredProbeKey)
	require.NoError(t, err)

	foreign, err := kms.NewVersioned(kms.Keyset{Current: 9, Versions: []kms.VersionedKey{
		{Version: 9, Key: verCredRingKey(0xF9)},
	}})
	require.NoError(t, err)
	store.AdoptCredentialKMS(foreign)

	got, err := store.decryptOrgCredentialKey(ctx, sealed)
	require.NoError(t, err, "the first keyset must stay bound: its envelopes stay readable")
	assert.Equal(t, orgCredProbeKey, got)

	// New writes still seal under the FIRST keyset, not the refused one.
	next, _, err := store.encryptOrgCredentialKey(ctx, orgCredProbeKey)
	require.NoError(t, err)
	raw, err := hex.DecodeString(strings.TrimPrefix(next, versionedCredPrefix))
	require.NoError(t, err)
	_, err = foreign.Decrypt(ctx, raw)
	require.Error(t, err, "the refused ring must never seal store writes")
	plain, err := ring.Decrypt(ctx, raw)
	require.NoError(t, err)
	assert.Equal(t, orgCredProbeKey, string(plain))

	// nil adoption stays a no-op (legacy default unchanged), and re-adopting
	// the SAME provider is an idempotent no-op, not an error or a swap.
	store.AdoptCredentialKMS(nil)
	store.AdoptCredentialKMS(ring)
	got, err = store.decryptOrgCredentialKey(ctx, sealed)
	require.NoError(t, err)
	assert.Equal(t, orgCredProbeKey, got)
}

// TestOrgCredential_VersionedAdoption_CorruptedFramingFailsClosed: the ykm1:
// prefix is a CLAIM of versioned framing. A stored value that carries the
// prefix but whose hex payload does not parse (corruption, torn row,
// odd-length hex in a TEXT column) must fail closed in every store
// configuration — it must never fall through IsEncrypted()==false into the
// dev-plaintext passthrough, which would serve the corrupted string AS the
// credential under a misleading "stored as PLAINTEXT (dev fallback row)"
// warning. Refusal errors stay material-free: structural detail (payload
// length) only, never the stored value or the probe key.
func TestOrgCredential_VersionedAdoption_CorruptedFramingFailsClosed(t *testing.T) {
	ctx := context.Background()

	// Corruption shapes: odd-length hex, non-hex characters, a valid nibble
	// run followed by garbage, and torn real envelopes (a leading or
	// trailing nibble lost between the framing and the payload).
	ring := verCredRing(t)
	tornEnvelope := func(cutHead bool) string {
		t.Helper()
		sealer := newForTest(&mockDB{}, newTestLogger(), encryption.MustNew(encryption.EncodeKey()))
		sealer.AdoptCredentialKMS(ring)
		sealed, _, err := sealer.encryptOrgCredentialKey(ctx, orgCredProbeKey)
		require.NoError(t, err)
		payload := sealed[len(versionedCredPrefix):]
		if cutHead {
			payload = payload[1:]
		} else {
			payload = payload[:len(payload)-1]
		}
		return versionedCredPrefix + payload
	}
	corrupt := []string{
		versionedCredPrefix + "abc",        // odd-length hex (torn TEXT row)
		versionedCredPrefix + "zz",         // non-hex characters
		versionedCredPrefix + "deadbeefZZ", // valid run, then garbage
		tornEnvelope(false),                // trailing nibble lost
		tornEnvelope(true),                 // leading nibble lost
	}

	enc := encryption.MustNew(encryption.EncodeKey())
	keysetStore := newForTest(&mockDB{}, newTestLogger(), enc)
	keysetStore.AdoptCredentialKMS(ring)
	configs := []struct {
		name  string
		store *Store
	}{
		{"adopted keyset", keysetStore},
		{"dual-trust legacy only", newForTest(&mockDB{}, newTestLogger(), enc)},
		{"no cipher configured", newForTest(&mockDB{}, newTestLogger(), nil)},
	}
	for _, cfg := range configs {
		t.Run(cfg.name, func(t *testing.T) {
			for _, v := range corrupt {
				got, err := cfg.store.decryptOrgCredentialKey(ctx, v)
				require.Error(t, err, "corrupted framing %q must fail closed", v)
				assert.Empty(t, got, "the corrupted string must never be served as the credential")
				assert.Contains(t, err.Error(), "refusing")
				assert.NotContains(t, err.Error(), orgCredProbeKey, "refusal errors stay material-free")
			}
		})
	}

	// End to end: a corrupted api_key_ct row is never resolved into a
	// credential — ResolveKey reports (ok=false, err) and the caller moves
	// on, exactly as for an undecryptable envelope.
	db := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{{versionedCredPrefix + "abc"}}}
		},
	}
	resolver := newForTest(db, newTestLogger(), nil)
	resolved, ok, err := resolver.ResolveKey(ctx, "org-1", "openai-compat", "")
	require.Error(t, err)
	assert.False(t, ok)
	assert.Empty(t, resolved)
	assert.NotContains(t, err.Error(), orgCredProbeKey)
}

// TestOrgCredential_VersionedAdoption_NoStopRotation_UnderTraffic extends the
// pkg/kms -race no-stop pattern to the STORE seam: writers seal through the
// store's credential cipher, a migrator drains old-format values through the
// store's lazy-migration path, and readers resolve through the store's
// dual-trust dispatch — while the orchestrator rotates 1→2 and retires v1
// mid-traffic. No worker is ever stopped or paused by the rotation itself;
// writers stop only for the modeled backlog freeze that precedes retirement,
// and readers run unbroken through the whole sequence.
func TestOrgCredential_VersionedAdoption_NoStopRotation_UnderTraffic(t *testing.T) {
	const (
		writers    = 3
		readers    = 3
		legacyRows = 32
	)
	probe := orgCredProbeKey
	ctx := context.Background()

	ring, err := kms.NewVersioned(kms.Keyset{Current: 1, Versions: []kms.VersionedKey{
		{Version: 1, Key: verCredRingKey(0xD0)},
	}})
	require.NoError(t, err)
	enc := encryption.MustNew(encryption.EncodeKey())
	store := newForTest(&mockDB{}, newTestLogger(), enc)
	store.AdoptCredentialKMS(ring)

	var (
		mu             sync.Mutex
		stored         = make(map[string]string) // row id → at-rest value
		nextID         int
		writerStop     = make(chan struct{})
		readerStop     = make(chan struct{})
		migratorStop   = make(chan struct{})
		writerWG       sync.WaitGroup
		readerWG       sync.WaitGroup
		migratorWG     sync.WaitGroup
		started        sync.WaitGroup // signals each worker completed its first op
		errs           = make(chan error, 32)
		retireArmed    atomic.Bool  // set strictly before the first Retire
		encCounter     atomic.Int64 // store-seal ops
		decCounter     atomic.Int64 // store-resolve ops
		migrated       atomic.Int64
		legacyMigrated atomic.Int64
	)
	started.Add(writers + readers + 1)

	// Pre-seed legacy enc: rows (the deployment's existing data): the
	// dual-trust read must serve them until the drain migrates them.
	for i := 0; i < legacyRows; i++ {
		ct, err := enc.Encrypt(probe)
		require.NoError(t, err)
		stored["legacy-"+string(rune('a'+i))] = ct
	}

	// Writers: continuously seal through the store under whatever ring
	// version is current (work-first ordering, same as the kms pattern).
	for w := 0; w < writers; w++ {
		writerWG.Add(1)
		go func() {
			defer writerWG.Done()
			var signal sync.Once
			defer signal.Do(started.Done)
			for {
				ct, last4, err := store.encryptOrgCredentialKey(ctx, probe)
				if err != nil {
					errs <- err
					return
				}
				if last4 != orgCredProbeLast4 {
					errs <- errors.New("store seal produced the wrong display mask")
					return
				}
				encCounter.Add(1)
				mu.Lock()
				id := "row-" + strconv.Itoa(nextID)
				nextID++
				stored[id] = ct
				mu.Unlock()
				signal.Do(started.Done)
				select {
				case <-writerStop:
					return
				default:
				}
			}
		}()
	}

	// Migrator: continuously drains old-format values through the store's
	// lazy migration (the per-row drain of the runbook — never a pause).
	migratorWG.Add(1)
	go func() {
		defer migratorWG.Done()
		var signal sync.Once
		defer signal.Do(started.Done)
		for {
			mu.Lock()
			sample := make(map[string]string, len(stored))
			for id, v := range stored {
				sample[id] = v
			}
			mu.Unlock()
			for id, v := range sample {
				mig, ok := store.migrateOrgCredentialEnvelope(ctx, v)
				if !ok {
					continue
				}
				migrated.Add(1)
				if strings.HasPrefix(v, "enc:") {
					legacyMigrated.Add(1)
				}
				mu.Lock()
				stored[id] = mig
				mu.Unlock()
			}
			signal.Do(started.Done)
			select {
			case <-migratorStop:
				return
			default:
			}
		}
	}()

	// Readers: continuously resolve a rolling sample through the store's
	// dual-trust dispatch. Samples are copied under the lock and decrypted
	// outside it (stored values are immutable strings). A retire that lands
	// mid-read lawfully closes the dual-trust window for v1 artifacts — but
	// only after retireArmed was set, i.e. strictly before the first Retire.
	for r := 0; r < readers; r++ {
		readerWG.Add(1)
		go func() {
			defer readerWG.Done()
			var signal sync.Once
			defer signal.Do(started.Done)
			for {
				mu.Lock()
				sample := make([]string, 0, len(stored))
				for _, v := range stored {
					sample = append(sample, v)
				}
				mu.Unlock()
				for _, v := range sample {
					got, err := store.decryptOrgCredentialKey(ctx, v)
					if err != nil {
						if errors.Is(err, kms.ErrRetiredKeyVersion) && retireArmed.Load() {
							continue
						}
						errs <- err
						return
					}
					if got != probe {
						errs <- errors.New("store resolve returned the wrong plaintext")
						return
					}
					decCounter.Add(1)
				}
				signal.Do(started.Done)
				select {
				case <-readerStop:
					return
				default:
				}
			}
		}()
	}

	started.Wait() // every worker is in its loop before the first rotation

	// --- Phase 1: rotate 1→2 while writers, readers AND the migrator flow.
	require.NoError(t, ring.Rotate(2, verCredRingKey(0xD9)))
	require.Equal(t, uint64(2), ring.Current())

	// --- Phase 2: freeze the backlog, then drain it at the seam.
	close(writerStop)
	writerWG.Wait()
	mu.Lock()
	for id, v := range stored {
		if mig, ok := store.migrateOrgCredentialEnvelope(ctx, v); ok {
			migrated.Add(1)
			if strings.HasPrefix(v, "enc:") {
				legacyMigrated.Add(1)
			}
			stored[id] = mig
		}
	}
	mu.Unlock()

	// --- Phase 3: revoke v1 while readers and the migrator still flow.
	retireArmed.Store(true)
	require.NoError(t, ring.Retire(1))

	// Post-retire store traffic (v2) is unaffected.
	ct, last4, err := store.encryptOrgCredentialKey(ctx, probe)
	require.NoError(t, err)
	require.Equal(t, orgCredProbeLast4, last4)
	got, err := store.decryptOrgCredentialKey(ctx, ct)
	require.NoError(t, err)
	require.Equal(t, probe, got)

	close(readerStop)
	readerWG.Wait()
	close(migratorStop)
	migratorWG.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("traffic error during no-stop store rotation: %v", err)
	}

	// Traffic actually flowed through every stage of the seam.
	if encCounter.Load() == 0 || decCounter.Load() == 0 || migrated.Load() == 0 || legacyMigrated.Load() == 0 {
		t.Fatalf("scenario produced no traffic: enc=%d dec=%d migrated=%d legacy=%d",
			encCounter.Load(), decCounter.Load(), migrated.Load(), legacyMigrated.Load())
	}

	// Post-sequence invariant: every surviving at-rest value resolves to the
	// probe through the store — legacy rows were drained, versioned rows sit
	// on a live version.
	mu.Lock()
	defer mu.Unlock()
	if len(stored) == 0 {
		t.Fatal("the scenario stored no values")
	}
	for id, v := range stored {
		got, err := store.decryptOrgCredentialKey(ctx, v)
		if err != nil {
			t.Fatalf("stored value %s must resolve after the rotation sequence: %v", id, err)
		}
		if got != probe {
			t.Fatalf("stored value %s resolved to %q", id, got)
		}
	}
}
