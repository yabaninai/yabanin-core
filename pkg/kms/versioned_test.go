package kms

// Versioned-envelope lifecycle tests (N01-P04-T03/T07/T08/T09):
//
//   - envelope round-trip with embedded key version; new writes always name
//     the current version (T03);
//   - the dual-trust window: old-version envelopes stay decryptable after a
//     rotation, cross-version material fails closed both ways (T03);
//   - the retirement contract: after Retire, the old version refuses every
//     decrypt with a material-free error and can never come back (T06);
//   - the fail-closed corpus: unknown/retired/unframed envelopes return
//     (nil, err), no code path degrades to plaintext, and no error carries
//     key material, plaintext, or ciphertext (T07);
//   - interruption: a torn/truncated keyset record refuses to load, an
//     interrupted rotation leaves the serving ring consistent, and retry
//     converges (Rotate idempotence + whole-state atomic persist) (T08);
//   - old/new config: the legacy single-key factory path still works, the
//     versioned keyset is explicit, and unsupported combinations fail loudly
//     (T09).

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// verKey builds a deterministic 32-byte key for a version (test-only
// material, not a real credential).
func verKey(seed byte) []byte { return masterKey(seed) }

// writeKeysetFile persists a keyset through the production writer and
// returns the path.
func writeKeysetFile(t *testing.T, ks Keyset) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keyset.json")
	if err := SaveKeysetFile(path, ks); err != nil {
		t.Fatalf("SaveKeysetFile: %v", err)
	}
	return path
}

func newOneVersionKMS(t *testing.T, seed byte) *VersionedKMS {
	t.Helper()
	v, err := NewVersioned(Keyset{Current: 1, Versions: []VersionedKey{{Version: 1, Key: verKey(seed)}}})
	if err != nil {
		t.Fatalf("NewVersioned: %v", err)
	}
	return v
}

// --- T03: envelope shape and the dual-trust window -------------------------

func TestVersionedKMS_RoundTripAndVersionEmbedding(t *testing.T) {
	v := newOneVersionKMS(t, 0x40)
	payload := []byte("versioned-envelope-payload")

	ct, err := v.Encrypt(context.Background(), payload)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !bytes.HasPrefix(ct, []byte(envelopeMagic)) {
		t.Fatalf("envelope must carry the %q framing, got prefix %q", envelopeMagic, ct[:4])
	}
	if ver, err := v.EnvelopeVersion(ct); err != nil || ver != 1 {
		t.Fatalf("EnvelopeVersion = %d, %v; want 1, nil", ver, err)
	}
	got, err := v.Decrypt(context.Background(), ct)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("round-trip: %q, %v", got, err)
	}

	// Rotation: new writes must name the new version without any stop.
	if err := v.Rotate(2, verKey(0x41)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if v.Current() != 2 {
		t.Fatalf("Current = %d, want 2 after Rotate", v.Current())
	}
	ct2, err := v.Encrypt(context.Background(), payload)
	if err != nil {
		t.Fatalf("Encrypt after rotate: %v", err)
	}
	if ver, _ := v.EnvelopeVersion(ct2); ver != 2 {
		t.Fatalf("post-rotation write names version %d, want 2", ver)
	}

	// Dual trust: the pre-rotation envelope still decrypts.
	got, err = v.Decrypt(context.Background(), ct)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("old-version envelope must decrypt during the dual-trust window: %q, %v", got, err)
	}
}

func TestVersionedKMS_ReencryptMigratesToCurrent(t *testing.T) {
	v := newOneVersionKMS(t, 0x42)
	payload := []byte("reencrypt-migration-payload")
	ct1, err := v.Encrypt(context.Background(), payload)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := v.Rotate(2, verKey(0x43)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	migrated, err := v.Reencrypt(context.Background(), ct1)
	if err != nil {
		t.Fatalf("Reencrypt: %v", err)
	}
	if ver, _ := v.EnvelopeVersion(migrated); ver != 2 {
		t.Fatalf("migrated envelope names version %d, want 2", ver)
	}
	if got, err := v.Decrypt(context.Background(), migrated); err != nil || string(got) != string(payload) {
		t.Fatalf("migrated envelope must round-trip: %q, %v", got, err)
	}

	// Idempotent: migrating an already-current envelope is a passthrough.
	again, err := v.Reencrypt(context.Background(), migrated)
	if err != nil {
		t.Fatalf("Reencrypt(current): %v", err)
	}
	if !bytes.Equal(again, migrated) {
		t.Fatal("Reencrypt of a current envelope must not rewrite it")
	}
}

// --- T06: the retirement contract ------------------------------------------

func TestVersionedKMS_RetireRevokesOldVersionPerContract(t *testing.T) {
	v := newOneVersionKMS(t, 0x44)
	payload := []byte("retire-contract-payload")
	ct1, err := v.Encrypt(context.Background(), payload)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := v.Rotate(2, verKey(0x45)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// Contract ordering: retiring the CURRENT write version is refused loudly
	// (it would orphan all subsequent writes).
	if err := v.Retire(2); err == nil {
		t.Fatal("retiring the current write version must be refused")
	}
	// Retiring an unknown version names it without material.
	if err := v.Retire(99); !errors.Is(err, ErrUnknownKeyVersion) {
		t.Fatalf("retiring an unknown version = %v, want ErrUnknownKeyVersion", err)
	}

	// The drain step (Reencrypt) removes the version's data, THEN retire
	// revokes it.
	if _, err := v.Reencrypt(context.Background(), ct1); err != nil {
		t.Fatalf("drain Reencrypt: %v", err)
	}
	if err := v.Retire(1); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	got, err := v.Decrypt(context.Background(), ct1)
	if !errors.Is(err, ErrRetiredKeyVersion) {
		t.Fatalf("retired-version decrypt = %q, %v; want ErrRetiredKeyVersion", got, err)
	}
	if got != nil {
		t.Fatalf("retired-version decrypt returned payload alongside the error: %q", got)
	}
	// Retire is idempotent.
	if err := v.Retire(1); err != nil {
		t.Fatalf("Retire must be idempotent: %v", err)
	}

	// A retired version can never be resurrected or reused.
	if err := v.Rotate(1, verKey(0x44)); err == nil {
		t.Fatal("re-using a retired version number must be refused")
	}

	// Traffic continues on the current version after two retires.
	ct2, err := v.Encrypt(context.Background(), payload)
	if err != nil {
		t.Fatalf("post-retire Encrypt: %v", err)
	}
	if got, err := v.Decrypt(context.Background(), ct2); err != nil || string(got) != string(payload) {
		t.Fatalf("current-version traffic must be unaffected: %q, %v", got, err)
	}
}

// --- T07: fail-closed corpus, material-free diagnostics ---------------------

func TestVersionedKMS_FailClosedCorpus(t *testing.T) {
	v, err := NewVersioned(Keyset{Current: 2, Versions: []VersionedKey{
		{Version: 1, Key: verKey(0x50)},
		{Version: 2, Key: verKey(0x51)},
	}})
	if err != nil {
		t.Fatalf("NewVersioned: %v", err)
	}
	payload := []byte("fail-closed-corpus-payload")
	ct, err := v.Encrypt(context.Background(), payload)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ctB64 := base64.StdEncoding.EncodeToString(ct)
	keyHex := "00" // probe substrings that must never appear

	// Craft an envelope naming an untrusted version (99): valid framing,
	// version absent from the ring — the "KMS lost this key" shape.
	unknown := append([]byte(envelopeMagic), 0, 0, 0, 0, 0, 0, 0, 99)
	unknown = append(unknown, ct[envelopeHeaderLen:]...)

	// Legacy/unframed input: raw LocalKMS output must never be silently
	// decoded or passed through as plaintext.
	legacy, err := func() ([]byte, error) {
		l, lerr := NewLocalKMS(verKey(0x52))
		if lerr != nil {
			return nil, lerr
		}
		return l.Encrypt(context.Background(), payload)
	}()
	if err != nil {
		t.Fatalf("build legacy ct: %v", err)
	}

	corpus := []struct {
		name     string
		envelope []byte
		wantErr  error
		// headerOK marks bodies whose FRAMING is intact (truncated/tampered
		// payloads): EnvelopeVersion is a header-only probe by design and
		// Reencrypt passthroughs already-current inputs — the decrypt path
		// is where integrity must fail.
		headerOK bool
	}{
		{"unknown version", unknown, ErrUnknownKeyVersion, false},
		{"no framing (legacy raw ct)", legacy, ErrMalformedEnvelope, false},
		{"empty", nil, ErrMalformedEnvelope, false},
		{"magic only", []byte(envelopeMagic), ErrMalformedEnvelope, false},
		{"foreign framing", append([]byte("enc:"), ct...), ErrMalformedEnvelope, false},
		{"truncated body", ct[:envelopeHeaderLen+4], ErrMalformedEnvelope, true},
		{"tampered body", func() []byte {
			bad := make([]byte, len(ct))
			copy(bad, ct)
			bad[len(bad)-1] ^= 0xFF
			return bad
		}(), nil, true},
	}
	for _, tc := range corpus {
		t.Run(tc.name, func(t *testing.T) {
			got, err := v.Decrypt(context.Background(), tc.envelope)
			if err == nil {
				t.Fatalf("%s must fail closed, got %q", tc.name, got)
			}
			if got != nil {
				t.Errorf("%s returned payload alongside the error: %q", tc.name, got)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("%s error = %v, want %v", tc.name, err, tc.wantErr)
			}
			// No error may carry plaintext, ciphertext, or key material.
			for _, material := range []string{string(payload), ctB64, keyHex} {
				if strings.Contains(err.Error(), material) {
					t.Errorf("%s error carried material: %q", tc.name, err.Error())
				}
			}
			// The header probe and the migration path have pinned semantics
			// per framing class; neither ever produces usable plaintext.
			ver, verr := v.EnvelopeVersion(tc.envelope)
			if tc.headerOK {
				if verr != nil || ver != 2 {
					t.Errorf("EnvelopeVersion(%s) = %d, %v; want header-only probe success (2)", tc.name, ver, verr)
				}
				out, rerr := v.Reencrypt(context.Background(), tc.envelope)
				if rerr != nil || !bytes.Equal(out, tc.envelope) {
					t.Errorf("Reencrypt(%s) = %q, %v; want same-input passthrough (already current)", tc.name, out, rerr)
				}
			} else {
				if verr == nil {
					t.Errorf("EnvelopeVersion(%s) = %d, want error", tc.name, ver)
				}
				if out, rerr := v.Reencrypt(context.Background(), tc.envelope); rerr == nil {
					t.Errorf("Reencrypt(%s) = %q, want error", tc.name, out)
				}
			}
		})
	}

	// The tampered body decrypts to no plaintext, ever (covered above by the
	// error path) and the SAME key still reads the untouched envelope.
	if got, err := v.Decrypt(context.Background(), ct); err != nil || string(got) != string(payload) {
		t.Fatalf("untouched envelope must still decrypt: %q, %v", got, err)
	}
}

// --- T09: old/new configuration matrix --------------------------------------

func TestVersionedKMS_ConfigMatrix(t *testing.T) {
	keysetPath := writeKeysetFile(t, Keyset{Current: 1, Versions: []VersionedKey{{Version: 1, Key: verKey(0x60)}}})

	t.Run("legacy single-key config still works", func(t *testing.T) {
		t.Setenv(keysetFileEnv, "")
		t.Setenv("YABANIN_KMS_LOCAL_KEY_FILE", "")
		t.Setenv("YABANIN_KMS_LOCAL_KEY", "0123456789abcdef0123456789abcdef")
		p, err := New("local", "")
		if err != nil {
			t.Fatalf("legacy New(local): %v", err)
		}
		if _, ok := p.(*LocalKMS); !ok {
			t.Fatalf("legacy config must build the unversioned LocalKMS, got %T", p)
		}
	})

	t.Run("explicit versioned keyset config", func(t *testing.T) {
		t.Setenv(keysetFileEnv, keysetPath)
		t.Setenv("YABANIN_KMS_LOCAL_KEY_FILE", "")
		t.Setenv("YABANIN_KMS_LOCAL_KEY", "")
		p, err := New("local", "")
		if err != nil {
			t.Fatalf("versioned New(local): %v", err)
		}
		if _, ok := p.(*VersionedKMS); !ok {
			t.Fatalf("keyset config must build a VersionedKMS, got %T", p)
		}
	})

	t.Run("both key sources at once fail loudly", func(t *testing.T) {
		t.Setenv(keysetFileEnv, keysetPath)
		t.Setenv("YABANIN_KMS_LOCAL_KEY_FILE", "")
		t.Setenv("YABANIN_KMS_LOCAL_KEY", "0123456789abcdef0123456789abcdef")
		if p, err := New("local", ""); err == nil {
			t.Fatalf("ambiguous key source = %v, want error", p)
		} else if strings.Contains(err.Error(), "0123456789abcdef0123456789abcdef") {
			t.Errorf("combo error echoed key material: %q", err.Error())
		}

		t.Setenv("YABANIN_KMS_LOCAL_KEY", "")
		t.Setenv("YABANIN_KMS_LOCAL_KEY_FILE", keysetPath+".key")
		if p, err := New("local", ""); err == nil {
			t.Fatalf("keyset + key FILE = %v, want error", p)
		}
	})

	t.Run("aws stub stays fail-closed even with a keyset", func(t *testing.T) {
		t.Setenv(keysetFileEnv, keysetPath)
		if p, err := New("aws", "alias/x"); err == nil || p != nil {
			t.Fatalf("New(aws) with keyset = %v, %v; want stub refusal", p, err)
		}
	})

	t.Run("unknown provider refused", func(t *testing.T) {
		t.Setenv(keysetFileEnv, keysetPath)
		t.Setenv("YABANIN_KMS_LOCAL_KEY", "")
		if p, err := New("vault", ""); err == nil {
			t.Fatalf("unknown provider = %v, want error", p)
		}
	})
}

func TestNewVersioned_KeysetValidationLoudFailures(t *testing.T) {
	ver := func(v uint64, seed byte, retired bool) VersionedKey {
		return VersionedKey{Version: v, Key: verKey(seed), Retired: retired}
	}
	cases := []struct {
		name string
		ks   Keyset
	}{
		{"no versions", Keyset{Current: 1}},
		{"no current", Keyset{Versions: []VersionedKey{ver(1, 0x61, false)}}},
		{"current missing from versions", Keyset{Current: 7, Versions: []VersionedKey{ver(1, 0x61, false)}}},
		{"current retired", Keyset{Current: 1, Versions: []VersionedKey{ver(1, 0x61, true)}}},
		{"duplicate versions", Keyset{Current: 1, Versions: []VersionedKey{ver(1, 0x61, false), ver(1, 0x62, false)}}},
		{"version 0", Keyset{Current: 0, Versions: []VersionedKey{ver(0, 0x61, false)}}},
		{"short key", Keyset{Current: 1, Versions: []VersionedKey{{Version: 1, Key: []byte("short")}}}},
		{"nil key", Keyset{Current: 1, Versions: []VersionedKey{{Version: 1}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if v, err := NewVersioned(tc.ks); err == nil {
				t.Fatalf("NewVersioned(%s) = %v, want error", tc.name, v)
			}
		})
	}

	// A retired NON-current version alongside an active current one is the
	// supported post-rotation shape and must build.
	if _, err := NewVersioned(Keyset{Current: 2, Versions: []VersionedKey{ver(1, 0x61, true), ver(2, 0x62, false)}}); err != nil {
		t.Fatalf("retired+active keyset must build: %v", err)
	}
}

// --- T08: interruption, torn records, convergence ---------------------------

func TestSaveLoadKeysetFile_RoundTripAndAtomicRecord(t *testing.T) {
	ks := Keyset{Current: 2, Versions: []VersionedKey{
		{Version: 1, Key: verKey(0x70), Retired: true},
		{Version: 2, Key: verKey(0x71)},
	}}
	path := writeKeysetFile(t, ks)

	got, err := LoadKeysetFile(path)
	if err != nil {
		t.Fatalf("LoadKeysetFile: %v", err)
	}
	if got.Current != 2 || len(got.Versions) != 2 {
		t.Fatalf("round-trip keyset = %+v", got)
	}
	for i, vk := range got.Versions {
		if !bytes.Equal(vk.Key, ks.Versions[i].Key) || vk.Retired != ks.Versions[i].Retired {
			t.Fatalf("version %d mismatch: %+v", vk.Version, vk)
		}
	}
	// The record is mode 0600 (it holds key material).
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("keyset file mode = %v, %v; want 0600", fi.Mode(), err)
	}

	// SaveKeysetFile refuses to persist a malformed ring.
	for _, bad := range []Keyset{
		{Current: 1},
		{Versions: ks.Versions},
		{Current: 2, Versions: []VersionedKey{{Version: 2, Key: []byte("nope")}}},
		{Current: 1, Versions: []VersionedKey{{Version: 1, Key: verKey(0x70), Retired: true}}},
	} {
		if err := SaveKeysetFile(filepath.Join(t.TempDir(), "bad.json"), bad); err == nil {
			t.Fatalf("SaveKeysetFile(%+v) must be refused", bad)
		}
	}
}

func TestLoadKeysetFile_TornRecordFailsLoudly(t *testing.T) {
	dir := t.TempDir()
	raw, err := json.MarshalIndent(keysetFile{
		Current: 1,
		Versions: []keyVersionFile{{
			Version: 1,
			KeyHex:  "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f", // not the real key bytes
		}},
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	cases := []struct {
		name    string
		content []byte
	}{
		{"truncated mid-record", raw[:len(raw)/2]},
		{"empty file", nil},
		{"garbage", []byte("{\"current\":1,\"versions\":[{\"version\":1,\"key_hex\":\"zz\"}]}")},
		{"unknown fields", []byte(`{"current":1,"versions":[],"surprise":true}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "torn.json")
			if err := os.WriteFile(path, tc.content, 0o600); err != nil {
				t.Fatalf("write torn record: %v", err)
			}
			ks, err := LoadKeysetFile(path)
			if err == nil {
				t.Fatalf("torn record (%s) = %+v, want loud load failure", tc.name, ks)
			}
		})
	}
}

func TestVersionedKMS_InterruptedRotationConverges(t *testing.T) {
	payload := []byte("interrupted-rotation-payload")
	v := newOneVersionKMS(t, 0x73)
	ct1, err := v.Encrypt(context.Background(), payload)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	path := filepath.Join(t.TempDir(), "keyset.json")
	if err := SaveKeysetFile(path, Keyset{Current: 1, Versions: []VersionedKey{{Version: 1, Key: verKey(0x73)}}}); err != nil {
		t.Fatalf("initial persist: %v", err)
	}

	// The rotation lands in memory but the persist is interrupted (crash
	// before the rename): the serving ring must stay fully consistent.
	if err := v.Rotate(2, verKey(0x74)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	ct2, err := v.Encrypt(context.Background(), payload)
	if err != nil {
		t.Fatalf("post-rotation Encrypt: %v", err)
	}
	if got, err := v.Decrypt(context.Background(), ct1); err != nil || string(got) != string(payload) {
		t.Fatalf("in-flight old envelope must survive an unpersisted rotation: %q, %v", got, err)
	}
	if got, err := v.Decrypt(context.Background(), ct2); err != nil || string(got) != string(payload) {
		t.Fatalf("new envelope after unpersisted rotation: %q, %v", got, err)
	}

	// The on-disk record is still the pre-rotation one (rename never
	// happened); loading it must yield the OLD ring, never a torn hybrid.
	onDisk, err := LoadKeysetFile(path)
	if err != nil {
		t.Fatalf("load after interrupted persist: %v", err)
	}
	if onDisk.Current != 1 || len(onDisk.Versions) != 1 {
		t.Fatalf("on-disk record must be the intact pre-rotation state, got %+v", onDisk)
	}

	// Retry converges: persisting the live state (rotate + drain + retire,
	// replayed) produces a record that boots an equivalent ring.
	if _, err := v.Reencrypt(context.Background(), ct1); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if err := v.Retire(1); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if err := SaveKeysetFile(path, Keyset{
		Current: 2,
		Versions: []VersionedKey{
			{Version: 1, Key: verKey(0x73), Retired: true},
			{Version: 2, Key: verKey(0x74)},
		},
	}); err != nil {
		t.Fatalf("converging persist: %v", err)
	}
	rebooted, err := NewVersioned(loadKeyset(t, path))
	if err != nil {
		t.Fatalf("reboot from converged record: %v", err)
	}
	if _, err := rebooted.Decrypt(context.Background(), ct2); err != nil {
		t.Fatalf("rebooted ring must serve post-rotation envelopes: %v", err)
	}
	if _, err := rebooted.Decrypt(context.Background(), ct1); !errors.Is(err, ErrRetiredKeyVersion) {
		t.Fatalf("rebooted ring must keep the retirement: %v", err)
	}

	// Rotate idempotence: the same version+key is a no-op success; a
	// different key for a live version is a loud refusal.
	if err := v.Rotate(2, verKey(0x74)); err != nil {
		t.Fatalf("idempotent Rotate: %v", err)
	}
	if err := v.Rotate(2, verKey(0x75)); err == nil {
		t.Fatal("re-binding a live version to different key material must be refused")
	}
}

func loadKeyset(t *testing.T, path string) Keyset {
	t.Helper()
	ks, err := LoadKeysetFile(path)
	if err != nil {
		t.Fatalf("LoadKeysetFile(%s): %v", path, err)
	}
	return ks
}
