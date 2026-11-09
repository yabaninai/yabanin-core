package kms

// Versioned envelope encryption: a key RING instead of a single static key.
//
// Envelope format (self-describing, one immutable buffer — no torn ciphertext
// is possible because the envelope is produced and consumed as a single
// value):
//
//	[ "ykm1" ][ uint64 big-endian key version ][ GCM nonce || AES-GCM ct ]
//
// Rotation contract (the contract T06 acceptance is pinned against):
//
//  1. Rotate(version, key) installs a new CURRENT write version by an atomic
//     snapshot swap. Traffic never stops: in-flight operations hold their own
//     immutable ring snapshot, new writes immediately use the new version,
//     and old-version envelopes stay decryptable (the dual-trust window).
//  2. Reencrypt lazily migrates an old-version envelope to the current
//     version (no-op when already current). Operators drain the backlog —
//     per-row on read or by sweep — while traffic keeps flowing.
//  3. Retire(version) closes the dual-trust window for that version: it is
//     the explicit "old secret is revoked" step. After retirement the version
//     refuses every decrypt with ErrRetiredKeyVersion and can never become
//     current again. Contract: retire a version ONLY after Reencrypt drained
//     all data under it; retiring the current write version is refused loudly.
//  4. The keyset record on disk is replaced atomically (temp file + fsync +
//     rename). An interrupted rotation therefore never tears the record: the
//     serving ring lives in memory and the file converges on retry because
//     SaveKeysetFile always writes the whole state.
//
// Fail-closed invariants (the negative corpus): a missing/malformed keyset
// refuses construction; an envelope naming an untrusted or retired version,
// or lacking the versioned framing entirely, fails with an error that names
// only version numbers and lengths — never key material, plaintext, or
// ciphertext — and Decrypt never returns payload bytes alongside an error.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
)

// envelopeMagic frames a versioned envelope. Everything else (raw LocalKMS
// output, "enc:" strings, foreign formats) must fail loudly instead of being
// best-effort decoded.
const envelopeMagic = "ykm1"

// envelopeHeaderLen is magic + the 8-byte key version.
const envelopeHeaderLen = len(envelopeMagic) + 8

// Sentinel errors: consumers branch on these; the wrapped messages add only
// version numbers and lengths, never material.
var (
	ErrMalformedEnvelope = errors.New("kms: malformed versioned envelope")
	ErrUnknownKeyVersion = errors.New("kms: envelope key version is not trusted by this deployment")
	ErrRetiredKeyVersion = errors.New("kms: envelope key version is retired")
)

// VersionedKey is one key version in the ring. Key must be 16 (AES-128) or
// 32 (AES-256) bytes of keying material.
type VersionedKey struct {
	Version uint64
	Key     []byte
	Retired bool
}

// Keyset is an explicit key-ring configuration: which versions exist, which
// one receives new writes, and which are retired.
type Keyset struct {
	Current  uint64
	Versions []VersionedKey
}

// keyRing is an immutable snapshot of the trusted versions. Every Encrypt/
// Decrypt reads one snapshot, so rotation never blocks or corrupts in-flight
// operations.
type keyRing struct {
	current uint64
	entries map[uint64]ringEntry
}

type ringEntry struct {
	// fp is a SHA-256 fingerprint of the key material, used only for the
	// idempotent-rotation equality check (never logged, never serialized).
	fp      [sha256.Size]byte
	aead    cipher.AEAD
	retired bool
}

// VersionedKMS is a Provider whose envelopes carry the key version, so a
// deployment can rotate key material online: add a version, drain, retire.
type VersionedKMS struct {
	ring atomic.Pointer[keyRing]
}

// NewVersioned builds a versioned provider from an explicit keyset. Every
// inconsistency (no versions, missing/retired current, duplicate versions,
// wrong key sizes, version 0) is a loud construction error — a half-specified
// ring must never start.
func NewVersioned(ks Keyset) (*VersionedKMS, error) {
	ring, err := buildRing(ks)
	if err != nil {
		return nil, err
	}
	v := &VersionedKMS{}
	v.ring.Store(ring)
	return v, nil
}

// buildRing validates the keyset and compiles it into an immutable snapshot.
func buildRing(ks Keyset) (*keyRing, error) {
	if len(ks.Versions) == 0 {
		return nil, fmt.Errorf("kms: versioned keyset has no key versions")
	}
	if ks.Current == 0 {
		return nil, fmt.Errorf("kms: versioned keyset must name the current write version")
	}
	entries := make(map[uint64]ringEntry, len(ks.Versions))
	for _, vk := range ks.Versions {
		if vk.Version == 0 {
			return nil, fmt.Errorf("kms: key version 0 is reserved; versions start at 1")
		}
		if _, dup := entries[vk.Version]; dup {
			return nil, fmt.Errorf("kms: duplicate key version %d", vk.Version)
		}
		if len(vk.Key) != 16 && len(vk.Key) != 32 {
			return nil, fmt.Errorf("kms: key version %d must be 16 (AES-128) or 32 (AES-256) bytes, got %d", vk.Version, len(vk.Key))
		}
		entry := ringEntry{retired: vk.Retired, fp: sha256.Sum256(vk.Key)}
		if !vk.Retired {
			aead, err := newAEAD(vk.Key)
			if err != nil {
				return nil, fmt.Errorf("kms: key version %d: %w", vk.Version, err)
			}
			entry.aead = aead
		}
		entries[vk.Version] = entry
	}
	cur, ok := entries[ks.Current]
	if !ok {
		return nil, fmt.Errorf("kms: current write version %d is not present in the keyset", ks.Current)
	}
	if cur.retired {
		return nil, fmt.Errorf("kms: current write version %d must not be retired; rotate to an active version first", ks.Current)
	}
	return &keyRing{current: ks.Current, entries: entries}, nil
}

// newAEAD builds the AES-GCM AEAD for one key version.
func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	return aead, nil
}

// Current reports the version that receives new writes.
func (v *VersionedKMS) Current() uint64 {
	return v.ring.Load().current
}

// Encrypt seals plaintext under the CURRENT version. The envelope is a single
// self-describing buffer: callers persist it as one value, so an interrupted
// write cannot tear it.
//
// Nonce bound: each seal draws a fresh random 96-bit GCM nonce, so safe
// encryptions per key version are bounded at ~2³² (the NIST SP 800-38D
// birthday bound for random nonces). Rotate to a fresh version — and drain
// the old one with Reencrypt — before approaching that bound.
func (v *VersionedKMS) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	ring := v.ring.Load()
	entry := ring.entries[ring.current]
	out := make([]byte, 0, envelopeHeaderLen+entry.aead.NonceSize()+len(plaintext)+entry.aead.Overhead())
	out = append(out, envelopeMagic...)
	var ver [8]byte
	binary.BigEndian.PutUint64(ver[:], ring.current)
	out = append(out, ver[:]...)

	nonce := make([]byte, entry.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("kms: generate nonce: %w", err)
	}
	out = append(out, nonce...)
	out = entry.aead.Seal(out, nonce, plaintext, nil)
	return out, nil
}

// Decrypt opens a versioned envelope under the version named in its header.
// Untrusted and retired versions fail closed with distinct sentinel errors;
// a non-versioned envelope (e.g. legacy raw ciphertext) is never silently
// accepted. Decrypt never returns payload bytes alongside an error.
func (v *VersionedKMS) Decrypt(_ context.Context, envelope []byte) ([]byte, error) {
	version, entry, err := v.resolve(envelope)
	if err != nil {
		return nil, err
	}
	if len(envelope) < envelopeHeaderLen+entry.aead.NonceSize() {
		return nil, fmt.Errorf("%w: version %d body too short", ErrMalformedEnvelope, version)
	}
	nonce := envelope[envelopeHeaderLen : envelopeHeaderLen+entry.aead.NonceSize()]
	plain, err := entry.aead.Open(nil, nonce, envelope[envelopeHeaderLen+entry.aead.NonceSize():], nil)
	if err != nil {
		return nil, fmt.Errorf("kms: decrypt with key version %d: %w", version, err)
	}
	return plain, nil
}

// resolve parses the envelope header and looks the version up in the ring.
func (v *VersionedKMS) resolve(envelope []byte) (uint64, ringEntry, error) {
	if len(envelope) < envelopeHeaderLen || string(envelope[:len(envelopeMagic)]) != envelopeMagic {
		return 0, ringEntry{}, fmt.Errorf("%w: missing %q framing", ErrMalformedEnvelope, envelopeMagic)
	}
	version := binary.BigEndian.Uint64(envelope[len(envelopeMagic):envelopeHeaderLen])
	entry, ok := v.ring.Load().entries[version]
	if !ok {
		return version, ringEntry{}, fmt.Errorf("%w: %d", ErrUnknownKeyVersion, version)
	}
	if entry.retired {
		return version, ringEntry{}, fmt.Errorf("%w: %d", ErrRetiredKeyVersion, version)
	}
	return version, entry, nil
}

// EnvelopeVersion reports the key version an envelope was written under
// without decrypting it (the lazy-migration probe).
func (v *VersionedKMS) EnvelopeVersion(envelope []byte) (uint64, error) {
	version, _, err := v.resolve(envelope)
	return version, err
}

// Rotate installs version as the new current write version. It is an atomic
// snapshot swap: traffic keeps flowing, existing envelopes stay decryptable
// under their own versions (dual-trust window). Idempotence: rotating to the
// already-current version with the same key material succeeds as a no-op;
// re-using a version number for DIFFERENT key material is a loud error, and
// a retired version can never be resurrected.
func (v *VersionedKMS) Rotate(version uint64, key []byte) error {
	if version == 0 {
		return fmt.Errorf("kms: key version 0 is reserved; versions start at 1")
	}
	if len(key) != 16 && len(key) != 32 {
		return fmt.Errorf("kms: key version %d must be 16 (AES-128) or 32 (AES-256) bytes, got %d", version, len(key))
	}
	for {
		old := v.ring.Load()
		if entry, exists := old.entries[version]; exists {
			if entry.retired {
				return fmt.Errorf("kms: key version %d is retired and cannot be reused; pick a fresh version number", version)
			}
			if version == old.current {
				if entry.fp == sha256.Sum256(key) {
					return nil // idempotent retry of an already-landed rotation
				}
				return fmt.Errorf("kms: key version %d is already the current write version with different key material; pick a fresh version number", version)
			}
			return fmt.Errorf("kms: key version %d already exists as a non-current version and cannot be rotated to; pick a fresh version number", version)
		}
		aead, err := newAEAD(key)
		if err != nil {
			return fmt.Errorf("kms: key version %d: %w", version, err)
		}
		entries := make(map[uint64]ringEntry, len(old.entries)+1)
		for ver, entry := range old.entries {
			entries[ver] = entry
		}
		entries[version] = ringEntry{aead: aead, fp: sha256.Sum256(key)}
		if v.ring.CompareAndSwap(old, &keyRing{current: version, entries: entries}) {
			return nil
		}
		// A concurrent rotation landed first; retry against its snapshot.
	}
}

// Retire revokes a key version: its envelopes stop decrypting
// (ErrRetiredKeyVersion) and the version can never become current again.
// Contract: retire only after the version's data has been re-encrypted;
// retiring the current write version is refused loudly because it would
// orphan every subsequent write.
func (v *VersionedKMS) Retire(version uint64) error {
	for {
		old := v.ring.Load()
		entry, exists := old.entries[version]
		if !exists {
			return fmt.Errorf("%w: cannot retire unknown key version %d", ErrUnknownKeyVersion, version)
		}
		if entry.retired {
			return nil // idempotent
		}
		if version == old.current {
			return fmt.Errorf("kms: refusing to retire the current write version %d; rotate to a new version first", version)
		}
		entries := make(map[uint64]ringEntry, len(old.entries))
		for ver, e := range old.entries {
			entries[ver] = e
		}
		entries[version] = ringEntry{retired: true} // key schedule released
		if v.ring.CompareAndSwap(old, &keyRing{current: old.current, entries: entries}) {
			return nil
		}
	}
}

// Reencrypt migrates an envelope to the current version. Already-current
// envelopes pass through unchanged WITHOUT being re-opened — the header
// probe is cheap, so a backlog sweep skips millions of already-migrated rows
// without paying an AEAD open each; Decrypt remains the integrity check.
// Old-version envelopes are decrypted and re-sealed one at a time, so
// migration is resumable and never stops traffic.
func (v *VersionedKMS) Reencrypt(ctx context.Context, envelope []byte) ([]byte, error) {
	version, err := v.EnvelopeVersion(envelope)
	if err != nil {
		return nil, err
	}
	if version == v.Current() {
		return envelope, nil
	}
	plain, err := v.Decrypt(ctx, envelope)
	if err != nil {
		return nil, err
	}
	return v.Encrypt(ctx, plain)
}

// ---------------------------------------------------------------------------
// Keyset persistence: the version record on disk is a whole-state JSON
// document replaced atomically (temp file + fsync + rename), so an
// interrupted rotation never tears it and a retry converges.
// ---------------------------------------------------------------------------

type keyVersionFile struct {
	Version uint64 `json:"version"`
	KeyHex  string `json:"key_hex"`
	Retired bool   `json:"retired,omitempty"`
}

type keysetFile struct {
	Current  uint64           `json:"current"`
	Versions []keyVersionFile `json:"versions"`
}

// LoadKeysetFile reads a keyset record. A truncated or corrupt file is a loud
// error — a partial record must never boot a half-trusting ring. Errors name
// the path and the reason, never the key material.
func LoadKeysetFile(path string) (Keyset, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from the operator's env config
	if err != nil {
		return Keyset{}, fmt.Errorf("kms: read keyset %s: %w", path, err)
	}
	var file keysetFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return Keyset{}, fmt.Errorf("kms: parse keyset %s: %w", path, err)
	}
	ks := Keyset{Current: file.Current, Versions: make([]VersionedKey, 0, len(file.Versions))}
	for _, fv := range file.Versions {
		key, err := hex.DecodeString(fv.KeyHex)
		if err != nil {
			return Keyset{}, fmt.Errorf("kms: keyset %s version %d: invalid key hex", path, fv.Version)
		}
		ks.Versions = append(ks.Versions, VersionedKey{Version: fv.Version, Key: key, Retired: fv.Retired})
	}
	return ks, nil
}

// SaveKeysetFile atomically replaces the keyset record: write to a temp file
// in the same directory, fsync, rename over the target, then a best-effort
// directory fsync. A crash before the rename leaves the previous record
// intact; a retry converges because the write is always the whole state.
func SaveKeysetFile(path string, ks Keyset) error {
	if err := validateKeysetShape(ks); err != nil {
		return err
	}
	file := keysetFile{Current: ks.Current, Versions: make([]keyVersionFile, 0, len(ks.Versions))}
	for _, vk := range ks.Versions {
		file.Versions = append(file.Versions, keyVersionFile{
			Version: vk.Version,
			KeyHex:  hex.EncodeToString(vk.Key),
			Retired: vk.Retired,
		})
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("kms: encode keyset: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("kms: create keyset temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName) // no-op after a successful rename
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close() // the write error is the failure being reported
		return fmt.Errorf("kms: write keyset temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close() // the sync error is the failure being reported
		return fmt.Errorf("kms: sync keyset temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("kms: close keyset temp file: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("kms: chmod keyset temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("kms: publish keyset %s: %w", path, err)
	}
	tmpName = "" // renamed into place; the deferred removal must not fire
	// Best-effort directory fsync: where the OS/file system supports it this
	// makes the rename itself durable; a failure to open or sync the
	// directory is ignored (the rename and the file fsync have already
	// succeeded, and a retry always rewrites the whole state), so it must
	// not fail the save.
	if d, err := os.Open(dir); err == nil { //nolint:gosec // dir derives from the operator's env-configured keyset path, same trust as the read above
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// validateKeysetShape checks a keyset before serializing it so a malformed
// ring can never be persisted as if it were valid.
func validateKeysetShape(ks Keyset) error {
	if len(ks.Versions) == 0 {
		return fmt.Errorf("kms: refusing to persist a keyset with no key versions")
	}
	if ks.Current == 0 {
		return fmt.Errorf("kms: refusing to persist a keyset without a current write version")
	}
	seen := make(map[uint64]bool, len(ks.Versions))
	currentKnown, currentRetired := false, false
	for _, vk := range ks.Versions {
		if vk.Version == 0 {
			return fmt.Errorf("kms: refusing to persist key version 0; versions start at 1")
		}
		if seen[vk.Version] {
			return fmt.Errorf("kms: refusing to persist duplicate key version %d", vk.Version)
		}
		seen[vk.Version] = true
		if len(vk.Key) != 16 && len(vk.Key) != 32 {
			return fmt.Errorf("kms: refusing to persist key version %d with a %d-byte key", vk.Version, len(vk.Key))
		}
		if vk.Version == ks.Current {
			currentKnown = true
			currentRetired = vk.Retired
		}
	}
	if !currentKnown {
		return fmt.Errorf("kms: refusing to persist a keyset whose current write version %d is not among the versions", ks.Current)
	}
	if currentRetired {
		return fmt.Errorf("kms: refusing to persist a keyset whose current write version %d is retired", ks.Current)
	}
	return nil
}

// keysetFileEnv selects the versioned keyset record. Setting it opts a
// deployment into versioned envelopes; it is mutually exclusive with the
// single-key legacy variables (an ambiguous key source must fail loudly).
const keysetFileEnv = "YABANIN_KMS_KEYSET_FILE"

// KeysetConfigured reports whether a versioned keyset record is configured
// (YABANIN_KMS_KEYSET_FILE is set). Consumers that adopt versioned envelopes
// store-side use it to keep the decision config-driven in one place: false
// means the legacy single-key behavior is unchanged; true means the keyset
// must load (NewVersionedFromEnv) or the misconfiguration is logged loudly.
func KeysetConfigured() bool {
	return os.Getenv(keysetFileEnv) != ""
}

// NewVersionedFromEnv builds a VersionedKMS from the keyset record named by
// YABANIN_KMS_KEYSET_FILE.
func NewVersionedFromEnv() (*VersionedKMS, error) {
	path := os.Getenv(keysetFileEnv)
	if path == "" {
		return nil, fmt.Errorf("kms: %s is not set", keysetFileEnv)
	}
	ks, err := LoadKeysetFile(path)
	if err != nil {
		return nil, err
	}
	return NewVersioned(ks)
}
