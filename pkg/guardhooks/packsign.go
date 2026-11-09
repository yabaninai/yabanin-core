package guardhooks

// Pack signature verification (scheme v1): ed25519 over the canonical pack
// payload.
//
// Scope and license boundary: this is INTEGRITY verification, not licensing.
// It proves who authored a pack and that its content was not changed after
// signing. It performs no license checks, contains no proprietary code and
// imposes no commercial gating — the free/BYO unsigned-pack cycle is
// unaffected. Any deployment can sign and verify packs with its own keys.
//
// Key management (static set v1): the verifier holds an explicitly
// configured, static set of trusted ed25519 PUBLIC keys. There is no network
// fetch, no key rotation protocol and no trust-on-first-use: changing the
// set is an operator configuration change (env/config) picked up at wiring
// time. Sources are a keys directory (`<key-id>.pub` files, hex or standard
// base64 of the raw 32-byte public key) and/or inline `key-id=<material>`
// entries. Absence of a configured verifier never degrades the core: the
// built-in chain and unsigned local packs keep working; only signed packs
// (which require verification by design) fail closed.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MaxVerifierKeyIDLen bounds key identifiers so hostile manifests cannot
// smuggle unbounded strings into verifier errors and logs.
const MaxVerifierKeyIDLen = 128

// Ed25519Verifier verifies declared pack signatures against a static set of
// trusted ed25519 public keys (scheme guardpack-sig.v1). It is immutable
// after construction and safe for concurrent use.
type Ed25519Verifier struct {
	keys map[string]ed25519.PublicKey
}

// NewEd25519Verifier builds a verifier over the given static key set. The
// set must be non-empty and every key must be a real ed25519 public key:
// an empty or malformed trusted set is a configuration error, not a verifier
// that quietly rejects (or accepts) everything.
func NewEd25519Verifier(keys map[string]ed25519.PublicKey) (*Ed25519Verifier, error) {
	if len(keys) == 0 {
		return nil, errors.New("guard pack verifier: at least one trusted public key is required")
	}
	set := make(map[string]ed25519.PublicKey, len(keys))
	for id, key := range keys {
		if err := validateVerifierKeyID(id); err != nil {
			return nil, err
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("guard pack verifier: key %q is not a %d-byte ed25519 public key", id, ed25519.PublicKeySize)
		}
		set[id] = ed25519.PublicKey(append([]byte(nil), key...))
	}
	return &Ed25519Verifier{keys: set}, nil
}

// Verify checks the manifest's declared signature over the canonical pack
// payload. Unsigned manifests are accepted without consultation (the free
// local-pack cycle); a declared signature must name a configured key, use
// the v1 ed25519 scheme and match the exact canonical payload — anything
// else is a loud rejection and the caller must not stage the pack.
func (v *Ed25519Verifier) Verify(manifest PackManifest, canonicalPayload []byte) error {
	if v == nil {
		return errors.New("guard pack verifier: no verifier configured")
	}
	sig := manifest.Signature
	if sig == nil {
		return nil
	}
	// Defense in depth: the decode layer already gates the scheme; a direct
	// Verify caller gets the same explicit rejection.
	if sig.Version != SignatureVersionV1 {
		return fmt.Errorf("guard pack verifier: unsupported signature scheme version %q", sig.Version)
	}
	if sig.Algorithm != SignatureAlgorithmEd25519 {
		return fmt.Errorf("guard pack verifier: unsupported signature algorithm %q", sig.Algorithm)
	}
	if err := validateVerifierKeyID(sig.KeyID); err != nil {
		return err
	}
	key, ok := v.keys[sig.KeyID]
	if !ok {
		return fmt.Errorf("guard pack verifier: signature key %q is not in the configured trusted set", sig.KeyID)
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return fmt.Errorf("guard pack verifier: signature value is not valid standard base64: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("guard pack verifier: signature value must decode to %d bytes, got %d", ed25519.SignatureSize, len(raw))
	}
	if !ed25519.Verify(key, canonicalPayload, raw) {
		return errors.New("guard pack verifier: ed25519 signature does not match the canonical pack payload")
	}
	return nil
}

// ParseEd25519PublicKey decodes one raw ed25519 public key from hex or
// standard base64 text (whitespace trimmed; a trailing newline in a key file
// is fine). Anything that does not decode to exactly 32 bytes is rejected.
func ParseEd25519PublicKey(raw string) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("guard pack verifier: empty public key material")
	}
	var decoded []byte
	var err error
	if isHexString(trimmed) {
		if decoded, err = hex.DecodeString(trimmed); err != nil {
			return nil, fmt.Errorf("guard pack verifier: public key hex decode: %w", err)
		}
	} else {
		if decoded, err = base64.StdEncoding.DecodeString(trimmed); err != nil {
			return nil, fmt.Errorf("guard pack verifier: public key base64 decode: %w", err)
		}
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("guard pack verifier: public key must be %d bytes, got %d", ed25519.PublicKeySize, len(decoded))
	}
	return ed25519.PublicKey(decoded), nil
}

// isHexString reports whether s could be hex (even length, hex digits only).
// A 64-character all-hex string is unambiguous hex of a 32-byte key; a
// standard-base64 key of that size is 44 characters including padding.
func isHexString(s string) bool {
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for _, r := range s {
		if !isHexDigit(r) {
			return false
		}
	}
	return true
}

func isHexDigit(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F'
}

// LoadEd25519VerifierKeyDir reads a static trusted key set from dir. Every
// regular `<key-id>.pub` file must hold one raw public key (hex or standard
// base64); the key id is the file name without the .pub suffix. A configured
// directory that yields no usable key set is an error (fail loud) — it is
// never silently treated as "no verifier".
func LoadEd25519VerifierKeyDir(dir string) (map[string]ed25519.PublicKey, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("guard pack verifier: key directory is not configured")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("guard pack verifier: read key directory: %w", err)
	}
	keys := make(map[string]ed25519.PublicKey)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pub") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".pub")
		path := filepath.Join(dir, entry.Name())
		// #nosec G304 -- entry names come from os.ReadDir over the
		// operator-configured key directory (not request input); the .pub
		// suffix is enforced above and the content is parse-validated.
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("guard pack verifier: read key %q: %w", id, readErr)
		}
		key, parseErr := ParseEd25519PublicKey(string(data))
		if parseErr != nil {
			return nil, fmt.Errorf("guard pack verifier: key file %q: %w", entry.Name(), parseErr)
		}
		if _, dup := keys[id]; dup {
			return nil, fmt.Errorf("guard pack verifier: duplicate key id %q", id)
		}
		keys[id] = key
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("guard pack verifier: key directory %q contains no .pub key files", dir)
	}
	return keys, nil
}

// ParseInlineVerifierKey parses one inline `key-id=<material>` entry.
func ParseInlineVerifierKey(entry string) (string, ed25519.PublicKey, error) {
	id, material, ok := strings.Cut(entry, "=")
	if !ok || id == "" || strings.TrimSpace(material) == "" {
		return "", nil, fmt.Errorf("guard pack verifier: inline key %q must have the form key-id=<base64-or-hex public key>", entry)
	}
	if err := validateVerifierKeyID(id); err != nil {
		return "", nil, err
	}
	key, err := ParseEd25519PublicKey(material)
	if err != nil {
		return "", nil, fmt.Errorf("guard pack verifier: inline key %q: %w", id, err)
	}
	return id, key, nil
}

// NewVerifierFromConfig builds the static pack-signature verifier from the
// configured key sources (a keys directory and/or inline entries). This is
// the loader-hook seam for wiring: callers resolve the env/config values and
// hand them here.
//
// The three outcomes are explicit:
//   - err != nil: a configured source is broken — fail loud, never silently
//     downgrade;
//   - configured == false: no key source is configured — the no-verifier
//     state (verifier is nil): unsigned packs load freely, any declared
//     signature fails closed at decode;
//   - configured == true: verifier is a usable static key set.
//
// configured is reported separately (instead of returning a bare nil
// verifier) so "deliberately not configured" cannot be confused with a
// construction failure, and a typed-nil-in-interface bug cannot make the
// decode layer misread "no verifier" as a present one.
func NewVerifierFromConfig(keysDir string, inlineKeys []string) (verifier SignatureVerifier, configured bool, err error) {
	keysDir = strings.TrimSpace(keysDir)
	inline := make([]string, 0, len(inlineKeys))
	for _, entry := range inlineKeys {
		if entry = strings.TrimSpace(entry); entry != "" {
			inline = append(inline, entry)
		}
	}
	if keysDir == "" && len(inline) == 0 {
		return nil, false, nil
	}
	keys := make(map[string]ed25519.PublicKey)
	if keysDir != "" {
		loaded, loadErr := LoadEd25519VerifierKeyDir(keysDir)
		if loadErr != nil {
			return nil, true, loadErr
		}
		for id, key := range loaded {
			keys[id] = key
		}
	}
	for _, entry := range inline {
		id, key, parseErr := ParseInlineVerifierKey(entry)
		if parseErr != nil {
			return nil, true, parseErr
		}
		if _, dup := keys[id]; dup {
			return nil, true, fmt.Errorf("guard pack verifier: duplicate key id %q across configured key sources", id)
		}
		keys[id] = key
	}
	verifier, err = NewEd25519Verifier(keys)
	if err != nil {
		return nil, true, err
	}
	return verifier, true, nil
}

func validateVerifierKeyID(id string) error {
	if id == "" {
		return errors.New("guard pack verifier: key id must not be empty")
	}
	if len(id) > MaxVerifierKeyIDLen {
		return fmt.Errorf("guard pack verifier: key id exceeds %d characters", MaxVerifierKeyIDLen)
	}
	for _, r := range id {
		if r <= ' ' || r > '~' {
			return fmt.Errorf("guard pack verifier: key id %q contains invalid characters", id)
		}
	}
	return nil
}
