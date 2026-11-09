package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/reireirei/yabanin/pkg/config"
)

// Encryptor provides AES-GCM authenticated encryption for secrets.
type Encryptor struct {
	aead cipher.AEAD
}

const prefix = "enc:" // version marker, prepend to base64 ciphertext for migration safety

// minKeyBytes is the exact decoded key length (AES-256). A shorter key would
// be weak; a longer one cannot be used by crypto/aes without an extra KDF.
const minKeyBytes = 32

// New creates an Encryptor from an encoded 32-byte random key: 64 hex chars
// (`openssl rand -hex 32`) or base64 encoding of exactly 32 bytes
// (`openssl rand -base64 32`). Password-like strings are rejected: the
// historical unsalted SHA-256(password) fallback turned low-entropy secrets
// into offline-brute-forceable AES keys and is removed. Surrounding
// whitespace is trimmed so keys can be read verbatim from files or env.
func New(keyOrPassword string) (*Encryptor, error) {
	key, err := keyFromConfig(keyOrPassword)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return &Encryptor{aead: aead}, nil
}

// keyFromConfig decodes and validates the configured key material.
func keyFromConfig(keyOrPassword string) ([]byte, error) {
	s := strings.TrimSpace(keyOrPassword)
	if s == "" {
		return nil, fmt.Errorf("encryption key is empty; generate one with `openssl rand -hex 32`")
	}
	if isHexString(s) {
		if len(s)%2 != 0 {
			return nil, fmt.Errorf("hex encryption key must have even length, got %d chars; generate one with `openssl rand -hex 32`", len(s))
		}
		key, err := hexDecode(s)
		if err != nil {
			return nil, fmt.Errorf("invalid hex key: %w", err)
		}
		if len(key) != minKeyBytes {
			return nil, fmt.Errorf("hex encryption key must decode to exactly %d bytes, got %d; generate one with `openssl rand -hex 32`", minKeyBytes, len(key))
		}
		return rejectWeakKey(key)
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		key, err := enc.DecodeString(s)
		if err == nil && len(key) == minKeyBytes {
			return rejectWeakKey(key)
		}
	}
	return nil, fmt.Errorf("encryption key must be a hex- or base64-encoded random key of exactly %d bytes; password-like strings are rejected; generate one with `openssl rand -hex 32` or `openssl rand -base64 32`", minKeyBytes)
}

// rejectWeakKey rejects key material that is text-shaped or low-entropy:
// a human-chosen passphrase encoded to the right length, not a random key.
// For genuinely random 32 bytes the probability of failing either check is
// negligible (all-ASCII alone is ~(95/256)^32 ≈ 5e-15).
func rejectWeakKey(key []byte) ([]byte, error) {
	ascii := true
	var seen [256]bool
	distinct := 0
	for _, b := range key {
		if b >= 0x80 {
			ascii = false
		}
		if !seen[b] {
			seen[b] = true
			distinct++
		}
	}
	if ascii || distinct < 16 {
		return nil, fmt.Errorf("encryption key looks password-derived (text-shaped or low-entropy bytes), not a random key; generate one with `openssl rand -hex 32`")
	}
	return key, nil
}

// isHexString reports whether s consists solely of hex digits (non-empty).
func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// plaintextPolicy is the seam deciding whether plaintext secret writes are
// tolerated. nil means the default: allowed under `go test` or when
// YABANIN_ENCRYPTION_ALLOW_PLAINTEXT=1 is set explicitly (dev escape hatch);
// production builds fail closed.
var plaintextPolicy atomic.Pointer[func() bool]

// PlaintextWritesAllowed reports whether writing a secret without a
// configured Encryptor is tolerated (dev/test only). Production deployments
// must keep it false so secret writes fail closed instead of silently
// storing plaintext.
func PlaintextWritesAllowed() bool {
	if f := plaintextPolicy.Load(); f != nil {
		return (*f)()
	}
	if config.EncryptionAllowPlaintext() {
		return true
	}
	return testing.Testing()
}

// SetPlaintextPolicyForTest overrides the plaintext policy (unit tests use it
// to simulate production). Returns a restore function; nested overrides
// restore correctly.
func SetPlaintextPolicyForTest(f func() bool) (restore func()) {
	prev := plaintextPolicy.Load()
	plaintextPolicy.Store(&f)
	return func() { plaintextPolicy.Store(prev) }
}

// MustNew creates an Encryptor, panicking on invalid key.
func MustNew(keyOrPassword string) *Encryptor {
	e, err := New(keyOrPassword)
	if err != nil {
		slog.Error("encryption init failed", "error", err)
		panic(err)
	}
	return e
}

// EncodeKey generates a random 32-byte hex key for use in config.
func EncodeKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		slog.Error("failed to generate encryption key", "error", err)
		return ""
	}
	return fmt.Sprintf("%x", b)
}

// Encrypt encrypts plaintext and returns a base64-encoded string with "enc:" prefix.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := e.aead.Seal(nil, nonce, []byte(plaintext), nil)
	out := make([]byte, base64.StdEncoding.EncodedLen(len(nonce)+len(ciphertext))+len(prefix))
	copy(out, prefix)
	combined := make([]byte, len(nonce)+len(ciphertext))
	copy(combined, nonce)
	copy(combined[len(nonce):], ciphertext)
	base64.StdEncoding.Encode(out[len(prefix):], combined)
	return string(out), nil
}

// Decrypt decrypts an "enc:" prefixed ciphertext back to plaintext.
func (e *Encryptor) Decrypt(signed string) (string, error) {
	if len(signed) < len(prefix) || signed[:len(prefix)] != prefix {
		return "", fmt.Errorf("invalid encryption prefix")
	}
	encoded := signed[len(prefix):]
	data := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(data, []byte(encoded))
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	data = data[:n]
	nonceSize := e.aead.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	ciphertext, err := e.aead.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(ciphertext), nil
}

// IsEncrypted checks if a value starts with the encryption prefix.
func IsEncrypted(s string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// DecryptOrPlain was removed deliberately (N01-P04 successor cleanup): it
// swallowed decrypt errors into ("", false), the one catch-and-degrade shape
// in the tree. It had no production caller. The sanctioned pair is
// IsEncrypted (dispatch) + Decrypt (which always returns the error), so a
// failure is never converted into an empty or passthrough value.

func hexDecode(s string) ([]byte, error) {
	b := make([]byte, (len(s)+1)/2)
	for i := 0; i < len(s); i += 2 {
		var v byte
		if s[i] >= '0' && s[i] <= '9' {
			v = s[i] - '0'
		} else if s[i] >= 'a' && s[i] <= 'f' {
			v = s[i] - 'a' + 10
		} else if s[i] >= 'A' && s[i] <= 'F' {
			v = s[i] - 'A' + 10
		} else {
			return nil, fmt.Errorf("invalid hex char %c at pos %d", s[i], i)
		}
		b[i/2] = v << 4
		j := i + 1
		if j < len(s) {
			c := s[j]
			var u byte
			if c >= '0' && c <= '9' {
				u = c - '0'
			} else if c >= 'a' && c <= 'f' {
				u = c - 'a' + 10
			} else if c >= 'A' && c <= 'F' {
				u = c - 'A' + 10
			} else {
				return nil, fmt.Errorf("invalid hex char %c at pos %d", s[j], j)
			}
			b[i/2] |= u
		}
	}
	return b, nil
}
