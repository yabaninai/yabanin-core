package encryption

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// testKeyA and testKeyB are fixed 32-byte random-shaped keys (high bytes,
// 32 distinct values each) so tests are deterministic and both pass the
// password-like rejection heuristics.
const (
	testKeyA = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
	testKeyB = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
)

// newTestEncryptor returns an Encryptor with a fresh random valid key.
func newTestEncryptor() *Encryptor {
	return MustNew(EncodeKey())
}

// ---------- New: valid key forms ----------

func TestNew_hexKey(t *testing.T) {
	e, err := New(testKeyA)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e == nil {
		t.Fatal("expected non-nil Encryptor")
	}
}

func TestNew_hexKeyMixedCase(t *testing.T) {
	e, err := New("808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F")
	if err != nil {
		t.Fatalf("unexpected error for mixed-case hex key: %v", err)
	}
	if e == nil {
		t.Fatal("expected non-nil Encryptor")
	}
}

func TestNew_hexKeyWithSurroundingWhitespace(t *testing.T) {
	// Keys read from files/env may carry trailing newlines or spaces.
	e, err := New(testKeyA + "\n")
	if err != nil {
		t.Fatalf("unexpected error for whitespace-padded hex key: %v", err)
	}
	if e == nil {
		t.Fatal("expected non-nil Encryptor")
	}
}

func TestNew_base64Key32Bytes(t *testing.T) {
	// openssl rand -base64 32 shape: std encoding with padding.
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(0x80 + i)
	}
	key := base64.StdEncoding.EncodeToString(raw)
	e, err := New(key)
	if err != nil {
		t.Fatalf("unexpected error for base64 key: %v", err)
	}
	if e == nil {
		t.Fatal("expected non-nil Encryptor")
	}
}

func TestNew_base64URLRawKey32Bytes(t *testing.T) {
	// openssl rand -base64url 32 shape (43 chars, no padding, - and _).
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(0x90 + i)
	}
	key := base64.RawURLEncoding.EncodeToString(raw)
	e, err := New(key)
	if err != nil {
		t.Fatalf("unexpected error for raw base64url key: %v", err)
	}
	if e == nil {
		t.Fatal("expected non-nil Encryptor")
	}
}

// ---------- New: rejected key forms ----------

func TestNew_emptyString(t *testing.T) {
	_, err := New("")
	if err == nil {
		t.Fatal("expected error for empty key, got nil")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected 'empty' in error, got: %v", err)
	}
}

func TestNew_passwordRejected(t *testing.T) {
	for _, pw := range []string{
		"my-super-secret-password",
		"correct horse battery staple",
		"password123",
		"tr0ub4dor&3",
	} {
		_, err := New(pw)
		if err == nil {
			t.Fatalf("expected error for password-like key %q, got nil", pw)
		}
		if !strings.Contains(err.Error(), "rejected") {
			t.Errorf("expected rejection guidance in error for %q, got: %v", pw, err)
		}
	}
}

func TestNew_shortHexKeyRejected(t *testing.T) {
	// 16 hex chars = 8 bytes < 32 bytes of key material.
	_, err := New("0123456789abcdef")
	if err == nil {
		t.Fatal("expected error for short hex key, got nil")
	}
	if !strings.Contains(err.Error(), "exactly 32 bytes") {
		t.Errorf("expected length guidance in error, got: %v", err)
	}
}

func TestNew_63CharHexKeyRejected(t *testing.T) {
	// Odd-length hex-ish string must not silently decode as base64.
	_, err := New("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")
	if err == nil {
		t.Fatal("expected error for 63-char hex string, got nil")
	}
}

func TestNew_hexKeyWrongDecodedLength(t *testing.T) {
	// 100 hex chars = 50 bytes, not exactly 32.
	_, err := New(strings.Repeat("8f", 50))
	if err == nil {
		t.Fatal("expected error for hex key decoding to 50 bytes, got nil")
	}
	if !strings.Contains(err.Error(), "exactly 32 bytes") {
		t.Errorf("expected length guidance in error, got: %v", err)
	}
}

func TestNew_base64TooShortRejected(t *testing.T) {
	// base64 of 8 bytes — well-formed but far below 32 bytes of entropy.
	raw := []byte{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87}
	_, err := New(base64.StdEncoding.EncodeToString(raw))
	if err == nil {
		t.Fatal("expected error for short base64 key, got nil")
	}
}

func TestNew_lowEntropyBase64Rejected(t *testing.T) {
	// 32 identical bytes, correctly base64-encoded: right length, no entropy.
	raw := make([]byte, 32)
	_, err := New(base64.StdEncoding.EncodeToString(raw))
	if err == nil {
		t.Fatal("expected error for all-zero base64 key, got nil")
	}
	if !strings.Contains(err.Error(), "password-derived") {
		t.Errorf("expected password-derived guidance in error, got: %v", err)
	}
}

func TestNew_asciiTextHexRejected(t *testing.T) {
	// Hex encoding of an ASCII passphrase: right length, but the decoded
	// bytes are text — must be rejected as password-derived.
	passphraseHex := hex.EncodeToString([]byte("super-secret-passphrase-oh-yes!!"))
	if len(passphraseHex) != 64 {
		t.Fatalf("test setup: want 64 hex chars, got %d", len(passphraseHex))
	}
	_, err := New(passphraseHex)
	if err == nil {
		t.Fatal("expected error for ASCII-passphrase hex key, got nil")
	}
	if !strings.Contains(err.Error(), "password-derived") {
		t.Errorf("expected password-derived guidance in error, got: %v", err)
	}
}

func TestNew_invalidHexKeyRejected(t *testing.T) {
	_, err := New("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")
	if err == nil {
		t.Fatal("expected error for invalid key, got nil")
	}
	if !strings.Contains(err.Error(), "encryption key") {
		t.Errorf("expected key guidance in error, got: %v", err)
	}
}

// ---------- MustNew ----------

func TestMustNew_valid(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("MustNew panicked unexpectedly: %v", r)
		}
	}()
	e := MustNew(testKeyA)
	if e == nil {
		t.Fatal("expected non-nil Encryptor from MustNew")
	}
}

func TestMustNew_invalidKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected MustNew to panic on invalid key")
		}
	}()
	MustNew("my-password")
}

// ---------- EncodeKey ----------

func TestEncodeKey_format(t *testing.T) {
	key := EncodeKey()
	if len(key) == 0 {
		t.Fatal("expected non-empty key from EncodeKey")
	}
	if len(key) != 64 {
		t.Errorf("expected key length 64, got %d", len(key))
	}
	// Verify it's valid hex
	e, err := New(key)
	if err != nil {
		t.Fatalf("EncodeKey output should be a valid hex key: %v", err)
	}
	if e == nil {
		t.Fatal("expected non-nil Encryptor from EncodeKey output")
	}
}

func TestEncodeKey_uniqueness(t *testing.T) {
	keys := make(map[string]bool)
	for i := 0; i < 10; i++ {
		k := EncodeKey()
		if keys[k] {
			t.Errorf("duplicate key generated: %q", k)
		}
		keys[k] = true
	}
}

// ---------- Encrypt / Decrypt round-trip ----------

func TestEncryptDecrypt_roundtrip(t *testing.T) {
	e := newTestEncryptor()
	plaintext := "s3cr3t-v@lu3"
	ciphertext, err := e.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if !IsEncrypted(ciphertext) {
		t.Fatal("expected encrypted output to start with enc:")
	}
	decrypted, err := e.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestEncryptDecrypt_emptyPlaintext(t *testing.T) {
	e := newTestEncryptor()
	plaintext := ""
	ciphertext, err := e.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	decrypted, err := e.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("expected empty string, got %q", decrypted)
	}
}

func TestEncryptDecrypt_specialChars(t *testing.T) {
	e := newTestEncryptor()
	plaintext := "line1\nline2\ttab!@#$%^&*()"
	ciphertext, err := e.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	decrypted, err := e.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestEncryptPrefix(t *testing.T) {
	e := newTestEncryptor()
	ciphertext, err := e.Encrypt("hello")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if !strings.HasPrefix(ciphertext, "enc:") {
		t.Errorf("expected ciphertext to start with 'enc:', got %q", ciphertext[:min(20, len(ciphertext))])
	}
}

func TestEncryptUniqueness(t *testing.T) {
	e := newTestEncryptor()
	c1, err := e.Encrypt("same-plaintext")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	c2, err := e.Encrypt("same-plaintext")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if c1 == c2 {
		t.Fatal("encrypted outputs should differ due to random nonce")
	}
}

// ---------- Decrypt error cases ----------

func TestDecrypt_noPrefix(t *testing.T) {
	e := newTestEncryptor()
	_, err := e.Decrypt("not-encrypted")
	if err == nil {
		t.Fatal("expected error for non-prefixed string, got nil")
	}
	if !strings.Contains(err.Error(), "invalid encryption prefix") {
		t.Errorf("expected 'invalid encryption prefix' in error, got: %v", err)
	}
}

func TestDecrypt_tamperedCiphertext(t *testing.T) {
	e := newTestEncryptor()
	ciphertext, _ := e.Encrypt("hello")
	// Tamper by replacing one base64 character with another valid base64 char
	b := []byte(ciphertext)
	if len(b) > len(prefix)+1 {
		// Replace a character in the encoded portion (not the prefix)
		if len(b) > len(prefix)+1 {
			old := b[len(prefix)]
			if old == 'A' {
				b[len(prefix)] = 'B'
			} else {
				b[len(prefix)] = 'A'
			}
		}
	}
	bad := string(b)
	_, err := e.Decrypt(bad)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext, got nil")
	}
	if !strings.Contains(err.Error(), "decrypt") {
		t.Errorf("expected 'decrypt' in error, got: %v", err)
	}
}

func TestDecrypt_wrongKey(t *testing.T) {
	e1 := MustNew(testKeyA)
	e2 := MustNew(testKeyB)
	ciphertext, err := e1.Encrypt("secret")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	_, err = e2.Decrypt(ciphertext)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key, got nil")
	}
	if !strings.Contains(err.Error(), "decrypt") {
		t.Errorf("expected 'decrypt' in error, got: %v", err)
	}
}

func TestDecrypt_invalidBase64(t *testing.T) {
	e := newTestEncryptor()
	_, err := e.Decrypt("enc:not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64, got nil")
	}
	if !strings.Contains(err.Error(), "base64 decode") {
		t.Errorf("expected 'base64 decode' in error, got: %v", err)
	}
}

func TestDecrypt_tooShort(t *testing.T) {
	e := newTestEncryptor()
	_, err := e.Decrypt("enc:YWJj") // "abc" in base64, too short for nonce+ciphertext
	if err == nil {
		t.Fatal("expected error for ciphertext too short, got nil")
	}
	if !strings.Contains(err.Error(), "ciphertext too short") {
		t.Errorf("expected 'ciphertext too short' in error, got: %v", err)
	}
}

func TestDecrypt_ciphertextTooShortThanNonce(t *testing.T) {
	e := newTestEncryptor()
	// "enc:" + 2 bytes base64 encoded (less than nonce size which is typically 12)
	_, err := e.Decrypt("enc:YQ==")
	if err == nil {
		t.Fatal("expected error for data shorter than nonce, got nil")
	}
	if !strings.Contains(err.Error(), "ciphertext too short") {
		t.Errorf("expected 'ciphertext too short' in error, got: %v", err)
	}
}

func TestDecrypt_prefixOnly(t *testing.T) {
	e := newTestEncryptor()
	_, err := e.Decrypt("enc:")
	if err == nil {
		t.Fatal("expected error for prefix-only string, got nil")
	}
}

// ---------- IsEncrypted ----------

func TestIsEncrypted_true(t *testing.T) {
	if !IsEncrypted("enc:something") {
		t.Error("expected true for enc: prefixed string")
	}
}

func TestIsEncrypted_false_plain(t *testing.T) {
	if IsEncrypted("not-encrypted") {
		t.Error("expected false for non-prefixed string")
	}
}

func TestIsEncrypted_false_empty(t *testing.T) {
	if IsEncrypted("") {
		t.Error("expected false for empty string")
	}
}

func TestIsEncrypted_false_shorterThanPrefix(t *testing.T) {
	if IsEncrypted("en") {
		t.Error("expected false for string shorter than prefix")
	}
}

func TestIsEncrypted_false_partialPrefix(t *testing.T) {
	if IsEncrypted("enx:something") {
		t.Error("expected false for partial prefix")
	}
}

// ---------- DecryptOrPlain (removed) ----------
//
// DecryptOrPlain was removed (N01-P04 successor cleanup): it was the only
// swallow-decrypt-error helper in the tree — a failed decrypt became
// ("", false) instead of an error — and had no production caller. Its
// fail-closed properties live on in Decrypt (always returns the error, never
// a value alongside it) and IsEncrypted (pure prefix dispatch), both covered
// by the tests above.

// ---------- hexDecode (indirect via New) ----------

func TestHexDecode(t *testing.T) {
	b, err := hexDecode("48656c6c6f")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f}
	for i := range expected {
		if b[i] != expected[i] {
			t.Errorf("b[%d] = 0x%02x, want 0x%02x", i, b[i], expected[i])
		}
	}
}

func TestHexDecode_oddLength(t *testing.T) {
	b, err := hexDecode("486")
	if err != nil {
		t.Fatalf("unexpected error for odd-length: %v", err)
	}
	expected := []byte{0x48, 0x60} // second nibble of '6' is shifted left in high nibble
	if len(b) != 2 || b[0] != expected[0] || b[1] != expected[1] {
		t.Errorf("expected %v, got %v", expected, b)
	}
}

func TestHexDecode_empty(t *testing.T) {
	b, err := hexDecode("")
	if err != nil {
		t.Fatalf("unexpected error for empty string: %v", err)
	}
	if len(b) != 0 {
		t.Errorf("expected empty byte slice, got %v", b)
	}
}

func TestHexDecode_invalidChar(t *testing.T) {
	_, err := hexDecode("gh")
	if err == nil {
		t.Fatal("expected error for invalid hex chars, got nil")
	}
}

func TestHexDecode_mixedCase(t *testing.T) {
	b, err := hexDecode("AaBbCcDd")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	for i := range expected {
		if b[i] != expected[i] {
			t.Errorf("b[%d] = 0x%02x, want 0x%02x", i, b[i], expected[i])
		}
	}
}

func TestHexDecode_invalidCharSecondNibble(t *testing.T) {
	_, err := hexDecode("4g")
	if err == nil {
		t.Fatal("expected error for invalid second hex char, got nil")
	}
}

// ---------- Nil receiver safety ----------

func TestEncryptNilReceiver(t *testing.T) {
	var e *Encryptor
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil receiver Encrypt")
		}
	}()
	_, _ = e.Encrypt("hello")
}

func TestDecryptNilReceiver(t *testing.T) {
	var e *Encryptor
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil receiver Decrypt")
		}
	}()
	_, _ = e.Decrypt("enc:test")
}

// ---------- Long plaintext ----------

func TestEncryptDecrypt_longPlaintext(t *testing.T) {
	e := newTestEncryptor()
	plaintext := strings.Repeat("a", 10000)
	ciphertext, err := e.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	decrypted, err := e.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if decrypted != plaintext {
		t.Error("long plaintext round-trip failed")
	}
}

func TestEncryptDecrypt_unicodePlaintext(t *testing.T) {
	e := newTestEncryptor()
	plaintext := "Hello 世界 🌍 Привет"
	ciphertext, err := e.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	decrypted, err := e.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestMustNew_withEncodeKey(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("MustNew panicked with EncodeKey output: %v", r)
		}
	}()
	key := EncodeKey()
	e := MustNew(key)
	if e == nil {
		t.Fatal("expected non-nil Encryptor")
	}
	// Verify round-trip works with generated key
	ciphertext, err := e.Encrypt("test-secret")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	decrypted, err := e.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if decrypted != "test-secret" {
		t.Errorf("expected 'test-secret', got %q", decrypted)
	}
}

func TestPlaintextWritesAllowed_defaultTrueUnderGoTest(t *testing.T) {
	if !PlaintextWritesAllowed() {
		t.Fatal("expected plaintext writes to be allowed under `go test` (dev/test mode)")
	}
}

func TestSetPlaintextPolicyForTest_overrideAndRestore(t *testing.T) {
	if !PlaintextWritesAllowed() {
		t.Fatal("test setup: expected dev/test default")
	}
	restore := SetPlaintextPolicyForTest(func() bool { return false })
	if PlaintextWritesAllowed() {
		t.Fatal("expected production policy (false) while overridden")
	}
	// Nested override chains correctly.
	restore2 := SetPlaintextPolicyForTest(func() bool { return true })
	if !PlaintextWritesAllowed() {
		t.Fatal("expected nested override to apply")
	}
	restore2()
	if PlaintextWritesAllowed() {
		t.Fatal("expected outer override (false) after nested restore")
	}
	restore()
	if !PlaintextWritesAllowed() {
		t.Fatal("expected default restored")
	}
}
