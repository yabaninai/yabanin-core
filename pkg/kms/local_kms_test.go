package kms

import (
	"context"
	"testing"
)

func TestLocalKMS_EncryptDecrypt_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	kms, err := NewLocalKMS(key)
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}

	plaintext := []byte("hello multi-region world")
	ciphertext, err := kms.Encrypt(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("expected non-empty ciphertext")
	}

	decrypted, err := kms.Decrypt(context.Background(), ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("round-trip mismatch: expected %q, got %q", plaintext, decrypted)
	}
}

func TestLocalKMS_DifferentCiphertexts(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	kms, err := NewLocalKMS(key)
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}

	plaintext := []byte("same plaintext")
	c1, err := kms.Encrypt(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("Encrypt 1: %v", err)
	}
	c2, err := kms.Encrypt(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}
	// Each encryption should produce different ciphertext (random nonce).
	if string(c1) == string(c2) {
		t.Error("expected different ciphertexts for same plaintext with random nonce")
	}

	d1, _ := kms.Decrypt(context.Background(), c1)
	d2, _ := kms.Decrypt(context.Background(), c2)
	if string(d1) != string(plaintext) || string(d2) != string(plaintext) {
		t.Error("both decryptions should match original plaintext")
	}
}

func TestLocalKMS_TamperedCiphertext_Fails(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	kms, err := NewLocalKMS(key)
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}

	plaintext := []byte("don't tamper with me")
	ciphertext, err := kms.Encrypt(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip a byte in the ciphertext.
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)/2] ^= 0xFF

	_, err = kms.Decrypt(context.Background(), tampered)
	if err == nil {
		t.Fatal("expected decryption to fail on tampered ciphertext")
	}
}

func TestLocalKMS_EmptyInput(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	kms, err := NewLocalKMS(key)
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}

	empty := []byte{}
	ciphertext, err := kms.Encrypt(context.Background(), empty)
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}
	decrypted, err := kms.Decrypt(context.Background(), ciphertext)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if string(decrypted) != "" {
		t.Errorf("expected empty output, got %q", decrypted)
	}
}

func TestLocalKMS_TooShortCiphertext(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	kms, err := NewLocalKMS(key)
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}

	_, err = kms.Decrypt(context.Background(), []byte{0x01})
	if err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
}
