package lineage

// migration flows, unit-tested with a lazy pool against a refused loopback
// address (pgxpool connects on first query — no Docker required). The
// happy-path round-trips are covered by the integration suite.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/encryption"
)

// deadPool returns a pool whose queries fail immediately (nothing listens on
// 127.0.0.1:1), exercising the store's DB-error paths without a container.
func deadPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, "postgres://yabanin:yabanin@127.0.0.1:1/yabanin?sslmode=disable&connect_timeout=2")
	if err != nil {
		t.Fatalf("build pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// Dev/test: a DB outage surfaces as an insert error after generation — never
// as a silent success.
func TestEnsureKeyPair_DatabaseUnavailableReturnsInsertError(t *testing.T) {
	ks := NewKeyStore(deadPool(t), nil)
	_, _, _, err := ks.EnsureKeyPair(context.Background(), "org-db-down")
	if err == nil {
		t.Fatal("expected error when the database is unavailable, got nil")
	}
	if !strings.Contains(err.Error(), "insert lineage key") {
		t.Errorf("expected insert lineage key in error, got: %v", err)
	}
}

// Production: even when the database is down, the write is refused BEFORE any
// SQL — plaintext private-key storage stays impossible.
func TestEnsureKeyPair_ProductionRefusesBeforeInsertWhenDatabaseDown(t *testing.T) {
	restore := encryption.SetPlaintextPolicyForTest(func() bool { return false })
	defer restore()

	ks := NewKeyStore(deadPool(t), nil)
	_, _, _, err := ks.EnsureKeyPair(context.Background(), "org-db-down-prod")
	if err == nil {
		t.Fatal("expected production refusal, got nil")
	}
	if !strings.Contains(err.Error(), "plaintext") {
		t.Errorf("expected plaintext refusal in error, got: %v", err)
	}
	if strings.Contains(err.Error(), "insert lineage key") {
		t.Error("refusal must happen before the INSERT attempt")
	}
}

// With an encryptor the private key is wrapped first; the DB outage then
// fails the insert (ciphertext is never lost to a silent fallback).
func TestEnsureKeyPair_WithEncryptorEncryptsThenFailsInsert(t *testing.T) {
	ks := NewKeyStore(deadPool(t), mustEncryptor(t))
	_, _, _, err := ks.EnsureKeyPair(context.Background(), "org-db-down-enc")
	if err == nil {
		t.Fatal("expected insert error, got nil")
	}
	if !strings.Contains(err.Error(), "insert lineage key") {
		t.Errorf("expected insert lineage key in error, got: %v", err)
	}
}

func TestMigratePlaintextKeys_DatabaseUnavailableErrors(t *testing.T) {
	ks := NewKeyStore(deadPool(t), mustEncryptor(t))
	_, err := ks.MigratePlaintextKeys(context.Background())
	if err == nil {
		t.Fatal("expected error when the database is unavailable, got nil")
	}
	if !strings.Contains(err.Error(), "scan plaintext lineage keys") {
		t.Errorf("expected scan error, got: %v", err)
	}
}

func TestGetPublicKeyByOrgID_DatabaseUnavailableErrors(t *testing.T) {
	ks := NewKeyStore(deadPool(t), nil)
	_, _, err := ks.GetPublicKeyByOrgID(context.Background(), "org-db-down")
	if err == nil {
		t.Fatal("expected error when the database is unavailable, got nil")
	}
	if !strings.Contains(err.Error(), "fetch public key for org") {
		t.Errorf("expected fetch public key error, got: %v", err)
	}
}
