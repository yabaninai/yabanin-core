package adminauth

import (
	"testing"
)

func TestHashPassword_RoundTrip(t *testing.T) {
	password := "super-secret-password-123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}
	if len(hash) < 50 {
		t.Errorf("expected bcrypt hash to be at least 50 chars, got %d", len(hash))
	}

	err = VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword error: %v", err)
	}
}

func TestHashPassword_VerifyWrong(t *testing.T) {
	password := "correct-password"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}

	err = VerifyPassword("wrong-password", hash)
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
}

func TestHashPassword_EmptyPassword(t *testing.T) {
	hash, err := HashPassword("")
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}

	err = VerifyPassword("", hash)
	if err != nil {
		t.Fatalf("VerifyPassword error on empty password: %v", err)
	}
}

func TestHashPassword_BcryptCost(t *testing.T) {
	password := "test-password"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}
	// bcrypt hashes contain the cost in the format $2a$12$...
	expectedCostPrefix := "$2a$12$"
	expectedCostPrefix2 := "$2b$12$"
	if len(hash) < 6 {
		t.Fatal("hash too short to contain cost")
	}
	hashCost := hash[:7]
	if hashCost != expectedCostPrefix && hashCost != expectedCostPrefix2 {
		t.Errorf("expected bcrypt cost prefix %q or %q, got %q", expectedCostPrefix, expectedCostPrefix2, hashCost)
	}
}
