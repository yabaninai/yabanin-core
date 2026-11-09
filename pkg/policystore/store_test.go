package policystore

import "testing"

func TestIsValidRegion(t *testing.T) {
	cases := map[string]bool{
		"SG": true, "IN": true, "ID": true,
		"US": false, "EU": false, "": false, "sg": false,
	}
	for r, want := range cases {
		if got := IsValidRegion(r); got != want {
			t.Errorf("IsValidRegion(%q) = %v, want %v", r, got, want)
		}
	}
}

func TestStore_Upsert_InvalidRegion_Errors(t *testing.T) {
	s := New(nil) // no DB; validation runs before the DB call
	_, err := s.Upsert(testCtx(), PackConfig{Region: "US", PackID: "x"})
	if err == nil {
		t.Fatal("expected error for invalid region")
	}
}

func TestStore_NoPool_ReturnsErrNoDB(t *testing.T) {
	s := New(nil)
	if _, err := s.GetByOrgRegion(testCtx(), "org", "SG"); err != ErrNoDB {
		t.Fatalf("expected ErrNoDB, got %v", err)
	}
	if _, err := s.List(testCtx(), "org"); err != ErrNoDB {
		t.Fatalf("expected ErrNoDB, got %v", err)
	}
}
