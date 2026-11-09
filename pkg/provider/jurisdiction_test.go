package provider

import (
	"context"
	"testing"
	"time"
)

// With a nil DB pool the registry never loads from Postgres, so every lookup
// must fall back to the fail-closed US default.

func TestJurisdictionRegistry_Unknown_FailClosedUS(t *testing.T) {
	r := NewJurisdictionRegistry(nil, time.Minute)
	got := r.Get(context.Background(), "totally-unknown-provider")
	if got.CorpCountry != "US" {
		t.Errorf("unknown provider CorpCountry = %q, want US (fail-closed)", got.CorpCountry)
	}
	if got.DefaultInferenceRegion != "US" {
		t.Errorf("unknown provider DefaultInferenceRegion = %q, want US", got.DefaultInferenceRegion)
	}
	if got.Provider != "totally-unknown-provider" {
		t.Errorf("echoed Provider = %q, want the lookup key", got.Provider)
	}
}

func TestJurisdictionRegistry_DefaultUnknownJurisdictionConstant(t *testing.T) {
	// Guard the constant so a careless edit is caught.
	if DefaultUnknownJurisdiction.CorpCountry != "US" ||
		DefaultUnknownJurisdiction.DefaultInferenceRegion != "US" {
		t.Fatal("DefaultUnknownJurisdiction must be US/US (fail-closed sovereignty)")
	}
}

// TestJurisdictionRegistry_NilPool_DoesNotPanic exercises the Get path with
// no DB, asserting the snapshot/refresh guards hold.
func TestJurisdictionRegistry_NilPool_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("registry panicked on nil pool: %v", r)
		}
	}()
	r := NewJurisdictionRegistry(nil, 0) // ttl==0 → should default to 5m internally
	for _, name := range []string{"openai", "anthropic", "", "OPENAI"} {
		_ = r.Get(context.Background(), name)
	}
}
