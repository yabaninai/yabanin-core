package policystore

// Unit coverage for the durable guard-pack CAS input gates (the SQL semantics
// live in the testdb contract below).

import (
	"errors"
	"testing"

	"github.com/reireirei/yabanin/pkg/guardhooks"
)

func TestGuardPolicyCASFeatureOffFailsClosed(t *testing.T) {
	var nilCAS *GuardPolicyCAS
	if err := nilCAS.CompareAndSwap(testCtx(), "core", "a@1"); !errors.Is(err, ErrNoDB) {
		t.Errorf("nil-receiver CAS = %v, want ErrNoDB (fail-closed, no silent local activation)", err)
	}
	if err := NewGuardPolicyCAS(nil).CompareAndSwap(testCtx(), "core", "a@1"); !errors.Is(err, ErrNoDB) {
		t.Errorf("nil-pool CAS = %v, want ErrNoDB", err)
	}
	if _, err := NewGuardPolicyCAS(nil).ActiveGuardPackState(testCtx()); !errors.Is(err, ErrNoDB) {
		t.Errorf("nil-pool read = %v, want ErrNoDB", err)
	}
}

func TestGuardPolicyCASRejectsEmptyAndDegenerateTransitions(t *testing.T) {
	cas := NewGuardPolicyCAS(nil) // gates run before any SQL, nil pool suffices
	if err := cas.CompareAndSwap(testCtx(), "", "a@1"); err == nil || errors.Is(err, ErrGuardPackConflict) {
		t.Errorf("empty from = %v, want a plain validation error", err)
	}
	if err := cas.CompareAndSwap(testCtx(), "core", ""); err == nil || errors.Is(err, ErrGuardPackConflict) {
		t.Errorf("empty to = %v, want a plain validation error", err)
	}
	if err := cas.CompareAndSwap(testCtx(), "a@1", "a@1"); !errors.Is(err, ErrGuardPackConflict) {
		t.Errorf("from == to = %v, want ErrGuardPackConflict (already active)", err)
	}
}

// compile pin (mirrors the production pin in guardpolicy.go, asserted from
// the test side so an interface drift breaks the build here too).
var _ guardhooks.PolicyVersionCAS = (*GuardPolicyCAS)(nil)
