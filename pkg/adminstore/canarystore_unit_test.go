package adminstore

import (
	"context"
	"testing"
)

// validation branches that must never reach SQL (DB paths live under the
// integration tag).
func TestCanaryStore_UnitGuards(t *testing.T) {
	s := &Store{}
	if _, _, err := s.CreateCanaryRollout(context.Background(), "", "name", "base", "canary", 10, "who"); err == nil {
		t.Fatal("validation must refuse empty org")
	}
	if _, err := s.ListCanaryRollouts(context.Background(), ""); err == nil {
		t.Fatal("no db must fail closed")
	}
	if _, err := s.GetCanaryRollout(context.Background(), "", "roll"); err == nil {
		t.Fatal("no db must fail closed")
	}
	if err := s.DeleteCanaryRollout(context.Background(), "", "roll"); err == nil {
		t.Fatal("no db must fail closed")
	}
	if _, err := s.LoadCanarySnapshot(context.Background(), ""); err == nil {
		t.Fatal("no db must fail closed")
	}
}
