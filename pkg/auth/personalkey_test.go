package auth

import (
	"strings"
	"testing"
)

func TestGeneratePersonalKey(t *testing.T) {
	k, err := GeneratePersonalKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(k, "yb_") || strings.HasPrefix(k, "ybs_") {
		t.Fatalf("prefix: %s", k)
	}
	if len(k) != len("yb_")+64 {
		t.Fatalf("len %d", len(k))
	}
	if HashKey(k) == "" {
		t.Fatal("hash")
	}
}
