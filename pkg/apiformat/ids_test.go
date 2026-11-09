package apiformat

import (
	"strings"
	"testing"
)

func TestNewID_PrefixAndLength(t *testing.T) {
	const prefix = "resp_"
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		id := NewID(prefix)
		if !strings.HasPrefix(id, prefix) {
			t.Fatalf("id %q missing prefix", id)
		}
		hexPart := strings.TrimPrefix(id, prefix)
		if len(hexPart) != 24 {
			t.Fatalf("hex length = %d, want 24 (%q)", len(hexPart), id)
		}
		for _, c := range hexPart {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Fatalf("non-hex %q in %q", string(c), id)
			}
		}
		if _, ok := seen[id]; ok {
			t.Fatalf("duplicate id %s", id)
		}
		seen[id] = struct{}{}
	}
}
