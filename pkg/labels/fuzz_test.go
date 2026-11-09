package labels

import "testing"

func FuzzParseHeaderValues(f *testing.F) {
	f.Add("issue=PAY-123, git.repo=payments%2Fbilling")
	f.Add("")
	f.Add("%%%")
	f.Add("yabanin.x=1, a=b")
	f.Fuzz(func(t *testing.T, raw string) {
		set, _ := ParseHeaderValues([]string{raw})
		for key, value := range set {
			if _, ok := NormalizeKey(key); !ok {
				t.Fatalf("key %q", key)
			}
			if len(value) > MaxValueLen {
				t.Fatalf("value len %d", len(value))
			}
		}
	})
}
