package labels

import (
	"math/rand"
	"net/http"
	"strings"
	"testing"
)

func TestParseHeaderValues(t *testing.T) {
	set, dropped := ParseHeaderValues([]string{
		" ci.system = gitlab , , ci.pipeline=812345;prop=1 ",
		"git.repo=payments%2Fbilling, issue=PAY-1, issue=PAY-2",
	})
	if set["ci.system"] != "gitlab" || set["ci.pipeline"] != "812345" || set["git.repo"] != "payments/billing" || set["issue"] != "PAY-2" {
		t.Fatalf("set %#v dropped %#v", set, dropped)
	}
	long := strings.Repeat("a", MaxHeaderBytes+1)
	_, dropped = ParseHeaderValues([]string{long})
	if len(dropped) != 1 || dropped[0].Key != "*" || dropped[0].Reason != DropHeaderTooLong {
		t.Fatalf("long %#v", dropped)
	}
	var parts []string
	for i := 0; i < MaxPerSource+1; i++ {
		parts = append(parts, "k"+string(rune('a'+i))+"=v")
	}
	set, dropped = ParseHeaderValues([]string{strings.Join(parts, ",")})
	if len(set) != MaxPerSource {
		t.Fatalf("count %d", len(set))
	}
	saw := false
	for _, drop := range dropped {
		if drop.Reason == DropTooMany {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("dropped %#v", dropped)
	}
}

func TestParsePerKeyOverridesAndReserved(t *testing.T) {
	h := make(http.Header)
	h.Add(HeaderName, "issue=OLD, env=prod")
	h.Set(PerKeyPrefix+"issue", "PAY-123")
	h.Set(PerKeyPrefix+"yabanin.x", "nope")
	set, dropped := FromRequest(h)
	if set["issue"] != "PAY-123" || set["env"] != "prod" {
		t.Fatalf("set %#v", set)
	}
	if !hasReason(dropped, "yabanin.x", DropReserved) {
		t.Fatalf("dropped %#v", dropped)
	}
	_, only := ParsePerKey(h)
	if !hasReason(only, "yabanin.x", DropReserved) {
		t.Fatalf("per-key %#v", only)
	}
}

func TestEncodeRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(1)) //nolint:gosec // G404: deterministic property test, not a secret
	alphabet := []rune("abcdefghijklmnopqrstuvwxyz0123456789-_")
	values := []rune("abcXYZ09-._~ Привет")
	for n := 0; n < 1000; n++ {
		set := Set{}
		count := 1 + rng.Intn(8)
		for len(set) < count {
			key := "k" + randomRunes(rng, alphabet, 1+rng.Intn(6))
			if _, ok := NormalizeKey(key); !ok {
				continue
			}
			value, reason := NormalizeValue(randomRunes(rng, values, 1+rng.Intn(12)))
			if reason != "" {
				continue
			}
			set[key] = value
		}
		got, dropped := ParseHeaderValues([]string{Encode(set)})
		if len(dropped) != 0 || !sameSet(got, set) {
			t.Fatalf("round trip got %#v dropped %#v want %#v encoded %s", got, dropped, set, Encode(set))
		}
	}
}

func randomRunes(rng *rand.Rand, alphabet []rune, n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(b)
}

func sameSet(a, b Set) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func TestHeaderEdges(t *testing.T) {
	set, dropped := ParseHeaderValues([]string{" ;ignored , noequals , yabanin.secret=1 , issue= , %zz=1"})
	if len(set) != 0 {
		t.Fatalf("set %#v", set)
	}
	if !hasReason(dropped, "noequals", DropInvalidKey) || !hasReason(dropped, "yabanin.secret", DropReserved) || !hasReason(dropped, "issue", DropInvalidValue) {
		t.Fatalf("dropped %#v", dropped)
	}
	if got, _ := ParsePerKey(nil); len(got) != 0 {
		t.Fatalf("nil per-key %#v", got)
	}
	if got, _ := FromRequest(nil); len(got) != 0 {
		t.Fatalf("nil request %#v", got)
	}
	if Encode(nil) != "" {
		t.Fatal("encode empty")
	}
	h := make(http.Header)
	h.Set(PerKeyPrefix, "x")
	h.Set(PerKeyPrefix+"issue", "\nbad")
	_, dropped = ParsePerKey(h)
	if !hasReason(dropped, "", DropInvalidKey) && !hasReason(dropped, PerKeyPrefix, DropInvalidKey) {
		if !hasReason(dropped, "issue", DropInvalidValue) {
			t.Fatalf("per-key %#v", dropped)
		}
	}
	many := make(http.Header)
	for i := 0; i < MaxPerSource+1; i++ {
		many.Set(PerKeyPrefix+"k"+string(rune('a'+i)), "v")
	}
	set, dropped = ParsePerKey(many)
	if len(set) != MaxPerSource || !hasReason(dropped, "", DropTooMany) && !containsReason(dropped, DropTooMany) {
		t.Fatalf("many %d %#v", len(set), dropped)
	}
	base := make(http.Header)
	var parts []string
	for i := 0; i < MaxPerSource; i++ {
		parts = append(parts, "k"+string(rune('a'+i))+"=v")
	}
	base.Set(HeaderName, strings.Join(parts, ","))
	base.Set(PerKeyPrefix+"zzz", "extra")
	_, dropped = FromRequest(base)
	if !containsReason(dropped, DropTooMany) {
		t.Fatalf("overlay %#v", dropped)
	}
}

func containsReason(dropped []Dropped, reason DropReason) bool {
	for _, drop := range dropped {
		if drop.Reason == reason {
			return true
		}
	}
	return false
}

func hasReason(dropped []Dropped, key string, reason DropReason) bool {
	for _, drop := range dropped {
		if drop.Key == key && drop.Reason == reason {
			return true
		}
	}
	return false
}
