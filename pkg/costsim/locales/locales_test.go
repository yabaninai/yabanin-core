package locales

import (
	"testing"

	"github.com/reireirei/yabanin/pkg/i18n"
)

// TestCatalogCompleteness enforces that every registered locale defines every
// key in the closed `keys` set (a missing key would silently fall back to en
// per-key, which we do not want to allow for a shipped locale). This is the
// guard that a new locale file is complete.
func TestCatalogCompleteness(t *testing.T) {
	for _, tag := range Available() {
		c := Get(tag)
		for _, k := range keys {
			if _, ok := c.strs[k]; !ok {
				t.Errorf("locale %q is missing key %q", tag, k)
			}
		}
		// No stray keys outside the closed set.
		for k := range c.strs {
			if !containsKey(k) {
				t.Errorf("locale %q defines unknown key %q", tag, k)
			}
		}
	}
}

func containsKey(k string) bool {
	for _, x := range keys {
		if x == k {
			return true
		}
	}
	return false
}

// TestGet_FallsBackToEn ensures empty/unknown locale tags degrade to English
// (the render must never fail on a bad --lang).
func TestGet_FallsBackToEn(t *testing.T) {
	if c := Get(""); c.Lang() != "en" {
		t.Fatalf("Get(\"\") lang = %q, want en", c.Lang())
	}
	if c := Get("xx-UNKNOWN"); c.Lang() != "en" {
		t.Fatalf("Get(unknown) lang = %q, want en", c.Lang())
	}
	// A per-key fallback: en catalog must answer any key.
	if got := Get("en").T("docTitle"); got != "Yabanin Spend Audit" {
		t.Fatalf("en docTitle = %q", got)
	}
}

// TestMoney_EnMatchesLegacy pins the invariant that en money formatting via
// pkg/i18n produces the legacy "$X.XX" shape, so en reports are unchanged.
func TestMoney_EnMatchesLegacy(t *testing.T) {
	got := Get("en").Money(1234.5)
	// i18n.FormatMoney("en","USD",1234.5) → "$1,234.50"
	if got != i18n.FormatMoney("en", "USD", 1234.5) {
		t.Fatalf("en Money(1234.5) = %q, want %q", got, i18n.FormatMoney("en", "USD", 1234.5))
	}
}

// TestRegisteredLocales pins that the locales this card ships (en + the
// machine locales) are actually registered. ru is the reference locale with a
// full translation; the rest are added as their files land.
func TestRegisteredLocales(t *testing.T) {
	avail := Available()
	for _, want := range []string{"en", "ru"} {
		if !containsStr(avail, want) {
			t.Fatalf("locale %q not registered (have %v)", want, avail)
		}
	}
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
