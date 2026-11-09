package i18n

import (
	"strings"
	"testing"
)

// These tests assert *structural* CLDR properties rather than brittle exact
// symbol strings, because CLDR revisions can change a symbol. The invariants
// that matter for I18N-11: (1) grouping is locale-correct, (2) the currency
// symbol is locale-specific (not a bare "USD"), (3) zero/unknown degrade
// safely.

func TestFormatMoney_GroupingIsLocaleCorrect(t *testing.T) {
	// 1234.5 with 2-decimal scale:
	//   en groups with comma: "1,234.50"
	//   de groups with dot + comma decimal: "1.234,50"
	en := FormatMoney("en", "USD", 1234.5)
	if !strings.Contains(en, "1,234.50") {
		t.Errorf("en/USD 1234.5 = %q, want to contain 1,234.50 (en grouping)", en)
	}
	de := FormatMoney("de", "EUR", 1234.5)
	if !strings.Contains(de, "1.234,50") {
		t.Errorf("de/EUR 1234.5 = %q, want to contain 1.234,50 (de grouping)", de)
	}
}

func TestFormatMoney_CurrencySymbolIsLocaleSpecific(t *testing.T) {
	// en/USD must carry the "$" symbol, not the ISO code.
	en := FormatMoney("en", "USD", 1)
	if !strings.Contains(en, "$") {
		t.Errorf("en/USD 1 = %q, want to contain the $ symbol", en)
	}
	// de/EUR must carry the "€" symbol.
	de := FormatMoney("de", "EUR", 1)
	if !strings.Contains(de, "€") {
		t.Errorf("de/EUR 1 = %q, want to contain the € symbol", de)
	}
	// ja/JPY renders with no decimal places (JPY scale 0) — 1234.5 -> 1,235.
	ja := FormatMoney("ja", "JPY", 1234.5)
	if !strings.Contains(ja, "1,235") {
		t.Errorf("ja/JPY 1234.5 = %q, want to contain 1,235 (JPY scale 0, rounded)", ja)
	}
}

func TestFormatMoney_UnknownCurrencyFallsBackToISO(t *testing.T) {
	// An ISO code the CLDR tables may not have a symbol for should still render
	// (with the ISO code or a symbol) — never empty, never panic.
	out := FormatMoney("en", "XYZ", 5)
	if strings.TrimSpace(out) == "" {
		t.Fatalf("en/XYZ 5 rendered empty")
	}
	// Empty code defaults to USD.
	empty := FormatMoney("en", "", 5)
	if !strings.Contains(empty, "$") {
		t.Errorf("en/(empty) 5 = %q, want USD $ default", empty)
	}
}

func TestFormatNumber_Grouping(t *testing.T) {
	en := FormatNumber("en", 1234567)
	if !strings.Contains(en, "1,234,567") {
		t.Errorf("en 1234567 = %q, want 1,234,567", en)
	}
	de := FormatNumber("de", 1234567)
	if !strings.Contains(de, "1.234.567") {
		t.Errorf("de 1234567 = %q, want 1.234.567 (de grouping)", de)
	}
}

func TestFormatNumber_EmptyLangDefaultsToEnglish(t *testing.T) {
	if got := FormatNumber("", 1234567); !strings.Contains(got, "1,234,567") {
		t.Errorf("FormatNumber(\"\") = %q, want en grouping", got)
	}
}
