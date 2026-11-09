package i18n

import (
	"golang.org/x/text/currency"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"golang.org/x/text/number"
)

// This file holds the ICU/CLDR *value* formatters (money and plain numbers)
// that I18N-11 introduces. There is intentionally NO date formatter here:
// billing-day keys are ISO `YYYY-MM-DD` strings (see billing.go) — they are
// data, not display text — and localized date *rendering* is the frontend's
// job (Intl.DateTimeFormat with the org timezone). Keeping dates out of Go
// avoids a second source of truth for how a day is spelled.

// FormatMoney renders a USD-denominated amount (dollars, e.g. 12.4) localized
// for `lang` in the org's presentation currency `code` (ISO-4217). It is an
// ICU/Unicode formatter built on golang.org/x/text:
//
//   - the numeric part (digit grouping, decimal mark, scale) comes from the
//     locale's CLDR decimal pattern via x/text/number;
//   - the currency symbol comes from the locale's CLDR currency data via
//     x/text/currency (so "USD" is "$" in en, "US$" in es, "¥" in ja, "€" in
//     de, etc.), with a graceful fallback to the ISO code when the locale has
//     no symbol for the unit.
//
// Note on rates: this formats the *number* under the org's currency code. The
// repo stores money in USD; a deployment that actually converts to another
// currency must apply the FX rate before calling this. I18N-11 scopes currency
// to *presentation* (code + CLDR formatting), not FX conversion (see the
// work-record).
func FormatMoney(lang, code string, amount float64) string {
	tag := language.Make(orEn(lang))
	unit := currencyUnit(code)
	// Symbol picks the CLDR symbol for (locale, unit) — "$" for en/USD,
	// "US$" for es/USD, "¥" for ja/JPY, etc. — falling back to the ISO code
	// when the locale has no symbol. Default(unit) pins the currency.
	f := message.NewPrinter(tag)
	return f.Sprintf("%v", currency.Symbol.Default(unit)(unit.Amount(amount)))
}

// FormatNumber renders a plain number (e.g. a request count) with the locale's
// CLDR digit grouping — no currency symbol. Replaces the dashboard's bare
// toLocaleString()/toFixed for counts and percentages.
func FormatNumber(lang string, amount float64) string {
	tag := language.Make(orEn(lang))
	// number.Decimal(x) is a Formatter; message's Printer applies the locale's
	// grouping via %d (the locale-aware decimal verb).
	f := message.NewPrinter(tag)
	return f.Sprintf("%d", number.Decimal(amount))
}

// currencyUnit parses an ISO-4217 code into a currency.Unit, defaulting to USD
// for empty or unparseable codes (presentation must not break the data path on
// a bad org setting).
func currencyUnit(code string) currency.Unit {
	if code == "" {
		return currency.USD
	}
	u, err := currency.ParseISO(code)
	if err != nil {
		return currency.USD
	}
	return u
}

func orEn(lang string) string {
	if lang == "" {
		return "en"
	}
	return lang
}
