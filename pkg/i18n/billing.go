// Package i18n holds the presentation-localization primitives introduced by
// I18N-11 (currencies, timezones, ICU formatting, billing-day bucketing).
//
// Money in the database stays USD / integer cents (see pkg/pricing and the
// 0001 schema). This package never converts stored amounts; it only (a) decides
// how a *day* or *period* boundary is computed for a given IANA timezone
// (DST-aware), and (b) formats raw numbers for a locale/currency using the
// Unicode/ICU data in golang.org/x/text.
package i18n

import (
	"fmt"
	"time"
)

// BillingDay returns the calendar day (YYYY-MM-DD, no time) that instant `t`
// falls in, expressed in the IANA timezone `tz`. This is the "billing day":
// the day a request is billed to, which rolls at *local* midnight.
//
// DST-awareness comes for free from Go's time.Location: converting to the
// location and reading the date fields yields the local calendar date, so a
// 23:30→01:30 spring-forward or a 01:59→00:59 fall-back in the target zone is
// handled correctly (the billing day advances when local midnight passes, not
// when 00:00 UTC passes).
//
// An empty or unresolvable `tz` falls back to UTC, preserving the legacy
// behavior for orgs that have not set a timezone.
func BillingDay(t time.Time, tz string) string {
	return BillingDayIn(t, Location(tz))
}

// BillingDayIn is BillingDay with an already-resolved *time.Location.
// Exported so callers that resolve the location once (and reuse it) can skip
// the repeated tzdb lookup.
func BillingDayIn(t time.Time, loc *time.Location) string {
	return t.In(loc).Format("2006-01-02")
}

// BillingMonth returns the calendar month (YYYY-MM) that instant `t` falls in,
// in the IANA timezone `tz`. Used for monthly period bucketing (team budgets,
// spend periods). Same DST/fallback semantics as BillingDay.
func BillingMonth(t time.Time, tz string) string {
	return BillingMonthIn(t, Location(tz))
}

// BillingMonthIn is BillingMonth with an already-resolved *time.Location.
func BillingMonthIn(t time.Time, loc *time.Location) string {
	return t.In(loc).Format("2006-01")
}

// Location resolves an IANA timezone name to *time.Location. Empty or unknown
// names resolve to time.UTC (never an error) so a bad org setting degrades to
// the legacy UTC behavior instead of failing the request path.
//
// Unknown names are not fatal: time.LoadLocation returns an error for them and
// we substitute UTC. This matches the "presentation must not break the data
// path" invariant of the rest of I18N-11.
func Location(tz string) *time.Location {
	if tz == "" || tz == "UTC" || tz == "Etc/UTC" {
		return time.UTC
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.UTC
	}
	return loc
}

// StartOfDay returns local midnight (00:00:00.000000000) of the day that
// instant `t` falls in, in the IANA timezone `tz`, as an absolute time.Time.
// Useful as the lower bound of a "billing day" range query.
func StartOfDay(t time.Time, tz string) time.Time {
	loc := Location(tz)
	local := t.In(loc)
	midnight := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
	return midnight
}

// Currency returns the normalized ISO-4217 code for an org's currency setting,
// upper-cased and defaulted to "USD" when empty. Stored money remains USD;
// this is purely the presentation code handed to the formatters.
func Currency(code string) string {
	if code == "" {
		return "USD"
	}
	return upper(code)
}

// upper is a small ASCII upper-caser so we avoid importing strings for a one-
// field normalization (and keep the package dependency-free outside x/text).
func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] = b[i] - ('a' - 'A')
		}
	}
	return string(b)
}

// MustLocation is the panicking variant of Location, for tests that need to
// assert a timezone actually resolved (e.g. a DST zone) rather than silently
// falling back to UTC.
func MustLocation(tz string) *time.Location {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		panic(fmt.Sprintf("i18n: unknown timezone %q: %v", tz, err))
	}
	return loc
}
