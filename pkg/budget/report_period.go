package budget

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Reporting periods for spend reports and reconciliation (N06-P06-T03).
//
// A reporting period is a half-open interval [From, To) of absolute
// instants whose DAY BUCKETS are calendar days in an explicit IANA
// timezone — the organization's reporting timezone (organizations.timezone,
// default 'UTC'). Two properties matter for financial exports and make the
// difference from naive UTC math:
//
//   - The period boundary of a named local period ("March 2026") is local
//     midnight, not UTC midnight: an org in America/New_York gets a month
//     that starts at 2026-03-01T00:00-05:00, and every request is bucketed
//     to the day it was billed on *for that org*.
//   - DST is handled by construction: local calendar days are 23 or 25
//     hours long around a transition, and [From, To) of a DST month is 743
//     or 745 hours, never a flat 30×24. time.AddDate/time.Date operate on
//     calendar fields in the location, so the math below is transition-safe
//     without any manual offset arithmetic.
//
// Every helper rejects unknown zone names instead of silently falling back
// to UTC: a report that quietly used a different timezone than the org
// configured would misstate the period while looking valid. (The
// presentation layer's i18n.Location degrades to UTC instead — that
// convention is deliberately NOT shared here; reporting is a fact surface.)

// ResolveReportZone resolves the IANA timezone name of an organization's
// reporting setting. Empty (and whitespace-only) names, "UTC" and "Etc/UTC"
// resolve to time.UTC; any other name must be a valid tzdb zone or an error
// is returned — never a silent UTC fallback. The returned Location's String()
// is the canonical name to pass to SQL (AT TIME ZONE $n) and to echo in
// reports.
func ResolveReportZone(tz string) (*time.Location, error) {
	name := strings.TrimSpace(tz)
	if name == "" || name == "UTC" || name == "Etc/UTC" {
		return time.UTC, nil
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("report zone %q: %w", tz, err)
	}
	return loc, nil
}

// ReportPeriod is a named half-open reporting period [From, To) whose day
// buckets are local calendar days in Zone. From is inclusive, To exclusive;
// both are absolute instants and compare correctly against any time.Time.
// Build instances only via MonthReportPeriod / DayReportPeriod (or the zero
// value, which methods treat as the empty period in UTC).
type ReportPeriod struct {
	// Label is the canonical local period label ("2026-03" or "2026-03-08").
	Label string
	// Zone is the resolved IANA zone name actually used (canonical: "UTC"
	// for empty input; never the raw unresolved setting).
	Zone string
	// From (inclusive) and To (exclusive) are absolute instants.
	From, To time.Time

	loc *time.Location
}

// zone returns the period location, defaulting to UTC for the zero value.
func (p ReportPeriod) zone() *time.Location {
	if p.loc == nil {
		return time.UTC
	}
	return p.loc
}

// MonthReportPeriod builds the calendar month `label` ("YYYY-MM") in zone
// tz: [local midnight of the 1st, local midnight of the 1st of the next
// month). The month containing a spring-forward transition is one hour
// shorter than 30×24; the fall-back month one hour longer. Invalid labels
// and unknown zones are errors (no silent defaults on a fact surface).
func MonthReportPeriod(label, tz string) (ReportPeriod, error) {
	loc, err := ResolveReportZone(tz)
	if err != nil {
		return ReportPeriod{}, err
	}
	year, month, err := parseYearMonth(label)
	if err != nil {
		return ReportPeriod{}, err
	}
	from := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, loc)
	nextYear, nextMonth := year, month+1
	if nextMonth == 13 {
		nextYear, nextMonth = year+1, 1
	}
	to := time.Date(nextYear, time.Month(nextMonth), 1, 0, 0, 0, 0, loc)
	return ReportPeriod{Label: label, Zone: loc.String(), From: from, To: to, loc: loc}, nil
}

// DayReportPeriod builds one local calendar day `label` ("YYYY-MM-DD") in
// zone tz: [local midnight, next local midnight). Around a DST transition
// the interval is 23 or 25 hours long (computed by calendar-field
// addition, so no offset arithmetic is needed). A label naming a local day
// that does not exist in the zone (whole-day skipped by a zone reform,
// e.g. Pacific/Apia 2011-12-30) yields an empty period; ordinary business
// zones never hit this.
func DayReportPeriod(label, tz string) (ReportPeriod, error) {
	loc, err := ResolveReportZone(tz)
	if err != nil {
		return ReportPeriod{}, err
	}
	if _, err := time.ParseInLocation("2006-01-02", label, loc); err != nil {
		return ReportPeriod{}, fmt.Errorf("day label %q: %w", label, err)
	}
	start, err := parseYearMonthDayStrict(label, loc)
	if err != nil {
		return ReportPeriod{}, err
	}
	return ReportPeriod{
		Label: label, Zone: loc.String(), From: start, To: start.AddDate(0, 0, 1), loc: loc,
	}, nil
}

// DayBuckets returns the local YYYY-MM-DD labels of every calendar day that
// intersects [From, To), in chronological order. Labels iterate by local
// calendar fields (AddDate), so DST transitions produce the correct number
// of 23/25-hour days. The zero period yields no buckets.
func (p ReportPeriod) DayBuckets() []string {
	var out []string
	for cur := p.From.In(p.zone()); !cur.IsZero() && cur.Before(p.To); cur = cur.AddDate(0, 0, 1) {
		out = append(out, cur.Format("2006-01-02"))
	}
	return out
}

// parseYearMonth strictly parses a "YYYY-MM" month label (1-based month,
// zero-padded, nothing else accepted) so a mistyped period can never be
// silently reinterpreted.
func parseYearMonth(label string) (int, int, error) {
	if len(label) != 7 || label[4] != '-' {
		return 0, 0, fmt.Errorf("month label %q must be YYYY-MM", label)
	}
	year, err := strconv.Atoi(label[:4])
	if err != nil {
		return 0, 0, fmt.Errorf("month label %q: bad year: %w", label, err)
	}
	month, err := strconv.Atoi(label[5:])
	if err != nil || label[5] == '0' && label[6] == '0' {
		return 0, 0, fmt.Errorf("month label %q: bad month", label)
	}
	if month < 1 || month > 12 {
		return 0, 0, fmt.Errorf("month label %q: month out of range 01..12", label)
	}
	return year, month, nil
}

// parseYearMonthDayStrict re-validates a "YYYY-MM-DD" label the same way
// ParseInLocation does (including month lengths and leap years) and returns
// local midnight. Callers that already parsed keep this as the single
// construction point so From always carries the period location.
func parseYearMonthDayStrict(label string, loc *time.Location) (time.Time, error) {
	t, err := time.ParseInLocation("2006-01-02", label, loc)
	if err != nil {
		return time.Time{}, fmt.Errorf("day label %q: %w", label, err)
	}
	return t, nil
}
