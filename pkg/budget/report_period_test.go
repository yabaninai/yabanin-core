package budget

import (
	"testing"
	"time"
)

func mustMonth(t *testing.T, label, tz string) ReportPeriod {
	t.Helper()
	p, err := MonthReportPeriod(label, tz)
	if err != nil {
		t.Fatalf("MonthReportPeriod(%q, %q): unexpected error: %v", label, tz, err)
	}
	return p
}

func mustDay(t *testing.T, label, tz string) ReportPeriod {
	t.Helper()
	p, err := DayReportPeriod(label, tz)
	if err != nil {
		t.Fatalf("DayReportPeriod(%q, %q): unexpected error: %v", label, tz, err)
	}
	return p
}

func TestResolveReportZone(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "UTC", false},
		{"   ", "UTC", false},
		{"UTC", "UTC", false},
		{"Etc/UTC", "UTC", false},
		{"America/New_York", "America/New_York", false},
		{"Europe/Berlin", "Europe/Berlin", false},
		{"Mars/Olympus_Mons", "", true},
		{"UTC/", "", true},
	}
	for _, tc := range cases {
		loc, err := ResolveReportZone(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ResolveReportZone(%q): expected error, got %v", tc.in, loc)
			}
			continue
		}
		if err != nil {
			t.Errorf("ResolveReportZone(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if loc.String() != tc.want {
			t.Errorf("ResolveReportZone(%q): zone = %q, want %q", tc.in, loc.String(), tc.want)
		}
	}
}

func TestMonthReportPeriodUTC(t *testing.T) {
	p := mustMonth(t, "2026-03", "")
	if p.Zone != "UTC" || p.Label != "2026-03" {
		t.Errorf("zone/label = %q/%q, want UTC/2026-03", p.Zone, p.Label)
	}
	if !p.From.Equal(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("From = %v, want 2026-03-01T00:00:00Z", p.From)
	}
	if !p.To.Equal(time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("To = %v, want 2026-04-01T00:00:00Z", p.To)
	}
	buckets := p.DayBuckets()
	if len(buckets) != 31 || buckets[0] != "2026-03-01" || buckets[30] != "2026-03-31" {
		t.Errorf("DayBuckets len/first/last = %d/%s/%s, want 31/2026-03-01/2026-03-31",
			len(buckets), firstOr(buckets), lastOr(buckets))
	}
}

func TestMonthReportPeriodDSTAndYearRollover(t *testing.T) {
	ny, err := ResolveReportZone("America/New_York")
	if err != nil {
		t.Fatal(err)
	}

	// March 2026 contains the US spring-forward transition (2026-03-08):
	// the month is one hour shorter than 31*24h when measured in absolute
	// instants, and starts/ends at LOCAL midnight.
	p := mustMonth(t, "2026-03", "America/New_York")
	if !p.From.Equal(time.Date(2026, 3, 1, 0, 0, 0, 0, ny)) {
		t.Errorf("NY March From = %v, want local midnight 2026-03-01", p.From)
	}
	if !p.To.Equal(time.Date(2026, 4, 1, 0, 0, 0, 0, ny)) {
		t.Errorf("NY March To = %v, want local midnight 2026-04-01", p.To)
	}
	if got := p.To.Sub(p.From); got != 31*24*time.Hour-time.Hour {
		t.Errorf("NY March duration = %v, want 743h (spring-forward month)", got)
	}
	if got := len(p.DayBuckets()); got != 31 {
		t.Errorf("NY March DayBuckets = %d days, want 31", got)
	}

	// November 2026 contains the fall-back transition (2026-11-01): one
	// hour longer than 30*24h.
	nov := mustMonth(t, "2026-11", "America/New_York")
	if got := nov.To.Sub(nov.From); got != 30*24*time.Hour+time.Hour {
		t.Errorf("NY November duration = %v, want 721h (fall-back month)", got)
	}

	// December rolls over into the next year at the local boundary.
	dec := mustMonth(t, "2026-12", "")
	if !dec.To.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("Dec To = %v, want 2027-01-01T00:00:00Z", dec.To)
	}
}

func TestMonthReportPeriodInvalidLabels(t *testing.T) {
	for _, label := range []string{"2026-13", "2026-00", "2026", "2026-3", "202603", "abc-03", "2026-03x", "2026-0a"} {
		if _, err := MonthReportPeriod(label, ""); err == nil {
			t.Errorf("MonthReportPeriod(%q): expected error, got none", label)
		}
	}
	if _, err := MonthReportPeriod("2026-03", "Nope/Nope"); err == nil {
		t.Errorf("MonthReportPeriod with unknown zone: expected error, got none")
	}
}

func TestDayReportPeriodDSTLengths(t *testing.T) {
	// Ordinary day: exactly 24h in any zone.
	d := mustDay(t, "2026-03-07", "America/New_York")
	if got := d.To.Sub(d.From); got != 24*time.Hour {
		t.Errorf("ordinary NY day length = %v, want 24h", got)
	}
	// Spring-forward day 2026-03-08: 23 hours.
	fwd := mustDay(t, "2026-03-08", "America/New_York")
	if got := fwd.To.Sub(fwd.From); got != 23*time.Hour {
		t.Errorf("spring-forward NY day length = %v, want 23h", got)
	}
	if !fwd.From.Equal(time.Date(2026, 3, 8, 5, 0, 0, 0, time.UTC)) {
		// 2026-03-08 local midnight is still EST (-05:00) → 05:00Z.
		t.Errorf("spring-forward From = %v, want 2026-03-08T05:00:00Z", fwd.From)
	}
	if !fwd.To.Equal(time.Date(2026, 3, 9, 4, 0, 0, 0, time.UTC)) {
		// Next local midnight is EDT (-04:00) → 04:00Z.
		t.Errorf("spring-forward To = %v, want 2026-03-09T04:00:00Z", fwd.To)
	}
	// Fall-back day 2026-11-01: 25 hours.
	back := mustDay(t, "2026-11-01", "America/New_York")
	if got := back.To.Sub(back.From); got != 25*time.Hour {
		t.Errorf("fall-back NY day length = %v, want 25h", got)
	}
	// UTC day: exactly 24h.
	utcDay := mustDay(t, "2026-03-08", "")
	if got := utcDay.To.Sub(utcDay.From); got != 24*time.Hour {
		t.Errorf("UTC day length = %v, want 24h", got)
	}
	if got := utcDay.DayBuckets(); len(got) != 1 || got[0] != "2026-03-08" {
		t.Errorf("day DayBuckets = %v, want [2026-03-08]", got)
	}
	if utcDay.Zone != "UTC" {
		t.Errorf("day Zone = %q, want UTC", utcDay.Zone)
	}
}

func TestDayReportPeriodInvalidLabels(t *testing.T) {
	for _, label := range []string{
		"2026-02-30", // never exists
		"2026-02-29", // 2026 is not a leap year
		"2026-3-8",   // not zero-padded
		"20260308",   // missing separators
		"2026-03-08T00:00:00Z",
		"",
	} {
		if _, err := DayReportPeriod(label, ""); err == nil {
			t.Errorf("DayReportPeriod(%q): expected error, got none", label)
		}
	}
	if _, err := DayReportPeriod("2026-03-08", "Mars/Olympus"); err == nil {
		t.Errorf("DayReportPeriod with unknown zone: expected error, got none")
	}
}

func TestDayBucketsTilePeriod(t *testing.T) {
	// The day buckets of a month must tile the period exactly: the first
	// bucket starts at From, consecutive buckets are back-to-back (prev To
	// == next From), and the last bucket ends at To. This is the property
	// that makes per-day reader rows (bucketed by the same local days in
	// SQL) sum exactly into the period window.
	for _, tc := range []struct{ label, tz string }{
		{"2026-03", "America/New_York"}, // 23h day inside
		{"2026-11", "America/New_York"}, // 25h day inside
		{"2026-02", "UTC"},
		{"2025-02", "Asia/Kolkata"},     // no DST; half-hour offset zone
		{"2026-12", "Pacific/Auckland"}, // southern DST, year rollover
	} {
		month := mustMonth(t, tc.label, tc.tz)
		buckets := month.DayBuckets()
		if len(buckets) == 0 {
			t.Fatalf("month %s/%s: no day buckets", tc.label, tc.tz)
		}
		first, err := DayReportPeriod(buckets[0], tc.tz)
		if err != nil {
			t.Fatalf("bucket %s: %v", buckets[0], err)
		}
		if !first.From.Equal(month.From) {
			t.Errorf("month %s/%s: first bucket From %v != period From %v",
				tc.label, tc.tz, first.From, month.From)
		}
		cursor := first
		for _, b := range buckets[1:] {
			next, err := DayReportPeriod(b, tc.tz)
			if err != nil {
				t.Fatalf("bucket %s: %v", b, err)
			}
			if !next.From.Equal(cursor.To) {
				t.Errorf("month %s/%s: bucket %s From %v != previous To %v (gap in tiling)",
					tc.label, tc.tz, b, next.From, cursor.To)
			}
			cursor = next
		}
		if !cursor.To.Equal(month.To) {
			t.Errorf("month %s/%s: last bucket To %v != period To %v",
				tc.label, tc.tz, cursor.To, month.To)
		}
	}
}

func firstOr(s []string) string {
	if len(s) == 0 {
		return "<none>"
	}
	return s[0]
}

func lastOr(s []string) string {
	if len(s) == 0 {
		return "<none>"
	}
	return s[len(s)-1]
}
