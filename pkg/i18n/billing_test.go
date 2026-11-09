package i18n

import (
	"testing"
	"time"
)

// TestBillingDay_DSTSpringForward locks the I18N-11 invariant: in a DST zone
// the billing day rolls at *local* midnight, not at 00:00 UTC. Around the
// 2026-03-08 02:00 America/New_York spring-forward (EST -5 -> EDT -4):
//
//   - 06:30 UTC = 01:30 EST (before the transition)  -> local day 2026-03-08
//   - 07:30 UTC = 03:30 EDT (after the transition)   -> local day 2026-03-08
//
// Both are the same billing day (correct — local midnight 03-08 -> 03-09 has
// not passed). A naive UTC-day implementation would also say 03-08 here, so the
// real DST discriminator is the fall-back / late-evening cases below.
func TestBillingDay_DSTSpringForward(t *testing.T) {
	ny := "America/New_York"
	cases := []struct {
		name string
		t    time.Time
		want string
	}{
		{"est-before-spring", time.Date(2026, 3, 8, 6, 30, 0, 0, time.UTC), "2026-03-08"},
		{"edt-after-spring", time.Date(2026, 3, 8, 7, 30, 0, 0, time.UTC), "2026-03-08"},
		// 2026-03-09 06:30 UTC = 01:30 EDT = local 03-09 (a full local day later).
		{"next-local-day", time.Date(2026, 3, 9, 6, 30, 0, 0, time.UTC), "2026-03-09"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := BillingDay(c.t, ny); got != c.want {
				t.Fatalf("BillingDay(%s, %s) = %s, want %s", c.t.UTC().Format(time.RFC3339), ny, got, c.want)
			}
		})
	}
}

// TestBillingDay_DSTFallBack is the strongest DST discriminator. In
// America/New_York, 2026-11-01 00:30 UTC = 2026-10-31 20:30 EDT — the request
// is billed to the *previous* UTC day (local 10-31), even though the UTC day is
// 11-01. A UTC-day implementation returns 2026-11-01 and fails; the local-day
// implementation returns 2026-10-31 and passes. This is exactly the
// "billing-day in local TZ" requirement of I18N-11.
func TestBillingDay_DSTFallBack(t *testing.T) {
	ny := "America/New_York"
	// 2026-11-01 00:30 UTC == 2026-10-31 20:30 EDT (offset -4, still DST).
	got := BillingDay(time.Date(2026, 11, 1, 0, 30, 0, 0, time.UTC), ny)
	if got != "2026-10-31" {
		t.Fatalf("BillingDay(2026-11-01T00:30Z, NY) = %s, want 2026-10-31 (local previous day)", got)
	}
	// And a clearly-local-next-morning instant stays on its local day.
	got2 := BillingDay(time.Date(2026, 11, 1, 5, 0, 0, 0, time.UTC), ny) // 01:00 EDT
	if got2 != "2026-11-01" {
		t.Fatalf("BillingDay(2026-11-01T05:00Z, NY) = %s, want 2026-11-01", got2)
	}
}

// TestBillingDay_NonDSTZone guards that a zone without DST (Asia/Tokyo, fixed
// +9) buckets purely by local day: 2026-01-02 15:30 UTC = 2026-01-03 00:30 JST
// is billed to 2026-01-03.
func TestBillingDay_NonDSTZone(t *testing.T) {
	tokyo := "Asia/Tokyo"
	got := BillingDay(time.Date(2026, 1, 2, 15, 30, 0, 0, time.UTC), tokyo)
	if got != "2026-01-03" {
		t.Fatalf("BillingDay(2026-01-02T15:30Z, Tokyo) = %s, want 2026-01-03", got)
	}
}

// TestBillingDay_UTCDefault verifies the legacy behavior is preserved: empty
// and "UTC" timezones bucket by UTC day.
func TestBillingDay_UTCDefault(t *testing.T) {
	for _, tz := range []string{"", "UTC", "Etc/UTC"} {
		got := BillingDay(time.Date(2026, 11, 1, 0, 30, 0, 0, time.UTC), tz)
		if got != "2026-11-01" {
			t.Fatalf("BillingDay(2026-11-01T00:30Z, %q) = %s, want 2026-11-01", tz, got)
		}
	}
}

// TestBillingDay_UnknownZoneFallsBackToUTC ensures a garbage timezone degrades
// to UTC (never an error) so a bad org setting cannot break the billing path.
func TestBillingDay_UnknownZoneFallsBackToUTC(t *testing.T) {
	got := BillingDay(time.Date(2026, 11, 1, 0, 30, 0, 0, time.UTC), "Not/AZone")
	if got != "2026-11-01" {
		t.Fatalf("BillingDay unknown zone = %s, want 2026-11-01 (UTC fallback)", got)
	}
}

// TestBillingMonth_DST verifies monthly bucketing is also local: in NY, the
// instant 2026-04-01 03:30 UTC = 2026-03-31 23:30 EDT is still March locally,
// so the billing month is 2026-03, not 2026-04.
func TestBillingMonth_DST(t *testing.T) {
	got := BillingMonth(time.Date(2026, 4, 1, 3, 30, 0, 0, time.UTC), "America/New_York")
	if got != "2026-03" {
		t.Fatalf("BillingMonth(2026-04-01T03:30Z, NY) = %s, want 2026-03", got)
	}
}

// TestStartOfDay returns local midnight of the org's billing day as an
// absolute time; it must round-trip to the same billing day.
func TestStartOfDay(t *testing.T) {
	ny := "America/New_York"
	// 2026-11-01 00:30 UTC = 2026-10-31 20:30 EDT.
	inst := time.Date(2026, 11, 1, 0, 30, 0, 0, time.UTC)
	sod := StartOfDay(inst, ny)
	// The midnight is on local 2026-10-31 in NY.
	if got := BillingDayIn(sod, MustLocation(ny)); got != "2026-10-31" {
		t.Fatalf("StartOfDay billing day = %s, want 2026-10-31", got)
	}
	// And it is exactly 00:00:00 local.
	if loc := sod.In(MustLocation(ny)); loc.Hour() != 0 || loc.Minute() != 0 || loc.Second() != 0 {
		t.Fatalf("StartOfDay not local midnight: %s", loc.Format(time.RFC3339))
	}
}

func TestCurrency_Normalize(t *testing.T) {
	cases := map[string]string{
		"":    "USD",
		"usd": "USD",
		"Usd": "USD",
		"eur": "EUR",
		"JPY": "JPY",
		"brl": "BRL",
	}
	for in, want := range cases {
		if got := Currency(in); got != want {
			t.Errorf("Currency(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestLocation_UnknownFallsBackToUTC(t *testing.T) {
	if loc := Location("Not/AZone"); loc != time.UTC {
		t.Fatalf("Location(unknown) = %v, want time.UTC", loc)
	}
	if loc := Location(""); loc != time.UTC {
		t.Fatalf("Location(\"\") = %v, want time.UTC", loc)
	}
}
