package money

import (
	"errors"
	"math"
	"testing"
)

func TestFromUSD_ExactConversionAndRounding(t *testing.T) {
	cases := []struct {
		name string
		usd  float64
		want MicroUSD
	}{
		{"zero", 0, 0},
		{"one cent", 0.01, 10000},
		{"four tenths of a cent", 0.004, 4000},
		{"third of a cent rounds down", 0.00333, 3330},
		{"half micro rounds away from zero", 0.0000005, 1},
		{"just under half micro rounds down", 0.00000049999, 0},
		{"one dollar", 1, 1_000_000},
		{"float noise still exact", 0.07, 70000},
		{"large but representable", 9e12, 9_000_000_000_000_000_000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FromUSD(tc.usd)
			if err != nil {
				t.Fatalf("FromUSD(%v): %v", tc.usd, err)
			}
			if got != tc.want {
				t.Fatalf("FromUSD(%v) = %d, want %d", tc.usd, int64(got), int64(tc.want))
			}
		})
	}
}

func TestFromUSD_RejectsInvalidQuotes(t *testing.T) {
	cases := []struct {
		name string
		usd  float64
		want error
	}{
		{"NaN", math.NaN(), ErrNonFinite},
		{"+Inf", math.Inf(1), ErrNonFinite},
		{"-Inf", math.Inf(-1), ErrNonFinite},
		{"negative", -0.01, ErrNegative},
		{"negative zero is valid", -0, error(nil)},
		{"beyond range", MaxUSD * 2, ErrRange},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FromUSD(tc.usd)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("FromUSD(%v): unexpected error %v", tc.usd, err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("FromUSD(%v) error = %v, want %v", tc.usd, err, tc.want)
			}
			if got != 0 {
				t.Fatalf("FromUSD(%v) = %d with error, want 0", tc.usd, int64(got))
			}
		})
	}
}

// TestFromUSD_MaxUSDBoundary pins the conversion at the representable
// domain edge: the exact MaxUSD quote is the largest billable positive and
// must convert to MaxInt64 µUSD, never wrap negative; the float64 one step
// below converts exactly; anything strictly above MaxUSD is ErrRange.
func TestFromUSD_MaxUSDBoundary(t *testing.T) {
	// float64(MaxInt64-1)/1e6 collapses onto MaxUSD: one µUSD below the
	// boundary is not representable in float64 at that magnitude, so the
	// converted amount must saturate identically instead of wrapping.
	maxUSDMinusOneMicro := float64(math.MaxInt64-1) / float64(MicroPerUSD)
	if maxUSDMinusOneMicro != MaxUSD {
		t.Fatalf("float64(MaxInt64-1)/1e6 = %.17g, want MaxUSD (%.17g)", maxUSDMinusOneMicro, MaxUSD)
	}
	cases := []struct {
		name    string
		usd     float64
		want    MicroUSD
		wantErr error
	}{
		{
			name: "exact MaxUSD is the largest billable positive",
			usd:  MaxUSD,
			want: MicroUSD(math.MaxInt64),
		},
		{
			name: "one micro below the boundary collapses to MaxUSD and saturates",
			usd:  maxUSDMinusOneMicro,
			want: MicroUSD(math.MaxInt64),
		},
		{
			name: "largest float64 strictly below MaxUSD converts exactly",
			usd:  math.Nextafter(MaxUSD, 0),
			want: MicroUSD(9223372036854773760),
		},
		{
			name:    "one-past-boundary is out of range",
			usd:     math.Nextafter(MaxUSD, math.Inf(1)),
			wantErr: ErrRange,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FromUSD(tc.usd)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("FromUSD(%v) error = %v, want %v", tc.usd, err, tc.wantErr)
				}
				if got != 0 {
					t.Fatalf("FromUSD(%v) = %d with error, want 0", tc.usd, int64(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("FromUSD(%v): %v", tc.usd, err)
			}
			if got != tc.want {
				t.Fatalf("FromUSD(%v) = %d, want %d", tc.usd, int64(got), int64(tc.want))
			}
			if got < 0 {
				t.Fatalf("FromUSD(%v) = %d wrapped negative", tc.usd, int64(got))
			}
			// Split round-trip must hold at the boundary: no residue loss,
			// no overflow rebuilding the amount from cents + remainder.
			cents, rem := got.Split()
			if rem < 0 || rem >= MicroUSD(MicroPerCent) ||
				MicroUSD(cents)*MicroUSD(MicroPerCent)+rem != got {
				t.Fatalf("Split(%d) = (%d, %d): round-trip broken", int64(got), cents, int64(rem))
			}
		})
	}
}

// TestQuoteFromUSD_MaxUSDBoundary pins the event-boundary classification at
// the representable edge: the exact MaxUSD quote is chargeable (QuotePositive
// with MaxInt64 µUSD), the one-past-boundary quote is unknown, never billed.
func TestQuoteFromUSD_MaxUSDBoundary(t *testing.T) {
	m, state := QuoteFromUSD(MaxUSD, true)
	if state != QuotePositive || m != MicroUSD(math.MaxInt64) {
		t.Fatalf("QuoteFromUSD(MaxUSD) = (%d, %v), want (MaxInt64, QuotePositive)", int64(m), state)
	}
	m, state = QuoteFromUSD(math.Nextafter(MaxUSD, math.Inf(1)), true)
	if state != QuoteUnknown || m != 0 {
		t.Fatalf("QuoteFromUSD(past MaxUSD) = (%d, %v), want (0, QuoteUnknown)", int64(m), state)
	}
}

func TestFromCents_AndCentsProjection(t *testing.T) {
	m, err := FromCents(25)
	if err != nil || m != 250_000 {
		t.Fatalf("FromCents(25) = %d, %v; want 250000, nil", int64(m), err)
	}
	if _, err := FromCents(-1); !errors.Is(err, ErrNegative) {
		t.Fatalf("FromCents(-1) = %v, want ErrNegative", err)
	}
	if _, err := FromCents(math.MaxInt64); !errors.Is(err, ErrRange) {
		t.Fatalf("FromCents(MaxInt64) = %v, want ErrRange", err)
	}
	if MustFromCents(1) != 10000 {
		t.Fatal("MustFromCents(1) = wrong value")
	}

	// Cents() is the lossy public projection: round half away from zero.
	cases := []struct {
		micro MicroUSD
		want  int64
	}{
		{0, 0},
		{4000, 0},        // $0.004 → 0 cents (sub-cent, remainder carries it)
		{5000, 1},        // exactly half a cent rounds away from zero
		{4999, 0},        // just under half a cent rounds down
		{15000, 2},       // 1.5 cents → 2
		{10000, 1},       // exact cent
		{4_000_000, 400}, // $4.00
		{9_999, 1},       // 0.9999 cents rounds to 1
	}
	for _, tc := range cases {
		if got := tc.micro.Cents(); got != tc.want {
			t.Fatalf("MicroUSD(%d).Cents() = %d, want %d", int64(tc.micro), got, tc.want)
		}
	}
}

func TestCents_RoundingBoundaries(t *testing.T) {
	cases := []struct {
		name  string
		micro MicroUSD
		want  int64
	}{
		{"zero", 0, 0},
		{"positive below half", 4_999, 0},
		{"positive half", 5_000, 1},
		{"positive above half", 5_001, 1},
		{"negative below half", -4_999, 0},
		{"negative half", -5_000, -1},
		{"negative above half", -5_001, -1},
		{"max int64", MicroUSD(math.MaxInt64), 922_337_203_685_478},
		{"min int64", MicroUSD(math.MinInt64), -922_337_203_685_478},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.micro.Cents(); got != tc.want {
				t.Fatalf("MicroUSD(%d).Cents() = %d, want %d", int64(tc.micro), got, tc.want)
			}
		})
	}
}

func TestSplit_PreservesExactValue(t *testing.T) {
	cases := []MicroUSD{0, 1, 4000, 9999, 10000, 10001, 4_000_000, 123_456_789, MicroUSD(math.MaxInt64)}
	for _, m := range cases {
		cents, rem := m.Split()
		rebuilt := MicroUSD(cents)*MicroUSD(MicroPerCent) + rem
		if rebuilt != m {
			t.Fatalf("Split(%d) = (%d, %d) rebuilds %d", int64(m), cents, int64(rem), int64(rebuilt))
		}
		if rem < 0 || rem >= MicroUSD(MicroPerCent) {
			t.Fatalf("Split(%d) remainder %d outside [0, 10000)", int64(m), int64(rem))
		}
	}
	if c, r := MicroUSD(4000).Split(); c != 0 || r != 4000 {
		t.Fatalf("Split(4000) = (%d, %d), want (0, 4000)", c, int64(r))
	}
	if c, r := MicroUSD(15000).Split(); c != 1 || r != 5000 {
		t.Fatalf("Split(15000) = (%d, %d), want (1, 5000)", c, int64(r))
	}
}

func TestAddSub_OverflowRejectedNotWrapped(t *testing.T) {
	max := MicroUSD(math.MaxInt64)
	if _, err := max.Add(1); !errors.Is(err, ErrRange) {
		t.Fatalf("max+1 = %v, want ErrRange", err)
	}
	if _, err := MicroUSD(0).Sub(1); !errors.Is(err, ErrRange) {
		t.Fatalf("0-1 = %v, want ErrRange (negative result invalid)", err)
	}
	got, err := MicroUSD(1).Add(MicroUSD(2))
	if err != nil || got != 3 {
		t.Fatalf("1+2 = %d, %v; want 3, nil", int64(got), err)
	}
}

func TestValid(t *testing.T) {
	if err := MicroUSD(-1).Valid(); !errors.Is(err, ErrNegative) {
		t.Fatalf("Valid(-1) = %v, want ErrNegative", err)
	}
	if err := MicroUSD(0).Valid(); err != nil {
		t.Fatalf("Valid(0) = %v, want nil", err)
	}
}
