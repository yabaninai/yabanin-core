package money

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"testing"
)

// TestParseUSD_ExactConversion pins exact decimal-to-micro conversion for
// canonical carriers, including short fractions that need zero-padding to
// the micro scale and the Split recombination invariant.
func TestParseUSD_ExactConversion(t *testing.T) {
	cases := []struct {
		in   string
		want MicroUSD
	}{
		{"0", 0},
		{"0000", 0},
		{"4", 4_000_000},
		{"12.34", 12_340_000},
		{"0.004", 4_000},
		{"0.0075", 7_500},
		{"0.1", 100_000},
		{".5", 500_000},
		{"5.", 5_000_000},
		{"007", 7_000_000},
		{"0.000000", 0},
		{"0.000001", 1},
		{"99.999999", 99_999_999},
	}
	for _, tc := range cases {
		got, err := ParseUSD(tc.in)
		if err != nil {
			t.Errorf("ParseUSD(%q) = err %v, want %d", tc.in, err, tc.want)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseUSD(%q) = %d, want %d", tc.in, got, tc.want)
		}
		// Exact values must satisfy the package invariants.
		if err := got.Valid(); err != nil {
			t.Errorf("ParseUSD(%q) = %d fails Valid: %v", tc.in, got, err)
		}
		cents, rem := got.Split()
		if MicroUSD(cents*int64(MicroPerCent))+rem != got {
			t.Errorf("ParseUSD(%q) Split recombination broken: %d + %d != %d", tc.in, cents, rem, got)
		}
	}
}

// TestParseUSD_DecimalIntent pins the class ParseUSD exists for: exact-half
// decimals whose float64 carrier double-rounds through FromUSD. The FromUSD
// values asserted here are verified float-path residues on this tree — they
// document the divergence, they are not regressions.
func TestParseUSD_DecimalIntent(t *testing.T) {
	cases := []struct {
		in     string
		want   MicroUSD
		floatF float64
	}{
		// 124.5 µUSD exact half: decimal intent 125, float carrier 124.
		{"0.0001245", 125, 0.0001245},
		// 244.5 µUSD exact half: decimal intent 245, float carrier 244.
		{"0.0002445", 245, 0.0002445},
		// Exact half at the 0.5 µUSD scale: both paths agree on 1.
		{"0.0000005", 1, 0.0000005},
		{"0.0000004", 0, 0.0000004},
		// Sticky remainder: just above/below the half.
		{"0.000000500001", 1, 0.000000500001},
		{"0.000000499999", 0, 0.000000499999},
		{"0.000000500000000001", 1, 0.000000500000000001},
		{"0.000000499999999999", 0, 0.000000499999999999},
		{"0.123456789", 123457, 0.123456789},
	}
	for _, tc := range cases {
		got, err := ParseUSD(tc.in)
		if err != nil {
			t.Errorf("ParseUSD(%q) = err %v, want %d", tc.in, err, tc.want)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseUSD(%q) = %d, want %d", tc.in, got, tc.want)
		}
		// Same text through the float64 carrier (shortest representation
		// round trip): the pins above state which side each literal lands on.
		floatGot, ferr := FromUSD(tc.floatF)
		if ferr != nil {
			t.Errorf("FromUSD(%v) unexpected err %v", tc.floatF, ferr)
			continue
		}
		if strconv.FormatFloat(tc.floatF, 'f', -1, 64) != tc.in {
			// The float carrier's shortest text differs from the tested
			// literal; the decimal-intent pin still applies to the text.
			t.Logf("note: FormatFloat(%v) = %q differs from literal %q", tc.floatF, strconv.FormatFloat(tc.floatF, 'f', -1, 64), tc.in)
		}
		t.Logf("ParseUSD(%q)=%d vs float-carrier FromUSD(%v)=%d", tc.in, got, tc.floatF, floatGot)
	}
	if got, _ := FromUSD(0.0001245); got != 124 {
		t.Errorf("float-carrier residue pin changed: FromUSD(0.0001245) = %d, want 124 (UpdateUse docs if intentional)", got)
	}
	if got, _ := FromUSD(0.0002445); got != 244 {
		t.Errorf("float-carrier residue pin changed: FromUSD(0.0002445) = %d, want 244", got)
	}
}

// TestParseUSD_Rejects pins the error taxonomy: every error is "unknown
// price" for callers, but the sentinel must classify the cause.
func TestParseUSD_Rejects(t *testing.T) {
	syntax := []string{
		"", ".", " 1", "1 ", "1_0", "1,5", "1e3", "1E3", "+1", "0x10",
		"nan", "inf", "$4", "1.2.3", "abc", "4  µUSD", "１",
	}
	for _, s := range syntax {
		got, err := ParseUSD(s)
		if !errors.Is(err, ErrSyntax) {
			t.Errorf("ParseUSD(%q) err = %v, want ErrSyntax (got %d)", s, err, got)
		}
	}
	negatives := []string{"-1", "-0", "-0.004", "-.5", "-inf"}
	for _, s := range negatives {
		got, err := ParseUSD(s)
		if !errors.Is(err, ErrNegative) {
			t.Errorf("ParseUSD(%q) err = %v, want ErrNegative (got %d)", s, err, got)
		}
	}
}

// TestParseUSD_RangeBounds pins the exact decimal capacity edge. The
// decimal "9223372036854.775807" IS MaxInt64 µUSD (valid); one more digit
// unit of any kind crosses 2^63 and must be rejected, including via a
// half-up rounding of "…7758075".
func TestParseUSD_RangeBounds(t *testing.T) {
	boundary := "9223372036854.775807"
	got, err := ParseUSD(boundary)
	if err != nil || got != MicroUSD(math.MaxInt64) {
		t.Errorf("ParseUSD(%q) = %d, %v; want MaxInt64 µUSD, nil", boundary, got, err)
	}
	below := "9223372036854.7758074" // rounds down onto MaxInt64
	got, err = ParseUSD(below)
	if err != nil || got != MicroUSD(math.MaxInt64) {
		t.Errorf("ParseUSD(%q) = %d, %v; want MaxInt64 µUSD, nil", below, got, err)
	}
	for _, s := range []string{
		"9223372036854.7758075", // half rounds up onto 2^63
		"9223372036854.775808",
		"9223372036855",
		"99999999999999999999",
		"123456789012345678901234567890",
	} {
		got, err := ParseUSD(s)
		if !errors.Is(err, ErrRange) {
			t.Errorf("ParseUSD(%q) err = %v, want ErrRange (got %d)", s, err, got)
		}
	}
	// The float-grid boundary artifact stays intact: FromUSD at the MaxUSD
	// float equals both the decimal boundary string and MaxInt64 exactly.
	if f := FromUSDMust(t, MaxUSD); f != MicroUSD(math.MaxInt64) {
		t.Errorf("FromUSD(MaxUSD) = %d, want MaxInt64 (fx2 pin)", f)
	}
}

// TestParseUSD_SystematicSeventhDigit sweeps every 7-digit micro fraction
// 0.0000001..0.02: ParseUSD must equal round-half-up at the micro scale
// for every n, covering all seventh-digit classes deterministically.
func TestParseUSD_SystematicSeventhDigit(t *testing.T) {
	const n = 200_000
	for i := 1; i <= n; i++ {
		s := fmt.Sprintf("0.%07d", i)
		got, err := ParseUSD(s)
		if err != nil {
			t.Fatalf("ParseUSD(%q) unexpected err %v", s, err)
		}
		want := MicroUSD((i + 5) / 10) // i/10 µUSD, half away from zero
		if got != want {
			t.Fatalf("ParseUSD(%q) = %d, want %d", s, got, want)
		}
	}
}

// TestParseUSD_AgreementWithFloatCarrier pins the compatibility contract:
// for floats whose shortest decimal text round-trips through both paths,
// ParseUSD(FormatFloat(f)) == FromUSD(f).
func TestParseUSD_AgreementWithFloatCarrier(t *testing.T) {
	for _, f := range []float64{
		0.004, 0.0075, 0.1, 1e-6, 0.25, 1, 4, 12.34, 99.999999,
		1234.5678, 0.000001, 0.0001234,
	} {
		s := strconv.FormatFloat(f, 'f', -1, 64)
		got, err := ParseUSD(s)
		if err != nil {
			t.Fatalf("ParseUSD(%q) unexpected err %v", s, err)
		}
		want, ferr := FromUSD(f)
		if ferr != nil {
			t.Fatalf("FromUSD(%v) unexpected err %v", f, ferr)
		}
		if got != want {
			t.Errorf("ParseUSD(%q) = %d != FromUSD(%v) = %d", s, got, f, want)
		}
	}
}

// FromUSDMust is a test-local helper (fromUSD for constant pins).
func FromUSDMust(t *testing.T, usd float64) MicroUSD {
	t.Helper()
	m, err := FromUSD(usd)
	if err != nil {
		t.Fatalf("FromUSD(%v): %v", usd, err)
	}
	return m
}
