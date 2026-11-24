package dimensions

// Exact-decimal tests: canonical acceptance, syntax and limit rejection at
// the boundaries, ordering, addition and JSON round-trips.

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestParseDecimal_CanonicalAccepts(t *testing.T) {
	tests := []struct{ input, want string }{
		{"3", "3"},
		{"0.02", "0.02"},
		{".5", "0.5"},
		{"5.", "5"},
		{"0.0200", "0.02"},
		{"3.0", "3"},
		{"0", "0"},
		{"00.10", "0.1"},
		{"123.450", "123.45"},
		{"0.05", "0.05"},
	}
	for _, tc := range tests {
		got, err := ParseDecimal(tc.input)
		if err != nil {
			t.Errorf("ParseDecimal(%q): %v", tc.input, err)
			continue
		}
		if got.String() != tc.want {
			t.Errorf("ParseDecimal(%q) = %s, want %s", tc.input, got, tc.want)
		}
	}
}

func TestParseDecimal_SyntaxRejects(t *testing.T) {
	inputs := []string{
		"-0.02", "+1", "0x10", "NaN", "Infinity", "1e3", "1E3", "", ".",
		"1.2.3", " 1", "1 ", "1,000", "1_000", "０.１", "0.0 2", "--", "\t0.5",
	}
	for _, in := range inputs {
		if _, err := ParseDecimal(in); !errors.Is(err, ErrSyntax) {
			t.Errorf("ParseDecimal(%q) err = %v, want ErrSyntax", in, err)
		}
	}
}

// boundary128 is a valid 128-byte input: 107 leading zeros, "12", then 18
// fractional digits (20 significant).
func boundary128() string {
	return strings.Repeat("0", 107) + "12." + "123456789012345678"
}

func TestParseDecimal_128ByteBoundaryAccepts(t *testing.T) {
	in := boundary128()
	if len(in) != maxInputBytes {
		t.Fatalf("boundary input length = %d, want %d", len(in), maxInputBytes)
	}
	got, err := ParseDecimal(in)
	if err != nil {
		t.Fatalf("ParseDecimal(128-byte input): %v", err)
	}
	if want := "12.123456789012345678"; got.String() != want {
		t.Errorf("128-byte input = %s, want %s", got, want)
	}
}

func TestParseDecimal_LimitRejects(t *testing.T) {
	tests := []struct {
		name, input, wantMsg string
	}{
		{"39 significant digits", strings.Repeat("9", 39), "more than 38 significant digits"},
		{"19 fractional digits", "0." + strings.Repeat("1", 19), "more than 18 fractional digits"},
		{"trailing zeros do not buy back fraction budget", "0." + strings.Repeat("1", 18) + "0", "more than 18 fractional digits"},
		{"129 bytes", "0" + boundary128(), "exceeds 128 bytes"},
	}
	for _, tc := range tests {
		_, err := ParseDecimal(tc.input)
		if !errors.Is(err, ErrLimit) {
			t.Errorf("%s: err = %v, want ErrLimit", tc.name, err)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantMsg) {
			t.Errorf("%s: err = %v, want message containing %q", tc.name, err, tc.wantMsg)
		}
	}
}

func TestParseDecimal_StructEqualityOfCanonicalForms(t *testing.T) {
	a, err := ParseDecimal("0.02")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseDecimal("0.0200")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("canonical forms differ: %+v != %+v", a, b)
	}
	c, _ := ParseDecimal("0.2")
	if a == c {
		t.Error("0.02 == 0.2 should not hold")
	}
}

// The struct zero value and the parsed zero are the same zero by value
// (Equal/Compare), but not by representation: == proves representation
// identity only, so the never-set marker never silently equals a parsed 0.
func TestDecimal_ZeroValueEqualsParsedZero(t *testing.T) {
	zero, err := ParseDecimal("0")
	if err != nil {
		t.Fatal(err)
	}
	if !Equal(Decimal{}, zero) || Compare(Decimal{}, zero) != 0 {
		t.Error("struct zero value and parsed zero must be the same zero by value")
	}
	if (Decimal{}) == zero {
		t.Error("Decimal{} == ParseDecimal(`0`) must not hold; == is representation identity only")
	}
}

func TestDecimal_String(t *testing.T) {
	tests := []struct {
		d    Decimal
		want string
	}{
		{Decimal{}, "0"},
		{Decimal{digits: "0"}, "0"},
		{Decimal{digits: "5"}, "5"},
		{Decimal{digits: "5", scale: 2}, "0.05"},
		{Decimal{digits: "2", scale: 2}, "0.02"},
		{Decimal{digits: "12345", scale: 3}, "12.345"},
	}
	for _, tc := range tests {
		if got := tc.d.String(); got != tc.want {
			t.Errorf("%+v.String() = %s, want %s", tc.d, got, tc.want)
		}
	}
}

func TestIsZero(t *testing.T) {
	zero, err := ParseDecimal("0")
	if err != nil {
		t.Fatal(err)
	}
	zeroPadded, _ := ParseDecimal("0.00")
	q, _ := ParseDecimal("0.02")
	if !IsZero(Decimal{}) || !IsZero(zero) || !IsZero(zeroPadded) {
		t.Error("zero states must be zero")
	}
	if IsZero(q) {
		t.Error("0.02 must not be zero")
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"0", "0", 0},
		{"0.02", "0.0200", 0},
		{"0.4", "0.6", -1},
		{"0.6", "0.4", 1},
		{"0.02", "3", -1},
		{"9", "10", -1},
		{"10", "9", 1},
		{"0.1", "0.09", 1},
		{"0", "0.5", -1},
		{"0.5", "0", 1},
	}
	for _, tc := range tests {
		a, err := ParseDecimal(tc.a)
		if err != nil {
			t.Fatal(err)
		}
		b, err := ParseDecimal(tc.b)
		if err != nil {
			t.Fatal(err)
		}
		if got := Compare(a, b); got != tc.want {
			t.Errorf("Compare(%s, %s) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if wantEqual := tc.want == 0; Equal(a, b) != wantEqual {
			t.Errorf("Equal(%s, %s) = %v, want %v", tc.a, tc.b, !wantEqual, wantEqual)
		}
	}
}

func TestAdd(t *testing.T) {
	table := []struct{ a, b, want string }{
		{"0.02", "0.03", "0.05"},
		{"0.4", "0.6", "1"},
		{"0.99", "0.01", "1"},
		{"0", "0.02", "0.02"},
		{"0.02", "0", "0.02"},
		// float64 would render this sum 0.30000000000000004.
		{"0.1", "0.2", "0.3"},
		{"1", "2", "3"},
		{"0.05", "0.05", "0.1"},
	}
	for _, tc := range table {
		a, err := ParseDecimal(tc.a)
		if err != nil {
			t.Fatal(err)
		}
		b, err := ParseDecimal(tc.b)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Add(a, b)
		if err != nil {
			t.Errorf("Add(%s, %s): %v", tc.a, tc.b, err)
			continue
		}
		if got.String() != tc.want {
			t.Errorf("Add(%s, %s) = %s, want %s", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestAdd_StructZeroValueOperand(t *testing.T) {
	q, err := ParseDecimal("0.02")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Add(Decimal{}, q)
	if err != nil {
		t.Fatal(err)
	}
	if !Equal(got, q) {
		t.Errorf("zero-value + 0.02 = %s, want 0.02", got)
	}
}

func TestAdd_OverflowNeverRounds(t *testing.T) {
	nines := strings.Repeat("9", 38)
	a, err := ParseDecimal(nines)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseDecimal("1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Add(a, b)
	if !errors.Is(err, ErrOverflow) {
		t.Errorf("38 nines + 1 err = %v, want ErrOverflow", err)
	}
}

func TestDecimal_MarshalCanonicalString(t *testing.T) {
	tests := []struct{ input, want string }{
		{"0.0200", `"0.02"`},
		{"3.0", `"3"`},
		{"0", `"0"`},
	}
	for _, tc := range tests {
		d, err := ParseDecimal(tc.input)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(mustMarshal(t, d)); got != tc.want {
			t.Errorf("marshal(%s) = %s, want %s", tc.input, got, tc.want)
		}
	}
}

func TestDecimal_UnmarshalRejectsJSONNumber(t *testing.T) {
	inputs := []string{`0.02`, `2`, `-1`, `1e-2`, `0.1`}
	for _, in := range inputs {
		var d Decimal
		err := json.Unmarshal([]byte(in), &d)
		if !errors.Is(err, ErrJSONNumber) {
			t.Errorf("unmarshal(%s) err = %v, want ErrJSONNumber", in, err)
		}
	}
}

func TestDecimal_UnmarshalStringErrorsClassify(t *testing.T) {
	tests := []struct {
		input   string
		wantErr error
	}{
		{`"abc"`, ErrSyntax},
		{`"1.2.3"`, ErrSyntax},
		{`"` + strings.Repeat("9", 39) + `"`, ErrLimit},
		{`"0.02"`, nil},
	}
	for _, tc := range tests {
		var d Decimal
		err := json.Unmarshal([]byte(tc.input), &d)
		if !errors.Is(err, tc.wantErr) {
			t.Errorf("unmarshal(%s) err = %v, want %v", tc.input, err, tc.wantErr)
		}
	}
}

func TestDecimal_RoundTrip(t *testing.T) {
	for _, in := range []string{"0.02", "3", "0.4", "0.6", "0", "12.123456789012345678"} {
		d, err := ParseDecimal(in)
		if err != nil {
			t.Fatal(err)
		}
		var rt Decimal
		if err := json.Unmarshal(mustMarshal(t, d), &rt); err != nil {
			t.Fatalf("round-trip %s: %v", in, err)
		}
		if d != rt {
			t.Errorf("round-trip %s changed value to %s", in, rt)
		}
	}
}
