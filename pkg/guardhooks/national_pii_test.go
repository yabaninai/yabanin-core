package guardhooks

import "testing"

// I18N-13: national PII detector tests. Each country has checksum-validated
// positives, checksum-broken negatives, and a detectCategories-level check that
// a well-formed number of the *right length for another country* is not
// misclassified (the no-collision property the eval corpus gates on).

func TestValidateCPF(t *testing.T) {
	valid := []string{
		"12345678909", "11144477735", "52998224725", "98765432100",
		"123.456.789-09", // grouped form
	}
	for _, v := range valid {
		if !validateCPF(v) {
			t.Errorf("validateCPF(%q) = false, want true", v)
		}
	}
	invalid := []string{
		"12345678901",  // check digit wrong
		"11111111111",  // all identical — illegal
		"123456789",    // 9 digits
		"123456789012", // 12 digits
		"123456789ab",  // non-digits
	}
	for _, v := range invalid {
		if validateCPF(v) {
			t.Errorf("validateCPF(%q) = true, want false", v)
		}
	}
}

func TestValidateCNPJ(t *testing.T) {
	// Build a guaranteed-valid CNPJ from a known base using the same weights the
	// validator uses, to avoid trusting a hand-typed constant.
	base := "112223330001" // 12 digits
	d1 := cnpjCheck(base, []int{5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2})
	d2 := cnpjCheck(base+digitStr(d1), []int{6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2})
	full := base + digitStr(d1) + digitStr(d2) // 14 digits
	if len(full) != 14 {
		t.Fatalf("constructed CNPJ length = %d, want 14 (%q)", len(full), full)
	}
	if !validateCNPJ(full) {
		t.Fatalf("validateCNPJ(%q) = false, want true (constructed valid)", full)
	}
	// Negative: corrupt the last digit.
	bad := full[:13] + string(flipDigit(full[13]))
	if validateCNPJ(bad) {
		t.Errorf("validateCNPJ(%q) = true, want false (corrupted)", bad)
	}
	if validateCNPJ("12345678") {
		t.Error("validateCNPJ(8 digits) = true, want false")
	}
}

// digitStr formats a single digit value (0-9) as a one-character string via a
// lookup (no int→rune/byte conversion, which gosec G115 flags).
func digitStr(d int) string {
	return "0123456789"[d : d+1]
}

func cnpjCheck(digits string, w []int) int {
	s := 0
	for i := 0; i < len(digits); i++ {
		s += (int(digits[i]) - '0') * w[i]
	}
	r := s % 11
	if r < 2 {
		return 0
	}
	return 11 - r
}

func flipDigit(c byte) byte {
	if c == '9' {
		return '0'
	}
	return c + 1
}

func TestValidateAadhaar(t *testing.T) {
	valid := []string{
		"8877-8932-8792", "2742-1809-6792", "1810-0339-0757",
		"4834-7017-4681", "1284-5673-9102", // grouped 4-4-4, non-trivial
	}
	for _, v := range valid {
		if !validateAadhaar(v) {
			t.Errorf("validateAadhaar(%q) = false, want true", v)
		}
	}
	invalid := []string{
		"0877-8932-8792", // leading zero
		"1111-1111-1111", // repeated run
		"12345678901",    // 11 digits, ungrouped
		"887789328792",   // 12 digits, ungrouped (no separators — not Aadhaar form)
		"2024-1111-2223", // date-shaped prefix
	}
	for _, v := range invalid {
		if validateAadhaar(v) {
			t.Errorf("validateAadhaar(%q) = true, want false", v)
		}
	}
}

func TestValidatePANIN(t *testing.T) {
	valid := []string{"UDAXI3321C", "VXRCS6001C", "GHQTA8386C", "HOSIZ0265E", "IEGYK1161A"}
	for _, v := range valid {
		if _, ok := validatePANIN(v); !ok {
			t.Errorf("validatePANIN(%q) = false, want true", v)
		}
	}
	invalid := []string{
		"UDAXI3321X",  // last char changed → Luhn broken
		"1234567890A", // letters where digits expected
		"ABC1234FG",   // 9 chars
		"ABCDE1234FG", // 11 chars
	}
	for _, v := range invalid {
		if _, ok := validatePANIN(v); ok {
			t.Errorf("validatePANIN(%q) = true, want false", v)
		}
	}
}

func TestValidateMyKad(t *testing.T) {
	if !validateMyKad("12345-6789012-5") {
		t.Error("validateMyKad(12345-6789012-5) = false, want true")
	}
	if validateMyKad("1234-6789012-5") {
		t.Error("validateMyKad(1234-6789012-5) = true, want false (wrong first group)")
	}
	if validateMyKad("1234567890123") {
		t.Error("validateMyKad(unseparated 13 digits) = true, want false (needs 5-7-1 form)")
	}
}

func TestValidateIqama(t *testing.T) {
	// Grouped "NNNN-NNNNNN" form (10 digits, non-trivial).
	if !validateIqama("1284-567391") {
		t.Error("validateIqama(1284-567391) = false, want true")
	}
	if validateIqama("1234-567890") {
		t.Error("validateIqama(monotonic 1234-567890) = true, want false")
	}
	if validateIqama("0284-567391") {
		t.Error("validateIqama(leading zero) = true, want false")
	}
	if validateIqama("1111-111111") {
		t.Error("validateIqama(repeated) = true, want false")
	}
	if validateIqama("1284567391") {
		t.Error("validateIqama(ungrouped 10 digits) = true, want false (needs 4-6 form)")
	}
}

func TestValidateZANIN(t *testing.T) {
	// 13-digit South African IDs (date + citizenship flag at position 10 + Luhn).
	valid := []string{
		"8001015000771", "9912311231770", "0102034560775", "7501017891771",
	}
	for _, v := range valid {
		if !validateZANIN(v) {
			t.Errorf("validateZANIN(%q) = false, want true", v)
		}
	}
	invalid := []string{
		"8013015000771", // month 13
		"8001325000771", // day 32
		"8001015009771", // citizenship flag 9 (must be 0/1)
		"800101500077",  // 12 digits
	}
	for _, v := range invalid {
		if validateZANIN(v) {
			t.Errorf("validateZANIN(%q) = true, want false", v)
		}
	}
}

func TestValidateNGNIN(t *testing.T) {
	valid := []string{"01234567897", "12345678903", "98765432103", "11122233346"}
	for _, v := range valid {
		if !validateNGNIN(v) {
			t.Errorf("validateNGNIN(%q) = false, want true", v)
		}
	}
	invalid := []string{
		"01234567898",  // Luhn broken
		"1234567890",   // 10 digits
		"123456789012", // 12 digits
	}
	for _, v := range invalid {
		if validateNGNIN(v) {
			t.Errorf("validateNGNIN(%q) = true, want false", v)
		}
	}
}

func TestValidateKENIN(t *testing.T) {
	// Non-monotonic 8-digit run (a placeholder like 12345678 is rejected).
	if !validateKENIN("12845673") {
		t.Error("validateKENIN(12845673) = false, want true")
	}
	if validateKENIN("12345678") {
		t.Error("validateKENIN(monotonic 12345678) = true, want false")
	}
	if validateKENIN("02845673") {
		t.Error("validateKENIN(leading zero) = true, want false")
	}
	if validateKENIN("1284567") {
		t.Error("validateKENIN(7 digits) = true, want false")
	}
}

func TestValidateEGNIN(t *testing.T) {
	// Non-trivial, non-date-shaped 14-digit run.
	if !validateEGNIN("28451739610284") {
		t.Error("validateEGNIN(28451739610284) = false, want true")
	}
	if validateEGNIN("02345678901234") {
		t.Error("validateEGNIN(leading zero) = true, want false")
	}
	if validateEGNIN("11111111111111") {
		t.Error("validateEGNIN(repeated) = true, want false")
	}
	// Date-shaped prefix (YYYYMM plausible) is rejected as a timestamp.
	if validateEGNIN("20240315143000") {
		t.Error("validateEGNIN(timestamp 20240315143000) = true, want false")
	}
}

// TestDetectNational_NoCrossCountryCollision ensures a well-formed number is
// attributed to exactly its own country's category and not to another country's
// detector (length/shape discrimination). This is the property the eval corpus
// gates on with >=30 decoys per country.
func TestDetectNational_NoCrossCountryCollision(t *testing.T) {
	cases := []struct {
		text string
		want Category
	}{
		{"cpf 12345678909 on file", CatBR},
		{"aadhaar 8877-8932-8792 attached", CatIN},
		{"pan UDAXI3321C for tax", CatIN},
		{"mykad 12345-6789012-5", CatMY},
		{"iqama 1284-567391", CatAE},
		{"sa id 8001015000771", CatZA},
		{"nin 01234567897", CatNG},
		{"kenya id 12845673", CatKE},
		{"egypt id 28451739610284", CatEG},
	}
	for _, c := range cases {
		hits := detectCategories(c.text)
		if !hits[c.want] {
			t.Errorf("detectCategories(%q) missing %s; got %v", c.text, c.want, hits)
		}
		// The expected category must be the *only* national-PII category hit, so a
		// number is not double-attributed to the wrong country.
		for _, other := range []Category{CatBR, CatIN, CatMY, CatAE, CatZA, CatNG, CatKE, CatEG} {
			if other != c.want && hits[other] {
				t.Errorf("detectCategories(%q) also hit %s (cross-country collision); got %v", c.text, other, hits)
			}
		}
	}
}

// TestDetectNational_DecoyNotFlagged ensures checksum-broken / wrong-length
// runs of each country's shape are not flagged (precision guard).
func TestDetectNational_DecoyNotFlagged(t *testing.T) {
	decoys := []string{
		"12345678901",      // CPF checksum broken (11 digits)
		"112223330900021",  // 13 digits, not a valid CNPJ (14) or ZA
		"12345678901",      // 11 digits (NG length, Luhn broken)
		"123456789012345",  // 15 digits
		"08778932879",      // Aadhaar leading zero
		"111111111111",     // repeated (12)
		"8013015000771",    // ZA bad month (13)
		"012345678",        // 9 digits
		"02345678",         // KE leading zero
		"1234567890123",    // 13 digits, bad ZA
		"111222333",        // 9 digits
		"1234567890123456", // 16 digits
	}
	for _, d := range decoys {
		hits := detectCategories("value " + d + " end")
		for _, c := range []Category{CatBR, CatIN, CatMY, CatAE, CatZA, CatNG, CatKE, CatEG} {
			if hits[c] {
				t.Errorf("decoy %q flagged as %s; got %v", d, c, hits)
			}
		}
	}
}

// TestRedact_NationalPII ensures redact mode replaces validated national PII and
// leaves innocent runs untouched.
func TestRedact_NationalPII(t *testing.T) {
	h := New(ModeRedact)
	in := "cpf 12345678909 and pan UDAXI3321C and mykad 12345-6789012-5"
	out := h.Redact(in)
	if containsAny(out, "12345678909", "UDAXI3321C", "12345-6789012-5") {
		t.Errorf("national PII not redacted: %s", out)
	}
	for _, tok := range []string{"[REDACTED_BR]", "[REDACTED_IN]", "[REDACTED_MY]"} {
		if !containsAny(out, tok) {
			t.Errorf("missing redaction token %s in %s", tok, out)
		}
	}
	// Innocent run of the right shape but wrong checksum must survive.
	in2 := "order 12345678901 ref"
	if out2 := h.Redact(in2); out2 != in2 {
		t.Errorf("innocent run was rewritten: %s", out2)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && indexOf(s, sub) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
