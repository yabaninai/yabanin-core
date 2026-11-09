package guardhooks

import (
	"strings"
)

// digitsOnly strips every non-digit rune from raw and returns the digit string.
func digitsOnly(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c >= '0' && c <= '9' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// toInts converts a digit string to a slice of digit values (len == len(digits)).
func toInts(digits string) []int {
	out := make([]int, len(digits))
	for i := 0; i < len(digits); i++ {
		out[i] = int(digits[i]) - '0'
	}
	return out
}

// validateINN checks the Russian INN control-sum for 10- or 12-digit numbers.
// This mirrors the Federal Tax Service checksum:
//   - 10-digit (legal entity): check digit d10 = (Σ d_i·c_i mod 11) mod 10,
//     over the first 9 digits with coefficients [2,4,10,3,5,9,4,6,8].
//   - 12-digit (individual / ИП): two check digits. d11 over the first 10
//     digits with [2,4,10,3,5,9,4,6,8,7]; d12 over the first 11 digits with
//     [7,2,4,10,3,5,9,4,6,8,2]. Each is (Σ mod 11) mod 10.
//
// A random 10/12-digit run that is not a real INN is rejected.
func validateINN(digits string) bool {
	n := len(digits)
	if n != 10 && n != 12 {
		return false
	}
	check := func(base []int, coef []int) int {
		s := 0
		for i, d := range base {
			s += d * coef[i]
		}
		return (s % 11) % 10
	}
	d := make([]int, n)
	for i := 0; i < n; i++ {
		d[i] = int(digits[i]) - '0'
	}
	if n == 10 {
		// 10-digit: check digit over the first 9.
		return check(d[:9], []int{2, 4, 10, 3, 5, 9, 4, 6, 8}) == d[9]
	}
	// 12-digit: two check digits.
	if check(d[:10], []int{2, 4, 10, 3, 5, 9, 4, 6, 8, 7}) != d[10] {
		return false
	}
	return check(d[:11], []int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8, 2}) == d[11]
}

// validateSNILS checks the 11-digit SNILS checksum. Structure: 9 registration
// digits + 2 control digits. The 2-digit control number is
// (Σ d_i·i for i=1..9 over the first 9 digits) mod 100. The accepted form is
// "NNN-NNN-NNN NN"; digits are extracted first.
func validateSNILS(raw string) bool {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, raw)
	if len(digits) != 11 {
		return false
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += (int(digits[i]) - '0') * (i + 1)
	}
	check := sum % 100 // 2-digit control number
	lastTwo := (int(digits[9])-'0')*10 + (int(digits[10]) - '0')
	return check == lastTwo
}

// validatePAN strips separators and checks the Luhn algorithm over 13–19
// digits. Returns the digit string (for redaction range) and whether it is a
// valid card number.
func validatePAN(raw string) (string, bool) {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, raw)
	if len(digits) < 13 || len(digits) > 19 {
		return digits, false
	}
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i]) - '0'
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return digits, sum%10 == 0
}

// detectCategories runs the offline detectors over the egress text and returns
// the set of categories present. INN/SNILS/PAN are checksum-validated so a
// random digit run is not a false positive; secrets and injection are plain
// regex matches.
func detectCategories(text string) map[Category]bool {
	hits := make(map[Category]bool)
	if injectionRe.MatchString(text) {
		hits[CatInjection] = true
	}
	if secretRe.MatchString(text) || pemRe.MatchString(text) {
		hits[CatSecret] = true
	}
	for _, m := range snilsRe.FindAllString(text, -1) {
		if validateSNILS(m) {
			hits[CatINNSNILS] = true
			break
		}
	}
	for _, m := range innRe.FindAllString(text, -1) {
		if validateINN(m) {
			hits[CatINNSNILS] = true
			break
		}
	}
	for _, m := range panRe.FindAllString(text, -1) {
		if _, ok := validatePAN(m); ok {
			hits[CatPAN] = true
			break
		}
	}
	// I18N-13 national PII. The 10/12-digit national detectors (Iqama, Aadhaar)
	// require a separator in their canonical grouped form, which disambiguates
	// them from the ungrouped 10/12-digit Russian INN namespace — so no
	// candidate-exclusion bookkeeping is needed here.
	for _, m := range cpfRe.FindAllString(text, -1) {
		if validateCPF(m) {
			hits[CatBR] = true
			break
		}
	}
	for _, m := range cnpjRe.FindAllString(text, -1) {
		if validateCNPJ(m) {
			hits[CatBR] = true
			break
		}
	}
	for _, m := range aadhaarRe.FindAllString(text, -1) {
		if validateAadhaar(m) {
			hits[CatIN] = true
			break
		}
	}
	for _, m := range panINRe.FindAllString(text, -1) {
		if _, ok := validatePANIN(m); ok {
			hits[CatIN] = true
			break
		}
	}
	for _, m := range mykadRe.FindAllString(text, -1) {
		if validateMyKad(m) {
			hits[CatMY] = true
			break
		}
	}
	for _, m := range iqamaRe.FindAllString(text, -1) {
		if validateIqama(m) {
			hits[CatAE] = true
			break
		}
	}
	for _, m := range zaNINRe.FindAllString(text, -1) {
		if validateZANIN(m) {
			hits[CatZA] = true
			break
		}
	}
	for _, m := range ngNINRe.FindAllString(text, -1) {
		if validateNGNIN(m) {
			hits[CatNG] = true
			break
		}
	}
	for _, m := range keNINRe.FindAllString(text, -1) {
		if validateKENIN(m) {
			hits[CatKE] = true
			break
		}
	}
	for _, m := range egNINRe.FindAllString(text, -1) {
		if validateEGNIN(m) {
			hits[CatEG] = true
			break
		}
	}
	return hits
}

// --- I18N-13 national PII validators -----------------------------------------

// validateCPF checks a Brazilian CPF (11 digits, two check digits). A run of
// 11 identical digits is invalid by law. Weights for the 1st check are 10..2
// over the first 9 digits; for the 2nd, 11..2 over the first 10. A remainder of
// 0 or 1 yields check digit 0; otherwise the check digit is 11 - remainder.
func validateCPF(raw string) bool {
	d := digitsOnly(raw)
	if len(d) != 11 {
		return false
	}
	uniq := map[byte]bool{}
	for i := 0; i < 11; i++ {
		uniq[d[i]] = true
	}
	if len(uniq) == 1 {
		return false // all-identical is not a real CPF
	}
	check := func(seq []int) int {
		s := 0
		for i, v := range seq {
			s += v * (len(seq) + 1 - i)
		}
		r := s % 11
		if r < 2 {
			return 0
		}
		return 11 - r
	}
	digs := toInts(d)
	return check(digs[:9]) == digs[9] && check(digs[:10]) == digs[10]
}

// validateCNPJ checks a Brazilian CNPJ (14 digits, two check digits). Weights
// for the 1st check over the first 12 are 5,4,3,2,9,8,7,6,5,4,3,2; for the 2nd
// over the first 13 they are 6,5,4,3,2,9,8,7,6,5,4,3,2. Remainder 0 or 1 → 0,
// else 11 - remainder.
func validateCNPJ(raw string) bool {
	d := digitsOnly(raw)
	if len(d) != 14 {
		return false
	}
	digs := toInts(d)
	check := func(seq []int, w []int) int {
		s := 0
		for i, v := range seq {
			s += v * w[i]
		}
		r := s % 11
		if r < 2 {
			return 0
		}
		return 11 - r
	}
	return check(digs[:12], []int{5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}) == digs[12] &&
		check(digs[:13], []int{6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}) == digs[13]
}

// validateAadhaar checks an Indian Aadhaar (12 digits). Structural rules only:
// exactly 12 digits, leading digit non-zero, and not a trivial run. To avoid
// colliding with the more specific Russian INN detector (12 digits,
// checksum-validated), a 12-digit run that is a valid INN is not an Aadhaar.
func validateAadhaar(raw string) bool {
	// Aadhaar requires the grouped 4-4-4 form with separators, which
	// disambiguates it from the ungrouped 12-digit Russian INN namespace.
	if !strings.ContainsAny(raw, " -") {
		return false
	}
	d := digitsOnly(raw)
	if len(d) != 12 || d[0] == '0' {
		return false
	}
	if trivialRun(d) {
		return false
	}
	// A checksum-valid Russian INN (12 digits) is not an Aadhaar.
	if validateINN(d) {
		return false
	}
	// Reject date-shaped prefixes (YYYYMM plausible) — e.g. "2024-1111-2223" is
	// a date-ish run, not an Aadhaar.
	return !plausibleYearMonth(d)
}

// validatePANIN checks an Indian PAN (5 letters + 4 digits + 1 letter, e.g.
// ABCDE1234F) using the Luhn algorithm over the 10 character values (A=10..Z=35).
func validatePANIN(raw string) (string, bool) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	if len(s) != 10 {
		return raw, false
	}
	for i := 0; i < 5; i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return raw, false
		}
	}
	for i := 5; i < 9; i++ {
		if s[i] < '0' || s[i] > '9' {
			return raw, false
		}
	}
	if s[9] < 'A' || s[9] > 'Z' {
		return raw, false
	}
	vals := make([]int, 10)
	for i := 0; i < 10; i++ {
		if s[i] >= 'A' {
			vals[i] = int(s[i]) - 55 // A=10..Z=35
		} else {
			vals[i] = int(s[i]) - '0'
		}
	}
	// Luhn over the 10 character values, doubling every 2nd from the right (the
	// 5th, 3rd, 1st positions from the end) — same scheme as validatePAN.
	sum := 0
	for i := 9; i >= 0; i-- {
		v := vals[i]
		if (9-i)%2 == 1 {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
	}
	return raw, sum%10 == 0
}

// validateMyKad checks a Malaysian MyKad / IC number in the canonical
// hyphen-separated "NNNNN-NNNNNNN-N" form (5-7-1). The hyphens are required so
// a plain 13-digit run is not a MyKad candidate. Format-only: the IC checksum
// is not publicly specified in a way that distinguishes real from random, so a
// well-formed 5-7-1 run is accepted.
func validateMyKad(raw string) bool {
	d := digitsOnly(raw)
	if len(d) != 13 {
		return false
	}
	return strings.Count(raw, "-") == 2
}

// validateIqama checks a Saudi Iqama / resident ID in the grouped "NNNN-NNNNNN"
// form (10 digits, leading non-zero, with the hyphen separator). The separator
// keeps it out of the 10-digit Russian INN namespace. It rejects trivially
// structured digit runs (placeholders).
func validateIqama(raw string) bool {
	if !strings.Contains(raw, "-") {
		return false
	}
	d := digitsOnly(raw)
	if len(d) != 10 || d[0] == '0' {
		return false
	}
	if trivialRun(d) {
		return false
	}
	// Reject date-shaped prefixes (YYYYMM plausible) — e.g. "2024-112233" is a
	// date-ish lot number, not an Iqama.
	return !plausibleYearMonth(d)
}

// validateKENIN checks a Kenyan national ID / NIN (8 digits, first digit
// non-zero), rejecting trivially structured runs and date-shaped runs
// (YYYYMMDD with a plausible date), which are the shape of timestamps, not IDs.
func validateKENIN(raw string) bool {
	d := digitsOnly(raw)
	if len(d) != 8 || d[0] == '0' {
		return false
	}
	if trivialRun(d) {
		return false
	}
	if looksLikeDate(d) {
		return false
	}
	return true
}

// plausibleYearMonth reports whether the first six digits of a digit run form a
// plausible YYYYMM date (year 1900-2099, month 01-12). Used to reject
// date-shaped runs that are not national IDs.
func plausibleYearMonth(d string) bool {
	if len(d) < 6 {
		return false
	}
	year := int(d[0]-'0')*1000 + int(d[1]-'0')*100 + int(d[2]-'0')*10 + int(d[3]-'0')
	month := int(d[4]-'0')*10 + int(d[5]-'0')
	return year >= 1900 && year <= 2099 && month >= 1 && month <= 12
}

// looksLikeDate reports whether an 8-digit run is a plausible YYYYMMDD date
// (year 1900-2099, month 01-12, day 01-31). Such runs are timestamps, not
// national IDs.
func looksLikeDate(d string) bool {
	if len(d) != 8 {
		return false
	}
	year := int(d[0]-'0')*1000 + int(d[1]-'0')*100 + int(d[2]-'0')*10 + int(d[3]-'0')
	month := int(d[4]-'0')*10 + int(d[5]-'0')
	day := int(d[6]-'0')*10 + int(d[7]-'0')
	return year >= 1900 && year <= 2099 && month >= 1 && month <= 12 && day >= 1 && day <= 31
}

// trivialRun reports whether a digit string is a placeholder-shaped run: a
// single repeated digit, a repeating 2-digit block, or a strictly monotonic
// (ascending/descending) sequence. These shapes are characteristic of test
// numbers, not real identity documents, and are rejected by the checksum-free
// national detectors (Iqama, Kenyan NIN) to keep precision high.
func trivialRun(d string) bool {
	if len(d) == 0 {
		return false
	}
	// single repeated digit
	single := true
	for i := 1; i < len(d); i++ {
		if d[i] != d[0] {
			single = false
			break
		}
	}
	if single {
		return true
	}
	// repeating 2-digit block
	if len(d)%2 == 0 {
		block := d[:2]
		repeat := true
		for i := 2; i < len(d); i += 2 {
			if d[i] != block[0] || d[i+1] != block[1] {
				repeat = false
				break
			}
		}
		if repeat {
			return true
		}
	}
	// consecutive-by-1 sequence (possibly wrapping 9→0), e.g. 1234567890 or
	// 90123. Placeholder-shaped; rejected.
	if isConsecutiveMod10(d) {
		return true
	}
	// three leading pairs (d0==d1, d2==d3, d4==d5), e.g. "11112223" or
	// "99001122". Placeholder-shaped; rejected.
	if len(d) >= 6 && d[0] == d[1] && d[2] == d[3] && d[4] == d[5] {
		return true
	}
	return false
}

// isConsecutiveMod10 reports whether the digit string is a run of consecutive
// digit values (step +1, wrapping 9→0) in order — the shape of placeholder
// numbers like "1234567890" or "789012".
func isConsecutiveMod10(d string) bool {
	n := len(d)
	if n < 3 {
		return false
	}
	for start := 0; start < 10; start++ {
		ok := true
		for i := 0; i < n; i++ {
			want := (start + i) % 10
			if int(d[i]-'0') != want {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// validateZANIN checks a South African ID / NIN (13 digits: YYMMDD date +
// sequence + a 1-digit citizenship flag 0/1 at position 10 + a Luhn check digit
// at the end). The date part must be a plausible calendar date, the citizenship
// flag must be 0 or 1, and the final digit must satisfy Luhn over all 13.
func validateZANIN(raw string) bool {
	d := digitsOnly(raw)
	if len(d) != 13 {
		return false
	}
	digs := toInts(d)
	month := digs[2]*10 + digs[3]
	day := digs[4]*10 + digs[5]
	if month < 1 || month > 12 || day < 1 || day > 31 {
		return false
	}
	if digs[9] != 0 && digs[9] != 1 {
		return false // citizenship flag must be 0 or 1
	}
	return luhnDigits(digs)
}

// validateNGNIN checks a Nigerian NIN (11 digits, Luhn-valid).
func validateNGNIN(raw string) bool {
	d := digitsOnly(raw)
	if len(d) != 11 {
		return false
	}
	return luhnDigits(toInts(d))
}

// validateEGNIN checks an Egyptian national ID (14 digits, leading non-zero,
// not a trivial run). It also rejects runs whose first six digits form a
// plausible YYYYMM date (year 1900-2099, month 01-12), because such 14-digit
// numbers are far more often ISO timestamps than Egyptian IDs.
func validateEGNIN(raw string) bool {
	d := digitsOnly(raw)
	if len(d) != 14 || d[0] == '0' {
		return false
	}
	if trivialRun(d) {
		return false
	}
	// Reject date-shaped prefixes (YYYYMM with a plausible year/month).
	year := int(d[0]-'0')*1000 + int(d[1]-'0')*100 + int(d[2]-'0')*10 + int(d[3]-'0')
	month := int(d[4]-'0')*10 + int(d[5]-'0')
	if year >= 1900 && year <= 2099 && month >= 1 && month <= 12 {
		return false
	}
	return true
}

// luhnDigits runs the Luhn algorithm over a digit value slice (most-significant
// first) and reports whether the sum is a multiple of 10.
func luhnDigits(digs []int) bool {
	sum := 0
	for i := len(digs) - 1; i >= 0; i-- {
		v := digs[i]
		if (len(digs)-1-i)%2 == 1 {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
	}
	return sum%10 == 0
}
