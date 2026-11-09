package guardhooks

import (
	"regexp"
	"strconv"
	"strings"
)

// Russian identifier detectors (RM-61). Checksum-confirmed INN and SNILS are
// confidence 1.0. A SNILS whose first nine digits are at most 001001998 is
// accepted on format alone at 0.9. Any other format-only INN or SNILS is 0.6,
// below the Scan threshold, so the existing innsnils regex keeps its recall.
// Phone and email are 0.8 and likewise stay out of Scan.

var (
	ruINN10Re  = regexp.MustCompile(`\b\d{10}\b`)
	ruINN12Re  = regexp.MustCompile(`\b\d{12}\b`)
	ruSNILSRe  = regexp.MustCompile(`\b\d{3}[ \-]?\d{3}[ \-]?\d{3}[ \-]?\d{2}\b`)
	ruOGRN13Re = regexp.MustCompile(`\b\d{13}\b`)
	ruOGRN15Re = regexp.MustCompile(`\b\d{15}\b`)
	ruPassSSRe = regexp.MustCompile(`\b\d{2} \d{2} \d{6}\b`)
	ruPass4Re  = regexp.MustCompile(`\b\d{4} \d{6}\b`)
	ruPass10Re = regexp.MustCompile(`\b\d{10}\b`)
	ruPhoneRe  = regexp.MustCompile(`(?:\+7|8)(?:[ ()\-]*\d){10}\b`)
	ruEmailRe  = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
)

const (
	ruINNFormatConfidence   = 0.6
	ruSNILSFormatConfidence = 0.9
	ruPassportConfidence    = 0.9
	ruPhoneConfidence       = 0.8
	ruEmailConfidence       = 0.8
	ruSNILSUncheckedMax     = 1001998
)

func ruDetectors() []Detector {
	return []Detector{
		fnDetector{name: "ru:inn10", detect: detectINN10},
		fnDetector{name: "ru:inn12", detect: detectINN12},
		fnDetector{name: "ru:snils-flex", detect: detectSNILSFlex},
		fnDetector{name: "ru:ogrn", detect: detectOGRN13},
		fnDetector{name: "ru:ogrnip", detect: detectOGRN15},
		fnDetector{name: "ru:passport", detect: detectPassport},
		fnDetector{name: "ru:phone", detect: detectPhone},
		fnDetector{name: "ru:email", detect: detectEmail},
	}
}

type fnDetector struct {
	name   string
	detect func(string) []Finding
}

func (d fnDetector) Name() string { return d.name }

func (d fnDetector) Detect(text string) []Finding { return d.detect(text) }

func inn10Check(d []int) int {
	coef := []int{2, 4, 10, 3, 5, 9, 4, 6, 8}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += coef[i] * d[i]
	}
	return (sum % 11) % 10
}

func inn12Checks(d []int) (int, int) {
	c11 := []int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
	c12 := []int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
	s11 := 0
	for i := 0; i < 10; i++ {
		s11 += c11[i] * d[i]
	}
	d11 := (s11 % 11) % 10
	s12 := 0
	body := append(append([]int{}, d[:10]...), d11)
	for i := 0; i < 11; i++ {
		s12 += c12[i] * body[i]
	}
	return d11, (s12 % 11) % 10
}

func digitsOf(raw string) []int {
	out := make([]int, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c >= '0' && c <= '9' {
			out = append(out, int(c-'0'))
		}
	}
	return out
}

func detectINN10(text string) []Finding {
	return detectINN(text, ruINN10Re, "ru:inn10", 10)
}

func detectINN12(text string) []Finding {
	return detectINN(text, ruINN12Re, "ru:inn12", 12)
}

func detectINN(text string, re *regexp.Regexp, name string, n int) []Finding {
	var out []Finding
	for _, span := range re.FindAllStringIndex(text, -1) {
		d := digitsOf(text[span[0]:span[1]])
		if len(d) != n {
			continue
		}
		conf := ruINNFormatConfidence
		if n == 10 && d[9] == inn10Check(d) {
			conf = 1
		}
		if n == 12 {
			c11, c12 := inn12Checks(d[:10])
			if d[10] == c11 && d[11] == c12 {
				conf = 1
			}
		}
		out = append(out, Finding{
			Category: CatINNSNILS, Start: span[0], End: span[1],
			Confidence: conf, Locale: "ru", Detector: name,
		})
	}
	return out
}

func snilsParts(digits []int) (number int, cc int) {
	for i := 0; i < 9; i++ {
		number = number*10 + digits[i]
	}
	cc = digits[9]*10 + digits[10]
	return number, cc
}

func snilsKey(digits []int) (int, bool) {
	number, _ := snilsParts(digits)
	if number <= ruSNILSUncheckedMax {
		return 0, true
	}
	weights := []int{9, 8, 7, 6, 5, 4, 3, 2, 1}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += digits[i] * weights[i]
	}
	switch {
	case sum < 100:
		return sum, false
	case sum == 100 || sum == 101:
		return 0, false
	default:
		k := sum % 101
		if k == 100 {
			return 0, false
		}
		return k, false
	}
}

func detectSNILSFlex(text string) []Finding {
	var out []Finding
	for _, span := range ruSNILSRe.FindAllStringIndex(text, -1) {
		d := digitsOf(text[span[0]:span[1]])
		if len(d) != 11 {
			continue
		}
		_, cc := snilsParts(d)
		key, formatOnly := snilsKey(d)
		conf := ruINNFormatConfidence
		if formatOnly {
			conf = ruSNILSFormatConfidence
		} else if key == cc {
			conf = 1
		}
		out = append(out, Finding{
			Category: CatINNSNILS, Start: span[0], End: span[1],
			Confidence: conf, Locale: "ru", Detector: "ru:snils-flex",
		})
	}
	return out
}

func ogrnOK(digits string, head int, mod int) bool {
	n, err := strconv.ParseInt(digits[:head], 10, 64)
	if err != nil {
		return false
	}
	want := int((n % int64(mod)) % 10)
	return want == int(digits[head]-'0')
}

func detectOGRN13(text string) []Finding {
	return detectOGRN(text, ruOGRN13Re, "ru:ogrn", 12, 11)
}

func detectOGRN15(text string) []Finding {
	return detectOGRN(text, ruOGRN15Re, "ru:ogrnip", 14, 13)
}

func detectOGRN(text string, re *regexp.Regexp, name string, head, mod int) []Finding {
	var out []Finding
	for _, span := range re.FindAllStringIndex(text, -1) {
		raw := text[span[0]:span[1]]
		if !ogrnOK(raw, head, mod) {
			continue
		}
		out = append(out, Finding{
			Category: CatOGRN, Start: span[0], End: span[1],
			Confidence: 1, Locale: "ru", Detector: name,
		})
	}
	return out
}

func passportContext(text string, start int) bool {
	prefix := []rune(text[:start])
	if len(prefix) > 60 {
		prefix = prefix[len(prefix)-60:]
	}
	window := strings.ToLower(string(prefix))
	return strings.Contains(window, "паспорт") ||
		strings.Contains(window, "серия") ||
		strings.Contains(window, "passport")
}

func detectPassport(text string) []Finding {
	var out []Finding
	for _, re := range []*regexp.Regexp{ruPassSSRe, ruPass4Re, ruPass10Re} {
		for _, span := range re.FindAllStringIndex(text, -1) {
			if !passportContext(text, span[0]) {
				continue
			}
			out = append(out, Finding{
				Category: CatRUPassport, Start: span[0], End: span[1],
				Confidence: ruPassportConfidence, Locale: "ru", Detector: "ru:passport",
			})
		}
	}
	return out
}

func detectPhone(text string) []Finding {
	var out []Finding
	for _, span := range ruPhoneRe.FindAllStringIndex(text, -1) {
		if span[0] > 0 && text[span[0]-1] >= '0' && text[span[0]-1] <= '9' {
			continue
		}
		out = append(out, Finding{
			Category: CatPhone, Start: span[0], End: span[1],
			Confidence: ruPhoneConfidence, Locale: "ru", Detector: "ru:phone",
		})
	}
	return out
}

func detectEmail(text string) []Finding {
	var out []Finding
	for _, span := range ruEmailRe.FindAllStringIndex(text, -1) {
		out = append(out, Finding{
			Category: CatEmail, Start: span[0], End: span[1],
			Confidence: ruEmailConfidence, Detector: "ru:email",
		})
	}
	return out
}

type ruSpan struct {
	start, end int
	repl       string
}

func redactRU(text string) string {
	var spans []ruSpan
	for _, f := range FindAll(text, ruDetectors()) {
		repl := ""
		switch f.Category {
		case CatPhone, CatEmail, CatRUPassport, CatOGRN:
			repl = redactions[f.Category]
		case CatINNSNILS:
			if f.Confidence >= ruSNILSFormatConfidence {
				repl = redactions[CatINNSNILS]
			}
		}
		if repl == "" {
			continue
		}
		spans = append(spans, ruSpan{f.Start, f.End, repl})
	}
	for i := len(spans) - 1; i >= 0; i-- {
		sp := spans[i]
		overlap := false
		for j := i + 1; j < len(spans); j++ {
			later := spans[j]
			if sp.start < later.end && later.start < sp.end {
				overlap = true
				break
			}
		}
		if overlap {
			continue
		}
		text = text[:sp.start] + sp.repl + text[sp.end:]
	}
	return text
}
