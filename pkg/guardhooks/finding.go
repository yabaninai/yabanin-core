package guardhooks

import "sort"

// Finding is one detector match. Start and End are byte offsets into the
// scanned text. Confidence is 1.0 when a checksum confirmed the match and
// 0.9 for a strict format. Locale is empty when the detector is not national.
type Finding struct {
	Category   Category
	Start, End int
	Confidence float64
	Locale     string
	Detector   string
}

// Detector reports non-overlapping matches of one kind.
type Detector interface {
	Name() string
	Detect(text string) []Finding
}

type patternDetector struct {
	name       string
	category   Category
	re         interface{ FindAllStringIndex(string, int) [][]int }
	confidence float64
	locale     string
	valid      func(string) bool
}

func (d patternDetector) Name() string { return d.name }

func (d patternDetector) Detect(text string) []Finding {
	spans := d.re.FindAllStringIndex(text, -1)
	if len(spans) == 0 {
		return nil
	}
	out := make([]Finding, 0, len(spans))
	for _, span := range spans {
		frag := text[span[0]:span[1]]
		if d.valid != nil && !d.valid(frag) {
			continue
		}
		out = append(out, Finding{
			Category:   d.category,
			Start:      span[0],
			End:        span[1],
			Confidence: d.confidence,
			Locale:     d.locale,
			Detector:   d.name,
		})
	}
	return out
}

// DefaultDetectors wraps the detectors Scan already uses. Checksum matches
// are confidence 1.0. Format matches are 0.9.
func DefaultDetectors() []Detector {
	base := []Detector{
		patternDetector{name: "ru:snils", category: CatINNSNILS, re: snilsRe, confidence: 1, locale: "ru", valid: validateSNILS},
		patternDetector{name: "ru:inn", category: CatINNSNILS, re: innRe, confidence: 1, locale: "ru", valid: validateINN},
		patternDetector{name: "luhn:pan", category: CatPAN, re: panRe, confidence: 1, valid: func(s string) bool {
			_, ok := validatePAN(s)
			return ok
		}},
		patternDetector{name: "regex:secret", category: CatSecret, re: secretRe, confidence: 0.9},
		patternDetector{name: "regex:pem", category: CatSecret, re: pemRe, confidence: 0.9},
		patternDetector{name: "regex:injection", category: CatInjection, re: injectionRe, confidence: 0.9},
		patternDetector{name: "br:cpf", category: CatBR, re: cpfRe, confidence: 1, locale: "br", valid: validateCPF},
		patternDetector{name: "br:cnpj", category: CatBR, re: cnpjRe, confidence: 1, locale: "br", valid: validateCNPJ},
		patternDetector{name: "in:aadhaar", category: CatIN, re: aadhaarRe, confidence: 1, locale: "in", valid: validateAadhaar},
		patternDetector{name: "in:pan", category: CatIN, re: panINRe, confidence: 1, locale: "in", valid: func(s string) bool {
			_, ok := validatePANIN(s)
			return ok
		}},
		patternDetector{name: "my:mykad", category: CatMY, re: mykadRe, confidence: 1, locale: "my", valid: validateMyKad},
		patternDetector{name: "ae:iqama", category: CatAE, re: iqamaRe, confidence: 1, locale: "ae", valid: validateIqama},
		patternDetector{name: "za:nin", category: CatZA, re: zaNINRe, confidence: 1, locale: "za", valid: validateZANIN},
		patternDetector{name: "ng:nin", category: CatNG, re: ngNINRe, confidence: 1, locale: "ng", valid: validateNGNIN},
		patternDetector{name: "ke:nin", category: CatKE, re: keNINRe, confidence: 1, locale: "ke", valid: validateKENIN},
		patternDetector{name: "eg:nin", category: CatEG, re: egNINRe, confidence: 1, locale: "eg", valid: validateEGNIN},
	}
	return append(base, ruDetectors()...)
}

// FindAll runs detectors and returns matches ordered by Start. Two matches of
// the same category that overlap are reduced to the earlier one.
func FindAll(text string, ds []Detector) []Finding {
	var all []Finding
	for _, d := range ds {
		if d == nil {
			continue
		}
		all = append(all, d.Detect(text)...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Start != all[j].Start {
			return all[i].Start < all[j].Start
		}
		if all[i].End != all[j].End {
			return all[i].End < all[j].End
		}
		return all[i].Detector < all[j].Detector
	})
	kept := make([]Finding, 0, len(all))
	lastEnd := map[Category]int{}
	seen := map[Category]bool{}
	for _, f := range all {
		if seen[f.Category] && f.Start < lastEnd[f.Category] {
			continue
		}
		kept = append(kept, f)
		if !seen[f.Category] || f.End > lastEnd[f.Category] {
			lastEnd[f.Category] = f.End
		}
		seen[f.Category] = true
	}
	return kept
}
