// Package cache — decisive-content admission guard (N03-P04-T05).
//
// T04 measured the failure this file closes: on the frozen holdout, 10 of 14
// near-duplicate pairs that differ only in a DATE, a NUMBER, an ENTITY or an
// ACCESS LEVEL were served the cached entry — the vectors of a strong
// embedder sit far above the 0.95 admission threshold for prompts whose
// decisive content disagrees ("revenue in Q1 2025" answering "revenue in Q2
// 2025"). Cosine similarity cannot see the difference; the tokens themselves
// can.
//
// The guard works in two halves that meet in the provenance envelope:
//
//   - Write side (writer.go): DecisiveContentStamp computes a ONE-WAY
//     fingerprint of the prompt's decisive content over the normalized
//     prompt bytes and seals it into the entry's provenance. The cache never
//     stores prompt text — only the hash — so this adds no new data-
//     exposure surface.
//
//   - Lookup side (service.go): after the exact layers, the qualifier-space
//     guard (T03) and the threshold epoch check (T02) pass, the service
//     recomputes the stamp from the current prompt and requires strict
//     equality (Provenance.DecisiveMatch). A mismatch means the entry was
//     written for a different question even under near-identical vectors;
//     it degrades to a self-healing miss exactly like a foreign space or
//     threshold epoch — never an error, never a leak.
//
// The detector is deterministic, dependency-free and bilingual (EN/RU), the
// two scripts the holdout and the product's qualifier taxonomy cover. It is
// deliberately coarse: a false veto costs a recompute (the fail-safe
// direction); a missed veto would serve someone else's answer.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// DecisiveContentVer identifies the decisive-content detector (and thus the
// fingerprint layout) a stamp was produced with (N03-P04-T05). It follows
// the SpaceMatch precedent: strict equality, including the empty string —
// an entry sealed before this guard (or by a writer that does not stamp)
// carries no decisive fingerprint and is never compatible with a versioning
// lookup; it degrades to a safe miss and refills stamped. Bump the constant
// only when the token extraction changes, never for hash-layer tweaks: the
// fingerprint itself is content-derived, not configuration-derived.
const DecisiveContentVer = "dc1"

// DecisiveContentStamp resolves the provenance fields the guard compares:
// the detector version and a one-way fingerprint of the prompt's decisive
// content. Input is the NORMALIZED prompt bytes — the exact input the write
// path hashes and embeds and the lookup path reconstructs (normalizeForCache);
// DecisiveContentStamp(normalize(p)) must be identical on both sides by
// construction.
func DecisiveContentStamp(normPrompt []byte) (ver, fp string) {
	return DecisiveContentVer, decisiveFingerprint(qualifierSourceText(normPrompt))
}

// DecisiveMatch reports whether a sealed entry's decisive-content stamp is
// compatible with the stamp current at lookup time (N03-P04-T05). Strict
// equality, including the empty string, mirroring SpaceMatch: a versioning
// lookup never accepts an entry whose decisive content is unknown (legacy
// or unstamped writer) — such entries degrade to self-healing misses and
// are re-stamped on refill. Two stamp-less sides remain compatible, which
// preserves the behavior of stamp-less test constructions. Exact-cache
// layers must not consult this check: hash equality already implies
// identical bytes.
func (p Provenance) DecisiveMatch(decisiveVer, decisiveFP string) bool {
	return p.DecisiveVer == decisiveVer && p.DecisiveFP == decisiveFP
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

// decisiveFingerprint reduces extracted decisive content to two hashes:
// the SET of all decisive tokens (sorted multiset) and the ORDERED sequence
// of the numeric/date tokens only. The second part exists for role swaps
// (holdout nn-ru-qty: system stock 1 240 / invoice 1 420 vs swapped) where
// the multiset is unchanged but the numbers traded places — a different
// question, not a duplicate. Entity and access-marker order stays out of
// the ordered part on purpose: rewording must not veto (a miss is cheap, a
// leak is not — but systematic over-invalidation would gut the hit rate).
func decisiveFingerprint(content string) string {
	set, ordered := extractDecisive(content)
	sort.Strings(set)
	sh := sha256.Sum256([]byte(strings.Join(set, "\x1f")))
	oh := sha256.Sum256([]byte(strings.Join(ordered, "\x1f")))
	// 8 bytes = 16 hex chars per half: collision odds are negligible for an
	// admission guard whose failure mode is a recompute, and the fingerprint
	// rides in every cached envelope.
	return "s=" + hex.EncodeToString(sh[:8]) + ";o=" + hex.EncodeToString(oh[:8])
}

// extractDecisive returns all decisive tokens (set, unsorted) and the
// position-ordered numeric/date tokens. Decisive classes:
//
//	d:…  dates in any supported spelling, canonicalized (cross-language
//	     equal: "2025-03-31" == "31.03.2025" == "March 31, 2025");
//	     bare quarters ("Q3", "Q3 2025") canonicalize as d:q3 / d:YYYYq3
//	n:…  numbers ≥ 10, decimals ("99.95"), group separators stripped
//	     ("45,200" == "45200"; "1 240"-style spaces too); single small
//	     integers are noise and skipped
//	e:…  quoted entity names («Ромашка», “Helios”) and mid-sentence
//	     capitalized words (Acme Manufacturing); lowercased
//	a:…  access-level markers (restricted/confidential/public/…,
//	     RU prefix stems: конфиденциальн*, закрыт*, обезличен*, …)
//
// Dates are matched first and masked before the number/entity passes so a
// date's digits never double-count as quantities.
func extractDecisive(content string) (set []string, ordered []string) {
	masked := []byte(content)

	spans := collectDateSpans(masked) // masks as it matches
	spans = append(spans, collectQuarterSpans(masked)...)
	spans = append(spans, collectNumberSpans(masked)...)
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })

	set = make([]string, 0, len(spans)+4)
	for _, sp := range spans {
		set = append(set, sp.token)
		ordered = append(ordered, sp.token) // numeric/date classes only, textual order
	}

	rest := string(masked)
	set = append(set, collectEntityTokens(rest)...)
	set = append(set, collectMarkerTokens(rest)...)
	return set, ordered
}

// span is one extracted decisive token with its byte offset in the masked
// text (offsets are stable: masking replaces matches with same-length
// spaces).
type span struct {
	start int
	token string
}

// ---------------------------------------------------------------------------
// Dates
// ---------------------------------------------------------------------------

var enMonths = map[string]string{
	"january": "01", "february": "02", "march": "03", "april": "04",
	"may": "05", "june": "06", "july": "07", "august": "08",
	"september": "09", "october": "10", "november": "11", "december": "12",
}

// monthStem pairs a Russian month prefix stem with its number; Russian
// month names inflect (март/марта/марте), so a stem match plus any letter
// tail is the month. Longer stems must precede their prefixes ("март"
// before "ма").
type monthStem struct{ stem, month string }

var ruMonthStems = []monthStem{
	{"январ", "01"}, {"феврал", "02"}, {"март", "03"}, {"апрел", "04"},
	{"ма", "05"}, {"июн", "06"}, {"июл", "07"}, {"август", "08"},
	{"сентябр", "09"}, {"октябр", "10"}, {"ноябр", "11"}, {"декабр", "12"},
}

// ruMonthWords is the alternation of Russian month stems for date patterns
// (case-insensitive matching; the tail letters are the inflection).
const ruMonthWords = `январ|феврал|март|апрел|ма[йя]|июн|июл|август|сентябр|октябр|ноябр|декабр`

// datePattern is one prioritized date spelling. Order matters: longer and
// more specific forms first, each match masked before the next pattern runs.
// NOTE: Go's regexp \b is ASCII-only, so it is only used where the match
// starts/ends on ASCII; Cyrillic-leading matches are boundary-checked in
// code (wordStartAt).
type datePattern struct {
	re        *regexp.Regexp
	canonical func(m []int, src []byte) (token string, maskEnd int, ok bool)
}

var datePatterns = []datePattern{
	// 31.03.2025 (RU/DE day.month.year)
	{
		re: regexp.MustCompile(`\b(\d{2})\.(\d{2})\.(20\d{2})\b`),
		canonical: func(m []int, src []byte) (string, int, bool) {
			tok, ok := ymd(grp(m, 3, src), grp(m, 2, src), grp(m, 1, src))
			return tok, m[7], ok
		},
	},
	// 2025-03-31 (ISO)
	{
		re: regexp.MustCompile(`\b(20\d{2})-(\d{2})-(\d{2})\b`),
		canonical: func(m []int, src []byte) (string, int, bool) {
			tok, ok := ymd(grp(m, 1, src), grp(m, 2, src), grp(m, 3, src))
			return tok, m[7], ok
		},
	},
	// March 15, 2025 (EN long-form, US order; optional ordinal suffix)
	{
		re: regexp.MustCompile(`(?i)\b(january|february|march|april|may|june|july|august|september|october|november|december)\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(20\d{2})\b`),
		canonical: func(m []int, src []byte) (string, int, bool) {
			month, ok := enMonths[strings.ToLower(grp(m, 1, src))]
			if !ok {
				return "", 0, false
			}
			tok, okY := ymd(grp(m, 3, src), month, grp(m, 2, src))
			return tok, m[7], okY
		},
	},
	// 15 марта 2025 (RU day-month-year; stem + inflection tail)
	{
		re: regexp.MustCompile(`(?i)\b(\d{1,2})\s+(` + ruMonthWords + `)[а-яё]*\s+(20\d{2})\b`),
		canonical: func(m []int, src []byte) (string, int, bool) {
			tok, ok := ymd(grp(m, 3, src), ruMonthNumber(grp(m, 2, src)), grp(m, 1, src))
			return tok, m[7], ok
		},
	},
	// March 2025 (EN month-year)
	{
		re: regexp.MustCompile(`(?i)\b(january|february|march|april|may|june|july|august|september|october|november|december)\s+(20\d{2})\b`),
		canonical: func(m []int, src []byte) (string, int, bool) {
			month, ok := enMonths[strings.ToLower(grp(m, 1, src))]
			if !ok {
				return "", 0, false
			}
			return "d:" + grp(m, 2, src) + "-" + month, m[5], true
		},
	},
	// март 2025 года (RU month-year; runs after the day-forms have masked).
	// Starts on a Cyrillic letter — no ASCII \b; wordStartAt is enforced in
	// canonical.
	{
		re: regexp.MustCompile(`(?i)(` + ruMonthWords + `)[а-яё]*\s+(20\d{2})\b`),
		canonical: func(m []int, src []byte) (string, int, bool) {
			if !wordStartAt(src, m[0]) {
				return "", 0, false
			}
			return "d:" + grp(m, 2, src) + "-" + ruMonthNumber(grp(m, 1, src)), m[5], true
		},
	},
	// Q3 2025 (EN quarter with year)
	{
		re: regexp.MustCompile(`\b[Qq]([1-4])\s*,?\s*(20\d{2})\b`),
		canonical: func(m []int, src []byte) (string, int, bool) {
			return "d:" + grp(m, 2, src) + "q" + grp(m, 1, src), m[5], true
		},
	},
	// 3-й квартал 2025 (RU quarter with year)
	{
		re: regexp.MustCompile(`(?i)\b([1-4])-?\s*[йя]?\.?\s*квартал[а-яё]*\s+(20\d{2})\b`),
		canonical: func(m []int, src []byte) (string, int, bool) {
			return "d:" + grp(m, 2, src) + "q" + grp(m, 1, src), m[5], true
		},
	},
	// 2025-03 (ISO year-month, only after the full ISO form masked)
	{
		re: regexp.MustCompile(`\b(20\d{2})-(\d{2})([^0-9]|$)`),
		canonical: func(m []int, src []byte) (string, int, bool) {
			month := pad2(grp(m, 2, src))
			if month < "01" || month > "12" {
				return "", 0, false
			}
			return "d:" + grp(m, 1, src) + "-" + month, m[5], true
		},
	},
}

// collectDateSpans runs the prioritized date patterns over the text, masks
// each match with spaces and returns its canonical spans. Masking is
// same-length, so later offsets stay valid.
func collectDateSpans(src []byte) []span {
	var out []span
	for _, dp := range datePatterns {
		for _, m := range dp.re.FindAllSubmatchIndex(src, -1) {
			tok, maskEnd, ok := dp.canonical(m, src)
			if !ok {
				continue
			}
			for i := m[0]; i < maskEnd; i++ {
				src[i] = ' '
			}
			out = append(out, span{start: m[0], token: tok})
		}
	}
	return out
}

// ymd validates and canonicalizes a year-month-day triple; months must be
// real, days loosely bounded (01-31 — decisive content is about equality,
// not calendar correctness). Single-digit months/days are zero-padded.
func ymd(year, month, day string) (string, bool) {
	month, day = pad2(month), pad2(day)
	if month < "01" || month > "12" || day < "01" || day > "31" {
		return "", false
	}
	return "d:" + year + "-" + month + "-" + day, true
}

// grp extracts capture group i's bytes as a string.
func grp(m []int, i int, src []byte) string {
	if m[2*i] < 0 {
		return ""
	}
	return string(src[m[2*i]:m[2*i+1]])
}

// pad2 zero-pads a 1-2 digit numeric string to two digits.
func pad2(s string) string {
	if len(s) == 1 {
		return "0" + s
	}
	return s
}

// ruMonthNumber maps a matched Russian month stem to its two-digit number.
func ruMonthNumber(stem string) string {
	lower := strings.ToLower(stem)
	for _, ms := range ruMonthStems {
		if strings.HasPrefix(lower, ms.stem) {
			return ms.month
		}
	}
	// The pattern only admits listed stems; unreachable in practice.
	return "00"
}

// wordStartAt reports whether the byte at start begins a word: it is the
// start of the text or follows a non-word byte (letters/digits in ASCII or
// any multibyte letter count as word bytes). This replaces the ASCII-only
// \b for Cyrillic-leading patterns.
func wordStartAt(src []byte, start int) bool {
	if start == 0 {
		return true
	}
	return !isWordByte(src[start-1])
}

func isWordByte(b byte) bool {
	return b >= 0x80 || isDigit(b) || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// ---------------------------------------------------------------------------
// Quarters without a year ("Q3", "Q3 cycle")
// ---------------------------------------------------------------------------

var reQuarterBare = regexp.MustCompile(`[Qq]([1-4])`)

// collectQuarterSpans finds standalone quarter tags (no year attached — the
// year form was masked by the date pass). Word boundaries are enforced
// manually: a word-byte neighbor disqualifies the match.
func collectQuarterSpans(src []byte) []span {
	var out []span
	for _, m := range reQuarterBare.FindAllSubmatchIndex(src, -1) {
		if m[0] > 0 && isWordByte(src[m[0]-1]) {
			continue
		}
		if m[1] < len(src) && isWordByte(src[m[1]]) {
			continue
		}
		out = append(out, span{start: m[0], token: "d:q" + string(src[m[2]:m[3]])})
	}
	return out
}

// ---------------------------------------------------------------------------
// Numbers
// ---------------------------------------------------------------------------

// collectNumberSpans scans the masked text for numeric runs and emits their
// canonical tokens. A run is a maximal stretch of digits, "."/"," separators
// (only when followed by a digit) and single spaces that join 3-digit groups
// (Russian "1 240" thousands grouping).
func collectNumberSpans(src []byte) []span {
	var out []span
	i := 0
	for i < len(src) {
		if !isDigit(src[i]) {
			i++
			continue
		}
		end := numberRunEnd(src, i)
		if canon, ok := canonicalNumber(string(src[i:end])); ok {
			out = append(out, span{start: i, token: "n:" + canon})
		}
		i = end
	}
	return out
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// numberRunEnd returns the exclusive end of the numeric run starting at i.
func numberRunEnd(src []byte, i int) int {
	j := i
	for j < len(src) {
		c := src[j]
		switch {
		case isDigit(c):
			j++
		case c == '.' || c == ',':
			if j+1 < len(src) && isDigit(src[j+1]) {
				j++
			} else {
				return j // trailing separator belongs to punctuation
			}
		case c == ' ':
			// Space is a thousands separator only when exactly three digits
			// follow; otherwise the run ends (e.g. "12 30" is two numbers).
			if j+4 <= len(src) && isDigit(src[j+1]) && isDigit(src[j+2]) && isDigit(src[j+3]) {
				j++
			} else {
				return j
			}
		default:
			return j
		}
	}
	return j
}

// canonicalNumber canonicalizes one numeric run. The decimal separator is
// the LAST "."/"," that is followed by only 1-2 digits (e.g. "99.95");
// a separator followed by exactly 3 digits is treated as thousands grouping
// ("45,200" → 45200) — the corpus convention, applied deterministically.
// Runs whose integer part does not validate as clean grouping (version
// strings like "2.13.1") are skipped entirely: symmetric on both sides and
// they carry no question-decisive quantity. Single small integers (0-9)
// are noise and skipped.
func canonicalNumber(run string) (string, bool) {
	dec := -1
	for k := len(run) - 2; k >= 0; k-- {
		if run[k] != '.' && run[k] != ',' {
			continue
		}
		tail := run[k+1:]
		if isAllDigits(tail) && len(tail) <= 2 {
			dec = k
			break
		}
	}
	if dec >= 0 {
		digits, ok := integerDigits(run[:dec])
		if !ok {
			return "", false
		}
		frac := strings.TrimRight(run[dec+1:], "0")
		switch {
		case frac != "":
			return digits + "." + frac, true
		case len(digits) > 1:
			return digits, true
		default:
			return "", false // single small integer
		}
	}
	digits, ok := integerDigits(run)
	if !ok || len(digits) == 1 {
		return "", false
	}
	return digits, true
}

func isAllDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// integerDigits validates the integer part (plain digits, or 1-3 digits
// followed by 3-digit groups separated by "."/","/" ") and returns the bare
// digit string with leading zeros trimmed.
func integerDigits(part string) (string, bool) {
	if !strings.ContainsAny(part, "., ") {
		return trimLeadingZeros(part), true
	}
	groups := strings.FieldsFunc(part, func(r rune) bool {
		return r == '.' || r == ',' || r == ' '
	})
	if len(groups) == 0 || len(groups[0]) == 0 || len(groups[0]) > 3 {
		return "", false
	}
	var b strings.Builder
	b.WriteString(trimLeadingZeros(groups[0]))
	for _, g := range groups[1:] {
		if len(g) != 3 {
			return "", false
		}
		b.WriteString(g)
	}
	d := b.String()
	if d == "" {
		return "0", true
	}
	return d, true
}

func trimLeadingZeros(s string) string {
	t := strings.TrimLeft(s, "0")
	if t == "" {
		return "0"
	}
	return t
}

// ---------------------------------------------------------------------------
// Entities
// ---------------------------------------------------------------------------

var (
	reQuoteGuillemet = regexp.MustCompile(`«([^«»\n]{1,80})»`)
	reQuoteCurly     = regexp.MustCompile(`“([^“”\n]{1,80})”`)
	reQuoteASCII     = regexp.MustCompile(`"([^"\n]{1,80})"`)
)

// collectEntityTokens extracts entity names: whole words inside quotation
// marks (the reliable cross-language entity signal) and mid-sentence
// capitalized words (Acme Manufacturing / Helios / ООО «Ромашка» without
// quotes). Sentence-initial words and ALL-CAPS acronyms are excluded —
// they are grammatical position and vocabulary, not decisive naming.
func collectEntityTokens(text string) []string {
	var out []string
	for _, re := range []*regexp.Regexp{reQuoteGuillemet, reQuoteCurly, reQuoteASCII} {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			for _, w := range letterWords(m[1]) {
				out = append(out, "e:"+w)
			}
		}
	}

	runes := []rune(text)
	for i := 0; i < len(runes); {
		if !unicode.IsLetter(runes[i]) {
			i++
			continue
		}
		j := i
		for j < len(runes) && unicode.IsLetter(runes[j]) {
			j++
		}
		if j-i >= 2 &&
			unicode.IsUpper(runes[i]) &&
			!allUpper(runes[i:j]) &&
			!atSentenceStart(runes, i) {
			out = append(out, "e:"+strings.ToLower(string(runes[i:j])))
		}
		i = j
	}
	return out
}

// letterWords splits a fragment into lowercased letter runs of length ≥ 2.
func letterWords(fragment string) []string {
	var out []string
	runes := []rune(fragment)
	for i := 0; i < len(runes); {
		if !unicode.IsLetter(runes[i]) {
			i++
			continue
		}
		j := i
		for j < len(runes) && unicode.IsLetter(runes[j]) {
			j++
		}
		if j-i >= 2 {
			out = append(out, strings.ToLower(string(runes[i:j])))
		}
		i = j
	}
	return out
}

// allUpper reports whether every rune is uppercase (acronyms like "HR").
func allUpper(rs []rune) bool {
	if len(rs) == 0 {
		return false
	}
	for _, r := range rs {
		if !unicode.IsUpper(r) {
			return false
		}
	}
	return true
}

// atSentenceStart reports whether the word starting at i begins a sentence:
// only whitespace (or nothing) precedes it back to the previous ".", "!",
// "?", "…" or the text start.
func atSentenceStart(runes []rune, i int) bool {
	for k := i - 1; k >= 0; k-- {
		r := runes[k]
		if unicode.IsSpace(r) {
			continue
		}
		switch r {
		case '.', '!', '?', '…':
			return true
		default:
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Access-level markers
// ---------------------------------------------------------------------------

// decisiveMarkersEN are prefix stems (public* covers public/publicly,
// publish* covers published/publishing); decisiveMarkersRU are prefix stems
// over inflected Russian (конфиденциальн*, закрыт*, обезличен*, …). The
// marker class is coarse by design: an extra symmetric marker on both sides
// changes nothing (sets still compare equal); a one-sided marker is exactly
// the access-level change the guard must see. Known coarseness: RU "закрыт*"
// also matches "тикеты закрыты" (tickets closed) — harmless for the guard
// because both sides of a true duplicate carry it, and the veto direction
// is the safe one.
var (
	decisiveMarkersEN = []string{"restrict", "confidential", "internal", "classifi", "privat", "public", "publish", "unannounc", "unpublish", "secret"}
	decisiveMarkersRU = []string{"конфиденциальн", "закрыт", "внутренн", "секретн", "публичн", "опубликован", "обезличен", "персональн"}
)

// collectMarkerTokens scans lowercased letter words for access-level stems.
func collectMarkerTokens(text string) []string {
	var out []string
	for _, w := range letterWords(text) {
		for _, stem := range decisiveMarkersEN {
			if strings.HasPrefix(w, stem) {
				out = append(out, "a:"+stem)
				break
			}
		}
		for _, stem := range decisiveMarkersRU {
			if strings.HasPrefix(w, stem) {
				out = append(out, "a:"+stem)
				break
			}
		}
	}
	return out
}
