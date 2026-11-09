package embeddings

import (
	"unicode"
)

// N03-P04-T03: multilingual domain and context qualifier separation.
//
// A semantic cache that embeds prompts from mixed-language traffic compares
// cosine distances across scripts: a Russian near-duplicate of an English
// question can score above the admission threshold on multilingual embedders
// (and on any embedder fed synthetic or low-quality vectors), and the org
// gets an answer generated for a different-language prompt. The same applies
// across context domains when an operator re-points the embedder.
//
// The mechanism here is the single source of truth for qualifier TAGS:
// a deterministic, dependency-free script classifier plus the two places a
// tag participates in identity — the embedding input prefix (so the vector
// itself is qualifier-conditioned, mirroring the QueryPrefix mechanism) and
// the space version suffix consumed by cache.Provenance.SpaceMatch (so
// entries from different qualifier spaces can never be compared at all, on
// any embedder). The cache derives the tag on BOTH the write and the lookup
// path from the same normalized prompt bytes, so both sides always agree.

// scriptBuckets are the recognized writing systems, in fixed scan order.
// The order breaks count ties deterministically (first max wins only when
// strictly greater; an exact tie is "mix").
var scriptBuckets = []struct {
	name   string
	ranges []*unicode.RangeTable
}{
	{"latn", []*unicode.RangeTable{unicode.Latin}},
	{"cyrl", []*unicode.RangeTable{unicode.Cyrillic}},
	{"grek", []*unicode.RangeTable{unicode.Greek}},
	{"arab", []*unicode.RangeTable{unicode.Arabic}},
	{"hebr", []*unicode.RangeTable{unicode.Hebrew}},
	{"deva", []*unicode.RangeTable{unicode.Devanagari}},
	{"hani", []*unicode.RangeTable{unicode.Han}},
	{"kana", []*unicode.RangeTable{unicode.Hiragana, unicode.Katakana}},
	{"hang", []*unicode.RangeTable{unicode.Hangul}},
	{"thai", []*unicode.RangeTable{unicode.Thai}},
	{"armn", []*unicode.RangeTable{unicode.Armenian}},
	{"geor", []*unicode.RangeTable{unicode.Georgian}},
}

// ScriptQualifier returns the deterministic multilingual qualifier tag for
// text: the ISO-15924-style short name of the dominant writing system
// ("latn", "cyrl", "hani", ...), "mix" when two scripts tie for the lead,
// and "none" when the text contains no classified letters at all (digits,
// punctuation, empty). The tag never depends on anything but the text
// bytes, so the write path and the lookup path of the semantic cache derive
// identical tags from the same prompt — which is the property that makes
// the qualified space identity safe.
//
// This is a script-level classifier, not a language detector: uk and ru
// both map to "cyrl", sr splits by script. That is the intended granularity
// — the cache must separate incomparable inputs cheaply and deterministically,
// not identify languages.
func ScriptQualifier(text string) string {
	counts := make([]int, len(scriptBuckets))
	total := 0
	for _, r := range text {
		if !unicode.IsLetter(r) {
			continue
		}
		total++
		for i, b := range scriptBuckets {
			for _, rt := range b.ranges {
				if unicode.Is(rt, r) {
					counts[i]++
					break
				}
			}
		}
	}
	if total == 0 {
		return "none"
	}
	best, bestCount := "none", 0
	tie := false
	for i, b := range scriptBuckets {
		switch {
		case counts[i] > bestCount:
			best, bestCount, tie = b.name, counts[i], false
		case counts[i] == bestCount && counts[i] > 0:
			tie = true
		}
	}
	if tie {
		return "mix"
	}
	return best
}

// QualifierInputPrefix returns the prefix that must precede an embedding
// input qualified with the given tag (N03-P04-T03). Empty for an empty tag,
// so unqualified inputs are byte-identical to the pre-T03 behavior. The
// prefix mirrors the QueryPrefix mechanism: it conditions the vector on the
// qualifier in addition to separating the space identity, and both the cache
// write path and the lookup path build it through this one function.
func QualifierInputPrefix(tag string) string {
	if tag == "" {
		return ""
	}
	return "[q:" + tag + "] "
}

// QualifiedSpaceVersion binds a base embedding-space version (see
// SpaceVersioner) to a qualifier tag (N03-P04-T03). An empty tag returns the
// base unchanged, so qualifier-blind embedders and pre-T03 entries keep
// their exact T02 identity. A non-empty tag yields a distinct space:
// cache.Provenance.SpaceMatch compares versions with strict equality, so an
// entry written under one qualifier can only be served by a lookup that
// derived the same qualifier — a ru↔en near-duplicate misses regardless of
// how similar the embedder claims the vectors are.
func QualifiedSpaceVersion(base, tag string) string {
	if tag == "" {
		return base
	}
	return base + "|q:" + tag
}

// InputQualifier is implemented by embedders that separate multilingual
// domains and context qualifiers (N03-P04-T03). The semantic cache type-
// asserts its embedder to this interface on both the write and the lookup
// path; embedders that do not implement it are qualifier-blind (empty tag)
// and keep the exact pre-T03 identity and input bytes.
type InputQualifier interface {
	// InputQualifierTag returns the deterministic qualifier tag for the
	// given text, or "" when qualification is disabled for this client.
	// Implementations must be pure functions of the text: the cache calls
	// it with the same content on write and lookup and relies on identical
	// answers.
	InputQualifierTag(text string) string
}

// HTTPClient always satisfies SpaceVersioner and satisfies InputQualifier
// (as a qualifier-blind no-op) even when qualification is disabled, so the
// cache's single type assertion covers both configurations.
var (
	_ SpaceVersioner = (*HTTPClient)(nil)
	_ InputQualifier = (*HTTPClient)(nil)
)

// InputQualifierTag implements InputQualifier for HTTPClient. When
// Config.QualifyScripts is off the client is qualifier-blind ("").
// When on, the tag is the dominant script of the text (ScriptQualifier),
// optionally bound to the client's static Config.ContextQualifier domain
// tag so two deployments of the same embedder model do not share one space.
func (c *HTTPClient) InputQualifierTag(text string) string {
	if c == nil || !c.qualifyScripts {
		return ""
	}
	tag := ScriptQualifier(text)
	if c.contextQualifier != "" {
		tag += ";d:" + c.contextQualifier
	}
	return tag
}
