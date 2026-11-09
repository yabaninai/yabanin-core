package dataclass

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/reireirei/yabanin/pkg/labels"
)

// Taxonomy model limits. Deliberately conservative: a taxonomy is an
// admin-curated structure, not a free-form corpus.
const (
	// MaxTaxonomyLabels bounds one org taxonomy.
	MaxTaxonomyLabels = 512
	// MaxSynonymsPerLocale bounds the synonym list of one label in one
	// locale.
	MaxSynonymsPerLocale = 64
	// MaxSynonymLen bounds one synonym phrase in bytes (the
	// labels.MaxValueLen precedent).
	MaxSynonymLen = 128
	// MaxTaxonomyDepth is the maximum number of PARENT hops from any
	// label: label → parent → grandparent is fine, a fourth node in the
	// chain is refused ("глубина 3 → отказ").
	MaxTaxonomyDepth = 2
)

// Supported synonym locales (finding Locale model: RU/EN only, dispatch
// E04-P01 §W01/W02 context).
const (
	LocaleRU = "ru"
	LocaleEN = "en"
)

// Label is one node of an org taxonomy: a normalized key, an optional
// parent key ("" = root) and per-locale synonym phrases used for matching.
type Label struct {
	Key      string              `json:"key"`
	Parent   string              `json:"parent,omitempty"`
	Synonyms map[string][]string `json:"synonyms,omitempty"`
}

// Taxonomy is the org-scoped label taxonomy (E04-P01-W02-C01). Version is
// store-managed: the in-memory model validates structure only.
type Taxonomy struct {
	OrgID   string  `json:"org_id"`
	Labels  []Label `json:"labels"`
	Version int64   `json:"version"`
}

// ValidationError carries EVERY validation problem, deterministically
// ordered (adversarial AC: "отказ со списком ошибок", not a first-error
// refusal).
type ValidationError struct {
	Errors []string `json:"errors"`
}

func (e *ValidationError) Error() string {
	return "dataclass: taxonomy validation failed: " + strings.Join(e.Errors, "; ")
}

// Validate checks the taxonomy structure and returns a *ValidationError
// listing every problem, or nil. Rules:
//
//   - OrgID must be non-blank (uuid syntax is store-level, see W02-C02);
//   - label count <= MaxTaxonomyLabels; an EMPTY label list is VALID — a
//     deliberate fixed choice (dispatch W02-C01: "зафиксировать одно из
//     двух"): it aligns with GET returning an empty default taxonomy, and
//     PUT of [] is the idempotent reset, not an error;
//   - keys follow the pkg/labels grammar (labels.NormalizeKey: ≤63 bytes,
//     ^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)*$) and MUST arrive canonical
//     (already trimmed+lowercase); the yabanin. reserved prefix is
//     refused — the taxonomy never enters the wire-reserved namespace;
//   - keys are unique; a parent reference must exist, differ from the
//     label's own key, form no cycle, and sit at most MaxTaxonomyDepth
//     hops up;
//   - synonyms: locales {ru,en} only, non-empty trimmed phrases, valid
//     UTF-8, no control characters, <=MaxSynonymLen bytes, no duplicates
//     within a locale, <=MaxSynonymsPerLocale entries per locale.
//
// The verdict is a pure function of the input: same taxonomy, same error
// list, same order.
func (t Taxonomy) Validate() error {
	var errs []string
	addf := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

	if strings.TrimSpace(t.OrgID) == "" {
		addf("org_id is blank")
	}
	if len(t.Labels) > MaxTaxonomyLabels {
		addf("label count %d exceeds %d", len(t.Labels), MaxTaxonomyLabels)
	}

	seen := make(map[string]bool, len(t.Labels))
	parent := make(map[string]string, len(t.Labels)) // child -> parent (only known keys enter)
	for _, l := range t.Labels {
		key, ok := labels.NormalizeKey(l.Key)
		if !ok {
			addf("label key %q: invalid grammar (lowercase, <=%d bytes, dots/digits/underscores/hyphens)", l.Key, labels.MaxKeyLen)
			continue
		}
		if key != l.Key {
			addf("label key %q: not canonical (want %q) — PUT must send normalized keys", l.Key, key)
			continue
		}
		if strings.HasPrefix(l.Key, labels.ReservedPrefix) {
			addf("label key %q: reserved prefix %q", l.Key, labels.ReservedPrefix)
			continue
		}
		if seen[l.Key] {
			addf("label key %q: duplicate", l.Key)
			continue
		}
		seen[l.Key] = true
		parent[l.Key] = l.Parent

		if l.Parent == l.Key {
			addf("label %q: parent is itself", l.Key)
		}
		for locale, synonyms := range l.Synonyms {
			if locale != LocaleRU && locale != LocaleEN {
				addf("label %q: synonym locale %q not in {%q,%q}", l.Key, locale, LocaleRU, LocaleEN)
				continue
			}
			if len(synonyms) > MaxSynonymsPerLocale {
				addf("label %q: %d synonyms in locale %q exceeds %d", l.Key, len(synonyms), locale, MaxSynonymsPerLocale)
			}
			dupes := make(map[string]bool, len(synonyms))
			for _, s := range synonyms {
				trimmed := strings.TrimSpace(s)
				switch {
				case trimmed == "":
					addf("label %q: empty synonym in locale %q", l.Key, locale)
				case len(s) > MaxSynonymLen:
					addf("label %q: synonym %q exceeds %d bytes", l.Key, trimmed, MaxSynonymLen)
				case !utf8.ValidString(s):
					addf("label %q: synonym %q is not valid UTF-8", l.Key, trimmed)
				case strings.ContainsFunc(s, unicode.IsControl):
					addf("label %q: synonym %q contains control characters", l.Key, trimmed)
				}
				if dupes[trimmed] {
					addf("label %q: duplicate synonym %q in locale %q", l.Key, trimmed, locale)
				}
				dupes[trimmed] = true
			}
		}
	}

	// Graph checks over known keys, in canonical (sorted) order so the
	// error list is deterministic regardless of input order.
	keys := make([]string, 0, len(parent))
	for k := range parent {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := parent[k]
		if p == "" {
			continue // root
		}
		norm, ok := labels.NormalizeKey(p)
		if !ok || norm != p || !seen[p] {
			if p != k { // self-parent already reported above
				addf("label %q: parent %q is not a label in this taxonomy", k, p)
			}
			continue
		}
		// Walk up: cycle guard + depth guard.
		visited := map[string]bool{k: true}
		cur := p
		hops := 0
		for {
			if visited[cur] {
				addf("label %q: parent chain contains a cycle at %q", k, cur)
				break
			}
			visited[cur] = true
			hops++
			if hops > MaxTaxonomyDepth {
				addf("label %q: parent chain deeper than %d hops", k, MaxTaxonomyDepth)
				break
			}
			next := parent[cur]
			if next == "" {
				break
			}
			cur = next
		}
	}

	if len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	return nil
}

// Canonical returns a normalized copy for comparison and storage: labels
// sorted by key, synonym lists sorted, empty synonym maps dropped, and the
// slice never nil (so a zero Taxonomy canonicalizes to an empty list, not
// a JSON null).
func (t Taxonomy) Canonical() Taxonomy {
	out := Taxonomy{OrgID: strings.TrimSpace(t.OrgID), Labels: []Label{}, Version: t.Version}
	out.Labels = append(out.Labels, t.Labels...)
	sort.Slice(out.Labels, func(i, j int) bool { return out.Labels[i].Key < out.Labels[j].Key })
	for i := range out.Labels {
		l := &out.Labels[i]
		if len(l.Synonyms) == 0 {
			l.Synonyms = nil
			continue
		}
		syn := make(map[string][]string, len(l.Synonyms))
		for locale, list := range l.Synonyms {
			cp := append([]string(nil), list...)
			sort.Strings(cp)
			if len(cp) > 0 {
				syn[locale] = cp
			}
		}
		if len(syn) == 0 {
			l.Synonyms = nil
		} else {
			l.Synonyms = syn
		}
	}
	return out
}

// Equal reports structural equality of two taxonomies in canonical form,
// ignoring OrgID spelling (whitespace-trimmed) and Version: the store uses
// it to decide whether a PUT actually changed anything (version bumps only
// on real change).
func (t Taxonomy) Equal(other Taxonomy) bool {
	a, b := t.Canonical(), other.Canonical()
	if a.OrgID != b.OrgID || len(a.Labels) != len(b.Labels) {
		return false
	}
	for i := range a.Labels {
		la, lb := a.Labels[i], b.Labels[i]
		if la.Key != lb.Key || la.Parent != lb.Parent {
			return false
		}
		if len(la.Synonyms) != len(lb.Synonyms) {
			return false
		}
		for locale, sa := range la.Synonyms {
			sb, ok := lb.Synonyms[locale]
			if !ok || len(sa) != len(sb) {
				return false
			}
			for j := range sa {
				if sa[j] != sb[j] {
					return false
				}
			}
		}
	}
	return true
}
