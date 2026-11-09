package dataclass

import (
	"errors"
	"strings"
	"testing"
)

// E04-P01-W02-C01 battery. Acceptance (dispatch §10):
//   - allowed: a valid taxonomy passes;
//   - empty: an EMPTY label list is VALID (the fixed no-op choice,
//     aligned with GET's empty default) — pinned here so the choice is
//     observable, not accidental;
//   - adversarial: key>63, illegal characters, cycles, depth 3 — refusal
//     WITH the full error list, deterministically ordered.

func validTaxonomy() Taxonomy {
	return Taxonomy{
		OrgID: "org-1",
		Labels: []Label{
			{Key: "personal"},
			{Key: "personal.ru_passport", Parent: "personal", Synonyms: map[string][]string{
				"ru": {"паспорт", "серия и номер"},
			}},
			{Key: "credentials.api_key", Parent: "credentials", Synonyms: map[string][]string{
				"en": {"api key", "access token"},
			}},
			{Key: "credentials"},
		},
	}
}

func TestTaxonomy_ValidMultiLevelPasses(t *testing.T) {
	tax := validTaxonomy()
	if err := tax.Validate(); err != nil {
		t.Fatalf("allowed scenario: valid taxonomy must pass, got %v", err)
	}
}

func TestTaxonomy_EmptyLabelListIsValidNoOp(t *testing.T) {
	// FIXED CHOICE (dispatch W01/W02 AC "зафиксировать одно из двух"):
	// empty list = valid no-op, aligned with GET returning an empty
	// default taxonomy; PUT [] is the idempotent reset, not an error.
	tax := Taxonomy{OrgID: "org-1", Labels: []Label{}}
	if err := tax.Validate(); err != nil {
		t.Fatalf("empty label list must be valid (no-op), got %v", err)
	}
	if got := tax.Canonical().Labels; got == nil {
		t.Fatal("canonical form must use an empty slice, never nil (JSON null hazard)")
	}
}

func TestTaxonomy_AdversarialRefusalsWithFullList(t *testing.T) {
	longKey := "k" + strings.Repeat("a", 63) // 64 bytes > MaxKeyLen
	deepChain := func() Taxonomy {
		return Taxonomy{OrgID: "org-1", Labels: []Label{
			{Key: "a"},
			{Key: "b", Parent: "a"},
			{Key: "c", Parent: "b"},
			{Key: "d", Parent: "c"}, // 3 hops up from d — refused
		}}
	}
	cases := []struct {
		name  string
		tax   Taxonomy
		wants []string
	}{
		{"key over 63", Taxonomy{OrgID: "o", Labels: []Label{{Key: longKey}}}, []string{longKey}},
		{"illegal characters", Taxonomy{OrgID: "o", Labels: []Label{{Key: "PII!"}, {Key: "ру_ключ"}, {Key: "a%b"}, {Key: "-lead"}}}, []string{"PII!", "ру_ключ", "a%b", "-lead"}},
		{"non-canonical key", Taxonomy{OrgID: "o", Labels: []Label{{Key: "Personal.Data"}}}, []string{"not canonical"}},
		{"reserved prefix", Taxonomy{OrgID: "o", Labels: []Label{{Key: "yabanin.core"}}}, []string{"reserved prefix"}},
		{"duplicate keys", Taxonomy{OrgID: "o", Labels: []Label{{Key: "a"}, {Key: "a"}}}, []string{"duplicate"}},
		{"missing parent", Taxonomy{OrgID: "o", Labels: []Label{{Key: "a", Parent: "ghost"}}}, []string{"ghost"}},
		{"self parent", Taxonomy{OrgID: "o", Labels: []Label{{Key: "a", Parent: "a"}}}, []string{"parent is itself"}},
		{"cycle", Taxonomy{OrgID: "o", Labels: []Label{{Key: "a", Parent: "b"}, {Key: "b", Parent: "a"}}}, []string{"cycle"}},
		{"depth 3", deepChain(), []string{"deeper than 2 hops"}},
		{"bad locale", Taxonomy{OrgID: "o", Labels: []Label{{Key: "a", Synonyms: map[string][]string{"fr": {"oui"}}}}}, []string{"locale"}},
		{"empty synonym", Taxonomy{OrgID: "o", Labels: []Label{{Key: "a", Synonyms: map[string][]string{"ru": {"  "}}}}}, []string{"empty synonym"}},
		{"oversized synonym", Taxonomy{OrgID: "o", Labels: []Label{{Key: "a", Synonyms: map[string][]string{"en": {strings.Repeat("x", MaxSynonymLen+1)}}}}}, []string{"exceeds"}},
		{"control char synonym", Taxonomy{OrgID: "o", Labels: []Label{{Key: "a", Synonyms: map[string][]string{"en": {"to\x00ken"}}}}}, []string{"control"}},
		{"duplicate synonym", Taxonomy{OrgID: "o", Labels: []Label{{Key: "a", Synonyms: map[string][]string{"en": {"key", "key"}}}}}, []string{"duplicate synonym"}},
		{"too many synonyms", Taxonomy{OrgID: "o", Labels: []Label{{Key: "a", Synonyms: map[string][]string{"en": makeSynonyms(MaxSynonymsPerLocale + 1)}}}}, []string{"exceeds"}},
		{"too many labels", Taxonomy{OrgID: "o", Labels: makeLabels(MaxTaxonomyLabels + 1)}, []string{"label count"}},
		{"blank org", Taxonomy{OrgID: "  ", Labels: []Label{{Key: "a"}}}, []string{"org_id is blank"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.tax.Validate()
			if err == nil {
				t.Fatalf("adversarial case %q must be refused", tc.name)
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("refusal must be a *ValidationError, got %T", err)
			}
			if len(ve.Errors) == 0 {
				t.Fatal("refusal must carry a non-empty error list")
			}
			for _, want := range tc.wants {
				found := false
				for _, line := range ve.Errors {
					if strings.Contains(line, want) {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("error list must mention %q; got %v", want, ve.Errors)
				}
			}
		})
	}
}

func TestTaxonomy_AllProblemsInOneList(t *testing.T) {
	// Multiple problems in one taxonomy → ONE refusal listing every
	// problem (not first-error).
	tax := Taxonomy{OrgID: "", Labels: []Label{
		{Key: "BAD!"},
		{Key: "ok", Parent: "ghost"},
	}}
	err := tax.Validate()
	if err == nil {
		t.Fatal("must be refused")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want *ValidationError, got %T", err)
	}
	if len(ve.Errors) < 3 {
		t.Fatalf("every problem must be listed, got %v", ve.Errors)
	}
}

func TestTaxonomy_ErrorsAreDeterministic(t *testing.T) {
	tax := validTaxonomy()
	tax.Labels = append(tax.Labels,
		Label{Key: "zz", Parent: "ghost"}, // missing-parent error (graph phase)
		Label{Key: "aa", Parent: "aa2"},
		Label{Key: "aa2", Parent: "aa3"},
		Label{Key: "aa3", Parent: "aa4"},
		Label{Key: "aa4"}, // aa's chain is 3 hops deep → depth error (graph phase)
	)
	e1 := tax.Validate()
	e2 := tax.Validate()
	if e1 == nil || e2 == nil {
		t.Fatal("must be refused both times")
	}
	if e1.Error() != e2.Error() {
		t.Fatalf("same input must yield the identical error list:\n%v\nvs\n%v", e1, e2)
	}
	// Graph checks run over sorted keys: the aa-chain error precedes the
	// zz one regardless of slice order.
	msgs := e1.(*ValidationError).Errors
	aaIdx, zzIdx := -1, -1
	for i, m := range msgs {
		if strings.HasPrefix(m, "label \"aa\"") && aaIdx == -1 {
			aaIdx = i
		}
		if strings.HasPrefix(m, "label \"zz\"") && zzIdx == -1 {
			zzIdx = i
		}
	}
	if aaIdx == -1 || zzIdx == -1 || aaIdx > zzIdx {
		t.Fatalf("graph errors must be sorted by key for determinism, got %v", msgs)
	}
}

func TestTaxonomy_EqualIgnoresOrderAndVersion(t *testing.T) {
	base := validTaxonomy()
	shuffled := validTaxonomy()
	shuffled.Labels = []Label{shuffled.Labels[3], shuffled.Labels[1], shuffled.Labels[0], shuffled.Labels[2]}
	shuffled.Version = base.Version + 7
	if !base.Equal(shuffled) {
		t.Fatal("reordered labels, reordered synonym lists and a different version must still be equal")
	}

	changedParent := validTaxonomy()
	changedParent.Labels[1].Parent = "credentials"
	if base.Equal(changedParent) {
		t.Fatal("parent change must not be equal (version must bump)")
	}

	changedSynonym := validTaxonomy()
	changedSynonym.Labels[1].Synonyms["ru"] = append(changedSynonym.Labels[1].Synonyms["ru"], "номер")
	if base.Equal(changedSynonym) {
		t.Fatal("synonym change must not be equal (version must bump)")
	}

	differentOrg := validTaxonomy()
	differentOrg.OrgID = "org-2"
	if base.Equal(differentOrg) {
		t.Fatal("different org must not be equal")
	}
}

func makeSynonyms(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = strings.Repeat("s", 3) + string(rune('a'+i%26)) + string(rune('0'+i/26%10))
	}
	return out
}

func makeLabels(n int) []Label {
	out := make([]Label, n)
	for i := range out {
		out[i] = Label{Key: "l" + string(rune('a'+i%26)) + string(rune('0'+i/26%10)) + string(rune('0'+i/100%10))}
	}
	return out
}
