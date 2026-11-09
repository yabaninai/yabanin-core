package llmjudge

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestParseVerdict_CleanJSON(t *testing.T) {
	v, err := ParseVerdict(`{"findings":[{"category":"toxicity","severity":"high","confidence":0.93,"evidence":"quote"}],"summary":"toxic"}`, 256)
	if err != nil {
		t.Fatalf("ParseVerdict: %v", err)
	}
	if len(v.Findings) != 1 || v.Findings[0].Category != "toxicity" || v.Findings[0].Severity != "high" {
		t.Fatalf("findings mismatch: %+v", v.Findings)
	}
	if got := v.Findings[0].confidence(); got != 0.93 {
		t.Fatalf("confidence = %v, want 0.93", got)
	}
}

func TestParseVerdict_CleanVerdict(t *testing.T) {
	for _, doc := range []string{
		`{"findings":[],"summary":"clean"}`,
		`{"findings":null}`,
		`{"verdict":"clean","findings":[]}`,
	} {
		v, err := ParseVerdict(doc, 256)
		if err != nil {
			t.Fatalf("ParseVerdict(%s): %v", doc, err)
		}
		if len(v.Findings) != 0 {
			t.Fatalf("findings = %+v, want none", v.Findings)
		}
	}
}

func TestParseVerdict_Fenced(t *testing.T) {
	v, err := ParseVerdict("```json\n{\"findings\":[{\"category\":\"toxicity\",\"confidence\":0.9}]}\n```", 256)
	if err != nil {
		t.Fatalf("ParseVerdict: %v", err)
	}
	if len(v.Findings) != 1 {
		t.Fatalf("findings = %+v", v.Findings)
	}
}

func TestParseVerdict_ProseWrapped(t *testing.T) {
	v, err := ParseVerdict("Here is my verdict: {\"findings\":[{\"category\":\"pii\",\"confidence\":0.5}]} — hope that helps!", 256)
	if err != nil {
		t.Fatalf("ParseVerdict: %v", err)
	}
	if len(v.Findings) != 1 || v.Findings[0].Category != "pii" {
		t.Fatalf("findings = %+v", v.Findings)
	}
}

func TestParseVerdict_Malformed(t *testing.T) {
	for _, doc := range []string{
		"",
		"looks fine to me",
		"no braces here at all",
		`{"findings": "not a list"}`,
		`[1,2,3]`,
	} {
		if _, err := ParseVerdict(doc, 256); err == nil {
			t.Errorf("ParseVerdict(%q) must fail", doc)
		}
	}
}

func TestParseVerdict_EmptyCategoryIsMalformed(t *testing.T) {
	if _, err := ParseVerdict(`{"findings":[{"category":"  ","confidence":0.9}]}`, 256); err == nil {
		t.Fatal("empty category must be a malformed verdict")
	}
}

func TestParseVerdict_MissingConfidenceFailsClosed(t *testing.T) {
	v, err := ParseVerdict(`{"findings":[{"category":"toxicity"}]}`, 256)
	if err != nil {
		t.Fatalf("ParseVerdict: %v", err)
	}
	if got := v.Findings[0].confidence(); got != 1 {
		t.Fatalf("omitted confidence = %v, want 1 (fail-closed)", got)
	}
}

func TestParseVerdict_ConfidenceClamped(t *testing.T) {
	v, err := ParseVerdict(`{"findings":[{"category":"a","confidence":2.5},{"category":"b","confidence":-1}]}`, 256)
	if err != nil {
		t.Fatalf("ParseVerdict: %v", err)
	}
	if got := v.Findings[0].confidence(); got != 1 {
		t.Errorf("high clamp = %v, want 1", got)
	}
	if got := v.Findings[1].confidence(); got != 0 {
		t.Errorf("low clamp = %v, want 0", got)
	}
}

func TestParseVerdict_EvidenceTruncated(t *testing.T) {
	long := strings.Repeat("x", 500)
	v, err := ParseVerdict(`{"findings":[{"category":"a","evidence":"`+long+`"}]}`, 100)
	if err != nil {
		t.Fatalf("ParseVerdict: %v", err)
	}
	got := v.Findings[0].Evidence
	if n := utf8.RuneCountInString(got); n != 101 || !strings.HasSuffix(got, "…") {
		t.Fatalf("evidence runes = %d, want 101 with ellipsis suffix (%q)", n, got)
	}
}

func TestFindingAction_ThresholdRule(t *testing.T) {
	const th = DefaultThreshold // 0.8
	for _, tc := range []struct {
		conf float64
		want string
	}{
		{0.79, "flag"},
		{0.80, "deny"}, // boundary: >= threshold denies (documented)
		{0.81, "deny"},
		{0, "flag"},
		{1, "deny"},
	} {
		if got := string(findingAction(tc.conf, th)); got != tc.want {
			t.Errorf("findingAction(%v) = %s, want %s", tc.conf, got, tc.want)
		}
	}
}
