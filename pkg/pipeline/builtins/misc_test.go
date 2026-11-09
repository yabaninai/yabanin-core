package builtins

import (
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

func TestURLCheck_HostPolicy(t *testing.T) {
	params := map[string]any{"allow_hosts": []any{"api.example.com"}}
	res := runOne(t, NameURLCheck, params, reqPayload("visit https://api.example.com/x and https://evil.com/y."))
	assertRan(t, res)
	fs := findingsOf(res, "s1")
	if len(fs) != 1 {
		t.Fatalf("findings = %v, want 1 (evil.com; trailing dot trimmed)", fs)
	}
	if !strings.Contains(fs[0].Evidence, "evil.com") {
		t.Errorf("evidence = %q, want the offending host", fs[0].Evidence)
	}
	if fs[0].Span == "" {
		t.Errorf("span empty, want URL location")
	}
}

func TestURLCheck_DenyAndWildcard(t *testing.T) {
	// deny_hosts wins even with empty allow list.
	res := runOne(t, NameURLCheck, map[string]any{"deny_hosts": []any{"evil.com", "*.banned.io"}}, reqPayload(
		"see https://evil.com/a and https://sub.banned.io/b but https://ok.io/c"))
	assertRan(t, res)
	if got := len(findingsOf(res, "s1")); got != 2 {
		t.Errorf("findings = %d, want 2 (evil.com + sub.banned.io)", got)
	}
	// Wildcard does not cover the apex.
	res = runOne(t, NameURLCheck, map[string]any{"allow_hosts": []any{"*.example.com"}}, reqPayload(
		"https://sub.example.com fine, https://example.com flagged"))
	assertRan(t, res)
	if got := len(findingsOf(res, "s1")); got != 1 {
		t.Errorf("findings = %d, want 1 (apex not covered by wildcard)", got)
	}
}

func TestURLCheck_Schemes(t *testing.T) {
	// Default schemes are http/https: ftp is flagged.
	res := runOne(t, NameURLCheck, nil, reqPayload("grab ftp://files.example.com/a"))
	assertRan(t, res)
	fs := findingsOf(res, "s1")
	if len(fs) != 1 || !strings.Contains(fs[0].Evidence, "scheme not allowed") {
		t.Errorf("findings = %v, want scheme violation", fs)
	}
	// Custom scheme allow-list.
	res = runOne(t, NameURLCheck, map[string]any{"schemes": []any{"https"}}, reqPayload(
		"http://insecure.com/a https://secure.com/b"))
	assertRan(t, res)
	if got := len(findingsOf(res, "s1")); got != 1 {
		t.Errorf("findings = %d, want 1 (http flagged)", got)
	}
}

func TestURLCheck_Edges(t *testing.T) {
	// Empty payload and URL-free text.
	for _, text := range []string{"", "no urls in here"} {
		res := runOne(t, NameURLCheck, nil, reqPayload(text))
		assertRan(t, res)
		if fs := findingsOf(res, "s1"); len(fs) != 0 {
			t.Errorf("text %q: findings = %v, want none", text, fs)
		}
	}
	mustCompileErr(t, NameURLCheck, map[string]any{"schemes": []any{""}})
	mustCompileErr(t, NameURLCheck, map[string]any{"allow_hosts": []any{""}})
}

func TestCodeDetect_Languages(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string // category, "" = no finding
	}{
		{"sql", "SELECT id FROM users WHERE id=1; DELETE FROM logs;", "code.sql"},
		{"sql lowercase", "select * from t where x = 1 group by y", "code.sql"},
		{"python", "def run():\n    print(None)", "code.python"},
		{"typescript", "const x: number = 1; export default x;", "code.typescript"},
		{"prose with two sql words", "please update the docs where needed", ""},
		{"plain prose", "just an ordinary sentence about weather", ""},
	}
	for _, tc := range cases {
		res := runOne(t, NameCodeDetect, nil, reqPayload(tc.text))
		assertRan(t, res)
		fs := findingsOf(res, "s1")
		if tc.want == "" {
			if len(fs) != 0 {
				t.Errorf("%s: findings = %v, want none", tc.name, fs)
			}
			continue
		}
		if len(fs) != 1 || fs[0].Category != tc.want {
			t.Errorf("%s: findings = %v, want %s", tc.name, fs, tc.want)
		}
	}
}

func TestCodeDetect_LanguageFilter(t *testing.T) {
	res := runOne(t, NameCodeDetect, map[string]any{"languages": []any{"python"}},
		reqPayload("SELECT 1; DELETE 2; WHERE 3;"))
	assertRan(t, res)
	if fs := findingsOf(res, "s1"); len(fs) != 0 {
		t.Errorf("findings = %v, want none (sql not selected)", fs)
	}
	mustCompileErr(t, NameCodeDetect, map[string]any{"languages": []any{"rust"}})
}

func TestLanguage_ScriptClassification(t *testing.T) {
	cases := []struct {
		text     string
		allowed  []any
		wantFire bool
	}{
		{"привет мир как дела", []any{"ru"}, false},
		{"привет мир как дела", []any{"en"}, true},
		{"hello world how are you", []any{"en"}, false},
		{"hello world how are you", []any{"ru"}, true},
		{"привет hi", []any{"ru"}, false}, // 6 cyrillic vs 2 latin → ru dominates
		{"12345 !!!", []any{"en"}, true},  // no letters → other → not allowed
	}
	for _, tc := range cases {
		res := runOne(t, NameLanguage, map[string]any{"allowed": tc.allowed}, reqPayload(tc.text))
		assertRan(t, res)
		fs := findingsOf(res, "s1")
		if tc.wantFire && len(fs) != 1 {
			t.Errorf("text %q allowed %v: findings = %v, want 1", tc.text, tc.allowed, fs)
		}
		if !tc.wantFire && len(fs) != 0 {
			t.Errorf("text %q allowed %v: findings = %v, want none", tc.text, tc.allowed, fs)
		}
	}
}

func TestLanguage_Edges(t *testing.T) {
	// Empty payload: no letters, nothing to classify.
	res := runOne(t, NameLanguage, map[string]any{"allowed": []any{"en"}},
		&pipeline.Payload{Kind: pipeline.KindRequest})
	assertRan(t, res)
	if fs := findingsOf(res, "s1"); len(fs) != 0 {
		t.Errorf("empty payload findings = %v, want none", fs)
	}
	mustCompileErr(t, NameLanguage, map[string]any{})
	mustCompileErr(t, NameLanguage, map[string]any{"allowed": []any{"de"}})
}
