package dataclass

import (
	"errors"
	"testing"
)

// E04-P01-W01-C03 battery. Acceptance (dispatch §10):
//   - determinism: the same input always yields the same verdict (one
//     input ⇒ one verdict), checked by running every corpus case twice;
//   - ambiguity is always a refusal (ErrUnknownType), never "plain by
//     default" — fail-closed;
//   - form is never sniffed (caller-declared type only).

func TestDetectType_Plain(t *testing.T) {
	for _, text := range []string{
		"Quarterly review notes for the routing team.",
		"Привет, это обычная заметка без какой-либо разметки.",
		"Two lines of prose\nwith no structure at all.",
		"A lone dash list item\nis not enough structure.", // 1 md signal only
		`"quoted scalar string"`,                          // valid JSON scalar root: not claimed, no structure → plain
	} {
		ty, err := DetectType(text)
		if err != nil || ty != TextTypePlain {
			t.Errorf("DetectType(%q) = (%q, %v), want plain", text, ty, err)
		}
	}
}

func TestDetectType_Markdown(t *testing.T) {
	for _, text := range []string{
		"# Heading\n\n- item one\n- item two",             // heading + list
		"```\ncode\n```\n\n[a link](https://example.com)", // fence + link
		"Doc\n\n1. first\n2. second\n\n## Section",        // list + heading
	} {
		ty, err := DetectType(text)
		if err != nil || ty != TextTypeMarkdown {
			t.Errorf("DetectType(%q) = (%q, %v), want markdown", text, ty, err)
		}
	}
}

func TestDetectType_JSON(t *testing.T) {
	for _, text := range []string{
		`{"k":[1,2,3]}`,
		`[1,2,3]`,
		"{\n  \"a\": 1,\n  \"b\": {\"c\": 2}\n}",
		"  \n [\"nested\", {\"x\": \"y\"}] \n",
	} {
		ty, err := DetectType(text)
		if err != nil || ty != TextTypeJSON {
			t.Errorf("DetectType(%q) = (%q, %v), want json", text, ty, err)
		}
	}
}

func TestDetectType_Code(t *testing.T) {
	// Every case carries at least TWO independent code signals (the
	// threshold); single-signal texts are deliberately plain — see the
	// plain corpus.
	for _, text := range []string{
		"func main() {\n\treturn\n}",                         // starter keyword + multiline brace block
		"// note one\n// note two\nlet a = 1;\nlet b = 2;\n", // two comment lines + two semicolon lines
		"import os\nx = 1;\ny = 2;\n",                        // starter keyword + two semicolon lines
		"// setup\n// run\nfunc main() {}\n",                 // two comment lines + starter keyword
		"/* header */\n// note\n{\n  block\n}\n",             // two comment lines + multiline brace block
		"x = 1;\ny = 2;\nif (x) {\n\treturn\n}\n",            // two semicolon lines + multiline brace block
	} {
		ty, err := DetectType(text)
		if err != nil || ty != TextTypeCode {
			t.Errorf("DetectType(%q) = (%q, %v), want code", text, ty, err)
		}
	}
}

func TestDetectType_SingleSignalStaysPlain(t *testing.T) {
	// Exactly one structural signal is chat noise, not structure: these
	// must all stay plain (the sniffer refuses to guess from one hint).
	for _, text := range []string{
		"let a = 1;\nlet b = 2;\n",                      // semicolon signal (one of four) alone
		"# only a heading here\n",                       // heading signal alone
		"just one [link](https://example.com) in prose", // link signal alone
		"func mentioned in prose about a function",      // starter-keyword signal alone
	} {
		ty, err := DetectType(text)
		if err != nil || ty != TextTypePlain {
			t.Errorf("DetectType(%q) = (%q, %v), want plain (single signal must not tip the verdict)", text, ty, err)
		}
	}
}

func TestDetectType_AmbiguousIsRefusalNotGuess(t *testing.T) {
	ambiguous := []string{
		// Markdown doc with an embedded fenced code block: md signals
		// (fence+list) AND code signals (starter keyword + braces).
		"# README\n\n- step one\n- step two\n\n```\nfunc main() {\n\treturn\n}\n```\n",
		// Fence + link (md) meets two semicolon lines + starter (code).
		"```\nimport os\nx = 1;\ny = 2;\n```\nsee [docs](https://example.com)\n",
	}
	for _, text := range ambiguous {
		ty, err := DetectType(text)
		if !errors.Is(err, ErrUnknownType) {
			t.Errorf("DetectType(%q) = (%q, %v): ambiguity must be a typed refusal, never a guess (fail-closed)", text, ty, err)
		}
		if ty != "" {
			t.Errorf("ambiguity must not carry a type, got %q", ty)
		}
	}
}

func TestDetectType_EmptyAndIdentitylessRefused(t *testing.T) {
	for _, text := range []string{"", " ", "\t\n  \n", "123 456", "!!! ... ???", "— – •"} {
		ty, err := DetectType(text)
		if !errors.Is(err, ErrUnknownType) {
			t.Errorf("DetectType(%q) = (%q, %v), want ErrUnknownType (fail-closed)", text, ty, err)
		}
	}
}

func TestDetectType_DeterministicOneInputOneVerdict(t *testing.T) {
	corpus := []string{
		"Quarterly review notes for the routing team.",
		"Привет, это обычная заметка без какой-либо разметки.",
		"# Heading\n\n- item one\n- item two",
		"```\ncode\n```\n\n[a link](https://example.com)",
		`{"k":[1,2,3]}`,
		"{\n  \"a\": 1\n}",
		"func main() {\n\treturn\n}",
		"let a = 1;\nlet b = 2;\n",
		"# README\n\n- step one\n- step two\n\n```\nfunc main() {\n\treturn\n}\n```\n",
		"", " ", "123 456",
	}
	for _, text := range corpus {
		ty1, err1 := DetectType(text)
		ty2, err2 := DetectType(text)
		if ty1 != ty2 || (err1 == nil) != (err2 == nil) || detectErrMsg(err1) != detectErrMsg(err2) {
			t.Errorf("non-deterministic verdict for %q: (%q,%v) vs (%q,%v)", text, ty1, err1, ty2, err2)
		}
		// The returned type, when present, is always from the sniffable
		// subset — form is never produced.
		switch ty1 {
		case "", TextTypePlain, TextTypeMarkdown, TextTypeJSON, TextTypeCode:
		default:
			t.Errorf("DetectType produced non-sniffable type %q for %q", ty1, text)
		}
	}
}

func detectErrMsg(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
