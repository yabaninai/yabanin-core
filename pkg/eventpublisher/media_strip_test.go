package eventpublisher

// N07-P05-T04 unit pins for StripInlineMedia — the I62 media-history rule:
// only metadata/references of media persist; inline base64 bytes never do.
// The rule must be idempotent, byte-preserving for non-media text, and
// explicit (a visible marker, never a silent edit).

import (
	"strings"
	"testing"
)

var (
	t04TinyB64  = "iVBORw0KGgoAAAANSUhEUg=="                                             // 28 chars
	t04AudioB64 = strings.Repeat("SGVsbG8", 40) + "=="                                   // 282 chars, audio-sized
	t04URLB64   = strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZQ", 6) + "==" // 200 chars
	t04Marker   = "media stripped"
)

// T04: data URLs lose their base64 span but keep the media reference (mime
// type) so history shows WHAT the media was without the bytes.
func TestStripInlineMedia_DataURLStrippedReferenceKept(t *testing.T) {
	in := `{"image_url":{"url":"data:image/png;base64,` + t04TinyB64 + `"}}`
	out := StripInlineMedia(in)
	if strings.Contains(out, t04TinyB64) {
		t.Fatalf("base64 span persisted: %q", out)
	}
	if !strings.Contains(out, "data:image/png;base64,") {
		t.Fatalf("mime reference lost: %q", out)
	}
	if !strings.Contains(out, t04Marker) {
		t.Fatalf("strip not explicit: %q", out)
	}
}

// T04: a hidden data URL pasted inside a plain text field is caught the
// same way — the negative card criterion.
func TestStripInlineMedia_HiddenDataURLInsideText(t *testing.T) {
	in := `{"content":[{"type":"text","text":"see data:application/pdf;base64,` + t04URLB64 + ` and describe"}]}`
	out := StripInlineMedia(in)
	if strings.Contains(out, t04URLB64) {
		t.Fatalf("hidden data URL bytes persisted: %q", out)
	}
	if !strings.Contains(out, "see data:application/pdf;base64,") || !strings.Contains(out, "and describe") {
		t.Fatalf("surrounding text damaged: %q", out)
	}
}

// T04: empty-mime data URLs (`data:;base64,...`) are media by intent.
func TestStripInlineMedia_EmptyMimeDataURL(t *testing.T) {
	in := "data:;base64," + t04TinyB64
	if out := StripInlineMedia(in); strings.Contains(out, t04TinyB64) {
		t.Fatalf("empty-mime data URL persisted: %q", out)
	}
}

// T04: provider wire carriers — Anthropic base64 source blocks, Gemini
// inline_data, OpenAI input_audio — lose the bytes under their `data` keys.
func TestStripInlineMedia_ProviderCarriers(t *testing.T) {
	cases := []string{
		`{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + t04URLB64 + `"}}`,
		`{"inline_data":{"mime_type":"image/png","data":"` + t04URLB64 + `"}}`,
		`{"input_audio":{"data":"` + t04AudioB64 + `","format":"wav"}}`,
		`{"b64_json":"` + t04TinyB64 + `"}`,
	}
	for i, in := range cases {
		out := StripInlineMedia(in)
		if strings.Contains(out, t04URLB64) || strings.Contains(out, t04AudioB64) || strings.Contains(out, t04TinyB64) {
			t.Fatalf("case %d: carrier bytes persisted: %q", i, out)
		}
		if !strings.Contains(out, t04Marker) {
			t.Fatalf("case %d: strip not explicit: %q", i, out)
		}
	}
}

// T04: sub-threshold generic `data` values stay untouched (sha256/short
// identifiers are not media); the generic-data rule is threshold-gated.
func TestStripInlineMedia_ShortDataValueUntouched(t *testing.T) {
	// 124-char value: under the 128-char carrier threshold.
	short := strings.Repeat("a", 124)
	in := `{"data":"` + short + `"}`
	if out := StripInlineMedia(in); out != in {
		t.Fatalf("short data value was rewritten: %q -> %q", in, out)
	}
	// A sha256 hex digest under a checksum key is never touched.
	sum := strings.Repeat("ab", 32) // 64 chars
	in = `{"checksum":"` + sum + `"}`
	if out := StripInlineMedia(in); out != in {
		t.Fatalf("checksum rewritten: %q -> %q", in, out)
	}
}

// T04: non-media text (prose containing the word "data:", code samples,
// hex) passes through byte-identical.
func TestStripInlineMedia_TextPassthroughByteIdentical(t *testing.T) {
	cases := []string{
		`{"text":"read the docs at data: or data:?;base64, no"}`,
		`{"content":"plain prose without media"}`,
		`{"tool_call":{"name":"run","arguments":"{\"path\":\"/tmp/x\"}"}}`,
		`{"data":[1,2,3]}`,
		`{"data":"short"}`,
		`{"sha":"` + strings.Repeat("ab", 64) + `"}`,
	}
	for i, in := range cases {
		if out := StripInlineMedia(in); out != in {
			t.Fatalf("case %d: text capture rewritten: %q -> %q", i, in, out)
		}
	}
}

// T04: empty captures and idempotency — stripping a stripped capture is a
// no-op.
func TestStripInlineMedia_EmptyAndIdempotent(t *testing.T) {
	if got := StripInlineMedia(""); got != "" {
		t.Fatalf("empty capture changed: %q", got)
	}
	in := `{"url":"data:image/png;base64,` + t04TinyB64 + `"}`
	once := StripInlineMedia(in)
	twice := StripInlineMedia(once)
	if once != twice {
		t.Fatalf("strip is not idempotent:\nonce:  %q\ntwice: %q", once, twice)
	}
}
