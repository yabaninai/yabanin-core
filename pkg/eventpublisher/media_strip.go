package eventpublisher

// Media-history hygiene (owner decision I62, refining I26 for media files):
// request history retains only metadata and references for input and
// generated media — inline media bytes, base64/data URLs and multipart
// file contents must never be retained indirectly in JSON payload logs or
// persistent history buffers. The rule is profile-independent: the legacy
// full-content default keeps TEXT and tool-call content (I26) but never
// media bytes; the metadata-only profile drops whole captures on top.
//
// StripInlineMedia implements the producer side of that rule for the three
// in-flight capture fields (payload, upstream payload, upstream response):
//
//  1. data URLs (`data:<mime>;base64,<span>`): the base64 span is replaced
//     with an explicit marker; the media type stays as the retained
//     reference. Matches anywhere in the capture — including data URLs
//     hidden inside plain text fields or escaped tool-call arguments (the
//     same span shape the reservation estimator counts, reservation-side).
//  2. known base64 media carriers in provider wire JSON: values of the
//     `b64_json` key, and pure-base64 string values of a generic `data`
//     key (Anthropic base64 sources, Gemini inline_data, OpenAI
//     input_audio) at 128+ characters. Below the threshold a `data` value
//     is indistinguishable from a short identifier and stays untouched —
//     checksum/hex fields under other keys are never touched.
//
// Deliberate limits: URL-encoded (non-base64) data URLs and raw base64
// runs with no data: prefix and no carrier key are not recognized (they
// are indistinguishable from text); URL-safe base64 alphabets are not
// carrier keys on the mapped providers. Multipart file contents never
// reach these captures at all (the audio pipelines persist a metadata
// projection only).
//
// The strip is idempotent and byte-preserving for anything it does not
// recognize; the marker text is plain ASCII, safe inside JSON strings.

import (
	"fmt"
	"regexp"
	"strings"
)

// mediaStrippedMarker formats the explicit replacement for one stripped
// base64 span; %d is the length of the removed base64 run.
const mediaStrippedMarker = "[media stripped: %d b64 chars]"

var (
	// dataURLBase64 matches `data:[mime];base64,<span>` with an optional
	// mime type (RFC 2397 allows the empty form). The base64 span charset
	// is the standard alphabet; the span runs to the first character
	// outside it (a JSON quote, whitespace, or the capture end).
	dataURLBase64 = regexp.MustCompile(`data:(?:[a-zA-Z0-9.+-]+/[a-zA-Z0-9.+-]+)?;base64,[A-Za-z0-9+/=]+`)

	// base64JSONCarrier matches explicit media carrier keys with a
	// pure-base64 string value. `b64_json` is media by key contract (any
	// length); the generic `data` key requires a 128+ character run so
	// short identifiers and digests under other keys stay untouched.
	base64JSONB64Key  = regexp.MustCompile(`("b64_json"\s*:\s*")[A-Za-z0-9+/=]+(")`)
	base64JSONDataKey = regexp.MustCompile(`("data"\s*:\s*")[A-Za-z0-9+/=]{128,}(")`)
)

// StripInlineMedia applies the I62 media-history rule to one capture
// string: base64 media spans are replaced by explicit metadata markers,
// everything else passes through byte-identical. Idempotent.
func StripInlineMedia(capture string) string {
	if capture == "" {
		return ""
	}
	// Cheap pre-gate: all three patterns need one of these substrings.
	if !strings.Contains(capture, "data:") &&
		!strings.Contains(capture, "b64_json") &&
		!strings.Contains(capture, `"data"`) {
		return capture
	}
	out := dataURLBase64.ReplaceAllStringFunc(capture, func(match string) string {
		i := strings.Index(match, ";base64,")
		span := len(match) - i - len(";base64,")
		return match[:i+len(";base64,")] + fmt.Sprintf(mediaStrippedMarker, span)
	})
	out = base64JSONB64Key.ReplaceAllStringFunc(out, stripQuotedBase64Value)
	out = base64JSONDataKey.ReplaceAllStringFunc(out, stripQuotedBase64Value)
	return out
}

// stripQuotedBase64Value rewrites one `"key":"<b64 run>"` match, keeping
// the key and quotes and replacing only the value with the marker.
func stripQuotedBase64Value(match string) string {
	open := strings.IndexByte(match, '"')
	close := strings.LastIndexByte(match, '"')
	if open < 0 || close <= open {
		return match // unreachable for the anchored patterns; keep the match as-is
	}
	value := close - open - 1
	return match[:open+1] + fmt.Sprintf(mediaStrippedMarker, value) + match[close:]
}
