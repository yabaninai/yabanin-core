package provider

// N07-P05-T05: the anthropic adapter must fail closed on media-bearing
// request shapes it cannot map. Unknown content-part types, nil/empty or
// unmappable image URLs and non-base64 data URLs used to be silently
// skipped in contentBlocks — a client that sent such a part received a
// text-only answer pretending the part never existed (a false success on a
// negative scenario). Like bedrock/vertex (N07-P05-T02), the adapter now
// raises the typed UnsupportedFeatureError before any byte leaves the
// gateway; the gateway answers an explicit 400 unsupported_feature.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestN07P5T05_AnthropicUnmappablePartsFailClosed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		// wantInReason is a substring the adapter's reason must carry so the
		// client can tell which shape was refused.
		wantInReason string
	}{
		{
			name:         "unknown content part type",
			body:         `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"hi"},{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}]}]}`,
			wantInReason: `content part type "input_audio"`,
		},
		{
			name:         "image_url without url object",
			body:         `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url"}]}]}`,
			wantInReason: "image_url part has no url object",
		},
		{
			name:         "image_url with empty url",
			body:         `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":""}}]}]}`,
			wantInReason: "image URL scheme is not mapped",
		},
		{
			name:         "image_url with unmappable scheme",
			body:         `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"ftp://example.invalid/y.png"}}]}]}`,
			wantInReason: "image URL scheme is not mapped",
		},
		{
			name:         "data URL that is not a base64 payload",
			body:         `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png,not-base64"}}]}]}`,
			wantInReason: "data URL is not a base64 image payload",
		},
		{
			name:         "assistant message with unknown part type",
			body:         `{"model":"m","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":[{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}]}]}`,
			wantInReason: `content part type "input_audio"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, err := chatToAnthropicRequest([]byte(tc.body))
			require.Error(t, err, "the unmappable shape must be rejected, not silently dropped")
			assert.Nil(t, out, "no translated body may be produced for a rejected request")
			var ufe *UnsupportedFeatureError
			require.ErrorAs(t, err, &ufe, "the rejection must be the typed UnsupportedFeatureError, got: %v", err)
			assert.Equal(t, "anthropic", ufe.Provider)
			assert.Contains(t, ufe.Reason, tc.wantInReason)
			assert.Contains(t, ufe.Reason, "rejecting instead of silently dropping",
				"the reason carries the fail-closed convention text")
		})
	}
}

// Positive controls: the mapping itself is unchanged — well-formed base64
// data URLs and http(s) references still translate to image blocks, and
// plain text still translates without an image block.
func TestN07P5T05_AnthropicMappablePartsStillTranslate(t *testing.T) {
	t.Parallel()
	imageCases := []string{
		`{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}}]}]}`,
		`{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid/y.png"}}]}]}`,
		`{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"http://example.invalid/y.png"}}]}]}`,
	}
	for _, body := range imageCases {
		out, err := chatToAnthropicRequest([]byte(body))
		require.NoError(t, err, "body: %s", body)
		assert.Contains(t, string(out), `"type":"image"`, "body: %s", body)
	}
	out, err := chatToAnthropicRequest([]byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"plain"}]}]}`))
	require.NoError(t, err)
	assert.Contains(t, string(out), `"text":"plain"`)
	assert.NotContains(t, string(out), `"type":"image"`)
}
