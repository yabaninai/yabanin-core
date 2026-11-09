package shadow

// N07-P05-T04: the shadow mirror event rides the same loggerd insert path
// as request.completed rows — the I62 media-history rule applies to its
// payload too: the mirrored request body keeps its text, loses its inline
// media bytes (base64/data URLs), and marks the strip explicitly.

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/provider"
)

func TestN07P5T04_ShadowMirrorEvent_MediaStripped(t *testing.T) {
	pngB64 := base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\n"))
	body := `{"model":"primary","messages":[{"role":"user","content":[` +
		`{"type":"text","text":"describe"},{"type":"image_url","image_url":{"url":"data:image/png;base64,` + pngB64 + `"}}]}]}`

	ev := buildEvent(Job{
		RequestID:    "req-shadow-t04",
		PrimaryModel: "primary",
		ShadowModel:  "shadow",
		Body:         []byte(body),
	}, provider.Usage{PromptTokens: 3, CompletionTokens: 2}, 0.0001, 1500*time.Millisecond)

	require.NotNil(t, ev)
	assert.Equal(t, "request.shadow_completed", ev.EventType)
	assert.NotContains(t, ev.Payload, pngB64, "mirrored media bytes must not persist (I62)")
	assert.Contains(t, ev.Payload, `"describe"`, "mirrored text content survives")
	assert.Contains(t, ev.Payload, "media stripped", "explicit strip marker in the mirror payload")
}
