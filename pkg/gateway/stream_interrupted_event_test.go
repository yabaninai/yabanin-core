package cli

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/resolver"
)

func TestChatStreamDiscardsInterruptedDataEvent(t *testing.T) {
	const prefix = "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n"
	for name, tail := range map[string]string{
		"single line": "data: {\"id\":",
		"multiline":   "data: {\"id\":\"partial\",\ndata: \"choices\":",
	} {
		t.Run(name, func(t *testing.T) {
			upstream := breakServer(t, prefix+tail)
			defer upstream.Close()
			gateway := streamTestGateway(upstream.URL)
			rec := h3ServeStream(t, gateway, resolver.ModelInfo{ModelName: "m", Enabled: true})
			require.Equal(t, http.StatusOK, rec.Code)
			out := rec.Body.String()
			require.True(t, strings.HasPrefix(out, prefix))
			frames := t08Frames(t, out)
			require.Len(t, frames, 3)
			require.Contains(t, frames[1], "stream interrupted")
			require.Equal(t, "[DONE]", frames[2])
		})
	}
}
