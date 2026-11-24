package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/stretchr/testify/require"
)

// An intact JSON document can still be an incomplete HTTP response. Only
// the fully delivered provider response may produce a successful charge.
func FuzzPaidCompletionResponse(f *testing.F) {
	f.Add("answer", uint16(17), uint16(3), uint16(0))
	f.Add("partial", uint16(31), uint16(7), uint16(1))
	f.Add("é\n", uint16(0), uint16(0), uint16(65535))
	f.Fuzz(func(t *testing.T, answer string, prompt, completion, missing uint16) {
		if len(answer) > 1024 {
			answer = answer[:1024]
		}
		quoted, err := json.Marshal(answer)
		require.NoError(t, err)
		body := fmt.Sprintf(`{"id":"fixture","choices":[{"text":%s}],"usage":{"prompt_tokens":%d,"completion_tokens":%d,"total_tokens":%d}}  `, quoted, prompt, completion, int(prompt)+int(completion))
		lost := int(missing) % (len(body) + 1)
		var contacts atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			contacts.Add(1)
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			_, _ = io.WriteString(w, body[:len(body)-lost])
		}))
		defer server.Close()
		gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "gpt-4o", Provider: "openai", UpstreamURL: server.URL, Enabled: true})
		store := &fakeInvocationStore{}
		gw.invocations = store
		rec := postCompletions(t, gw, `{"model":"m","prompt":"hello"}`)
		require.EqualValues(t, 1, contacts.Load())
		require.Len(t, store.admitted, 1)
		if lost > 0 {
			require.Equal(t, http.StatusBadGateway, rec.Code)
			require.Equal(t, "false", rec.Header().Get("X-Should-Retry"))
			require.Contains(t, rec.Body.String(), "failed to read upstream response")
			require.Empty(t, store.facts)
			return
		}
		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, body, rec.Body.String())
		require.Len(t, store.facts, 1)
		require.Equal(t, store.admitted[0].InvocationID, store.facts[0].InvocationID)
		require.Equal(t, strconv.Itoa(int(prompt)), store.facts[0].Fields["tokens_in"])
		require.Equal(t, strconv.Itoa(int(completion)), store.facts[0].Fields["tokens_out"])
	})
}
