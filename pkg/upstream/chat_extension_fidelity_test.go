package upstream

// N07-P01-T04 — unit-level pin for the chat JSON path's extension value
// fidelity (facet 3, artifacts/internal-delivery-program/N07-P01/T01-scope-2026-10-30.md).
//
// forward() applies the per-hop model override to every non-streaming chat
// request. The legacy map[string]interface{} round-trip re-encoded every
// field through float64, silently corrupting integers beyond 2^53 in ANY
// consumer field (known or extension). The native passthrough endpoints
// already use OverrideModelRaw for exactly this reason; the chat path must
// give its payloads the same fidelity.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestForwardJSON_PreservesBigIntExtensionValues(t *testing.T) {
	var mu sync.Mutex
	var sent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		mu.Lock()
		sent = string(raw)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl-1","choices":[]}`))
	}))
	t.Cleanup(srv.Close)

	client := newTestClient(t, srv)

	body := []byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}],"x_ext_id":9007199254740993}`)
	_, err := client.ForwardJSON(context.Background(), body, "resolved-model", "test-key")
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	assert.Contains(t, sent, `"x_ext_id":9007199254740993`,
		"extension integer beyond 2^53 must survive the model-override re-encode exactly")
	assert.NotContains(t, sent, "9007199254740992",
		"the float64-nearest corrupted value must never reach the upstream")
	assert.Contains(t, sent, `"model":"resolved-model"`, "model override must still apply")
}
