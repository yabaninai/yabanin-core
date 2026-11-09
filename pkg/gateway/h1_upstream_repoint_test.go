package cli

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Audit H1: the cache route identity carries an endpoint-revision component.
// Behavioral pin (RED on a baseline without the fix): a warm entry written
// against upstream A must NOT be served after the model is re-pointed to
// upstream B — on the baseline the identity had no endpoint component and
// the stale entry was served verbatim from the old endpoint. The entry B
// writes for itself must replay for the following identical request, so the
// guard is a fail-closed cold start, not a permanent cache disable.
//
// Upstream distinctness is visible through the doubles' wire shapes: A
// answers with its own completion id/content, B with another.
func TestH1_CacheRepointedEndpointIsAMiss(t *testing.T) {
	a := newRT02Upstream(t)
	b := newRT02Upstream(t)
	gw := rt02ChatGateway(t, a, nil)
	c := newRT05Cache()
	gw.cache = c
	gw.res = stubModelResolver{
		"m": {ModelName: "m", Provider: "openai", UpstreamURL: a.srv.URL, Enabled: true},
	}

	body := `{"model":"m","messages":[{"role":"user","content":"h1-repoint"}]}`

	// Request 1: miss → A serves → production write under fp(A).
	rec := rt02Post(t, gw, body, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"content":"ok"`, "A's live answer")
	require.Eventually(t, func() bool { return c.writeCount() == 1 },
		2*time.Second, 10*time.Millisecond, "the miss must populate the cache")

	// Re-point the model to upstream B (same model name, new endpoint).
	gw.res = stubModelResolver{
		"m": {ModelName: "m", Provider: "openai", UpstreamURL: b.srv.URL, Enabled: true},
	}

	// Request 2: must MISS — the re-pointed request reaches B and is served
	// live, never A's sealed entry. Baseline RED: no endpoint component in
	// the identity, so the lookup hit A's entry and B was never called.
	rec = rt02Post(t, gw, body, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Empty(t, rec.Header().Get("X-Cache"),
		"an entry from the pre-repoint endpoint must not serve the re-pointed route")
	assert.Equal(t, 1, b.totalCalls(), "the re-pointed request must reach upstream B")
	assert.Equal(t, 1, a.totalCalls(), "upstream A must not be consulted again")

	// Request 3: B's own fresh entry must replay (cold-start, then warm).
	rec = rt02Post(t, gw, body, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "EXACT", rec.Header().Get("X-Cache"),
		"the re-pointed endpoint's own entry replays")
	assert.Equal(t, 1, b.totalCalls(), "no second upstream call after B's write")
}
