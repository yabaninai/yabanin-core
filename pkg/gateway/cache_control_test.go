package cli

// CACHE-01 regressions (DEEP-AUDIT 2026-10-31, P1): the cache opt-out
// contract is a Cache-Control DIRECTIVE check, not a whole-header byte
// comparison. Per RFC 9111 §5.2 directive names are case-insensitive and
// the field value is a comma-separated list that may also arrive as several
// header lines. Every no-store spelling below must keep the request out of
// the cache on all three paths at once: no lookup, no write, no stream
// recording — while a plain sibling request still populates and hits the
// cache (the skips stay selective, not a dead path).

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lookupCount exposes the rt05Cache lookup counter for the no-lookup pin.
func (c *rt05Cache) lookupCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lookups
}

// cache01Post posts a chat completion with the given raw Cache-Control
// header values (each argument becomes its own header line, reproducing the
// multi-line field folding Header.Get can never see past).
func cache01Post(t *testing.T, gw *gateway, body string, ccValues ...string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Org-Id", "org-a")
	if len(ccValues) > 0 {
		r.Header["Cache-Control"] = ccValues
	}
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)
	return rec
}

func TestCACHE01_NoStore_DirectiveForms_NoLookupNoWrite_JSON(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	c := newRT05Cache()
	gw.cache = c

	const body = `{"model":"m","messages":[{"role":"user","content":"cache01-json"}]}`

	// Every no-store spelling: fresh upstream answer, no cache lookup, no
	// cache write. The JSON cache write (chat.go) is synchronous, so the
	// absence pins below are deterministic at response completion.
	variants := []struct {
		name    string
		headers []string
	}{
		{"compound single line", []string{"max-age=0, no-store"}},
		{"case-insensitive name", []string{"No-Store"}},
		{"no-store first", []string{"no-store, max-age=0"}},
		{"two header lines", []string{"max-age=0", "no-store"}},
		{"padded list", []string{"private ,\tno-store , must-revalidate"}},
	}
	for i, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			// A fresh gateway per variant: a warm entry from a baseline leak
			// (a write that slipped through) must not mask the lookup
			// assertion of a later variant.
			u := newRT02Upstream(t)
			gw := rt02ChatGateway(t, u, nil)
			c := newRT05Cache()
			gw.cache = c

			b := strings.Replace(body, "cache01-json", "cache01-json-"+fmt.Sprintf("v%d", i), 1)
			rec := cache01Post(t, gw, b, v.headers...)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Empty(t, rec.Header().Get("X-Cache"),
				"a no-store request is never answered from the cache")
			assert.Equal(t, 1, u.totalCalls(),
				"a no-store request must not be served from the cache")
			assert.Equal(t, 0, c.lookupCount(),
				"a no-store request must not even consult the cache")
			assert.Equal(t, 0, c.writeCount(),
				"a no-store response must never be written to the cache")
		})
	}

	// Control: the same body without no-store writes normally — proving the
	// skips above are the no-store branch, not a broken cache path.
	rec := cache01Post(t, gw, body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Eventually(t, func() bool { return c.writeCount() == 1 }, 2*time.Second, 10*time.Millisecond,
		"the plain request must populate the cache")

	// Control: a warm entry is served as an EXACT hit (and the no-store
	// variants above could never have poisoned it).
	rec = cache01Post(t, gw, body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "EXACT", rec.Header().Get("X-Cache"))
	assert.Equal(t, 2, c.lookupCount(),
		"both control requests consulted the cache (miss, then hit); the variants ran on isolated doubles")
}

func TestCACHE01_NoStore_DirectiveForms_NeverRecorded_SSE(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	gw.cfg.CacheStreamEnabled = true // the stream write path is kill-switched off by default
	c := newRT05Cache()
	gw.cache = c

	streamBody := func(tok string) string {
		return `{"model":"m","stream":true,"messages":[{"role":"user","content":"cache01-sse-` + tok + `"}]}`
	}

	// Compound single-line and multi-line spellings must leave no stream
	// recording behind. The stream write is asynchronous: absence is pinned
	// over a bounded window (a leak surfaces within it, cf. rt07's Eventually).
	for i, headers := range [][]string{
		{"max-age=0, no-store"},
		{"max-age=0", "no-store"},
	} {
		rec := cache01Post(t, gw, streamBody(fmt.Sprintf("v%d", i)), headers...)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "data: ",
			"the client stream itself must be unaffected")
	}
	require.Never(t, func() bool { return c.writeCount() > 0 },
		300*time.Millisecond, 10*time.Millisecond,
		"a no-store stream must never be recorded for the cache")

	// Control: a streaming request without no-store DOES record.
	rec := cache01Post(t, gw, streamBody("ctrl"))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Eventually(t, func() bool { return c.writeCount() == 1 }, 2*time.Second, 10*time.Millisecond,
		"the recorded stream write proves the no-store skips are selective")

	// The recorded entry replays for a plain repeat (cache sane), while the
	// no-store spelling keeps hitting upstream even when an entry exists.
	rec = cache01Post(t, gw, streamBody("ctrl"))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "data: ")
	assert.NotEmpty(t, rec.Header().Get("X-Cache"), "a recorded stream must replay")

	rec = cache01Post(t, gw, streamBody("a"), "max-age=0, no-store")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Empty(t, rec.Header().Get("X-Cache"),
		"an existing entry must not be served to a no-store request")
}

// TestCACHE01_NoStore_WarmEntryNeverServed pins the symmetric contract on
// the lookup side of an already-populated key: the same body previously
// written by a plain request stays unreusable for any no-store spelling.
func TestCACHE01_NoStore_WarmEntryNeverServed(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	c := newRT05Cache()
	gw.cache = c

	const body = `{"model":"m","messages":[{"role":"user","content":"cache01-sym"}]}`

	// Populate.
	rec := cache01Post(t, gw, body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Eventually(t, func() bool { return c.writeCount() == 1 }, 2*time.Second, 10*time.Millisecond)

	// The no-store repeat must go upstream despite the warm entry.
	before := u.totalCalls()
	rec = cache01Post(t, gw, body, "max-age=0, no-store")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, before+1, u.totalCalls(),
		"no-store must bypass a warm entry: the client forbade caching this exchange")
	assert.Empty(t, rec.Header().Get("X-Cache"))
}

// TestCACHE01_NoStore_DirectiveParser pins clientNoStore's parsing contract
// directly: name-only matching (case-insensitive, comma-separated, multi-line
// folding, whitespace/OWS tolerant), positive failure-safety on parametered
// spellings, and no false positive on lookalike directive names.
func TestCACHE01_NoStore_DirectiveParser(t *testing.T) {
	cases := []struct {
		name    string
		headers []string
		want    bool
	}{
		{"absent", nil, false},
		{"empty value", []string{""}, false},
		{"exact", []string{"no-store"}, true},
		{"uppercase", []string{"NO-STORE"}, true},
		{"mixed case", []string{"No-Store"}, true},
		{"compound", []string{"max-age=0, no-store"}, true},
		{"no-store first", []string{"no-store, max-age=0"}, true},
		{"padded OWS", []string{"  no-store  "}, true},
		{"padded list", []string{"private , no-store , must-revalidate"}, true},
		{"two lines one carrying it", []string{"max-age=0", "no-store"}, true},
		{"parametered fails safe", []string{"no-store=1"}, true},
		{"lookalike name rejected", []string{"x-no-store"}, false},
		{"substring not a directive", []string{"no-storehouse"}, false},
		{"only other directives", []string{"max-age=0", "private, no-cache"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
			if len(tc.headers) > 0 {
				r.Header["Cache-Control"] = tc.headers
			}
			assert.Equal(t, tc.want, clientNoStore(r))
		})
	}
}
