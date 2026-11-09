package handlers

//
// The deprecated cache-warm route is the lifecycle's end-to-end example: the
// spec marks the operation deprecated and carries the announcement/sunset
// metadata, and the handler mirrors both dates as Deprecation/Sunset response
// headers so clients that never read the spec still see the notice
// (docs/api/CONTRACT.md §9). This test is the lock-step between the two:
// change the spec dates without the handler (or the other way around) and it
// fails.
//

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// specCacheWarmLifecycle extracts the lifecycle metadata of the deprecated
// cache-warm operation from the admin spec.
func specCacheWarmLifecycle(tb testing.TB) deprecationMeta {
	tb.Helper()
	doc := loadSpecDocument(tb, adminOpenAPISpec)
	var meta deprecationMeta
	found := false
	walkOperations(tb, doc, adminOpenAPISpec, func(key string, opNode *yaml.Node, m deprecationMeta) {
		if key == "POST /api/cache/warm" {
			meta = m
			found = true
		}
	})
	if !found {
		tb.Fatalf("POST /api/cache/warm is no longer documented in %s — update this test with the route", adminOpenAPISpec)
	}
	return meta
}

// headerDay normalizes an IMF-fixdate header value to its RFC3339 date.
func headerDay(tb testing.TB, key, value string) string {
	tb.Helper()
	parsed, err := http.ParseTime(value)
	if err != nil {
		tb.Fatalf("%s header %q is not a parseable HTTP date: %v", key, value, err)
	}
	return parsed.UTC().Format(time.DateOnly)
}

func TestWarmCacheLifecycleHeaders(t *testing.T) {
	meta := specCacheWarmLifecycle(t)
	if !meta.Deprecated {
		t.Fatalf("POST /api/cache/warm lost deprecated: true in %s — the header pin follows the spec", adminOpenAPISpec)
	}
	if meta.DeprecatedSince == "" || meta.Sunset == "" {
		t.Fatalf("POST /api/cache/warm has no announcement/sunset metadata in %s", adminOpenAPISpec)
	}

	h := inventoryHandlers(t)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/cache/warm", nil)
	w := httptest.NewRecorder()
	h.WarmCache()(w, req)

	if w.Code != http.StatusGone {
		t.Fatalf("status = %d, want %d Gone", w.Code, http.StatusGone)
	}
	dep, sunset := w.Header().Get("Deprecation"), w.Header().Get("Sunset")
	if strings.TrimSpace(dep) == "" || strings.TrimSpace(sunset) == "" {
		t.Fatalf("deprecated route answered without lifecycle headers: Deprecation=%q Sunset=%q", dep, sunset)
	}
	if got := headerDay(t, "Deprecation", dep); got != meta.DeprecatedSince {
		t.Errorf("Deprecation header day %s != spec x-deprecated-since %s — the handler and the spec drifted", got, meta.DeprecatedSince)
	}
	if got := headerDay(t, "Sunset", sunset); got != meta.Sunset {
		t.Errorf("Sunset header day %s != spec x-sunset %s — the handler and the spec drifted", got, meta.Sunset)
	}
}
