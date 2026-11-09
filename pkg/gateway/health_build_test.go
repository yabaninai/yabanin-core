package cli

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHealthzBuildMarker pins the build-marker surface (incident 2026-11-01:
// the stand ran pre-fix code and nothing could tell). GET /healthz must
// always carry the build identity twice — the X-Yabanin-Build response
// header and the "build" JSON field — with the same value, including the
// honest "dev" default of an unstamped build (no version invention, no
// leak of anything beyond the marker itself).
func TestHealthzBuildMarker(t *testing.T) {
	orig := buildVersion
	defer func() { buildVersion = orig }()

	// healthHandler reads only gw.rdb; the zero value (nil) takes the
	// "redis skipped" branch, so no live infrastructure is needed.
	newRouter := func() http.Handler {
		r := chi.NewRouter()
		healthHandler(&gateway{}, r, slog.Default())
		return r
	}

	do := func(t *testing.T) (header string, body map[string]any) {
		t.Helper()
		rec := httptest.NewRecorder()
		newRouter().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil))
		require.Equal(t, http.StatusOK, rec.Code)
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		return rec.Header().Get("X-Yabanin-Build"), body
	}

	t.Run("injected build identity", func(t *testing.T) {
		buildVersion = "bmark1abc1234"
		header, body := do(t)
		assert.Equal(t, "bmark1abc1234", header, "X-Yabanin-Build header must carry the injected marker")
		assert.Equal(t, "bmark1abc1234", body["build"], "healthz body must carry the injected marker")
	})

	t.Run("unstamped build reports dev", func(t *testing.T) {
		buildVersion = "dev" // the var declaration default (ldflags unset)
		header, body := do(t)
		assert.Equal(t, "dev", header)
		assert.Equal(t, "dev", body["build"])
	})

	t.Run("header and field agree", func(t *testing.T) {
		buildVersion = "fpv2-deadbee"
		header, body := do(t)
		assert.Equal(t, header, body["build"], "header and body must never disagree")
	})
}
