package trcli

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runTr executes the CLI with the given args and captures combined output.
// Replaces the old TestNotImplementedCommandsExitWithError (I10): keys/spend are
// now implemented against the /internal service API and are tested over httptest.
func runTr(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := RootCommand()
	root.SilenceErrors = true
	root.SilenceUsage = true
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func TestKeysList_MissingFlags(t *testing.T) {
	_, err := runTr(t, "keys", "list", "--api-key", "k")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "org required")

	_, err = runTr(t, "keys", "list", "--org", "o1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--api-key required")
}

func TestKeysList_SuccessOverHTTPT(t *testing.T) {
	got := struct {
		sync.Mutex
		key string
		org string
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/api-keys" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		got.Lock()
		got.key = r.Header.Get("X-Admin-Key")
		got.org = r.URL.Query().Get("org_id")
		got.Unlock()
		if got.key != "svc-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		body := `{"data":[{"id":"a","name":"deploy","active":true,"created_at":"2026-08-01T00:00:00Z"},` +
			`{"id":"b","name":"ci","active":false,"created_at":"2026-07-01T00:00:00Z"}],` +
			`"pagination":{"page":1,"page_size":50,"total":2,"total_pages":1}}`
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)

	out, err := runTr(t, "keys", "list", "--api-key", "svc-key", "--admin-url", srv.URL, "--org", "o1")
	require.NoError(t, err)
	assert.Contains(t, out, "deploy")
	assert.Contains(t, out, "active")
	assert.Contains(t, out, "2026-08-01")
	assert.Contains(t, out, "ci")

	got.Lock()
	defer got.Unlock()
	assert.Equal(t, "svc-key", got.key, "service key must travel in X-Admin-Key header")
	assert.Equal(t, "o1", got.org)
}

// N1: --page/--page-size must be forwarded to the admin API and the total must
// surface in the output when more pages exist.
func TestKeysList_PagingOverHTTPT(t *testing.T) {
	got := struct {
		sync.Mutex
		page string
		size string
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/api-keys" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		got.Lock()
		got.page = r.URL.Query().Get("page")
		got.size = r.URL.Query().Get("page_size")
		got.Unlock()
		w.Header().Set("Content-Type", "application/json")
		body := `{"data":[{"id":"a","name":"k1","active":true,"created_at":"2026-08-01T00:00:00Z"}],` +
			`"pagination":{"page":2,"page_size":10,"total":25,"total_pages":3}}`
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)

	out, err := runTr(t, "keys", "list", "--api-key", "svc-key", "--admin-url", srv.URL, "--org", "o1",
		"--page", "2", "--page-size", "10")
	require.NoError(t, err)

	got.Lock()
	assert.Equal(t, "2", got.page, "page param must be forwarded")
	assert.Equal(t, "10", got.size, "page_size param must be forwarded")
	got.Unlock()

	assert.Contains(t, out, "k1")
	assert.Contains(t, out, "Showing 1 of 25")
}

func TestKeysList_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"error":"unauthorized"}`)
	}))
	t.Cleanup(srv.Close)

	_, err := runTr(t, "keys", "list", "--api-key", "wrong", "--admin-url", srv.URL, "--org", "o1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "YABANIN_ADMIN_API_KEY set")
}

func TestSpend_MissingOrg(t *testing.T) {
	_, err := runTr(t, "spend", "--api-key", "k")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "org required")
}

func TestSpend_SuccessOverHTTPT(t *testing.T) {
	got := struct {
		sync.Mutex
		key  string
		org  string
		days string
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/analytics/savings" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		got.Lock()
		got.key = r.Header.Get("X-Admin-Key")
		got.org = r.URL.Query().Get("org_id")
		got.days = r.URL.Query().Get("days")
		got.Unlock()
		if got.key != "svc-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"period":"30d","total_requests":42,`+
			`"actual_cost_usd":10.5,"counterfactual_cost_usd":20.0,"combined_savings_pct":47.5,`+
			`"top_models_by_cost":[{"model":"gpt-x","requests":30,"actual_cost_usd":8.0,"savings_pct":50.0}]}`)
	}))
	t.Cleanup(srv.Close)

	out, err := runTr(t, "spend", "--api-key", "svc-key", "--admin-url", srv.URL, "--org", "o9", "--days", "30")
	require.NoError(t, err)
	assert.Contains(t, out, "Period 30d")
	assert.Contains(t, out, "requests: 42")
	assert.Contains(t, out, "$10.50")
	assert.Contains(t, out, "47.5%")
	assert.Contains(t, out, "gpt-x")

	got.Lock()
	defer got.Unlock()
	assert.Equal(t, "svc-key", got.key)
	assert.Equal(t, "o9", got.org)
	assert.Equal(t, "30", got.days, "days query param must be forwarded")
}

// TestVersionCarriesBackronym pins the canonical YABANIN expansion on the
// version surface; the first line stays machine-parseable for version probes.
func TestVersionCarriesBackronym(t *testing.T) {
	out, err := runTr(t, "version")
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.GreaterOrEqual(t, len(lines), 2)
	assert.Contains(t, lines[0], version)
	assert.Contains(t, lines[0], commit)
	assert.Equal(t, Backronym, lines[1])
}
