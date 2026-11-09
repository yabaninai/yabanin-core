package cli

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/config"
)

func modelsGateway(lister modelLister, access modelAccess) *gateway {
	cfg := config.Gateway{AuthMode: "strict", APIKey: "test-key", FallbackModel: "smart"}
	gw := &gateway{
		cfg:    cfg,
		log:    slog.Default(),
		auth:   NewAuthMiddleware(cfg, nil),
		models: lister,
		wl:     access,
	}
	return gw
}

func modelsHTTP(gw *gateway) http.Handler {
	r := chi.NewRouter()
	gw.routes(r)
	return r
}

func authed(t *testing.T, method, path string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
	req.Header.Set("Authorization", "Bearer test-key")
	return req
}

type fixedLister []modelEntry

func (f fixedLister) ListEnabledModels(context.Context) ([]modelEntry, error) {
	return append([]modelEntry(nil), f...), nil
}

func TestListModels_WhitelistAndLimit(t *testing.T) {
	created := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	gw := modelsGateway(fixedLister{
		{ID: "shown", DisplayName: "Shown", Provider: "openai", CreatedAt: created},
		{ID: "hidden", DisplayName: "Hidden", Provider: "openai", CreatedAt: created},
		{ID: "second", DisplayName: "Second", Provider: "", CreatedAt: created},
	}, fakeAccess{allowed: true})
	gw.wl = allowExcept("hidden")

	rec := httptest.NewRecorder()
	modelsHTTP(gw).ServeHTTP(rec, authed(t, http.MethodGet, "/v1/models?limit=1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var body openAIModelList
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Object != "list" || len(body.Data) != 1 || body.Data[0].ID != "shown" {
		t.Fatalf("body %+v", body)
	}
	if body.Data[0].OwnedBy != "openai" || body.Data[0].Object != "model" {
		t.Fatalf("model %+v", body.Data[0])
	}
}

func TestListModels_AnthropicFormat(t *testing.T) {
	created := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	gw := modelsGateway(fixedLister{
		{ID: "claude", DisplayName: "Claude", Provider: "anthropic", CreatedAt: created},
	}, nil)
	req := authed(t, http.MethodGet, "/v1/models")
	req.Header.Set("anthropic-version", "2023-06-01")
	rec := httptest.NewRecorder()
	modelsHTTP(gw).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	var body anthropicModelList
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.HasMore || body.FirstID != "claude" || body.LastID != "claude" || len(body.Data) != 1 {
		t.Fatalf("body %+v", body)
	}
	if body.Data[0].Type != "model" || body.Data[0].DisplayName != "Claude" || body.Data[0].CreatedAt != "2026-09-01T12:00:00Z" {
		t.Fatalf("model %+v", body.Data[0])
	}
}

func TestListModels_WhitelistError(t *testing.T) {
	gw := modelsGateway(fixedLister{{ID: "m", DisplayName: "M", Provider: "openai", CreatedAt: time.Unix(1, 0)}}, fakeAccess{err: errors.New("down")})
	rec := httptest.NewRecorder()
	modelsHTTP(gw).ServeHTTP(rec, authed(t, http.MethodGet, "/v1/models"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if errorType(t, rec) != "whitelist_check_unavailable" {
		t.Fatalf("body %s", rec.Body.String())
	}
}

func TestListModels_StaticWithoutDatabase(t *testing.T) {
	cfg := config.Gateway{AuthMode: "strict", APIKey: "test-key", FallbackModel: "smart"}
	gw := &gateway{cfg: cfg, log: slog.Default(), auth: NewAuthMiddleware(cfg, nil)}
	gw.bindModelLister(nil)
	rec := httptest.NewRecorder()
	modelsHTTP(gw).ServeHTTP(rec, authed(t, http.MethodGet, "/v1/models"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	var body openAIModelList
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data) != 1 || body.Data[0].ID != "smart" || body.Data[0].OwnedBy != "yabanin" {
		t.Fatalf("body %+v", body)
	}
}

func TestGetModel_NotFound(t *testing.T) {
	gw := modelsGateway(fixedLister{{ID: "smart", DisplayName: "Smart", Provider: "yabanin", CreatedAt: time.Unix(1, 0)}}, nil)
	rec := httptest.NewRecorder()
	modelsHTTP(gw).ServeHTTP(rec, authed(t, http.MethodGet, "/v1/models/missing"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if errorType(t, rec) != "not_found_error" {
		t.Fatalf("body %s", rec.Body.String())
	}
}

func TestModels_Unauthorized(t *testing.T) {
	gw := modelsGateway(fixedLister{{ID: "smart", DisplayName: "Smart", Provider: "yabanin", CreatedAt: time.Unix(1, 0)}}, nil)
	rec := httptest.NewRecorder()
	modelsHTTP(gw).ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/models", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if errorType(t, rec) != "authentication_error" {
		t.Fatalf("body %s", rec.Body.String())
	}
}

func TestPGModelLister_CachesFor30s(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	calls := 0
	lister := &pgModelLister{
		now: func() time.Time { return now },
		query: func(context.Context) ([]modelEntry, error) {
			calls++
			return []modelEntry{{ID: "m"}}, nil
		},
	}
	if _, err := lister.ListEnabledModels(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := lister.ListEnabledModels(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("calls %d, want 1", calls)
	}
	now = now.Add(31 * time.Second)
	if _, err := lister.ListEnabledModels(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls %d, want 2", calls)
	}
}

type allowExcept string

func (a allowExcept) Check(_ context.Context, _, _, model string) (bool, error) {
	return model != string(a), nil
}
