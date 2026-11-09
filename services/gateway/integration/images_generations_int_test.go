//go:build integration

package integration

//: images generations integration at the consumer boundary. The
// pkg/gateway images tests pin handler behavior with a hand-built gateway
// struct; this file drives the REAL deployment entry point
// (RunGatewayServer → chi chain incl. httpmw.MaxBody 10 MiB, auth, credit
// guard, reservation gate → POST /v1/images/generations) against real
// Postgres (models_registry resolution, wallets, budgets) + Redis (auth
// cache, events) and a fake OpenAI upstream. Packet criterion: accepted
// formats pass end-to-end; unsupported surfaces are not promised (invalid
// input, payload size, SSRF-risk data[].url items never fetched).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/gateway"
)

const (
	imagesOrgID    = "22222222-3333-4444-8555-666677770050"
	imagesTeamID   = "22222222-3333-4444-8555-666677770051"
	imagesKeyRaw   = "images-int-key"
	imagesModel    = "images-int-model"
	imagesURLModel = "images-int-url-model"
	imagesBadModel = "images-int-anthropic-model"
	// imagesTinyPNGB64 is the base64 of the 8-byte PNG signature
	// (\x89PNG\r\n\x1a\n): opaque provider image bytes the gateway passes
	// through without dereferencing or validating.
	imagesTinyPNGB64 = "iVBORw0KGgo="
	imagesUsageBody  = `{"created":1790000000,"data":[{"b64_json":"` + imagesTinyPNGB64 + `"}],"usage":{"input_tokens":20,"output_tokens":1424,"total_tokens":1444,"input_tokens_details":{"cached_tokens":0}}}`
)

// seedImagesOrg provisions a dedicated funded org (own team, own wallet) so
// per-process credit-guard caches cannot be poisoned across tests.
func seedImagesOrg(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	mustExec(ctx, t, pool,
		"INSERT INTO organizations (id, name, slug) VALUES ($1, 'r050-images-org', 'r050-images') ON CONFLICT (id) DO NOTHING",
		imagesOrgID)
	mustExec(ctx, t, pool,
		"INSERT INTO org_credits (org_id, balance_cents, updated_at) VALUES ($1, 100000, now()) ON CONFLICT (org_id) DO NOTHING",
		imagesOrgID)
	mustExec(ctx, t, pool,
		"INSERT INTO organizations_teams (id, org_id, name, slug) VALUES ($1, $2, 'r050-images-team', 'r050-images-team') ON CONFLICT (id) DO NOTHING",
		imagesTeamID, imagesOrgID)
	mustExec(ctx, t, pool,
		"INSERT INTO team_budgets (team_id, monthly_limit_usd, hard_limit) VALUES ($1, 1000.00, true) ON CONFLICT (team_id) DO NOTHING",
		imagesTeamID)
	mustExec(ctx, t, pool,
		`INSERT INTO api_keys (id, key_hash, org_id, name, active, team_id)
		 VALUES (gen_random_uuid(), $1, $2, 'r050-images-key', true, $3) ON CONFLICT (key_hash) DO NOTHING`,
		sha256Hex(imagesKeyRaw), imagesOrgID, imagesTeamID)
}

// seedImagesModel registers a model row the real resolver reads. Must run
// BEFORE the gateway starts (5-minute resolver cache).
func seedImagesModel(ctx context.Context, t *testing.T, pool *pgxpool.Pool, name, provider, upstreamURL string) {
	t.Helper()
	mustExec(ctx, t, pool,
		`INSERT INTO models_registry (model_name, display_name, tier, upstream_url, provider, enabled)
		 VALUES ($1, $1, 'smart', $2, $3, true)
		 ON CONFLICT (model_name) DO UPDATE SET upstream_url = EXCLUDED.upstream_url, provider = EXCLUDED.provider, enabled = true`,
		name, upstreamURL, provider)
}

// imagesIntegrationServer starts the real gateway wired to the fake upstream.
func imagesIntegrationServer(t *testing.T, ctx context.Context, rdb *redis.Client, pool *pgxpool.Pool, upstreamURL, stream string) (string, func()) {
	t.Helper()
	port := findFreePort(t)
	cfg := config.Gateway{
		ListenAddr:  fmt.Sprintf("127.0.0.1:%d", port),
		AuthMode:    "header",
		PGURI:       gatewayPGURI(),
		Provider:    upstreamURL,
		FallbackKey: "r050-images-fallback",
		EventStream: stream,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	serverCtx, serverCancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = cli.RunGatewayServer(cfg, rdb, pool, integrationTestKMS{}, logger, serverCtx)
	}()
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForGatewayReady(t, baseURL)
	return baseURL, func() {
		serverCancel()
		select {
		case <-time.After(5 * time.Second):
		case <-done:
		}
	}
}

func TestImagesGenerations_Integration_ConsumerBoundary(t *testing.T) {
	ctx := t.Context()
	rdb := NewGatewayTestRedis(t, ctx)
	pool := NewGatewayTestDB(t, ctx)
	FlushGatewayRedis(ctx, t, rdb)
	seedImagesOrg(ctx, t, pool)

	// OpenAI upstream serving the accepted generation format with a provider
	// usage block. Non-generations paths are the SSRF probe: any hit there
	// means the gateway dereferenced a data[].url item (D5 violation).
	var upstreamHits atomic.Int64
	var upstreamBody atomic.Value
	var upstreamPath atomic.Value
	genSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/images/generations" {
			t.Errorf("unexpected upstream path %q", r.URL.Path)
			return
		}
		upstreamHits.Add(1)
		upstreamPath.Store(r.URL.Path)
		raw, _ := io.ReadAll(r.Body)
		upstreamBody.Store(string(raw))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(imagesUsageBody))
	}))
	defer genSrv.Close()

	// URL-shaped upstream: generations answer carries data[].url items only
	// (one lookalike internal-metadata link, one link back at this server's
	// never-fetched path) and NO usage block (D4 no-fabrication over wire).
	ssrfHits := new(atomic.Int64)
	ssrfSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/images/generations" {
			ssrfHits.Add(1)
			t.Errorf("gateway dereferenced data[].url item: %s %s", r.Method, r.URL.Path)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"created":1790000000,"data":[` +
			`{"url":"http://169.254.169.254/latest/meta-data/"},` +
			`{"url":"http://` + r.Host + `/secret-image.png"}]}`))
	}))
	defer ssrfSrv.Close()

	seedImagesModel(ctx, t, pool, imagesModel, "openai", genSrv.URL)
	seedImagesModel(ctx, t, pool, imagesURLModel, "openai", ssrfSrv.URL)
	seedImagesModel(ctx, t, pool, imagesBadModel, "anthropic", genSrv.URL)

	stream := fmt.Sprintf("r050-images-events-%d", time.Now().UnixNano())
	baseURL, cleanup := imagesIntegrationServer(t, ctx, rdb, pool, genSrv.URL, stream)
	defer cleanup()

	client := &http.Client{Timeout: 30 * time.Second}
	headers := map[string]string{"Authorization": "Bearer " + imagesKeyRaw}
	post := func(t *testing.T, path string, body json.RawMessage, extra map[string]string) (int, map[string]string, string) {
		t.Helper()
		h := map[string]string{}
		for k, v := range headers {
			h[k] = v
		}
		for k, v := range extra {
			h[k] = v
		}
		code, hdr, respBody := roundTrip(t, client, baseURL, path, h, body)
		return code, hdr, string(respBody)
	}

	// [accepted format passes] Full pass-through with provider usage turning
	// into a request.completed event with honest accounting observables.
	t.Run("accepted format passes with usage accounting and completed event", func(t *testing.T) {
		body := json.RawMessage(`{"model":"` + imagesModel + `","prompt":"a single red cube on a white background","n":1,"size":"1024x1024"}`)
		code, hdr, respBody := post(t, "/v1/images/generations", body, nil)
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", code, respBody)
		}
		if strings.TrimSpace(respBody) != imagesUsageBody {
			t.Fatalf("response body is not a verbatim passthrough: %s", respBody)
		}
		if hdr["Content-Type"] != "application/json" {
			t.Fatalf("content type = %q", hdr["Content-Type"])
		}
		if hits := upstreamHits.Load(); hits != 1 {
			t.Fatalf("upstream hits = %d, want 1", hits)
		}
		if got := upstreamPath.Load(); got != "/v1/images/generations" {
			t.Fatalf("upstream path = %v", got)
		}
		sent := upstreamBody.Load().(string)
		if !strings.Contains(sent, `"model":"`+imagesModel+`"`) || !strings.Contains(sent, `"prompt":"a single red cube on a white background"`) {
			t.Fatalf("upstream body lost canonical model/prompt: %s", sent)
		}
		entry := pollStreamEntry(t, rdb, stream, func(e map[string]string) bool {
			return e["event_type"] == "request.completed" && e["org_id"] == imagesOrgID
		})
		if entry["endpoint"] != "images.generation" {
			t.Errorf("event endpoint = %q", entry["endpoint"])
		}
		if entry["model_used"] != imagesModel {
			t.Errorf("event model_used = %q", entry["model_used"])
		}
		if entry["tokens_in"] != "20" || entry["tokens_out"] != "1424" {
			t.Errorf("event tokens = %s/%s, want 20/1424", entry["tokens_in"], entry["tokens_out"])
		}
		if entry["usage_source"] != "provider" {
			t.Errorf("event usage_source = %q, want provider", entry["usage_source"])
		}
		if entry["cost_status"] != "unknown_price" {
			t.Errorf("event cost_status = %q, want unknown_price (no image pricing basis)", entry["cost_status"])
		}
		if entry["status_code"] != "200" || entry["request_id"] == "" {
			t.Errorf("event status/request_id = %q/%q", entry["status_code"], entry["request_id"])
		}
	})

	// [payload size not promised] A body past the 10 MiB gateway cap is
	// refused 413 by the REAL httpmw.MaxBody middleware before any upstream
	// call (contract negative scenario: payload size).
	t.Run("payload size refused 413 at the real MaxBody boundary", func(t *testing.T) {
		body := json.RawMessage(`{"model":"` + imagesModel + `","prompt":"` + strings.Repeat("a", 10<<20) + `"}`)
		code, _, respBody := post(t, "/v1/images/generations", body, nil)
		if code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413; body: %s", code, respBody)
		}
		var env struct {
			Error struct {
				Type string `json:"type"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(respBody), &env); err != nil {
			t.Fatalf("envelope: %v (%s)", err, respBody)
		}
		if env.Error.Type != "invalid_request_error" {
			t.Errorf("error type = %q, want invalid_request_error", env.Error.Type)
		}
		if hits := upstreamHits.Load(); hits != 1 {
			t.Fatalf("oversized body reached upstream: hits = %d", hits)
		}
	})

	// [unsupported not promised] A registry model resolving to a non-OpenAI-
	// compat provider is refused with the contract code, zero upstream calls.
	t.Run("unsupported provider refused from the real registry row", func(t *testing.T) {
		body := json.RawMessage(`{"model":"` + imagesBadModel + `","prompt":"x"}`)
		code, _, respBody := post(t, "/v1/images/generations", body, nil)
		if code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body: %s", code, respBody)
		}
		var env struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(respBody), &env); err != nil {
			t.Fatalf("envelope: %v (%s)", err, respBody)
		}
		if env.Error.Code != "images_not_supported_for_provider" {
			t.Errorf("error code = %q, want images_not_supported_for_provider", env.Error.Code)
		}
		if hits := upstreamHits.Load(); hits != 1 {
			t.Fatalf("unsupported provider reached upstream: hits = %d", hits)
		}
	})

	// [SSRF-risk URLs] data[].url items come back verbatim; the gateway never
	// issues a secondary fetch (D5), and the usage-less response is accounted
	// as no_usage with zero tokens (D4) instead of a fabricated estimate.
	t.Run("data url passthrough never fetched, no usage fabricated", func(t *testing.T) {
		body := json.RawMessage(`{"model":"` + imagesURLModel + `","prompt":"url passthrough"}`)
		code, _, respBody := post(t, "/v1/images/generations", body, nil)
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", code, respBody)
		}
		if !strings.Contains(respBody, `"url":"http://169.254.169.254/latest/meta-data/"`) {
			t.Fatalf("metadata-style url not passed through verbatim: %s", respBody)
		}
		wantSelf := `"url":"` + ssrfSrv.URL + `/secret-image.png"`
		if !strings.Contains(respBody, wantSelf) {
			t.Fatalf("self url not passed through verbatim: %s", respBody)
		}
		if fetched := ssrfHits.Load(); fetched != 0 {
			t.Fatalf("gateway fetched data[].url %d time(s)", fetched)
		}
		entry := pollStreamEntry(t, rdb, stream, func(e map[string]string) bool {
			return e["event_type"] == "request.completed" && e["model_used"] == imagesURLModel
		})
		if entry["usage_source"] != "none" || entry["cost_status"] != "no_usage" {
			t.Errorf("event usage_source/cost_status = %q/%q, want none/no_usage", entry["usage_source"], entry["cost_status"])
		}
		if entry["tokens_in"] != "0" || entry["tokens_out"] != "0" {
			t.Errorf("event tokens = %s/%s, want 0/0 (no fabricated estimate)", entry["tokens_in"], entry["tokens_out"])
		}
	})

	// [invalid input not promised] Malformed JSON is refused 400 without
	// echoing request content, zero upstream calls.
	t.Run("invalid request refused without echo", func(t *testing.T) {
		marker := "r050-secret-marker-7f3a"
		body := json.RawMessage(`{"model":"` + imagesModel + `","prompt":"` + marker + `","n":`)
		code, _, respBody := post(t, "/v1/images/generations", body, nil)
		if code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body: %s", code, respBody)
		}
		if strings.Contains(respBody, marker) {
			t.Errorf("invalid request echoed back to the client: %s", respBody)
		}
		code, _, respBody = post(t, "/v1/images/generations", json.RawMessage(`{"model":"`+imagesModel+`"}`), nil)
		if code != http.StatusBadRequest || !strings.Contains(respBody, "prompt is required") {
			t.Fatalf("missing prompt = %d %q, want 400 prompt is required", code, respBody)
		}
		if hits := upstreamHits.Load(); hits != 1 {
			t.Fatalf("invalid requests reached upstream: hits = %d", hits)
		}
	})

	// [unsupported surfaces not promised] No edits route and no GET on the
	// generations path through the real router (D3).
	t.Run("unsupported surfaces refused", func(t *testing.T) {
		if code, _, _ := post(t, "/v1/images/edits", json.RawMessage(`{}`), nil); code != http.StatusNotFound {
			t.Errorf("edits = %d, want 404", code)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v1/images/generations", nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+imagesKeyRaw)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET generations: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("GET generations = %d, want 405", resp.StatusCode)
		}
	})
}
