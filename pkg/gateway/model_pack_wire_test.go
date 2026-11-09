package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/config"
)

// minimal mode stays untouched (NoopClient + rule-tier, zero download);
// an explicitly attached pack (YABANIN_ML_PACK_DIR) is verified on disk
// before the embedder/classifier is enabled, and any refusal aborts startup.

// wirePackFixture writes a pack directory whose declared digest matches the
// file contents and returns the dir. mutate adjusts the manifest afterwards
// so negative tests break exactly one thing.
func wirePackFixture(t *testing.T, mutate func(m *map[string]any)) string {
	t.Helper()
	weights := "wire-test-weights"
	sum := sha256.Sum256([]byte(weights))
	manifest := map[string]any{
		"id":       "BAAI/bge-small-en-v1.5",
		"version":  "v1.5",
		"revision": "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a",
		"license":  "MIT",
		"files": []map[string]string{
			{"path": "model.safetensors", "sha256": hex.EncodeToString(sum[:])},
		},
	}
	if mutate != nil {
		mutate(&manifest)
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pack.json"), raw, 0o600); err != nil {
		t.Fatalf("write pack.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "model.safetensors"), []byte(weights), 0o600); err != nil {
		t.Fatalf("write weights: %v", err)
	}
	return dir
}

// wireTestDeps returns a wiring with lazily-dialled pg/redis handles (never
// contacted: the pack gate refuses before any store is touched, and the
// happy path only constructs in-memory services) plus a log capture buffer.
func wireTestDeps(t *testing.T, ctx context.Context, cfg config.Gateway) (*gatewayWiring, *gateway, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	pool, err := pgxpool.New(ctx, "postgres://test:test@127.0.0.1:1/test")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	w := &gatewayWiring{
		cfg:  cfg,
		pool: pool,
		rdb:  redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}),
		l:    logger,
	}
	t.Cleanup(func() { _ = w.rdb.Close() })
	return w, &gateway{}, buf
}

// TestModelPackWire_MinimalModeUnchanged is acceptance example 1: without
// embedder env and without a pack dir the cache wire takes the NoopClient
// branch and the classifier stays rule-tier — no pack is processed, nothing
// is downloaded (patterns: cache_wire_test startup + gateway.go:734/:913).
func TestModelPackWire_MinimalModeUnchanged(t *testing.T) {
	t.Setenv("YABANIN_ML_PACK_DIR", "")
	t.Setenv("YABANIN_EMBEDDER_ENABLED", "")
	t.Setenv("YABANIN_EMBEDDER_MODEL", "")
	t.Setenv("YABANIN_CLASSIFIER_SERVICE_URL", "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w, gw, buf := wireTestDeps(t, ctx, config.Gateway{CacheEnabled: true})

	if err := wireCacheService(ctx, w, gw); err != nil {
		t.Fatalf("minimal mode must start: %v", err)
	}
	logs := buf.String()
	if !strings.Contains(logs, "cache enabled but no embedder configured — exact-Redis cache active") {
		t.Errorf("logs = %q, want the NoopClient branch marker", logs)
	}
	if strings.Contains(logs, "model pack") {
		t.Errorf("logs = %q, want no pack processing in minimal mode", logs)
	}

	// Classifier: no service URL → behavior unchanged even with a pack dir set.
	t.Setenv("YABANIN_ML_PACK_DIR", filepath.Join(t.TempDir(), "does-not-matter"))
	if _, err := wireClassifier(ctx, w, gw); err != nil {
		t.Fatalf("wireClassifier without URL must not change behavior: %v", err)
	}
	logs = buf.String()
	if !strings.Contains(logs, "ML classifier v1 disabled — using rule-tier V0 only") {
		t.Errorf("logs = %q, want the rule-tier-only branch marker", logs)
	}
	if strings.Contains(logs, "model pack") {
		t.Errorf("logs = %q, want no pack processing without a classifier URL", logs)
	}
}

// TestModelPackWire_ExplicitPackBoots is acceptance example 2: a verified
// pack whose id matches the embedder model passes the provenance gate as a
// confirmed origin with the no-download notice.
func TestModelPackWire_ExplicitPackBoots(t *testing.T) {
	dir := wirePackFixture(t, nil)
	t.Setenv("YABANIN_ML_PACK_DIR", dir)
	t.Setenv("YABANIN_EMBEDDER_ENABLED", "true")
	t.Setenv("YABANIN_EMBEDDER_BASE_URL", "http://embed:6006")
	t.Setenv("YABANIN_EMBEDDER_MODEL", "BAAI/bge-small-en-v1.5")
	t.Setenv("YABANIN_EMBEDDER_QUERY_PREFIX", "query: ")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w, gw, buf := wireTestDeps(t, ctx, config.Gateway{CacheEnabled: true})

	if err := wireCacheService(ctx, w, gw); err != nil {
		t.Fatalf("verified pack must boot: %v", err)
	}
	logs := buf.String()
	for _, want := range []string{
		"model pack attached — verified on disk, no download",
		"pack_id=BAAI/bge-small-en-v1.5",
		"provenance is the operator's supply chain",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs = %q, want it to mention %q", logs, want)
		}
	}
	if gw.cacheSvc == nil {
		t.Error("cache service must be wired after a successful pack attach")
	}
}

// TestModelPackWire_PackDirWithoutConsumerIsNotVerified pins the documented
// consumer-gated verification boundary (; review finding 2)
// verification runs only at the point a consumer (semantic cache, classifier
// service) would use the weights. A pack dir with NO enabled consumer is
// never verified — even a deliberately broken pack cannot refuse or block a
// minimal deployment; the consumer-on side verifies eagerly, before any
// serving, regardless of the embedder toggle.
func TestModelPackWire_PackDirWithoutConsumerIsNotVerified(t *testing.T) {
	brokenPackDir := func(t *testing.T) string {
		t.Helper()
		dir := wirePackFixture(t, nil)
		if err := os.WriteFile(filepath.Join(dir, "model.safetensors"), []byte("tampered"), 0o600); err != nil {
			t.Fatalf("tamper weights: %v", err)
		}
		t.Setenv("YABANIN_ML_PACK_DIR", dir)
		return dir
	}

	t.Run("cache disabled and no classifier URL — no verification, no refusal", func(t *testing.T) {
		brokenPackDir(t)
		t.Setenv("YABANIN_EMBEDDER_ENABLED", "")
		t.Setenv("YABANIN_EMBEDDER_MODEL", "")
		t.Setenv("YABANIN_CLASSIFIER_SERVICE_URL", "")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		w, gw, buf := wireTestDeps(t, ctx, config.Gateway{CacheEnabled: false})

		if err := wireCacheService(ctx, w, gw); err != nil {
			t.Fatalf("broken pack with cache disabled must not refuse startup: %v", err)
		}
		if gw.cacheSvc != nil {
			t.Error("cache disabled must not wire the cache service")
		}
		if _, err := wireClassifier(ctx, w, gw); err != nil {
			t.Fatalf("broken pack without a classifier URL must not refuse startup: %v", err)
		}
		if logs := buf.String(); strings.Contains(logs, "model pack") {
			t.Errorf("logs = %q, want no pack processing without consumers", logs)
		}
	})

	t.Run("cache enabled — broken pack refuses even with the embedder off", func(t *testing.T) {
		brokenPackDir(t)
		t.Setenv("YABANIN_EMBEDDER_ENABLED", "")
		t.Setenv("YABANIN_EMBEDDER_MODEL", "")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		w, gw, _ := wireTestDeps(t, ctx, config.Gateway{CacheEnabled: true})

		err := wireCacheService(ctx, w, gw)
		if err == nil {
			t.Fatal("broken pack with cache enabled must refuse startup even with no embedder")
		}
		if !strings.Contains(err.Error(), "startup refused (R058 model pack)") {
			t.Errorf("error = %v, want the pack startup refusal", err)
		}
		if gw.cacheSvc != nil {
			t.Error("cache service must NOT be wired after a pack refusal")
		}
	})
}

// TestModelPackWire_RefusesWeightsMissing is acceptance example 3: a pack
// declaring a file that is absent refuses startup with the "weights missing"
// branch wording.
func TestModelPackWire_RefusesWeightsMissing(t *testing.T) {
	dir := wirePackFixture(t, nil)
	if err := os.Remove(filepath.Join(dir, "model.safetensors")); err != nil {
		t.Fatalf("remove weights: %v", err)
	}
	t.Setenv("YABANIN_ML_PACK_DIR", dir)
	t.Setenv("YABANIN_EMBEDDER_ENABLED", "true")
	t.Setenv("YABANIN_EMBEDDER_BASE_URL", "http://embed:6006")
	t.Setenv("YABANIN_EMBEDDER_MODEL", "BAAI/bge-small-en-v1.5")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w, gw, buf := wireTestDeps(t, ctx, config.Gateway{CacheEnabled: true})

	err := wireCacheService(ctx, w, gw)
	if err == nil {
		t.Fatal("missing weights must refuse startup")
	}
	for _, want := range []string{"startup refused (R058 model pack)", "weights missing"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
	if !strings.Contains(buf.String(), "model pack attach refused startup") {
		t.Errorf("logs = %q, want the pack refusal marker", buf.String())
	}
	if gw.cacheSvc != nil {
		t.Error("cache service must NOT be wired after a pack refusal")
	}
}

// TestModelPackWire_RefusesDigestMismatch is acceptance example 4: weights
// whose actual sha256 differs from the manifest refuse startup with the
func TestModelPackWire_RefusesDigestMismatch(t *testing.T) {
	dir := wirePackFixture(t, nil)
	if err := os.WriteFile(filepath.Join(dir, "model.safetensors"), []byte("tampered"), 0o600); err != nil {
		t.Fatalf("tamper weights: %v", err)
	}
	t.Setenv("YABANIN_ML_PACK_DIR", dir)
	t.Setenv("YABANIN_EMBEDDER_ENABLED", "true")
	t.Setenv("YABANIN_EMBEDDER_BASE_URL", "http://embed:6006")
	t.Setenv("YABANIN_EMBEDDER_MODEL", "BAAI/bge-small-en-v1.5")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w, gw, _ := wireTestDeps(t, ctx, config.Gateway{CacheEnabled: true})

	err := wireCacheService(ctx, w, gw)
	if err == nil {
		t.Fatal("digest mismatch must refuse startup")
	}
	for _, want := range []string{"startup refused (R058 model pack)", "digest mismatch", "must not enter the distribution"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
	if gw.cacheSvc != nil {
		t.Error("cache service must NOT be wired after a pack refusal")
	}
}

// TestModelPackWire_RefusesUnknownOrigin is acceptance example 5 at wire
// level: an intact pack for an unregistered id (or an adjacent version) is
// unknown origin and refuses like a distribution default.
func TestModelPackWire_RefusesUnknownOrigin(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   string
	}{
		{"unregistered vendor", "some-vendor/mystery-embed"},
		{"adjacent version v1.4", "BAAI/bge-small-en-v1.4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := wirePackFixture(t, func(m *map[string]any) {
				(*m)["id"] = tc.id
			})
			t.Setenv("YABANIN_ML_PACK_DIR", dir)
			t.Setenv("YABANIN_EMBEDDER_ENABLED", "true")
			t.Setenv("YABANIN_EMBEDDER_BASE_URL", "http://embed:6006")
			t.Setenv("YABANIN_EMBEDDER_MODEL", tc.id)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			w, gw, _ := wireTestDeps(t, ctx, config.Gateway{CacheEnabled: true})

			err := wireCacheService(ctx, w, gw)
			if err == nil {
				t.Fatalf("unknown-origin pack %q must refuse startup", tc.id)
			}
			for _, want := range []string{"startup refused (R058 model pack)", "unknown origin", "must not enter the distribution", tc.id} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %v, want it to mention %q", err, want)
				}
			}
			if gw.cacheSvc != nil {
				t.Error("cache service must NOT be wired after a pack refusal")
			}
		})
	}
}

// TestModelPackWire_MismatchedEmbedderModelVerifiesButWarns: a pack whose id
// differs from the configured embedder model verifies fine (it is intact and
// registered) but is flagged as unused — the embedder model is then judged by
// the ordinary provenance gate (operator-explicit here, so a notice not a
// refusal).
func TestModelPackWire_MismatchedEmbedderModelVerifiesButWarns(t *testing.T) {
	dir := wirePackFixture(t, nil)
	t.Setenv("YABANIN_ML_PACK_DIR", dir)
	t.Setenv("YABANIN_EMBEDDER_ENABLED", "true")
	t.Setenv("YABANIN_EMBEDDER_BASE_URL", "http://embed:6006")
	t.Setenv("YABANIN_EMBEDDER_MODEL", "operator-choice-embedding")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w, gw, buf := wireTestDeps(t, ctx, config.Gateway{CacheEnabled: true})

	if err := wireCacheService(ctx, w, gw); err != nil {
		t.Fatalf("intact pack + explicit operator model must boot: %v", err)
	}
	logs := buf.String()
	if !strings.Contains(logs, "does not match the configured embedder model") {
		t.Errorf("logs = %q, want the mismatch warning", logs)
	}
	if !strings.Contains(logs, "provenance is the operator's supply chain") {
		t.Errorf("logs = %q, want the operator-supply-chain notice", logs)
	}
}

// TestClassifierModelPack verifies the optional head-pack branch: a broken
// pack refuses startup only when a classifier service is being enabled; a
// verified pack attaches with a notice and the wire proceeds.
func TestClassifierModelPack(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("service URL without a pack dir is unchanged minimal mode", func(t *testing.T) {
		t.Setenv("YABANIN_ML_PACK_DIR", "")
		w, gw, buf := wireTestDeps(t, ctx, config.Gateway{ClassifierServiceURL: "http://classifier:8080"})
		ml, err := wireClassifier(ctx, w, gw)
		if err != nil {
			t.Fatalf("classifier with no pack dir must boot unchanged: %v", err)
		}
		if ml == nil {
			t.Error("ML classifier must be wired when the service URL is set")
		}
		if logs := buf.String(); strings.Contains(logs, "model pack") {
			t.Errorf("logs = %q, want no pack processing without a pack dir", logs)
		}
	})
	t.Run("broken pack with service URL refuses startup", func(t *testing.T) {
		dir := wirePackFixture(t, nil)
		if err := os.WriteFile(filepath.Join(dir, "model.safetensors"), []byte("tampered"), 0o600); err != nil {
			t.Fatalf("tamper weights: %v", err)
		}
		t.Setenv("YABANIN_ML_PACK_DIR", dir)

		w, gw, _ := wireTestDeps(t, ctx, config.Gateway{ClassifierServiceURL: "http://classifier:8080"})
		_, err := wireClassifier(ctx, w, gw)
		if err == nil {
			t.Fatal("broken pack must refuse classifier startup")
		}
		for _, want := range []string{"startup refused (R058 model pack)", "digest mismatch"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error = %v, want it to mention %q", err, want)
			}
		}
	})
	t.Run("verified pack attaches with a notice", func(t *testing.T) {
		dir := wirePackFixture(t, nil)
		t.Setenv("YABANIN_ML_PACK_DIR", dir)

		w, gw, buf := wireTestDeps(t, ctx, config.Gateway{ClassifierServiceURL: "http://classifier:8080"})
		ml, err := wireClassifier(ctx, w, gw)
		if err != nil {
			t.Fatalf("verified pack must enable the classifier: %v", err)
		}
		if ml == nil {
			t.Error("ML classifier must be wired when the service URL is set")
		}
		if !strings.Contains(buf.String(), "classifier head model pack attached — verified on disk, no download") {
			t.Errorf("logs = %q, want the classifier pack notice", buf.String())
		}
	})
}

// integration: the pack boundary through the real composition root
// (buildGateway), not only the facet helpers. The pack dir is a real
// directory on disk, YABANIN_ML_PACK_DIR is the real env read, and success
// or refusal is the actual startup outcome of the gateway build. pg/redis
// handles are lazily dialled (127.0.0.1:1 — never contacted: verification
// refuses before any store is touched, and the happy path only constructs
// in-memory services), exactly like the facet-level wire tests.

// packCompositionConfig is the minimal real-boot config for the composition
// root tests: golden-deps shape (routes_golden_test.go) plus the cache gate
// that routes startup through the pack verification in wireCacheService.
func packCompositionConfig(cacheEnabled bool) config.Gateway {
	return config.Gateway{
		ListenAddr:    ":0",
		Provider:      "127.0.0.1:1",
		AuthMode:      "header",
		APIKey:        "pack-integration-key",
		FallbackModel: "smart",
		CacheEnabled:  cacheEnabled,
	}
}

// TestModelPackIntegration_BuildGatewayBootsVerifiedPack is acceptance
// example 2 through the real composition root: a verified pack on disk plus
// YABANIN_ML_PACK_DIR boots the actual gateway build — pack attach notice,
// cache service wired, embedder-less cache branch — with zero download.
func TestModelPackIntegration_BuildGatewayBootsVerifiedPack(t *testing.T) {
	dir := wirePackFixture(t, nil)
	t.Setenv("YABANIN_ML_PACK_DIR", dir)
	t.Setenv("YABANIN_EMBEDDER_ENABLED", "")
	t.Setenv("YABANIN_EMBEDDER_MODEL", "")
	t.Setenv("YABANIN_CLASSIFIER_SERVICE_URL", "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := packCompositionConfig(true)
	w, _, logBuf := wireTestDeps(t, ctx, cfg)
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	gw, err := buildGateway(cfg, w.rdb, w.pool, logger, ctx, JWTWiring{}, CircuitScopeWiring{})
	if err != nil {
		t.Fatalf("buildGateway with a verified pack must boot: %v", err)
	}
	if gw.cacheSvc == nil {
		t.Error("cache service must be wired through the composition root after a successful pack attach")
	}
	logs := logBuf.String()
	for _, want := range []string{
		"model pack attached — verified on disk, no download",
		"pack_id=BAAI/bge-small-en-v1.5",
		"cache enabled but no embedder configured — exact-Redis cache active",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs = %q, want it to mention %q", logs, want)
		}
	}
	if strings.Contains(logs, "model pack attach refused") {
		t.Errorf("logs = %q, want no pack refusal on a verified pack", logs)
	}
}

// TestModelPackIntegration_BuildGatewayRefusesBrokenPack is the negative
// branch through the real composition root: a digest-mismatched pack aborts
// buildGateway itself — no gateway is returned, the refusal carries the
func TestModelPackIntegration_BuildGatewayRefusesBrokenPack(t *testing.T) {
	dir := wirePackFixture(t, nil)
	if err := os.WriteFile(filepath.Join(dir, "model.safetensors"), []byte("tampered"), 0o600); err != nil {
		t.Fatalf("tamper weights: %v", err)
	}
	t.Setenv("YABANIN_ML_PACK_DIR", dir)
	t.Setenv("YABANIN_EMBEDDER_ENABLED", "")
	t.Setenv("YABANIN_EMBEDDER_MODEL", "")
	t.Setenv("YABANIN_CLASSIFIER_SERVICE_URL", "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := packCompositionConfig(true)
	w, _, logBuf := wireTestDeps(t, ctx, cfg)
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	gw, err := buildGateway(cfg, w.rdb, w.pool, logger, ctx, JWTWiring{}, CircuitScopeWiring{})
	if err == nil {
		t.Fatal("buildGateway with a digest-mismatched pack must refuse startup")
	}
	if gw != nil {
		t.Error("no gateway may be returned after a pack startup refusal")
	}
	for _, want := range []string{"startup refused (R058 model pack)", "digest mismatch"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
	if !strings.Contains(logBuf.String(), "model pack attach refused startup") {
		t.Errorf("logs = %q, want the pack refusal marker", logBuf.String())
	}
}

// TestModelPackIntegration_BuildGatewayRefusesBrokenClassifierHeadPack pins
// the routing facet's pack gate through the composition root: with the cache
// disabled but a classifier service being enabled, a broken pack still
// aborts buildGateway — the two consumer gates are independent boundaries.
func TestModelPackIntegration_BuildGatewayRefusesBrokenClassifierHeadPack(t *testing.T) {
	dir := wirePackFixture(t, nil)
	if err := os.WriteFile(filepath.Join(dir, "model.safetensors"), []byte("tampered"), 0o600); err != nil {
		t.Fatalf("tamper weights: %v", err)
	}
	t.Setenv("YABANIN_ML_PACK_DIR", dir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := packCompositionConfig(false)
	cfg.ClassifierServiceURL = "http://classifier:8080"
	w, _, _ := wireTestDeps(t, ctx, cfg)

	gw, err := buildGateway(cfg, w.rdb, w.pool, slog.New(slog.DiscardHandler), ctx, JWTWiring{}, CircuitScopeWiring{})
	if err == nil {
		t.Fatal("buildGateway with a broken head pack must refuse classifier startup")
	}
	if gw != nil {
		t.Error("no gateway may be returned after a pack startup refusal")
	}
	for _, want := range []string{"startup refused (R058 model pack)", "digest mismatch"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
}
