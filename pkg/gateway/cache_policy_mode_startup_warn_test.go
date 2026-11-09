package cli

// w23-06 (w22-06 review MEDIUM): the production default ResolvePolicyMode("")
// → PolicyModeOff means a deployment that sets cache_enabled but leaves
// YABANIN_POLICY_MODE unset boots a cache whose regime resolver fail-safes to
// "" for every org (the accepted N03-P02-T04 semantics) — no lookups, no
// writes, every op silently ticked into CacheEnforcementOffSkippedTotal. The
// remediation is observability only: a one-shot startup WARN from
// wireCacheService — the single boot locus where the cache is fully wired and
// the effective policy mode is known. These pins freeze the warn contract:
// exactly one warn when the cache is enabled and the effective mode is off or
// unset, none when the mode is shadow/enforce or the cache is disabled. The
// fail-safe gating itself must never change (a semantic revert here fails
// N03-P02-T04 acceptance, not just this pin).

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/config"
)

// warnModeOffMarker is the exact message wireCacheService emits — matched as
// a substring so the pin survives attribute rendering, not the wording.
const warnModeOffMarker = "cache enabled but the policy mode is off/unset"

// TestWireCacheService_PolicyModeOffStartupWarn drives the real cache wiring
// (the production warn site) across the mode × cache_enabled matrix with the
// lazily-dialled pg/redis handles of wireTestDeps: the happy path constructs
// in-memory services only, no store is contacted.
func TestWireCacheService_PolicyModeOffStartupWarn(t *testing.T) {
	t.Setenv("YABANIN_ML_PACK_DIR", "")
	t.Setenv("YABANIN_EMBEDDER_ENABLED", "")
	t.Setenv("YABANIN_EMBEDDER_MODEL", "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tests := []struct {
		name      string
		cache     bool
		wiring    PolicyWiring
		wantWarns int
	}{
		{
			name:      "cache enabled with mode off warns exactly once",
			cache:     true,
			wiring:    PolicyWiring{Mode: PolicyModeOff},
			wantWarns: 1,
		},
		{
			name:      "cache enabled with zero wiring (mode unset) warns exactly once",
			cache:     true,
			wiring:    PolicyWiring{},
			wantWarns: 1,
		},
		{
			name:      "cache enabled with mode enforce stays silent",
			cache:     true,
			wiring:    PolicyWiring{Mode: PolicyModeEnforce},
			wantWarns: 0,
		},
		{
			name:      "cache enabled with mode shadow stays silent",
			cache:     true,
			wiring:    PolicyWiring{Mode: PolicyModeShadow},
			wantWarns: 0,
		},
		{
			name:      "cache disabled with mode off stays silent",
			cache:     false,
			wiring:    PolicyWiring{Mode: PolicyModeOff},
			wantWarns: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, gw, buf := wireTestDeps(t, ctx, config.Gateway{CacheEnabled: tc.cache})
			w.policy = tc.wiring

			if err := wireCacheService(ctx, w, gw); err != nil {
				t.Fatalf("wireCacheService must boot: %v", err)
			}

			logs := buf.String()
			if got := strings.Count(logs, warnModeOffMarker); got != tc.wantWarns {
				t.Errorf("warn count = %d, want %d\nlogs:\n%s", got, tc.wantWarns, logs)
			}
			// The cache must actually be wired in the enabled cases — the warn
			// is about a wired-but-gated cache, not a missing one.
			if tc.cache && gw.cacheSvc == nil {
				t.Error("cacheSvc must be wired when cache_enabled")
			}
			if !tc.cache && gw.cacheSvc != nil {
				t.Error("cacheSvc must stay unwired when cache_enabled is false")
			}
		})
	}
}

// TestWireCacheService_PolicyModeOffWarnIsLevelWarn pins the severity: the
// finding is a WARN at startup (visible in default operator log levels), not
// an Error (must not look like a boot failure) and not Info (must not
// disappear under default levels). Drives one real wiring with a
// level-counting handler instead of string matching.
func TestWireCacheService_PolicyModeOffWarnIsLevelWarn(t *testing.T) {
	t.Setenv("YABANIN_ML_PACK_DIR", "")
	t.Setenv("YABANIN_EMBEDDER_ENABLED", "")
	t.Setenv("YABANIN_EMBEDDER_MODEL", "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// pgxpool.New / redis.NewClient only build handles — connections dial
	// lazily on first use, which never happens here (wireTestDeps pattern).
	pool, err := pgxpool.New(ctx, "postgres://test:test@127.0.0.1:1/test")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)

	counter := &levelCountHandler{buf: &strings.Builder{}}
	w := &gatewayWiring{
		cfg:    config.Gateway{CacheEnabled: true},
		pool:   pool,
		rdb:    redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}),
		l:      slog.New(counter),
		policy: PolicyWiring{Mode: PolicyModeOff},
	}
	t.Cleanup(func() { _ = w.rdb.Close() })

	if err := wireCacheService(ctx, w, &gateway{}); err != nil {
		t.Fatalf("wireCacheService must boot: %v", err)
	}

	if counter.counts[slog.LevelWarn] != 1 {
		t.Errorf("warn-level records = %d, want exactly 1\nlogs:\n%s", counter.counts[slog.LevelWarn], counter.buf.String())
	}
	if counter.counts[slog.LevelError] != 0 {
		t.Errorf("error-level records = %d, want 0 — the gated cache is not a boot failure\nlogs:\n%s", counter.counts[slog.LevelError], counter.buf.String())
	}
	if !strings.Contains(counter.buf.String(), warnModeOffMarker) {
		t.Errorf("logs = %q, want the mode-off warn marker", counter.buf.String())
	}
}

// levelCountHandler is a minimal slog handler that counts records per level
// and mirrors the rendered text into buf.
type levelCountHandler struct {
	buf    *strings.Builder
	counts map[slog.Level]int
}

func (h *levelCountHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *levelCountHandler) Handle(_ context.Context, r slog.Record) error {
	if h.counts == nil {
		h.counts = make(map[slog.Level]int)
	}
	h.counts[r.Level]++
	h.buf.WriteString(r.Message)
	h.buf.WriteByte('\n')
	return nil
}

func (h *levelCountHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }

func (h *levelCountHandler) WithGroup(_ string) slog.Handler { return h }
