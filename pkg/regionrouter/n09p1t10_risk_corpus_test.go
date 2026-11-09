package regionrouter

// N09-P01-T10 [risk] — rights/data/resources verification for
// pkg/regionrouter. Test-only card: zero production changes.
//
//	permissions — caller-controlled region strings can never reach the
//	app.region GUC: every admission door (ValidateRegion, the bare
//	AfterConnect hook, ConfigurePool) validates before any database
//	interaction is wired, and ConfigurePool leaves the pool unscoped when
//	the region is invalid;
//	resources — the unknown-org storm cannot hammer the store: the negative
//	cache shields the DB behind one read, and positive/negative TTLs stay
//	differentiated (15s negative vs 60s positive).

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestN09P1T10_Risk_AdversarialRegionTokensNeverReachTheGUC: the region id
// is interpolated into SET ROLE / set_config calls on every pooled
// connection. Injection-shaped, casing, length and punctuation variants must
// all be refused by the same gate every door uses.
func TestN09P1T10_Risk_AdversarialRegionTokensNeverReachTheGUC(t *testing.T) {
	t.Parallel()

	hostile := []string{
		"'; DROP TABLE regions; --",
		"sg' OR '1'='1",
		`"sg"`,
		"$(id)",
		"`id`",
		"sg; set_config('app.region','evil',false)",
		"sg\nset role owner",
		"SG",                    // case is never normalized at the gate: refuse, don't canonicalize
		"-sg",                   // leading dash: pattern requires [a-z0-9] first
		"-sg-1",                 // leading dash
		"sg_eu",                 // underscore outside the safe class
		"sg eu",                 // space
		"sg.eu",                 // dot
		"sg/eu",                 // path separator
		"sg=eu",                 // GUC assignment syntax
		"sg\t",                  // trailing tab
		strings.Repeat("a", 32), // one over the 31-char cap
		strings.Repeat("';", 40),
	}
	for _, region := range hostile {
		require.Error(t, ValidateRegion(region), "hostile region %q must be refused", region)
	}

	// The boundary nuances: exactly 31 safe characters is legal, 32 is not;
	// a trailing dash is legal, a leading one is not.
	assert.NoError(t, ValidateRegion(strings.Repeat("a", 31)))
	assert.NoError(t, ValidateRegion("sg-1-"))
	assert.Error(t, ValidateRegion("-sg-1"))
}

// TestN09P1T10_Risk_AfterConnectHookFailsClosedOnInvalidRegion: the bare
// AfterConnect hook re-validates before touching the connection — an invalid
// region returns an error and never issues a GUC statement (proven here with
// a nil connection: reaching the GUC would dereference it).
func TestN09P1T10_Risk_AfterConnectHookFailsClosedOnInvalidRegion(t *testing.T) {
	t.Parallel()

	hook := AfterConnectRegion("NOT-A-REGION")
	require.NotNil(t, hook)

	err := hook(context.Background(), nil)
	require.Error(t, err, "invalid region must fail closed before any conn use")
	assert.Contains(t, err.Error(), "invalid region id")
}

// TestN09P1T10_Risk_ConfigurePoolRefusesInvalidRegionBeforeWiring: ConfigurePool
// validates first — on refusal no hook is installed, so a pool built from
// the config anyway cannot silently run unscoped-but- believing-scoped;
// callers that check the error see the refusal, callers that ignore it get a
// config without a region hook rather than a half-valid one.
func TestN09P1T10_Risk_ConfigurePoolRefusesInvalidRegionBeforeWiring(t *testing.T) {
	t.Parallel()

	t.Run("invalid region: refused, no hook installed", func(t *testing.T) {
		t.Parallel()

		cfg := &pgxpool.Config{}
		err := ConfigurePool(cfg, "'; drop table x")
		require.Error(t, err)
		assert.Nil(t, cfg.AfterConnect, "a refused region must not install a hook")
	})

	t.Run("valid region: hook installed", func(t *testing.T) {
		t.Parallel()

		cfg := &pgxpool.Config{}
		require.NoError(t, ConfigurePool(cfg, "eu"))
		assert.NotNil(t, cfg.AfterConnect)
	})
}

// t10KV is an in-memory kvStore recording every Set's TTL, so the corpus can
// pin the negative/positive TTL differentiation without Redis.
type t10KV struct {
	mu   sync.Mutex
	vals map[string]string
	ttls map[string]time.Duration
	sets int
	gets int
	dels int
}

func newT10KV() *t10KV {
	return &t10KV{vals: map[string]string{}, ttls: map[string]time.Duration{}}
}

func (k *t10KV) Get(_ context.Context, key string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.gets++
	v, ok := k.vals[key]
	if !ok {
		return "", errCacheMiss
	}
	return v, nil
}

func (k *t10KV) Set(_ context.Context, key, value string, ttl time.Duration) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.sets++
	k.vals[key] = value
	k.ttls[key] = ttl
	return nil
}

func (k *t10KV) Del(_ context.Context, key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.dels++
	delete(k.vals, key)
	return nil
}

func (k *t10KV) setTTL(key string) time.Duration {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.ttls[key]
}

// t10Store is an orgStore stub; fail=true always reports the org as unknown.
type t10Store struct {
	mu    sync.Mutex
	calls int
	fail  bool
}

func (s *t10Store) LookupRegion(_ context.Context, _ string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.fail {
		return "", false, errors.New("no row")
	}
	return "eu", true, nil
}

func (s *t10Store) readCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// TestN09P1T10_Risk_UnknownOrgStormIsShieldedByNegativeCache: a burst of
// Resolves for an unknown org hits the store exactly once — the negative
// cache (short TTL) answers the rest — and the negative entry is written
// with the documented 15s TTL, not the 60s positive one.
func TestN09P1T10_Risk_UnknownOrgStormIsShieldedByNegativeCache(t *testing.T) {
	t.Parallel()

	store := &t10Store{fail: true}
	cache := newT10KV()
	r := New(store, cache)

	ctx := context.Background()
	for i := 0; i < 200; i++ {
		assign := r.Resolve(ctx, "org-unknown-storm")
		assert.Equal(t, DefaultRegion, assign.HomeRegion)
		assert.False(t, assign.ResidencyPinned)
	}

	assert.Equal(t, 1, store.readCalls(),
		"the unknown-org storm must be answered from the negative cache after one store read")
	assert.Equal(t, 1, cache.sets)
	assert.Equal(t, 15*time.Second, cache.setTTL("org_region:org-unknown-storm"),
		"negative entries use the short TTL")
}

// TestN09P1T10_Risk_PositiveAssignmentUsesLongTTLAndInvalidate: the positive
// path writes the 60s TTL, and the admin invalidation (the rights-relevant
// write path: SetAssignment updates then invalidates) clears the cached
// decision so the next Resolve re-reads the store.
func TestN09P1T10_Risk_PositiveAssignmentUsesLongTTLAndInvalidate(t *testing.T) {
	t.Parallel()

	store := &t10Store{}
	cache := newT10KV()
	r := New(store, cache)

	ctx := context.Background()
	assign := r.Resolve(ctx, "org-1")
	assert.Equal(t, "eu", assign.HomeRegion)
	assert.True(t, assign.ResidencyPinned)
	assert.Equal(t, 1, store.readCalls())
	assert.Equal(t, 60*time.Second, cache.setTTL("org_region:org-1"),
		"positive entries use the long TTL")

	// Cached fast path: no additional store reads.
	_ = r.Resolve(ctx, "org-1")
	assert.Equal(t, 1, store.readCalls())

	// Admin invalidation clears the cached decision: the next Resolve
	// re-reads the store instead of serving the stale assignment.
	r.Invalidate(ctx, "org-1")
	assert.Equal(t, 1, cache.dels)
	after := r.Resolve(ctx, "org-1")
	assert.Equal(t, "eu", after.HomeRegion)
	assert.Equal(t, 2, store.readCalls(), "invalidated entry re-reads the store")
}

// TestN09P1T10_Risk_AdminWriteIsGatedOnAWriterStore: SetAssignment is the
// rights-relevant admin action. A read-only store refuses the whole action —
// the cached decision is left untouched, so the refusal never half-applies.
// A writer store upserts and then invalidates.
func TestN09P1T10_Risk_AdminWriteIsGatedOnAWriterStore(t *testing.T) {
	t.Parallel()

	t.Run("read-only store: refused, cache untouched", func(t *testing.T) {
		t.Parallel()

		store := &t10Store{}
		cache := newT10KV()
		r := New(store, cache)
		ctx := context.Background()
		_ = r.Resolve(ctx, "org-9") // prime the cache

		err := r.SetAssignment(ctx, "org-9", "us", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read-only")
		assert.Equal(t, 0, cache.dels, "a refused admin write must not invalidate anything")
		assert.Equal(t, 1, store.readCalls(), "the write path never touches the store")
	})

	t.Run("writer store: upsert then invalidate", func(t *testing.T) {
		t.Parallel()

		store := &t10WriterStore{}
		cache := newT10KV()
		r := New(store, cache)
		ctx := context.Background()
		_ = r.Resolve(ctx, "org-9")

		require.NoError(t, r.SetAssignment(ctx, "org-9", "us", true))
		assert.Equal(t, 1, store.upserts)
		assert.Equal(t, 1, cache.dels, "the write path invalidates the cached decision")
	})
}

// t10WriterStore is an orgStore that also exposes the admin write.
type t10WriterStore struct {
	t10Store
	upserts int
}

func (s *t10WriterStore) UpsertRegion(_ context.Context, _, _ string, _ bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upserts++
	return nil
}

// compile-time guards: the stubs satisfy the Router's contracts.
var (
	_ orgStore  = (*t10Store)(nil)
	_ kvStore   = (*t10KV)(nil)
	_ orgWriter = (*t10WriterStore)(nil)
)
