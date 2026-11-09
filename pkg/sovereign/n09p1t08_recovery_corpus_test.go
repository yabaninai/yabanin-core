package sovereign

// N09-P01-T08 recovery corpus — the sovereignty policy layer (pkg/sovereign).
//
// The store's degraded-nil path (TestPolicyStore_NilStore_ReturnsDefault),
// the egress precedence order and the per-kind selection are pinned by
// policy_test.go, egress_test.go and the T07 boundary corpus. This corpus
// adds the recovery dimension those leave open: a REAL outage of both the
// Redis cache and the Postgres row store — what the store answers while the
// dependency is down (including a request whose context dies mid-decision),
// what changes when the row store comes back, and whether the degraded
// interval can poison the recovered answers; plus the serialization round
// trip the cache path performs, pinned at the level of routing DECISIONS
// (Allows / CheckEgress), not just struct equality.
//
// Two properties are pinned here:
//  1. During a full policy-store outage the store falls open to the
//     permissive default — and the default keeps the CN gate shut (CNGuard
//     independence). A cancelled context degrades identically, never
//     half-read. Recovery is not sticky: the next Get returns the real row,
//     re-reads keep returning it, and the recovered row answers what the
//     degraded default could not.
//  2. The JSON round trip (the cache write/read path) preserves the policy
//     struct and every routing decision it drives — allow/deny per model
//     and per egress kind, with the exact denial reasons.

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// t08PgRow is a scripted single-row Scan result (or a scripted failure).
type t08PgRow struct {
	reqTier string
	excl    []string
	buyer   string
	cn      bool
	err     error
}

func (r *t08PgRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*string)) = r.reqTier
	*(dest[1].(*[]string)) = r.excl
	*(dest[2].(*string)) = r.buyer
	*(dest[3].(*bool)) = r.cn
	return nil
}

// t08PgQueryer is a PgQueryer whose single row flips between outage
// (nil row → Scan error) and recovery (a real row).
type t08PgQueryer struct {
	mu  sync.Mutex
	row *t08PgRow
}

func (q *t08PgQueryer) QueryRow(context.Context, string, ...any) PgRow {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.row == nil {
		return &t08PgRow{err: errors.New("pq: the database system is shutting down")}
	}
	return q.row
}

// TestN09P1T08_Recovery_PolicyStoreOutageFallsOpenThenRecoversRow drives the
// store against a dead Redis (loopback port 1 — connection refused) and a
// Postgres stub that fails first and recovers mid-test.
func TestN09P1T08_Recovery_PolicyStoreOutageFallsOpenThenRecoversRow(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1",
		MaxRetries:  -1, // fail fast and deterministically on the dead port
		DialTimeout: time.Second,
		ReadTimeout: time.Second,
	})
	t.Cleanup(func() { _ = rdb.Close() })
	pg := &t08PgQueryer{}
	store := NewPolicyStore(rdb, pg)

	cnModel := ModelMeta{ModelName: "cn-flagged", CNFlagged: true, Tier: TierFull}

	// Outage: both the cache and the row store are unreachable — the store
	// falls open to the permissive default.
	got := store.Get(context.Background(), "org-1")
	assert.Equal(t, DefaultPolicy(), got)
	assert.False(t, got.Allows(cnModel),
		"the degraded default keeps the CN gate shut — CNGuard independence survives the outage")

	// A cancelled context (the request dying mid-decision) degrades the
	// same way — never a half-read policy.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.Equal(t, DefaultPolicy(), store.Get(ctx, "org-1"))

	// Recovery: the row store comes back — the next Get returns the real
	// row, not the sticky default.
	pg.mu.Lock()
	pg.row = &t08PgRow{reqTier: string(TierFull), excl: []string{"RU"}, buyer: "DE", cn: true}
	pg.mu.Unlock()
	got = store.Get(context.Background(), "org-1")
	assert.Equal(t, Policy{
		RequiredTier:      TierFull,
		ExcludedCountries: []string{"RU"},
		BuyerJurisdiction: "DE",
		CNAllowed:         true,
	}, got)

	// The recovery is not a one-shot: re-reads — and an explicit cache
	// invalidation followed by a re-read — keep returning the row.
	assert.Equal(t, got, store.Get(context.Background(), "org-1"))
	store.Invalidate(context.Background(), "org-1")
	assert.Equal(t, got, store.Get(context.Background(), "org-1"))

	// The recovered policy answers what the degraded default could not —
	// the outage interval left no residue in either direction.
	assert.True(t, got.Allows(cnModel),
		"the recovered row explicitly allows CN models — the outage answer was the default, not the row")
	assert.False(t, got.Allows(ModelMeta{ModelName: "ru-full", Tier: TierFull, Country: "RU"}),
		"the recovered row's org-wide exclusion applies")
}

// TestN09P1T08_Recovery_PolicyRoundTripKeepsDecisions pins the cache
// serialization path: marshal → unmarshal (what PolicyStore writes into and
// reads back from Redis) preserves the policy struct AND every routing
// decision it drives.
func TestN09P1T08_Recovery_PolicyRoundTripKeepsDecisions(t *testing.T) {
	policies := map[string]Policy{
		"default": DefaultPolicy(),
		"row": {
			RequiredTier:      TierFull,
			ExcludedCountries: []string{"RU"},
			BuyerJurisdiction: "DE",
			CNAllowed:         true,
			Egress: map[EgressKind]EgressProfile{
				EgressInference: {AllowedCountries: []string{"DE", "FR"}, ExcludedCountries: []string{"CN"}},
				EgressLogs:      {ExcludedCountries: []string{"US"}},
			},
		},
		"cn_open": {RequiredTier: TierPartial, CNAllowed: true},
	}
	models := map[string]ModelMeta{
		"cn-flagged": {CNFlagged: true, Tier: TierFull, Country: "CN"},
		"de-full":    {Tier: TierFull, Country: "DE"},
		"ru-full":    {Tier: TierFull, Country: "RU"},
		"us-partial": {Tier: TierPartial, Country: "US"},
	}
	egress := []struct {
		kind    EgressKind
		country string
	}{
		{EgressInference, "DE"}, {EgressInference, "CN"}, {EgressInference, "US"},
		{EgressLogs, "US"}, {EgressEmbeddings, "CN"}, {EgressExport, "RU"},
	}

	for name, p := range policies {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(p)
			require.NoError(t, err)
			var rebuilt Policy
			require.NoError(t, json.Unmarshal(raw, &rebuilt))
			assert.Equal(t, p, rebuilt, "the round trip preserves the policy struct")

			for mName, m := range models {
				assert.Equal(t, p.Allows(m), rebuilt.Allows(m),
					"model %s: the rebuilt policy must answer identically", mName)
			}
			for _, e := range egress {
				okA, reasonA := p.CheckEgress(e.kind, e.country)
				okB, reasonB := rebuilt.CheckEgress(e.kind, e.country)
				assert.Equal(t, okA, okB, "%s→%s: identical verdict", e.kind, e.country)
				assert.Equal(t, reasonA, reasonB, "%s→%s: identical denial reason", e.kind, e.country)
			}
		})
	}

	// Absolute pins for the richest policy: the round trip preserves real
	// delivered answers, not just self-consistency.
	var row Policy
	raw, err := json.Marshal(policies["row"])
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &row))
	ok, reason := row.CheckEgress(EgressInference, "CN")
	assert.False(t, ok)
	assert.Equal(t, DenialKindExcluded, reason)
	ok, reason = row.CheckEgress(EgressInference, "US")
	assert.False(t, ok)
	assert.Equal(t, DenialKindNotAllowed, reason)
	ok, reason = row.CheckEgress(EgressInference, "DE")
	assert.True(t, ok)
	assert.Equal(t, DenialReason(""), reason)
	assert.True(t, row.Allows(models["cn-flagged"]),
		"the explicit CN allowance survives the round trip")
	assert.False(t, row.Allows(models["ru-full"]))
	assert.True(t, policies["default"].Allows(models["us-partial"]),
		"the permissive default answers through the round trip unchanged")
}
