//go:build integration

package adminstore

// Real-Postgres coverage for the durable rates-catalog promotion
// (AUDIT-P1-04) against the squashed baseline + migration 0019:
//   - active-of-record anchoring (bundled → durable row → chained chain);
//   - single-transaction atomicity (failed/refused promotion writes nothing);
//   - advisory-lock serialization of concurrent promotions;
//   - materialization semantics: added/updated rows, manual override
//     retention, close of retired seed rows;
//   - restart + cross-process serve: a fresh pool and a fresh DBPricer
//     read the promoted prices with no in-process state.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pickCatalogActiveModel returns the index of the n-th active entry of the
// catalog (bundled production entries are active and sourced).
func pickCatalogActiveModel(t *testing.T, cat pricing.Catalog, n int) int {
	t.Helper()
	seen := 0
	for i := range cat.Models {
		if cat.Models[i].Status == pricing.RefStatusActive {
			if seen == n {
				return i
			}
			seen++
		}
	}
	t.Fatalf("catalog has only %d active entries, wanted index %d", seen, n)
	return -1
}

// setCatalogInputRate rewrites an entry's input rate amount (fresh pointer —
// loaded pack catalogs may share rate pointers across entries).
func setCatalogInputRate(m *pricing.RefModel, input float64) {
	for ri := range m.Rates {
		if m.Rates[ri].Axis == pricing.AxisInput {
			amt := input
			m.Rates[ri].Amount = &amt
			return
		}
	}
}

func catalogInputRate(m pricing.RefModel) float64 {
	for ri := range m.Rates {
		if m.Rates[ri].Axis == pricing.AxisInput && m.Rates[ri].Amount != nil {
			return *m.Rates[ri].Amount
		}
	}
	return -1
}

func openPricingRowsCount(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM models_pricing WHERE effective_to IS NULL`).Scan(&n))
	return n
}

func promotionWrittenRowsCount(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM models_pricing WHERE updated_by LIKE 'rates-promotion:%'`).Scan(&n))
	return n
}

func TestIntegrationRatesCatalogState_DurableLifecycle(t *testing.T) {
	store, connStr := startStoreDB(t)
	ctx := context.Background()

	// --- Fresh deployment: no durable row, bundled pack is the anchor. ---
	bundled := pricing.BundledRefPackJSON()
	packJSON, found, err := store.DurableRatesCatalogPackJSON(ctx)
	require.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, bundled, packJSON)

	committed, err := CurrentRefRatesCatalog()
	require.NoError(t, err)
	durable, err := store.CurrentDurableRatesCatalog(ctx)
	require.NoError(t, err)
	assert.Equal(t, committed.Ref.Digest, durable.Ref.Digest,
		"without a promotion the GET payload cites the committed pack")

	// --- Pre-seed operator state: a manual override + a retired seed row. ---
	_, baseCat, err := pricing.LoadRefPack(bundled)
	require.NoError(t, err)
	yi := pickCatalogActiveModel(t, baseCat, 0)
	xi := pickCatalogActiveModel(t, baseCat, 1)
	overrideKey := baseCat.Models[xi]

	_, err = store.pool.Exec(ctx, `
		INSERT INTO models_pricing (provider, model, input_per_m, output_per_m, source, updated_by)
		VALUES ($1, $2, 3.333333, 4.444444, 'manual', 'it-operator')`,
		overrideKey.Provider, overrideKey.Model)
	require.NoError(t, err, "manual override row must insert")
	_, err = store.pool.Exec(ctx, `
		INSERT INTO models_pricing (provider, model, input_per_m, output_per_m, source, updated_by)
		VALUES ('it-seed-only', 'ghost', 1, 1, 'seed', 'seed')`)
	require.NoError(t, err, "seed row must insert")

	// --- Promotion 1: chained on the bundled pack. ---
	v2 := baseCat
	v2.Models = append([]pricing.RefModel(nil), baseCat.Models...)
	v2.Version = "it-v2"
	v2.Supersedes = baseCat.Digest
	bumped := v2.Models[yi]
	newInput := catalogInputRate(bumped) + 0.5
	setCatalogInputRate(&v2.Models[yi], newInput)
	v2.Models = append(v2.Models, pricing.RefModel{
		Provider: bumped.Provider, Model: "ci-added-model",
		Currency: "USD", Status: pricing.RefStatusActive,
		EffectiveFrom: "2026-11-01", VerifiedAt: "2026-11-02",
		Rates: []pricing.RefRate{
			{
				Axis: pricing.AxisInput, Unit: pricing.RefUnitPer1MTokens,
				Amount: ptr(7.777777),
			},
			{
				Axis: pricing.AxisOutput, Unit: pricing.RefUnitPer1MTokens,
				Amount: ptr(2.222222),
			},
		},
		Sources: []pricing.RefSource{{
			Kind: pricing.RefSourceURL, Ref: "https://pricing.example.test/ci/added",
			VerifiedAt: "2026-11-02",
		}},
		Reviewer: "it-reviewer",
	})
	v2Pack := ratesChainedPack(t, bundled, v2)

	promo, err := store.PromoteRefCatalogDurable(ctx, v2Pack, "it-operator")
	require.NoError(t, err)
	require.NotNil(t, promo)
	assert.True(t, promo.Applied)
	assert.True(t, promo.Persisted)
	assert.Equal(t, "it-v2", promo.After.Version)
	require.NotNil(t, promo.Materialization)
	assert.GreaterOrEqual(t, promo.Materialization.Added, 1, "the added model (and the rest of the projection) materializes")
	assert.Contains(t, promo.Materialization.RetainedOverrides,
		overrideKey.Provider+"/"+overrideKey.Model,
		"the manual override is reported as retained")

	// Durable row: provenance + exact promoted bytes.
	row, err := store.LoadRatesCatalogState(ctx)
	require.NoError(t, err)
	require.NotNil(t, row)
	assert.Equal(t, "it-v2", row.Version)
	assert.Equal(t, promo.After.Digest, row.Digest)
	assert.Equal(t, "it-operator", row.ActivatedBy)
	assert.Equal(t, v2Pack, row.PackJSON, "the row holds the exact promoted envelope bytes")
	assert.WithinDuration(t, time.Now(), row.ActivatedAt, time.Minute)

	// GET payload now cites the promoted catalog and its bytes re-load.
	getPayload, err := store.CurrentDurableRatesCatalog(ctx)
	require.NoError(t, err)
	assert.Equal(t, "it-v2", getPayload.Ref.Version)
	_, getCat, err := pricing.LoadRefPack(packJSONMust(t, store))
	require.NoError(t, err)
	assert.Equal(t, "it-v2", getCat.Version)

	// --- Restart + cross-process: a FRESH pool and FRESH DBPricer serve
	// the promoted prices with no in-process state. ---
	freshPool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	defer freshPool.Close()

	freshPricer := pricing.NewDBPricer(freshPool)
	price, ok := freshPricer.Lookup(bumped.Provider, bumped.Model)
	require.True(t, ok, "bumped model must be serveable from the table")
	assert.InDelta(t, newInput, price.InputPerM, 1e-6,
		"the promoted input price is served after a cold process start")

	addedPrice, ok := freshPricer.Lookup(bumped.Provider, "ci-added-model")
	require.True(t, ok)
	assert.InDelta(t, 7.777777, addedPrice.InputPerM, 1e-6)

	overridePrice, ok := freshPricer.Lookup(overrideKey.Provider, overrideKey.Model)
	require.True(t, ok)
	assert.InDelta(t, 3.333333, overridePrice.InputPerM, 1e-6,
		"the manual override price keeps serving over the catalog projection")

	// Retired seed row closed by the promotion (ghost key not projected).
	var ghostClosed bool
	require.NoError(t, freshPool.QueryRow(ctx, `
		SELECT (effective_to IS NOT NULL) FROM models_pricing
		WHERE provider = 'it-seed-only' AND model = 'ghost'`).Scan(&ghostClosed))
	assert.True(t, ghostClosed, "the retired seed row must be closed, not left open")
	var overrideOpen bool
	require.NoError(t, freshPool.QueryRow(ctx, `
		SELECT (effective_to IS NULL) FROM models_pricing
		WHERE provider = $1 AND model = $2 AND source = 'manual'`,
		overrideKey.Provider, overrideKey.Model).Scan(&overrideOpen))
	assert.True(t, overrideOpen, "the manual override row stays open")

	// --- Promotion 2: chains on the DURABLE row (restart-proof anchor). ---
	v3Cat := getCat
	v3Cat.Models = append([]pricing.RefModel(nil), getCat.Models...)
	v3Cat.Version = "it-v3"
	yi3 := pickCatalogActiveModel(t, v3Cat, 0)
	setCatalogInputRate(&v3Cat.Models[yi3], newInput+0.25)
	v3Pack := ratesChainedPack(t, v2Pack, v3Cat)
	promo3, err := store.PromoteRefCatalogDurable(ctx, v3Pack, "it-operator-2")
	require.NoError(t, err, "the chain anchor is the durable row, not the bundled pack")
	assert.Equal(t, "it-v3", promo3.After.Version)

	row, err = store.LoadRatesCatalogState(ctx)
	require.NoError(t, err)
	require.NotNil(t, row)
	assert.Equal(t, "it-v3", row.Version)
	assert.Equal(t, "it-operator-2", row.ActivatedBy)

	// --- Refused/stale promotions write NOTHING (atomicity). ---
	before := openPricingRowsCount(t, store.pool)
	beforePromoRows := promotionWrittenRowsCount(t, store.pool)

	stalePack := ratesChainedPack(t, bundled, ratesTestCatalog("it-stale", baseCat.Digest,
		[]pricing.RefModel{ratesActiveModel("it-stale", "m", 1, 2, "it-reviewer")}))
	_, err = store.PromoteRefCatalogDurable(ctx, stalePack, "it-operator")
	require.Error(t, err, "a pack chained on the superseded anchor must be refused")
	assert.Contains(t, err.Error(), "chain")

	assert.Equal(t, before, openPricingRowsCount(t, store.pool), "no materialization rows from a failed promotion")
	assert.Equal(t, beforePromoRows, promotionWrittenRowsCount(t, store.pool), "no promotion-stamped rows from a failed promotion")
	row, err = store.LoadRatesCatalogState(ctx)
	require.NoError(t, err)
	require.NotNil(t, row)
	assert.Equal(t, "it-v3", row.Version, "durable row unchanged after the failed promotion")
}

// packJSONMust reads the current active-of-record pack bytes for re-loading.
func packJSONMust(t *testing.T, store *Store) []byte {
	t.Helper()
	pack, _, err := store.DurableRatesCatalogPackJSON(context.Background())
	require.NoError(t, err)
	return pack
}

func TestIntegrationRatesCatalogState_ConcurrentPromotionsSerialize(t *testing.T) {
	store, _ := startStoreDB(t)
	ctx := context.Background()

	bundled := pricing.BundledRefPackJSON()
	_, baseCat, err := pricing.LoadRefPack(bundled)
	require.NoError(t, err)

	build := func(version string, delta float64) []byte {
		cat := baseCat
		cat.Models = append([]pricing.RefModel(nil), baseCat.Models...)
		cat.Version = version
		i := pickCatalogActiveModel(t, baseCat, 0)
		setCatalogInputRate(&cat.Models[i], catalogInputRate(baseCat.Models[i])+delta)
		return ratesChainedPack(t, bundled, cat)
	}
	packA := build("it-conc-a", 0.10)
	packB := build("it-conc-b", 0.20)

	// Two promotions race for the same anchor; the advisory lock serializes
	// plan→write, so exactly one lands and the other sees the new
	// active-of-record and fails its chain check. Nothing interleaves.
	type result struct {
		version string
		err     error
	}
	results := make([]result, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		promo, err := store.PromoteRefCatalogDurable(ctx, packA, "it-op-a")
		if err != nil {
			results[0] = result{err: err}
			return
		}
		results[0] = result{version: promo.After.Version}
	}()
	go func() {
		defer wg.Done()
		promo, err := store.PromoteRefCatalogDurable(ctx, packB, "it-op-b")
		if err != nil {
			results[1] = result{err: err}
			return
		}
		results[1] = result{version: promo.After.Version}
	}()
	wg.Wait()

	winners := 0
	for _, r := range results {
		if r.err == nil {
			winners++
		} else {
			assert.Contains(t, r.err.Error(), "chain",
				"the loser must fail its chain check against the winner's pack")
		}
	}
	assert.Equal(t, 1, winners, "exactly one racing promotion may land")

	row, err := store.LoadRatesCatalogState(ctx)
	require.NoError(t, err)
	require.NotNil(t, row)
	if row.Version != "it-conc-a" && row.Version != "it-conc-b" {
		t.Fatalf("durable row must be one of the racing packs, got %s", row.Version)
	}
	if row.Version == "it-conc-a" {
		assert.Equal(t, "it-op-a", row.ActivatedBy)
	} else {
		assert.Equal(t, "it-op-b", row.ActivatedBy)
	}

	// The table serves a consistent projection: every open catalog row was
	// written inside the winner's single transaction.
	var openCatalogRows int
	require.NoError(t, store.pool.QueryRow(ctx, `
		SELECT count(*) FROM models_pricing
		WHERE effective_to IS NULL AND source IN ('catalog', 'seed')`).Scan(&openCatalogRows))
	assert.GreaterOrEqual(t, openCatalogRows, 1, "the winner's projection materialized")
}

func TestIntegrationRatesCatalogState_RefusedPromotionAtomic(t *testing.T) {
	store, _ := startStoreDB(t)
	ctx := context.Background()

	bundled := pricing.BundledRefPackJSON()
	_, baseCat, err := pricing.LoadRefPack(bundled)
	require.NoError(t, err)

	// Anchor: promote a catalog carrying a draft entry (draft is legal in a
	// pack; it is just not serveable, so it does not materialize).
	draftCat := baseCat
	draftCat.Models = append([]pricing.RefModel(nil), baseCat.Models...)
	draftCat.Version = "it-draft"
	di := pickCatalogActiveModel(t, baseCat, 0)
	draftEntry := draftCat.Models[di]
	draftEntry.Status = pricing.RefStatusDraft
	draftEntry.Reviewer = ""
	draftCat.Models[di] = draftEntry
	draftPack := ratesChainedPack(t, bundled, draftCat)
	_, err = store.PromoteRefCatalogDurable(ctx, draftPack, "it-op")
	require.NoError(t, err)

	// Refused: the draft entry flips to active with NO reviewer — the
	// review gate must refuse and the transaction must write nothing.
	activeCat := draftCat
	activeCat.Models = append([]pricing.RefModel(nil), draftCat.Models...)
	activeCat.Version = "it-refused"
	flip := activeCat.Models[di]
	flip.Status = pricing.RefStatusActive
	flip.Reviewer = ""
	activeCat.Models[di] = flip
	refusedPack := ratesChainedPack(t, draftPack, activeCat)

	before := openPricingRowsCount(t, store.pool)
	beforePromoRows := promotionWrittenRowsCount(t, store.pool)

	_, err = store.PromoteRefCatalogDurable(ctx, refusedPack, "it-op")
	require.Error(t, err)
	var refusal *RatesRefusal
	require.ErrorAs(t, err, &refusal, "the review-gate refusal must surface as the typed 422 payload")
	require.NotNil(t, refusal.Report)
	assert.True(t, refusal.Report.Refused)

	row, err := store.LoadRatesCatalogState(ctx)
	require.NoError(t, err)
	require.NotNil(t, row)
	assert.Equal(t, "it-draft", row.Version, "durable row unchanged after a refused promotion")
	assert.Equal(t, before, openPricingRowsCount(t, store.pool))
	assert.Equal(t, beforePromoRows, promotionWrittenRowsCount(t, store.pool))
}
