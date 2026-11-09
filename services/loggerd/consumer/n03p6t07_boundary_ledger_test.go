package consumer

// N03-P06-T07 — boundary regression corpus, ledger leg: the request_logs
// rows loggerd writes must mirror the gateway's boundary billing exactly —
// the fully-cached floor, the anthropic write premium, the clamped
// malformed-usage bill, and the known defects (D1 negative provider fields,
// the wrapped-overflow astronomical bill). The gateway-side pins live in
// pkg/gateway/n03p6t07_boundary_corpus_test.go; this file pins the
// event → ledger row seam over the same boundary shapes.
//
// Positions are pinned by the tail-column contract (endpoint/usage_source/
// cost_status/cache_read/cache_creation, same as T06) and — strengthened
// per F3 — by the bound-argument order of fullRequestLogRow:
// args[14] = counterfactual_cost_usd, args[15] = cost_in_usd.
// nullableInt64 collapses only exact 0; negative provider counts are
// therefore mirrored verbatim (prior behavior, see D1 handoff).

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
)

// n03p6t07LedgerArgs captures the request_logs insert arguments of one
// delivery (the last insert issued for the given delivery, selected by
// table name so scope/settlement intents never confuse the pin).
func n03p6t07LedgerArgs(t *testing.T, consumer *StreamConsumer, msg redis.XMessage, pool *mockDB) []any {
	t.Helper()
	var rowArgs []any
	pool.ExecFn = func(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
		if strings.Contains(query, "INSERT INTO request_logs") {
			rowArgs = args
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}
	require.NoError(t, consumer.handleRequestComplete(context.Background(), msg))
	require.NotNil(t, rowArgs, "delivery must issue a request_logs insert")
	require.Greater(t, len(rowArgs), 16, "canonical row must expose the cost positions")
	return rowArgs
}

// n03p6t07BoundaryValues mirrors eventpublisher.RedisPublisher.Publish
// field names and the wire encoding for one boundary request.completed
// event. counterfactualUSD nil means the gateway published no baseline
// (the native /v1/messages finisher) — the wire field is absent.
func n03p6t07BoundaryValues(requestID string, tr n03p6t06Traffic, costUSD float64, counterfactualUSD *float64) map[string]interface{} {
	values := map[string]interface{}{
		"event_type":            "request.completed",
		"source":                "gateway",
		"ts":                    "1770000000000",
		"request_id":            requestID,
		"session_id":            "sess-n03p6t07",
		"org_id":                "org-n03p6t07",
		"model_requested":       tr.model,
		"model_used":            tr.model,
		"endpoint":              tr.endpoint,
		"usage_source":          "provider",
		"cost_status":           "priced",
		"status_code":           "200",
		"method":                "POST",
		"tokens_in":             strconv.FormatInt(tr.tokensIn, 10),
		"tokens_out":            strconv.FormatInt(tr.tokensOut, 10),
		"cache_read_tokens":     strconv.FormatInt(tr.cacheRead, 10),
		"cache_creation_tokens": strconv.FormatInt(tr.cacheCreate, 10),
		"estimated_cost_usd":    strconv.FormatFloat(costUSD, 'f', -1, 64),
	}
	if counterfactualUSD != nil {
		values["counterfactual_cost_usd"] = strconv.FormatFloat(*counterfactualUSD, 'f', -1, 64)
	}
	return values
}

// TestN03P6T07_LedgerBoundaryMix_PositionalAndReconciliation: the ledger
// mirrors the gateway's honest boundary bills exactly — the 100%-cached
// floor, the write premium that exceeds no-cache pricing, and the clamped
// malformed-usage bill (cache reads stored verbatim even above prompt) —
// then reconciles the aggregate like the console totals must.
func TestN03P6T07_LedgerBoundaryMix_PositionalAndReconciliation(t *testing.T) {
	pricing.SetDefaultPricer(pricing.StaticPricer())
	t.Cleanup(func() { pricing.SetDefaultPricer(pricing.StaticPricer()) })

	type boundaryRow struct {
		name string
		tr   n03p6t06Traffic
		cost float64
		// counterfactual mirrors the baseline the gateway published: the
		// expected ledger args[14] value.
		counterfactual float64
		publishCounter bool // whether the gateway published a counterfactual baseline
	}
	rows := []boundaryRow{
		{name: "openai-full-cached", tr: n03p6t06Traffic{
			name: "full-cached", endpoint: "chat.completions", provider: "openai", model: "gpt-4o",
			tokensIn: 800, tokensOut: 10, cacheRead: 800,
		},
			// (0×2.5 + 100 + 800×1.25)/1e6 — the cached floor.
			cost: 0.0011, counterfactual: 0.0011, publishCounter: true},
		{name: "anthropic-creation-only", tr: n03p6t06Traffic{
			name: "creation-only", endpoint: "messages", provider: "anthropic", model: "claude-sonnet-4-5",
			tokensIn: 1000, tokensOut: 50, cacheCreate: 2000,
		},
			// (3000 + 750 + 2000×3.75)/1e6 — write premium billed honestly.
			cost: 0.01125, counterfactual: 0, publishCounter: false},
		{name: "openai-clamped-malformed", tr: n03p6t06Traffic{
			name: "clamped", endpoint: "chat.completions", provider: "openai", model: "gpt-4o",
			tokensIn: 800, tokensOut: 10, cacheRead: 1000,
		},
			// ComputeCost clamps the input term: (0 + 100 + 1250)/1e6.
			cost: 0.00135, counterfactual: 0.00135, publishCounter: true},
	}

	type execCall struct {
		query string
		args  []any
	}
	var calls []execCall
	pool := &mockDB{
		ExecFn: func(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
			calls = append(calls, execCall{query: query, args: args})
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	consumer := New(nil, pool, "events:queue", slog.Default())

	var (
		sumCost   float64
		sumRead   int64
		sumCreate int64
	)
	for i, row := range rows {
		cf := row.counterfactual
		var cfWire *float64
		if row.publishCounter {
			cfWire = &cf
		}
		before := len(calls)
		msg := redis.XMessage{
			ID:     fmt.Sprintf("%d-0", i+1),
			Values: n03p6t07BoundaryValues(fmt.Sprintf("n03p6t07-mix-%d", i+1), row.tr, row.cost, cfWire),
		}
		require.NoError(t, consumer.handleRequestComplete(context.Background(), msg), "%s: delivery failed", row.name)

		var rowArgs []any
		for _, c := range calls[before:] {
			if strings.Contains(c.query, "INSERT INTO request_logs") {
				rowArgs = c.args
			}
		}
		require.NotNil(t, rowArgs, "%s: no request_logs insert in delivery", row.name)
		require.Greater(t, len(rowArgs), 16, "%s: short arg list", row.name)

		// F3 positional contract: bound args[15] is cost_in_usd and
		// args[14] is counterfactual_cost_usd (fullRequestLogRow order).
		// InDelta with 0 tolerance asserts the BIT-EXACT float64 round-trip
		// (FormatFloat/ParseFloat) — same semantics as T06's exact equality.
		assert.InDelta(t, row.cost, rowArgs[15], 0, "%s: cost_in_usd position 15 must carry the exact bill", row.name)
		assert.InDelta(t, row.counterfactual, rowArgs[14], 0,
			"%s: counterfactual position 14 must mirror what the gateway published", row.name)

		// Tail columns (same positions as T06): usage source and verbatim
		// cache counts (0 collapses to NULL; read above prompt stays).
		n := len(rowArgs)
		assert.Equal(t, row.tr.endpoint, rowArgs[n-10], "%s: endpoint column", row.name)
		assert.Equal(t, "provider", rowArgs[n-9], "%s: usage_source column", row.name)
		assert.Equal(t, "priced", rowArgs[n-8], "%s: cost_status column", row.name)
		wantRead, wantCreate := any(nil), any(nil)
		if row.tr.cacheRead > 0 {
			wantRead = row.tr.cacheRead
		}
		if row.tr.cacheCreate > 0 {
			wantCreate = row.tr.cacheCreate
		}
		assert.Equal(t, wantRead, rowArgs[n-7], "%s: cache_read verbatim (incl. above-prompt)", row.name)
		assert.Equal(t, wantCreate, rowArgs[n-6], "%s: cache_creation verbatim", row.name)

		sumCost += row.cost
		sumRead += row.tr.cacheRead
		sumCreate += row.tr.cacheCreate
	}

	// Aggregate reconciliation across the boundary mix: Σ rows equals the
	// hand-computed ledger total (0.0011 + 0.01125 + 0.00135).
	assert.InDelta(t, 0.0137, sumCost, 1e-12,
		"aggregate billed spend pinned against the hand-computed boundary total")
	assert.Equal(t, int64(1800), sumRead, "Σ cache reads across the mix")
	assert.Equal(t, int64(2000), sumCreate, "Σ cache creations across the mix")
}

// TestN03P6T07_LedgerMirrorsDefectD1_NegativeRowsAndRollup: the D1 defect
// (negative provider cache fields) flows through the ledger UNCLAMPED —
// the row stores the negative bill and negative token counts verbatim and
// the aggregate inherits a negative total. Documented prior behavior; the
// fix is owned by the D1 handoff, this pin guards against silent change.
func TestN03P6T07_LedgerMirrorsDefectD1_NegativeRowsAndRollup(t *testing.T) {
	pricing.SetDefaultPricer(pricing.StaticPricer())
	t.Cleanup(func() { pricing.SetDefaultPricer(pricing.StaticPricer()) })

	pool := &mockDB{}
	consumer := New(nil, pool, "events:queue", slog.Default())

	// anthropic negative cache_creation: (3000 + 750 − 18750)/1e6 = −0.015.
	negCreate := n03p6t06Traffic{
		name: "neg-create", endpoint: "messages", provider: "anthropic", model: "claude-sonnet-4-5",
		tokensIn: 1000, tokensOut: 50, cacheCreate: -5000,
	}
	rowArgs := n03p6t07LedgerArgs(t, consumer, redis.XMessage{
		ID:     "1-0",
		Values: n03p6t07BoundaryValues("n03p6t07-d1-1", negCreate, -0.015, nil),
	}, pool)
	n := len(rowArgs)
	assert.InDelta(t, -0.015, rowArgs[15], 0, "negative bill stored verbatim at the cost position")
	assert.Equal(t, int64(-5000), rowArgs[n-6],
		"negative cache_creation stored verbatim (nullableInt64 collapses only exact 0)")
	assert.Equal(t, "priced", rowArgs[n-8], "the defect bill still classifies as priced")

	// openai negative cache_read: the unclamped (800+300)×2.5 − 375 + 100 →
	// 0.002475 — an OVERCHARGE above the 0.0021 full list.
	negRead := n03p6t06Traffic{
		name: "neg-read", endpoint: "chat.completions", provider: "openai", model: "gpt-4o",
		tokensIn: 800, tokensOut: 10, cacheRead: -300,
	}
	rowArgs = n03p6t07LedgerArgs(t, consumer, redis.XMessage{
		ID:     "2-0",
		Values: n03p6t07BoundaryValues("n03p6t07-d1-2", negRead, 0.002475, nil),
	}, pool)
	n = len(rowArgs)
	assert.InDelta(t, 0.002475, rowArgs[15], 0, "overcharge bill stored verbatim")
	assert.Equal(t, int64(-300), rowArgs[n-7], "negative cache_read stored verbatim")

	// The aggregate over the defect rows inherits the negative total
	// (−0.015 + 0.002475 = −0.012525) — the same sum the console shows.
	assert.InDelta(t, -0.012525, -0.015+0.002475, 1e-15,
		"aggregate over D1 rows is negative — documented prior behavior")
}

// TestN03P6T07_LedgerOverflowRow_AstronomicallyPositiveBill: the int64
// overflow boundary (read == prompt == MaxInt64) produces a wrapped
// tokens-in and an astronomically large-but-positive bill; the ledger
// stores both verbatim through the wire round-trip — no clamping, no
// sentinel, no negative.
//
// Vehicle note (union 2026-11-03, AUD-PRICE-01 collision): the original
// vehicle openai/gpt-4o is a catalog-draft name the static fallback now
// REFUSES (review-accepted pricing semantics), so Lookup misses and the
// bill collapses to 0. The pinned contract here is the LEDGER boundary —
// wrapped tokens + astronomically positive bill stored verbatim — not the
// gpt-4o price row; the vehicle moves to a catalog-served model
// (anthropic/claude-3-opus-20240229, bill 1.38e13) keeping every
// assertion identical.
func TestN03P6T07_LedgerOverflowRow_AstronomicallyPositiveBill(t *testing.T) {
	pricing.SetDefaultPricer(pricing.StaticPricer())
	t.Cleanup(func() { pricing.SetDefaultPricer(pricing.StaticPricer()) })

	const maxI64 = int64(math.MaxInt64)
	billed := provider.ComputeCost(provider.Usage{
		PromptTokens:     maxI64,
		CompletionTokens: 10,
		CacheReadTokens:  maxI64,
		Source:           provider.UsageSourceProvider,
	}, "anthropic", "claude-3-opus-20240229").EstimatedCostUSD
	assert.Positive(t, billed, "the wrapped-overflow bill stays positive")
	assert.Greater(t, billed, 1e12, "astronomical magnitude pinned")

	tr := n03p6t06Traffic{
		name: "overflow", endpoint: "messages", provider: "anthropic", model: "claude-3-opus-20240229",
		tokensIn: maxI64, tokensOut: 10, cacheRead: maxI64,
	}
	cf := billed
	pool := &mockDB{}
	consumer := New(nil, pool, "events:queue", slog.Default())
	rowArgs := n03p6t07LedgerArgs(t, consumer, redis.XMessage{
		ID:     "1-0",
		Values: n03p6t07BoundaryValues("n03p6t07-overflow", tr, billed, &cf),
	}, pool)
	n := len(rowArgs)
	assert.InDelta(t, billed, rowArgs[15], 0,
		"the exact float64 survives the wire round-trip into cost_in_usd")
	assert.Equal(t, maxI64, rowArgs[8], "wrapped tokens_in stored verbatim")
	assert.Equal(t, maxI64, rowArgs[n-7], "overflow cache_read stored verbatim")
	assert.InDelta(t, billed, rowArgs[14], 0, "counterfactual mirrors the (absurd) actual")
}
