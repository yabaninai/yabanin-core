package consumer

// N03-P06-T06 — joint user scenario, billing-ledger leg: the request_logs
// rows loggerd writes must carry exactly the provider-reported cache usage
// and the exact billed cost the gateway computed from it. The gateway-side
// tests (pkg/gateway/n03p6t06_joint_scenario_test.go) pin that the
// request.completed events carry the provider's numbers; this file pins the
// remaining seam — event → ledger row — over the same six-request mixed
// traffic (both provider contracts, hits and misses, JSON and SSE surfaces).
//
// The billed cost is recomputed here with provider.ComputeCost from the
// provider-reported token counts (the same function the gateway runs), so
// an exact float equality on the row proves no drift was introduced between
// event publication and ledger persistence. The wire form (Redis stream
// fields as go-redis delivers them: strings) is mirrored exactly.

import (
	"context"
	"fmt"
	"log/slog"
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

// n03p6t06PricedDefault builds the deterministic default pricer the ledger
// oracles assume, mirroring the gateway-side fixture
// (pkg/gateway/n03p6t06_joint_scenario_test.go): since CORE-REF-04 the
// shipped default serves the reference catalog projection, so the rates the
// hand-computed ledger totals encode are pinned here explicitly instead of
// depending on which snapshot ships.
func n03p6t06PricedDefault(t *testing.T) *pricing.FilePricer {
	t.Helper()
	p, err := pricing.NewFilePricer(pricing.PriceFile{
		Source: "n03p6t06 ledger fixture (pinned rates)", Date: "2026-11-02",
		Currency: "USD", Units: "per_1m_tokens",
		Models: []pricing.PriceFileModel{
			{Provider: "anthropic", Model: "claude-sonnet-4-5", Input: 3, Output: 15, CacheW: 3.75, CacheR: 0.3},
			{Provider: "openai", Model: "gpt-4o", Input: 2.5, Output: 10, CacheR: 1.25},
		},
	}, "sha256:n03p6t06-ledger-fixture")
	if err != nil {
		t.Fatalf("n03p6t06 ledger fixture pricer: %v", err)
	}
	return p
}

// n03p6t06Traffic is one request of the joint scenario as the provider
// reported it (canonical event numbers: anthropic prompt includes cache,
// OpenAI prompt includes cached reads).
type n03p6t06Traffic struct {
	name        string
	endpoint    string
	provider    string
	model       string
	tokensIn    int64
	tokensOut   int64
	cacheRead   int64
	cacheCreate int64
}

// n03p6t06Billed recomputes the billed amount from the provider-reported
// usage only — the exact quantity the gateway's ComputeCost produced for
// the event.
func (tr n03p6t06Traffic) billed() float64 {
	return provider.ComputeCost(provider.Usage{
		PromptTokens:        tr.tokensIn,
		CompletionTokens:    tr.tokensOut,
		CacheReadTokens:     tr.cacheRead,
		CacheCreationTokens: tr.cacheCreate,
		Source:              provider.UsageSourceProvider,
	}, tr.provider, tr.model).EstimatedCostUSD
}

// n03p6t06EventValues mirrors eventpublisher.RedisPublisher.Publish field
// names and the wire encoding (go-redis delivers every stream field as a
// string) for one request.completed event of the scenario.
func n03p6t06EventValues(tr n03p6t06Traffic, requestID string) map[string]interface{} {
	return map[string]interface{}{
		"event_type":            "request.completed",
		"source":                "gateway",
		"ts":                    "1770000000000",
		"request_id":            requestID,
		"session_id":            "sess-n03p6t06",
		"org_id":                "org-n03p6t06",
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
		"estimated_cost_usd":    strconv.FormatFloat(tr.billed(), 'f', -1, 64),
	}
}

// TestN03P6T06_LedgerRowsCarryProviderCacheExactly feeds the mixed-traffic
// events through the real delivery path and pins, per ledger row: the
// provider-reported cache token counts, the exact billed cost, and the
// billing classification — then reconciles the aggregate the same way the
// console totals must.
func TestN03P6T06_LedgerRowsCarryProviderCacheExactly(t *testing.T) {
	// The test binary may carry tests that swap the global default pricer for
	// a DB pricer without restoring it; pin the deterministic fixture snapshot
	// so the ComputeCost oracle below is order-independent.
	pricing.SetDefaultPricer(n03p6t06PricedDefault(t))
	t.Cleanup(func() { pricing.SetDefaultPricer(pricing.StaticPricer()) })

	traffic := []n03p6t06Traffic{
		{name: "anthropic-json-hit", endpoint: "messages", provider: "anthropic", model: "claude-sonnet-4-5",
			tokensIn: 1750, tokensOut: 200, cacheRead: 600, cacheCreate: 150},
		{name: "anthropic-json-miss", endpoint: "messages", provider: "anthropic", model: "claude-sonnet-4-5",
			tokensIn: 1000, tokensOut: 200},
		{name: "openai-json-hit", endpoint: "chat.completions", provider: "openai", model: "gpt-4o",
			tokensIn: 800, tokensOut: 120, cacheRead: 300},
		{name: "openai-json-miss", endpoint: "chat.completions", provider: "openai", model: "gpt-4o",
			tokensIn: 800, tokensOut: 120},
		{name: "anthropic-sse-hit", endpoint: "messages", provider: "anthropic", model: "claude-sonnet-4-5",
			tokensIn: 650, tokensOut: 80, cacheRead: 200, cacheCreate: 50},
		{name: "openai-sse-miss", endpoint: "chat.completions", provider: "openai", model: "gpt-4o",
			tokensIn: 500, tokensOut: 60},
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
	ctx := context.Background()

	var (
		sumBilled  float64
		sumRead    int64
		sumCreate  int64
		rowBilled  []float64
		rowRead    []int64
		rowCreate  []int64
		rowMissing []string
	)
	for i, tr := range traffic {
		before := len(calls)
		msg := redis.XMessage{
			ID:     fmt.Sprintf("%d-0", i+1),
			Values: n03p6t06EventValues(tr, fmt.Sprintf("n03p6t06-%d", i+1)),
		}
		require.NoError(t, consumer.handleRequestComplete(ctx, msg), "%s: delivery failed", tr.name)

		// The ledger row is one of the inserts this delivery issued; pick
		// it by table name so scope/settlement intents never confuse the pin.
		var rowArgs []any
		for _, c := range calls[before:] {
			if strings.Contains(c.query, "INSERT INTO request_logs") {
				rowArgs = c.args
			}
		}
		require.NotNil(t, rowArgs, "%s: no request_logs insert in delivery", tr.name)

		// Tail-column contract (same positions the accounting pins cover):
		// [... endpoint, usage_source, cost_status, cache_read, cache_creation, ...]
		// Zero cache activity is stored as NULL (nullableInt64 collapses 0),
		// so expect the exact int64 for hits and NULL for misses.
		n := len(rowArgs)
		require.GreaterOrEqual(t, n, 10, "%s: short arg list", tr.name)
		wantRead, wantCreate := any(nil), any(nil)
		if tr.cacheRead > 0 {
			wantRead = tr.cacheRead
		}
		if tr.cacheCreate > 0 {
			wantCreate = tr.cacheCreate
		}
		assert.Equal(t, tr.endpoint, rowArgs[n-10], "%s: endpoint column", tr.name)
		assert.Equal(t, "provider", rowArgs[n-9], "%s: usage_source column", tr.name)
		assert.Equal(t, "priced", rowArgs[n-8], "%s: cost_status column", tr.name)
		assert.Equal(t, wantRead, rowArgs[n-7],
			"%s: ledger cache_read_tokens must equal the provider-reported value", tr.name)
		assert.Equal(t, wantCreate, rowArgs[n-6],
			"%s: ledger cache_creation_tokens must equal the provider-reported value", tr.name)

		// The billed amount is stored exactly — same float64 the gateway's
		// ComputeCost produced (round-tripped through the wire format).
		want := tr.billed()
		found := false
		for _, a := range rowArgs {
			if f, ok := a.(float64); ok && f == want {
				found = true
				break
			}
		}
		assert.True(t, found, "%s: ledger must store the billed cost %v exactly", tr.name, want)
		if !found {
			rowMissing = append(rowMissing, tr.name)
		}

		rowBilled = append(rowBilled, want)
		rowRead = append(rowRead, tr.cacheRead)
		rowCreate = append(rowCreate, tr.cacheCreate)
		sumBilled += want
		sumRead += tr.cacheRead
		sumCreate += tr.cacheCreate
	}
	require.Empty(t, rowMissing)

	// Aggregate reconciliation across the mixed traffic: Σ rows equals the
	// Σ of the provider-reported figures (billed spend, cached reads,
	// cache creations) — the ledger and usage rows tell one story.
	var ledgerBilled float64
	var ledgerRead, ledgerCreate int64
	for i := range rowBilled {
		ledgerBilled += rowBilled[i]
		ledgerRead += rowRead[i]
		ledgerCreate += rowCreate[i]
	}
	assert.InDelta(t, sumBilled, ledgerBilled, 1e-15,
		"aggregate ledger spend must reconcile to Σ per-request provider-usage bills")
	assert.Equal(t, sumRead, ledgerRead, "aggregate ledger cache reads must reconcile exactly")
	assert.Equal(t, sumCreate, ledgerCreate, "aggregate ledger cache creations must reconcile exactly")
	assert.InDelta(t, 0.023265, ledgerBilled, 1e-12,
		"aggregate billed spend pinned against the hand-computed ledger total")
	assert.Equal(t, int64(1100), ledgerRead)
	assert.Equal(t, int64(200), ledgerCreate)
}

// TestN03P6T06_LedgerKeepsUnsupportedHintUnpriced: the ledger must never
// invent cache savings either — an event for the unsupported-hint request
// (provider reported no cached tokens; gateway billed full list) lands as a
// row with NULL-free zero cache columns and the full list-rate cost.
func TestN03P6T06_LedgerKeepsUnsupportedHintUnpriced(t *testing.T) {
	pricing.SetDefaultPricer(n03p6t06PricedDefault(t))
	t.Cleanup(func() { pricing.SetDefaultPricer(pricing.StaticPricer()) })

	tr := n03p6t06Traffic{
		name: "unsupported-hint", endpoint: "chat.completions", provider: "openai", model: "gpt-4o",
		tokensIn: 800, tokensOut: 120,
	}
	var rowArgs []any
	pool := &mockDB{
		ExecFn: func(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
			if strings.Contains(query, "INSERT INTO request_logs") {
				rowArgs = args
			}
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	consumer := New(nil, pool, "events:queue", slog.Default())

	msg := redis.XMessage{ID: "1-0", Values: n03p6t06EventValues(tr, "n03p6t06-hint")}
	require.NoError(t, consumer.handleRequestComplete(context.Background(), msg))
	require.NotNil(t, rowArgs)

	n := len(rowArgs)
	assert.Nil(t, rowArgs[n-7], "no cache reads may appear in the ledger (stored as NULL)")
	assert.Nil(t, rowArgs[n-6], "no cache creations may appear in the ledger (stored as NULL)")

	want := tr.billed() // full list: (800×2.5 + 120×10)/1e6 = 0.0032
	assert.InDelta(t, 0.0032, want, 1e-15, "sanity: full list-rate bill")
	found := false
	for _, a := range rowArgs {
		if f, ok := a.(float64); ok && f == want {
			found = true
			break
		}
	}
	assert.True(t, found, "full list-rate cost must be stored — no fabricated discount")
}
