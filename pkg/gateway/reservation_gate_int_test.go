//go:build integration

// NEXT-18c gateway-level acceptance on a disposable live Postgres: the
// enforce denial surfaces through the REAL chat handler (402 at exhaustion —
// including for a would-be cache hit, D7), shadow serves with a would_deny
// metric and no reserve linkage, a funded enforce org completes with reserve
// tuples + termination on the event, unpriced models answer 403
// model_unpriced (I3), and off keeps events free of reservation fields.
package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/cache"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// seedReservationsOrg creates the organization row (uuid PK) + wallet and
// sets its §9 mode. Balance 0 with a NULL floor and a store floor of 0
// leaves free capacity at 0 — exhausted for any positive bound.
func seedReservationsOrg(t *testing.T, pool *pgxpool.Pool, mode string, balanceCents int64) string {
	t.Helper()
	ctx := context.Background()
	org := uuid.New()
	_, err := pool.Exec(ctx,
		`INSERT INTO organizations (id, name, slug, reservations_mode) VALUES ($1, $2, $3, $4)`,
		org, "g18c-"+org.String()[:8], "g18c-"+org.String()[:8], mode)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`INSERT INTO org_credits (org_id, balance_cents, remainder_micro_usd, reserved_micro_usd)
		 VALUES ($1, $2, 0, 0)
		 ON CONFLICT (org_id) DO UPDATE SET balance_cents = $2, reserved_micro_usd = 0`,
		org.String(), balanceCents)
	require.NoError(t, err)
	return org.String()
}

func setOrgMode(t *testing.T, pool *pgxpool.Pool, org, mode string) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`UPDATE organizations SET reservations_mode = $2 WHERE id = $1::uuid`, org, mode)
	require.NoError(t, err)
}

// gwStubPricer prices every model at the given USD-per-1M rates.
type gwStubPricer struct{ in, out float64 }

func (p gwStubPricer) Lookup(_, _ string) (pricing.Price, bool) {
	return pricing.Price{InputPerM: p.in, OutputPerM: p.out}, true
}

// gwEmptyPricer prices nothing — every model is unpriced (I3).
type gwEmptyPricer struct{}

func (gwEmptyPricer) Lookup(_, _ string) (pricing.Price, bool) { return pricing.Price{}, false }

// gatewayRates prices the harness model: base 2 USD/1M for budget scopes,
// resale 2.3 USD/1M (before the default 15% markup the MarkupPricer adds).
func gatewayRates(pool *pgxpool.Pool) budget.ScopedRateSource {
	return budget.ScopedRateSource{
		Base:   budget.BaseRateSource{Pricer: gwStubPricer{in: 2, out: 2}},
		Resale: budget.ResaleRateSource{Markup: pricing.NewMarkupPricer(pool, gwStubPricer{in: 2.3, out: 2.3}, nil)},
	}
}

// newReservationGateway wires the chat pipeline with a reservations
// controller over the live pool, a stub resolver and a mock upstream.
func newReservationGateway(t *testing.T, pool *pgxpool.Pool, up *httptest.Server, gate budget.Mode) *gateway {
	t.Helper()
	gw := streamTestGateway(up.URL)
	gw.retryPolicy.MaxAttempts = 1
	gw.res = stubModelResolver{
		"stub-model": {ModelName: "stub-model", Provider: "openai", UpstreamURL: up.URL, Enabled: true},
	}
	if gate != budget.ModeOff {
		store := budget.NewReservationStoreWithConfig(pool, nil, budget.ReservationConfig{
			DefaultGraceFloorCents: 0, // free capacity == balance
		})
		gw.admission = budget.NewAdmission(store, gatewayRates(pool), nil,
			"gw-int-"+uuid.NewString()[:8], gate, reservationOrgLoader(pool), budget.DefaultAdmissionConfig())
	}
	return gw
}

// hitCache is a responseCache double that always answers a warm entry.
type hitCache struct{ hit bool }

func (c *hitCache) LookupWithResult(_ context.Context, _ cache.RouteIdentity, _ []byte) (*cache.CacheHit, error) {
	if !c.hit {
		return nil, nil
	}
	return &cache.CacheHit{
		Data:       []byte(`{"id":"warm","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"cached"},"finish_reason":"stop"}]}`),
		SourceType: "exact",
		ModelUsed:  "stub-model",
	}, nil
}

func (c *hitCache) Write(_ context.Context, _ cache.RouteIdentity, _, _ json.RawMessage, _, _ int) error {
	return nil
}

// postChat drives the real handler with the given org header.
func postChat(t *testing.T, gw *gateway, org, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Org-Id", org)
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)
	return rec
}

const bigOutBody = `{"model":"stub-model","messages":[{"role":"user","content":"hi"}],"max_tokens":131072}`

// TestNext18cLiveGateway_EnforceDeniesCacheHitToo: an exhausted enforce org
// is refused (402 insufficient_credits) at the pre-check — BEFORE the cache
// branch, so even a warm entry is not served (D7).
func TestNext18cLiveGateway_EnforceDeniesCacheHitToo(t *testing.T) {
	pool := testdb.Postgres(t)
	up, _, _ := af03Upstream(t)
	org := seedReservationsOrg(t, pool, "enforce", 0)
	gw := newReservationGateway(t, pool, up, budget.ModeEnforce)
	c := &hitCache{hit: true}
	gw.cache = c

	rec := postChat(t, gw, org, bigOutBody)
	require.Equal(t, http.StatusPaymentRequired, rec.Code, "body: %s", rec.Body.String())
	require.Contains(t, rec.Body.String(), "insufficient_credits")
	require.NotContains(t, rec.Body.String(), "cached", "a warm entry must not be served at exhaustion (D7)")

	// A funded org passes the same gate and reaches the upstream.
	funded := seedReservationsOrg(t, pool, "enforce", 100000) // $1000 → free 10M µ
	rec = postChat(t, gw, funded, bigOutBody)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
}

// TestNext18cLiveGateway_ShadowServesAtExhaustion: shadow never denies —
// the exhausted request is served and the would_deny metric moves.
func TestNext18cLiveGateway_ShadowServesAtExhaustion(t *testing.T) {
	pool := testdb.Postgres(t)
	up, calls, _ := af03Upstream(t)
	org := seedReservationsOrg(t, pool, "shadow", 0)
	gw := newReservationGateway(t, pool, up, budget.ModeShadow)

	before := testutil.ToFloat64(metrics.ReservationsWouldDenyTotal.WithLabelValues("wallet"))
	rec := postChat(t, gw, org, bigOutBody)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	require.Positive(t, calls.Load(), "shadow request reached the upstream")
	after := testutil.ToFloat64(metrics.ReservationsWouldDenyTotal.WithLabelValues("wallet"))
	require.Greater(t, after, before, "exhaustion recorded as would_deny")
}

// TestNext18cLiveGateway_EventCarriesTuplesAndTermination: a funded
// enforce org completes; the completion event carries the reserve tuples
// (wallet, priced bound) and the completed termination.
func TestNext18cLiveGateway_EventCarriesTuplesAndTermination(t *testing.T) {
	pool := testdb.Postgres(t)
	up, _, _ := af03Upstream(t)
	org := seedReservationsOrg(t, pool, "enforce", 100000)
	gw := newReservationGateway(t, pool, up, budget.ModeEnforce)

	restore := observeEvent(func(ev *eventpub.Event) {
		if ev.EventType != "request.completed" {
			return
		}
		require.NotEmpty(t, ev.Reservations, "reserve tuples ride the completion event")
		var tuples []struct {
			ScopeKind     string `json:"scope_kind"`
			ScopeKey      string `json:"scope_key"`
			Period        string `json:"period"`
			AllowanceID   int64  `json:"allowance_id"`
			BoundMicroUSD int64  `json:"bound_micro_usd"`
		}
		require.NoError(t, json.Unmarshal([]byte(ev.Reservations), &tuples))
		require.NotEmpty(t, tuples)
		require.Equal(t, "wallet", tuples[0].ScopeKind)
		require.Equal(t, org, tuples[0].ScopeKey)
		require.Positive(t, tuples[0].AllowanceID)
		require.Positive(t, tuples[0].BoundMicroUSD)
		require.Equal(t, "completed", ev.Termination)
		// The reserve landed in the scope row.
		var reserved int64
		require.NoError(t, pool.QueryRow(context.Background(),
			`SELECT reserved_micro_usd FROM org_credits WHERE org_id = $1`, org).Scan(&reserved))
		require.Positive(t, reserved)
	})
	defer restore()

	rec := postChat(t, gw, org, bigOutBody)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
}

// TestNext18cLiveGateway_UnpricedModel403: enforce + a chain without any
// priced candidate answers 403 model_unpriced (I3) — the pricing source,
// not the registry, decides.
func TestNext18cLiveGateway_UnpricedModel403(t *testing.T) {
	pool := testdb.Postgres(t)
	up, _, _ := af03Upstream(t)
	org := seedReservationsOrg(t, pool, "enforce", 100000)

	gw := newReservationGateway(t, pool, up, budget.ModeOff) // off: wire manually
	store := budget.NewReservationStoreWithConfig(pool, nil, budget.ReservationConfig{
		DefaultGraceFloorCents: 0,
	})
	unpriced := budget.ScopedRateSource{
		Base:   budget.BaseRateSource{Pricer: gwEmptyPricer{}},
		Resale: budget.ResaleRateSource{Markup: pricing.NewMarkupPricer(pool, gwEmptyPricer{}, nil)},
	}
	gw.admission = budget.NewAdmission(store, unpriced, nil,
		"gw-int-"+uuid.NewString()[:8], budget.ModeEnforce, reservationOrgLoader(pool), budget.DefaultAdmissionConfig())

	rec := postChat(t, gw, org, bigOutBody)
	require.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
	require.Contains(t, rec.Body.String(), "model_unpriced")
}

// TestNext18cLiveGateway_OffKeepsEventsClean: with the gate off (nil
// controller) the completion event carries no reservation fields — the
// legacy event shape is preserved bit-for-bit.
func TestNext18cLiveGateway_OffKeepsEventsClean(t *testing.T) {
	pool := testdb.Postgres(t)
	up, _, _ := af03Upstream(t)
	org := seedReservationsOrg(t, pool, "off", 100000)
	gw := newReservationGateway(t, pool, up, budget.ModeOff)

	restore := observeEvent(func(ev *eventpub.Event) {
		if ev.EventType != "request.completed" {
			return
		}
		require.Empty(t, ev.Reservations)
		require.Empty(t, ev.Termination)
	})
	defer restore()

	rec := postChat(t, gw, org, bigOutBody)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
}

// TestNext18cLiveGateway_TeamScopeDenial: an enforce org with an exhausted
// hard team budget answers 429 budget_exceeded — the refusal names the area.
func TestNext18cLiveGateway_TeamScopeDenial(t *testing.T) {
	pool := testdb.Postgres(t)
	up, _, _ := af03Upstream(t)
	org := seedReservationsOrg(t, pool, "enforce", 100000)

	team := uuid.New()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO organizations_teams (id, org_id, name, slug) VALUES ($1, $2::uuid, 't18c', 't18c')`,
		team, org)
	require.NoError(t, err)
	_, err = pool.Exec(context.Background(),
		`INSERT INTO team_budgets (team_id, monthly_limit_usd, hard_limit) VALUES ($1, 0.000001, true)`, team)
	require.NoError(t, err)

	gw := newReservationGateway(t, pool, up, budget.ModeEnforce)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(bigOutBody))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Org-Id", org)
	r.Header.Set("X-Team-Id", team.String())
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)
	require.Equal(t, http.StatusTooManyRequests, rec.Code, "body: %s", rec.Body.String())
	require.Contains(t, rec.Body.String(), "budget_exceeded")
}
