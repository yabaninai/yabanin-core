//go:build integration

// Accounting cancellation/recovery reproducer — task
// accounting-cancel-recovery-repro, base 786885f.
//
// FROZEN CONTRACT (decided before implementation; three-outcome acceptance:
// original red OR verified-negative, bounded fix green, deliberately-broken
// scratch variant red on the SAME invariant):
//
//	Invariant (R1 leaf, accounting-recovery investigation): "client-cancelled
//	stream with known partial usage bills exactly the delivered prefix once,
//	releases the reservation, records unknown usage as uncharged-unknown —
//	never silent zero, never leaked reserve."
//
//	ACC-R1a  client cancels BEFORE any usage chunk → usage unknown.
//	         PASS: zero wallet debit for the request; a durable record
//	         exists (request_logs row + pending_price settlement row);
//	         reservation returns to reserved=0 via the documented
//	         reconcile release path; no debit appears after release.
//	         PREDICTED ORIGINAL: RED — the provider fallback estimates
//	         usage from byte counts on the scanner-error path and the
//	         consumer bills resale(estimate) as if it were known.
//
//	ACC-R1b  client cancels AFTER a usage-bearing chunk (2500+2500 tokens,
//	         0% markup → resale 2.3 USD/1M per side = 11 500 µUSD).
//	         PASS: exactly one debit of exactly -11 500 µUSD; exact wallet
//	         carry math (100 000¢/0µ → 99 999¢/1 500µ); exactly one
//	         'settled' resale_deduction job; reserved returns to 0; no
//	         second debit after the late release.
//	         PREDICTED ORIGINAL: GREEN (verified-negative accepted).
//
//	ACC-R2   settlement worker down during delivery → durable pending job,
//	         no debit; worker start → exactly one debit; worker restart →
//	         still exactly one debit (no loss, no double charge).
//
//	ACC-R3   two concurrent cancels with distinct request IDs → two
//	         independent single debits; byte-identical replay of a settled
//	         event → still exactly one debit for that request; two
//	         concurrent requests sharing one client X-Request-Id → exactly
//	         one debit (documented by-design boundary: the money layer
//	         dedups by request ID while the transport honors client
//	         X-Request-Id verbatim).
//
// Deliberately-broken scratch variants (verified on a throwaway tree, never
// committed): skip-finalize-on-cancel (leaked reserve → R1a/R1b reserved
// stays > 0), unknown-as-zero (pending_price row missing → R1a durable
// signal absent), settle-key idempotency removed (duplicate debit on R3
// replay).
//
// Oracle of record is SQL over credit_transactions / org_credits /
// settlement_jobs / request_logs / budget_allowances — never the service's
// own accounting API.
package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/services/loggerd/consumer"
)

const (
	accStream           = "events:queue"
	accConsumerGroup    = "loggerd-workers"
	accSeedBalanceCents = 100_000
	// 2500 in + 2500 out tokens at 2.3 USD/1M with 0% org markup:
	// (2500+2500) * 2.3 / 1e6 USD = 11 500 µUSD = 1¢ + 1 500µ carry.
	accResaleMicro = 11_500
	accBody        = `{"model":"stub-model","messages":[{"role":"user","content":"hi"}],"stream":true,"max_tokens":16384}`
	// chunk1: content only — no usage information.
	accContentChunk = `data: {"id":"acc-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hello"},"finish_reason":null}]}` + "\n\n"
	// chunk2: content + final usage from the provider.
	accUsageChunk = `data: {"id":"acc-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":" world"},"finish_reason":null}],"usage":{"prompt_tokens":2500,"completion_tokens":2500,"total_tokens":5000}}` + "\n\n"
)

// accUpstream is a barrier-held SSE upstream: it writes the scripted chunks,
// flushes each, then holds the connection open until release (test end) or
// until the gateway drops it (client cancellation propagating upstream).
type accUpstream struct {
	srv     *httptest.Server
	release chan struct{}
	once    sync.Once
	dropped atomic.Bool
}

func accStartUpstream(t *testing.T, chunks []string) *accUpstream {
	t.Helper()
	up := &accUpstream{release: make(chan struct{})}
	up.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		for _, c := range chunks {
			fmt.Fprint(w, c)
			if flusher != nil {
				flusher.Flush()
			}
		}
		select {
		case <-up.release:
			fmt.Fprint(w, "data: [DONE]\n\n")
			if flusher != nil {
				flusher.Flush()
			}
		case <-r.Context().Done():
			up.dropped.Store(true)
		}
	}))
	t.Cleanup(func() {
		up.once.Do(func() { close(up.release) })
		up.srv.Close()
	})
	return up
}

// accShared holds the process-wide consumer. A per-test consumer cannot
// work here: Start's shutdown is abrupt by design (detached groupCtx), so
// a canceled consumer can still have one blocked XREADGROUP in flight that
// resolves with the NEXT test's message — claiming it with a dead context
// and stranding it in the PEL. One shared consumer eliminates the zombie
// window; every message is org/request-scoped so cross-test sharing is
// safe, and each test's oracle filters by its own fresh org.
var accShared struct {
	once sync.Once
	pool *pgxpool.Pool
	rdb  *redis.Client
	cs   *credits.Store
	log  *slog.Logger
}

func accEnsureShared(t *testing.T) {
	t.Helper()
	accShared.once.Do(func() {
		pool := testdb.PostgresRegion(t, "e2e")
		rdb := testdb.Redis(t)
		log := accLogger()
		cs := credits.NewStore(pool, log)
		cons := consumer.NewWithCreditStore(consumer.NewRedisOps(rdb), consumer.NewDBOps(pool), accStream, log, cs)
		go cons.Start(context.Background()) // lives for the whole binary
		accShared.pool, accShared.rdb, accShared.cs, accShared.log = pool, rdb, cs, log
	})
}

// accEnv is the full live accounting pipeline: real gateway handler (real
// chi router with RequestID middleware), real Postgres, real Redis, real
// shared consumer and (optionally) a real per-test settlement worker. The
// SQL oracle reads the same pool the services write to.
type accEnv struct {
	pool          *pgxpool.Pool
	rdb           *redis.Client
	org           string
	srv           *httptest.Server
	up            *accUpstream
	cs            *credits.Store
	log           *slog.Logger
	stream        string
	settleCancel  context.CancelFunc
	settleMu      sync.Mutex
	settleCleanup bool
}

func accLogger() *slog.Logger {
	if os.Getenv("ACC_LOUD") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// accNewEnv builds the pipeline. withSettlement controls whether the
// settlement worker runs from the start (ACC-R2 starts it in phases).
func accNewEnv(t *testing.T, chunks []string, withSettlement bool) *accEnv {
	t.Helper()
	accEnsureShared(t)
	pool, rdb, cs, log := accShared.pool, accShared.rdb, accShared.cs, accShared.log
	up := accStartUpstream(t, chunks)

	org := seedReservationsOrg(t, pool, "enforce", accSeedBalanceCents)
	// 0% resale markup for this org → resale price == base 2.3 USD/1M,
	// making the expected charge an independent constant, not a guess.
	_, err := pool.Exec(context.Background(),
		`INSERT INTO reseller_pricing (org_id, model_name, markup_pct, active) VALUES ($1, NULL, 0, true)`, org)
	require.NoError(t, err)

	gw := newReservationGateway(t, pool, up.srv, budget.ModeEnforce)
	gw.markupPricer = pricing.NewMarkupPricer(pool, gwStubPricer{in: 2.3, out: 2.3}, nil)
	gw.publisher = eventpublisher.NewRedisPublisher(rdb, accStream)

	mux := chi.NewRouter()
	mux.Use(middleware.RequestID)
	mux.Post("/v1/chat/completions", gw.chatCompletions)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	e := &accEnv{pool: pool, rdb: rdb, org: org, srv: srv, up: up, cs: cs, log: log, stream: accStream}
	if withSettlement {
		e.startSettlement(t)
	}
	return e
}

// startSettlement runs a real per-test settlement worker with a fast live
// config. The cleanup registration guarantees the worker is fully stopped
// before the next test begins (an unregistered worker would leak across
// tests and break ACC-R2's worker-down premise).
func (e *accEnv) startSettlement(t *testing.T) {
	t.Helper()
	e.settleMu.Lock()
	defer e.settleMu.Unlock()
	if e.settleCancel != nil {
		return
	}
	if !e.settleCleanup {
		e.settleCleanup = true
		t.Cleanup(func() { e.stopSettlement(t) })
	}
	w := consumer.NewSettlementWorker(e.pool, e.cs, nil, e.log)
	w = w.WithConfig(consumer.SettlementConfig{
		Interval:           50 * time.Millisecond,
		BatchSize:          25,
		MaxBatchesPerTick:  10,
		LeaseTTL:           2 * time.Second,
		BackoffBase:        5 * time.Millisecond,
		BackoffMax:         50 * time.Millisecond,
		MaxAttempts:        5,
		InboxRetention:     30 * 24 * time.Hour,
		InboxCleanupEvery:  time.Hour,
		InboxCleanupBatch:  500,
		InboxCleanupPasses: 40,
	})
	ctx, cancel := context.WithCancel(context.Background())
	e.settleCancel = cancel
	go w.Run(ctx)
}

// stopSettlement cancels the worker and waits out any in-flight tick.
func (e *accEnv) stopSettlement(t *testing.T) {
	t.Helper()
	e.settleMu.Lock()
	cancel := e.settleCancel
	e.settleCancel = nil
	e.settleMu.Unlock()
	if cancel != nil {
		cancel()
		time.Sleep(300 * time.Millisecond)
	}
}

func (e *accEnv) restartSettlement(t *testing.T) {
	t.Helper()
	e.stopSettlement(t)
	e.startSettlement(t)
}

// streamAndCancel drives a REAL streaming client against the REAL gateway
// server, cancels the request context mid-stream right after the client
// observes stopMarker, and drains the torn-down response.
func (e *accEnv) streamAndCancel(t *testing.T, reqID, stopMarker string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.srv.URL+"/v1/chat/completions", strings.NewReader(accBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-Id", e.org)
	req.Header.Set("X-Request-Id", reqID)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	sc := bufio.NewScanner(resp.Body)
	saw := false
	for sc.Scan() {
		if stopMarker != "" && strings.Contains(sc.Text(), stopMarker) {
			saw = true
			break
		}
	}
	require.True(t, saw, "client never observed stop marker %q (status=%d)", stopMarker, resp.StatusCode)
	cancel() // mid-stream client cancellation
	_, _ = io.Copy(io.Discard, resp.Body)
}

// requireUpstreamTeardown proves the cancellation propagated: the gateway
// dropped the upstream connection (barrier-held handler sees ctx done).
func (e *accEnv) requireUpstreamTeardown(t *testing.T) {
	t.Helper()
	require.Eventually(t, func() bool { return e.up.dropped.Load() },
		10*time.Second, 100*time.Millisecond,
		"gateway did not drop the upstream connection after client cancel")
}

// --- SQL oracle (reads the services' own tables; independent assertions) ---

func (e *accEnv) usageDebits(t *testing.T, reqID string) []int64 {
	t.Helper()
	rows, err := e.pool.Query(context.Background(),
		`SELECT amount_micro_usd FROM credit_transactions
		 WHERE org_id = $1 AND request_id = $2 AND type = 'usage' ORDER BY id`, e.org, reqID)
	require.NoError(t, err)
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var v int64
		require.NoError(t, rows.Scan(&v))
		out = append(out, v)
	}
	require.NoError(t, rows.Err())
	return out
}

func (e *accEnv) walletRow(t *testing.T) (cents, remMicro, reserved int64) {
	t.Helper()
	err := e.pool.QueryRow(context.Background(),
		`SELECT balance_cents, remainder_micro_usd, reserved_micro_usd
		 FROM org_credits WHERE org_id = $1`, e.org).Scan(&cents, &remMicro, &reserved)
	require.NoError(t, err)
	return cents, remMicro, reserved
}

func (e *accEnv) jobRow(t *testing.T, reqID, kind string) (status string, amount int64, ok bool) {
	t.Helper()
	err := e.pool.QueryRow(context.Background(),
		`SELECT status, COALESCE(amount_micro_usd, 0) FROM settlement_jobs
		 WHERE org_id = $1 AND request_id = $2 AND charge_kind = $3`, e.org, reqID, kind).
		Scan(&status, &amount)
	if err != nil {
		return "", 0, false
	}
	return status, amount, true
}

func (e *accEnv) jobCount(t *testing.T, reqID string) int {
	t.Helper()
	var n int
	require.NoError(t, e.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM settlement_jobs WHERE org_id = $1 AND request_id = $2`, e.org, reqID).Scan(&n))
	return n
}

func (e *accEnv) requestLogSource(t *testing.T, reqID string) (string, bool) {
	t.Helper()
	var src string
	err := e.pool.QueryRow(context.Background(),
		`SELECT usage_source FROM request_logs WHERE org_id = $1 AND request_id = $2 ORDER BY id DESC LIMIT 1`,
		e.org, reqID).Scan(&src)
	if err != nil {
		return "", false
	}
	return src, true
}

// evidence renders the full oracle state for a request — used as the
// failure message so a red run self-documents the accounting outcome.
func (e *accEnv) evidence(t *testing.T, reqID string) string {
	t.Helper()
	debits := e.usageDebits(t, reqID)
	cents, rem, reserved := e.walletRow(t)
	jobs := e.jobCount(t, reqID)
	walletStatus, walletAmount, walletOK := e.jobRow(t, reqID, consumer.ChargeKindResaleDeduction)
	ppStatus, _, ppOK := e.jobRow(t, reqID, consumer.ChargeKindPendingPrice)
	src, hasLog := e.requestLogSource(t, reqID)
	streamLen := e.rdb.XLen(context.Background(), e.stream).Val()
	return fmt.Sprintf("evidence[org=%s req=%s]: debits=%v wallet=(%d¢,%dµ,reserved=%dµ) jobs=%d resale=(%s,%d,%t) pending_price=(%s,%t) log=(%q,exists=%t) stream_len=%d group_pending=%d",
		e.org, reqID, debits, cents, rem, reserved, jobs, walletStatus, walletAmount, walletOK, ppStatus, ppOK, src, hasLog, streamLen, e.groupPending(t))
}

// forceReleaseReservation exercises the documented crash-recovery path for
// reserve release: backdate the org's wallet allowances past the reconcile
// safety window, then run one real reconcile pass.
func (e *accEnv) forceReleaseReservation(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	_, err := e.pool.Exec(ctx,
		`UPDATE budget_allowances SET status = 'expired', lease_until = now() - interval '3 hours'
		 WHERE org_id = $1`, e.org)
	require.NoError(t, err)
	cfg := budget.DefaultReconcileConfig()
	cfg.Interval = 50 * time.Millisecond
	cfg.SafetyWindow = time.Second
	budget.NewReconcileWorker(e.pool, e.log, cfg).Tick(ctx)
}

func (e *accEnv) groupPending(t *testing.T) int64 {
	t.Helper()
	res, err := e.rdb.XPending(context.Background(), e.stream, accConsumerGroup).Result()
	if err != nil {
		return -1 // group not created yet
	}
	return res.Count
}

// findStreamMessage returns the raw published event values for a request.
func (e *accEnv) findStreamMessage(t *testing.T, reqID string) map[string]interface{} {
	t.Helper()
	msgs, err := e.rdb.XRange(context.Background(), e.stream, "-", "+").Result()
	require.NoError(t, err)
	for _, m := range msgs {
		if v, ok := m.Values["request_id"].(string); ok && v == reqID {
			return m.Values
		}
	}
	return nil
}

// --- ACC-R1a --------------------------------------------------------------

func TestAccR1aClientCancelBeforeUsageNotBilled(t *testing.T) {
	e := accNewEnv(t, []string{accContentChunk}, true)
	reqID := "acc-r1a-" + uuid.NewString()[:8]

	e.streamAndCancel(t, reqID, `"content":"hello"`)
	e.requireUpstreamTeardown(t)

	// Durable record exists — never silent zero.
	require.Eventually(t, func() bool {
		_, ok := e.requestLogSource(t, reqID)
		return ok
	}, 20*time.Second, 200*time.Millisecond, "no request_logs row for cancelled request")
	src, _ := e.requestLogSource(t, reqID)
	t.Logf("request_logs.usage_source=%q (unknown usage documented)", src)

	// Durable unknown-cost signal: a settlement row for the request must
	// exist. Desired shape: a pending_price record (never claimed, never
	// charged, expires to terminal 'unknown') — never a wallet charge.
	require.Eventually(t, func() bool {
		return e.jobCount(t, reqID) > 0
	}, 20*time.Second, 200*time.Millisecond, "no settlement record for cancelled request — %s (event reservations: %v)",
		e.evidence(t, reqID), func() any {
			msg := e.findStreamMessage(t, reqID)
			if msg == nil {
				return "message-not-found"
			}
			return msg["reservations"]
		}())
	require.Eventually(t, func() bool {
		status, _, ok := e.jobRow(t, reqID, consumer.ChargeKindPendingPrice)
		return ok && status == "pending_price"
	}, 20*time.Second, 200*time.Millisecond, "no pending_price record — %s", e.evidence(t, reqID))
	_, _, resaleCharged := e.jobRow(t, reqID, consumer.ChargeKindResaleDeduction)
	require.False(t, resaleCharged, "resale charge for unknown-usage cancel — %s", e.evidence(t, reqID))

	// Give the worker a few ticks, then the oracle: NO wallet debit may
	// exist for usage that was never known. (Original prediction: RED —
	// estimated usage billed as if known.)
	time.Sleep(1 * time.Second)
	require.Empty(t, e.usageDebits(t, reqID),
		"ACC-R1a violated: unknown-usage cancel billed — %s", e.evidence(t, reqID))

	// Reservation was held and is released via the reconcile path; the
	// release must not bill anything.
	_, _, reserved := e.walletRow(t)
	require.Greater(t, reserved, int64(0), "no reserve held for cancelled request — %s", e.evidence(t, reqID))
	e.forceReleaseReservation(t)
	require.Eventually(t, func() bool {
		_, _, r := e.walletRow(t)
		return r == 0
	}, 15*time.Second, 200*time.Millisecond,
		"ACC-R1a violated: leaked reserve after reconcile release — %s", e.evidence(t, reqID))
	require.Empty(t, e.usageDebits(t, reqID),
		"debit appeared after reserve release — %s", e.evidence(t, reqID))
}

// --- ACC-R1b --------------------------------------------------------------

func TestAccR1bClientCancelAfterUsageBillsDeliveredPrefixOnce(t *testing.T) {
	e := accNewEnv(t, []string{accContentChunk, accUsageChunk}, true)
	reqID := "acc-r1b-" + uuid.NewString()[:8]

	e.streamAndCancel(t, reqID, `"completion_tokens":2500`)
	e.requireUpstreamTeardown(t)

	// Exactly one wallet settlement, terminal.
	require.Eventually(t, func() bool {
		status, _, ok := e.jobRow(t, reqID, consumer.ChargeKindResaleDeduction)
		return ok && status == "settled"
	}, 25*time.Second, 200*time.Millisecond, "resale job never settled — %s", e.evidence(t, reqID))

	// Exactly the delivered prefix, exactly once: 11 500 µUSD debit.
	require.Equal(t, []int64{-accResaleMicro}, e.usageDebits(t, reqID),
		"ACC-R1b violated: delivered-prefix charge not exact-once — %s", e.evidence(t, reqID))

	// Exact wallet carry math: 1¢ charged, 1 500µ carried.
	cents, rem, reserved := e.walletRow(t)
	require.Equal(t, int64(accSeedBalanceCents-1), cents, "wallet cents — %s", e.evidence(t, reqID))
	require.Equal(t, int64(1_500), rem, "wallet remainder — %s", e.evidence(t, reqID))

	// One charge job only (no duplicate intents beside the settled one).
	require.Equal(t, 1, e.jobCount(t, reqID), "duplicate settlement jobs — %s", e.evidence(t, reqID))

	// Reservation release: settle decremented min(actual, bound); anything
	// still held goes through the reconcile path; no late second debit.
	if reserved > 0 {
		e.forceReleaseReservation(t)
	}
	require.Eventually(t, func() bool {
		_, _, r := e.walletRow(t)
		return r == 0
	}, 15*time.Second, 200*time.Millisecond, "reserve not released — %s", e.evidence(t, reqID))
	require.Equal(t, []int64{-accResaleMicro}, e.usageDebits(t, reqID),
		"second debit after release — %s", e.evidence(t, reqID))
}

// --- ACC-R2 ---------------------------------------------------------------

func TestAccR2SettlementRestartNoLossNoDouble(t *testing.T) {
	// Settlement worker DOWN during delivery.
	e := accNewEnv(t, []string{accContentChunk, accUsageChunk}, false)
	reqID := "acc-r2-" + uuid.NewString()[:8]

	e.streamAndCancel(t, reqID, `"completion_tokens":2500`)
	e.requireUpstreamTeardown(t)

	// The charge is durable (pending job), and nothing was lost…
	require.Eventually(t, func() bool {
		status, _, ok := e.jobRow(t, reqID, consumer.ChargeKindResaleDeduction)
		return ok && status == "pending"
	}, 20*time.Second, 200*time.Millisecond, "no durable pending charge — %s", e.evidence(t, reqID))
	require.Empty(t, e.usageDebits(t, reqID), "premature debit — %s", e.evidence(t, reqID))

	// …worker start converges to exactly one debit…
	e.startSettlement(t)
	require.Eventually(t, func() bool {
		status, _, ok := e.jobRow(t, reqID, consumer.ChargeKindResaleDeduction)
		return ok && status == "settled"
	}, 25*time.Second, 200*time.Millisecond, "restart did not settle — %s", e.evidence(t, reqID))
	require.Equal(t, []int64{-accResaleMicro}, e.usageDebits(t, reqID),
		"ACC-R2 violated: post-restart charge not exact-once — %s", e.evidence(t, reqID))

	// …and a SECOND worker restart does not double-charge.
	e.restartSettlement(t)
	time.Sleep(1 * time.Second)
	require.Equal(t, []int64{-accResaleMicro}, e.usageDebits(t, reqID),
		"ACC-R2 violated: double charge after second restart — %s", e.evidence(t, reqID))
	require.Equal(t, 1, e.jobCount(t, reqID), "duplicate jobs after restart — %s", e.evidence(t, reqID))
}

// --- ACC-R3 ---------------------------------------------------------------

func TestAccR3ConcurrentAndReplaySingleDebitPerRequest(t *testing.T) {
	e := accNewEnv(t, []string{accContentChunk, accUsageChunk}, true)

	// Phase A: two concurrent cancels, distinct request IDs → two
	// independent exact-once debits.
	reqA := "acc-r3a-" + uuid.NewString()[:8]
	reqB := "acc-r3b-" + uuid.NewString()[:8]
	var wg sync.WaitGroup
	for _, id := range []string{reqA, reqB} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			e.streamAndCancel(t, id, `"completion_tokens":2500`)
		}(id)
	}
	wg.Wait()
	require.Eventually(t, func() bool {
		return len(e.usageDebits(t, reqA)) == 1 && len(e.usageDebits(t, reqB)) == 1
	}, 30*time.Second, 200*time.Millisecond, "concurrent pair did not settle — %s / %s",
		e.evidence(t, reqA), e.evidence(t, reqB))
	require.Equal(t, []int64{-accResaleMicro}, e.usageDebits(t, reqA), "A — %s", e.evidence(t, reqA))
	require.Equal(t, []int64{-accResaleMicro}, e.usageDebits(t, reqB), "B — %s", e.evidence(t, reqB))

	// Phase B: byte-identical replay of A's settled event → still exactly
	// one debit for that request.
	msg := e.findStreamMessage(t, reqA)
	require.NotNil(t, msg, "published event for %s not found", reqA)
	require.NoError(t, e.rdb.XAdd(context.Background(), &redis.XAddArgs{
		Stream: e.stream, Values: msg,
	}).Err())
	require.Eventually(t, func() bool {
		return e.groupPending(t) == 0
	}, 30*time.Second, 200*time.Millisecond, "replayed message never drained — %s", e.evidence(t, reqA))
	time.Sleep(1 * time.Second)
	require.Equal(t, []int64{-accResaleMicro}, e.usageDebits(t, reqA),
		"ACC-R3 violated: replay double-charged — %s", e.evidence(t, reqA))

	// Phase C: two concurrent requests sharing one client X-Request-Id →
	// exactly one debit (by-design money-layer dedup; the transport honors
	// client request IDs verbatim — boundary documented in the contract).
	reqC := "acc-r3c-" + uuid.NewString()[:8]
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.streamAndCancel(t, reqC, `"completion_tokens":2500`)
		}()
	}
	wg.Wait()
	require.Eventually(t, func() bool {
		return len(e.usageDebits(t, reqC)) == 1
	}, 30*time.Second, 200*time.Millisecond, "shared-ID pair never converged — %s", e.evidence(t, reqC))
	require.Equal(t, []int64{-accResaleMicro}, e.usageDebits(t, reqC),
		"ACC-R3 violated: shared-ID pair charged twice — %s", e.evidence(t, reqC))

	// Org-level total: three exact-once debits (A, B, C) — no phantom.
	total := append(append(e.usageDebits(t, reqA), e.usageDebits(t, reqB)...), e.usageDebits(t, reqC)...)
	require.Len(t, total, 3, "org totals — A:%s B:%s C:%s",
		e.evidence(t, reqA), e.evidence(t, reqB), e.evidence(t, reqC))
}
