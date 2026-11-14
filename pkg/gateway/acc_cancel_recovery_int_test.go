//go:build integration

// ACC — accounting cancellation/recovery integration cases against the
// real gateway, real Postgres, real Redis and the real consumer/settlement
// workers. Oracle of record is SQL over credit_transactions / org_credits /
// settlement_jobs / request_logs — never the service's own accounting API.
//
//	ACC-R1a  A client write failure mid-stream (first content chunk
//	         delivered, second write fails) must bill the byte-estimated
//	         delivered prefix exactly once — D1: the delivered prefix of a
//	         client-interrupted stream is billable, and without provider
//	         usage the estimate is ceil(bytes/4) tokens per side, priced at
//	         the org's 0%-markup resale rate. PASS: request_logs carries
//	         usage_source='estimated', exactly one usage debit of the
//	         hand-counted amount, one settled resale_deduction job, no
//	         pending_price record, reservation fully released, no late
//	         second debit.
//	ACC-R1b  Client cancels after a usage-bearing chunk (2500+2500 tokens
//	         at 2.3 USD/1M, 0% markup → 11 500 µUSD): exactly one debit of
//	         -11 500 µUSD, exact wallet carry (100 000¢/0µ → 99 999¢/1 500µ),
//	         one settled job, reserve release, no second debit.
//	ACC-R2   Settlement worker down during delivery → durable pending job,
//	         no debit; worker start → exactly one debit; second restart →
//	         still exactly one debit (no loss, no double charge).
//	ACC-R3   Two concurrent cancels with distinct request IDs → two
//	         independent single debits; byte-identical replay of a settled
//	         event → still exactly one debit for that request; two
//	         concurrent requests sharing one client X-Request-Id → exactly
//	         one debit (by-design boundary: the money layer dedups by
//	         request ID while the transport honors client X-Request-Id
//	         verbatim).
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
// until the gateway drops it (client cancellation propagating upstream). It
// also records the serialized upstream request body length so tests can
// assert byte-freezes they price against.
type accUpstream struct {
	srv       *httptest.Server
	release   chan struct{}
	once      sync.Once
	dropped   atomic.Bool
	bodyBytes atomic.Int64
}

func accStartUpstream(t *testing.T, chunks []string) *accUpstream {
	t.Helper()
	up := &accUpstream{release: make(chan struct{})}
	up.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		up.bodyBytes.Store(int64(len(body)))
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
	mux           *chi.Mux
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

	e := &accEnv{pool: pool, rdb: rdb, org: org, mux: mux, srv: srv, up: up, cs: cs, log: log, stream: accStream}
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

// Frozen ACC-R1a script bytes. The client disconnect is selected by
// payload, not timing: whichever stream write carries accR1aFailMarker is
// the scripted connection break, so the exit under test is deterministic.
const (
	// accR1aFirstContent is exactly 40 bytes: completion tokens are
	// ceil(40/4) = 10, a multiple of 10 so each priced side is an integral
	// micro-USD amount under any rounding rule.
	accR1aFirstContent = "0123456789012345678901234567890123456789"
	accR1aFailMarker   = "SECOND-CHUNK-NEVER-DELIVERED"
	// accR1aClientBody is the client request (exactly 120 bytes). The
	// gateway forwards it upstream with a byte-neutral model override and
	// — in this programmatic harness, where streamUsageProviders is unset —
	// no stream_options injection: the stub sees exactly the same 120
	// bytes, which is the prompt term of the estimate.
	accR1aClientBody = `{"model":"stub-model","messages":[{"role":"user","content":"r1a-oracle-freeze-12345"}],"stream":true,"max_tokens":16384}`
)

var (
	accR1aChunk1 = `data: {"id":"acc-r1a","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"` + accR1aFirstContent + `"},"finish_reason":null}]}` + "\n\n"
	accR1aChunk2 = `data: {"id":"acc-r1a","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"` + accR1aFailMarker + `"},"finish_reason":null}]}` + "\n\n"
)

// Hand-counted ACC-R1a oracle, frozen at compile time:
//
//	upstream body bytes  accR1aUpstreamBodyBytes = 120  (≡ 0 mod 40)
//	prompt tokens        ceil(120/4)            = 30   (≡ 0 mod 10)
//	completion tokens    ceil(40/4)             = 10   (≡ 0 mod 10)
//	resale USD           (30 + 10) tokens × 2.3 USD / 1M, 0% org markup
//	charge µUSD          23 × (30 + 10) / 10    = 92
//
// Each token side prices to an integral µUSD amount (30×2.3 = 69µ,
// 10×2.3 = 23µ), so the total is independent of rounding order. The test
// asserts the upstream body really is the frozen byte count before using
// the constant, so serialization drift fails loudly instead of mis-pricing.
const (
	accR1aUpstreamBodyBytes = 120
	accR1aPromptTokens      = accR1aUpstreamBodyBytes / 4
	accR1aCompletionTokens  = 10
	accR1aChargeMicro       = 23 * (accR1aPromptTokens + accR1aCompletionTokens) / 10
)

// accFailWriter is a client whose connection breaks mid-stream: the write
// whose payload carries the fail marker both fails and cancels the request
// context, mirroring net/http on a peer disconnect. Failure is sticky —
// later best-effort writes (error frames after the drain failure) fail too.
type accFailWriter struct {
	header http.Header
	cancel context.CancelFunc
	failed bool
}

func (w *accFailWriter) Header() http.Header { return w.header }
func (w *accFailWriter) WriteHeader(int)     {}
func (w *accFailWriter) Flush()              {}

func (w *accFailWriter) fail(p string) bool {
	if w.failed || strings.Contains(p, accR1aFailMarker) {
		w.failed = true
		w.cancel()
		return true
	}
	return false
}

func (w *accFailWriter) Write(p []byte) (int, error) {
	if w.fail(string(p)) {
		return 0, fmt.Errorf("acc: client connection reset")
	}
	return len(p), nil
}

func (w *accFailWriter) WriteString(s string) (int, error) {
	if w.fail(s) {
		return 0, fmt.Errorf("acc: client connection reset")
	}
	return len(s), nil
}

func TestAccR1aClientWriteFailureBillsEstimatedPrefixOnce(t *testing.T) {
	e := accNewEnv(t, []string{accR1aChunk1, accR1aChunk2}, true)
	reqID := "acc-r1a-" + uuid.NewString()[:8]

	// Drive the real handler chain (same chi router the live tests use)
	// in-process with the scripted disconnect: chunk1 is delivered, the
	// chunk2 write fails and cancels the request context.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(accR1aClientBody))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-Id", e.org)
	req.Header.Set("X-Request-Id", reqID)
	e.mux.ServeHTTP(&accFailWriter{header: make(http.Header), cancel: cancel}, req)

	// The freeze guard: the prompt term of the estimate must come from
	// exactly the bytes the gateway serialized upstream.
	require.EqualValues(t, accR1aUpstreamBodyBytes, e.up.bodyBytes.Load(),
		"upstream request body length drifted from the frozen oracle constant")

	// The interrupted stream must be accounted as a byte-based estimate of
	// the delivered prefix — never usage_source='none' (which would
	// silently drop the whole charge).
	require.Eventually(t, func() bool {
		src, ok := e.requestLogSource(t, reqID)
		return ok && src == "estimated"
	}, 20*time.Second, 200*time.Millisecond,
		"ACC-R1a violated: usage_source is not 'estimated' — %s", e.evidence(t, reqID))

	// Exactly one settled resale job at the hand-counted amount…
	require.Eventually(t, func() bool {
		status, amount, ok := e.jobRow(t, reqID, consumer.ChargeKindResaleDeduction)
		return ok && status == "settled" && amount == accR1aChargeMicro
	}, 25*time.Second, 200*time.Millisecond,
		"ACC-R1a violated: estimated-prefix charge did not settle at the hand-counted amount — %s", e.evidence(t, reqID))

	// …exactly one usage debit of exactly that amount, and no unknown-price
	// record (the estimate is a priced quote, not an unknown).
	require.Equal(t, []int64{-accR1aChargeMicro}, e.usageDebits(t, reqID),
		"ACC-R1a violated: estimated delivered prefix not billed exactly once — %s", e.evidence(t, reqID))
	require.Equal(t, 1, e.jobCount(t, reqID), "unexpected settlement jobs — %s", e.evidence(t, reqID))
	if _, _, ppOK := e.jobRow(t, reqID, consumer.ChargeKindPendingPrice); ppOK {
		t.Fatalf("ACC-R1a violated: pending_price record for a fully-priced estimate — %s", e.evidence(t, reqID))
	}

	// Reservation fully released (the settle pass decrements the hold; any
	// remainder goes through the documented reconcile path), with no late
	// second debit.
	if _, _, reserved := e.walletRow(t); reserved > 0 {
		e.forceReleaseReservation(t)
	}
	require.Eventually(t, func() bool {
		_, _, r := e.walletRow(t)
		return r == 0
	}, 15*time.Second, 200*time.Millisecond,
		"ACC-R1a violated: leaked reserve after estimated-prefix settlement — %s", e.evidence(t, reqID))
	require.Equal(t, []int64{-accR1aChargeMicro}, e.usageDebits(t, reqID),
		"ACC-R1a violated: second debit after reserve release — %s", e.evidence(t, reqID))
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
