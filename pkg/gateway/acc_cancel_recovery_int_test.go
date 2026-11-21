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
//
// Controls (isolated discriminator checks for the assertions above):
//
//	ACC-CTL-S Claim-starved live worker: durable pending charge, zero
//	         debits across five completed observed backlog passes.
//	ACC-CTL-D One injected post-debit settle failure forces the
//	         duplicate-settlement window (attempts >= 2) — still one debit.
//	ACC-CTL-O Backlog publishing down, claims live and settling — the
//	         observer counts zero completed backlog observations.
package cli

import (
	"bufio"
	"context"
	"errors"
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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	settleDone    chan error
	settleMu      sync.Mutex
	settleCleanup bool
	tickDB        *accTickDB
	// settleDB is the seam the per-test real worker runs on; controls
	// replace it with a fault-injecting wrapper before startSettlement.
	settleDB consumer.SettlementDB
}

// accTickDB observes COMPLETED backlog passes of the real settlement
// worker by wrapping the consumer.SettlementDB seam production
// dependency-injects (the real pool). One observation = the worker's
// per-tick backlog aggregation consumed in full (Next exhausted, terminal
// Err nil, Close done) — not a Query call, a claim query or a log line.
// publishBacklog runs after lease recovery and the bounded claim/execute
// batches, so a completed observation proves that pass's claims and
// executions already ran. All methods forward unchanged; only backlog
// rows come back wrapped, so the real worker still settles against real
// Postgres.
type accTickDB struct {
	consumer.SettlementDB
	obs atomic.Int64
	sig chan struct{} // coalescing wake-up; the counter is the truth
}

// Compile-time proof the wrapper still satisfies the seam's interface.
var _ consumer.SettlementDB = (*accTickDB)(nil)

// The settlement worker issues exactly two Query shapes through the
// SettlementDB seam — the claim (claimReadyJobsQuery, $1 = lease TTL
// seconds, $2 = batch limit) and the per-tick backlog aggregation — and
// one advisory-lock Exec per settle transaction ($1 = org ID). The
// prefixes identify them without coupling to the full statement text.
const (
	accSettlementClaimPrefix   = "WITH claimed AS ("
	accSettlementBacklogPrefix = "SELECT status, count(*) FROM settlement_jobs"
)

func newAccTickDB(pool *pgxpool.Pool) *accTickDB {
	return &accTickDB{SettlementDB: pool, sig: make(chan struct{}, 1)}
}

// accObservedRows wraps ONLY the backlog query's rows and fires obs once,
// after the real rows consumer completed the full pass: Next() exhausted,
// terminal error nil, Close() done. It forwards every rows method
// unchanged via embedding.
type accObservedRows struct {
	pgx.Rows
	obs       func()
	once      sync.Once
	exhausted bool
	termErr   error
}

func (r *accObservedRows) Next() bool {
	if r.Rows.Next() {
		return true
	}
	r.exhausted = true
	r.termErr = r.Rows.Err()
	return false
}

func (r *accObservedRows) Close() {
	r.Rows.Close()
	r.once.Do(func() {
		if r.exhausted && r.termErr == nil {
			r.obs()
		}
	})
}

// Query forwards the real pool's Query unchanged. Only the backlog
// query's rows come back wrapped; everything else is the pool's own
// result, untouched.
func (d *accTickDB) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	rows, err := d.SettlementDB.Query(ctx, query, args...)
	if err != nil || !strings.HasPrefix(query, accSettlementBacklogPrefix) {
		return rows, err
	}
	return &accObservedRows{Rows: rows, obs: d.observe}, nil
}

// observe counts one completed settlement/backlog observation and sends
// the one-shot coalescing signal.
func (d *accTickDB) observe() {
	d.obs.Add(1)
	select {
	case d.sig <- struct{}{}:
	default:
	}
}

// requireDeliveryAcked proves COMPLETED delivery: the consumer group has
// no pending (unacked) messages, so the request's event was processed and
// acked by the real consumer — the precondition for deciding settlement
// absence without a blind timeout.
func (e *accEnv) requireDeliveryAcked(t *testing.T, reqID string) {
	t.Helper()
	require.Eventually(t, func() bool { return e.groupPending(t) == 0 },
		10*time.Second, 100*time.Millisecond,
		"delivered event never acked (group_pending>0) — %s", e.evidence(t, reqID))
}

// awaitSettlementObservations blocks until need MORE completed backlog
// observations occurred since the entry baseline (the atomic counter is
// the truth; the channel is a coalescing wake-up), within a one-shot
// named bound — never a wall-clock sleep as proof. Two post-delivery
// completed observations mean a full claim+execute opportunity ran
// strictly after the durable intent existed, making "settled or never"
// decidable immediately.
func (e *accEnv) awaitSettlementObservations(t *testing.T, reqID string, need int64) {
	t.Helper()
	baseline := e.tickDB.obs.Load()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for e.tickDB.obs.Load()-baseline < need {
		select {
		case <-e.tickDB.sig:
		case <-timer.C:
			t.Fatalf("real settlement worker completed too few settlement/backlog observations (need +%d, got +%d) within bound — %s",
				need, e.tickDB.obs.Load()-baseline, e.evidence(t, reqID))
		}
	}
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

	tick := newAccTickDB(pool)
	e := &accEnv{pool: pool, rdb: rdb, org: org, mux: mux, srv: srv, up: up, cs: cs, log: log, stream: accStream, tickDB: tick, settleDB: tick}
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
	// Real worker on the real pool; wrapped only at the SettlementDB
	// dependency seam (accTickDB, or a control's wrapper of it).
	w := consumer.NewSettlementWorker(e.settleDB, e.cs, nil, e.log)
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
	done := make(chan error, 1)
	e.settleDone = done
	go func() { done <- w.Run(ctx) }()
}

// stopSettlement cancels the worker and waits for that start's Run
// goroutine to actually return (bounded, named), so a restart cannot
// overlap the old Run — and post-stop observation increments are
// impossible, since obs fires only inside Run's tick call stack.
// Idempotent; lifecycle under settleMu is unchanged.
func (e *accEnv) stopSettlement(t *testing.T) {
	t.Helper()
	e.settleMu.Lock()
	cancel := e.settleCancel
	done := e.settleDone
	e.settleCancel = nil
	e.settleDone = nil
	e.settleMu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		t.Fatalf("settlement worker Run did not exit after cancel within bound — leaked worker")
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

// jobAttempts reads the resale job's attempt counter — the terminal-row
// proof that a claimed job's charge path executed N times.
func (e *accEnv) jobAttempts(t *testing.T, reqID string) int {
	t.Helper()
	var n int
	require.NoError(t, e.pool.QueryRow(context.Background(),
		`SELECT attempts FROM settlement_jobs
		 WHERE org_id = $1 AND request_id = $2 AND charge_kind = $3`,
		e.org, reqID, consumer.ChargeKindResaleDeduction).Scan(&n))
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

	// Settled at the hand-counted amount, decided after ack + two
	// observed completed backlog passes.
	e.requireDeliveryAcked(t, reqID)
	e.awaitSettlementObservations(t, reqID, 2)
	gotStatus, gotAmount, settledOK := e.jobRow(t, reqID, consumer.ChargeKindResaleDeduction)
	require.True(t, settledOK && gotStatus == "settled" && gotAmount == accR1aChargeMicro,
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

	// Terminal settled state, decided after ack + two observed completed
	// backlog passes.
	e.requireDeliveryAcked(t, reqID)
	e.awaitSettlementObservations(t, reqID, 2)
	r1bStatus, _, r1bOK := e.jobRow(t, reqID, consumer.ChargeKindResaleDeduction)
	require.True(t, r1bOK && r1bStatus == "settled",
		"resale job never settled — %s", e.evidence(t, reqID))

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

	// …worker start converges to exactly one debit, decided after two
	// newly observed completed backlog passes…
	e.startSettlement(t)
	e.awaitSettlementObservations(t, reqID, 2)
	r2Status, _, r2OK := e.jobRow(t, reqID, consumer.ChargeKindResaleDeduction)
	require.True(t, r2OK && r2Status == "settled",
		"restart did not settle — %s", e.evidence(t, reqID))
	require.Equal(t, []int64{-accResaleMicro}, e.usageDebits(t, reqID),
		"ACC-R2 violated: post-restart charge not exact-once — %s", e.evidence(t, reqID))

	// …and a SECOND worker restart does not double-charge — decided after
	// two newly observed completed backlog passes.
	e.restartSettlement(t)
	e.requireDeliveryAcked(t, reqID)
	e.awaitSettlementObservations(t, reqID, 2)
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
	// Completed delivery (group_pending==0 covers both events) plus two
	// observed completed backlog passes make the pair's settlement
	// decidable.
	e.requireDeliveryAcked(t, reqA)
	e.awaitSettlementObservations(t, reqA, 2)
	require.True(t, len(e.usageDebits(t, reqA)) == 1 && len(e.usageDebits(t, reqB)) == 1,
		"concurrent pair did not settle — %s / %s", e.evidence(t, reqA), e.evidence(t, reqB))
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
	// The replay had two observed completed backlog passes in which a
	// duplicate charge could have landed.
	e.awaitSettlementObservations(t, reqA, 2)
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
	e.requireDeliveryAcked(t, reqC)
	e.awaitSettlementObservations(t, reqC, 2)
	require.True(t, len(e.usageDebits(t, reqC)) == 1,
		"shared-ID pair never converged — %s", e.evidence(t, reqC))
	require.Equal(t, []int64{-accResaleMicro}, e.usageDebits(t, reqC),
		"ACC-R3 violated: shared-ID pair charged twice — %s", e.evidence(t, reqC))

	// Org-level total: three exact-once debits (A, B, C) — no phantom.
	total := append(append(e.usageDebits(t, reqA), e.usageDebits(t, reqB)...), e.usageDebits(t, reqC)...)
	require.Len(t, total, 3, "org totals — A:%s B:%s C:%s",
		e.evidence(t, reqA), e.evidence(t, reqB), e.evidence(t, reqC))
}

// --- ACC controls ---------------------------------------------------------
//
// Each control injects a fault ONLY at the SettlementDB seam its own
// worker runs on; every other test keeps the plain pool-backed accTickDB.
// Workers claim jobs globally, so a fault that must survive test-order
// shuffles binds to its org — via the advisory lock's org argument —
// instead of firing on the first matching statement from any org.

var (
	errAccCtlBlindBacklog = errors.New("acc ctl: backlog publish unavailable")
	errAccCtlSettleTx     = errors.New("acc ctl: injected settle-transaction failure")
)

// Compile-time proof the control wrappers satisfy the seam's interface.
var (
	_ consumer.SettlementDB = (*accCtlStuckDB)(nil)
	_ consumer.SettlementDB = (*accCtlRetryDB)(nil)
	_ consumer.SettlementDB = (*accCtlBlindDB)(nil)
)

// accCtlStuckDB starves claims while keeping the worker otherwise live:
// the real claim query runs with a zero batch limit, so nothing is ever
// claimed or debited and backlog passes keep completing. This is the
// stuck-before-settlement state R1b/R2's decision procedure must
// recognize instead of passing vacuously.
type accCtlStuckDB struct {
	*accTickDB
}

func (d *accCtlStuckDB) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	if strings.HasPrefix(query, accSettlementClaimPrefix) {
		return d.accTickDB.SettlementDB.Query(ctx, query, args[0], 0)
	}
	return d.accTickDB.Query(ctx, query, args...)
}

// accCtlRetryDB forces exactly one settle-transaction failure for its
// org AFTER the debit committed: the first advisory-lock Exec for that
// org fails, beginMoneyTx unwinds, and lease recovery re-queues the job
// for a real second execution of the charge path — the
// duplicate-settlement window the exact-once guarantee must survive.
type accCtlRetryDB struct {
	*accTickDB
	org       string
	failState atomic.Bool // armed = true; fires once, then disarms
}

// accCtlRetryTx is the worker-visible transaction whose only deviation
// is that single org-bound advisory-lock failure; everything else
// delegates to the real transaction untouched.
type accCtlRetryTx struct {
	pgx.Tx
	org string
	db  *accCtlRetryDB
}

func (d *accCtlRetryDB) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := d.accTickDB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &accCtlRetryTx{Tx: tx, org: d.org, db: d}, nil
}

func (x *accCtlRetryTx) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(query, "pg_advisory_xact_lock") && len(args) == 1 && args[0] == x.org &&
		x.db.failState.CompareAndSwap(true, false) {
		return pgconn.CommandTag{}, errAccCtlSettleTx
	}
	return x.Tx.Exec(ctx, query, args...)
}

// accCtlBlindDB takes backlog publishing down for its worker while
// claims keep passing: every backlog Query errors, and claim rows come
// back wrapped so fully consumed claim passes are counted. Settlement
// still completes; the backlog observation counter must stay zero.
type accCtlBlindDB struct {
	*accTickDB
	claims atomic.Int64
}

func (d *accCtlBlindDB) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	if strings.HasPrefix(query, accSettlementBacklogPrefix) {
		return nil, errAccCtlBlindBacklog
	}
	if strings.HasPrefix(query, accSettlementClaimPrefix) {
		rows, err := d.accTickDB.SettlementDB.Query(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		return &accObservedRows{Rows: rows, obs: func() { d.claims.Add(1) }}, nil
	}
	return d.accTickDB.Query(ctx, query, args...)
}

// TestAccCtlStuckBeforeSettlementStaysPendingNoDebit (ACC-CTL-S): with
// the worker alive, ticking and observable but claim-starved, the durable
// charge stays pending and NO debit ever lands — across five completed
// observed backlog passes, a strictly stronger barrier than the R-tests'
// two. If an R-test's observation barrier were vacuous (counting Query
// calls, claims or log lines), this control would see money move.
func TestAccCtlStuckBeforeSettlementStaysPendingNoDebit(t *testing.T) {
	e := accNewEnv(t, []string{accContentChunk, accUsageChunk}, false)
	e.settleDB = &accCtlStuckDB{accTickDB: e.tickDB}
	e.startSettlement(t)
	reqID := "acc-ctl-s-" + uuid.NewString()[:8]

	e.streamAndCancel(t, reqID, `"completion_tokens":2500`)
	e.requireUpstreamTeardown(t)
	require.Eventually(t, func() bool {
		status, _, ok := e.jobRow(t, reqID, consumer.ChargeKindResaleDeduction)
		return ok && status == "pending"
	}, 20*time.Second, 200*time.Millisecond, "ACC-CTL-S: no durable pending charge — %s", e.evidence(t, reqID))
	e.requireDeliveryAcked(t, reqID)

	e.awaitSettlementObservations(t, reqID, 5)
	status, _, ok := e.jobRow(t, reqID, consumer.ChargeKindResaleDeduction)
	require.True(t, ok && status == "pending",
		"ACC-CTL-S violated: claim-starved worker settled or lost the charge — %s", e.evidence(t, reqID))
	require.Empty(t, e.usageDebits(t, reqID),
		"ACC-CTL-S violated: debit without a claim — %s", e.evidence(t, reqID))
}

// TestAccCtlForcedSettleRetryStillSingleDebit (ACC-CTL-D): the debit
// commits, the settle transaction fails exactly once, lease recovery
// re-queues the charge and the second execution runs (attempts >= 2 is
// the terminal-row proof). The money oracle must still see exactly one
// debit — the duplicate-settlement window traversed for real.
func TestAccCtlForcedSettleRetryStillSingleDebit(t *testing.T) {
	e := accNewEnv(t, []string{accContentChunk, accUsageChunk}, false)
	ctl := &accCtlRetryDB{accTickDB: e.tickDB, org: e.org}
	ctl.failState.Store(true)
	e.settleDB = ctl
	e.startSettlement(t)
	reqID := "acc-ctl-d-" + uuid.NewString()[:8]

	e.streamAndCancel(t, reqID, `"completion_tokens":2500`)
	e.requireUpstreamTeardown(t)
	e.requireDeliveryAcked(t, reqID)

	// Lease expiry (2s) plus recovery plus the retry's settle: bounded by
	// the terminal-row oracle, not a sleep.
	require.Eventually(t, func() bool {
		status, _, ok := e.jobRow(t, reqID, consumer.ChargeKindResaleDeduction)
		return ok && status == "settled"
	}, 25*time.Second, 200*time.Millisecond, "ACC-CTL-D: settle retry did not converge — %s", e.evidence(t, reqID))

	require.GreaterOrEqual(t, e.jobAttempts(t, reqID), 2,
		"ACC-CTL-D: the injected failure never produced a second execution — %s", e.evidence(t, reqID))
	require.Equal(t, []int64{-accResaleMicro}, e.usageDebits(t, reqID),
		"ACC-CTL-D violated: forced settle retry double-charged — %s", e.evidence(t, reqID))
	require.Equal(t, 1, e.jobCount(t, reqID),
		"ACC-CTL-D: duplicate jobs — %s", e.evidence(t, reqID))
}

// TestAccCtlObserverBlindToClaimsCountsZero (ACC-CTL-O): backlog
// publishing is down while claims pass and settlement completes; claim
// passes accrue but the backlog observation counter stays at zero — the
// observer cannot be confused by claim queries or failed backlog
// queries.
func TestAccCtlObserverBlindToClaimsCountsZero(t *testing.T) {
	e := accNewEnv(t, []string{accContentChunk, accUsageChunk}, false)
	blind := &accCtlBlindDB{accTickDB: e.tickDB}
	e.settleDB = blind
	e.startSettlement(t)
	reqID := "acc-ctl-o-" + uuid.NewString()[:8]

	e.streamAndCancel(t, reqID, `"completion_tokens":2500`)
	e.requireUpstreamTeardown(t)
	e.requireDeliveryAcked(t, reqID)

	require.Eventually(t, func() bool {
		status, _, ok := e.jobRow(t, reqID, consumer.ChargeKindResaleDeduction)
		return ok && status == "settled"
	}, 25*time.Second, 200*time.Millisecond, "ACC-CTL-O: settlement did not converge without backlog — %s", e.evidence(t, reqID))
	require.Eventually(t, func() bool { return blind.claims.Load() >= 3 },
		10*time.Second, 100*time.Millisecond, "ACC-CTL-O: no completed claim passes observed")
	require.Zero(t, e.tickDB.obs.Load(),
		"ACC-CTL-O violated: observer counted non-backlog or failed queries — %s", e.evidence(t, reqID))
}
