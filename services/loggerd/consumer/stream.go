package consumer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/money"
)

const (
	consumerGroup     = "loggerd-workers"
	consumerName      = "loggerd-0"
	batchSize         = int64(100)
	idleTimeout       = 1000 * time.Millisecond
	defaultStream     = "events:queue"
	maxRetries        = 3
	dlqTTL            = 7 * 24 * time.Hour
	pelReclaimTimeout = 5 * time.Minute
	// dlqMaxLen caps the DLQ stream (approximate trim): the queue is for
	// diagnosis and replay, not an archive — an unbounded DLQ would itself
	// become the outage during a poison burst.
	dlqMaxLen = int64(100_000)
	// dbProbeQuery/dbProbeTimeout decide "is this failure infrastructure?"
	// after a delivery error: an unreachable Postgres means the message stays
	// in the PEL and consumption pauses — a full outage must never burn the
	// retry budget toward the DLQ.
	dbProbeQuery   = "SELECT 1"
	dbProbeTimeout = 2 * time.Second
	// defaultOutagePause backs off the consume loop between delivery
	// attempts while Postgres is unreachable.
	defaultOutagePause = 2 * time.Second
)

const (
	dlqRetryKeyPrefix = "dlq:retry"
	dlqStreamName     = "events:queue:dlq"
	msgSeenKeyPrefix  = "msg:seen:"
	msgSeenTTL        = 24 * time.Hour
)

// Delivery identity persisted in event_inbox: (source, consumer, event_id) is
// (stream name, consumer group, Redis stream entry id). The same entry id in
// two different streams therefore never conflicts.
const (
	inboxClaimQuery = `INSERT INTO event_inbox (source, consumer, event_id)
		 VALUES ($1, $2, $3)
		 ON CONFLICT DO NOTHING`
	// amount_cents keeps the rounded compatibility projection; the exact
	// charge amount lives in amount_micro_usd (AF-05) and is what settlement
	// execution must bill (AF-06).
	//
	// Intent statements come in three shapes and the exact bytes must match
	// the live schema's unique indexes:
	//   - bare legacy arbiter (org_id, request_id, charge_kind): the only
	//     valid form on a pre-0028 schema — there, any WHERE invocation_id
	//     predicate is a 42703 error before index inference even runs.
	//   - partial legacy arbiter: the same columns plus
	//     "WHERE invocation_id IS NULL", required once 0028's
	//     uniq_settlement_jobs_request_legacy exists, because Postgres
	//     infers a partial index ONLY from an arbiter with the matching
	//     predicate.
	//   - invocation arbiter (org_id, invocation_id, charge_kind) with
	//     "WHERE invocation_id IS NOT NULL" for invocation-domain events
	//     (0028+ only).
	settlementIntentQuery = `INSERT INTO settlement_jobs
		 (org_id, request_id, charge_kind, amount_cents, amount_micro_usd, status, payload)
		 VALUES ($1, $2, $3, $4, $5, 'pending', $6)
		 ON CONFLICT (org_id, request_id, charge_kind) DO NOTHING`
	settlementIntentLegacyPartialQuery = `INSERT INTO settlement_jobs
		 (org_id, request_id, charge_kind, amount_cents, amount_micro_usd, status, payload)
		 VALUES ($1, $2, $3, $4, $5, 'pending', $6)
		 ON CONFLICT (org_id, request_id, charge_kind) WHERE invocation_id IS NULL DO NOTHING`
	settlementIntentInvocationQuery = `INSERT INTO settlement_jobs
		 (org_id, request_id, invocation_id, charge_kind, amount_cents, amount_micro_usd, status, payload)
		 VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7)
		 ON CONFLICT (org_id, invocation_id, charge_kind) WHERE invocation_id IS NOT NULL DO NOTHING`
	// The reservation-linked variant (NEXT-18d, ADR-0001 §13) additionally
	// records the allocation whose reserve the settle decrements. Only
	// intent inserts carrying a reserve tuple use it, so a pre-reservation
	// schema (no allowance_id column) never sees this statement.
	settlementIntentWithAllowanceQuery = `INSERT INTO settlement_jobs
		 (org_id, request_id, charge_kind, amount_cents, amount_micro_usd, status, payload, allowance_id)
		 VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)
		 ON CONFLICT (org_id, request_id, charge_kind) DO NOTHING`
	settlementIntentWithAllowanceLegacyPartialQuery = `INSERT INTO settlement_jobs
		 (org_id, request_id, charge_kind, amount_cents, amount_micro_usd, status, payload, allowance_id)
		 VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)
		 ON CONFLICT (org_id, request_id, charge_kind) WHERE invocation_id IS NULL DO NOTHING`
	settlementIntentWithAllowanceInvocationQuery = `INSERT INTO settlement_jobs
		 (org_id, request_id, invocation_id, charge_kind, amount_cents, amount_micro_usd, status, payload, allowance_id)
		 VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8)
		 ON CONFLICT (org_id, invocation_id, charge_kind) WHERE invocation_id IS NOT NULL DO NOTHING`
	// a settlement_jobs row in the non-claimable 'pending_price' state,
	// written in the SAME delivery transaction as the request log. It is
	// never billed (the claim query only takes pending/retry) and never a
	// confirmed zero; the worker's expiry pass terminates it as 'unknown'
	// after PendingPriceExpiry (24h default).
	pendingPriceIntentQuery = `INSERT INTO settlement_jobs
		 (org_id, request_id, charge_kind, amount_cents, amount_micro_usd, status, payload)
		 VALUES ($1, $2, $3, 0, 0, 'pending_price', $4)
		 ON CONFLICT (org_id, request_id, charge_kind) DO NOTHING`
	pendingPriceIntentLegacyPartialQuery = `INSERT INTO settlement_jobs
		 (org_id, request_id, charge_kind, amount_cents, amount_micro_usd, status, payload)
		 VALUES ($1, $2, $3, 0, 0, 'pending_price', $4)
		 ON CONFLICT (org_id, request_id, charge_kind) WHERE invocation_id IS NULL DO NOTHING`
	pendingPriceIntentInvocationQuery = `INSERT INTO settlement_jobs
		 (org_id, request_id, invocation_id, charge_kind, amount_cents, amount_micro_usd, status, payload)
		 VALUES ($1, $2, $3, $4, 0, 0, 'pending_price', $5)
		 ON CONFLICT (org_id, invocation_id, charge_kind) WHERE invocation_id IS NOT NULL DO NOTHING`
)

// settlementIntentStatements selects the exact INSERT bytes for one intent
// row from the live schema (hasColumn — the cached 0028 probe) and the
// event's identity domain (invocation nil = legacy). An invocation-domain
// event on a pre-0028 schema keeps the invocation bytes and fails loudly
// in the request_logs insert before this choice matters.
func settlementIntentStatements(hasColumn bool, invocation any) (plain, withAllowance string) {
	if invocation == nil {
		if hasColumn {
			return settlementIntentLegacyPartialQuery, settlementIntentWithAllowanceLegacyPartialQuery
		}
		return settlementIntentQuery, settlementIntentWithAllowanceQuery
	}
	return settlementIntentInvocationQuery, settlementIntentWithAllowanceInvocationQuery
}

// pendingPriceIntentStatement is the pending_price sibling of
// settlementIntentStatements.
func pendingPriceIntentStatement(hasColumn bool, invocation any) string {
	if invocation == nil {
		if hasColumn {
			return pendingPriceIntentLegacyPartialQuery
		}
		return pendingPriceIntentQuery
	}
	return pendingPriceIntentInvocationQuery
}

// settlementSchemaProbeQuery reports whether the live schema carries the
// invocation_id column on settlement_jobs (migration 0028+). column_name is
// a bind parameter so schema-less test doubles answer 0 (int scan) instead
// of echoing a probe row back as truth.
const settlementSchemaProbeQuery = `SELECT count(*) FROM information_schema.columns
	WHERE table_schema = current_schema() AND table_name = 'settlement_jobs' AND column_name = $1`

// settlementInvocationSchemaTx resolves whether legacy-domain intent
// statements need the partial arbiter, using the delivery's own
// transaction: a pool-level probe here could wait on a connection the
// caller already holds — fatal at MaxConns=1. Only a successful probe is
// cached; a transient failure propagates (the delivery retries, the probe
// re-runs) instead of resolving false forever. Invoked events never call
// this: their statements are schema-self-evidencing (valid on 0028+, a
// loud 42703 before it).
func (c *StreamConsumer) settlementInvocationSchemaTx(ctx context.Context, tx InboxTx) (bool, error) {
	c.schemaMu.Lock()
	defer c.schemaMu.Unlock()
	if c.schemaResolved {
		return c.schemaHasInvocationID, nil
	}
	has, err := probeSettlementInvocationColumn(ctx, tx)
	if err != nil {
		return false, err
	}
	c.schemaResolved, c.schemaHasInvocationID = true, has
	return has, nil
}

// probeSettlementInvocationColumn reports whether the live schema carries
// invocation_id on settlement_jobs (migration 0028+). column_name is a bind
// parameter so schema-less test doubles answer 0 (int scan) instead of
// echoing a probe row back as truth. A read failure returns the error —
// callers must retry, never cache it as the old schema.
func probeSettlementInvocationColumn(ctx context.Context, db interface {
	QueryRow(ctx context.Context, query string, args ...any) pgx.Row
}) (bool, error) {
	var n int
	if err := db.QueryRow(ctx, settlementSchemaProbeQuery, "invocation_id").Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// Reservations modes of an organization (ADR-0001 §9). The consumer reads
// the mode only to decide partial-usage billing of request.failed events;
// an unreadable mode (pre-reservation schema, missing org row) degrades to
// the legacy off behavior.
const (
	modeOff     = "off"
	modeShadow  = "shadow"
	modeEnforce = "enforce"
)

// allowanceLink carries the reserve-tuple linkage of an intent (ADR-0001
// §5.3 Finalize): written into the job payload and the
// settlement_jobs.allowance_id column so the settle-time reserve decrement
// (reserved -= min(actual, bound)) and the NEXT-18a reconcile can find it.
type allowanceLink struct {
	AllowanceID   int64
	BoundMicroUSD int64
}

// Charge kinds for durable settlement work items (AF-04 schema/insert
// contract; execution is AF-06). Identity is (org_id, request_id, kind).
const (
	ChargeKindResaleDeduction = "resale_deduction"
	ChargeKindAgentSpend      = "agent_spend"
	// ADR-0001 F7): the durable side effect that keeps team_spend_monthly
	// and the hard-limit CheckBudget working. Amounts are the BASE cost
	// (ADR I4 — budgets never carry the resale markup).
	ChargeKindTeamSpend = "team_spend"
	// ChargeKindSessionSpend records a session key's spend against its
	// max_cost_usd cap (NEXT-18d, ADR-0001 §4.1/§13): exact micro-USD
	// upsert into session_spend, the `session` reserve area. Created only
	// for keys that carry a money cap (i.e. the event carries a session
	// reserve tuple); the amount is the BASE cost (ADR I4).
	ChargeKindSessionSpend = "session_spend"
	// visibility row (not a charge) for an event whose cost stayed unknown
	// while a reserve existed. Its identity (org, request, kind) is unique,
	// so a redelivery re-inserts nothing. The row is born 'pending_price',
	// never claimable by the settlement worker, and expires to terminal
	// 'unknown' after the pending deadline (24h, owner decision 2026-10-18).
	ChargeKindPendingPrice = "pending_price"
)

// RedisOps is the minimal interface for Redis operations used by the consumer.
type RedisOps interface {
	XAdd(ctx context.Context, args *redis.XAddArgs) *redis.StringCmd
	XGroupCreateMkStream(ctx context.Context, stream, group, startID string) *redis.StatusCmd
	XReadGroup(ctx context.Context, args *redis.XReadGroupArgs) *redis.XStreamSliceCmd
	XAck(ctx context.Context, stream, group string, ids []string) *redis.IntCmd
	XPendingExt(ctx context.Context, args *redis.XPendingExtArgs) *redis.XPendingExtCmd
	XClaim(ctx context.Context, args *redis.XClaimArgs) *redis.XMessageSliceCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
	INCR(ctx context.Context, key string) *redis.IntCmd
	SETNX(ctx context.Context, key string, value any, expiration time.Duration) *redis.BoolCmd
	DEL(ctx context.Context, keys ...string) *redis.IntCmd
}

// StreamConsumer manages a Redis Streams consumer group.
type StreamConsumer struct {
	rdb          RedisOps
	dbPool       DBOps
	streamName   string
	logger       *slog.Logger
	creditStore  *credits.Store // optional — nil when billing is not configured
	agentSpender AgentSpender   // optional — nil when per-agent budgets are off
	otelSink     OTelLogSink
	// originalRetention is the N02-P06 org original-text retention source
	// (nil = fail-closed processed-only persistence for every org). The
	// effective value is resolved once per message at handleMessage.
	originalRetention *originalRetentionResolver
	// retentionPolicy is the N02-P06 T04 Enterprise separation seam (nil =
	// the FREE-core boolean default over originalRetention governs; see
	// SetRetentionPolicy). Wire before Start, like the other seams.
	retentionPolicy RetentionPolicyResolver
	// bufferGate is the N10-P04-T02 durable-buffer backpressure signal over
	// the Redis history stream (nil = disarmed, no signal). It never gates
	// consumption itself — draining the backlog is the way out of
	// saturation; the signal targets the admission policy (N10-P04-T03).
	bufferGate *HistoryBufferGate
	// historySignal is the N10-P04-T03 inter-process seam to the gateway's
	// admission policy: it folds buffer-gate and write-outage observations
	// into the TTL-heartbeated budget.HistorySignal key (nil = disarmed).
	historySignal *HistorySignalPublisher
	mu            sync.Mutex
	cancel        context.CancelFunc

	// Behavioral seams (W-LOGG). Zero fields use the production defaults;
	// tests shrink them so outage/reclaim timelines run in milliseconds.
	// outagePause backs off the consume loop while Postgres is unreachable;
	// reclaimIdle/reclaimEvery bound which pending messages are reclaimed
	// and how often the reclaim pass runs (both default to
	// pelReclaimTimeout, the pre-W-LOGG behavior).
	outagePause  time.Duration
	reclaimIdle  time.Duration
	reclaimEvery time.Duration

	// The settlement schema probe caches whether settlement_jobs carries
	// the invocation_id column (migration 0028). The exact ON CONFLICT
	// bytes must match the live schema: on a pre-0028 schema a
	// WHERE-qualified arbiter is invalid SQL (42703, the predicate
	// references a missing column), while on a 0028+ schema the partial
	// unique indexes are only inferable from an arbiter carrying the
	// matching predicate. Only a successful probe is cached — a transient
	// probe failure propagates so the next delivery re-probes instead of
	// sealing "old schema" forever and downgrading invoked events.
	schemaMu                      sync.Mutex
	schemaResolved                bool
	schemaHasInvocationID         bool
	schemaToolFactResolved        bool
	schemaToolFactHasInvocationID bool
}

// redisXAckWrapper bridges *redis.Client's variadic XAck to our interface.
type redisXAckWrapper struct {
	*redis.Client
}

func (w *redisXAckWrapper) XAck(ctx context.Context, stream, group string, ids []string) *redis.IntCmd {
	return w.Client.XAck(ctx, stream, group, ids...)
}

func (w *redisXAckWrapper) Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd {
	return w.Client.Expire(ctx, key, expiration)
}

func (w *redisXAckWrapper) INCR(ctx context.Context, key string) *redis.IntCmd {
	return w.Incr(ctx, key)
}

func (w *redisXAckWrapper) SETNX(ctx context.Context, key string, value any, expiration time.Duration) *redis.BoolCmd {
	return w.SetNX(ctx, key, value, expiration)
}

func (w *redisXAckWrapper) DEL(ctx context.Context, keys ...string) *redis.IntCmd {
	return w.Del(ctx, keys...)
}

func (w *redisXAckWrapper) XPendingExt(ctx context.Context, args *redis.XPendingExtArgs) *redis.XPendingExtCmd {
	return w.Client.XPendingExt(ctx, args)
}

func (w *redisXAckWrapper) XClaim(ctx context.Context, args *redis.XClaimArgs) *redis.XMessageSliceCmd {
	return w.Client.XClaim(ctx, args)
}

// InboxTx is the transactional slice of one delivery write: the durable inbox
// claim, the request log and every mandatory settlement intent commit
// atomically or not at all (AF-04).
type InboxTx interface {
	Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, query string, args ...any) pgx.Row
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// DBOps is the minimal interface for database executions. BeginTx opens the
// delivery transaction; pgx.Tx satisfies InboxTx.
type DBOps interface {
	Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, query string, args ...any) pgx.Row
	BeginTx(ctx context.Context) (InboxTx, error)
}

// poolDBOps adapts *pgxpool.Pool to DBOps (Begin returns a pgx.Tx, which
// satisfies InboxTx).
type poolDBOps struct {
	pool *pgxpool.Pool
}

// NewDBOps adapts a pgx pool to the consumer DBOps, mirroring NewRedisOps and
// NewRollupDB.
func NewDBOps(pool *pgxpool.Pool) DBOps {
	return poolDBOps{pool: pool}
}

func (p poolDBOps) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	return p.pool.Exec(ctx, query, args...)
}

func (p poolDBOps) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	return p.pool.QueryRow(ctx, query, args...)
}

func (p poolDBOps) BeginTx(ctx context.Context) (InboxTx, error) {
	return p.pool.Begin(ctx)
}

func (c *StreamConsumer) attributionID(fields map[string]interface{}, key string) any {
	value, ok := strictUUID(eventString(fields, key))
	if !ok && c.logger != nil {
		c.logger.Warn("request attribution id is not a uuid; stored as null", "field", key)
	}
	return value
}

// New starts a mock upstream server for tests.
// New.
func New(rdb RedisOps, dbPool DBOps, streamName string, logger *slog.Logger) *StreamConsumer {
	return NewWithCreditStore(rdb, dbPool, streamName, logger, nil)
}

// AgentSpender gates and executes per-agent daily spend recording (G2).
// *budget.AgentEnforcer satisfies it via RecordAgentSpendExact (exact
// micro-USD, transactional with the settlement job); a nil consumer field
// disables both the agent_spend intent and its execution. The legacy
// cent-rounded, non-idempotent RecordAgentSpend is not used on this path.
type AgentSpender interface {
	RecordAgentSpendExact(ctx context.Context, tx budget.SpendExecutor, agentID string, amount money.MicroUSD, tokensIn, tokensOut int64) error
}

// NewWithCreditStore creates a consumer with an optional credits store for billing.
func NewWithCreditStore(rdb RedisOps, dbPool DBOps, streamName string, logger *slog.Logger, cs *credits.Store) *StreamConsumer {
	if streamName == "" {
		streamName = defaultStream
	}
	c := &StreamConsumer{
		rdb:         rdb,
		dbPool:      dbPool,
		streamName:  streamName,
		logger:      logger,
		creditStore: cs,
	}
	// N10-P04-T02: arm the durable-buffer gate when the Redis adapter can
	// probe the stream depth (the production wrapper can; test mocks
	// without XLen stay disarmed with zero behavior change). streamName was
	// defaulted above, so the gate always has a concrete stream to probe.
	// The gate only observes and signals — admission behavior is unchanged
	// until N10-P04-T03 wires the signal into the admission policy.
	if prober, ok := rdb.(BufferProber); ok {
		c.bufferGate = NewHistoryBufferGate(prober, streamName, DefaultHistoryBufferMaxEntries, logger)
	}
	// N10-P04-T03: arm the admission signal when the Redis adapter can
	// write the heartbeat key (the production wrapper can; test mocks
	// without Set stay disarmed with zero behavior change). Wire-before-
	// Start like every other seam — SetHistorySignalPublisher replaces it.
	if writer, ok := rdb.(HistorySignalWriter); ok {
		c.historySignal = NewHistorySignalPublisher(writer, streamName, logger)
	}
	return c
}

// SetAgentSpender wires per-agent spend recording (G2). Optional; nil disables.
func (c *StreamConsumer) SetAgentSpender(as AgentSpender) { c.agentSpender = as }

// SetHistoryBufferGate replaces the durable-buffer backpressure gate
// (N10-P04-T02 seam, same pattern as the other wire-before-Start seams).
// nil disarms the signal. Tests shrink the bound so saturation timelines
// run in milliseconds.
func (c *StreamConsumer) SetHistoryBufferGate(g *HistoryBufferGate) { c.bufferGate = g }

// SetHistorySignalPublisher replaces the admission-signal publisher
// (N10-P04-T03 seam, same pattern as the other wire-before-Start seams).
// nil disarms the signal.
func (c *StreamConsumer) SetHistorySignalPublisher(p *HistorySignalPublisher) { c.historySignal = p }

// Start runs the consumer group loop until the caller's ctx is cancelled.
// Start.
//
// Start is restartable on the SAME instance: the ENT-04 leader-election
// wiring re-invokes Start for every leadership term this replica wins (Lead
// cancels the term context, waits for Start to return, then loops). Each
// term gets a fresh group context, so the consume/reclaim loops of a
// finished term exit through their own ctx and no shutdown may close shared
// lifecycle state twice.
func (c *StreamConsumer) Start(ctx context.Context) error {
	groupCtx, groupCancel := context.WithCancel(context.Background())
	c.mu.Lock()
	c.cancel = groupCancel
	c.mu.Unlock()

	cmd := c.rdb.XGroupCreateMkStream(groupCtx, c.streamName, consumerGroup, "0") //nolint:contextcheck // group lifecycle detached from caller ctx by design
	if err := cmd.Err(); err != nil {
		// BUSYGROUP is the normal restart path (group persists in Redis):
		// keep groupCtx alive and continue. Only a real failure may cancel.
		if err.Error() == "BUSYGROUP Consumer Group name already exists" {
			c.logger.Info("consumer group already exists", slog.String("group", consumerGroup))
		} else {
			groupCancel()
			return fmt.Errorf("create consumer group: %w", err)
		}
	}

	c.logger.Info("stream consumer started",
		slog.String("stream", c.streamName),
		slog.String("group", consumerGroup),
	)

	go c.consume(groupCtx)    //nolint:contextcheck // group lifecycle detached from caller ctx by design
	go c.reclaimPEL(groupCtx) //nolint:contextcheck // group lifecycle detached from caller ctx by design

	<-ctx.Done()
	groupCancel()
	return nil
}

func (c *StreamConsumer) consume(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			c.logger.Info("stream consumer stopping", slog.String("reason", ctx.Err().Error()))
			return
		default:
		}

		// N10-P04-T02: probe the durable history buffer once per consume
		// iteration. The result is advisory on purpose — the consume loop
		// never acts on the error (draining the backlog is the way out of
		// saturation); the gate logs the state transition once and exposes
		// Saturated()/Depth() for the admission policy (N10-P04-T03). A nil
		// gate is disarmed (Evaluate is nil-receiver safe and returns nil).
		// N10-P04-T03: the observation now feeds the inter-process
		// admission signal (a nil publisher is disarmed and skips it) —
		// consumption itself still never gates on it.
		gateErr := c.bufferGate.Evaluate(ctx)
		c.historySignal.ObserveGate(ctx, gateErr, c.bufferGate.Depth())
		// N12-P02-T04: the same observation also lands in the process
		// metrics — the durable-buffer BACKLOG and its fail-closed
		// saturation flag must be visible on /metrics across the whole
		// outage→drain→recovery cycle, not only through the TTL-expiring
		// Redis signal key (which the gateway reads, but an operator
		// scraping loggerd never sees).
		c.exportHistoryBufferMetrics(gateErr, c.bufferGate.Depth())

		streams, err := c.rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    consumerGroup,
			Consumer: consumerName,
			Streams:  []string{c.streamName, ">"},
			Count:    batchSize,
			Block:    idleTimeout,
		}).Result()

		if err != nil {
			if err == redis.Nil {
				continue
			}
			c.logger.Error("XREADGROUP error", slog.String("error", err.Error()))
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}

		if len(streams) == 0 || len(streams[0].Messages) == 0 {
			continue
		}

		for _, msg := range streams[0].Messages {
			metrics.EventsInFlight.Inc()
			c.handleMessage(ctx, msg)
		}
	}
}

// exportHistoryBufferMetrics publishes one durable-buffer observation to
// the metrics registry (N12-P02-T04). gateErr non-nil is exactly the gate's
// fail-closed backpressure signal (saturation, hysteresis hold, or probe
// failure — an unverifiable capacity counts as saturated, never healthy);
// depth -1 means "unobserved" (gate disarmed or consumer not running) and
// is exported verbatim so it is never mistaken for an empty buffer.
func (c *StreamConsumer) exportHistoryBufferMetrics(gateErr error, depth int64) {
	metrics.HistoryBufferDepth.Set(float64(depth))
	if gateErr != nil {
		metrics.HistoryBufferSaturated.Set(1)
		return
	}
	metrics.HistoryBufferSaturated.Set(0)
}

// handleMessage delivers one stream message: the in-flight gauge is always
// balanced (Dec via defer — the old code leaked the gauge on every failed
// delivery), DB outages pause consumption instead of burning the retry
// budget, and every other failure follows the retry/DLQ path.
//
// this is the single content-profile boundary. The effective
// profile (strictest of the process-local declaration and the wire-declared
// content_profile) is computed once; the sanitized COPY flows into
// processing, diagnostics, retry and DLQ, and every error diagnostic is
// sanitized with the same profile before it reaches a log.
//
// The org original-retention toggle (N02-P06 T03) is resolved here too —
// once per message, next to the profile — and threaded into delivery as
// part of the delivery policy: retention OFF (the fail-closed default)
// persists processed text only, no matter which event shape follows.
func (c *StreamConsumer) handleMessage(ctx context.Context, msg redis.XMessage) {
	defer metrics.EventsInFlight.Dec()

	eventType, _ := msg.Values["event_type"].(string)

	sanitized, profile := sanitizeStreamMessageForContentProfile(msg, config.LogContentProfileFromEnv())
	policy := deliveryPolicy{
		profile:        profile,
		retainOriginal: c.originalRetentionEnabled(ctx, msg.Values),
	}

	if err := c.processMessagePolicy(ctx, sanitized, policy); err != nil {
		c.logger.Error("process message failed",
			slog.String("stream_id", msg.ID),
			slog.String("error", safeDiagnostic(profile, err.Error())),
		)

		// Infrastructure failure (Postgres unreachable): the message stays
		// unACKed in the PEL and consumption pauses. Retrying it is free —
		// it must NOT count toward the DLQ retry budget (W-LOGG: a full DB
		// outage longer than maxRetries attempts used to DLQ live billing
		// traffic).
		if c.dbUnavailable(ctx) {
			c.logger.Warn("postgres unreachable — pausing consumption, message stays pending",
				slog.String("stream_id", msg.ID),
			)
			// N10-P04-T03: the durable append is failing — raise the
			// admission signal so the default reject policy stops the
			// gateway from admitting requests whose history would be lost.
			c.historySignal.ObserveWriteOutage(ctx)
			c.pauseForOutage(ctx)
			return
		}

		isPoison, sendErr := c.trySendToDLQProfile(ctx, sanitized, policy)
		if sendErr != nil {
			c.logger.Error("failed to send poison message to DLQ",
				slog.String("stream_id", msg.ID),
				slog.String("error", safeDiagnostic(profile, sendErr.Error())),
			)
		} else if isPoison {
			if ackErr := c.rdb.XAck(ctx, c.streamName, consumerGroup, []string{msg.ID}).Err(); ackErr != nil {
				c.logger.Warn("XACK failed for DLQ message", slog.String("stream_id", msg.ID), slog.String("error", safeDiagnostic(profile, ackErr.Error())))
			}
		}
		return
	}

	// N10-P04-T03: a successful durable delivery clears the write-outage
	// latch; the next gate observation heartbeats the recovered signal.
	c.historySignal.ClearWriteOutage()

	if eventType != "" {
		metrics.EventsConsumedTotal.WithLabelValues(eventType).Inc()
	}
	retryKey := fmt.Sprintf("%s:%s:%s:%s", dlqRetryKeyPrefix, c.streamName, consumerGroup, msg.ID)
	c.rdb.DEL(ctx, retryKey)
	if err := c.rdb.XAck(ctx, c.streamName, consumerGroup, []string{msg.ID}).Err(); err != nil {
		c.logger.Warn("XACK failed", slog.String("stream_id", msg.ID), slog.String("error", safeDiagnostic(profile, err.Error())))
	}
}

// dbUnavailable reports a full Postgres outage: a delivery error against a
// database that does not answer a trivial probe. A nil pool is a permanent
// configuration error, not an outage — those messages keep the retry/DLQ
// path (retrying them can never succeed).
func (c *StreamConsumer) dbUnavailable(ctx context.Context) bool {
	if c.dbPool == nil {
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, dbProbeTimeout)
	defer cancel()
	var one int
	return c.dbPool.QueryRow(probeCtx, dbProbeQuery).Scan(&one) != nil
}

// pauseForOutage sleeps the outage backoff, returning early on shutdown.
func (c *StreamConsumer) pauseForOutage(ctx context.Context) {
	pause := c.outagePause
	if pause <= 0 {
		pause = defaultOutagePause
	}
	timer := time.NewTimer(pause)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// processMessagePolicy delivers one message under its per-message delivery
// policy; the OTel mirror sees the same sanitized fields.
func (c *StreamConsumer) processMessagePolicy(ctx context.Context, msg redis.XMessage, policy deliveryPolicy) error {
	fields := msg.Values
	eventType, _ := fields["event_type"].(string)

	err := c.deliverEventPolicy(ctx, msg, eventType, policy)
	// side-sink. exportOTelLogProfile is a nil-check + map build; the export
	// itself is non-blocking inside the sink (bounded queue + drop counter).
	if err == nil {
		c.exportOTelLogProfile(eventType, fields, policy.profile)
	}
	return err
}

// processMessage is the legacy-profile seam kept for existing callers that
// predate the content-profile boundary (tests, tooling). The production
// flow always enters through handleMessage, which computes the policy.
func (c *StreamConsumer) processMessage(ctx context.Context, msg redis.XMessage) error {
	return c.processMessagePolicy(ctx, msg, legacyDeliveryPolicy())
}

// deliverEventPolicy dispatches one stream message to its typed handler
// (the delivery/insertion path shared by every event shape), carrying the
// message's delivery policy (effective content profile + original
// retention).
func (c *StreamConsumer) deliverEventPolicy(ctx context.Context, msg redis.XMessage, eventType string, policy deliveryPolicy) error {
	fields := msg.Values

	// Invocation identity gate: only an ABSENT invocation_id may take the
	// legacy dedupe domain. A present malformed value (wrong JSON type,
	// empty, non-canonical spelling) parks via the standard retry→DLQ
	// machinery instead of silently downgrading — a downgrade could
	// double-bill or suppress a genuine invocation.
	if strings.HasPrefix(eventType, "request.") {
		if raw, _, malformed := invocationField(fields); malformed {
			c.logger.Error("malformed invocation_id — parking event",
				slog.String("event_type", eventType),
				slog.String("invocation_id_raw", raw),
				slog.String("request_id", eventString(fields, "request_id")),
			)
			return errMalformedInvocationID
		}
	}

	switch eventType {
	case "request.completed":
		return c.handleRequestCompleteProfile(ctx, msg, policy)
	case "request.failed":
		return c.handleRequestFailedProfile(ctx, msg, policy)
	case "request.budget_exceeded":
		// QG2-D2: budget-blocked requests were previously dropped at the
		// default branch. Persist them (status 429) so spend analytics see
		// blocked demand. Never routed to the Deductor: no spend happened.
		return c.handleRequestBudgetExceededProfile(ctx, msg, policy)
	case "request.shadow_completed":
		// V9: shadow-mode mirror result. Stored as its own request_logs row
		// (ab_group='shadow', same request_id as the primary). It is NEVER
		// passed to the credit Deductor: the Deductor dedupes by request_id,
		// so a shadow row sharing the primary's id would double-charge the
		// org. See the v9 plan (S3) for the analytics audit.
		return c.handleRequestShadowCompleteProfile(ctx, msg, policy)
	default:
		c.logger.Info("generic event received",
			slog.String("event_type", eventType),
			slog.String("source", fmt.Sprintf("%v", fields["source"])),
		)
		return nil
	}
}

// deliverEvent is the legacy-profile seam for existing callers; see
// deliverEventPolicy.
func (c *StreamConsumer) deliverEvent(ctx context.Context, msg redis.XMessage, eventType string) error {
	return c.deliverEventPolicy(ctx, msg, eventType, legacyDeliveryPolicy())
}

// handleRequestBudgetExceededProfile persists a request.budget_exceeded event as a
// request_logs row with status 429, so blocked demand is visible in analytics.
// The row never reaches the Deductor (that path only runs for
// request.completed), so no credit is charged for a blocked request.
// resolveRefusalAdmission binds the admission of an invocation-bearing
// budget refusal before any write: a bound admission of another tenant can
// never be claimed (that identity is paid elsewhere) and a voided one
// parks; a genuinely unadmitted refusal is a pre-dispatch event — the row
// records in the legacy domain without claiming the minted uuid.
// Refusals carry no charge, so no facts comparison applies.
func (c *StreamConsumer) resolveRefusalAdmission(ctx context.Context, tx InboxTx, ev *requestEvent) error {
	b, err := c.resolveAdmission(ctx, tx, *ev)
	if err != nil {
		return err
	}
	switch {
	case !b.found:
		c.logger.Info("unadmitted budget refusal — recording legacy-domain history without claiming the invocation",
			slog.String("invocation_id", ev.invocationID),
			slog.String("request_id", ev.requestID),
			slog.String("org_id", ev.orgID),
		)
		ev.invocationIDValue = nil
		ev.invocationID = ""
	case b.orgID != ev.orgID:
		c.logger.Error("budget refusal admission belongs to another org — parking, never claiming a paid identity",
			slog.String("invocation_id", ev.invocationID),
			slog.String("request_id", ev.requestID),
			slog.String("admission_org_id", b.orgID),
			slog.String("event_org_id", ev.orgID),
		)
		return errAdmissionOrgConflict
	case b.state == "voided":
		c.logger.Error("budget refusal for a voided invocation admission — parking",
			slog.String("invocation_id", ev.invocationID),
			slog.String("request_id", ev.requestID),
		)
		return errAdmissionVoided
	}
	return nil
}

func (c *StreamConsumer) handleRequestBudgetExceededProfile(ctx context.Context, msg redis.XMessage, policy deliveryPolicy) error {
	fields := msg.Values

	if c.dbPool == nil {
		c.logger.Error("DB pool not configured — cannot write request.budget_exceeded logs")
		return fmt.Errorf("DB is required but not configured")
	}

	c.markDeliverySeen(ctx, msg.ID)

	ev := parseRequestEventPolicy(fields, policy)
	errorMsg := ev.errorMsg
	if errorMsg == "" {
		errorMsg = "team budget limit reached"
	}

	tx, claimed, err := c.beginDelivery(ctx, msg.ID)
	if err != nil || !claimed {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful commit

	if ev.invocationIDValue != nil {
		if err := c.resolveRefusalAdmission(ctx, tx, &ev); err != nil {
			return err
		}
	}

	sessionIDStr := c.resolveSessionID(ctx, tx, ev.orgID, ev.sessionID)
	row := budgetRequestLogRow(ev, sessionIDStr, errorMsg)
	row.setAttribution(c.attributionID(fields, "api_key_id"), c.attributionID(fields, "session_key_id"))
	// Budget-refused requests carry no gateway-minted invocation today; the
	// binding is purely defensive and never downgrades to the legacy domain.
	row.setInvocation(ev.invocationIDValue)

	if _, err := tx.Exec(ctx, row.insertSQL(), row.args()...); err != nil {
		return fmt.Errorf("insert request_log for budget_exceeded event: %w", err)
	}

	// OP-9: a budget-blocked request still went through the policy pipeline;
	// its decision commits with the log (absent policy field skips silently).
	if err := c.insertPolicyDecision(ctx, tx, ev); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit delivery transaction: %w", err)
	}

	c.logger.Warn("budget-blocked request logged",
		slog.String("request_id", ev.requestID),
		slog.String("org_id", ev.orgID),
		slog.Int("status", 429),
		slog.String("error", safeDiagnostic(policy.profile, errorMsg)),
	)
	return nil
}

func (c *StreamConsumer) handleRequestFailed(ctx context.Context, msg redis.XMessage) error {
	return c.handleRequestFailedProfile(ctx, msg, legacyDeliveryPolicy())
}

func (c *StreamConsumer) handleRequestFailedProfile(ctx context.Context, msg redis.XMessage, policy deliveryPolicy) error {
	fields := msg.Values

	if c.dbPool == nil {
		c.logger.Error("DB pool not configured — cannot write request.failed logs")
		return fmt.Errorf("DB is required but not configured")
	}

	c.markDeliverySeen(ctx, msg.ID)

	ev := parseRequestEventPolicy(fields, policy)

	// Partial usage (NEXT-18d, ADR-0001 §6/D5/D6, I2): a failed request that
	// reached the provider with a known price bills like any other spend in
	// enforce mode; shadow only observes what enforce WOULD bill; off keeps
	// the legacy behavior (no intents for failed requests). Unknown
	// usage/price is the distinct uncharged state — reserve released by
	// reconcile, counted in uncharged_unknown_total, never a silent zero.
	//
	// usage is absorbed by the platform — no charge intents in any mode.
	// The would-be charge per scope is exported to
	// absorbed_upstream_error_micro_usd so the platform cost stays
	// observable; the reserve is left for reconcile to return after the
	// safety window. Client-side interrupts (client_cancel, idle_timeout)
	// keep the consumption model (D1: the delivered prefix is billable).
	chargeMicro, chargeState := resaleDeductionMicro(ev.costQuote, ev.resaleQuote, ev.costQuoteState, ev.resaleQuoteState)
	partialUsageKnown, absorbedUpstream := classifyFailedCharge(ev, chargeState)
	var plan []scopeCharge
	switch {
	case absorbedUpstream:
		emitAbsorbedUpstreamMetrics(ev, chargeMicro, chargeState)
	case partialUsageKnown:
		var err error
		plan, err = c.billablePlanForMode(ctx, ev, chargeMicro, chargeState)
		if err != nil {
			return err
		}
	}
	// A priced-and-absorbed upstream failure is not an unknown cost — its
	// bound belongs to the absorbed metric, not to uncharged_unknown.

	tx, claimed, err := c.beginDelivery(ctx, msg.ID)
	if err != nil || !claimed {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful commit

	return c.persistFailedDelivery(ctx, tx, msg, ev, plan, chargeState, absorbedUpstream, policy)
}

// classifyFailedCharge derives the two charge classes of a request.failed
// event: partialUsageKnown (usage existed and a positive quote survived —
// billable in enforce mode; client-side interrupts keep the D1
// delivered-prefix consumption model) and absorbedUpstream (an upstream
// error whose cost the platform absorbs, observed only).
func classifyFailedCharge(ev requestEvent, chargeState money.QuoteState) (partialUsageKnown, absorbedUpstream bool) {
	partialUsageKnown = ev.acct.usageSource != "none" && chargeState == money.QuotePositive
	absorbedUpstream = ev.termination == TerminationUpstreamErr && ev.acct.usageSource != "none"
	return partialUsageKnown, absorbedUpstream
}

// emitAbsorbedUpstreamMetrics exports the would-be charge per scope of a
// priced upstream failure the platform absorbs (NEXT-18d): the platform
// cost stays observable while no charge intents are ever created.
func emitAbsorbedUpstreamMetrics(ev requestEvent, chargeMicro money.MicroUSD, chargeState money.QuoteState) {
	for _, sc := range scopeChargePlan(ev, chargeMicro, chargeState) {
		metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues(sc.scope).Add(float64(sc.amount))
	}
}

// billablePlanForMode resolves the enforce-mode charge plan for a failed
// request with known partial usage: shadow only observes what enforce
// WOULD bill (WouldBillPartialMicroUSD), off keeps the legacy behavior
// (failed requests are never billed). A mode-lookup error on a LEGACY
// event bills nothing — failing closed to off preserves the exact
// pre-invocation behavior and the durable settlement path stays
// authoritative. An INVOKED event instead fails the delivery: committing a
// zero charge under an unknown mode would mint an invocation-domain row
// the settlement worker could never reprice, so the delivery retries
// until the mode is readable.
func (c *StreamConsumer) billablePlanForMode(ctx context.Context, ev requestEvent, chargeMicro money.MicroUSD, chargeState money.QuoteState) ([]scopeCharge, error) {
	mode, modeErr := c.reservationsMode(ctx, ev.orgID)
	if modeErr != nil {
		if ev.invocationIDValue != nil {
			return nil, fmt.Errorf("resolve reservations mode for invoked partial billing: %w", modeErr)
		}
		return nil, nil
	}
	switch mode {
	case modeEnforce:
		return scopeChargePlan(ev, chargeMicro, chargeState), nil
	case modeShadow:
		for _, sc := range scopeChargePlan(ev, chargeMicro, chargeState) {
			metrics.WouldBillPartialMicroUSD.WithLabelValues(sc.scope).Add(float64(sc.amount))
		}
	default: // off — legacy: failed requests are never billed
	}
	return nil, nil
}

// insertTerminalRequestLog writes the terminal request_logs row of a
// failed or completed delivery and returns the insert result for duplicate
// detection. The failed shape keeps the raw error text and the raw status
// code; the completed shape binds the defaulted status and an optional
// error.
func (c *StreamConsumer) insertTerminalRequestLog(ctx context.Context, tx InboxTx, msg redis.XMessage, ev requestEvent, errorValue any, statusCode int64) (pgconn.CommandTag, error) {
	sessionIDStr := c.resolveSessionID(ctx, tx, ev.orgID, ev.sessionID)
	row := fullRequestLogRow(ev, sessionIDStr, errorValue, statusCode)
	row.setAttribution(c.attributionID(msg.Values, "api_key_id"), c.attributionID(msg.Values, "session_key_id"))
	row.setInvocation(ev.invocationIDValue)
	return tx.Exec(ctx, row.insertSQL(), row.args()...)
}

// finishDuplicateInvocation closes a redelivered terminal whose request log
// row and every charge intent are already durable (a prior live delivery or
// the recovery materialization committed them): enrich optional history
// only, transition the admission, commit, ACK — never re-emit intents,
// never recharge.
func (c *StreamConsumer) finishDuplicateInvocation(ctx context.Context, tx InboxTx, ev requestEvent, policy deliveryPolicy) error {
	if err := c.enrichDuplicateInvocation(ctx, tx, ev); err != nil {
		return err
	}
	if err := c.transitionAdmissionDelivered(ctx, tx, ev, policy); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit delivery transaction: %w", err)
	}
	c.logger.Info("duplicate invocation delivery — optional history enriched, no recharge",
		slog.String("invocation_id", ev.invocationID),
		slog.String("request_id", ev.requestID),
		slog.String("org_id", ev.orgID),
	)
	return nil
}

// writeFirstDeliverySideEffects writes the mandatory side effects of a
// FIRST terminal delivery and commits the claimed transaction: the policy
// decision verdict (OP-9), one settlement intent per charged scope
// (AF-04/NEXT-18d), the pending_price record, and the admission
// resolution. Post-commit signals stay with the caller — they differ per
// event class.
func (c *StreamConsumer) writeFirstDeliverySideEffects(ctx context.Context, tx InboxTx, ev requestEvent, plan []scopeCharge, chargeState money.QuoteState, policy deliveryPolicy) error {
	if err := c.insertPolicyDecision(ctx, tx, ev); err != nil {
		return err
	}
	for _, sc := range plan {
		if err := c.insertScopeIntent(ctx, tx, ev.orgID, ev.requestID, ev.invocationIDValue, sc, ev.tokensIn, ev.tokensOut, ev.costInUSD, ev.resaleCostUSD, ev.modelUsed); err != nil {
			return err
		}
	}
	if err := c.insertPendingPriceIntent(ctx, tx, ev, chargeState); err != nil {
		return err
	}
	if err := c.transitionAdmissionDelivered(ctx, tx, ev, policy); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// persistCompletedSideEffects writes the post-log persistence of a
// first-delivery request.completed as one unit: the retained tool-call
// aggregate, then the shared first-delivery side effects with their commit.
// request.failed keeps its own envelope (persistFailedDelivery) and its
// semantics are unchanged — failures carry no tool-call aggregate.
func (c *StreamConsumer) persistCompletedSideEffects(ctx context.Context, tx InboxTx, ev requestEvent, plan []scopeCharge, chargeState money.QuoteState, policy deliveryPolicy) error {
	if err := c.insertToolCalls(ctx, tx, ev.requestIDValue, ev.orgIDValue, ev.g2.taskIDStr, ev.modelUsed, ev.upstreamResponse, ev.invocationIDValue); err != nil {
		return err
	}
	return c.writeFirstDeliverySideEffects(ctx, tx, ev, plan, chargeState, policy)
}

// persistFailedDelivery writes one request.failed delivery inside the
// claimed transaction and commits it: the request log row (raw error text
// and raw status code — the failed-shape contract), the policy decision
// verdict, the enforce-mode charge intents, and the pending_price record.
// After the commit it reports the uncharged-unknown signal exactly once
// per committed delivery (N06-P04-T08).
func (c *StreamConsumer) persistFailedDelivery(ctx context.Context, tx InboxTx, msg redis.XMessage, ev requestEvent, plan []scopeCharge, chargeState money.QuoteState, absorbedUpstream bool, policy deliveryPolicy) error {
	// The admission binding parks before any write when the event would
	// charge an org other than the one that admitted the invocation, or
	// claims a positive charge with no bound admission at all.
	if _, err := c.bindAdmission(ctx, tx, ev, plan); err != nil {
		return err
	}

	// request.failed keeps the raw error text and the raw status code: a
	// failed event with status 0 stores 0, and an absent error stores '' —
	// the failed-shape contract, unchanged.
	result, err := c.insertTerminalRequestLog(ctx, tx, msg, ev, ev.errorMsg, ev.statusCode)
	if err != nil {
		return fmt.Errorf("insert request_log for failed event: %w", err)
	}

	// Duplicate invocation: the row and every charge intent are already
	// durable — optional history only, never a recharge.
	if ev.invocationIDValue != nil && result.RowsAffected() == 0 {
		return c.finishDuplicateInvocation(ctx, tx, ev, policy)
	}

	if err := c.writeFirstDeliverySideEffects(ctx, tx, ev, plan, chargeState, policy); err != nil {
		return err
	}

	// After the commit succeeded: exactly one uncharged-unknown increment
	// per committed delivery (N06-P04-T08). The residual window — a crash
	// between the commit and the increment — is at-most-once for the signal
	// alone: no money is affected, and the bound stays durably visible
	// through the pending_price record committed in the same transaction,
	// so the reconciler's pending deadline still surfaces it as terminal
	// unknown. A priced-and-absorbed upstream failure is not an unknown
	// cost — its bound belongs to the absorbed metric, not here.
	if !absorbedUpstream || chargeState != money.QuotePositive {
		reportUnchargedUnknown(ev, plan, chargeState)
	}

	c.logger.Info("failed request log inserted",
		slog.String("request_id", ev.requestID),
		slog.String("org_id", ev.orgID),
		slog.Int64("status", ev.statusCode),
		slog.Int("scope_intents", len(plan)),
		slog.String("termination", string(ev.termination)),
		slog.String("error", safeDiagnostic(policy.profile, ev.errorMsg)),
	)

	return nil
}

// reservationsMode reads the org's reservations mode (ADR-0001 §9). Any
// read failure — a pre-reservation schema without the column, a missing org
// row, a transient error — degrades to off, the exact legacy behavior; the
// mode only ever widens billing for enforce orgs, so failing closed to off
// can never create a charge the org did not opt into.
func (c *StreamConsumer) reservationsMode(ctx context.Context, orgID string) (string, error) {
	if orgID == "" || c.dbPool == nil {
		return modeOff, nil
	}
	var mode string
	if err := c.dbPool.QueryRow(ctx,
		`SELECT reservations_mode FROM organizations WHERE id = $1`, orgID).Scan(&mode); err != nil {
		return modeOff, fmt.Errorf("read reservations mode: %w", err)
	}
	switch mode {
	case modeShadow, modeEnforce:
		return mode, nil
	default:
		return modeOff, nil
	}
}

// handleRequestShadowCompleteProfile stores a shadow-mode mirror result as its own
// request_logs row. The row shape mirrors request.completed (same 25-column
// insert) so existing tooling can read it, but:
//   - ab_group is forced to "shadow" (the discriminator for all analytics)
//   - the credit Deductor is deliberately NOT called (double-charge guard)
//   - resale_cost_usd is never read
//
// The write is atomic with the durable inbox claim per stream message
// (beginDelivery): exactly-once persistence no longer depends on Redis.
func (c *StreamConsumer) handleRequestShadowCompleteProfile(ctx context.Context, msg redis.XMessage, policy deliveryPolicy) error {
	fields := msg.Values

	if c.dbPool == nil {
		c.logger.Error("DB pool not configured — cannot write shadow request logs")
		return fmt.Errorf("DB is required but not configured")
	}

	c.markDeliverySeen(ctx, msg.ID)

	ev := parseRequestEventPolicy(fields, policy)
	statusCode := ev.statusCode
	if statusCode == 0 {
		statusCode = 200
	}

	tx, claimed, err := c.beginDelivery(ctx, msg.ID)
	if err != nil || !claimed {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful commit

	// Shadow admissions bind like primary ones (the gateway admits the
	// shadow dispatch before mirroring); the shadow plan never charges, so
	// the paid-without-admission gate cannot fire here — an org conflict or
	// a voided mirror still parks.
	if _, err := c.bindAdmission(ctx, tx, ev, nil); err != nil {
		return err
	}

	sessionIDStr := c.resolveSessionID(ctx, tx, ev.orgID, ev.sessionID)
	row := shadowRequestLogRow(ev, sessionIDStr, statusCode)
	row.setAttribution(c.attributionID(fields, "api_key_id"), c.attributionID(fields, "session_key_id"))
	row.setInvocation(ev.invocationIDValue)

	result, err := tx.Exec(ctx, row.insertSQL(), row.args()...)
	if err != nil {
		return fmt.Errorf("insert shadow request_log: %w", err)
	}

	if ev.invocationIDValue != nil && result.RowsAffected() == 0 {
		// Duplicate invocation: the mirror row is already durable — enrich
		// the shadow policy decision only when absent, never anything else.
		if err := c.enrichPolicyDecisionIfAbsent(ctx, tx, ev); err != nil {
			return err
		}
		if err := c.transitionAdmissionDelivered(ctx, tx, ev, policy); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit delivery transaction: %w", err)
		}
		c.logger.Info("duplicate shadow invocation delivery — policy decision guarded, no recharge",
			slog.String("invocation_id", ev.invocationID),
			slog.String("request_id", ev.requestID),
			slog.String("org_id", ev.orgID),
		)
		return nil
	}

	// OP-9: shadow decisions are the whole point of shadow mode ("what would
	// the policy have done") — commit with the mirror row.
	if err := c.insertPolicyDecision(ctx, tx, ev); err != nil {
		return err
	}

	if err := c.transitionAdmissionDelivered(ctx, tx, ev, policy); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit delivery transaction: %w", err)
	}

	c.logger.Info("shadow request log inserted",
		slog.String("request_id", ev.requestID),
		slog.String("org_id", ev.orgID),
		slog.String("primary_model", ev.modelRequested),
		slog.String("shadow_model", ev.modelUsed),
	)

	// NOTE: intentionally NO c.deductor.ProcessDeduction and NO settlement
	// intent here — see the double-charge guard in the processMessage
	// comment. Shadow cost is never charged.

	return nil
}

// scopeCharge is one per-scope settlement charge resolved from an event
// (ADR-0001 §5.3): one intent per reserve area the request touched.
type scopeCharge struct {
	kind   string // settlement charge kind
	scope  string // scope_kind (metric label + allowance mapping)
	key    string // scope key (team id / agent id / session key id)
	period string // budget period for period-scoped areas ("" for wallet)
	amount money.MicroUSD
	link   allowanceLink
}

// scopeChargePlan resolves the per-scope charges of one event. Reservation
// tuples (§5.3 Finalize) are authoritative when present: they name the
// exact area, key, period and allocation for every scope the request
// reserved. Legacy events (off mode, no tuples) fall back to the
// attribution fields exactly as before this card. The wallet area bills the
// resale charge (only a positive quote produces an amount); every budget
// area bills the BASE cost quote — including a genuine zero, which keeps
// the scope visible as a zero-cost counting entry instead of vanishing
// from the plan entirely.
func scopeChargePlan(ev requestEvent, chargeMicro money.MicroUSD, chargeState money.QuoteState) []scopeCharge {
	var tuples map[string]reservationTuple
	if len(ev.reservations) > 0 {
		tuples = make(map[string]reservationTuple, len(ev.reservations))
		for _, t := range ev.reservations {
			tuples[t.ScopeKind] = t
		}
	}
	linkOf := func(t reservationTuple) allowanceLink {
		return allowanceLink{AllowanceID: t.AllowanceID, BoundMicroUSD: t.BoundMicroUSD}
	}

	plan := make([]scopeCharge, 0, 4)
	// Wallet: resale price wins over base, unknown is never billed.
	if chargeState == money.QuotePositive {
		charge := scopeCharge{
			kind:   ChargeKindResaleDeduction,
			scope:  "wallet",
			amount: chargeMicro,
		}
		if t, ok := tuples["wallet"]; ok {
			charge.link = linkOf(t)
		}
		plan = append(plan, charge)
	}

	// team_month: tuple key/period, else the event's team attribution with
	// I5; W-LOGG: the period derives from the producer ts, never from the
	// delivery moment — delayed delivery must not shift the bucket).
	teamBase := scopeCharge{kind: ChargeKindTeamSpend, scope: "team_month", amount: ev.costQuote}
	if t, ok := tuples["team_month"]; ok {
		teamBase.key = t.ScopeKey
		teamBase.period = t.Period
		teamBase.link = linkOf(t)
		plan = append(plan, teamBase)
	} else if teamID, ok := ev.teamIDValue.(string); ok && teamID != "" {
		teamBase.key = teamID
		teamBase.period = ev.businessPeriod()
		plan = append(plan, teamBase)
	}

	// agent_day: tuple key, else the event's agent attribution.
	agentBase := scopeCharge{kind: ChargeKindAgentSpend, scope: "agent_day", amount: ev.costQuote}
	if t, ok := tuples["agent_day"]; ok {
		agentBase.key = t.ScopeKey
		agentBase.period = t.Period
		agentBase.link = linkOf(t)
		plan = append(plan, agentBase)
	} else if agentID, ok := ev.g2.agentIDStr.(string); ok && agentID != "" {
		agentBase.key = agentID
		plan = append(plan, agentBase)
	}

	// session: exists only for keys with a money cap, which is exactly when
	// the gateway reserves the area — tuple-driven only (ADR §4.1).
	if t, ok := tuples["session"]; ok {
		plan = append(plan, scopeCharge{
			kind:   ChargeKindSessionSpend,
			scope:  "session",
			key:    t.ScopeKey,
			period: t.Period,
			amount: ev.costQuote,
			link:   linkOf(t),
		})
	}
	return plan
}

// reportUnchargedUnknown counts the reserve bounds of an event whose
// usage/price is unknown (ADR-0001 §6): never billed, never reported as a
// zero, reserve released by reconcile. A tuple counts when no plan entry
// actually bills its scope — a zero-amount plan entry keeps the bound
// counted, because with an unknown price the zero is a placeholder, not a
// fact. A known-zero quote is the opposite case (N06-P04-T07 boundary): a
// valid zero quote proves the cost is zero — the counting intents bill it
// as 0 — so nothing is unknown and the bound is NOT counted here; counting
// it would inflate the unknown-price signal for provably-free requests.
// A request denied before the provider call (usage_source none, e.g.
// policy_denied) has no usage to be unknown — its reserve is released
// without charge and without the metric.
//
// Counting contract (N06-P04-T08): call this only AFTER the delivery
// transaction committed — exactly one increment per committed delivery.
// A pre-claim call re-inflated the counter on every redelivery of the
// same entry id; a post-claim pre-commit call survived a rolled-back
// delivery the same way. The residual commit→increment crash window is
// at-most-once for the signal alone; the bound itself stays durably
// visible through the pending_price record written in the same
// transaction.
func reportUnchargedUnknown(ev requestEvent, plan []scopeCharge, chargeState money.QuoteState) {
	if ev.acct.usageSource == "none" || len(ev.reservations) == 0 || chargeState == money.QuoteZero {
		return
	}
	billed := make(map[string]bool, len(plan))
	for _, sc := range plan {
		if sc.amount > 0 {
			billed[sc.scope] = true
		}
	}
	for _, t := range ev.reservations {
		if billed[t.ScopeKind] {
			continue
		}
		metrics.UnchargedUnknownTotal.WithLabelValues(t.ScopeKind).Add(float64(t.BoundMicroUSD))
	}
}

func (c *StreamConsumer) handleRequestComplete(ctx context.Context, msg redis.XMessage) error {
	return c.handleRequestCompleteProfile(ctx, msg, legacyDeliveryPolicy())
}

// terminalChargePlan resolves the per-scope charge plan of a completed
// event and warns when the price stayed unknown (AF-05): unknown
// price/usage is a distinct state — never billed, never reported as zero —
// and the cost stays visible through the pending_price record. Reservation
// tuples are the authoritative areas when present, legacy attributions
// otherwise.
func (c *StreamConsumer) terminalChargePlan(ev requestEvent) (money.MicroUSD, money.QuoteState, []scopeCharge) {
	chargeMicro, chargeState := resaleDeductionMicro(ev.costQuote, ev.resaleQuote, ev.costQuoteState, ev.resaleQuoteState)
	if chargeState == money.QuoteUnknown {
		c.logger.Warn("request completed with unknown price — no charge intent; pending_price record keeps the cost visible",
			slog.String("request_id", ev.requestID),
			slog.String("org_id", ev.orgID),
			slog.String("resale_quote", ev.resaleQuoteState.String()),
			slog.String("cost_quote", ev.costQuoteState.String()),
		)
	}
	// A cache replay has a history identity and can carry team attribution,
	// but it never opened a paid dispatch or a spend reservation.
	if ev.invocationIDValue != nil && genuineCacheHit(ev) {
		return chargeMicro, chargeState, nil
	}
	return chargeMicro, chargeState, scopeChargePlan(ev, chargeMicro, chargeState)
}

// handleRequestCompleteProfile persists one request.completed event under
// the message's delivery policy: the content profile decides whether
// content rides at all; the org original-retention resolution (N02-P06 T03)
// decides whether the full-fidelity ORIGINAL captures (upstream
// request/response samples and the tool-call arguments derived from them)
// are persisted next to the processed response snapshot.
func (c *StreamConsumer) handleRequestCompleteProfile(ctx context.Context, msg redis.XMessage, policy deliveryPolicy) error {
	fields := msg.Values

	if c.dbPool == nil {
		c.logger.Error("DB pool not configured — cannot write request logs")
		return fmt.Errorf("DB is required but not configured")
	}

	c.markDeliverySeen(ctx, msg.ID)

	ev := parseRequestEventPolicy(fields, policy)

	// Completed events default a missing status to 200 (a well-formed event
	// that simply omits the field); the error column binds NULL, not ''.
	statusCode := ev.statusCode
	if statusCode == 0 {
		statusCode = 200
	}

	// Mandatory monetary side effects are computed up front and persisted as
	// durable settlement work items inside the SAME transaction as the
	// request log (AF-04). The AF-06 settlement worker executes these
	// intents (lease/retry/idempotency); nothing is charged directly on the
	// delivery path anymore.
	_, chargeState, plan := c.terminalChargePlan(ev)
	// Unknown usage with a reserve: the bound is never billed and never
	// reported as zero; reconcile releases it (ADR-0001 §6). The
	// uncharged-unknown signal itself counts only after the commit below.

	tx, claimed, err := c.beginDelivery(ctx, msg.ID)
	if err != nil || !claimed {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful commit

	// The admission binding parks before any write when the event would
	// charge an org other than the one that admitted the invocation, or
	// claims a positive charge with no bound admission at all.
	if _, err := c.bindAdmission(ctx, tx, ev, plan); err != nil {
		return err
	}

	result, err := c.insertTerminalRequestLog(ctx, tx, msg, ev, ev.errorOptional(), statusCode)
	if err != nil {
		return fmt.Errorf("insert request_log: %w", err)
	}

	// Duplicate invocation (fresh Redis entry id, consumer restart, DLQ
	// replay): the row and every charge intent are already durable.
	if ev.invocationIDValue != nil && result.RowsAffected() == 0 {
		return c.finishDuplicateInvocation(ctx, tx, ev, policy)
	}

	// Tool-call aggregate + first-delivery accounting as one atomic unit:
	// the calls the model requested are extracted from the raw sample
	// (pre-truncation) so the analytics table stays queryable, then the
	// shared side effects (policy decision, charge intents, admission
	// transition, commit) run in the same transaction. The tool facts carry
	// this delivery's invocation identity when it has one (0030); a legacy
	// delivery binds the NULL domain unchanged. Errors fail the delivery
	// (rollback, no ack, redelivery) — see insertToolCalls for why nothing
	// inside a PostgreSQL transaction is fail-soft, and how redelivery
	// converges without duplicate children.
	if err := c.persistCompletedSideEffects(ctx, tx, ev, plan, chargeState, policy); err != nil {
		return err
	}

	// After the commit succeeded: exactly one uncharged-unknown increment
	// per committed delivery (N06-P04-T08). The residual crash window is
	// at-most-once for the signal alone — the bound stays durably visible
	// through the pending_price record committed in the same transaction.
	reportUnchargedUnknown(ev, plan, chargeState)

	rowsAffected := result.RowsAffected()

	c.logger.Info("request log inserted",
		slog.String("request_id", ev.requestID),
		slog.Int64("rows", rowsAffected),
		slog.String("model", ev.modelRequested),
		slog.Int64("status", statusCode),
		slog.Int64("duration_ms", ev.durationMs),
	)

	// AF-06: no direct charge happens on the delivery path. The mandatory
	// monetary side effects are the durable settlement_jobs intents written
	// above, in this same transaction; the settlement worker executes them
	// with lease/retry/idempotency (a DB error → restart → retry still
	// bills exactly once). The legacy best-effort Deductor/RecordAgentSpend
	// calls were removed with the worker's cutover.
	return nil
}

// The DLQ payload schema (eventpublisher.DLQEnvelope) lives beside the event
// contract in pkg/eventpublisher: the consumer writes it, `yb dlq replay`
// reads it — one definition, no drift.

// trySendToDLQ is the legacy-profile seam for existing callers; see
// trySendToDLQProfile.
func (c *StreamConsumer) trySendToDLQ(ctx context.Context, msg redis.XMessage) (bool, error) {
	return c.trySendToDLQProfile(ctx, msg, legacyDeliveryPolicy())
}

// trySendToDLQProfile records the retry attempt and, past the budget,
// archives the message in the DLQ. Under the metadata-only profile the
// envelope Values are rebuilt from the bounded allowlist (the sanitized
// message already lost every content capture), so poison events can never
// carry content into the DLQ; under retention OFF the original-capture
// fields are stripped the same way (N02-P06: retention applies before every
// durable write, the DLQ included — a poisoned entry can never re-introduce
// captures the producer withheld, and pre-fix in-flight entries are cleaned
// at this boundary too). TTL, marshal and Redis writer errors are
// sanitized with the same profile before they reach logs. Returned errors
// are raw (callers log them through the profile-aware diagnostic path).
func (c *StreamConsumer) trySendToDLQProfile(ctx context.Context, msg redis.XMessage, policy deliveryPolicy) (bool, error) {
	profile := policy.profile
	retryKey := fmt.Sprintf("%s:%s:%s:%s", dlqRetryKeyPrefix, c.streamName, consumerGroup, msg.ID)

	count, err := c.rdb.INCR(ctx, retryKey).Result()
	if err != nil {
		return false, fmt.Errorf("incr retry counter: %w", err)
	}

	// W-LOGG: the TTL is refreshed on EVERY attempt, not only the first —
	// the old code left count>=2 keys effectively immortal (an INCR without
	// Expire creates or refreshes nothing), leaking retry state forever.
	if _, err := c.rdb.Expire(ctx, retryKey, dlqTTL).Result(); err != nil {
		c.logger.Warn("set dlq retry ttl failed",
			slog.String("retry_key", retryKey),
			slog.String("error", safeDiagnostic(profile, err.Error())),
		)
	}

	if count > maxRetries {
		envelopeValues := msg.Values
		if profile == config.LogContentProfileMetadataOnly {
			envelopeValues = strictDLQValues(msg.Values)
		} else if !policy.retainOriginal {
			// N02-P06: retention OFF strips the original-capture fields
			// before the durable DLQ write (shared resolver semantic with
			// the producer's pre-XADD strip).
			envelopeValues = retentionStrippedValues(msg.Values)
		}
		envelope := eventpublisher.DLQEnvelope{
			OriginalStream: c.streamName,
			EntryID:        msg.ID,
			RetryCount:     count,
			Error:          "max retries exceeded",
			FailedAt:       time.Now().UTC().Format(time.RFC3339),
			Values:         envelopeValues,
		}
		body, marshalErr := json.Marshal(envelope)
		if marshalErr != nil {
			// Values only ever holds JSON-marshalable scalars (Redis stream
			// wire values); falling back to an empty map keeps the envelope
			// identifiable instead of losing the entry entirely.
			c.logger.Error("marshal dlq envelope failed; storing identifiers only",
				slog.String("stream_id", msg.ID),
				slog.String("error", safeDiagnostic(profile, marshalErr.Error())),
			)
			envelope.Values = map[string]interface{}{}
			body, marshalErr = json.Marshal(envelope)
			if marshalErr != nil {
				return false, fmt.Errorf("marshal dlq envelope: %w", marshalErr)
			}
		}

		dlqFields := map[string]interface{}{
			// The replay contract: the whole original event lives in the
			// structured `payload` JSON; the flat fields below are the
			// human/debug surface (XRANGE inspection without decoding).
			"payload":         string(body),
			"original_stream": c.streamName,
			"entry_id":        msg.ID,
			"retry_count":     count,
			"error":           "max retries exceeded",
			"failed_at":       envelope.FailedAt,
		}
		if eventType, ok := msg.Values["event_type"].(string); ok {
			dlqFields["event_type"] = eventType
		}

		if _, err := c.rdb.XAdd(ctx, &redis.XAddArgs{
			Stream: dlqStreamName,
			MaxLen: dlqMaxLen,
			Approx: true,
			Values: dlqFields,
		}).Result(); err != nil {
			return false, fmt.Errorf("xadd to DLQ: %w", err)
		}

		c.logger.Warn("message sent to DLQ after max retries",
			slog.String("stream_id", msg.ID),
			slog.Int64("retry_count", count),
		)
		return true, nil
	}

	return false, nil
}

// NewRedisOps creates a RedisOps wrapper around a real *redis.Client.
func NewRedisOps(rdb *redis.Client) RedisOps {
	return &redisXAckWrapper{rdb}
}

// markDeliverySeen records the Redis "msg:seen" marker for this delivery.
// AF-04: the marker is a redelivery optimization plus a compatibility
// artefact for pre-inbox workers (a rolled-back old worker still consults it
// to avoid reprocessing recent events). It is NEVER proof that the event was
// persisted: a marker left by a crashed attempt whose transaction did not
// commit must not skip the delivery — only a committed event_inbox row does.
func (c *StreamConsumer) markDeliverySeen(ctx context.Context, msgID string) {
	if c.rdb == nil || msgID == "" {
		return
	}
	if _, err := c.rdb.SETNX(ctx, msgSeenKeyPrefix+msgID, "1", msgSeenTTL).Result(); err != nil {
		c.logger.Warn("dedup SETNX failed; durable inbox stays authoritative",
			slog.String("msg_id", msgID),
			slog.String("error", err.Error()),
		)
	}
}

// beginDelivery opens the delivery transaction and claims the durable inbox
// identity (stream, consumer group, stream entry id). claimed=false means an
// earlier delivery already committed this event: the caller must skip every
// write and report success (the delivery is done, not failed) so the message
// is ACKed without a duplicate row.
//
// Events without an entry id (degenerate test fixtures; real Redis streams
// always assign one) skip the inbox claim and degrade to a plain transaction
// — a synthetic empty id must not dedupe unrelated events against each other.
func (c *StreamConsumer) beginDelivery(ctx context.Context, eventID string) (InboxTx, bool, error) {
	tx, err := c.dbPool.BeginTx(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("begin delivery transaction: %w", err)
	}
	if eventID == "" {
		return tx, true, nil
	}
	tag, err := tx.Exec(ctx, inboxClaimQuery, c.streamName, consumerGroup, eventID)
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, false, fmt.Errorf("claim event_inbox: %w", err)
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		c.logger.Info("duplicate delivery skipped by durable inbox",
			slog.String("stream", c.streamName),
			slog.String("event_id", eventID),
		)
		return nil, false, nil
	}
	return tx, true, nil
}

// ---------------------------------------------------------------------------
// Invocation admission binding (Preview2)
//
// Live terminal events for invocation-domain requests bind to the durable
// admission the gateway wrote before the first paid provider call. The
// binding enforces two owner invariants:
//
//  1. A charged event may only book against the org that admitted the
//     invocation: a cross-org event parks (typed error → retry → DLQ) and
//     never charges a different tenant. A terminal event for a voided
//     invocation is a contradiction and parks the same way.
//  2. Only an ABSENT invocation_id may take the legacy dedupe domain
//     (malformed nonempty values park at dispatch). A present canonical
//     identity that would create a positive wallet charge without any
//     bound admission parks too: the gateway admits every paid dispatch
//     fail-closed, so such an event is a defect. Cache hits legitimately
//     mint an identity with no admission row and never carry a charge —
//     their history still records under the event's own org, keeping the
//     established cache accounting.
// ---------------------------------------------------------------------------

// admissionLookupQuery reads the admission row bound to the event's
// invocation FOR UPDATE: the row lock lives for the delivery transaction
// and serializes this binding against a concurrent gateway void or a
// reconciler transition, so the state read here cannot be invalidated
// before the delivery commits.
const admissionLookupQuery = `SELECT org_id, state FROM request_admissions WHERE invocation_id = $1 FOR UPDATE`

// admissionFactsQuery selects the authoritative terminal fact of an
// admitted invocation FOR UPDATE. The gateway commits this row before
// publishing the event (single ts stamped before both), so the stream
// delivery must find it present and equal — a missing or divergent fact
// means the stream event cannot be trusted to resolve or charge.
const admissionFactsQuery = `SELECT event FROM request_terminal_facts WHERE invocation_id = $1 AND org_id = $2 FOR UPDATE`

// admissionResolveEventQuery is the consumer-owned guarded transition after
// a live delivery committed the accounting. The state guard makes it a
// no-op when recovery already reconciled the admission, and 'voided' rows
// are terminal and never touched here.
const admissionResolveEventQuery = `UPDATE request_admissions
	SET state = 'reconciled', resolved_at = now(), resolve_reason = $1
	WHERE invocation_id = $2 AND state IN ('admitted', 'unresolved')`

// invocationEnrichmentLockQuery serializes duplicate-invocation enrichment
// against concurrent redeliveries (reclaim overlap): the second delivery
// waits for the first enrichment to commit, then its existence probes see
// the committed side-table rows and skip. Same per-key pattern as the
// credits store's deduct serialization.
const invocationEnrichmentLockQuery = `SELECT pg_advisory_xact_lock(hashtext($1))`

var (
	// errMalformedInvocationID parks events whose nonempty invocation_id is
	// not a canonical UUID: silently downgrading them to the legacy dedupe
	// domain could double-bill or suppress a genuine invocation.
	errMalformedInvocationID = errors.New("invocation_id present but not a canonical UUID")
	errAdmissionOrgConflict  = errors.New("invocation admission belongs to a different org")
	errAdmissionVoided       = errors.New("terminal event for a voided invocation admission")
	errPaidWithoutAdmission  = errors.New("positive charge without a bound invocation admission")
	// errAdmissionSchemaMissing surfaces an invocation-bearing event on a
	// schema without request_admissions (pre-0028): the failed lookup has
	// already aborted the transaction, and treating it as unbound would
	// both continue on an aborted transaction and silently downgrade the
	// identity domain.
	errAdmissionSchemaMissing = errors.New("invocation event on a schema without request_admissions")
	// errUnadmittedTerminal parks a terminal event without an admission
	// that does not carry explicit free cache semantics: zero-charge,
	// unpriced and provider-BYOK terminals are not cache history.
	errUnadmittedTerminal = errors.New("terminal event without an admission or explicit free cache semantics")
	// errTerminalFactsMissing parks an admitted invocation's terminal
	// event whose authoritative facts row is absent: the stream cannot
	// resolve or charge ahead of the fact the gateway commits first.
	errTerminalFactsMissing = errors.New("admitted invocation has no authoritative terminal facts row")
	// errTerminalFactsDivergent parks a terminal event whose accounting
	// fields disagree with the authoritative facts row (different model,
	// usage, cost or timestamp under the same invocation id).
	errTerminalFactsDivergent = errors.New("wire event accounting fields diverge from the terminal facts")
)

// admissionBinding is the resolved durable admission of one event.
type admissionBinding struct {
	orgID string
	state string
	found bool
}

// resolveAdmission reads the admission row bound to the event's invocation,
// if any, under FOR UPDATE. Every read error fails the delivery: a missing
// request_admissions table (42P01, pre-0028) has already aborted the
// transaction, and an invocation event on that schema must surface instead
// of proceeding unbound.
func (c *StreamConsumer) resolveAdmission(ctx context.Context, tx InboxTx, ev requestEvent) (admissionBinding, error) {
	if ev.invocationIDValue == nil {
		return admissionBinding{}, nil
	}
	var b admissionBinding
	err := tx.QueryRow(ctx, admissionLookupQuery, ev.invocationID).Scan(&b.orgID, &b.state)
	if err == nil {
		b.found = true
		return b, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return admissionBinding{}, nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
		c.logger.Error("invocation event but request_admissions is missing — parking (schema predates 0028)",
			slog.String("invocation_id", ev.invocationID),
			slog.String("request_id", ev.requestID),
		)
		return admissionBinding{}, errAdmissionSchemaMissing
	}
	return admissionBinding{}, fmt.Errorf("resolve invocation admission: %w", err)
}

// bindAdmission resolves and enforces the admission binding before any
// accounting write in the delivery transaction. Legacy-domain events (no
// invocation id) have no admission by definition and pass untouched.
func (c *StreamConsumer) bindAdmission(ctx context.Context, tx InboxTx, ev requestEvent, plan []scopeCharge) (admissionBinding, error) {
	if ev.invocationIDValue == nil {
		return admissionBinding{}, nil
	}
	b, err := c.resolveAdmission(ctx, tx, ev)
	if err != nil {
		return b, err
	}
	if !b.found {
		if c.chargePlanCarriesCharge(plan) {
			c.logger.Error("positive charge without a bound invocation admission — parking (the gateway admits every paid dispatch before any provider call)",
				slog.String("invocation_id", ev.invocationID),
				slog.String("request_id", ev.requestID),
				slog.String("org_id", ev.orgID),
			)
			return b, errPaidWithoutAdmission
		}
		if !genuineCacheHit(ev) || planHasPayableScope(plan) {
			// Zero-charge, unpriced and provider-BYOK terminals are not
			// cache history: without an admission row the identity is
			// unaccounted for, and recording it as cache would silently
			// lose it.
			c.logger.Error("terminal event without an admission and without explicit free cache semantics — parking",
				slog.String("invocation_id", ev.invocationID),
				slog.String("request_id", ev.requestID),
				slog.String("org_id", ev.orgID),
			)
			return b, errUnadmittedTerminal
		}
		// A genuine cache hit mints an identity with no admission row and
		// carries no charge, reservation or payable scope: its history
		// records under the event's own org, keeping the established
		// cache accounting.
		c.logger.Info("cache-hit identity without admission — recording history without charge",
			slog.String("invocation_id", ev.invocationID),
			slog.String("request_id", ev.requestID),
			slog.String("org_id", ev.orgID),
		)
		return b, nil
	}
	if b.orgID != ev.orgID {
		c.logger.Error("invocation admission org differs from the event org — parking, never charging a different tenant",
			slog.String("invocation_id", ev.invocationID),
			slog.String("request_id", ev.requestID),
			slog.String("admission_org_id", b.orgID),
			slog.String("event_org_id", ev.orgID),
		)
		return b, errAdmissionOrgConflict
	}
	if b.state == "voided" {
		c.logger.Error("terminal event for a voided invocation admission — parking",
			slog.String("invocation_id", ev.invocationID),
			slog.String("request_id", ev.requestID),
			slog.String("org_id", ev.orgID),
		)
		return b, errAdmissionVoided
	}
	// The bound admission's authoritative facts row is the terminal record
	// of truth: the delivery compares against it (locked) before any live
	// write, so a divergent or missing fact can neither resolve the
	// admission nor charge from the stream.
	if err := c.verifyTerminalFacts(ctx, tx, ev); err != nil {
		return b, err
	}
	return b, nil
}

// genuineCacheHitKind enumerates the cache kinds the gateway actually mints
// for a free, fully-cached response. Anything else on the wire — an unknown
// kind, a gateway "none" placeholder, free-form text — is not cache
// evidence and must not excuse a missing admission.
var genuineCacheHitKinds = map[string]bool{
	"exact":    true,
	"pg_exact": true,
	"semantic": true,
}

// planHasPayableScope reports whether any plan entry bills a real scope: a
// budget-area entry always counts, a wallet entry counts when its amount is
// positive. Genuine free cache evidence requires none of them.
func planHasPayableScope(plan []scopeCharge) bool {
	for _, sc := range plan {
		switch sc.kind {
		case ChargeKindAgentSpend, ChargeKindTeamSpend, ChargeKindSessionSpend:
			return true
		case ChargeKindResaleDeduction:
			if sc.amount > 0 {
				return true
			}
		}
	}
	return false
}

// genuineCacheHit reports whether an admission-less invocation event
// carries explicit free cache semantics — the only legitimate
// admission-less terminal. The evidence must be explicit on every axis: a
// gateway-declared cache_hit_type (a real cache kind, never an arbitrary
// string), the gateway's cache accounting shape (usage_source "none" and
// cost_status "cache_hit"), quotes resolved to a genuine zero (not
// unknown/unpriced), no new token consumption and no reservation linkage.
func genuineCacheHit(ev requestEvent) bool {
	kind, ok := ev.cacheHitType.(string)
	if !ok || !genuineCacheHitKinds[kind] {
		return false
	}
	if ev.acct.usageSource != "none" || ev.acct.costStatus != "cache_hit" {
		return false
	}
	if ev.resaleQuoteState != money.QuoteZero || ev.costQuoteState != money.QuoteZero {
		return false
	}
	return len(ev.reservations) == 0 && ev.tokensIn == 0 && ev.tokensOut == 0
}

// verifyTerminalFacts selects the admission's terminal fact row FOR UPDATE
// and compares its accounting fields against the wire event's published
// scalars. The gateway stamps one ts and commits the fact before
// publishing, so equality is the expected outcome of a genuine delivery;
// a missing row or any field divergence parks the event (recovery owns
// fact-authoritative materialization, never the live stream).
func (c *StreamConsumer) verifyTerminalFacts(ctx context.Context, tx InboxTx, ev requestEvent) error {
	// The gateway stores the canonical facts map (all values stringified)
	// as jsonb; scanning into a string keeps the value bytes exact.
	var factsJSON string
	err := tx.QueryRow(ctx, admissionFactsQuery, ev.invocationID, ev.orgID).Scan(&factsJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		c.logger.Error("admitted invocation has no terminal facts row — parking (the gateway commits the fact before publishing)",
			slog.String("invocation_id", ev.invocationID),
			slog.String("request_id", ev.requestID),
			slog.String("org_id", ev.orgID),
		)
		return errTerminalFactsMissing
	}
	if err != nil {
		return fmt.Errorf("select terminal facts: %w", err)
	}
	// The producer-side decoder re-derives the exact schema — field count,
	// scalar validity, invocation/org attribution — so the stored side of
	// the comparison is the full producer keyset, never a consumer-chosen
	// subset.
	facts, err := eventpublisher.DecodeTerminalAccounting([]byte(factsJSON), ev.invocationID, ev.orgID)
	if err != nil {
		c.logger.Error("terminal facts row fails the canonical producer contract — parking",
			slog.String("invocation_id", ev.invocationID),
			slog.String("org_id", ev.orgID),
			slog.String("error", err.Error()),
		)
		return errTerminalFactsDivergent
	}
	if diff, ok := compareAccountingFields(facts, ev.raw); !ok {
		c.logger.Error("wire event accounting fields diverge from the terminal facts — parking, never resolving or charging from the stream",
			slog.String("invocation_id", ev.invocationID),
			slog.String("request_id", ev.requestID),
			slog.String("org_id", ev.orgID),
			slog.String("field", diff),
		)
		return errTerminalFactsDivergent
	}
	return nil
}

// compareAccountingFields checks the stored facts map against the wire
// event's raw scalars. The decoded facts row covers exactly the producer
// keyset, so every stored scalar must appear on the wire as the equal
// string — the published values are exactly these scalars, and a canonical
// wire value the facts row does not carry (an added payer, a second
// event_type) has no facts-side counterpart to match and cannot pass. The
// one normalization: a stored canonical empty string ("") matches an absent
// wire scalar, because the producer always writes the full keyset while
// older wire events may omit empty fields. Returns the first divergent
// field for the park diagnostic.
func compareAccountingFields(facts map[string]any, wire map[string]interface{}) (string, bool) {
	for key, factValue := range facts {
		factStr, ok := factValue.(string)
		if !ok {
			return key, false
		}
		raw, ok := wire[key]
		if !ok {
			if factStr == "" {
				continue // canonical empty ≡ absent wire scalar
			}
			return key, false
		}
		wireValue, ok := raw.(string)
		if !ok || wireValue != factStr {
			return key, false
		}
	}
	return "", true
}

// chargePlanCarriesCharge reports whether the plan would create a positive
// wallet (resale_deduction) intent — the one scope that moves money. It
// mirrors the insertScopeIntent gate exactly, so "carries a charge" and
// "would write a charge intent" can never disagree.
func (c *StreamConsumer) chargePlanCarriesCharge(plan []scopeCharge) bool {
	if c.creditStore == nil {
		return false
	}
	for _, sc := range plan {
		if sc.kind == ChargeKindResaleDeduction && sc.amount > 0 {
			return true
		}
	}
	return false
}

// transitionAdmissionDelivered moves the bound admission to 'reconciled'
// inside the delivery transaction. A failed UPDATE has aborted the
// transaction, so the error propagates — logging and continuing would
// commit nothing (25P02) while reporting the delivery as done. The
// reconciler's grace sweep remains the backstop for deliveries that never
// reach this point.
func (c *StreamConsumer) transitionAdmissionDelivered(ctx context.Context, tx InboxTx, ev requestEvent, policy deliveryPolicy) error {
	if ev.invocationIDValue == nil {
		return nil
	}
	// The resolve reason separates live stream delivery from the
	// PostgreSQL facts-recovery materialization: only the recovery policy
	// sets recoveredFromFacts, so the audit trail names which path made
	// the admission durable.
	reason := "event_delivered"
	if policy.recoveredFromFacts {
		reason = "recovered_from_facts"
	}
	if _, err := tx.Exec(ctx, admissionResolveEventQuery, reason, ev.invocationID); err != nil {
		c.logger.Warn("admission transition to reconciled failed — delivery rolls back, reconciler backstop will retry",
			slog.String("invocation_id", ev.invocationID),
			slog.String("resolve_reason", reason),
			slog.String("error", err.Error()),
		)
		return fmt.Errorf("transition admission to reconciled: %w", err)
	}
	return nil
}

// enrichDuplicateInvocation fills optional history for a duplicate
// invocation delivery: the request row and every charge intent are already
// durable (a prior live delivery, or the recovery materialization from
// request_terminal_facts), so this path only enriches content and side
// tables the recovery projection cannot know. It never re-emits intents,
// never writes pending_price, never re-charges, and never downgrades the
// identity to the legacy domain.
func (c *StreamConsumer) enrichDuplicateInvocation(ctx context.Context, tx InboxTx, ev requestEvent) error {
	if ev.invocationIDValue == nil {
		return nil
	}
	if _, err := tx.Exec(ctx, invocationEnrichmentLockQuery, ev.invocationID); err != nil {
		return fmt.Errorf("lock duplicate invocation enrichment: %w", err)
	}
	if err := c.enrichRequestLogContent(ctx, tx, ev); err != nil {
		return err
	}
	if err := c.enrichToolCallsIfAbsent(ctx, tx, ev); err != nil {
		return err
	}
	return c.enrichPolicyDecisionIfAbsent(ctx, tx, ev)
}

// enrichRequestLogContent fills only the optional content columns that are
// still empty on the existing row (fill-NULL; labels additionally only
// replace the '{}' default). Existing values are never overwritten — the
// first materialization stays authoritative.
func (c *StreamConsumer) enrichRequestLogContent(ctx context.Context, tx InboxTx, ev requestEvent) error {
	type setCol struct {
		col string
		val any
	}
	var sets []setCol
	appendIf := func(col string, v any) {
		if v != nil {
			sets = append(sets, setCol{col, v})
		}
	}
	appendIf("response", ev.responseJSON)
	appendIf("upstream_request", ev.upstreamReqJSON)
	appendIf("upstream_response", ev.upstreamRespJSON)
	appendIf("prompt_hash", ev.promptHash)
	if len(ev.labels) > 0 && !bytes.Equal(ev.labels, []byte("{}")) {
		sets = append(sets, setCol{"labels", ev.labels})
	}
	if len(sets) == 0 {
		return nil
	}
	var sb strings.Builder
	sb.WriteString("UPDATE request_logs SET ")
	args := make([]any, 0, len(sets)+1)
	for i, s := range sets {
		if i > 0 {
			sb.WriteString(", ")
		}
		n := len(args) + 1
		if s.col == "labels" {
			// labels defaults to '{}' rather than NULL: fill only the
			// empty object, never a populated set.
			fmt.Fprintf(&sb, "labels = CASE WHEN labels = '{}'::jsonb THEN $%d ELSE labels END", n)
		} else {
			fmt.Fprintf(&sb, "%s = COALESCE(%s, $%d)", s.col, s.col, n)
		}
		args = append(args, s.val)
	}
	fmt.Fprintf(&sb, " WHERE invocation_id = $%d", len(args)+1)
	args = append(args, ev.invocationID)
	if _, err := tx.Exec(ctx, sb.String(), args...); err != nil {
		return fmt.Errorf("enrich duplicate invocation content: %w", err)
	}
	return nil
}

// Tool-fact enrichment probes for the absent-children backfill path:
//   - the coarse pre-0030 probe — the only valid form where the
//     invocation_id column does not exist (a 42703 there fails the
//     enrichment transaction);
//   - the NULL-domain form, required once 0030 added the identity column:
//     a minted sibling sharing the client request-id must never satisfy
//     the legacy existence check and suppress genuine legacy facts.
const (
	toolCallsAbsentProbeCoarseQuery     = `SELECT 1 FROM tool_calls WHERE request_id = $1 AND org_id = $2 LIMIT 1`
	toolCallsAbsentProbeNullDomainQuery = `SELECT 1 FROM tool_calls WHERE request_id = $1 AND org_id = $2 AND invocation_id IS NULL LIMIT 1`
)

// enrichToolCallsIfAbsent replays the tool-call extraction for a
// duplicate-invocation delivery whose children may be absent or partial.
//
// Identity split (0030):
//   - invocation-bearing deliveries skip the existence probe entirely:
//     every entry inserts under its own ON CONFLICT arbiter, so a partially
//     written prior attempt (an insert error rolls back its whole delivery
//     transaction, but a replay must not trust that) can never suppress
//     the missing names or occurrences — each replay re-inserts everything
//     and the arbiter no-ops exactly the rows that already exist for THIS
//     invocation. On a pre-0030 schema the original coarse probe and the
//     legacy bytes are kept verbatim: that is the supported
//     rolling-deployment mode, and its inserts are non-idempotent, so the
//     probe stays their only dedupe.
//   - legacy deliveries keep the coarse probe — their inserts have no
//     arbiter in any schema — scoped to the NULL domain once 0030's column
//     exists. Existing rows are never read to infer an invocation (no
//     guessed linkage); enrichment only replays THIS delivery's own
//     retained sample. Existence is established only by a clean row or by
//     pgx.ErrNoRows: any other probe error fails the enrichment (delivery
//     error, no ack, redelivery) rather than being mistaken for absence.
func (c *StreamConsumer) enrichToolCallsIfAbsent(ctx context.Context, tx InboxTx, ev requestEvent) error {
	hasToolFactInvocation, err := c.toolFactInvocationSchemaTx(ctx, tx)
	if err != nil {
		return fmt.Errorf("probe tool-fact invocation schema: %w", err)
	}
	if ev.invocationIDValue != nil {
		if !hasToolFactInvocation {
			var one int
			switch err := tx.QueryRow(ctx, toolCallsAbsentProbeCoarseQuery, ev.requestID, ev.orgID).Scan(&one); {
			case err == nil:
				return nil
			case !errors.Is(err, pgx.ErrNoRows):
				return fmt.Errorf("probe tool_calls enrichment: %w", err)
			}
		}
		return c.insertToolCalls(ctx, tx, ev.requestIDValue, ev.orgIDValue, ev.g2.taskIDStr, ev.modelUsed, ev.upstreamResponse, ev.invocationIDValue)
	}
	probe := toolCallsAbsentProbeCoarseQuery
	if hasToolFactInvocation {
		probe = toolCallsAbsentProbeNullDomainQuery
	}
	var one int
	switch err := tx.QueryRow(ctx, probe, ev.requestID, ev.orgID).Scan(&one); {
	case err == nil:
		return nil
	case !errors.Is(err, pgx.ErrNoRows):
		return fmt.Errorf("probe tool_calls enrichment: %w", err)
	}
	return c.insertToolCalls(ctx, tx, ev.requestIDValue, ev.orgIDValue, ev.g2.taskIDStr, ev.modelUsed, ev.upstreamResponse, nil)
}

// enrichPolicyDecisionIfAbsent commits the policy decision with the
// enrichment only when no decision row exists for the request yet. The
// org GUC is pinned first because policy_decisions carries the org
// isolation RLS posture and a bare probe would read zero rows.
func (c *StreamConsumer) enrichPolicyDecisionIfAbsent(ctx context.Context, tx InboxTx, ev requestEvent) error {
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_org', $1, true)", ev.orgID); err != nil {
		return fmt.Errorf("pin policy decision org GUC: %w", err)
	}
	var one int
	if err := tx.QueryRow(ctx,
		`SELECT 1 FROM policy_decisions WHERE org_id = $1 AND request_id = $2 LIMIT 1`,
		ev.orgID, ev.requestID,
	).Scan(&one); err == nil {
		return nil
	}
	return c.insertPolicyDecision(ctx, tx, ev)
}

// resaleDeductionMicro resolves the exact charge amount for a completed
// request, mirroring the legacy selection contract with exact units: a
// positive resale_cost_usd wins (org-facing price); otherwise a positive
// estimated_cost_usd is the fallback (a zero/absent resale quote means "no
// resale price", exactly as the pre-AF-05 path treated it — billing is not
// silently changed). When no positive quote exists, any present valid zero
// quote makes this a genuine zero-cost event; only when every quote is
// unknown/absent is the outcome QuoteUnknown — a distinct state, never
// billed, never reported as a genuine zero.
func resaleDeductionMicro(cost, resale money.MicroUSD, costState, resaleState money.QuoteState) (money.MicroUSD, money.QuoteState) {
	if resaleState == money.QuotePositive {
		return resale, money.QuotePositive
	}
	if costState == money.QuotePositive {
		return cost, money.QuotePositive
	}
	if resaleState == money.QuoteZero || costState == money.QuoteZero {
		return 0, money.QuoteZero
	}
	return 0, money.QuoteUnknown
}

// insertScopeIntent persists the durable work item for one scope charge
// inside the delivery transaction (AF-04; executed by the AF-06 settlement
// worker, NEXT-18d batch). The gates mirror the legacy per-kind call sites:
//   - wallet (resale_deduction): requires a configured credit store and a
//     positive charge — the intent exists exactly when a charge would be
//     attempted today; exact micro-USD amount (AF-05), sub-cent prices keep
//     their intent instead of rounding to zero.
//   - team_month / agent_day / session: every attributed request is counted
//
// A reserve link (NEXT-18d) additionally lands in the payload and the
// settlement_jobs.allowance_id column for the settle-time reserve decrement.
// A failure fails the whole delivery transaction: committing the request log
// without the mandatory charge intent is exactly the silent-loss bug AF-04
// fixes.
//
// Conflicting re-delivery (same identity, different amount): the first
// amount stays authoritative, the second is never charged — the conflict is
// reported (warn log + metric) instead of silently ignored.
// scopeIntentEligible reports whether this scope's intent exists at all:
// the wallet charge exists exactly when a deduction would be attempted
// today (positive charge, identified request, credit store configured);
// agent spend needs a configured spender and its key; every other scope
// needs its key. An unknown kind warns and skips — never a silent drop.
func (c *StreamConsumer) scopeIntentEligible(sc scopeCharge, orgID, requestID string) bool {
	if orgID == "" {
		return false
	}
	switch sc.kind {
	case ChargeKindResaleDeduction:
		return c.creditStore != nil && sc.amount > 0 && requestID != ""
	case ChargeKindTeamSpend:
		return sc.key != ""
	case ChargeKindAgentSpend:
		return c.agentSpender != nil && sc.key != ""
	case ChargeKindSessionSpend:
		return sc.key != ""
	default:
		c.logger.Warn("unknown scope charge kind — intent skipped",
			slog.String("charge_kind", sc.kind),
			slog.String("request_id", requestID),
		)
		return false
	}
}

// scopeIntentPayload renders the settlement payload of one scope charge:
// the wallet scope carries the full pricing facts, agent spend the token
// counts, the period scopes their identity; a reserve link additionally
// lands in the payload for the settle-time decrement. A marshal failure
// degrades to an empty object — the intent row is still mandatory.
func scopeIntentPayload(sc scopeCharge, tokensIn, tokensOut int64, costUSD, resaleUSD float64, modelUsed string) []byte {
	payload := map[string]any{}
	switch sc.kind {
	case ChargeKindResaleDeduction:
		payload["model"] = modelUsed
		payload["tokens_in"] = tokensIn
		payload["tokens_out"] = tokensOut
		payload["cost_usd"] = costUSD
		payload["resale_usd"] = resaleUSD
	case ChargeKindAgentSpend:
		payload["agent_id"] = sc.key
		payload["tokens_in"] = tokensIn
		payload["tokens_out"] = tokensOut
	case ChargeKindTeamSpend:
		payload["team_id"] = sc.key
		payload["period"] = sc.period
	case ChargeKindSessionSpend:
		payload["session_key_id"] = sc.key
	}
	if sc.link.AllowanceID > 0 {
		payload["allowance_id"] = sc.link.AllowanceID
		payload["bound_micro_usd"] = sc.link.BoundMicroUSD
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return []byte("{}")
	}
	return payloadBytes
}

func (c *StreamConsumer) insertScopeIntent(ctx context.Context, tx InboxTx, orgID, requestID string, invocation any, sc scopeCharge, tokensIn, tokensOut int64, costUSD, resaleUSD float64, modelUsed string) error {
	if !c.scopeIntentEligible(sc, orgID, requestID) {
		return nil
	}
	payloadBytes := scopeIntentPayload(sc, tokensIn, tokensOut, costUSD, resaleUSD, modelUsed)

	// The invocation-domain statements carry invocation_id in their column
	// list and are schema-self-evidencing (invalid before 0028 — a loud
	// failure, never a silent downgrade). Only legacy-domain rows need the
	// probe: their arbiter differs between the pre-0028 bytes and the
	// partial index of 0028+.
	var plainStmt, withAllowanceStmt string
	if invocation == nil {
		hasColumn, perr := c.settlementInvocationSchemaTx(ctx, tx)
		if perr != nil {
			return fmt.Errorf("probe settlement schema for legacy intent: %w", perr)
		}
		plainStmt, withAllowanceStmt = settlementIntentStatements(hasColumn, nil)
	} else {
		plainStmt, withAllowanceStmt = settlementIntentStatements(false, invocation)
	}

	// Both statement families bind the same prefix (identity columns, then
	// kind and the two amount renderings, then the payload); the allowance
	// variant appends its link.
	args := []any{orgID, requestID}
	if invocation != nil {
		args = append(args, invocation)
	}
	args = append(args, sc.kind, sc.amount.Cents(), int64(sc.amount), payloadBytes)
	stmt := plainStmt
	if sc.link.AllowanceID > 0 {
		stmt = withAllowanceStmt
		args = append(args, sc.link.AllowanceID)
	}

	tag, err := tx.Exec(ctx, stmt, args...)
	if err != nil {
		return fmt.Errorf("insert %s settlement intent: %w", sc.kind, err)
	}
	if tag.RowsAffected() == 0 {
		c.diagnoseIntentAmountConflict(ctx, tx, orgID, requestID, invocation, sc.kind, sc.amount)
	}
	return nil
}

// pendingPricePayload snapshots the reservations whose bound cost stayed
// unknown — the durable visibility the reconciler's pending deadline
// expires to terminal 'unknown' (24h default, owner decision 2026-10-18).
func pendingPricePayload(ev requestEvent) []byte {
	reserved := make([]map[string]any, 0, len(ev.reservations))
	for _, t := range ev.reservations {
		reserved = append(reserved, map[string]any{
			"scope_kind":      t.ScopeKind,
			"bound_micro_usd": t.BoundMicroUSD,
		})
	}
	payload, err := json.Marshal(map[string]any{
		"termination":  string(ev.termination),
		"reservations": reserved,
	})
	if err != nil {
		return []byte("{}")
	}
	return payload
}

// insertPendingPriceIntent records one pending_price settlement row inside
// the delivery transaction: one per (org, request) when the event's cost
// stayed unknown while usage existed and a reserve was held. The row
// carries no amount and no charge semantics — the settlement worker never
// claims it (the claim query takes only pending/retry); the worker's
// expiry pass terminates it as 'unknown' after the pending deadline.
// Skipping conditions mirror reportUnchargedUnknown: no usage (nothing
// unknown) or no reserve (nothing at stake) means no record.
func (c *StreamConsumer) insertPendingPriceIntent(ctx context.Context, tx InboxTx, ev requestEvent, chargeState money.QuoteState) error {
	if chargeState != money.QuoteUnknown || ev.acct.usageSource == "none" || len(ev.reservations) == 0 {
		return nil
	}
	if ev.orgID == "" || ev.requestID == "" {
		return nil
	}
	payload := pendingPricePayload(ev)
	stmt := pendingPriceIntentStatement(true, ev.invocationIDValue)
	args := []any{ev.orgID, ev.requestID}
	if ev.invocationIDValue == nil {
		hasColumn, perr := c.settlementInvocationSchemaTx(ctx, tx)
		if perr != nil {
			return fmt.Errorf("probe settlement schema for pending_price intent: %w", perr)
		}
		stmt = pendingPriceIntentStatement(hasColumn, nil)
	} else {
		args = append(args, ev.invocationIDValue)
	}
	args = append(args, ChargeKindPendingPrice, payload)
	if _, err := tx.Exec(ctx, stmt, args...); err != nil {
		return fmt.Errorf("insert pending_price settlement record: %w", err)
	}
	return nil
}

// settlementExistingAmountQuery reads the amount of an already-known
// settlement identity for the conflict diagnostic. The invocation-domain
// variant matches on the minted identity; the plain variant serves both
// legacy domains (a plain SELECT needs no index inference).
const settlementExistingAmountQuery = `SELECT amount_micro_usd FROM settlement_jobs
	WHERE org_id = $1 AND request_id = $2 AND charge_kind = $3`
const settlementExistingAmountInvocationQuery = `SELECT amount_micro_usd FROM settlement_jobs
	WHERE org_id = $1 AND invocation_id = $2 AND charge_kind = $3`

// diagnoseIntentAmountConflict reports a duplicate settlement identity whose
// event carries a different amount than the already-known job. The known
// job stays authoritative and only it will settle; the conflict is a
// diagnostic (warn + metric), never a second charge.
func (c *StreamConsumer) diagnoseIntentAmountConflict(ctx context.Context, tx InboxTx, orgID, requestID string, invocation any, chargeKind string, amountMicro money.MicroUSD) {
	var existing int64
	var err error
	if invocation != nil {
		err = tx.QueryRow(ctx, settlementExistingAmountInvocationQuery, orgID, invocation, chargeKind).Scan(&existing)
	} else {
		err = tx.QueryRow(ctx, settlementExistingAmountQuery, orgID, requestID, chargeKind).Scan(&existing)
	}
	if err != nil {
		// The duplicate row exists (the claim insert said so); a read
		// failure must not fail the delivery — log and move on.
		c.logger.Warn("settlement duplicate identity: amount lookup failed",
			slog.String("org_id", orgID),
			slog.String("request_id", requestID),
			slog.String("charge_kind", chargeKind),
			slog.String("error", err.Error()),
		)
		return
	}
	if int64(amountMicro) == existing {
		return // identical re-delivery of the same charge — nothing to report
	}
	metrics.SettlementIntentConflicts.WithLabelValues(chargeKind).Inc()
	c.logger.Warn("settlement identity conflict: event amount differs from the known job (first amount stays authoritative, no second charge)",
		slog.String("org_id", orgID),
		slog.String("request_id", requestID),
		slog.String("charge_kind", chargeKind),
		slog.Int64("known_amount_micro_usd", existing),
		slog.Int64("event_amount_micro_usd", int64(amountMicro)),
	)
}

func (c *StreamConsumer) reclaimPEL(ctx context.Context) {
	every := c.reclaimEvery
	if every <= 0 {
		every = pelReclaimTimeout
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.reclaimStaleMessages(ctx)
		}
	}
}

func (c *StreamConsumer) reclaimStaleMessages(ctx context.Context) {
	idle := c.reclaimIdle
	if idle <= 0 {
		idle = pelReclaimTimeout
	}
	pendingCmd := c.rdb.XPendingExt(ctx, &redis.XPendingExtArgs{
		Stream: c.streamName,
		Group:  consumerGroup,
		Start:  "-",
		End:    "+",
		Count:  100,
	})
	pending, err := pendingCmd.Result()
	if err != nil {
		c.logger.Error("XPENDING_EXT failed during PEL reclaim",
			slog.String("error", err.Error()),
		)
		return
	}

	if len(pending) == 0 {
		return
	}

	var idsToReclaim []string
	for _, p := range pending {
		if p.Idle >= idle {
			idsToReclaim = append(idsToReclaim, p.ID)
		}
	}

	if len(idsToReclaim) == 0 {
		return
	}

	for _, id := range idsToReclaim {
		streamCmd := c.rdb.XClaim(ctx, &redis.XClaimArgs{
			Stream:   c.streamName,
			Group:    consumerGroup,
			Consumer: "reclaimer",
			Messages: []string{id},
			MinIdle:  idle,
		})
		streamSlice, err := streamCmd.Result()
		if err != nil {
			c.logger.Error("XCLAIM failed for message",
				slog.String("stream_id", id),
				slog.String("error", err.Error()),
			)
			continue
		}

		for _, msg := range streamSlice {
			// The same delivery contract as the main loop: gauge balanced
			// via defer, DB outage pauses instead of DLQ (the message is
			// left pending for the next reclaim pass).
			metrics.EventsInFlight.Inc()
			c.handleMessage(ctx, msg)
		}
	}
}

// Stop cancels the consumer's group context and waits for shutdown.
// Stop.
func (c *StreamConsumer) Stop() {
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
