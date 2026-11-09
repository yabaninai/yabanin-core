package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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
	settlementIntentQuery = `INSERT INTO settlement_jobs
		 (org_id, request_id, charge_kind, amount_cents, amount_micro_usd, status, payload)
		 VALUES ($1, $2, $3, $4, $5, 'pending', $6)
		 ON CONFLICT (org_id, request_id, charge_kind) DO NOTHING`
	// The reservation-linked variant (NEXT-18d, ADR-0001 §13) additionally
	// records the allocation whose reserve the settle decrements. Only
	// intent inserts carrying a reserve tuple use it, so a pre-reservation
	// schema (no allowance_id column) never sees this statement.
	settlementIntentWithAllowanceQuery = `INSERT INTO settlement_jobs
		 (org_id, request_id, charge_kind, amount_cents, amount_micro_usd, status, payload, allowance_id)
		 VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)
		 ON CONFLICT (org_id, request_id, charge_kind) DO NOTHING`
	// a settlement_jobs row in the non-claimable 'pending_price' state,
	// written in the SAME delivery transaction as the request log. It is
	// never billed (the claim query only takes pending/retry) and never a
	// confirmed zero; the worker's expiry pass terminates it as 'unknown'
	// after PendingPriceExpiry (24h default).
	pendingPriceIntentQuery = `INSERT INTO settlement_jobs
		 (org_id, request_id, charge_kind, amount_cents, amount_micro_usd, status, payload)
		 VALUES ($1, $2, $3, 0, 0, 'pending_price', $4)
		 ON CONFLICT (org_id, request_id, charge_kind) DO NOTHING`
)

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

	sessionIDStr := c.resolveSessionID(ctx, tx, ev.orgID, ev.sessionID)
	row := budgetRequestLogRow(ev, sessionIDStr, errorMsg)
	row.setAttribution(c.attributionID(fields, "api_key_id"), c.attributionID(fields, "session_key_id"))

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
	partialUsageKnown := ev.acct.usageSource != "none" && chargeState == money.QuotePositive
	absorbedUpstream := ev.termination == TerminationUpstreamErr && ev.acct.usageSource != "none"
	var plan []scopeCharge
	switch {
	case absorbedUpstream:
		for _, sc := range scopeChargePlan(ev, chargeMicro, chargeState) {
			metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues(sc.scope).Add(float64(sc.amount))
		}
	case partialUsageKnown:
		if mode, modeErr := c.reservationsMode(ctx, ev.orgID); modeErr == nil {
			switch mode {
			case modeEnforce:
				plan = scopeChargePlan(ev, chargeMicro, chargeState)
			case modeShadow:
				for _, sc := range scopeChargePlan(ev, chargeMicro, chargeState) {
					metrics.WouldBillPartialMicroUSD.WithLabelValues(sc.scope).Add(float64(sc.amount))
				}
			default: // off — legacy: failed requests are never billed
			}
		}
	}
	// A priced-and-absorbed upstream failure is not an unknown cost — its
	// bound belongs to the absorbed metric, not to uncharged_unknown.

	tx, claimed, err := c.beginDelivery(ctx, msg.ID)
	if err != nil || !claimed {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful commit

	// request.failed keeps the raw error text and the raw status code: a
	// failed event with status 0 stores 0, and an absent error stores '' —
	// the failed-shape contract, unchanged.
	sessionIDStr := c.resolveSessionID(ctx, tx, ev.orgID, ev.sessionID)
	row := fullRequestLogRow(ev, sessionIDStr, ev.errorMsg, ev.statusCode)
	row.setAttribution(c.attributionID(fields, "api_key_id"), c.attributionID(fields, "session_key_id"))

	if _, err := tx.Exec(ctx, row.insertSQL(), row.args()...); err != nil {
		return fmt.Errorf("insert request_log for failed event: %w", err)
	}

	// OP-9: the policy decision (when the event carries one) commits with
	// the log — a policy_denied failure keeps its verdict trail.
	if err := c.insertPolicyDecision(ctx, tx, ev); err != nil {
		return err
	}

	// Partial-usage intents (enforce only) commit with the log — a request
	// whose provider cost was already incurred bills exactly once.
	for _, sc := range plan {
		if err := c.insertScopeIntent(ctx, tx, ev.orgID, ev.requestID, sc, ev.tokensIn, ev.tokensOut, ev.costInUSD, ev.resaleCostUSD, ev.modelUsed); err != nil {
			return err
		}
	}

	// pending_price record in the same transaction — never billed, expires
	// to terminal 'unknown' after the pending deadline.
	if err := c.insertPendingPriceIntent(ctx, tx, ev, chargeState); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit delivery transaction: %w", err)
	}

	// After the commit succeeded: exactly one uncharged-unknown increment
	// per committed delivery (N06-P04-T08). Counting before the claim let
	// a redelivery of the same entry id re-inflate the signal on every
	// retry; counting after the claim but before the commit would survive
	// a rollback the same way. The residual window — a crash between the
	// commit and the increment — is at-most-once for the signal alone: no
	// money is affected, and the bound stays durably visible through the
	// pending_price record committed in the same transaction, so the
	// reconciler's pending deadline still surfaces it as terminal unknown.
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

	sessionIDStr := c.resolveSessionID(ctx, tx, ev.orgID, ev.sessionID)
	row := shadowRequestLogRow(ev, sessionIDStr, statusCode)
	row.setAttribution(c.attributionID(fields, "api_key_id"), c.attributionID(fields, "session_key_id"))

	if _, err := tx.Exec(ctx, row.insertSQL(), row.args()...); err != nil {
		return fmt.Errorf("insert shadow request_log: %w", err)
	}

	// OP-9: shadow decisions are the whole point of shadow mode ("what would
	// the policy have done") — commit with the mirror row.
	if err := c.insertPolicyDecision(ctx, tx, ev); err != nil {
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
	// request log (AF-04). Since AF-05 the amounts are exact micro-USD
	// validated at the event boundary; unknown price/usage stays a distinct
	// state (never billed, never reported as zero). The AF-06 settlement
	// worker executes these intents (lease/retry/idempotency); nothing is
	// charged directly on the delivery path anymore.
	chargeMicro, chargeState := resaleDeductionMicro(ev.costQuote, ev.resaleQuote, ev.costQuoteState, ev.resaleQuoteState)
	if chargeState == money.QuoteUnknown {
		c.logger.Warn("request completed with unknown price — no charge intent; pending_price record keeps the cost visible",
			slog.String("request_id", ev.requestID),
			slog.String("org_id", ev.orgID),
			slog.String("resale_quote", ev.resaleQuoteState.String()),
			slog.String("cost_quote", ev.costQuoteState.String()),
		)
	}

	// Per-scope charge plan (NEXT-18d): reservation tuples are the
	// authoritative areas when present, legacy attributions otherwise.
	plan := scopeChargePlan(ev, chargeMicro, chargeState)
	// Unknown usage with a reserve: the bound is never billed and never
	// reported as zero; reconcile releases it (ADR-0001 §6). The
	// uncharged-unknown signal itself counts only after the commit below.

	tx, claimed, err := c.beginDelivery(ctx, msg.ID)
	if err != nil || !claimed {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful commit

	sessionIDStr := c.resolveSessionID(ctx, tx, ev.orgID, ev.sessionID)
	row := fullRequestLogRow(ev, sessionIDStr, ev.errorOptional(), statusCode)
	row.setAttribution(c.attributionID(fields, "api_key_id"), c.attributionID(fields, "session_key_id"))
	result, err := tx.Exec(ctx, row.insertSQL(), row.args()...)
	if err != nil {
		return fmt.Errorf("insert request_log: %w", err)
	}

	// Tool-call aggregate (fail-soft like the budget roll below): the calls
	// the model requested are extracted from the raw sample (pre-truncation)
	// so the analytics table stays queryable; a failure never breaks the log.
	c.insertToolCalls(ctx, tx, ev.requestIDValue, ev.orgIDValue, ev.g2.taskIDStr, ev.modelUsed, ev.upstreamResponse)

	// OP-9: the policy decision log row (when the event carries one)
	// commits in this same delivery transaction.
	if err := c.insertPolicyDecision(ctx, tx, ev); err != nil {
		return err
	}

	// Durable intents for every scope the request touched (AF-04/NEXT-18d) —
	// wallet, team_month, agent_day and session. Each intent commits with
	// the log or the whole delivery fails and is retried.
	for _, sc := range plan {
		if err := c.insertScopeIntent(ctx, tx, ev.orgID, ev.requestID, sc, ev.tokensIn, ev.tokensOut, ev.costInUSD, ev.resaleCostUSD, ev.modelUsed); err != nil {
			return err
		}
	}

	// pending_price record in the same transaction — never billed, expires
	// to terminal 'unknown' after the pending deadline.
	if err := c.insertPendingPriceIntent(ctx, tx, ev, chargeState); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit delivery transaction: %w", err)
	}

	// After the commit succeeded: exactly one uncharged-unknown increment
	// per committed delivery (N06-P04-T08). Counting before the claim let
	// a redelivery of the same entry id re-inflate the signal on every
	// retry; counting after the claim but before the commit would survive
	// a rollback the same way. The residual window — a crash between the
	// commit and the increment — is at-most-once for the signal alone: no
	// money is affected, and the bound stays durably visible through the
	// pending_price record committed in the same transaction, so the
	// reconciler's pending deadline still surfaces it as terminal unknown.
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
func (c *StreamConsumer) insertScopeIntent(ctx context.Context, tx InboxTx, orgID, requestID string, sc scopeCharge, tokensIn, tokensOut int64, costUSD, resaleUSD float64, modelUsed string) error {
	if orgID == "" {
		return nil
	}
	switch sc.kind {
	case ChargeKindResaleDeduction:
		// Legacy gate: the wallet charge exists exactly when a deduction
		// would be attempted today (positive charge, identified request).
		if c.creditStore == nil || sc.amount <= 0 || requestID == "" {
			return nil
		}
	case ChargeKindTeamSpend:
		if sc.key == "" {
			return nil
		}
	case ChargeKindAgentSpend:
		if c.agentSpender == nil || sc.key == "" {
			return nil
		}
	case ChargeKindSessionSpend:
		if sc.key == "" {
			return nil
		}
	default:
		c.logger.Warn("unknown scope charge kind — intent skipped",
			slog.String("charge_kind", sc.kind),
			slog.String("request_id", requestID),
		)
		return nil
	}

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
		payloadBytes = []byte("{}")
	}

	var tag pgconn.CommandTag
	if sc.link.AllowanceID > 0 {
		tag, err = tx.Exec(ctx, settlementIntentWithAllowanceQuery,
			orgID, requestID, sc.kind, sc.amount.Cents(), int64(sc.amount), payloadBytes, sc.link.AllowanceID)
	} else {
		tag, err = tx.Exec(ctx, settlementIntentQuery,
			orgID, requestID, sc.kind, sc.amount.Cents(), int64(sc.amount), payloadBytes)
	}
	if err != nil {
		return fmt.Errorf("insert %s settlement intent: %w", sc.kind, err)
	}
	if tag.RowsAffected() == 0 {
		c.diagnoseIntentAmountConflict(ctx, tx, orgID, requestID, sc.kind, sc.amount)
	}
	return nil
}

// record inside the delivery transaction: one pending_price settlement row
// per (org, request) when the event's cost stayed unknown while usage
// existed and a reserve was held. The row carries no amount and no charge
// semantics — the settlement worker never claims it (the claim query takes
// only pending/retry); the worker's expiry pass terminates it as 'unknown'
// after the pending deadline (24h default, owner decision 2026-10-18).
// Skipping conditions mirror reportUnchargedUnknown: no usage (nothing
// unknown) or no reserve (nothing at stake) means no record.
func (c *StreamConsumer) insertPendingPriceIntent(ctx context.Context, tx InboxTx, ev requestEvent, chargeState money.QuoteState) error {
	if chargeState != money.QuoteUnknown || ev.acct.usageSource == "none" || len(ev.reservations) == 0 {
		return nil
	}
	if ev.orgID == "" || ev.requestID == "" {
		return nil
	}
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
		payload = []byte("{}")
	}
	if _, err := tx.Exec(ctx, pendingPriceIntentQuery, ev.orgID, ev.requestID, ChargeKindPendingPrice, payload); err != nil {
		return fmt.Errorf("insert pending_price settlement record: %w", err)
	}
	return nil
}

// settlementExistingAmountQuery reads the amount of an already-known
// settlement identity for the conflict diagnostic.
const settlementExistingAmountQuery = `SELECT amount_micro_usd FROM settlement_jobs
	WHERE org_id = $1 AND request_id = $2 AND charge_kind = $3`

// diagnoseIntentAmountConflict reports a duplicate settlement identity whose
// event carries a different amount than the already-known job. The known
// job stays authoritative and only it will settle; the conflict is a
// diagnostic (warn + metric), never a second charge.
func (c *StreamConsumer) diagnoseIntentAmountConflict(ctx context.Context, tx InboxTx, orgID, requestID, chargeKind string, amountMicro money.MicroUSD) {
	var existing int64
	err := tx.QueryRow(ctx, settlementExistingAmountQuery, orgID, requestID, chargeKind).Scan(&existing)
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
