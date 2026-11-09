package run

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/credits"
	gateway "github.com/reireirei/yabanin/pkg/gateway"
	"github.com/reireirei/yabanin/pkg/logging"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/regionrepl"
	"github.com/reireirei/yabanin/pkg/regionrouter"
	"github.com/reireirei/yabanin/pkg/tracing"
	"github.com/reireirei/yabanin/services/loggerd"
	"github.com/reireirei/yabanin/services/loggerd/consumer"
)

// Loggerd starts the loggerd Redis-stream consumer and its health/metrics
// HTTP server, blocking until SIGINT/SIGTERM or parentCtx cancellation.
// Postgres is REQUIRED for loggerd (request logging is its whole job): missing
// or unreachable PG returns an error rather than degraded start.
func Loggerd(parentCtx context.Context) error {
	// Kubernetes deployments configure via env only; fall back to defaults
	// when no config file exists and none was requested explicitly.
	cfgFile := config.PathFromEnv()
	if cfgFile == "" {
		if _, statErr := os.Stat("config.yaml"); statErr == nil {
			cfgFile = "config.yaml"
		}
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		logging.New(cfg.Loggerd.LogLevel, cfg.Loggerd.LogFormat).Error("failed to load config", "error", err)
		return err
	}

	if err := cfg.Loggerd.Validate(); err != nil {
		logging.New(cfg.Loggerd.LogLevel, cfg.Loggerd.LogFormat).Error("invalid loggerd config", "error", err)
		return err
	}

	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	// Initialize tracing if an OTEL endpoint is configured.
	if cfg.Loggerd.TracingEnabled() {
		if err := tracing.Init(ctx, "loggerd", cfg.Loggerd.OTELTracingEndpoint, cfg.Loggerd.OTELTracingSample); err != nil {
			logging.New(cfg.Loggerd.LogLevel, cfg.Loggerd.LogFormat).Warn("tracing init failed, continuing without tracing", "error", err)
		}
		//nolint:contextcheck // closure runs after ctx is cancelled at shutdown; deriving from the cancelled parent would abort the flush immediately
		defer func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			_ = tracing.Shutdown(shutdownCtx)
		}()
	}

	logger := logging.New(cfg.Loggerd.LogLevel, cfg.Loggerd.LogFormat).With(slog.String("service", "loggerd"))

	// Disabled entirely unless YABANIN_OTEL_LOGS_ENDPOINT is set — no
	// exporter, no goroutines, consumer path bit-for-bit unchanged.
	otelSink, otelEnabled, otelErr := newOTelLogSinkFromEnv(ctx, logger)
	if otelErr != nil {
		logger.Warn("otel logs exporter disabled (configuration error)", "error", otelErr)
	} else if otelEnabled {
		//nolint:contextcheck // the sink's lifecycle is independent of the runtime ctx (flush happens after cancellation; the deferred Shutdown carries its own timeout)
		defer func() {
			flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer flushCancel()
			if err := otelSink.Shutdown(flushCtx); err != nil {
				logger.Warn("otel logs flush on shutdown failed", "error", err)
			}
		}()
	}

	var dbPool *pgxpool.Pool
	if cfg.Loggerd.PGURI != "" {
		// pgxpool.ParseConfig (not pgx.ParseConfig + manual wrap) so the pool
		// config carries the createdByParseConfig flag that
		// pgxpool.NewWithConfig requires in pgx v5.10.
		pc, parseErr := pgxpool.ParseConfig(cfg.Loggerd.PGURI)
		if parseErr != nil {
			logging.New(cfg.Loggerd.LogLevel, cfg.Loggerd.LogFormat).Error("failed to parse pg_uri", "error", parseErr)
			return parseErr
		}
		if cfg.Gateway.Region != "" {
			if err := regionrouter.ConfigurePool(pc, cfg.Gateway.Region); err != nil {
				logging.New(cfg.Loggerd.LogLevel, cfg.Loggerd.LogFormat).Error("failed to configure RLS region hook", "error", err)
				return err
			}
			logger.Info("RLS region context configured", "region", cfg.Gateway.Region)
		}
		dbPool, err = pgxpool.NewWithConfig(ctx, pc)
		if err != nil {
			logging.New(cfg.Loggerd.LogLevel, cfg.Loggerd.LogFormat).Error("failed to connect to postgres", "error", err)
			return err
		}
		if err := dbPool.Ping(ctx); err != nil {
			logging.New(cfg.Loggerd.LogLevel, cfg.Loggerd.LogFormat).Error("failed to ping postgres, DB is required for request logging — aborting", "error", err)
			dbPool.Close()
			return err
		}
		defer dbPool.Close()
	} else {
		logging.New(cfg.Loggerd.LogLevel, cfg.Loggerd.LogFormat).Error("DB is required but PG_URI is not configured — aborting")
		return errors.New("loggerd: PG_URI is required")
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:         cfg.Loggerd.RedisAddr,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		DialTimeout:  3 * time.Second,
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		logging.New(cfg.Loggerd.LogLevel, cfg.Loggerd.LogFormat).Error("failed to connect to redis", "error", err)
		return err
	}

	streamName := cfg.Loggerd.StreamName

	// PR1: Wire credits store if DB is available (for reseller billing).
	var creditStore *credits.Store
	if dbPool != nil {
		storeCfg := credits.DefaultConfig()
		storeCfg.GracePeriodCents = cfg.Gateway.CreditsGraceCents
		if ttl, err := time.ParseDuration(cfg.Gateway.CreditsCacheTTL); err == nil && ttl > 0 {
			storeCfg.CacheTTL = ttl
		}
		creditStore = credits.NewStoreWithConfig(dbPool, logger.With("component", "loggerd-credits"), storeCfg)
		logger.Info("loggerd credit store initialized", "grace_cents", storeCfg.GracePeriodCents)
	}

	consumerInstance := consumer.NewWithCreditStore(consumer.NewRedisOps(rdb), consumer.NewDBOps(dbPool), streamName, logger.With("component", "consumer"), creditStore)

	// N02-P06 T03: the org original-text retention source. The consumer
	// resolves the effective toggle once per message at its delivery
	// boundary and persists processed text only unless the org explicitly
	// opted in; lookup failures fail closed to processed-only. A nil DB
	// pool keeps the fail-closed default (no store, no retention).
	if dbPool != nil {
		consumerInstance.SetOriginalRetentionStore(consumer.AdminOriginalRetentionStore{
			Store: adminstore.New(dbPool, logger.With("component", "adminstore"), nil),
		})
		logger.Info("original retention source initialized", "default_processed_only", true)
	}

	// endpoint is configured (disabled = feature off, zero overhead).
	if otelEnabled {
		consumerInstance.SetOTelSink(otelSink)
	}

	// G2 debt fix: wire per-agent spend recording so agent budgets see usage.
	// AF-06: the same enforcer executes the settlement worker's exact
	// micro-USD agent-spend side effect (transactional with the job).
	var agentBudgets *budget.AgentEnforcer
	if dbPool != nil {
		agentBudgets = budget.NewAgentEnforcer(dbPool, logger.With("component", "agent-budget"))
		consumerInstance.SetAgentSpender(agentBudgets)
	}

	// a watermark-gated, at-least-once JSONL dump of closed-period
	// request_logs rows. Enabled by YABANIN_LOG_EXPORT_S3_BUCKET; the
	// exporter is a separate goroutine on its own ticker and never touches
	// the consumer hot path.
	var logExporter *loggerd.LogExporter
	if expCfg := loggerd.LogExportConfigFromEnv(os.Getenv); expCfg.Enabled() {
		if expCfg.Schedule != "" && expCfg.Schedule != loggerd.ScheduleHourly && expCfg.Schedule != loggerd.ScheduleDaily {
			logger.Warn("invalid log export schedule, using hourly", "value", expCfg.Schedule)
		}
		uploader, upErr := loggerd.NewS3Uploader(ctx, expCfg)
		if upErr != nil {
			logging.New(cfg.Loggerd.LogLevel, cfg.Loggerd.LogFormat).Error("failed to init log export S3 uploader", "error", upErr)
			return upErr
		}
		logExporter = loggerd.NewLogExporter(dbPool, uploader, expCfg, logger.With("component", "log-export"))
		logger.Info("log export enabled",
			"bucket", expCfg.Bucket, "prefix", expCfg.Prefix,
			"schedule", logExporter.Schedule(), "redact", expCfg.Redact, "endpoint", expCfg.Endpoint)
	}

	// AF-06: the durable settlement worker executes settlement_jobs intents
	// (resale wallet deduction, exact agent budget spend) with lease/retry/
	// idempotency. It coordinates with other replicas via SKIP LOCKED, so it
	// runs wherever the consumer runs (leader-elected when enabled).
	var settlementWorker *consumer.SettlementWorker
	if dbPool != nil {
		settlementWorker = consumer.NewSettlementWorker(dbPool, creditStore, agentBudgets, logger.With("component", "settlement"))
	}

	// NEXT-18e (ADR-0001 §7.1): the reservation reconcile worker — bounded
	// ticker releasing lapsed escrow (expired past the safety window,
	// draining/expired zero-remainder), checking the §7.1.3/§7.1.4 money
	// invariants and running the §7.1.5 released-allowance retention. It
	// runs wherever the settlement worker runs (§5.4: when loggerd stalls,
	// reconcile conservatively releases nothing), leader-elected when
	// enabled.
	reconciler := budget.NewReconcileWorker(dbPool, logger.With("component", "budget-reconcile"), budget.DefaultReconcileConfig())

	// ENT-04 (HA multi-replica): when leader election is on, N loggerd
	// replicas elect a single active node and only the leader's Start runs;
	// losing the lock cancels the consumer and another replica takes over.
	if cfg.Loggerd.LeaderElection {
		ttl := 30 * time.Second
		if cfg.Loggerd.LeaderLockTTL != "" {
			if parsed, err := time.ParseDuration(cfg.Loggerd.LeaderLockTTL); err == nil && parsed > 0 {
				ttl = parsed
			} else {
				logger.Warn("invalid leader_lock_ttl, using 30s default", "value", cfg.Loggerd.LeaderLockTTL)
			}
		}
		leader := consumer.NewLeader(consumer.NewLeaderRedis(rdb), streamName+":loggerd-leader", "", ttl, logger.With("component", "leader"))
		go func() {
			if err := leader.Lead(ctx, func(leadCtx context.Context) error {
				logger.Info("leader: starting stream consumer under elected leadership")
				if settlementWorker != nil {
					go func() {
						if runErr := settlementWorker.Run(leadCtx); runErr != nil {
							logger.Error("settlement worker failed", "error", runErr)
						}
					}()
				}
				go func() {
					if runErr := reconciler.Run(leadCtx); runErr != nil {
						logger.Error("budget reconcile worker failed", "error", runErr)
					}
				}()
				if logExporter != nil {
					go func() {
						if runErr := logExporter.Run(leadCtx); runErr != nil {
							logger.Error("log export worker failed", "error", runErr)
						}
					}()
				}
				return consumerInstance.Start(leadCtx)
			}); err != nil {
				logger.Error("leader loop failed", "error", err)
			}
		}()
		startRollups(ctx, dbPool, logger, leader.IsHeld)
	} else {
		go func() {
			logger.Info("starting stream consumer", "stream", streamName)
			if err := consumerInstance.Start(ctx); err != nil {
				logger.Error("consumer failed", "error", err)
			}
		}()
		if settlementWorker != nil {
			go func() {
				logger.Info("starting settlement worker")
				if err := settlementWorker.Run(ctx); err != nil {
					logger.Error("settlement worker failed", "error", err)
				}
			}()
		}
		go func() {
			logger.Info("starting budget reservation reconcile worker")
			if err := reconciler.Run(ctx); err != nil {
				logger.Error("budget reconcile worker failed", "error", err)
			}
		}()
		if logExporter != nil {
			go func() {
				logger.Info("starting S3 log export worker",
					"bucket", logExporter.Bucket(), "schedule", logExporter.Schedule())
				if err := logExporter.Run(ctx); err != nil {
					logger.Error("log export worker failed", "error", err)
				}
			}()
		}
		startRollups(ctx, dbPool, logger, nil)
	}

	// PH.2: purge_expired_records — hourly background job that deletes old
	// request_logs (and, OP-9, the 90d policy decision log). W-LOGG: the
	// loop selects on ctx.Done() (the old ticker range kept the goroutine —
	// and its DB handle — alive forever after shutdown) and deletes in
	// bounded batches so one oversized backlog cannot hold a long
	// transaction and its bloat window for hours.
	if days, ok := config.LogRetentionDays(); ok {
		go func() {
			logger.Info("purge_expired_records started", "retention_days", days)
			ticker := time.NewTicker(1 * time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					deleted, err := purgeExpiredRequestLogs(ctx, dbPool, purgeBatchSize, days)
					if err != nil {
						logger.Warn("purge_expired_records failed", "error", err, "retention_days", days, "rows_deleted", deleted)
						continue
					}
					logger.Info("purge_expired_records completed", "rows_deleted", deleted, "retention_days", days)

					// OP-9: the decision log keeps its own fixed window
					// (owner decision, 90d) — it is purged on the same
					// hourly cycle, not a new worker.
					purged, err := consumer.PurgeExpiredPolicyDecisions(ctx, dbPool, purgeBatchSize, consumer.PolicyDecisionsRetentionDays)
					if err != nil {
						logger.Warn("purge_policy_decisions failed", "error", err, "rows_deleted", purged)
						continue
					}
					if purged > 0 {
						logger.Info("purge_policy_decisions completed", "rows_deleted", purged, "retention_days", consumer.PolicyDecisionsRetentionDays)
					}
				}
			}
		}()
	}

	// PB2.4: nightly replication cron — rollup + ship at midnight UTC.
	if cfg.Loggerd.ReplicationEndpoint != "" && dbPool != nil {
		localRegion := cfg.Gateway.Region
		if localRegion == "" {
			localRegion = "sg" // fallback for single-region deployments
		}
		shipper := regionrepl.NewShipper(cfg.Loggerd.ReplicationEndpoint, localRegion)
		go func() {
			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()
			logger.Info("nightly replication cron started", "endpoint", cfg.Loggerd.ReplicationEndpoint)
			for {
				select {
				case <-ctx.Done():
					return
				case t := <-ticker.C:
					// Rollup the previous day (UTC).
					day := t.Add(-24 * time.Hour)
					rows, err := regionrepl.RollupForDay(ctx, dbPool, localRegion, day)
					if err != nil {
						logger.Error("rollup failed", "day", day.Format("2006-01-02"), "error", err)
						continue
					}
					if len(rows) == 0 {
						logger.Debug("no rollup rows for day", "day", day.Format("2006-01-02"))
						continue
					}
					start := time.Now()
					if err := shipper.Ship(ctx, rows); err != nil {
						logger.Error("rollup ship failed after retry", "day", day.Format("2006-01-02"), "error", err)
					} else {
						logger.Info("rollup shipped", "day", day.Format("2006-01-02"), "rows", len(rows), "duration", time.Since(start).String())
					}
				}
			}
		}()
	}

	httpAddr := cfg.Loggerd.ListenAddr
	if httpAddr == "" {
		httpAddr = ":8085"
	}

	// N12-P03-T03: readiness gate wired BEFORE the listener opens; an invalid
	// YABANIN_READINESS_DRAIN_DELAY fails startup (fail-closed knob
	// convention, shared with the gateway).
	drain, err := gateway.NewDrainReadiness()
	if err != nil {
		logger.Error("invalid readiness drain delay", "error", err)
		return err
	}

	mux := newLoggerdMux(drain)
	server, err := newLoggerdHTTPServer(httpAddr, mux)
	if err != nil {
		logger.Error("invalid HTTP server configuration", "error", err)
		return err
	}

	go func() {
		logger.Info("starting HTTP server", "addr", httpAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server failed", "error", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		logger.Info("received signal, shutting down", "signal", sig.String())
	case <-ctx.Done():
	}

	// N12-P03-T03: readiness=false → bounded propagation window → close the
	// listener — not-ready is observable by the LB/readiness probes BEFORE
	// the port stops accepting. The subsequent consumer stop keeps its
	// existing bound.
	//nolint:contextcheck // shutdown runs after ctx cancellation; deriving from the cancelled ctx would time out instantly
	drainLoggerdHTTP(drain, server, loggerdShutdownBudget, logger)
	consumerInstance.Stop()
	return nil
}

// loggerdShutdownBudget bounds the health/metrics listener drain. The
// listener is bodyless GETs only (/healthz, /metrics) — no streaming — so a
// small fixed budget is enough; the process exit path is bounded from the
// outside by the orchestrator regardless.
const loggerdShutdownBudget = 5 * time.Second

// newLoggerdMux builds the loggerd health/metrics mux. The /healthz endpoint
// is readiness-managed (N12-P03-T03): 503 once the drain gate is flipping,
// so load balancers and readiness probes stop routing here before the
// listener closes. A nil gate keeps the always-ready shape (tests).
func newLoggerdMux(drain *gateway.DrainReadiness) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", loggerdHealthHandler(drain))
	mux.Handle("/metrics", metrics.PrometheusHandler())
	return mux
}

// loggerdHealthHandler reports readiness: 200 while the process accepts
// work, 503 "draining" from the moment the drain gate flips (N12-P03-T03).
func loggerdHealthHandler(drain *gateway.DrainReadiness) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if !drain.Ready() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"draining"}` + "\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// drainLoggerdHTTP runs the readiness-first listener drain: flip the gate,
// hold the bounded propagation window, then close the listener under its
// budget. Deterministic apart from the real listener close, which is what
// the sequence exists to bound.
func drainLoggerdHTTP(drain *gateway.DrainReadiness, server *http.Server, budget time.Duration, logger *slog.Logger) {
	drain.SetDraining()
	logger.Info("loggerd readiness set to draining", "readiness_propagation_delay", drain.PropagationDelay().String())
	drain.WaitPropagation()
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("HTTP server shutdown error", "error", err)
	}
}

func startRollups(ctx context.Context, db *pgxpool.Pool, logger *slog.Logger, leader func() bool) {
	refresher := &consumer.RollupRefresher{DB: consumer.NewRollupDB(db), Now: time.Now, Log: logger.With("component", "rollup")}
	go consumer.RunRollupSchedule(ctx, refresher, leader)
}

// newLoggerdHTTPServer builds the loggerd health/metrics listener with the
// same server-level hardening as the admin panel listener (identical surface
// shape: bounded request/response endpoints, no streaming):
//   - ReadHeaderTimeout/ReadTimeout 10s: /healthz and /metrics are bodyless
//     GETs; a slow-header or slow-body client cannot hold a connection past
//     these bounds;
//   - WriteTimeout 15s: a scrape response is a single bounded body — writing
//     it must finish; a wedged consumer cannot pin the connection forever
//     (the admin panel uses the same 15s for its non-streaming responses);
//   - IdleTimeout 60s: shared with the gateway/admin keep-alive posture;
//   - MaxHeaderBytes: the same YABANIN_HTTP_MAX_HEADER_BYTES aggregate header
//     cap as the gateway and admin listeners, via the shared helper — an
//     invalid override fails startup (fail-closed) instead of silently
//     riding the Go default.
//
// N01-P06 remainder closure: this listener previously carried
// ReadHeaderTimeout only.
func newLoggerdHTTPServer(addr string, handler http.Handler) (*http.Server, error) {
	maxHeaderBytes, err := adminMaxHeaderBytes()
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    maxHeaderBytes,
	}, nil
}

//	YABANIN_OTEL_LOGS_ENDPOINT  OTLP/HTTP collector; either host:port
//	                            (HTTPS, like the trace endpoint) or a full
//	                            http(s):// URL for plain-HTTP collectors.
//	                            Empty/absent = export OFF (default; the
//	                            consumer path is bit-for-bit unchanged).
//	YABANIN_OTEL_LOGS_SAMPLE    deterministic sample rate 0–1 by request_id
//	                            hash (fnv64a — the same request is always
//	                            sampled or not). Invalid/out-of-range values
//	                            fall back to the default 1.0.
//	YABANIN_OTEL_LOGS_HEADERS   optional extra OTLP request headers as
//	                            "Key:Value,Key2:Value2" (e.g. auth for SaaS
//	                            collectors). Malformed entries are skipped.
//
// Content is NOT exported: message text leaves the process only with an
// explicit code-level opt-in (tracing.LogExporterConfig.IncludeContent, not
// exposed via env by default).
const (
	envOTelLogsEndpoint = "YABANIN_OTEL_LOGS_ENDPOINT"
	envOTelLogsSample   = "YABANIN_OTEL_LOGS_SAMPLE"
	envOTelLogsHeaders  = "YABANIN_OTEL_LOGS_HEADERS"

	defaultOTelLogsSample = 1.0
)

// newOTelLogSinkFromEnv builds the OTLP logs sink from the env knobs above.
// enabled=false with nil error is the normal disabled state (no endpoint);
// a non-nil error means the collector config is broken (the caller logs and
// continues without export — observability must never block loggerd).
// ctx is construction-time only: the exporter's pump and the deferred flush
// run on their own lifecycles (see tracing.LogExporter).
func newOTelLogSinkFromEnv(ctx context.Context, logger *slog.Logger) (sink consumer.OTelLogSink, enabled bool, err error) {
	cfg, ok := otelLogConfigFromEnv(os.Getenv, logger)
	if !ok {
		return nil, false, nil
	}
	s, buildErr := tracing.NewLogExporter(ctx, cfg)
	if buildErr != nil {
		return nil, false, buildErr
	}
	logger.Info("otel logs export enabled",
		slog.String("endpoint", cfg.Endpoint),
		slog.Float64("sample", cfg.SampleRate),
		slog.Bool("include_content", cfg.IncludeContent),
	)
	return s, true, nil
}

// otelLogConfigFromEnv parses the env knobs; getenv is injected for tests.
func otelLogConfigFromEnv(getenv func(string) string, logger *slog.Logger) (tracing.LogExporterConfig, bool) {
	endpoint := getenv(envOTelLogsEndpoint)
	if endpoint == "" {
		return tracing.LogExporterConfig{}, false
	}

	sample := defaultOTelLogsSample
	if raw := getenv(envOTelLogsSample); raw != "" {
		parsed, err := strconv.ParseFloat(raw, 64)
		switch {
		case err != nil:
			logger.Warn("invalid YABANIN_OTEL_LOGS_SAMPLE, using default", "value", raw, "default", defaultOTelLogsSample)
		case !(parsed >= 0 && parsed <= 1): // also rejects NaN (ParseFloat accepts it)
			logger.Warn("YABANIN_OTEL_LOGS_SAMPLE out of range, using default", "value", raw, "default", defaultOTelLogsSample)
		default:
			sample = parsed
		}
	}

	headers := parseOTelHeaders(getenv(envOTelLogsHeaders), logger)

	return tracing.LogExporterConfig{
		ServiceName: "loggerd",
		Endpoint:    endpoint,
		Headers:     headers,
		SampleRate:  sample,
	}, true
}

// parseOTelHeaders decodes "Key:Value,Key2:Value2". Entries without a colon
// or an empty key are skipped with a warning — a header typo must not
// disable export.
func parseOTelHeaders(raw string, logger *slog.Logger) map[string]string {
	if raw == "" {
		return nil
	}
	headers := make(map[string]string)
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		key, value, found := strings.Cut(entry, ":")
		key = strings.TrimSpace(key)
		if !found || key == "" {
			logger.Warn("skipping malformed YABANIN_OTEL_LOGS_HEADERS entry", "entry", entry)
			continue
		}
		headers[key] = strings.TrimSpace(value)
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

// purgeBatchSize bounds each purge DELETE (W-LOGG): one statement
// touches at most this many rows, so a retention backlog drains in short
// transactions instead of one long-running delete that stalls vacuum.
const purgeBatchSize = 5000

// purgeExpiredRequestLogs deletes request_logs older than `days` in bounded
// batches (ctid subselect, so the batch is chosen without a stable-id
// assumption) and returns the total deleted. It stops early when ctx is
// cancelled — shutdown must not wait out a multi-batch backlog.
func purgeExpiredRequestLogs(ctx context.Context, db *pgxpool.Pool, batchSize, days int) (int64, error) {
	if db == nil {
		return 0, errors.New("purge_expired_records: nil db pool")
	}
	if batchSize <= 0 {
		batchSize = purgeBatchSize
	}
	cutoff := time.Now().AddDate(0, 0, -days)
	const query = `DELETE FROM request_logs WHERE ctid IN (
			SELECT ctid FROM request_logs WHERE created_at < $1 LIMIT $2
		)`
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		tag, err := db.Exec(ctx, query, cutoff, batchSize)
		if err != nil {
			return total, fmt.Errorf("purge_expired_records batch: %w", err)
		}
		deleted := tag.RowsAffected()
		total += deleted
		if deleted < int64(batchSize) {
			return total, nil
		}
	}
}
