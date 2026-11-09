// Package loggerd hosts the loggerd side-processes that are NOT the Redis
// stream consumer (the consumer hot path lives in the consumer package and
// periodic, watermark-gated dump of request_logs into JSONL objects.
//
// Parity: Bifrost log exports / LiteLLM spend capture.
//
// Semantics:
//   - at-least-once: rows are selected with id > watermark, uploaded, and
//     only then does the watermark advance. A crash or upload failure after
//     a successful PutObject re-exports the same rows on the next pass, so
//     downstream consumers may see duplicates — never silent loss.
//   - complete objects: a pass only exports rows older than the START of
//     the current open period (hour for the hourly schedule, UTC day for
//     the daily one), so each object holds the full closed period. Late
//     rows (created_at inside an already-exported period, id above the
//     watermark) are MERGED into the existing object: ids above the
//     watermark are strictly greater than every id already in the object,
//     so plain byte concatenation preserves id order and the rewrite stays
//     deterministic.
//   - non-blocking: the exporter is its own goroutine on its own ticker;
//     it never touches the event stream or the consumer hot path.
//   - privacy: the export is a FULL copy of the request_logs rows (payload
//     content included), matching what hot storage holds. When the redact
//     knob is set, the content columns (response, upstream_request,
//     upstream_response, error) are exported as null; hashes and metadata
//     always go verbatim (the same redaction contract as the NEXT-21
//     retention archives).
//
// S3-compatible stores: the writer speaks the S3 API with an optional
// endpoint override, so AWS S3, GCS (https://storage.googleapis.com) and
// MinIO all work with the same code path. Credentials follow the standard
// AWS default chain (env → shared config → IAM role). Path-style addressing
// is forced (required by MinIO, recommended for GCS, valid for AWS).
package loggerd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
)

// Environment knobs (read by services/run/loggerd.go wiring, NOT pkg/config —
// K8s deployments configure the exporter via env only):
//
//	YABANIN_LOG_EXPORT_S3_BUCKET   — target bucket; EMPTY disables the exporter
//	YABANIN_LOG_EXPORT_S3_PREFIX   — key prefix under the bucket (default "")
//	YABANIN_LOG_EXPORT_S3_REGION   — AWS region (default "us-east-1"; GCS
//	                                 ignores it, MinIO needs any non-empty value)
//	YABANIN_LOG_EXPORT_S3_ENDPOINT — S3-compatible endpoint override for
//	                                 GCS/MinIO (default: native AWS S3)
//	YABANIN_LOG_EXPORT_SCHEDULE    — "hourly" (default) or "daily"
//	YABANIN_LOG_EXPORT_REDACT      — "true" strips content payloads from the
//	                                 exported JSONL (default: full copy)
const (
	envLogExportBucket   = "YABANIN_LOG_EXPORT_S3_BUCKET"
	envLogExportPrefix   = "YABANIN_LOG_EXPORT_S3_PREFIX"
	envLogExportRegion   = "YABANIN_LOG_EXPORT_S3_REGION"
	envLogExportEndpoint = "YABANIN_LOG_EXPORT_S3_ENDPOINT"
	envLogExportSchedule = "YABANIN_LOG_EXPORT_SCHEDULE"
	envLogExportRedact   = "YABANIN_LOG_EXPORT_REDACT"
)

// Schedule vocabulary.
const (
	ScheduleHourly = "hourly"
	ScheduleDaily  = "daily"
)

// Export defaults: one pass per hour, 5000 rows per batch (the same batch
// bound as the request_logs purge, so one pass cannot hold a long-lived
// transaction open over an oversized backlog).
const (
	defaultExportInterval = time.Hour
	defaultExportBatch    = 5000
	defaultExportRegion   = "us-east-1"
)

// LogExportConfig is the resolved exporter configuration.
type LogExportConfig struct {
	// Bucket enables the exporter when non-empty.
	Bucket string
	// Prefix is prepended to every object key ("" = bucket root).
	Prefix string
	// Region is the signing region (default us-east-1).
	Region string
	// Endpoint overrides the S3 API endpoint (GCS/MinIO); "" = native AWS.
	Endpoint string
	// Schedule is hourly|daily; anything else falls back to hourly.
	Schedule string
	// Redact nulls the content payload columns in the exported JSONL.
	Redact bool
	// Interval is the pass ticker (0 = 1h). One hour matches both
	// schedules: an hourly bucket closes at most once per hour, a daily
	// bucket once per day, and the extra no-op checks are cheap.
	Interval time.Duration
	// BatchSize bounds one SELECT (0 = 5000).
	BatchSize int
}

// Enabled reports whether the exporter should run.
func (c LogExportConfig) Enabled() bool { return c.Bucket != "" }

// LogExportConfigFromEnv resolves the exporter knobs. getenv is a seam for
// tests; production passes os.Getenv. Schedule stays the RAW value (so the
// wiring can warn on a bad setting); NewLogExporter normalizes unknown
// values to hourly.
func LogExportConfigFromEnv(getenv func(string) string) LogExportConfig {
	cfg := LogExportConfig{
		Bucket:    strings.TrimSpace(getenv(envLogExportBucket)),
		Prefix:    strings.Trim(getenv(envLogExportPrefix), "/"),
		Region:    strings.TrimSpace(getenv(envLogExportRegion)),
		Endpoint:  strings.TrimSpace(getenv(envLogExportEndpoint)),
		Schedule:  strings.ToLower(strings.TrimSpace(getenv(envLogExportSchedule))),
		Redact:    strings.EqualFold(strings.TrimSpace(getenv(envLogExportRedact)), "true"),
		Interval:  defaultExportInterval,
		BatchSize: defaultExportBatch,
	}
	if cfg.Region == "" {
		cfg.Region = defaultExportRegion
	}
	return cfg
}

// LogExportDB is the database surface of the exporter (satisfied by
// *pgxpool.Pool — the same seam shape as the retention worker).
type LogExportDB interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// LogUploader is the object-store seam: read-modify-write over JSONL keys.
// The production implementation speaks S3; tests serve a local mock.
type LogUploader interface {
	// Get returns the object body; exists=false when the key is absent.
	Get(ctx context.Context, key string) (data []byte, exists bool, err error)
	// Put stores the object atomically (one PutObject).
	Put(ctx context.Context, key string, data []byte) error
}

// exportLogRow is one exported request_logs row. Content columns mirror the
// hot-storage row; the redaction contract nulls Response, UpstreamRequest,
// UpstreamResponse and Error (prompt_hash and metadata always go — they are
// the redaction-safe projection, same as the retention archives).
type exportLogRow struct {
	ID                    int64           `json:"id"`
	RequestID             *string         `json:"request_id"`
	SessionID             *string         `json:"session_id"`
	OrgID                 *string         `json:"org_id"`
	TeamID                *string         `json:"team_id"`
	UserID                *string         `json:"user_id"`
	APIKeyID              *string         `json:"api_key_id"`
	AgentID               *string         `json:"agent_id"`
	ModelRequested        string          `json:"model_requested"`
	ModelUsed             string          `json:"model_used"`
	Endpoint              string          `json:"endpoint"`
	Method                string          `json:"method"`
	StatusCode            int32           `json:"status_code"`
	DurationMs            int32           `json:"duration_ms"`
	FirstTokenMs          *int32          `json:"first_token_ms"`
	TokensIn              int32           `json:"tokens_in"`
	TokensOut             int32           `json:"tokens_out"`
	CacheReadTokens       *int32          `json:"cache_read_tokens"`
	CacheCreationTokens   *int32          `json:"cache_creation_tokens"`
	CostInUSD             *float64        `json:"cost_in_usd"`
	CounterfactualCostUSD *float64        `json:"counterfactual_cost_usd"`
	UsageSource           string          `json:"usage_source"`
	CostStatus            string          `json:"cost_status"`
	CacheHitType          *string         `json:"cache_hit_type"`
	ClassifierClass       *string         `json:"classifier_class"`
	ClassifierConfidence  *float32        `json:"classifier_confidence"`
	TierUsed              *string         `json:"tier_used"`
	RoutingDecision       *string         `json:"routing_decision"`
	PromptHash            *string         `json:"prompt_hash"`
	Error                 *string         `json:"error"`
	Response              json.RawMessage `json:"response"`
	UpstreamRequest       json.RawMessage `json:"upstream_request"`
	UpstreamResponse      json.RawMessage `json:"upstream_response"`
	CreatedAt             time.Time       `json:"created_at"`
}

const (
	// exportSelect reads one oldest-first id-watermarked batch of rows whose
	// created_at falls into CLOSED periods (boundary passed by the caller).
	// Rows keep insertion order via the bigserial id; the RLS region
	// isolation on request_logs scopes the batch to the exporter's region
	// (the pool pins app.region, exactly like the purge path).
	exportSelect = `SELECT id, request_id, session_id::text, org_id::text, team_id::text,
			user_id::text, api_key_id::text, agent_id::text,
			model_requested, model_used, endpoint, method, status_code, duration_ms,
			first_token_ms, tokens_in, tokens_out, cache_read_tokens, cache_creation_tokens,
			cost_in_usd, counterfactual_cost_usd, usage_source, cost_status, cache_hit_type,
			classifier_class, classifier_confidence, tier_used, routing_decision, prompt_hash,
			error, response, upstream_request, upstream_response, created_at
		FROM request_logs
		WHERE id > $1 AND created_at < $2
		ORDER BY id
		LIMIT $3`

	// watermarkSelect reads the cursor (the singleton row is seeded by the
	// migration, so a missing row is a real error, not "start from zero").
	watermarkSelect = `SELECT last_id FROM log_export_watermark WHERE id = 1`

	// watermarkUpdate advances the cursor monotonically. GREATEST keeps the
	// cursor stable if a retried pass ever writes an older high-water mark.
	watermarkUpdate = `UPDATE log_export_watermark
		SET last_id = GREATEST(last_id, $1), updated_at = now()
		WHERE id = 1`
)

// LogExporter periodically exports closed-period request_logs rows into
// JSONL objects. One instance runs per process (leader-elected when leader
// election is on, mirroring the settlement worker wiring).
type LogExporter struct {
	db       LogExportDB
	uploader LogUploader
	cfg      LogExportConfig
	log      *slog.Logger
	now      func() time.Time
}

// NewLogExporter builds the exporter. Callers own the pass loop (Run) or
// drive RunOnce directly in tests.
func NewLogExporter(db LogExportDB, uploader LogUploader, cfg LogExportConfig, log *slog.Logger) *LogExporter {
	if log == nil {
		log = slog.Default()
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultExportBatch
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaultExportInterval
	}
	if cfg.Schedule != ScheduleHourly && cfg.Schedule != ScheduleDaily {
		cfg.Schedule = ScheduleHourly
	}
	return &LogExporter{db: db, uploader: uploader, cfg: cfg, log: log, now: time.Now}
}

// Schedule reports the normalized schedule (the wiring uses it for the
// enabled-banner after NewLogExporter normalized a bad raw value).
func (e *LogExporter) Schedule() string { return e.cfg.Schedule }

// Bucket reports the target bucket (wiring banner).
func (e *LogExporter) Bucket() string { return e.cfg.Bucket }

// Run drives one export pass immediately at startup, then on the ticker,
// until ctx is cancelled. A failing pass is logged, never fatal: the next
// tick retries from the unchanged watermark.
func (e *LogExporter) Run(ctx context.Context) error {
	if _, err := e.RunOnce(ctx); err != nil && ctx.Err() == nil {
		e.log.Error("log export pass failed", "error", err)
	}
	ticker := time.NewTicker(e.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			exported, err := e.RunOnce(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				e.log.Error("log export pass failed", "error", err)
				continue
			}
			if exported > 0 {
				e.log.Info("log export pass completed", "rows", exported,
					"schedule", e.cfg.Schedule, "bucket", e.cfg.Bucket)
			}
		}
	}
}

// RunOnce drains every closed batch (bounded per SELECT) and returns the
// number of rows uploaded. The watermark advances ONLY after the whole
// batch's objects are confirmed uploaded.
func (e *LogExporter) RunOnce(ctx context.Context) (int, error) {
	watermark, err := e.loadWatermark(ctx)
	if err != nil {
		return 0, fmt.Errorf("log export: load watermark: %w", err)
	}
	boundary := e.closedBoundary(e.now())
	total := 0
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		rows, err := e.selectBatch(ctx, watermark, boundary)
		if err != nil {
			return total, fmt.Errorf("log export: select batch (watermark %d): %w", watermark, err)
		}
		if len(rows) == 0 {
			return total, nil
		}
		if err := e.uploadBatch(ctx, rows); err != nil {
			return total, fmt.Errorf("log export: upload batch (watermark %d): %w", watermark, err)
		}
		watermark = rows[len(rows)-1].ID
		if _, err := e.db.Exec(ctx, watermarkUpdate, watermark); err != nil {
			return total, fmt.Errorf("log export: advance watermark to %d: %w", watermark, err)
		}
		total += len(rows)
		if len(rows) < e.cfg.BatchSize {
			return total, nil
		}
	}
}

// closedBoundary returns the start of the current OPEN period: only rows
// strictly older than this instant belong to fully closed objects.
func (e *LogExporter) closedBoundary(now time.Time) time.Time {
	now = now.UTC()
	if e.cfg.Schedule == ScheduleDaily {
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	}
	return now.Truncate(time.Hour)
}

func (e *LogExporter) loadWatermark(ctx context.Context) (int64, error) {
	var last int64
	if err := e.db.QueryRow(ctx, watermarkSelect).Scan(&last); err != nil {
		return 0, err
	}
	return last, nil
}

func (e *LogExporter) selectBatch(ctx context.Context, watermark int64, boundary time.Time) ([]exportLogRow, error) {
	rows, err := e.db.Query(ctx, exportSelect, watermark, boundary, e.cfg.BatchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []exportLogRow
	for rows.Next() {
		var r exportLogRow
		if err := rows.Scan(&r.ID, &r.RequestID, &r.SessionID, &r.OrgID, &r.TeamID,
			&r.UserID, &r.APIKeyID, &r.AgentID,
			&r.ModelRequested, &r.ModelUsed, &r.Endpoint, &r.Method, &r.StatusCode, &r.DurationMs,
			&r.FirstTokenMs, &r.TokensIn, &r.TokensOut, &r.CacheReadTokens, &r.CacheCreationTokens,
			&r.CostInUSD, &r.CounterfactualCostUSD, &r.UsageSource, &r.CostStatus, &r.CacheHitType,
			&r.ClassifierClass, &r.ClassifierConfidence, &r.TierUsed, &r.RoutingDecision, &r.PromptHash,
			&r.Error, &r.Response, &r.UpstreamRequest, &r.UpstreamResponse, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// uploadBatch groups the batch by period key, merges with any existing
// object, uploads every key, and reports failure before the caller may
// advance the watermark.
func (e *LogExporter) uploadBatch(ctx context.Context, rows []exportLogRow) error {
	keys := make([]string, 0, 2)
	byKey := make(map[string][]exportLogRow)
	for _, r := range rows {
		key := objectKey(e.cfg.Prefix, r.CreatedAt.UTC(), e.cfg.Schedule)
		if _, seen := byKey[key]; !seen {
			keys = append(keys, key)
		}
		byKey[key] = append(byKey[key], r)
	}
	for _, key := range keys {
		batch := byKey[key]
		if e.cfg.Redact {
			for i := range batch {
				batch[i].Response = nil
				batch[i].UpstreamRequest = nil
				batch[i].UpstreamResponse = nil
				batch[i].Error = nil
			}
		}
		// Merge with the existing object when late rows re-open a written
		// period. Every id in this batch is above the watermark, and every
		// id already in the object is at or below it — concatenation keeps
		// strict id order.
		existing, _, err := e.uploader.Get(ctx, key)
		if err != nil {
			return fmt.Errorf("read existing object %s: %w", key, err)
		}
		var buf bytes.Buffer
		buf.Write(existing)
		enc := json.NewEncoder(&buf)
		for i := range batch {
			if err := enc.Encode(batch[i]); err != nil {
				return fmt.Errorf("encode row %d for %s: %w", batch[i].ID, key, err)
			}
		}
		if err := e.uploader.Put(ctx, key, buf.Bytes()); err != nil {
			return fmt.Errorf("put object %s: %w", key, err)
		}
	}
	return nil
}

// objectKey renders the canonical layout:
//
//	hourly: <prefix>/yyyy/mm/dd/hh.jsonl   (UTC hour of created_at)
//	daily:  <prefix>/yyyy/mm/dd/day.jsonl  (one object per UTC day)
func objectKey(prefix string, t time.Time, schedule string) string {
	t = t.UTC()
	name := fmt.Sprintf("%02d.jsonl", t.Hour())
	if schedule == ScheduleDaily {
		name = "day.jsonl"
	}
	if prefix == "" {
		return fmt.Sprintf("%04d/%02d/%02d/%s", t.Year(), int(t.Month()), t.Day(), name)
	}
	return fmt.Sprintf("%s/%04d/%02d/%02d/%s", prefix, t.Year(), int(t.Month()), t.Day(), name)
}

// S3Uploader is the production LogUploader over AWS SDK v2. The client is
// built once (the default credential chain resolves lazily per call, so a
// role that appears later still works without a restart).
type S3Uploader struct {
	client *s3.Client
	bucket string
}

// NewS3Uploader builds the S3-compatible uploader from the resolved config.
// Path-style addressing is forced: MinIO requires it, GCS prefers it, AWS
// accepts it.
func NewS3Uploader(ctx context.Context, cfg LogExportConfig) (*S3Uploader, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("log export: empty bucket")
	}
	awsCfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("log export: load AWS config: %w", err)
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = true
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
	})
	return &S3Uploader{client: client, bucket: cfg.Bucket}, nil
}

// Get fetches an object; a missing key is (nil, false, nil).
func (u *S3Uploader) Get(ctx context.Context, key string) ([]byte, bool, error) {
	out, err := u.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(u.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if objectNotFound(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer out.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(out.Body); err != nil {
		return nil, false, fmt.Errorf("read object %s: %w", key, err)
	}
	return buf.Bytes(), true, nil
}

// Put stores one object in a single atomic PutObject.
func (u *S3Uploader) Put(ctx context.Context, key string, data []byte) error {
	_, err := u.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(u.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(data),
		ContentType: aws.String("application/x-ndjson"),
	})
	return err
}

// objectNotFound maps NoSuchKey (AWS) and 404 status (GCS/MinIO variants
// that answer with a plain status) to a clean miss.
func objectNotFound(err error) bool {
	var noKey *s3types.NoSuchKey
	if errors.As(err, &noKey) {
		return true
	}
	var apiErr *smithy.GenericAPIError
	if errors.As(err, &apiErr) && (apiErr.Code == "NoSuchKey" || apiErr.Code == "NotFound") {
		return true
	}
	var httpErr *smithyhttp.ResponseError
	return errors.As(err, &httpErr) && httpErr.HTTPStatusCode() == 404
}
