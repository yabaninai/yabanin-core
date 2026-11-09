package loggerd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Unit tests (dockerless): key layout, env parsing, redaction and the JSONL
// merge contract over a local S3 mock. The mock serves real HTTP to the REAL
// aws-sdk-go-v2 client (client-side SigV4 signing included) — the exporter
// surface is Get/Put only, so signature VERIFICATION server-side would test
// the SDK rather than this codebase, while a minio container would add a
// module dependency and lose the dockerless fast loop. The DB contract
// (watermark idempotency, at-least-once) runs against the disposable
// Postgres stand in the live tests below.
// ---------------------------------------------------------------------------

// s3Mock is a tiny path-style S3: GET/PUT on /<bucket>/<key>.
type s3Mock struct {
	mu       sync.Mutex
	objects  map[string][]byte
	failPuts int // fail this many PUTs with 503 before succeeding
	putCount int
	requests int // every HTTP request the mock has received
}

func newS3Mock() *s3Mock { return &s3Mock{objects: map[string][]byte{}} }

// totalRequests reports the number of HTTP requests the mock has received.
func (m *s3Mock) totalRequests() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requests
}

func (m *s3Mock) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.requests++
		m.mu.Unlock()
		trimmed := strings.TrimPrefix(r.URL.Path, "/")
		parts := strings.SplitN(trimmed, "/", 2)
		if len(parts) != 2 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		key := parts[1]
		m.mu.Lock()
		defer m.mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			defer r.Body.Close()
			var body bytes.Buffer
			if _, err := body.ReadFrom(r.Body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			m.putCount++
			if m.failPuts > 0 {
				m.failPuts--
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			m.objects[key] = body.Bytes()
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			body, ok := m.objects[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"code":"NoSuchKey"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

// newMockUploader builds a REAL aws-sdk-go-v2 S3 client aimed at the mock.
func newMockUploader(t *testing.T, m *s3Mock) *S3Uploader {
	t.Helper()
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)
	ctx := context.Background()
	awsCfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion("us-east-1"))
	require.NoError(t, err)
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = true
		o.BaseEndpoint = aws.String(srv.URL)
		o.Credentials = aws.AnonymousCredentials{}
	})
	return &S3Uploader{client: client, bucket: "test-bucket"}
}

func TestObjectKeyLayout(t *testing.T) {
	ts := time.Date(2026, 10, 7, 13, 45, 12, 0, time.UTC)
	assert.Equal(t, "2026/10/07/13.jsonl", objectKey("", ts, ScheduleHourly))
	assert.Equal(t, "logs/2026/10/07/13.jsonl", objectKey("logs", ts, ScheduleHourly))
	assert.Equal(t, "logs/2026/10/07/day.jsonl", objectKey("logs", ts, ScheduleDaily))
	assert.Equal(t, "2026/10/07/day.jsonl", objectKey("", ts, ScheduleDaily))
	zeroHour := time.Date(2026, 3, 5, 7, 0, 0, 0, time.UTC)
	assert.Equal(t, "p/2026/03/05/07.jsonl", objectKey("p", zeroHour, ScheduleHourly),
		"month/day/hour must be zero-padded")
}

func TestLogExportConfigFromEnv(t *testing.T) {
	t.Run("disabled without bucket", func(t *testing.T) {
		cfg := LogExportConfigFromEnv(func(string) string { return "" })
		assert.False(t, cfg.Enabled())
		assert.Equal(t, defaultExportRegion, cfg.Region)
		assert.Empty(t, cfg.Schedule)
		assert.False(t, cfg.Redact)
	})
	t.Run("full knob set", func(t *testing.T) {
		cfg := LogExportConfigFromEnv(func(name string) string {
			switch name {
			case envLogExportBucket:
				return " yb-logs "
			case envLogExportPrefix:
				return "/logs/prod/"
			case envLogExportRegion:
				return "eu-central-1"
			case envLogExportEndpoint:
				return "https://storage.googleapis.com"
			case envLogExportSchedule:
				return "DAILY"
			case envLogExportRedact:
				return "true"
			}
			return ""
		})
		assert.True(t, cfg.Enabled())
		assert.Equal(t, "yb-logs", cfg.Bucket)
		assert.Equal(t, "logs/prod", cfg.Prefix)
		assert.Equal(t, "eu-central-1", cfg.Region)
		assert.Equal(t, "https://storage.googleapis.com", cfg.Endpoint)
		assert.Equal(t, ScheduleDaily, cfg.Schedule)
		assert.True(t, cfg.Redact)
	})
	t.Run("unknown schedule stays raw for the wiring to warn, constructor normalizes", func(t *testing.T) {
		cfg := LogExportConfigFromEnv(func(name string) string {
			if name == envLogExportBucket {
				return "b"
			}
			if name == envLogExportSchedule {
				return "Weekly"
			}
			return ""
		})
		assert.Equal(t, "weekly", cfg.Schedule, "raw value preserved")
		normalized := NewLogExporter(nil, nil, cfg, slog.Default())
		assert.Equal(t, ScheduleHourly, normalized.cfg.Schedule)
	})
}

// exportRowJSON parses every JSONL line of a stored object.
func exportRowJSON(t *testing.T, data []byte) []exportLogRow {
	t.Helper()
	var rows []exportLogRow
	for _, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r exportLogRow
		require.NoError(t, json.Unmarshal(line, &r))
		rows = append(rows, r)
	}
	return rows
}

func strPtr(s string) *string { return &s }

func TestUploadBatchRedactsContent(t *testing.T) {
	mock := newS3Mock()
	e := NewLogExporter(nil, newMockUploader(t, mock), LogExportConfig{
		Bucket: "test-bucket", Redact: true, Schedule: ScheduleHourly,
	}, slog.Default())
	ts := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	rows := []exportLogRow{{
		ID: 7, ModelUsed: "gpt-x", Response: json.RawMessage(`{"messages":"hi"}`),
		UpstreamRequest: json.RawMessage(`{"q":1}`), Error: strPtr("boom"),
		PromptHash: strPtr("abc"), CreatedAt: ts,
	}}
	require.NoError(t, e.uploadBatch(context.Background(), rows))

	stored := exportRowJSON(t, mock.objects["2026/10/07/12.jsonl"])
	require.Len(t, stored, 1)
	assert.JSONEq(t, "null", string(stored[0].Response), "content payload must be redacted to null")
	assert.JSONEq(t, "null", string(stored[0].UpstreamRequest))
	assert.Nil(t, stored[0].Error)
	assert.Equal(t, "abc", *stored[0].PromptHash, "metadata survives redaction")
}

func TestUploadBatchMergesLateRowsInIDOrder(t *testing.T) {
	mock := newS3Mock()
	e := NewLogExporter(nil, newMockUploader(t, mock), LogExportConfig{
		Bucket: "test-bucket", Schedule: ScheduleHourly,
	}, slog.Default())
	ts := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	require.NoError(t, e.uploadBatch(context.Background(), []exportLogRow{
		{ID: 10, CreatedAt: ts}, {ID: 11, CreatedAt: ts},
	}))
	require.NoError(t, e.uploadBatch(context.Background(), []exportLogRow{
		{ID: 12, CreatedAt: ts},
	}))
	stored := exportRowJSON(t, mock.objects["2026/10/07/09.jsonl"])
	require.Len(t, stored, 3, "merge must not lose or duplicate prior rows")
	assert.Equal(t, int64(10), stored[0].ID)
	assert.Equal(t, int64(11), stored[1].ID)
	assert.Equal(t, int64(12), stored[2].ID)
}

func TestS3UploaderGetPutRoundTrip(t *testing.T) {
	mock := newS3Mock()
	u := newMockUploader(t, mock)
	ctx := context.Background()
	_, exists, err := u.Get(ctx, "2026/10/07/13.jsonl")
	require.NoError(t, err)
	assert.False(t, exists, "missing key reports not-found, not error")
	require.NoError(t, u.Put(ctx, "2026/10/07/13.jsonl", []byte("hello")))
	data, exists, err := u.Get(ctx, "2026/10/07/13.jsonl")
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, "hello", string(data))
}

func TestClosedBoundary(t *testing.T) {
	e := NewLogExporter(nil, nil, LogExportConfig{Schedule: ScheduleHourly}, slog.Default())
	now := time.Date(2026, 10, 7, 13, 42, 5, 0, time.UTC)
	assert.Equal(t, time.Date(2026, 10, 7, 13, 0, 0, 0, time.UTC), e.closedBoundary(now))

	e.cfg.Schedule = ScheduleDaily
	assert.Equal(t, time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC), e.closedBoundary(now))
}

// ---------------------------------------------------------------------------
// Live tests (disposable Postgres stand, same contract as the consumer
// package): watermark idempotency, at-least-once on upload failure and
// resume-across-restart.
// ---------------------------------------------------------------------------

// seedRequestLog inserts one request_logs row and returns its id. The stand
// connects as the container superuser, so the region RLS policy does not
// filter these rows (the same posture as the loggerd purge path).
func seedRequestLog(t *testing.T, pool *pgxpool.Pool, createdAt time.Time, cost float64, response string) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(context.Background(),
		`INSERT INTO request_logs (model_requested, model_used, status_code, duration_ms,
			tokens_in, tokens_out, cost_in_usd, response, created_at, updated_at, home_region)
		 VALUES ('gpt-x', 'gpt-x', 200, 10, 1, 2, $1, $2, $3, $3, 'test-region')
		 RETURNING id`,
		cost, response, createdAt).Scan(&id)
	require.NoError(t, err)
	return id
}

func watermarkOf(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var wm int64
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT last_id FROM log_export_watermark WHERE id = 1`).Scan(&wm))
	return wm
}

// resetExportStand gives each live test a deterministic stand: the test
// binary's disposable Postgres is SHARED (testdb per-binary singleton), so
// leftover rows and the watermark singleton from a previous test would leak
// into the next one.
func resetExportStand(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `DELETE FROM request_logs`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE log_export_watermark SET last_id = 0`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `ALTER SEQUENCE request_logs_id_seq RESTART WITH 1`)
	require.NoError(t, err)
}

func TestLogExporterWatermarkIdempotency(t *testing.T) {
	pool := testdb.Postgres(t)
	resetExportStand(t, pool)
	mock := newS3Mock()
	e := NewLogExporter(pool, newMockUploader(t, mock), LogExportConfig{
		Bucket: "test-bucket", Schedule: ScheduleHourly, BatchSize: 2, Interval: time.Minute,
	}, slog.Default())
	ctx := context.Background()
	// Pin just after an hour boundary so the open row cannot drift into a closed hour.
	now := time.Date(2026, time.October, 10, 4, 0, 1, 0, time.UTC)
	e.now = func() time.Time { return now }

	// Two rows in a closed hour, one in the current open hour.
	closed := now.Add(-2 * time.Hour).Truncate(time.Hour)
	id1 := seedRequestLog(t, pool, closed, 0.25, `{"m":"a"}`)
	id2 := seedRequestLog(t, pool, closed.Add(time.Minute), 0.5, `{"m":"b"}`)
	open := now
	seedRequestLog(t, pool, open, 1.0, `{"m":"open"}`)

	exported, err := e.RunOnce(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, exported, "only closed-period rows export")

	assert.Equal(t, id2, watermarkOf(t, pool), "watermark = max exported id")

	hour := closed.Format("2006/01/02/15") + ".jsonl"
	stored := exportRowJSON(t, mock.objects[hour])
	require.Len(t, stored, 2)
	assert.Equal(t, id1, stored[0].ID)
	assert.InDelta(t, 0.25, *stored[0].CostInUSD, 1e-9)
	require.NotNil(t, stored[0].Response)
	assert.JSONEq(t, `{"m":"a"}`, string(stored[0].Response), "content is a full copy by default")

	// Idempotency: a repeat pass must not duplicate.
	exported, err = e.RunOnce(ctx)
	require.NoError(t, err)
	assert.Zero(t, exported)
	stored = exportRowJSON(t, mock.objects[hour])
	require.Len(t, stored, 2, "no duplicates after the repeat pass")

	// The open row closes an hour later: it exports exactly once.
	e.now = func() time.Time { return now.Add(time.Hour) }
	exported, err = e.RunOnce(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, exported)
	stored = exportRowJSON(t, mock.objects[open.Format("2006/01/02/15")+".jsonl"])
	require.Len(t, stored, 1)
}

func TestLogExporterUploadFailureKeepsWatermark(t *testing.T) {
	pool := testdb.Postgres(t)
	resetExportStand(t, pool)
	mock := newS3Mock()
	// Exceed the SDK's default retry budget (3 attempts) so the outage is
	// not masked: the pass must FAIL on a dead store, not retry through it.
	mock.failPuts = 5
	e := NewLogExporter(pool, newMockUploader(t, mock), LogExportConfig{
		Bucket: "test-bucket", Schedule: ScheduleHourly, Interval: time.Minute,
	}, slog.Default())
	ctx := context.Background()

	closed := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Hour)
	seeded := seedRequestLog(t, pool, closed, 1.0, `{}`)

	_, err := e.RunOnce(ctx)
	require.Error(t, err, "failing upload must fail the pass")
	assert.Equal(t, int64(0), watermarkOf(t, pool), "watermark must not advance before confirmed upload")

	// Retry after the outage: the same rows export again (at-least-once).
	exported, err := e.RunOnce(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, exported)
	assert.Equal(t, seeded, watermarkOf(t, pool))
}

// failingUploader fails exactly one Put (the Nth call, no SDK retries on a
// seam error) to simulate death between two batches.
type failingUploader struct {
	LogUploader
	failAt  int
	attempt int
}

func (f *failingUploader) Put(ctx context.Context, key string, data []byte) error {
	f.attempt++
	if f.attempt == f.failAt {
		return errors.New("boom: simulated store outage")
	}
	return f.LogUploader.Put(ctx, key, data)
}

func TestLogExporterResumeAcrossRestart(t *testing.T) {
	pool := testdb.Postgres(t)
	resetExportStand(t, pool)
	mock := newS3Mock()
	uploader := newMockUploader(t, mock)
	ctx := context.Background()

	// Three rows of one closed UTC day; batch cap 2 splits them 2+1.
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Truncate(24 * time.Hour)
	var ids []int64
	for i := 0; i < 3; i++ {
		ids = append(ids, seedRequestLog(t, pool, yesterday.Add(time.Duration(i)*time.Minute), 0.1, `{}`))
	}

	// First exporter instance commits batch 1 (watermark = ids[1]) and then
	// dies on the second batch's upload — exactly the crash window the
	// at-least-once contract covers.
	e1 := NewLogExporter(pool, &failingUploader{LogUploader: uploader, failAt: 2}, LogExportConfig{
		Bucket: "test-bucket", Schedule: ScheduleDaily, Interval: time.Minute, BatchSize: 2,
	}, slog.Default())
	_, err := e1.RunOnce(ctx)
	require.Error(t, err, "the simulated outage fails the second batch")
	assert.Equal(t, ids[1], watermarkOf(t, pool), "watermark advanced per committed batch only")

	// A fresh instance (restart) resumes from the committed watermark:
	// exactly the remaining row — no re-export, no gap.
	e2 := NewLogExporter(pool, uploader, LogExportConfig{
		Bucket: "test-bucket", Schedule: ScheduleDaily, Interval: time.Minute,
	}, slog.Default())
	exported, err := e2.RunOnce(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, exported)

	stored := exportRowJSON(t, mock.objects[yesterday.Format("2006/01/02")+"/day.jsonl"])
	require.Len(t, stored, 3)
	assert.Equal(t, ids[0], stored[0].ID)
	assert.Equal(t, ids[1], stored[1].ID)
	assert.Equal(t, ids[2], stored[2].ID)
}

// the REAL S3 constructor is a credential/egress boundary. With
// synthetic static credentials pinned to a local mock, construction performs
// no I/O and a missing-key Get is exactly one signed request to the
// configured endpoint; without any credentials (IMDS disabled) the same Get
// fails client-side and nothing reaches the wire.
func TestNewS3Uploader_ConstructorAndCredentialNegatives(t *testing.T) {
	ctx := context.Background()

	// Empty bucket is rejected before any AWS machinery runs.
	_, err := NewS3Uploader(ctx, LogExportConfig{Bucket: "", Region: "us-east-1"})
	require.Error(t, err)

	// Synthetic static credentials only: no IMDS, no shared config files, so
	// no ambient credential source can dial out on this machine.
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAYABANINLOCALTEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "yabanin-local-synthetic-secret")
	t.Setenv("AWS_SESSION_TOKEN", "yabanin-local-synthetic-session")
	t.Setenv("AWS_CONFIG_FILE", "/nonexistent-yabanin-s3-test-config")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent-yabanin-s3-test-creds")

	mock := newS3Mock()
	srv := httptest.NewServer(mock.handler())
	t.Cleanup(srv.Close)
	uploader, err := NewS3Uploader(ctx, LogExportConfig{
		Bucket: "yabanin-test-bucket", Region: "us-east-1", Endpoint: srv.URL,
	})
	require.NoError(t, err)
	assert.Zero(t, mock.totalRequests(), "construction must not touch the endpoint")

	_, exists, err := uploader.Get(ctx, "probe.jsonl")
	require.NoError(t, err)
	assert.False(t, exists, "missing key reports not-found, not error")
	assert.Equal(t, 1, mock.totalRequests(), "missing-key Get is exactly one signed request to the configured endpoint")

	// No credentials (and IMDS disabled): the same Get must fail client-side
	// and send nothing — no unauthenticated egress attempt.
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_SESSION_TOKEN", "")

	bareMock := newS3Mock()
	bareSrv := httptest.NewServer(bareMock.handler())
	t.Cleanup(bareSrv.Close)
	plain, err := NewS3Uploader(ctx, LogExportConfig{
		Bucket: "yabanin-test-bucket", Region: "us-east-1", Endpoint: bareSrv.URL,
	})
	require.NoError(t, err)
	_, _, err = plain.Get(ctx, "probe.jsonl")
	require.Error(t, err, "a credential resolution failure must surface as an error")
	assert.Zero(t, bareMock.totalRequests(), "a credential failure must never reach the wire")
}
