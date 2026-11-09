package loggerd

// N01-P04-T08 interruption/retry corpus at the S3 EXPORT seam (period
// object keys): the exporter's read-modify-write over JSONL keys must
// survive an upload interrupted mid-write without tearing an object or
// losing/duplicating rows, and a retry must converge to the exact merged
// result.
//
// The pinned contract (mirrors the KMS envelope atomicity in pkg/kms):
//   - a Put is all-or-nothing per object; a failed Put leaves the stored
//     object byte-identical (no torn ciphertext/object);
//   - every Put payload ever attempted is a COMPLETE JSONL document (the
//     envelope is built fully in memory before the write);
//   - a multi-key batch fails fast: keys after the failed one are not
//     attempted and the watermark cannot advance (the watermark contract is
//     covered live in export_s3_test.go);
//   - the retry re-merges against the intact stored objects and converges:
//     every row exactly once, strict id order, no loss.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingUploader wraps the real mock-backed uploader, records every Put
// payload, and fails the Nth Put to simulate an interruption mid-write.
type recordingUploader struct {
	LogUploader
	mu   sync.Mutex
	puts []struct {
		key  string
		data []byte
	}
	failAt int
	calls  int
}

func (r *recordingUploader) Put(ctx context.Context, key string, data []byte) error {
	r.mu.Lock()
	r.calls++
	call := r.calls
	r.puts = append(r.puts, struct {
		key  string
		data []byte
	}{key, data})
	r.mu.Unlock()
	if call == r.failAt {
		return errors.New("boom: interrupted mid-write")
	}
	return r.LogUploader.Put(ctx, key, data)
}

func (r *recordingUploader) putPayloads() []struct {
	key  string
	data []byte
} {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]struct {
		key  string
		data []byte
	}, len(r.puts))
	copy(out, r.puts)
	return out
}

func TestLogExportUpload_InterruptedWriteConvergesOnRetry(t *testing.T) {
	mock := newS3Mock()
	uploader := &recordingUploader{LogUploader: newMockUploader(t, mock)}
	e := NewLogExporter(nil, uploader, LogExportConfig{
		Bucket: "test-bucket", Schedule: ScheduleHourly,
	}, slog.Default())
	ctx := context.Background()

	hourA := time.Date(2026, 10, 7, 8, 0, 0, 0, time.UTC)
	hourB := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	keyA, keyB := "2026/10/07/08.jsonl", "2026/10/07/09.jsonl"

	// Pre-existing closed-period objects (late rows will re-open them).
	require.NoError(t, e.uploadBatch(ctx, []exportLogRow{
		{ID: 10, CreatedAt: hourA}, {ID: 11, CreatedAt: hourB},
	}))

	// A two-key batch whose FIRST Put is interrupted mid-write.
	uploader.mu.Lock()
	uploader.failAt = uploader.calls + 1
	uploader.mu.Unlock()
	batch := []exportLogRow{{ID: 12, CreatedAt: hourA}, {ID: 13, CreatedAt: hourB}}
	err := e.uploadBatch(ctx, batch)
	require.Error(t, err, "the interruption must fail the pass, not vanish")

	// No torn state: both objects are byte-identical to their pre-batch
	// content — the failed write changed nothing, the not-yet-attempted key
	// changed nothing.
	assert.Len(t, exportRowJSON(t, mock.objects[keyA]), 1, "failed key must keep exactly its old rows")
	assert.Equal(t, int64(10), exportRowJSON(t, mock.objects[keyA])[0].ID)
	assert.Len(t, exportRowJSON(t, mock.objects[keyB]), 1, "unattempted key must keep exactly its old rows")
	assert.Equal(t, int64(11), exportRowJSON(t, mock.objects[keyB])[0].ID)

	// Every attempted payload was a complete JSONL document — an envelope
	// (here: an export object) is always built fully before any write.
	for i, put := range uploader.putPayloads() {
		require.True(t, bytes.HasSuffix(put.data, []byte("\n")), "put %d: payload must end with a newline frame", i)
		require.NotPanics(t, func() { exportRowJSON(t, put.data) }, "put %d: payload must parse fully", i)
		var rows []exportLogRow
		require.NoError(t, eachJSONLObject(put.data, &rows), "put %d: payload must be valid JSONL", i)
	}

	// Retry converges: the same batch re-merges against the intact objects.
	uploader.failAt = 0
	require.NoError(t, e.uploadBatch(ctx, batch))

	storedA, storedB := exportRowJSON(t, mock.objects[keyA]), exportRowJSON(t, mock.objects[keyB])
	require.Len(t, storedA, 2, "key A must hold exactly old+batch rows")
	require.Len(t, storedB, 2, "key B must hold exactly old+batch rows")
	assert.Equal(t, []int64{10, 12}, []int64{storedA[0].ID, storedA[1].ID}, "strict id order, no duplicates, no loss")
	assert.Equal(t, []int64{11, 13}, []int64{storedB[0].ID, storedB[1].ID}, "strict id order, no duplicates, no loss")
}

// eachJSONLObject parses every line of a JSONL payload into rows.
func eachJSONLObject(data []byte, rows *[]exportLogRow) error {
	for _, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r exportLogRow
		if err := json.Unmarshal(line, &r); err != nil {
			return err
		}
		*rows = append(*rows, r)
	}
	return nil
}
