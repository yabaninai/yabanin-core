package cli

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/batchstore"
)

// Unit-level pins for the D3 batch-line limit (no DB): the parse-time cap
// added over the store-level check in CreateBatch. The integration suite
// (files_batch_int_test.go, DB-gated) covers the endpoint behavior; these
// tests pin the parser boundary itself.

func batchLine(i int) string {
	return `{"custom_id":"c-` + strconv.Itoa(i) + `","method":"POST","url":"/v1/chat/completions","body":{"model":"m"}}`
}

// Exactly MaxBatchLines lines parse; one more is the D3 ErrTooManyLines
// (mapped by batchesCreate to 400 too_many_requests_in_batch).
func TestParseBatchJSONL_LineCapBoundary(t *testing.T) {
	var b strings.Builder
	for i := 0; i < batchstore.MaxBatchLines; i++ {
		b.WriteString(batchLine(i))
		b.WriteByte('\n')
	}
	lines, err := parseBatchJSONL([]byte(b.String()))
	if err != nil {
		t.Fatalf("exactly %d lines must parse: %v", batchstore.MaxBatchLines, err)
	}
	if len(lines) != batchstore.MaxBatchLines {
		t.Fatalf("got %d lines, want %d", len(lines), batchstore.MaxBatchLines)
	}

	b.WriteString(batchLine(batchstore.MaxBatchLines))
	b.WriteByte('\n')
	_, err = parseBatchJSONL([]byte(b.String()))
	if !errors.Is(err, batchstore.ErrTooManyLines) {
		t.Fatalf("MaxBatchLines+1 must be ErrTooManyLines, got %v", err)
	}
}

// The cap stops parsing at the first line past it: a valid line 1001 is
// reported as the cap, and garbage AFTER the cap never changes the verdict
// (bounded work on oversized files). A defect BEFORE the cap still wins, so
// per-line validation order is preserved for files that are invalid earlier.
func TestParseBatchJSONL_LineCapEarlyExit(t *testing.T) {
	var b strings.Builder
	for i := 0; i < batchstore.MaxBatchLines; i++ {
		b.WriteString(batchLine(i))
		b.WriteByte('\n')
	}
	// First line past the cap: valid shape — the cap fires here.
	b.WriteString(batchLine(batchstore.MaxBatchLines))
	b.WriteByte('\n')
	// Everything after: garbage that must NOT be reached.
	b.WriteString("not json at all\n")
	_, err := parseBatchJSONL([]byte(b.String()))
	if !errors.Is(err, batchstore.ErrTooManyLines) {
		t.Fatalf("cap must fire at line %d before later garbage: %v", batchstore.MaxBatchLines+1, err)
	}

	// Defect before the cap keeps precedence.
	var c strings.Builder
	c.WriteString(batchLine(0))
	c.WriteString("\n{\"custom_id\":\"x\",\"method\":\"GET\",\"url\":\"/v1/chat/completions\",\"body\":{\"model\":\"m\"}}\n")
	_, err = parseBatchJSONL([]byte(c.String()))
	if err == nil || errors.Is(err, batchstore.ErrTooManyLines) || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("pre-cap defect must be the line-2 validation error, got %v", err)
	}
}

// Parser negatives pinned at unit level (previously only DB-gated coverage).
func TestParseBatchJSONL_RejectsEmptyStreamAndForeignURL(t *testing.T) {
	if _, err := parseBatchJSONL([]byte("")); err == nil {
		t.Fatal("empty input must be rejected")
	}
	if _, err := parseBatchJSONL([]byte("\n\n")); err == nil {
		t.Fatal("blank-line-only input must be rejected")
	}
	_, err := parseBatchJSONL([]byte(`{"custom_id":"c","method":"POST","url":"/v1/chat/completions","body":{"model":"m","stream":true}}` + "\n"))
	if err == nil || !strings.Contains(err.Error(), "streaming") {
		t.Fatalf("streaming line must be rejected explicitly, got %v", err)
	}
	_, err = parseBatchJSONL([]byte(`{"custom_id":"c","method":"POST","url":"/v1/embeddings","body":{"model":"m"}}` + "\n"))
	if err == nil || !strings.Contains(err.Error(), "/v1/chat/completions") {
		t.Fatalf("non-chat URL must be rejected with the supported endpoint, got %v", err)
	}
}
