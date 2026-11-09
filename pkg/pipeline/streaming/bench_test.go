package streaming

import (
	"fmt"
	"testing"
)

// benchReplacements is a realistic alias map: multi-byte aliases, a secret
// shape and a short token.
var benchReplacements = map[string]string{
	"Иванов Иван":   "ORG_1",
	"Иванов":        "ORG_2",
	"secret-key":    "[REDACTED]",
	"acme corp":     "ORG_3",
	"internal user": "USER_1",
}

// benchChunks builds a deterministic stream of ~32-byte deltas, every third
// chunk carrying a match (split across the boundary half the time).
func benchChunks() []string {
	chunks := make([]string, 0, 64)
	for i := 0; i < 64; i++ {
		switch i % 3 {
		case 0:
			chunks = append(chunks, fmt.Sprintf("plain text delta %d ", i))
		case 1:
			chunks = append(chunks, "data for Ivan")
		default:
			chunks = append(chunks, "ov and secret-ke")
		}
	}
	return chunks
}

// BenchmarkChunkProcessor measures the steady-state cost of rewriting one
// chunk with the carry state across chunk boundaries (allocations per
// chunk are the budget OP-8 adds per SSE delta).
func BenchmarkChunkProcessor(b *testing.B) {
	cp, err := NewChunkProcessor(benchReplacements)
	if err != nil {
		b.Fatalf("construct: %v", err)
	}
	chunks := benchChunks()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if out := cp.Process(chunks[i%len(chunks)]); len(out) > 4096 {
			b.Fatal("output grew unexpectedly")
		}
	}
}

// BenchmarkFrameProcessor measures one mutated SSE event end to end
// (JSON round-trip included — the price of rebuilding the event boundary).
func BenchmarkFrameProcessor(b *testing.B) {
	cp, err := NewChunkProcessor(benchReplacements)
	if err != nil {
		b.Fatalf("construct: %v", err)
	}
	fp := NewFrameProcessor(cp)
	frame := []byte(`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1728300000,"model":"gpt-test","choices":[{"index":0,"delta":{"content":"data for Ivan"},"finish_reason":null}]}` + "\n\n")
	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = fp.ProcessFrame(frame)
	}
}
