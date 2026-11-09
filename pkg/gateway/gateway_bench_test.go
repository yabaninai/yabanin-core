package cli

import (
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/reireirei/yabanin/pkg/openai"
)

// BenchmarkNormalizeMessagesJSON_HotPath tests the JSON parsing overhead in the hot path.
func BenchmarkNormalizeMessagesJSON_HotPath(b *testing.B) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello world"},{"role":"assistant","content":"hi there!"}],"stream":false}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var req openai.ChatCompletionRequest
		if err := json.Unmarshal(body, &req); err != nil {
			b.Fatal(err)
		}
		if len(req.Messages) == 0 {
			b.Fatal("no messages")
		}
	}
}

// BenchmarkLogWithContext tests the overhead of logctx.WithLogger.
func BenchmarkLogWithContext(b *testing.B) {
	l := slog.Default()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = l.With("bench", i)
	}
}
