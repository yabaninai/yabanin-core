package classifier

import (
	"context"
	"strings"
	"testing"
)

func BenchmarkExtractFeatures(b *testing.B) {
	prompt := strings.Repeat("Debug this Go code and analyze the time complexity of the recursive algorithm. ", 10)
	in := Input{Prompt: prompt}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ExtractFeatures(in)
	}
}

func BenchmarkRuleTier_Classify_Easy(b *testing.B) {
	r := NewRuleTier()
	ctx := context.Background()
	in := Input{Prompt: "What is the capital of France?"}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = r.Classify(ctx, in)
	}
}

func BenchmarkRuleTier_Classify_Hard(b *testing.B) {
	r := NewRuleTier()
	ctx := context.Background()
	in := Input{Prompt: "Debug and refactor this distributed system architecture. Analyze the race conditions in the concurrent goroutine pool and optimize the channel-based communication pattern for minimal latency."}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = r.Classify(ctx, in)
	}
}

func BenchmarkRuleTier_Classify_Long(b *testing.B) {
	r := NewRuleTier()
	ctx := context.Background()
	in := Input{Prompt: strings.Repeat("Analyze the performance characteristics of this database query. ", 100)}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = r.Classify(ctx, in)
	}
}

func BenchmarkRegistry_FallbackChain(b *testing.B) {
	r := NewRegistry(NewRuleTier())
	ctx := context.Background()
	in := Input{Prompt: "Translate this paragraph from English to French."}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = r.Classify(ctx, in)
	}
}
