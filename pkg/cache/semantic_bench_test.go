package cache

import (
	"testing"
)

// BenchmarkSemanticNormalize_Strict tests normalization speed under PolicyStrict.
func BenchmarkSemanticNormalize_Strict(b *testing.B) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"tell me about artificial intelligence and machine learning"}],"stream":false}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := NormalizeWithPolicy(body, PolicyStrict)
		if err != nil {
			b.Fatal(err)
		}
		if len(result) == 0 {
			b.Fatal("empty result")
		}
	}
}

// BenchmarkSemanticNormalize_Normalized tests normalization speed under PolicyNormalized.
func BenchmarkSemanticNormalize_Normalized(b *testing.B) {
	body := []byte(`{"model":"gpt-4o","request_id":"abc123","messages":[{"role":"user","content":"  tell me about AI  "}]}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := NormalizeWithPolicy(body, PolicyNormalized)
		if err != nil {
			b.Fatal(err)
		}
		if len(result) == 0 {
			b.Fatal("empty result")
		}
	}
}

// BenchmarkSemanticNormalize_Aggressive tests normalization speed under PolicyAggressive.
func BenchmarkSemanticNormalize_Aggressive(b *testing.B) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"Hello, World! What's up? 123"}]}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := NormalizeWithPolicy(body, PolicyAggressive)
		if err != nil {
			b.Fatal(err)
		}
		if len(result) == 0 {
			b.Fatal("empty result")
		}
	}
}

// BenchmarkNormalizePromptHash tests full normalization + hash computation.
func BenchmarkNormalizePromptHash(b *testing.B) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"explain quantum computing"},"{"role":"assistant","content":"Quantum computing uses qubits..."}]}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h, err := NormalizePromptHash(body)
		if err != nil {
			b.Fatal(err)
		}
		if len(h) != 64 {
			b.Fatal("expected 64-char hex digest")
		}
	}
}
