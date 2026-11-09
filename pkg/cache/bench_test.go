package cache

import (
	"testing"
)

func BenchmarkNormalizeMessagesJSON(b *testing.B) {
	input := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello world"},{"role":"assistant","content":"hi there"}],"stream":false}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NormalizeMessagesJSON(input)
	}
}

func BenchmarkComputePromptHash(b *testing.B) {
	data := []byte(`{"messages":[{"role":"user","content":"hello world"}]}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputePromptHash(data)
	}
}

func BenchmarkVectorHelpers(b *testing.B) {
	vec := make([]float32, 384)
	for i := range vec {
		vec[i] = float32(i) / 384.0
	}

	b.Run("ToSQL", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = vectorToSQL(vec)
		}
	})

	sql, _ := vectorToSQL(vec)
	b.Run("FromSQL", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = vectorFromSQL(sql)
		}
	})
}

func BenchmarkSquaredL2Distance(b *testing.B) {
	a := make([]float32, 384)
	bVec := make([]float32, 384)
	for i := range a {
		a[i] = float32(i) / 384.0
		bVec[i] = float32(i+1) / 384.0
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SquaredL2Distance(a, bVec)
	}
}

func BenchmarkMakeKey(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MakeKey("org-123", "smart", "hash-abc")
	}
}
