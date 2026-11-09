package embeddings

import (
	"context"
	"testing"
)

// BenchmarkNoopClient_Embed tests the overhead of the NoopClient.
func BenchmarkNoopClient_Embed_SingleShort(b *testing.B) {
	client := &NoopClient{}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.Embed(ctx, "hello world")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNoopClient_Embed_Batch32(b *testing.B) {
	client := &NoopClient{}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.Embed(ctx, "hello world batch prompt")
		if err != nil {
			b.Fatal(err)
		}
	}
}
