package cli

import (
	"fmt"
	"testing"

	"github.com/reireirei/yabanin/pkg/provider"
)

// FuzzUsageAccounting covers real image, speech and reranking usage
// accounting in audioUsage, imagesUsage, rerankUsage and tokenUsageBlock
// with six named fixture templates, bounded fuzzed int64 counts and
// independently derived expectations.
func FuzzUsageAccounting(f *testing.F) {
	names := []string{"audio-prompt-details", "speech-input-completion-cached",
		"rerank-input-total-details", "image-cached-details", "usage-null", "malformed-body"}
	for i, s := range [][3]int64{{120, 45, 8}, {9, 60, 5}, {300, 12, 40}, {77, 21, 9}, {1, 1, 0}, {2, 3, 1}} {
		f.Add(uint8(i), s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, pick uint8, r1, r2, r3 int64) {
		fixture := int(pick) % len(names)
		name := names[fixture]
		in := 1 + mod(r1, 4999)
		out := 1 + mod(r2, 4999)
		total := in + out + mod(r3, 97)
		cached := mod(r1+r2, in+1)
		switch fixture {
		case 0: // prompt_tokens + output_tokens + total + prompt_tokens_details.cached_tokens
			body := []byte(fmt.Sprintf(`{"usage":{"prompt_tokens":%d,"output_tokens":%d,"total_tokens":%d,"prompt_tokens_details":{"cached_tokens":%d}}}`, in, out, total, cached))
			expectAudio(t, name, body, in, out)
			expectImages(t, name, body, 0, out, total, 0)
			expectTokens(t, name, body, in, out, total, cached)
		case 1: // input_tokens alias + completion_tokens + cached_tokens; total falls back to in+out
			body := []byte(fmt.Sprintf(`{"usage":{"input_tokens":%d,"completion_tokens":%d,"cached_tokens":%d}}`, in, out, cached))
			expectAudio(t, name, body, in, 0)
			expectImages(t, name, body, in, 0, 0, 0)
			expectTokens(t, name, body, in, out, in+out, cached)
		case 2: // input_tokens + output_tokens + total + input_token_details.cached_tokens
			body := []byte(fmt.Sprintf(`{"usage":{"input_tokens":%d,"output_tokens":%d,"total_tokens":%d,"input_token_details":{"cached_tokens":%d}}}`, in, out, total, cached))
			expectAudio(t, name, body, in, out)
			expectImages(t, name, body, in, out, total, 0)
			expectTokens(t, name, body, in, out, total, cached)
		case 3: // image shape: input_tokens_details.cached_tokens
			body := []byte(fmt.Sprintf(`{"usage":{"input_tokens":%d,"output_tokens":%d,"total_tokens":%d,"input_tokens_details":{"cached_tokens":%d}}}`, in, out, total, cached))
			expectAudio(t, name, body, in, out)
			expectImages(t, name, body, in, out, total, cached)
			expectTokens(t, name, body, in, out, total, 0)
		case 4: // usage present but null
			expectEmpty(t, name, `{"usage":null}`)
		default: // malformed JSON body
			expectEmpty(t, name, `{"usage":`)
		}
	})
}

func expectAudio(t *testing.T, name string, body []byte, wantIn, wantOut int64) {
	t.Helper()
	gotIn, gotOut, src := audioUsage(body)
	if gotIn != wantIn || gotOut != wantOut || src != provider.UsageSourceProvider {
		t.Fatalf("%s: audioUsage=(%d,%d,%q) want (%d,%d,%q)", name, gotIn, gotOut, src, wantIn, wantOut, provider.UsageSourceProvider)
	}
}

func expectImages(t *testing.T, name string, body []byte, wantIn, wantOut, wantTotal, wantCache int64) {
	t.Helper()
	u, src := imagesUsage(body)
	if u.PromptTokens != wantIn || u.CompletionTokens != wantOut || u.TotalTokens != wantTotal ||
		u.CacheReadTokens != wantCache || u.Source != provider.UsageSourceProvider || src != provider.UsageSourceProvider {
		t.Fatalf("%s: imagesUsage=(%+v,%q) want (%d,%d,%d,%d)", name, u, src, wantIn, wantOut, wantTotal, wantCache)
	}
}

func expectTokens(t *testing.T, name string, body []byte, wantIn, wantOut, wantTotal, wantCache int64) {
	t.Helper()
	want := provider.Usage{PromptTokens: wantIn, CompletionTokens: wantOut, TotalTokens: wantTotal, CacheReadTokens: wantCache, Source: provider.UsageSourceProvider}
	u, ok := tokenUsageBlock(body)
	if !ok || u != want {
		t.Fatalf("%s: tokenUsageBlock=(%+v,%v) want %+v", name, u, ok, want)
	}
	if got := rerankUsage(body); got != want {
		t.Fatalf("%s: rerankUsage=%+v want %+v", name, got, want)
	}
}

func expectEmpty(t *testing.T, name, body string) {
	t.Helper()
	if in, out, src := audioUsage([]byte(body)); in != 0 || out != 0 || src != "" {
		t.Fatalf("%s: audioUsage=(%d,%d,%q) want zeros/empty", name, in, out, src)
	}
	if u, src := imagesUsage([]byte(body)); u != (provider.Usage{}) || src != provider.UsageSourceNone {
		t.Fatalf("%s: imagesUsage=(%+v,%q) want zero/none", name, u, src)
	}
	if u, ok := tokenUsageBlock([]byte(body)); u != (provider.Usage{}) || ok {
		t.Fatalf("%s: tokenUsageBlock=(%+v,%v) want zero/false", name, u, ok)
	}
	if u := rerankUsage([]byte(body)); u != (provider.Usage{}) {
		t.Fatalf("%s: rerankUsage=%+v want zero", name, u)
	}
}

func mod(v, m int64) int64 {
	v %= m
	if v < 0 {
		v += m
	}
	return v
}
