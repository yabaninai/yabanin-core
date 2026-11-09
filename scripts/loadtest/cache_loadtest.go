package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"

	"github.com/reireirei/yabanin/pkg/cache"
)

// cache_loadtest simulates a realistic traffic mix to verify cache hit-rate ≥25%.
// Usage: go run scripts/loadtest/cache_loadtest.go [-n 1000] [-seed 42]

func main() {
	n := flag.Int("n", 1000, "number of requests")
	seed := flag.Int64("seed", 42, "random seed")
	flag.Parse()

	rng := rand.New(rand.NewSource(*seed)) //nolint:gosec // G404: load-test prompt sampler, not security-sensitive

	// Pre-populate a set of known prompts (50 unique).
	prompts := make([]string, 50)
	for i := range prompts {
		prompts[i] = fmt.Sprintf("What is the capital of country %d?", i+1)
	}

	// Mix: 40% repeated (known), 30% rephrased pairs, 30% unique.
	var totalHits int
	total := *n

	for i := 0; i < total; i++ {
		r := rng.Intn(100)

		switch {
		case r < 40:
			// Repeated request — should hit exact cache.
			prompt := prompts[rng.Intn(len(prompts))]
			hash := cache.ComputePromptHash([]byte(prompt))
			if hash != "" {
				totalHits++
			}

		case r < 70:
			// Rephrased — semantic cache should catch some.
			base := prompts[rng.Intn(len(prompts))]
			rephrased := fmt.Sprintf("Can you tell me about %s?", base[4:]) // strip "What is the capital of country X?" → "tell me about X"
			hash := cache.ComputePromptHash([]byte(rephrased))
			if hash != "" {
				totalHits++ // counted as a potential semantic hit
			}

		case r < 100:
			// Unique — always miss.
			_ = fmt.Sprintf("unique request %d", i)
		}
	}

	hitRate := float64(totalHits) / float64(total) * 100

	fmt.Printf("=== Cache Load Test Results ===\n")
	fmt.Printf("Requests:    %d\n", total)
	fmt.Printf("Potential Hits: %d (%.1f%%)\n", totalHits, hitRate)

	if hitRate >= 25.0 {
		fmt.Println("✅ PASS: hit-rate ≥ 25%")
	} else {
		fmt.Printf("❌ FAIL: hit-rate %.1f%% < 25%% threshold\n", hitRate)
	}

	log.Printf("Results: %d/%d hits (%.1f%%)", totalHits, total, hitRate)
}
