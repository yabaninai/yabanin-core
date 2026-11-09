package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

//go:generate go build -o cache_loadtest .

// cache_loadtest_http sends real HTTP requests through the gateway and
// measures cache hit-rate by parsing X-Cache response headers.
func main() {
	gateway := flag.String("gateway", "http://localhost:8082", "gateway base URL")
	apiKey := flag.String("api-key", "yabanin-dev-key", "API key for auth")
	allowRemote := flag.Bool("allow-remote-target", false, "allow attaching credentials to non-loopback targets")
	_ = flag.String("org", "", "org_id (UUID, unused in v1)")
	rps := flag.Int("rps", 20, "requests per second")
	duration := flag.Duration("duration", 2*time.Minute, "test duration")
	mixFile := flag.String("mix", "", "path to rephrased_pairs.json (empty = use built-in prompts)")
	flag.Parse()
	requestKey := ""
	if *apiKey != "" {
		if shouldAttachCredentials(*gateway, *allowRemote) {
			requestKey = *apiKey
		} else {
			log.Printf("WARNING: credential attachment to non-loopback target requires --allow-remote-target; sending requests without credentials")
		}
	} else {
		log.Printf("WARNING: no API key configured; sending requests without credentials")
	}

	prompts := loadPrompts(*mixFile)
	if len(prompts) == 0 {
		log.Fatal("no prompts loaded — check -mix file or builtin set")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	var totalHits, exactHits, semanticHits, misses int
	var latencies []time.Duration

	start := time.Now()
	interval := time.Second / time.Duration(*rps)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for reqNum := 0; reqNum < 2000; reqNum++ { // safety cap
		if time.Since(start) > *duration {
			break
		}
		<-ticker.C

		prompt := prompts[reqNum%len(prompts)]
		body := map[string]interface{}{
			"model": "smart",
			"messages": []map[string]string{
				{"role": "user", "content": prompt},
			},
		}
		payload, _ := json.Marshal(body)

		req, _ := http.NewRequest("POST", *gateway+"/v1/chat/completions", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		if requestKey != "" {
			req.Header.Set("Authorization", "Bearer "+requestKey)
		}

		t0 := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("request %d failed: %v", reqNum, err)
			continue
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck // load-test drain; a short read only skews stats
		resp.Body.Close()
		latency := time.Since(t0)
		latencies = append(latencies, latency)

		cacheHeader := strings.ToLower(resp.Header.Get("X-Cache"))
		switch cacheHeader {
		case "exact", "pg_exact":
			exactHits++
			totalHits++
		case "semantic":
			semanticHits++
			totalHits++
		default:
			misses++
		}

		if (reqNum+1)%50 == 0 {
			rate := float64(totalHits) / float64(reqNum+1) * 100
			log.Printf("progress: %d/%d requests, hit-rate=%.1f%% (exact=%d semantic=%d miss=%d)",
				reqNum+1, reqNum+1, rate, exactHits, semanticHits, misses)
		}
	}

	total := totalHits + misses
	if total == 0 {
		fmt.Println("NO REQUESTS COMPLETED")
		os.Exit(1)
	}

	rate := float64(totalHits) / float64(total) * 100
	log.Printf("\n===== Results =====")
	log.Printf("Total requests: %d", total)
	log.Printf("Cache hits:     %d (%.1f%%)", totalHits, rate)
	log.Printf("  Exact:        %d", exactHits)
	log.Printf("  Semantic:     %d", semanticHits)
	log.Printf("Cache misses:   %d", misses)

	if len(latencies) > 0 {
		var sum time.Duration
		for _, l := range latencies {
			sum += l
		}
		avgMs := float64(sum.Milliseconds()) / float64(len(latencies))
		log.Printf("Avg latency:    %.0fms", avgMs)
	}

	fmt.Printf("hit_rate=%.2f\n", rate/100)
	fmt.Printf("exact_hits=%d\n", exactHits)
	fmt.Printf("semantic_hits=%d\n", semanticHits)
	fmt.Printf("misses=%d\n", misses)

	if rate < 25.0 {
		log.Printf("WARNING: hit-rate %.1f%% < 25%% (P4 control point)", rate)
	} else {
		log.Printf("PASS: hit-rate %.1f%% >= 25%% (P4 control point met)", rate)
	}
}

func shouldAttachCredentials(target string, allowRemote bool) bool {
	parsed, err := url.Parse(target)
	if err == nil && hostIsLoopback(parsed.Hostname()) {
		return true
	}
	return allowRemote
}

func hostIsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func loadPrompts(mixFile string) []string {
	if mixFile != "" {
		data, err := os.ReadFile(mixFile)
		if err == nil {
			var pairs []struct {
				Base      string   `json:"base"`
				Rephrased []string `json:"rephrased"`
			}
			json.Unmarshal(data, &pairs)

			prompts := make([]string, 0, len(pairs)*4)
			for _, p := range pairs {
				prompts = append(prompts, p.Base)
				for _, r := range p.Rephrased {
					prompts = append(prompts, r)
				}
			}
			if len(prompts) > 0 {
				return prompts
			}
		}
	}

	// Fallback: built-in prompt set (10 base prompts, repeated to ensure cache hits).
	prompts := make([]string, 0, 30)
	for i := 1; i <= 10; i++ {
		base := fmt.Sprintf("What is the capital of country %d?", i)
		prompts = append(prompts, base)
		// Add rephrased variants (semantic cache should catch these).
		if i%2 == 0 {
			prompts = append(prompts, fmt.Sprintf("Can you tell me the capital city of nation number %d?", i))
		} else {
			prompts = append(prompts, fmt.Sprintf("Name the main city of country #%d", i))
		}
	}
	return prompts
}
