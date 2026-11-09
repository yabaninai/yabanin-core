// matched: WEB-03 benchmark — the SAME traffic straight at the provider mock
// (direct) and through the Yabanin gateway, non-streaming and SSE, with
// percentile latencies and time-to-first-token.
//
// The point is a MATCHED pair: identical requests, identical mock upstream,
// back-to-back on the same host — the delta between the two cells is the
// gateway overlay (auth, credit guard, cache lookup miss-path, routing,
// lineage, event publish).
//
// Prompts are UNIQUE per request (a UUID inside the prompt) so the gateway's
// exact cache never shortcuts the path being measured. SSE cells measure
// TTFT (first "data:" frame byte) and total time.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type cell struct {
	Side  string // direct | gateway
	Mode  string // nostream | stream
	Times []time.Duration
	TTFTs []time.Duration
	Errs  int
	// Non-200 status codes seen (code→count) — published with the numbers
	// so an error cell is diagnosable, not just "errors: n".
	Statuses map[int]int
}

type result struct {
	Side string `json:"side"`
	Mode string `json:"mode"`
	N    int    `json:"n"`
	Errs int    `json:"errors"`
	// Status code → count for the errored requests (0 = transport error).
	Statuses map[int]int `json:"error_statuses,omitempty"`
	AvgMs    float64     `json:"avg_ms"`
	MinMs    float64     `json:"min_ms"`
	P50Ms    float64     `json:"p50_ms"`
	P95Ms    float64     `json:"p95_ms"`
	P99Ms    float64     `json:"p99_ms"`
	MaxMs    float64     `json:"max_ms"`
	// SSE only: time to the first "data:" frame byte.
	TTFTP50Ms float64 `json:"ttft_p50_ms,omitempty"`
	TTFTP95Ms float64 `json:"ttft_p95_ms,omitempty"`
	TTFTP99Ms float64 `json:"ttft_p99_ms,omitempty"`
}

func pct(ds []time.Duration, p float64) float64 {
	if len(ds) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	idx := int(float64(len(s)-1)*p + 0.5)
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return ms(s[idx])
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }

// defaultRequestTimeout preserves the historical behavior: matched was
// hard-coded to a 30 s client timeout (T01 inventory gap G3). The contract's
// long-response profiles (30 s/120 s answers, PRODUCT-CONTRACT §15) need an
// explicit lift via -timeout; the default stays 30 s so existing matched
// invocations are behavior-identical.
const defaultRequestTimeout = 30 * time.Second

// newClient isolates the client construction for the timeout-lift test.
func newClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

func main() {
	direct := flag.String("direct", "http://127.0.0.1:8091", "provider mock base URL")
	gateway := flag.String("gateway", "http://127.0.0.1:8082", "gateway base URL")
	key := flag.String("key", "demo-key-1234567890", "gateway API key (ignored for direct)")
	allowRemote := flag.Bool("allow-remote-target", false, "allow attaching credentials to non-loopback gateway targets")
	model := flag.String("model", "gpt-4o-mini", "model name")
	n := flag.Int("n", 200, "requests per cell")
	conc := flag.Int("c", 4, "concurrency")
	rps := flag.Float64("rps", 40, "paced requests per second (0 = unpaced); keep below the gateway per-IP limiter (50)")
	timeout := flag.Duration("timeout", defaultRequestTimeout, "per-request client timeout (default 30s; 120s+ responses need a lift, e.g. -timeout 150s)")
	flag.Parse()
	requestKey := ""
	if *key != "" {
		if shouldAttachCredentials(*gateway, *allowRemote) {
			requestKey = *key
		} else {
			log.Printf("WARNING: credential attachment to non-loopback target requires --allow-remote-target; sending gateway requests without credentials")
		}
	} else {
		log.Printf("WARNING: no API key configured; gateway requests will be sent without credentials")
	}

	client := newClient(*timeout)
	results := make([]result, 0, 4)
	for _, side := range []string{"direct", "gateway"} {
		base := *direct
		if side == "gateway" {
			base = *gateway
		}
		for _, mode := range []string{"nostream", "stream"} {
			c := runCell(client, base, side, mode, *model, requestKey, *n, *conc, *rps)
			results = append(results, summarize(c))
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(results)
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

func runCell(client *http.Client, base, side, mode, model, key string, n, conc int, rps float64) *cell {
	c := &cell{Side: side, Mode: mode}
	var wg sync.WaitGroup
	sem := make(chan struct{}, conc)
	var mu sync.Mutex
	// Pacing: the gateway enforces a per-IP token bucket (50 rps, burst
	// 100). A benchmark that trips it measures the limiter's rejections,
	// not the per-request overlay — so the default paces below it.
	interval := time.Duration(0)
	if rps > 0 {
		interval = time.Duration(float64(time.Second) / rps)
	}
	for i := 0; i < n; i++ {
		if interval > 0 {
			time.Sleep(interval)
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			stream := mode == "stream"
			// Unique prompt per request: the gateway's exact cache must not
			// shortcut the path being measured.
			body, _ := json.Marshal(map[string]any{
				"model":    model,
				"stream":   stream,
				"messages": []map[string]string{{"role": "user", "content": fmt.Sprintf("matched-bench %d %d", i, time.Now().UnixNano())}},
			})
			req, err := http.NewRequest(http.MethodPost, base+"/v1/chat/completions", bytes.NewReader(body))
			if err != nil {
				mu.Lock()
				c.Errs++
				mu.Unlock()
				return
			}
			req.Header.Set("Content-Type", "application/json")
			if side == "gateway" && key != "" {
				req.Header.Set("Authorization", "Bearer "+key)
			}
			start := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				mu.Lock()
				c.Errs++
				mu.Unlock()
				return
			}
			var ttft time.Duration
			if stream {
				br := bufio.NewReader(resp.Body)
				// TTFT is measured from the REQUEST START (before Do) —
				// the number a client experiences as time-to-first-token.
				for {
					line, err := br.ReadBytes('\n')
					if len(line) > 0 && bytes.HasPrefix(line, []byte("data:")) {
						ttft = time.Since(start)
						break
					}
					if err != nil {
						break
					}
				}
				_, _ = io.Copy(io.Discard, br) // drain the rest
			} else {
				_, _ = io.Copy(io.Discard, resp.Body)
			}
			_ = resp.Body.Close()
			total := time.Since(start)
			if resp.StatusCode != http.StatusOK {
				mu.Lock()
				c.Errs++
				if c.Statuses == nil {
					c.Statuses = map[int]int{}
				}
				c.Statuses[resp.StatusCode]++
				mu.Unlock()
				return
			}
			mu.Lock()
			c.Times = append(c.Times, total)
			// ttft==0 means no "data:" frame was ever matched (a
			// non-SSE upstream answers stream:true with a single JSON) —
			// recording it would publish a fake 0ms TTFT.
			if stream && ttft > 0 {
				c.TTFTs = append(c.TTFTs, ttft)
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	return c
}

func summarize(c *cell) result {
	r := result{Side: c.Side, Mode: c.Mode, N: len(c.Times), Errs: c.Errs, Statuses: c.Statuses}
	if r.N == 0 {
		return r
	}
	var sum float64
	minV := c.Times[0]
	for _, d := range c.Times {
		sum += ms(d)
		if d < minV {
			minV = d
		}
	}
	r.AvgMs = sum / float64(r.N)
	r.MinMs = ms(minV)
	r.P50Ms = pct(c.Times, 0.50)
	r.P95Ms = pct(c.Times, 0.95)
	r.P99Ms = pct(c.Times, 0.99)
	r.MaxMs = ms(c.Times[len(c.Times)-1])
	for _, d := range c.Times {
		if ms(d) > r.MaxMs {
			r.MaxMs = ms(d)
		}
	}
	if len(c.TTFTs) > 0 {
		r.TTFTP50Ms = pct(c.TTFTs, 0.50)
		r.TTFTP95Ms = pct(c.TTFTs, 0.95)
		r.TTFTP99Ms = pct(c.TTFTs, 0.99)
	}
	return r
}
