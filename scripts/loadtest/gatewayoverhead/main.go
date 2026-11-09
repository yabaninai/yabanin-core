// Command gatewayoverhead is the RM-105 gateway overhead benchmark tool.
//
// It has two subcommands:
//
//	mock   — deterministic OpenAI-compatible upstream (fixed response,
//	         optional fixed first-byte delay, JSON and SSE).
//	bench  — load generator that measures end-to-end latency (JSON) and
//	         time-to-first-token (SSE) against a target base URL.
//
// The benchmark methodology pairs two runs of this same tool against
// (1) the mock upstream directly and (2) the same mock upstream behind the
// gateway; the reported gateway overhead is the percentile difference
// (gateway − direct). Stdlib only: the tool must stay dependency-free.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// fixedPrompt is the single deterministic user prompt used for every request
// (~1 KB): identical bytes are required for exact-cache hit measurement.
var fixedPrompt = strings.Repeat(
	"You are a latency benchmark probe. Reply with one short deterministic sentence. ", 12)

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "mock":
		runMock(os.Args[2:])
	case "bench":
		runBench(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gatewayoverhead mock|-addr :8081 [-delay 0s]\n"+
		"       gatewayoverhead bench -target http://host:port -mode json|sse [-n 300] [-c 4] [-warmup 30] [-out file.json]")
}

// ---- mock upstream ----

func runMock(args []string) {
	fs := flag.NewFlagSet("mock", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:14650", "listen address")
	delay := fs.Duration("delay", 0, "fixed artificial delay before the first response byte")
	fs.Parse(args) //nolint:errcheck // ExitOnError

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`) //nolint:errcheck // client may hang up; nothing to log
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req chatRequest
		body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
		if err != nil || json.Unmarshal(body, &req) != nil {
			// The mock answers every well-formed POST identically; an
			// undecodable body still gets the fixed response so the load
			// generator never measures mock-side parse failures.
			req = chatRequest{}
		}
		if *delay > 0 {
			time.Sleep(*delay)
		}
		if req.Stream {
			writeMockStream(w)
			return
		}
		writeMockJSON(w)
	})

	log.Printf("mock upstream listening on %s (delay=%s)", *addr, *delay)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("mock server failed: %v", err)
	}
}

func writeMockJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]any{
		"id":      "chatcmpl-bench",
		"object":  "chat.completion",
		"created": 1720000000,
		"model":   "bench-model",
		"choices": []any{map[string]any{
			"index":         0,
			"message":       map[string]any{"role": "assistant", "content": "Deterministic benchmark reply."},
			"finish_reason": "stop",
		}},
		"usage": map[string]any{"prompt_tokens": 256, "completion_tokens": 8, "total_tokens": 264},
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// writeMockStream emits 16 delta chunks, a terminal stop chunk with usage,
// and [DONE], flushing after every frame (streaming contract).
func writeMockStream(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	for i := 0; i < 16; i++ {
		fmt.Fprintf(w, "data: {\"id\":\"chatcmpl-bench\",\"object\":\"chat.completion.chunk\",\"created\":1720000000,\"model\":\"bench-model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" tok%d\"},\"finish_reason\":null}]}\n\n", i)
		flusher.Flush()
	}
	fmt.Fprint(w, "data: {\"id\":\"chatcmpl-bench\",\"object\":\"chat.completion.chunk\",\"created\":1720000000,\"model\":\"bench-model\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":256,\"completion_tokens\":16,\"total_tokens\":272}}\n\n")
	flusher.Flush()
	fmt.Fprint(w, "data: [DONE]\n\n")
	flusher.Flush()
}

// ---- bench client ----

type result struct {
	Target         string         `json:"target"`
	Mode           string         `json:"mode"`
	Requests       int            `json:"requests"`
	Concurrency    int            `json:"concurrency"`
	RateLimit      float64        `json:"rate_limit_rps"`
	Errors         int            `json:"errors"`
	ErrorReason    map[string]int `json:"error_reason,omitempty"`
	LatencyMS      []float64      `json:"latency_ms"`
	TTFTMS         []float64      `json:"ttft_ms,omitempty"`
	CacheHeaders   map[string]int `json:"cache_headers,omitempty"`
	StartedAt      string         `json:"started_at"`
	DurationSec    float64        `json:"duration_sec"`
	RequestsPerSec float64        `json:"requests_per_sec"`
}

func runBench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	target := fs.String("target", "", "base URL, e.g. http://127.0.0.1:14651")
	mode := fs.String("mode", "json", "json | sse")
	n := fs.Int("n", 300, "measured requests")
	c := fs.Int("c", 4, "concurrent workers")
	warmup := fs.Int("warmup", 30, "unmeasured warmup requests")
	rps := fs.Float64("rps", 0, "aggregate request pacing (0 = unlimited)")
	out := fs.String("out", "", "optional path for the full JSON result")
	apiKey := fs.String("api-key", os.Getenv("BENCH_API_KEY"), "bearer token")
	allowRemote := fs.Bool("allow-remote-target", false, "allow attaching credentials to non-loopback targets")
	fs.Parse(args) //nolint:errcheck // ExitOnError

	if *target == "" || (*mode != "json" && *mode != "sse") || *n < 1 || *c < 1 {
		usage()
		os.Exit(2)
	}
	requestKey := ""
	if *apiKey != "" {
		if shouldAttachCredentials(*target, *allowRemote) {
			requestKey = *apiKey
		} else {
			log.Printf("WARNING: credential attachment to non-loopback target requires --allow-remote-target; sending requests without credentials")
		}
	} else {
		log.Printf("WARNING: no API key configured; sending requests without credentials")
	}

	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        *c * 2,
			MaxIdleConnsPerHost: *c,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	body := mustPayload(*mode)

	// Optional global pacing: every request (warmup included) first takes a
	// ticket from one ticker, so the aggregate rate never exceeds rps. The
	// benchmark stays under the gateway's production per-IP limiter this way.
	var tickets chan time.Time
	stopPace := func() {}
	if *rps > 0 {
		tickets = make(chan time.Time)
		stop := make(chan struct{})
		go func() {
			t := time.NewTicker(time.Duration(float64(time.Second) / *rps))
			defer t.Stop()
			for {
				select {
				case ts := <-t.C:
					tickets <- ts
				case <-stop:
					return
				}
			}
		}()
		stopPace = func() { close(stop) }
		defer stopPace()
	}
	awaitTicket := func() {
		if tickets != nil {
			<-tickets
		}
	}

	do := func() error { return oneRequest(client, *target, *mode, body, requestKey, nil) }

	// Warmup: fill caches/pools; results are discarded.
	for i := 0; i < *warmup; i++ {
		awaitTicket()
		if err := do(); err != nil {
			log.Fatalf("warmup request %d failed: %v", i+1, err)
		}
	}

	res := result{
		Target: *target, Mode: *mode, Requests: *n, Concurrency: *c, RateLimit: *rps,
		ErrorReason: map[string]int{}, CacheHeaders: map[string]int{},
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	start := time.Now()
	work := make(chan int, *n)
	for i := 0; i < *n; i++ {
		work <- i
	}
	close(work)

	var mu sync.Mutex
	var wg sync.WaitGroup
	for w := 0; w < *c; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range work {
				awaitTicket()
				lat := sample{}
				err := oneRequest(client, *target, *mode, body, requestKey, &lat)
				mu.Lock()
				if err != nil {
					res.Errors++
					res.ErrorReason[err.Error()]++
				} else {
					res.LatencyMS = append(res.LatencyMS, lat.totalMS)
					if *mode == "sse" {
						res.TTFTMS = append(res.TTFTMS, lat.ttftMS)
					}
					if lat.cache != "" {
						res.CacheHeaders[lat.cache]++
					}
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	res.DurationSec = time.Since(start).Seconds()
	res.RequestsPerSec = float64(*n) / res.DurationSec

	printSummary(res)
	if *out != "" {
		data, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			log.Fatalf("marshal result: %v", err)
		}
		if err := os.WriteFile(*out, data, 0o600); err != nil {
			log.Fatalf("write result: %v", err)
		}
	}
	if res.Errors > 0 {
		os.Exit(1)
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

type sample struct {
	totalMS float64
	ttftMS  float64
	cache   string
}

func mustPayload(mode string) []byte {
	b, err := json.Marshal(chatRequest{
		Model:    "bench-model",
		Messages: []chatMessage{{Role: "user", Content: fixedPrompt}},
		Stream:   mode == "sse",
	})
	if err != nil {
		log.Fatalf("marshal payload: %v", err)
	}
	return b
}

// oneRequest performs one chat completion and fills the sample. For SSE the
// total is time to [DONE] and ttft is time to the first response byte; for
// JSON the total is time to a fully read body.
func oneRequest(client *http.Client, target, mode string, body []byte, apiKey string, s *sample) error {
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(target, "/")+"/v1/chat/completions", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	t0 := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if mode == "sse" {
		if resp.StatusCode != http.StatusOK {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) //nolint:errcheck // draining an error body
			return fmt.Errorf("status %d", resp.StatusCode)
		}
		first := true
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			if first {
				if s != nil {
					s.ttftMS = float64(time.Since(t0).Microseconds()) / 1000
				}
				first = false
			}
			if strings.TrimSpace(sc.Text()) == "data: [DONE]" {
				break
			}
		}
		if err := sc.Err(); err != nil {
			return err
		}
		if first {
			return fmt.Errorf("empty stream")
		}
	} else {
		if resp.StatusCode != http.StatusOK {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) //nolint:errcheck // draining an error body
			return fmt.Errorf("status %d", resp.StatusCode)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			return err
		}
	}
	if s != nil {
		s.totalMS = float64(time.Since(t0).Microseconds()) / 1000
		s.cache = strings.ToLower(resp.Header.Get("X-Cache"))
	}
	return nil
}

func printSummary(res result) {
	p := func(v []float64, q float64) float64 {
		if len(v) == 0 {
			return 0
		}
		sort.Float64s(v)
		idx := int(math.Ceil(q/100*float64(len(v)))) - 1
		if idx < 0 {
			idx = 0
		}
		return v[idx]
	}
	if res.Errors > 0 {
		reasons := ""
		first := true
		for reason, count := range res.ErrorReason {
			if !first {
				reasons += ","
			}
			reasons += fmt.Sprintf("%s=%d", reason, count)
			first = false
		}
		log.Printf("RESULT mode=%s errors=%d reasons={%s} (target %s)", res.Mode, res.Errors, reasons, res.Target)
		return
	}
	line := fmt.Sprintf("RESULT mode=%s n=%d c=%d rps=%.0f errs=0 p50=%.3f p95=%.3f p99=%.3f mean=%.3f wall_rps=%.1f",
		res.Mode, res.Requests, res.Concurrency, res.RateLimit,
		p(res.LatencyMS, 50), p(res.LatencyMS, 95), p(res.LatencyMS, 99), mean(res.LatencyMS), res.RequestsPerSec)
	if res.Mode == "sse" {
		line += fmt.Sprintf(" ttft_p50=%.3f ttft_p95=%.3f ttft_p99=%.3f",
			p(res.TTFTMS, 50), p(res.TTFTMS, 95), p(res.TTFTMS, 99))
	}
	if len(res.CacheHeaders) > 0 {
		line += " cache={"
		first := true
		for k, v := range res.CacheHeaders {
			if !first {
				line += ","
			}
			line += fmt.Sprintf("%s=%d", k, v)
			first = false
		}
		line += "}"
	}
	log.Print(line)
}

func mean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	var sum float64
	for _, x := range v {
		sum += x
	}
	return sum / float64(len(v))
}
