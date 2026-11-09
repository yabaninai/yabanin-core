package callout

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/reireirei/yabanin/pkg/circuit"
)

// Metrics follow the pkg/metrics promauto pattern; the label `endpoint` is
// the allow-listed endpoint key (scheme://host/path — see endpointKey), so
// cardinality is bounded by the operator allow-list.
var (
	calloutRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "pipeline",
			Subsystem: "callout",
			Name:      "requests_total",
			Help:      "Upstream callout HTTP requests actually sent (singleflight winners only), by endpoint.",
		},
		[]string{"endpoint"},
	)
	calloutErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "pipeline",
			Subsystem: "callout",
			Name:      "errors_total",
			Help:      "Callout step errors (network, non-2xx, contract, breaker rejections), by endpoint.",
		},
		[]string{"endpoint"},
	)
	calloutDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "pipeline",
			Subsystem: "callout",
			Name:      "duration_seconds",
			Help:      "Upstream callout round-trip latency (winners only), by endpoint.",
			Buckets:   []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"endpoint"},
	)
)

// scannerResponse is the outcome of one (shared) upstream call: the raw,
// size-capped 2xx body. Anything else is an error.
type scannerResponse struct {
	body []byte
}

// post performs the one-shot guarded HTTP call: POST application/json, no
// redirects, no retries. A non-2xx status, a wrong content-type, an
// oversized body and transport failures are all errors; a valid 2xx JSON
// body is returned. This is the ONLY place an upstream request is sent.
func (r *Runtime) post(ctx context.Context, endpoint string, body []byte, maxReply int64) (*scannerResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("callout %s: build request: %w", endpoint, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// Drop the default Go UA: the scanner does not need gateway internals.
	req.Header.Set("User-Agent", "yabanin-callout/1")

	resp, err := r.client.Do(req)
	if err != nil {
		// ctx cancellation surfaces as a plain context error either way;
		// the engine classifies timeouts from the step ctx.
		return nil, fmt.Errorf("callout %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("callout %s: unexpected status %s", endpoint, resp.Status)
	}
	ct := resp.Header.Get("Content-Type")
	media, _, ctErr := mime.ParseMediaType(ct)
	if ctErr != nil || media != "application/json" {
		return nil, fmt.Errorf("callout %s: response content-type %q: want application/json", endpoint, ct)
	}
	reply, readErr := io.ReadAll(io.LimitReader(resp.Body, maxReply+1))
	if readErr != nil {
		return nil, fmt.Errorf("callout %s: read response: %w", endpoint, readErr)
	}
	if int64(len(reply)) > maxReply {
		return nil, fmt.Errorf("callout %s: response exceeds %d bytes", endpoint, maxReply)
	}
	return &scannerResponse{body: reply}, nil
}

// call executes one deduplicated upstream call for the (endpoint, content)
// pair: concurrent identical calls within the in-flight window share the
// winner's request and verdict (singleflight; no result cache — sequential
// identical calls each hit the endpoint). Breaker admission and failure
// recording happen on the winner path; waiters inherit the shared outcome.
//
// The shared call runs under the WINNER's context: a waiter whose own step
// budget expires still returns the shared verdict, and its engine records
// the step timeout afterwards (pkg/pipeline step semantics). The call itself
// is bounded by the winner's step timeout and Deps.Timeout.
func (r *Runtime) call(ctx context.Context, cfg stepConfig, content []byte) (*scannerResponse, error) {
	br := r.breakerFor(cfg.endpoint)
	if err := br.Allow(); err != nil {
		calloutErrors.WithLabelValues(cfg.endpoint).Inc()
		return nil, fmt.Errorf("callout %s: %w", cfg.endpoint, err)
	}

	key := flightKey(cfg.endpoint, content)
	r.inFlight.Add(1)
	v, err, _ := r.flight.Do(key, func() (any, error) {
		start := time.Now()
		calloutRequests.WithLabelValues(cfg.endpoint).Inc()
		resp, err := r.post(ctx, cfg.endpoint, content, cfg.maxReply)
		d := time.Since(start)
		if err != nil {
			calloutErrors.WithLabelValues(cfg.endpoint).Inc()
			br.RecordFailure()
			return nil, err
		}
		calloutDuration.WithLabelValues(cfg.endpoint).Observe(d.Seconds())
		br.RecordSuccess() // a healthy 2xx verdict is endpoint success
		return resp, nil
	})
	r.inFlight.Add(-1)
	if err != nil {
		return nil, err
	}
	resp, ok := v.(*scannerResponse)
	if !ok {
		return nil, fmt.Errorf("callout %s: singleflight returned %T", cfg.endpoint, v)
	}
	return resp, nil
}

// flightKey scopes singleflight dedup to one (endpoint, content) pair.
// sha256 only scopes the dedup window — it carries no security property.
func flightKey(endpoint string, content []byte) string {
	sum := sha256.Sum256(content)
	return endpoint + "\x00" + hex.EncodeToString(sum[:])
}

// breakerState is a diagnostic snapshot for tests and health tooling.
func (r *Runtime) breakerState(endpoint string) (circuit.State, bool) {
	v, ok := r.breakers.Load(endpoint)
	if !ok {
		return circuit.StateClosed, false
	}
	return v.(*circuit.Breaker).State(), true
}
