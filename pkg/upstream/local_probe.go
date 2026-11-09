package upstream

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/reireirei/yabanin/pkg/provider"
)

// Local probe executor: the network half of the discovery / availability /
// health split (N08-P04-T03). The pure vocabulary and composition live in
// pkg/provider (local_discovery.go); this file produces the two probe
// observations through the SAME guarded Client the request path uses, so a
// probe can never dial a host the egress policy refuses for traffic.
//
// Probes are loopback-local by nature (local runtimes), fully offline — no
// cloud access of any kind — and deterministic: the availability probe sends
// a body no runtime accepts for generation, and the health probe sends a
// one-token chat.

const (
	// DefaultLocalAvailabilityProbeTimeout bounds the reachability +
	// endpoint-presence probe (a validation exchange, no generation).
	DefaultLocalAvailabilityProbeTimeout = 5 * time.Second
	// DefaultLocalHealthProbeTimeout bounds the live serving check. A cold
	// local runtime may load the model on first request, so this is the
	// more generous of the two.
	DefaultLocalHealthProbeTimeout = 30 * time.Second
)

// localAvailabilityProbeBody is syntactically valid JSON that fails
// validation on every local runtime: it proves the route exists (any status
// except 404) without triggering a generation.
var localAvailabilityProbeBody = []byte("{}")

// LocalProbeRequest carries the registry row fields a probe run needs.
type LocalProbeRequest struct {
	// Provider is the registry row's provider name (local runtime adapter).
	Provider string
	// Model is the registry model name = the served name (locals have no
	// remap hook).
	Model string
	// APIKey is optional: local runtimes are keyless by default.
	APIKey string
	// AvailabilityTimeout / HealthTimeout override the defaults; zero keeps
	// the default.
	AvailabilityTimeout time.Duration
	HealthTimeout       time.Duration
}

// ProbeLocalAvailability checks the configured endpoint WITHOUT generating:
// it confirms the host answers and the adapter's required chat serving
// endpoint exists on it. A 404 is the only status treated as "endpoint
// missing" — every other status (400/405/422 validation refusal, 500 route
// error, 200) proves the route exists and processed the probe.
func (c *Client) ProbeLocalAvailability(ctx context.Context, timeout time.Duration) provider.LocalAvailability {
	if timeout <= 0 {
		timeout = DefaultLocalAvailabilityProbeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	path := c.adapter.Path(false)
	resp, err := c.Do(ctx, path, localAvailabilityProbeBody, "", false, nil)
	if err != nil {
		return provider.LocalAvailability{
			Probed:     true,
			HTTPStatus: 0,
			Reason:     fmt.Sprintf("endpoint %s unreachable: %v", c.baseURL, err),
		}
	}
	defer resp.Body.Close()
	status := resp.StatusCode
	if status == http.StatusNotFound {
		return provider.LocalAvailability{
			Probed:     true,
			Reachable:  true,
			HTTPStatus: status,
			Reason: fmt.Sprintf("required chat endpoint %s not found on %s (HTTP 404): the model is installed but this endpoint cannot serve it",
				path, c.baseURL),
		}
	}
	return provider.LocalAvailability{
		Probed:          true,
		Reachable:       true,
		EndpointPresent: true,
		HTTPStatus:      status,
	}
}

// ProbeLocalHealth runs the live serving check: one minimal real chat
// request (one output token) through the full adapter path — translate,
// model override, prepare, send, translate response. Success means the model
// is serving right now; failure carries the upstream's own status and error
// body verbatim in Reason (I51: the precise refusal is surfaced, never
// masked).
func (c *Client) ProbeLocalHealth(ctx context.Context, model, apiKey string, timeout time.Duration) provider.LocalHealth {
	if timeout <= 0 {
		timeout = DefaultLocalHealthProbeTimeout
	}
	body := []byte(`{"model":"health-probe","messages":[{"role":"user","content":"ping"}],"max_tokens":1,"stream":false}`)
	// The response body itself is not needed: a 200 through the translated
	// adapter path is the live-serving proof.
	_, err := c.ForwardJSONWithTimeout(ctx, body, model, apiKey, timeout)
	if err == nil {
		return provider.LocalHealth{Serving: true}
	}
	var uerr *Error
	if errors.As(err, &uerr) {
		return provider.LocalHealth{
			Serving:    false,
			HTTPStatus: uerr.Status,
			// *Error.Error() keeps the "upstream error NNN: body" shape —
			// the endpoint's own reason reaches the surface verbatim.
			Reason: fmt.Sprintf("live serving check failed: %s", uerr.Error()),
		}
	}
	return provider.LocalHealth{
		Serving: false,
		Reason:  fmt.Sprintf("live serving check failed: %v", err),
	}
}

// ProbeLocalModel composes discovery and both probes into the surfaced
// three-state row. Network discipline:
//
//   - a row that is not an installed local model is classified offline and
//     dials NOTHING (discovery is static);
//   - when availability is not met the health probe is skipped (nothing can
//     serve through a missing or unreachable endpoint);
//   - every dial goes through the guarded client (SSRF allow-list + pin
//     guard), loopback or operator-pinned only.
func (c *Client) ProbeLocalModel(ctx context.Context, req LocalProbeRequest) provider.LocalModelStatus {
	d := provider.DiscoverLocalModel(req.Provider, req.Model)
	if !d.Installed {
		// Not a local model row: classify offline, zero network.
		return provider.ClassifyLocalModel(c.baseURL, d, provider.LocalAvailability{}, nil)
	}
	a := c.ProbeLocalAvailability(ctx, req.AvailabilityTimeout)
	if !a.Met() {
		return provider.ClassifyLocalModel(c.baseURL, d, a, nil)
	}
	h := c.ProbeLocalHealth(ctx, req.Model, req.APIKey, req.HealthTimeout)
	return provider.ClassifyLocalModel(c.baseURL, d, a, &h)
}
