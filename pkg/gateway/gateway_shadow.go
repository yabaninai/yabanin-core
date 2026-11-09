package cli

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/shadow"
)

// maybeShadow fires a detached shadow call AFTER the primary (non-streaming)
// response has been written to the client (mandatory passthrough: nothing here
// can affect the client's bytes). The body must be a parseable non-streaming
// chat completion; stream=true is handled by maybeShadowStream instead.
func (gw *gateway) maybeShadow(r *http.Request, body []byte, model, orgID, teamID, sessionID, reqID string) {
	if gw.shadow == nil {
		return
	}
	var req struct {
		Stream bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Stream {
		return // not a parseable non-streaming body — the stream path owns it
	}
	gw.fireShadow(r.Context(), body, model, orgID, teamID, sessionID, reqID)
}

// maybeShadowStream fires a detached shadow call for a STREAMING primary, after
// the upstream connection succeeded (mandatory passthrough: the client's SSE
// bytes are unaffected — the shadow is a separate non-streaming request to the
// candidate, fired in its own goroutine). buildShadowJob forces "stream": false
// into the shadow body, so the candidate gets a plain completion regardless of
// how the primary was served.
func (gw *gateway) maybeShadowStream(ctx context.Context, body []byte, model, orgID, teamID, sessionID, reqID string) {
	if gw.shadow == nil {
		return
	}
	// The body is a chat completion (streaming or not); buildShadowJob rewrites
	// model + forces stream:false. A non-parseable body degrades to an empty
	// job, which shadow.Run skips — no panic, no client impact.
	gw.fireShadow(ctx, body, model, orgID, teamID, sessionID, reqID)
}

// fireShadow is the shared decision + dispatch core for both the streaming and
// non-streaming hooks. It runs the mirror gate, and when the request is
// mirrored, fires one detached shadow call. It never blocks the caller beyond
// the (cheap) gate checks and never affects the client's response.
func (gw *gateway) fireShadow(ctx context.Context, body []byte, model, orgID, teamID, sessionID, reqID string) {
	mirror, skipReason := gw.shadow.ShouldMirror(ctx, model, orgID)
	if !mirror {
		if skipReason != shadow.SkipNone {
			shadow.SkippedTotal.WithLabelValues(skipReason).Inc()
		}
		return
	}

	// RT-03: the shadow target is a real provider call paid by the gateway —
	// it is gated like every other secondary candidate under the request's
	// trusted identity. A denied/unavailable shadow candidate makes no call,
	// emits no shadow event, and is counted under its own skip reason.
	// RT-06: resolution runs under the request context; an unavailable
	// registry skips the optional shadow entirely (no degraded candidate).
	sc := gw.cfg.Shadow
	shadowInfo, resErr := gw.resolveModelInfo(ctx, sc.Model)
	if resErr != nil {
		gw.log.Debug("shadow: target model resolution failed, skipping", "error", resErr, "model", sc.Model)
		return
	}
	if _, pol := gw.gateAttemptCandidate(ctx, candidateIdentity{OrgID: orgID, TeamID: teamID, APIKeyID: eventKeyID(ctx)}, sc.Model, shadowInfo); pol != nil {
		shadow.SkippedTotal.WithLabelValues(shadow.SkipPolicy).Inc()
		return
	}

	l := gw.log.With("component", "shadow")
	job := gw.buildShadowJob(ctx, body, model, orgID, teamID, sessionID, reqID, l)

	// Fire-and-forget. The goroutine must not inherit the request context
	// (client cancellation would kill the shadow call mid-flight); shadow.Run
	// builds its own context.Background() + timeout and recovers panics.
	go gw.shadow.Run(job) //nolint:contextcheck // detached by design: shadow survives request cancellation; Run has its own timeout + recover
}

// buildShadowJob assembles the provider-agnostic job. The Call closure makes
// exactly one upstream HTTP call to the shadow target with the shadow model
// forced into the body; it never touches the primary request or response.
func (gw *gateway) buildShadowJob(ctx context.Context, body []byte, model, orgID, teamID, sessionID, reqID string, l *slog.Logger) shadow.Job {
	sc := gw.cfg.Shadow

	// Rewrite the model field to the shadow target, preserving all other
	// client fields (temperature, tools, ...).
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		m = map[string]interface{}{}
	}
	m["model"] = sc.Model
	m["stream"] = false
	shadowBody, err := json.Marshal(m)
	if err != nil {
		l.Debug("shadow: body rewrite failed", "error", err)
		return shadow.Job{}
	}

	// Usage parsing + cost use the shadow model's own adapter (the shadow
	// target is what produced the tokens; its adapter knows its schema).
	providerName := providerForModel(ctx, gw, sc.Model)
	adapter, _ := provider.New(providerName)

	return shadow.Job{
		RequestID:    reqID,
		SessionID:    sessionID,
		OrgID:        orgID,
		TeamID:       teamID,
		PrimaryModel: model,
		ShadowModel:  sc.Model,
		Body:         shadowBody,
		Call: func(ctx context.Context) ([]byte, error) {
			url := sc.UpstreamURL
			if url == "" {
				url = gw.cfg.Provider
			}
			key := sc.APIKey
			if key == "" {
				key = gw.getUpstreamAPIKey()
			}
			client, err := gw.pool.Get(url, providerName)
			if err != nil {
				return nil, fmt.Errorf("shadow upstream client for %s: %w", providerName, err)
			}
			return client.ForwardJSON(ctx, shadowBody, sc.Model, key)
		},
		ParseUsage: func(b []byte) provider.Usage {
			if adapter == nil {
				return provider.Usage{}
			}
			return adapter.ParseUsage(b)
		},
		ComputeCost: func(u provider.Usage, _, modelName string) float64 {
			return provider.ComputeCost(u, providerName, modelName).EstimatedCostUSD
		},
		Publish: func(ev *eventpub.Event) { //nolint:contextcheck // publishEvent creates its own timeout context internally — standard pattern in gateway
			// Bounded, retrying publisher (50-slot semaphore, 2s timeout,
			// 3 retries) — same delivery guarantees as primary events.
			publishEvent(gw.publisher, l, ev)
		},
	}
}

// providerForModel returns the provider adapter name for a model: the
// resolver's registry when available, else "openai" (the pool default). A
// registry failure (outage or cancelled context) degrades to the default —
// this name only selects the usage-parsing adapter for an optional shadow.
func providerForModel(ctx context.Context, gw *gateway, model string) string {
	if gw.res != nil {
		info, err := gw.res.ResolveChecked(ctx, model)
		if err == nil && info.Provider != "" {
			return info.Provider
		}
	}
	return "openai"
}

// shadowAdminBearer is the fail-closed constant-time bearer check for the
// shadow admin endpoints (S4). Unlike /metrics (network-restriction-only
// when no key is set), a cost-bearing control REQUIRES the key: empty
// MetricsBearerKey ⇒ 403.
func shadowAdminBearer(cfgKey string, r *http.Request) bool {
	if cfgKey == "" {
		return false
	}
	token := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(token) <= len(prefix) {
		return false
	}
	token = token[len(prefix):]
	return subtle.ConstantTimeCompare([]byte(token), []byte(cfgKey)) == 1
}

// registerShadowAdmin mounts the runtime kill-switch on the gateway admin
// listener:
//
//	GET  /admin/shadow/status  → operator view (never leaks the API key)
//	POST /admin/shadow/toggle  → {"enabled": true|false}
//
// Auth: Bearer <YABANIN_METRICS_BEARER_KEY>, constant-time, fail-closed
// (no key configured ⇒ 403 for both). The toggle is process-local: a
// restart resets state to the env config. Multi-replica operators toggle
// each replica (v9 scope; shared state is frozen).
func (gw *gateway) registerShadowAdmin(r chi.Router, l *slog.Logger) {
	if gw.shadow == nil {
		// Shadow not configured: still mount the routes so operators get a
		// clear 409 instead of a 404 that reads as "endpoint missing".
		r.Get("/admin/shadow/status", func(w http.ResponseWriter, req *http.Request) {
			writeShadowJSON(w, http.StatusConflict, map[string]string{
				"error": "shadow-mode is not configured (YABANIN_SHADOW_ENABLED=false)",
			})
		})
		r.Post("/admin/shadow/toggle", func(w http.ResponseWriter, req *http.Request) {
			writeShadowJSON(w, http.StatusConflict, map[string]string{
				"error": "shadow-mode is not configured (YABANIN_SHADOW_ENABLED=false)",
			})
		})
		return
	}
	key := gw.cfg.MetricsBearerKey
	auth := func(w http.ResponseWriter, req *http.Request) bool {
		if !shadowAdminBearer(key, req) {
			writeShadowJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized"})
			return false
		}
		return true
	}
	r.Get("/admin/shadow/status", func(w http.ResponseWriter, req *http.Request) {
		if !auth(w, req) {
			return
		}
		writeShadowJSON(w, http.StatusOK, gw.shadow.Status())
	})
	r.Post("/admin/shadow/toggle", func(w http.ResponseWriter, req *http.Request) {
		if !auth(w, req) {
			return
		}
		var body struct {
			Enabled *bool `json:"enabled"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body.Enabled == nil {
			writeShadowJSON(w, http.StatusBadRequest, map[string]string{
				"error": `body must be {"enabled": true|false}`,
			})
			return
		}
		gw.shadow.SetEnabled(*body.Enabled)
		l.Info("shadow-mode toggled at runtime", "enabled", *body.Enabled)
		writeShadowJSON(w, http.StatusOK, gw.shadow.Status())
	})
}

func writeShadowJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("shadow admin: encode failed", "error", err)
	}
}
