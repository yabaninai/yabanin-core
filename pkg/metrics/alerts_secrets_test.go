package metrics_test

// N13-P04-T05 part 2 — the no-secrets-in-alert-message invariant.
//
// Alert annotations (summary + description) are exactly what Alertmanager
// delivers to pagers, chat channels and email. This file locks the
// invariant that no attacker-controlled or secret-shaped material can reach
// them, by three cumulative mechanisms over the REAL rules file:
//
//  1. Template allowlist — every `{{ ... }}` action across all annotations
//     must be one of: `$value` (optionally piped through humanize /
//     humanizePercentage / humanizeDuration, prefix or pipe form), or
//     `$labels.<name>` for a name on the declared-safe list. Every safe
//     label's VALUE source is documented and bounded: closed enums
//     (place/reason from the silent-failure registry, op from the
//     regionrouter set, scope_kind from the pkg/budget ScopeKind
//     constants) or operator-fed config (upstream url, scrape instance).
//     Nothing else — never path-like request identifiers, never query
//     strings, never header material, never .CommonLabels/query/env.
//
//  2. Canary poisoning — for every alert, the fired-vector label space is
//     poisoned with canary credential-shaped material on every label the
//     templates do NOT reference (attacker-influenceable vectors: path,
//     query, method, status, model, org, ids, authorization-style names),
//     while the referenced labels hold their real bounded values. The
//     rendered messages must contain neither the canary nor any generic
//     secret shape. The alert value itself is typed float64, so textual
//     canary material cannot enter through $value at all — renders with
//     NaN/±Inf/huge values pin that down.
//
//  3. Closed-space enumeration — for the alerts whose messages interpolate
//     closed-enum labels, EVERY reachable message is rendered and scanned:
//     all 23 registered silent-failure (place, reason) pairs (each driven
//     through the real closed registry — an unregistered pair panics, so
//     removals are caught mechanically), both regionrouter ops, and all
//     four pkg/budget ScopeKind constants.
//
// Plus a static scan: the rules file's own annotations must not carry
// secret-shaped literals (hardcoded credentials would ship to every
// notification channel).
//
// Disclosed deltas vs the real Alertmanager template engine: the renderer
// below accepts exactly the allowlisted actions — it IS the enforcement of
// mechanism 1 — and its number formatting approximates prometheus humanize
// with Go %g; formatting fidelity is irrelevant to the invariant (the scans
// look for credential-shaped TEXT, and $value is typed float64). What is
// exact: the rejection of every non-allowlisted action, and the value
// sources of every interpolated label.

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/metrics"
)

// canaryMaterial mimics a credential: recognizable marker + a 32-hex run
// (the hex run alone trips the generic secret-shape scan, the marker makes
// leak attribution unambiguous).
const canaryMaterial = "CANARY-3f9a1c7e5b2d8046a1b3c5d7e9f0a2b4"

// secretShapeRes are generic credential shapes (not tied to any provider):
// long hex/base64 runs, key=value assignments for classic secret keywords,
// PEM headers, bearer tokens and common provider key prefixes. They must
// match NO rendered alert message.
var secretShapeRes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b[0-9a-f]{32,}\b`),
	regexp.MustCompile(`\b[A-Za-z0-9+/]{40,}={0,2}\b`),
	regexp.MustCompile(`(?i)\b(password|passwd|secret|api[_-]?key|token|authorization)\b\s*[:=]\s*\S{6,}`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._-]{16,}`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9]{16,}\b`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`),
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`),
}

// safeLabelRefs is the declared-safe list of label references an annotation
// template may use, with the value source that makes each one safe. Label
// names outside this list are rejected by the renderer and by the explicit
// template walk.
var safeLabelRefs = map[string]string{
	"url":        "operator upstream registry (config-fed endpoint URL, not a credential)",
	"upstream":   "operator upstream registry (config-fed endpoint URL)",
	"instance":   "prometheus scrape target (exporter-fed, operator config)",
	"place":      "closed silent-failure registry (bounded enum, enumerated in this file)",
	"reason":     "closed silent-failure registry (bounded enum per place, enumerated in this file)",
	"op":         "closed regionrouter op set {set, del}",
	"scope_kind": "pkg/budget ScopeKind constants (four, locked below)",
}

// ---------------------------------------------------------------------------
// Alertmanager-shaped renderer over the allowlisted action grammar.
// ---------------------------------------------------------------------------

// renderAnnotation renders one annotation template with the given labels and
// value. It rejects every action outside the allowlist — the rejection is
// the security boundary; the numeric formatting only approximates the
// prometheus humanize functions.
func renderAnnotation(tmpl string, labels map[string]string, value float64) (string, error) {
	var b strings.Builder
	for {
		i := strings.Index(tmpl, "{{")
		if i < 0 {
			b.WriteString(tmpl)
			return b.String(), nil
		}
		j := strings.Index(tmpl[i:], "}}")
		if j < 0 {
			return "", fmt.Errorf("unterminated {{ action")
		}
		b.WriteString(tmpl[:i])
		action := strings.TrimSpace(tmpl[i+2 : i+j])
		out, err := evalTemplateAction(action, labels, value)
		if err != nil {
			return "", fmt.Errorf("action %q: %w", action, err)
		}
		b.WriteString(out)
		tmpl = tmpl[i+j+2:]
	}
}

func evalTemplateAction(action string, labels map[string]string, value float64) (string, error) {
	// $value, optionally piped
	if strings.HasPrefix(action, "$value") {
		rest := strings.TrimSpace(strings.TrimPrefix(action, "$value"))
		if rest == "" {
			return strconv.FormatFloat(value, 'g', -1, 64), nil
		}
		if !strings.HasPrefix(rest, "|") {
			return "", fmt.Errorf("only a pipe may follow $value")
		}
		pipe := strings.TrimSpace(strings.TrimPrefix(rest, "|"))
		fn, ok := safeValuePipes[pipe]
		if !ok {
			return "", fmt.Errorf("pipe %q is not allowlisted", pipe)
		}
		return fn(value), nil
	}
	// function-prefix form: humanizeXxx $value
	for name, fn := range safeValuePipes {
		if strings.HasPrefix(action, name+" ") {
			arg := strings.TrimSpace(strings.TrimPrefix(action, name))
			if arg != "$value" {
				return "", fmt.Errorf("argument %q is not $value", arg)
			}
			return fn(value), nil
		}
	}
	// $labels.<name>
	if strings.HasPrefix(action, "$labels.") {
		name := strings.TrimPrefix(action, "$labels.")
		if _, ok := safeLabelRefs[name]; !ok {
			return "", fmt.Errorf("label %q is not on the declared-safe list", name)
		}
		return labels[name], nil
	}
	return "", fmt.Errorf("unsupported template action")
}

var safeValuePipes = map[string]func(float64) string{
	"humanize":           humanizeValue,
	"humanizePercentage": humanizePercentage,
	"humanizeDuration":   humanizeDuration,
}

func fmtNum(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return strconv.FormatFloat(v, 'g', -1, 64) // "NaN", "+Inf"
	}
	return strconv.FormatFloat(v, 'g', 4, 64)
}

// humanizeValue approximates prometheus humanize: %.4g with SI-ish
// thousand suffixes.
func humanizeValue(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return fmtNum(v)
	}
	suffix := ""
	switch abs := math.Abs(v); {
	case abs >= 1e12:
		v, suffix = v/1e12, "T"
	case abs >= 1e9:
		v, suffix = v/1e9, "B"
	case abs >= 1e6:
		v, suffix = v/1e6, "M"
	case abs >= 1e3:
		v, suffix = v/1e3, "k"
	}
	return strconv.FormatFloat(v, 'g', 4, 64) + suffix
}

// humanizePercentage approximates prometheus humanizePercentage: value
// scaled to percent.
func humanizePercentage(v float64) string {
	return strconv.FormatFloat(v*100, 'g', 4, 64) + "%"
}

// humanizeDuration approximates prometheus humanizeDuration coarsely
// (seconds→ms/s/m/h/d buckets); fidelity is irrelevant to the invariant.
func humanizeDuration(v float64) string {
	switch {
	case math.Abs(v) < 1:
		return fmtNum(v*1000) + "ms"
	case math.Abs(v) < 60:
		return fmtNum(v) + "s"
	case math.Abs(v) < 3600:
		return fmtNum(v/60) + "m"
	case math.Abs(v) < 86400:
		return fmtNum(v/3600) + "h"
	default:
		return fmtNum(v/86400) + "d"
	}
}

// ---------------------------------------------------------------------------
// Test 1: explicit allowlist walk over every action in every annotation.
// ---------------------------------------------------------------------------

func TestN13P04T05_AnnotationTemplatesUseOnlySafeConstructs(t *testing.T) {
	rf := loadRules(t)
	checked := 0
	for _, g := range rf.Groups {
		for _, r := range g.Rules {
			for key, tmpl := range r.Annotations {
				for {
					i := strings.Index(tmpl, "{{")
					if i < 0 {
						break
					}
					j := strings.Index(tmpl[i:], "}}")
					if j < 0 {
						t.Errorf("%s: %s: unterminated {{ action", r.Alert, key)
						break
					}
					action := strings.TrimSpace(tmpl[i+2 : i+j])
					if _, err := evalTemplateAction(action, map[string]string{}, 0.5); err != nil {
						t.Errorf("%s: %s: template action %q rejected: %v", r.Alert, key, action, err)
					}
					checked++
					tmpl = tmpl[i+j+2:]
				}
			}
		}
	}
	if checked < 25 {
		t.Errorf("only %d template actions checked — the rules file should carry a rich annotation surface", checked)
	}
}

// ---------------------------------------------------------------------------
// Test 2: canary-poisoned render sweep over all alerts and value shapes.
// ---------------------------------------------------------------------------

// poisonedLabels returns the label map for the canary sweep: every label the
// alert's annotations actually reference keeps its real bounded value (see
// safeLabelRefs); everything else — the attacker-influenceable vectors —
// carries canaryMaterial.
func poisonedLabels(alert string, referenced map[string]bool, realValues map[string]string) map[string]string {
	labels := map[string]string{}
	for _, name := range []string{
		"path", "method", "status", "model", "org", "user", "request_id",
		"key", "authorization", "query", "le", "result", "from", "to",
		"class", "source", "provider", "url", "upstream", "instance",
		"place", "reason", "op", "scope_kind",
	} {
		if referenced[name] {
			labels[name] = realValues[name]
			continue
		}
		labels[name] = canaryMaterial
	}
	return labels
}

// collectReferencedLabels lists the $labels.<name> references of one rule's
// annotations. Callers only use it on rules whose templates already passed
// the allowlist walk, so every name here is on the safe list.
func collectReferencedLabels(r alertRule) map[string]bool {
	out := map[string]bool{}
	for _, tmpl := range r.Annotations {
		for {
			i := strings.Index(tmpl, "{{")
			if i < 0 {
				break // annotation exhausted; scan the next one
			}
			j := strings.Index(tmpl[i:], "}}")
			if j < 0 {
				break
			}
			action := strings.TrimSpace(tmpl[i+2 : i+j])
			if name, ok := strings.CutPrefix(action, "$labels."); ok {
				out[name] = true
			}
			tmpl = tmpl[i+j+2:]
		}
	}
	return out
}

func assertMessageClean(t *testing.T, alert, annotation, rendered string) {
	t.Helper()
	if strings.Contains(rendered, canaryMaterial) {
		t.Errorf("%s: %s: rendered message contains canary material: %q", alert, annotation, rendered)
	}
	for _, re := range secretShapeRes {
		if re.MatchString(rendered) {
			t.Errorf("%s: %s: rendered message matches secret shape %v: %q", alert, annotation, re, rendered)
		}
	}
	if len(rendered) > 4096 {
		t.Errorf("%s: %s: rendered message unbounded (%d bytes)", alert, annotation, len(rendered))
	}
}

func TestN13P04T05_RenderedMessagesNeverContainCanaryMaterial(t *testing.T) {
	rf := loadRules(t)
	// real bounded values for the labels templates may reference; the
	// closed-enum spaces get their full enumeration in the dedicated test
	realValues := map[string]string{
		"url":        "http://upstream-a.internal:8080/v1",
		"upstream":   "http://upstream-a.internal:8080/v1",
		"instance":   "gateway-0:8080",
		"place":      "apiformat_request_parse",
		"reason":     "prompt_cache_key",
		"op":         "set",
		"scope_kind": "wallet",
	}
	valueShapes := []float64{0.5, 0, math.NaN(), math.Inf(1), math.Inf(-1), 1e308}
	rendered := 0
	for _, g := range rf.Groups {
		for _, r := range g.Rules {
			referenced := collectReferencedLabels(r)
			labels := poisonedLabels(r.Alert, referenced, realValues)
			for _, value := range valueShapes {
				for key, tmpl := range r.Annotations {
					out, err := renderAnnotation(tmpl, labels, value)
					if err != nil {
						t.Fatalf("%s: %s: render: %v", r.Alert, key, err)
					}
					assertMessageClean(t, r.Alert, key, out)
					rendered++
				}
			}
		}
	}
	if rendered < 150 {
		t.Errorf("only %d renders swept — expected all annotations × value shapes", rendered)
	}
}

// ---------------------------------------------------------------------------
// Test 3: the closed label spaces, fully enumerated.
// ---------------------------------------------------------------------------

// mirroredSilentFailurePairs mirrors pkg/metrics silentFailurePlaces (23
// pairs over 8 places). Every mirrored pair is driven through the real
// closed registry — an unregistered pair panics, so REMOVING a registry
// entry turns this red mechanically. Adding a pair to the registry requires
// extending this mirror in the same change (lockstep by review; the pair
// values are bounded Go identifiers either way, never attacker input).
var mirroredSilentFailurePairs = []struct{ place, reason string }{
	{"apiformat_request_parse", "prompt_cache_key"},
	{"apiformat_request_parse", "stream"},
	{"apiformat_request_parse", "message_item"},
	{"apiformat_request_parse", "image_url"},
	{"apiformat_request_parse", "function_call"},
	{"apiformat_request_parse", "tool_output"},
	{"apiformat_request_parse", "system_text"},
	{"apiformat_request_parse", "tool_format"},
	{"apiformat_request_parse", "reasoning"},
	{"apiformat_request_parse", "user"},
	{"apiformat_stream_parse", "chunk_decode"},
	{"audit_ingest_decode", "reservations"},
	{"audit_ingest_decode", "labels"},
	{"audit_ingest_decode", "settlement_link"},
	{"audit_ingest_decode", "tool_frame"},
	{"audit_ingest_decode", "policy"},
	{"audit_ingest_policy_envelope", "unknown_version"},
	{"audit_ingest_trace_completeness", "unknown_version"},
	{"audit_ingest_trace_completeness", "invalid_value"},
	{"mcp_audit_write", "log_failed"},
	{"a2a_audit_write", "log_failed"},
	{"event_publish", "backlog_full"},
	{"event_publish", "publish_failed"},
}

func TestN13P04T05_ClosedLabelSpacesEnumerateClean(t *testing.T) {
	rf := loadRules(t)

	t.Run("silent failure place/reason registry", func(t *testing.T) {
		rule, ok := rf.byAlert("SilentFailureObserved")
		if !ok {
			t.Fatal("SilentFailureObserved not in rules file")
		}
		if len(mirroredSilentFailurePairs) != 23 {
			t.Errorf("mirror carries %d pairs, expected 23 — the registry and the mirror drifted", len(mirroredSilentFailurePairs))
		}
		for _, pair := range mirroredSilentFailurePairs {
			// panics on an unregistered pair (closed registry contract)
			metrics.SilentFailure(pair.place, pair.reason)
			labels := map[string]string{"place": pair.place, "reason": pair.reason}
			for key, tmpl := range rule.Annotations {
				out, err := renderAnnotation(tmpl, labels, 1)
				if err != nil {
					t.Fatalf("%s %q: render: %v", pair.place, key, err)
				}
				assertMessageClean(t, "SilentFailureObserved", key, out)
			}
		}
		// the whole enumerated space is exposed on /metrics
		mfs, err := prometheus.DefaultGatherer.Gather()
		if err != nil {
			t.Fatalf("gather: %v", err)
		}
		series := 0
		for _, mf := range mfs {
			if mf.GetName() == "gateway_silent_failures_total" {
				series = len(mf.GetMetric())
			}
		}
		if series != len(mirroredSilentFailurePairs) {
			t.Errorf("gateway_silent_failures_total exposes %d series after driving the mirror, want %d", series, len(mirroredSilentFailurePairs))
		}
	})

	t.Run("regionrouter ops", func(t *testing.T) {
		rule, ok := rf.byAlert("RegionCacheInvalidateFailed")
		if !ok {
			t.Fatal("RegionCacheInvalidateFailed not in rules file")
		}
		for _, op := range []string{"set", "del"} {
			metrics.RegionCacheInvalidateFailedTotal.WithLabelValues(op).Inc()
			labels := map[string]string{"op": op}
			for key, tmpl := range rule.Annotations {
				out, err := renderAnnotation(tmpl, labels, 1)
				if err != nil {
					t.Fatalf("op %s %q: render: %v", op, key, err)
				}
				assertMessageClean(t, "RegionCacheInvalidateFailed", key, out)
			}
		}
	})

	t.Run("budget scope kinds", func(t *testing.T) {
		rule, ok := rf.byAlert("BudgetScopeReserveDivergence")
		if !ok {
			t.Fatal("BudgetScopeReserveDivergence not in rules file")
		}
		kinds := map[budget.ScopeKind]string{
			budget.ScopeWallet:    "wallet",
			budget.ScopeTeamMonth: "team_month",
			budget.ScopeAgentDay:  "agent_day",
			budget.ScopeSession:   "session",
		}
		for kind, want := range kinds {
			if string(kind) != want {
				t.Errorf("ScopeKind constant drifted: %q != %q", string(kind), want)
			}
			labels := map[string]string{"scope_kind": string(kind)}
			for key, tmpl := range rule.Annotations {
				out, err := renderAnnotation(tmpl, labels, 1)
				if err != nil {
					t.Fatalf("scope %s %q: render: %v", kind, key, err)
				}
				assertMessageClean(t, "BudgetScopeReserveDivergence", key, out)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Test 4: raw request material never reaches metric labels.
// ---------------------------------------------------------------------------

func TestN13P04T05_RawRequestMaterialNeverReachesMetricLabels(t *testing.T) {
	// canary in the query string, the User-Agent and an unknown path — the
	// three request-borne channels an external caller controls outright.
	// The unknown-path probe must NOT register the canary as a route
	// (driveGatewayTraffic registers a handler at its path argument); the
	// UA helper keeps one fixed route so the canary path lands in the
	// middleware's "unmatched" fallback instead.
	resetGauges()
	driveGatewayTraffic(t, "/v1/chat", http.StatusOK, 3, 0) // route pattern label
	driveGatewayTrafficWithUA(t, "/v1/chat", http.StatusOK, 1, canaryMaterial)
	driveGatewayTrafficWithUA(t, "/"+canaryMaterial+"?q="+canaryMaterial, http.StatusNotFound, 1, canaryMaterial)

	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	checked := 0
	for _, mf := range mfs {
		if mf.GetName() != "gateway_http_requests_total" && mf.GetName() != "gateway_http_request_duration_seconds" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				checked++
				if strings.Contains(lp.GetValue(), canaryMaterial) {
					t.Errorf("%s label %s carries raw request material: %q", mf.GetName(), lp.GetName(), lp.GetValue())
				}
			}
		}
	}
	if checked < 10 {
		t.Errorf("only %d label values inspected — the request-path families should be populated", checked)
	}
	// Restore the shared request counter vec: this binary's registry is
	// process-global and counter children cannot be zeroed individually, so
	// the probe's unmatched-path increment would otherwise leak into
	// order-dependent absolute assertions in the middleware tests
	// (TestMiddleware_UnmatchedPathIsBoundedLabel expects exactly its own 4
	// unmatched requests). Resetting the vec keeps the probe
	// order-independent under -shuffle in both directions; the assertions
	// above already ran on the post-drive state.
	metrics.RequestsTotal.Reset()
}

// driveGatewayTrafficWithUA drives requests carrying a custom User-Agent
// through the real chi router and the real PrometheusMiddleware with a
// fixed /v1/chat route. With path=/v1/chat it exercises the header channel;
// with any other path the request never matches, so the middleware's
// "unmatched" fallback label is what gets inspected.
func driveGatewayTrafficWithUA(t *testing.T, path string, status int, count int, ua string) {
	t.Helper()
	router := chi.NewRouter()
	router.Use(metrics.PrometheusMiddleware())
	router.Get("/v1/chat", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	})
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 30 * time.Second}
	for i := 0; i < count; i++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("User-Agent", ua)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_ = resp.Body.Close()
	}
}

// ---------------------------------------------------------------------------
// Test 5: the rules file itself carries no secret-shaped literals.
// ---------------------------------------------------------------------------

func TestN13P04T05_RulesFileAnnotationsCarryNoSecretLiterals(t *testing.T) {
	rf := loadRules(t)
	for _, g := range rf.Groups {
		for _, r := range g.Rules {
			for key, text := range r.Annotations {
				for _, re := range secretShapeRes {
					if re.MatchString(text) {
						t.Errorf("%s: %s: annotation matches secret shape %v: %q", r.Alert, key, re, text)
					}
				}
			}
		}
	}
}
