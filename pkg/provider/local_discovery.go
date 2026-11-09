package provider

import (
	"fmt"
	"sort"
	"strings"
)

// Discovery / availability / health split for local model runtimes
// (N08-P04-T03). The three words answer three different questions about a
// locally installed model and used to collapse into one "works" opinion:
//
//   - Discovery (static, zero network): the model is installed/present — a
//     registry row names it, its provider is one of the local runtime
//     adapters, and the adapter declares the serving endpoint a client must
//     find. This is answerable offline, before anything is dialed.
//   - Availability (probe): the configured endpoint is reachable AND the
//     required serving endpoint exists on it (capability match at the path
//     level). No generation is triggered.
//   - Health (probe): a live serving check — a minimal real chat request —
//     proves the model actually serves through the full adapter path.
//
// ClassifyLocalModel surfaces the three aspects as three distinct fields
// plus a derived Working label that is true ONLY when all three are
// positive. The negative contract is encoded in that derivation: an
// installed model whose endpoint lacks the required serving endpoint is
// reported endpoint-missing and can never render as working/healthy, no
// matter what any static surface claims.
//
// Everything in this file is pure classification: no I/O, no clock, no
// catalog consultation. The probe executor that produces the observations
// lives in pkg/upstream (it needs the guarded HTTP client).

// localRuntimeAdapters are the local runtime adapters keyed by their
// canonical registry provider name. Discovery consults this table instead of
// the factory so a catalog withdrawal can never masquerade as "provider
// unknown" (those are different facts), and so discovery stays allocation-
// free offline. All local adapters are stateless value types.
var localRuntimeAdapters = map[string]Provider{
	"vllm":     VLLM{},
	"ollama":   Ollama{},
	"llamacpp": LlamaCPP{},
	"tgi":      TGI{},
}

// LocalRuntimeProviders returns the canonical local runtime provider names,
// sorted. The slice is a copy; callers cannot mutate the discovery table.
func LocalRuntimeProviders() []string {
	names := make([]string, 0, len(localRuntimeAdapters))
	for name := range localRuntimeAdapters {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// isLocalRuntimeProvider is the package-internal predicate for "name is one
// of the local runtime adapters" (trimmed input, canonical lowercase names).
// Discovery and the offline pricing guard (usage.go) share it so the two
// surfaces can never drift apart on what counts as a local runtime.
func isLocalRuntimeProvider(name string) bool {
	_, ok := localRuntimeAdapters[strings.TrimSpace(name)]
	return ok
}

// IsLocalProvider reports whether name is one of the local runtime adapters.
func IsLocalProvider(name string) bool {
	return isLocalRuntimeProvider(name)
}

// LocalChatPath returns the serving endpoint path the local runtime adapter
// requires for non-streaming chat (the path both probes validate). Empty for
// a name that is not a local runtime.
func LocalChatPath(name string) string {
	a, ok := localRuntimeAdapters[strings.TrimSpace(name)]
	if !ok {
		return ""
	}
	return a.Path(false)
}

// LocalDiscovery is the static, offline half of the split: what the
// installation claims about a local model row before anything is dialed.
type LocalDiscovery struct {
	// Installed reports the model is present: a non-empty model name whose
	// provider resolves to a local runtime adapter.
	Installed bool
	// Provider is the canonical local adapter name (trimmed input).
	Provider string
	// Model is the served model name (trimmed input; for local runtimes the
	// registry name IS the served name — there is no remap hook).
	Model string
	// ChatPath is the required serving endpoint path.
	ChatPath string
	// Reason states precisely why the row is not installed (I51: exact
	// reason, never a bare false).
	Reason string
}

// DiscoverLocalModel classifies a registry row's (provider, model) pair into
// the static discovery facts without any I/O. Cloud adapters are explicitly
// not local discoveries: a row pointing at api.openai.com must never be
// reported as an installed local model.
func DiscoverLocalModel(providerName, model string) LocalDiscovery {
	d := LocalDiscovery{Provider: strings.TrimSpace(providerName), Model: strings.TrimSpace(model)}
	adapter, ok := localRuntimeAdapters[d.Provider]
	switch {
	case !ok:
		d.Reason = fmt.Sprintf("provider %q is not a local runtime (local runtimes: %s)",
			providerName, strings.Join(LocalRuntimeProviders(), ", "))
		return d
	case d.Model == "":
		d.Reason = fmt.Sprintf("provider %q is a local runtime but the model name is empty", d.Provider)
		return d
	default:
		d.Installed = true
		d.ChatPath = adapter.Path(false)
		return d
	}
}

// LocalAvailability is the reachability + capability-match observation for
// one endpoint. Availability is met only when the probe ran, the endpoint
// answered, and the required serving endpoint was found on it.
type LocalAvailability struct {
	// Probed is false when the availability probe never ran (the surfaced
	// state must then stay "discovered", not "unreachable" — an unverified
	// claim would be dishonest).
	Probed bool
	// Reachable: the endpoint host answered at all.
	Reachable bool
	// EndpointPresent: the required chat serving endpoint exists on the
	// reachable host (any status other than 404 proves the route exists and
	// processed the probe).
	EndpointPresent bool
	// HTTPStatus is the observed status (0 when unreachable).
	HTTPStatus int
	// Reason carries the precise failure observation (I51).
	Reason string
}

// Met reports the availability verdict.
func (a LocalAvailability) Met() bool { return a.Probed && a.Reachable && a.EndpointPresent }

// LocalHealth is the live serving observation: one minimal real chat request
// through the full adapter path.
type LocalHealth struct {
	// Serving: the live serving check passed.
	Serving bool
	// HTTPStatus is the observed status (0 for transport-level failures).
	HTTPStatus int
	// Reason carries the precise failure observation, including the
	// endpoint's own error body where one was returned (I51: the refusal is
	// surfaced, never masked or rewritten into "unavailable").
	Reason string
}

// Local model lifecycle state labels. The vocabulary is deliberately finer
// than discovered/configured/tested: for local runtimes the questions
// "installed?", "endpoint answers with the required endpoint?" and "serving
// right now?" have distinct observable answers and each gets its own label.
const (
	// LocalStateUnknown: the row is not a local model at all.
	LocalStateUnknown = "unknown"
	// LocalStateDiscovered: installed, but no availability probe has run.
	LocalStateDiscovered = "discovered"
	// LocalStateUnreachable: probed, endpoint did not answer.
	LocalStateUnreachable = "unreachable"
	// LocalStateEndpointMissing: reachable, but the required serving
	// endpoint is absent (HTTP 404) — the packet's negative case.
	LocalStateEndpointMissing = "endpoint-missing"
	// LocalStateAvailable: availability met, health not probed yet.
	LocalStateAvailable = "available"
	// LocalStateUnhealthy: health probed and the live serving check failed.
	LocalStateUnhealthy = "unhealthy"
	// LocalStateHealthy: installed, available, and serving.
	LocalStateHealthy = "healthy"
)

// LocalModelStatus is the surfaced row: three distinct aspect fields, the
// derived Working label, and the finest-grained state with its precise
// reason. JSON-tagged so admin/ops surfaces can render it verbatim.
type LocalModelStatus struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	// Endpoint is the base URL the probes dialed (empty when nothing was
	// probed).
	Endpoint   string `json:"endpoint,omitempty"`
	ChatPath   string `json:"chat_path,omitempty"`
	Discovered bool   `json:"discovered"`
	// Available: endpoint reachable and required serving endpoint present.
	Available bool `json:"available"`
	// Healthy: live serving check passed. False unless Available is also
	// true — a missing endpoint can never report a healthy model.
	Healthy bool `json:"healthy"`
	// Working is the derived display label: true only when all three
	// aspects are positive. This is the ONLY field a "working models"
	// surface may filter on.
	Working bool `json:"working"`
	// State is the finest-grained distinct observation (see the
	// LocalState* constants).
	State string `json:"state"`
	// Reason states precisely why the row is not working (I51: exact
	// reason; empty exactly when the row is healthy).
	Reason string `json:"reason,omitempty"`
}

// ClassifyLocalModel composes the discovery facts and the two probe
// observations into the surfaced row. h == nil means the health probe did
// not run (it is skipped when availability is not met — a health check
// cannot pass through a missing or unreachable endpoint). The composition is
// fail-closed: every aspect starts false and only explicit positive
// observations flip it, so a partially probed row can never render green.
func ClassifyLocalModel(endpoint string, d LocalDiscovery, a LocalAvailability, h *LocalHealth) LocalModelStatus {
	st := LocalModelStatus{
		Provider:   d.Provider,
		Model:      d.Model,
		Endpoint:   endpoint,
		ChatPath:   d.ChatPath,
		Discovered: d.Installed,
		Available:  a.Met(),
	}
	switch {
	case !st.Discovered:
		st.State = LocalStateUnknown
		st.Reason = d.Reason
		return st
	case !a.Probed:
		st.State = LocalStateDiscovered
		st.Reason = "availability not probed yet"
		return st
	case !a.Reachable:
		st.State = LocalStateUnreachable
		st.Reason = a.Reason
		return st
	case !a.EndpointPresent:
		// Negative contract: installed model, endpoint reachable, required
		// serving endpoint missing. Never available, never healthy, never
		// working — and the reason names the missing endpoint precisely.
		st.State = LocalStateEndpointMissing
		st.Reason = a.Reason
		return st
	case h == nil:
		st.State = LocalStateAvailable
		return st
	case !h.Serving:
		st.State = LocalStateUnhealthy
		st.Reason = h.Reason
		return st
	default:
		st.State = LocalStateHealthy
		st.Healthy = true
		st.Working = true
		return st
	}
}
