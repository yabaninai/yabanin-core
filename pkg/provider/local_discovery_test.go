package provider

import (
	"strings"
	"testing"
)

// Tests for the discovery / availability / health split (N08-P04-T03), pure
// half: no network, no clock, no catalog — deterministic tables only.

func TestLocalRuntimeProviders_SortedAndComplete(t *testing.T) {
	t.Parallel()

	got := LocalRuntimeProviders()
	want := []string{"llamacpp", "ollama", "tgi", "vllm"}
	if len(got) != len(want) {
		t.Fatalf("LocalRuntimeProviders() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("LocalRuntimeProviders() = %v, want %v (order must be sorted for stable rendering)", got, want)
		}
	}
}

func TestIsLocalProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want bool
	}{
		{"vllm", true},
		{"ollama", true},
		{"llamacpp", true},
		{"tgi", true},
		{" vllm ", true}, // trimmed input
		{"", false},
		{"llama-cpp", false}, // near-miss typo stays a non-local name
		{"openai", false},    // cloud adapters are never local discoveries
		{"anthropic", false}, //nolint:dupl // table rows are data, not duplication
		{"azure-openai", false},
		{"vertex", false},
		{"bedrock", false},
		{"VLLM", false}, // canonical names are lowercase; no silent normalization
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsLocalProvider(tt.name); got != tt.want {
				t.Errorf("IsLocalProvider(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestLocalChatPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		provider string
		want     string
	}{
		{"vllm", "/v1/chat/completions"},
		{"ollama", "/v1/chat/completions"},
		{"llamacpp", "/v1/chat/completions"},
		{"tgi", "/generate"},
		{"openai", ""}, // not a local runtime: no local chat path
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			t.Parallel()
			if got := LocalChatPath(tt.provider); got != tt.want {
				t.Errorf("LocalChatPath(%q) = %q, want %q", tt.provider, got, tt.want)
			}
		})
	}
}

func TestDiscoverLocalModel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		providerName  string
		model         string
		wantInstalled bool
		wantProvider  string
		wantModel     string
		wantChatPath  string
		wantReasonSub string // non-empty → Reason must contain it
	}{
		{
			name:          "vllm row installed",
			providerName:  "vllm",
			model:         "qwen2.5-7b-instruct",
			wantInstalled: true,
			wantProvider:  "vllm",
			wantModel:     "qwen2.5-7b-instruct",
			wantChatPath:  "/v1/chat/completions",
		},
		{
			name:          "ollama row installed with tag",
			providerName:  "ollama",
			model:         "qwen2.5:7b",
			wantInstalled: true,
			wantProvider:  "ollama",
			wantModel:     "qwen2.5:7b",
			wantChatPath:  "/v1/chat/completions",
		},
		{
			name:          "llamacpp row installed",
			providerName:  "llamacpp",
			model:         "local-qwen",
			wantInstalled: true,
			wantProvider:  "llamacpp",
			wantModel:     "local-qwen",
			wantChatPath:  "/v1/chat/completions",
		},
		{
			name:          "tgi row installed on its generate endpoint",
			providerName:  "tgi",
			model:         "local-qwen",
			wantInstalled: true,
			wantProvider:  "tgi",
			wantModel:     "local-qwen",
			wantChatPath:  "/generate",
		},
		{
			name:          "whitespace is trimmed",
			providerName:  " vllm ",
			model:         " m ",
			wantInstalled: true,
			wantProvider:  "vllm",
			wantModel:     "m",
			wantChatPath:  "/v1/chat/completions",
		},
		{
			name:          "typo near-miss provider is not installed",
			providerName:  "llama-cpp",
			model:         "m",
			wantInstalled: false,
			wantProvider:  "llama-cpp",
			wantModel:     "m",
			wantReasonSub: `provider "llama-cpp" is not a local runtime`,
		},
		{
			name:          "cloud adapter is not a local discovery",
			providerName:  "openai",
			model:         "gpt-4o",
			wantInstalled: false,
			wantProvider:  "openai",
			wantModel:     "gpt-4o",
			wantReasonSub: `provider "openai" is not a local runtime`,
		},
		{
			name:          "empty provider is not installed",
			providerName:  "",
			model:         "m",
			wantInstalled: false,
			wantProvider:  "",
			wantModel:     "m",
			wantReasonSub: "is not a local runtime",
		},
		{
			name:          "empty model name is not installed",
			providerName:  "ollama",
			model:         "   ",
			wantInstalled: false,
			wantProvider:  "ollama",
			wantModel:     "",
			wantReasonSub: `provider "ollama" is a local runtime but the model name is empty`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := DiscoverLocalModel(tt.providerName, tt.model)
			if d.Installed != tt.wantInstalled {
				t.Errorf("Installed = %v, want %v (reason %q)", d.Installed, tt.wantInstalled, d.Reason)
			}
			if d.Provider != tt.wantProvider {
				t.Errorf("Provider = %q, want %q", d.Provider, tt.wantProvider)
			}
			if d.Model != tt.wantModel {
				t.Errorf("Model = %q, want %q", d.Model, tt.wantModel)
			}
			if d.ChatPath != tt.wantChatPath {
				t.Errorf("ChatPath = %q, want %q", d.ChatPath, tt.wantChatPath)
			}
			if tt.wantReasonSub != "" && !strings.Contains(d.Reason, tt.wantReasonSub) {
				t.Errorf("Reason = %q, want it to contain %q (I51: precise reason)", d.Reason, tt.wantReasonSub)
			}
			if tt.wantInstalled && d.Reason != "" {
				t.Errorf("installed row must carry no failure reason, got %q", d.Reason)
			}
		})
	}
}

func TestClassifyLocalModel(t *testing.T) {
	t.Parallel()

	okDiscovery := DiscoverLocalModel("llamacpp", "local-qwen")
	endpoint := "http://127.0.0.1:8080"

	tests := []struct {
		name        string
		discovery   LocalDiscovery
		avail       LocalAvailability
		health      *LocalHealth
		wantState   string
		wantDisc    bool
		wantAvail   bool
		wantHealthy bool
		wantWorking bool
		wantReason  string // non-empty → Reason must contain it
	}{
		{
			name:       "not a local row: unknown, nothing positive, no probes implied",
			discovery:  DiscoverLocalModel("llama-cpp", "m"),
			avail:      LocalAvailability{},
			health:     nil,
			wantState:  LocalStateUnknown,
			wantReason: "is not a local runtime",
		},
		{
			name:       "installed, not probed: discovered",
			discovery:  okDiscovery,
			avail:      LocalAvailability{},
			health:     nil,
			wantState:  LocalStateDiscovered,
			wantDisc:   true,
			wantReason: "availability not probed yet",
		},
		{
			name:       "probed, host dead: unreachable",
			discovery:  okDiscovery,
			avail:      LocalAvailability{Probed: true, Reason: "connection refused"},
			health:     nil,
			wantState:  LocalStateUnreachable,
			wantDisc:   true,
			wantReason: "connection refused",
		},
		{
			name:      "NEGATIVE: installed model, endpoint reachable, chat endpoint missing (404)",
			discovery: okDiscovery,
			avail: LocalAvailability{
				Probed:     true,
				Reachable:  true,
				HTTPStatus: 404,
				Reason:     "required chat endpoint /v1/chat/completions not found on http://127.0.0.1:8080 (HTTP 404)",
			},
			health:     nil,
			wantState:  LocalStateEndpointMissing,
			wantDisc:   true,
			wantReason: "HTTP 404",
		},
		{
			name:      "NEGATIVE: missing endpoint must stay non-working even if a stale health result claims serving",
			discovery: okDiscovery,
			avail: LocalAvailability{
				Probed:     true,
				Reachable:  true,
				HTTPStatus: 404,
				Reason:     "required chat endpoint /v1/chat/completions not found (HTTP 404)",
			},
			health:     &LocalHealth{Serving: true, HTTPStatus: 200},
			wantState:  LocalStateEndpointMissing,
			wantDisc:   true,
			wantReason: "HTTP 404",
		},
		{
			name:      "available: endpoint met, health not probed",
			discovery: okDiscovery,
			avail: LocalAvailability{
				Probed:          true,
				Reachable:       true,
				EndpointPresent: true,
				HTTPStatus:      400,
			},
			health:     nil,
			wantState:  LocalStateAvailable,
			wantDisc:   true,
			wantAvail:  true,
			wantReason: "",
		},
		{
			name:      "unhealthy: endpoint met, live serving check failed",
			discovery: okDiscovery,
			avail: LocalAvailability{
				Probed:          true,
				Reachable:       true,
				EndpointPresent: true,
				HTTPStatus:      400,
			},
			health:     &LocalHealth{Serving: false, HTTPStatus: 404, Reason: "live serving check failed: upstream error 404: model does not exist"},
			wantState:  LocalStateUnhealthy,
			wantDisc:   true,
			wantAvail:  true,
			wantReason: "model does not exist",
		},
		{
			name:      "healthy: all three aspects positive → working",
			discovery: okDiscovery,
			avail: LocalAvailability{
				Probed:          true,
				Reachable:       true,
				EndpointPresent: true,
				HTTPStatus:      400,
			},
			health:      &LocalHealth{Serving: true},
			wantState:   LocalStateHealthy,
			wantDisc:    true,
			wantAvail:   true,
			wantHealthy: true,
			wantWorking: true,
			wantReason:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			st := ClassifyLocalModel(endpoint, tt.discovery, tt.avail, tt.health)
			if st.State != tt.wantState {
				t.Errorf("State = %q, want %q", st.State, tt.wantState)
			}
			if st.Discovered != tt.wantDisc {
				t.Errorf("Discovered = %v, want %v", st.Discovered, tt.wantDisc)
			}
			if st.Available != tt.wantAvail {
				t.Errorf("Available = %v, want %v", st.Available, tt.wantAvail)
			}
			if st.Healthy != tt.wantHealthy {
				t.Errorf("Healthy = %v, want %v", st.Healthy, tt.wantHealthy)
			}
			if st.Working != tt.wantWorking {
				t.Errorf("Working = %v, want %v (Working must be the AND of all three aspects)", st.Working, tt.wantWorking)
			}
			if tt.wantReason != "" && !strings.Contains(st.Reason, tt.wantReason) {
				t.Errorf("Reason = %q, want it to contain %q", st.Reason, tt.wantReason)
			}
			if tt.wantState == LocalStateHealthy && st.Reason != "" {
				t.Errorf("healthy row must carry no reason, got %q", st.Reason)
			}
			if st.Endpoint != endpoint {
				t.Errorf("Endpoint = %q, want %q", st.Endpoint, endpoint)
			}
			if st.ChatPath != tt.discovery.ChatPath {
				t.Errorf("ChatPath = %q, want %q", st.ChatPath, tt.discovery.ChatPath)
			}
		})
	}
}

// TestClassifyLocalModel_WorkingImpliesAllAspects is the derivational
// invariant a "working models" surface relies on: Working=true exists only in
// the all-positive corner of the matrix. Enumerated exhaustively over the
// boolean aspect space so a future refactor cannot quietly widen it.
func TestClassifyLocalModel_WorkingImpliesAllAspects(t *testing.T) {
	t.Parallel()

	for _, installed := range []bool{false, true} {
		for _, probed := range []bool{false, true} {
			for _, reachable := range []bool{false, true} {
				for _, present := range []bool{false, true} {
					for _, healthProbed := range []bool{false, true} {
						for _, serving := range []bool{false, true} {
							d := DiscoverLocalModel("llamacpp", "m")
							if !installed {
								d = DiscoverLocalModel("nope", "m")
							}
							a := LocalAvailability{Probed: probed, Reachable: reachable, EndpointPresent: present}
							var h *LocalHealth
							if healthProbed {
								h = &LocalHealth{Serving: serving}
							}
							st := ClassifyLocalModel("http://ep", d, a, h)
							wantWorking := installed && probed && reachable && present && healthProbed && serving
							if st.Working != wantWorking {
								t.Fatalf("Working = %v, want %v for (installed=%t probed=%t reachable=%t present=%t healthProbed=%t serving=%t)",
									st.Working, wantWorking, installed, probed, reachable, present, healthProbed, serving)
							}
							if st.Working && (!st.Discovered || !st.Available || !st.Healthy) {
								t.Fatalf("Working row must have all three aspects true, got %+v", st)
							}
							if st.Working && st.State != LocalStateHealthy {
								t.Fatalf("Working row must be state %q, got %q", LocalStateHealthy, st.State)
							}
						}
					}
				}
			}
		}
	}
}
