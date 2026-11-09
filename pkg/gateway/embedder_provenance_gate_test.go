package cli

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/config"
)

// refusal): the provenance gate hard-refuses only the DISTRIBUTION default
// model — an explicitly operator-configured external model boots with a
// notice (its supply chain is the operator's); disabled/no-model configs
// pass untouched.
func TestEmbedderProvenanceGate(t *testing.T) {
	t.Run("distribution default with unknown origin is refused with the manifest reason", func(t *testing.T) {
		err := embedderProvenanceGate(config.EmbedderConfig{
			Enabled: true, BaseURL: "http://bge-embedder:6006", Model: "unknown-org/who-knows",
		}, gateTestLogger(t))
		if err == nil {
			t.Fatal("startup must be refused for an unknown-origin distribution default")
		}
		if !strings.Contains(err.Error(), "startup refused (R003 D4)") || !strings.Contains(err.Error(), "unknown origin") {
			t.Fatalf("refusal must name the gate and the manifest reason, got %q", err.Error())
		}
	})
	t.Run("explicit operator model overrides the refusal with a notice", func(t *testing.T) {
		err := embedderProvenanceGate(config.EmbedderConfig{
			Enabled: true, BaseURL: "http://embed:6006", Model: "wire-test-embedding", ModelExplicit: true,
		}, gateTestLogger(t))
		if err != nil {
			t.Fatalf("operator-supplied model is the operator's supply chain: %v", err)
		}
	})
	t.Run("registered model with confirmed rights passes", func(t *testing.T) {
		if err := embedderProvenanceGate(config.EmbedderConfig{
			Enabled: true, BaseURL: "http://bge-embedder:6006", Model: "BAAI/bge-small-en-v1.5",
		}, gateTestLogger(t)); err != nil {
			t.Fatalf("registered origin must boot: %v", err)
		}
	})
	t.Run("disabled or model-less configs are not gated", func(t *testing.T) {
		for _, cfg := range []config.EmbedderConfig{
			{Enabled: false, BaseURL: "http://x", Model: "unknown/x"},
			{Enabled: true, BaseURL: "", Model: "unknown/x"},
			{Enabled: true, BaseURL: "http://x", Model: ""},
		} {
			if err := embedderProvenanceGate(cfg, gateTestLogger(t)); err != nil {
				t.Fatalf("nothing enabled must not be gated: %v", err)
			}
		}
	})
}

func gateTestLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.DiscardHandler)
}
