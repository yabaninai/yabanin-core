package provider

import (
	"errors"
	"fmt"
	"testing"
)

// CapabilityError.Error returns the Detail field verbatim: adapter refusal
// strings are pinned contracts (compat tests and gateway wire messages
// assert them byte-for-byte), so the typed carrier must not reformat them.
func TestCapabilityError_ErrorReturnsDetailVerbatim(t *testing.T) {
	ce := &CapabilityError{
		Provider:   "vertex",
		Capability: CapabilityStreaming,
		Model:      "m",
		Detail:     "exact pinned text",
	}
	if ce.Error() != "exact pinned text" {
		t.Fatalf("Error() = %q, want the Detail verbatim", ce.Error())
	}
}

// The gateway observes refusals wrapped by the upstream client
// ("translate request: %w", "create request: %w"); Refusal must match
// through the wrap chain and reject unrelated errors.
func TestRefusal_MatchesDirectAndWrapped(t *testing.T) {
	direct := &CapabilityError{Provider: "bedrock", Capability: CapabilityTools, Detail: "d"}
	got, ok := Refusal(direct)
	if !ok || got != direct {
		t.Fatalf("direct refusal not matched (got %v, ok %v)", got, ok)
	}
	wrapped := fmt.Errorf("translate request: %w", direct)
	got, ok = Refusal(wrapped)
	if !ok || got != direct {
		t.Fatalf("wrapped refusal not matched (got %v, ok %v)", got, ok)
	}
	if _, ok := Refusal(errors.New("unrelated")); ok {
		t.Fatal("unrelated error matched as a refusal")
	}
	if _, ok := Refusal(nil); ok {
		t.Fatal("nil matched as a refusal")
	}
}

// TestBedrockTranslate_TypedRefusalFamily pins the bedrock translator's
// refusal contract: tool-bearing requests carry the typed *CapabilityError
// (capability_not_supported family, chain-terminal), while image-bearing and
// unknown-part requests carry the typed *UnsupportedFeatureError
// (unsupported_feature family — N07-RECON restore of the N07-P05-T02
// semantics). Both messages stay byte-identical to the pinned strings.
func TestBedrockTranslate_TypedRefusalFamily(t *testing.T) {
	const toolsMessage = "bedrock adapter: tools/tool_choice are not supported yet (Converse toolUse mapping pending); refusing instead of silently dropping (I50/I51)"
	const mediaMessage = "bedrock adapter: image inputs are not supported yet (I61 media deferred); text-only at T02"

	toolBodies := []string{
		`{"model":"b","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object","properties":{}}}}]}`,
		`{"model":"b","messages":[{"role":"user","content":"hi"}],"tool_choice":"auto"}`,
		`{"model":"b","messages":[{"role":"assistant","content":"","tool_calls":[{"id":"1","type":"function","function":{"name":"f","arguments":"{}"}}]}]}`,
		`{"model":"b","messages":[{"role":"tool","content":"r"}]}`,
	}
	for _, body := range toolBodies {
		_, _, err := chatToBedrockConverse([]byte(body))
		ce, ok := Refusal(err)
		if !ok {
			t.Fatalf("tools body %s: no typed refusal (err %v)", body, err)
		}
		if ce.Provider != "bedrock" || ce.Capability != CapabilityTools {
			t.Fatalf("tools body %s: refusal %+v, want provider bedrock capability tools", body, ce)
		}
		if ce.Error() != toolsMessage {
			t.Fatalf("tools refusal message drifted: %q", ce.Error())
		}
	}

	mediaBody := `{"model":"b","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid/y.png"}}]}]}`
	_, _, err := chatToBedrockConverse([]byte(mediaBody))
	var ufe *UnsupportedFeatureError
	if !errors.As(err, &ufe) {
		t.Fatalf("media body: no typed unsupported-feature rejection (err %v)", err)
	}
	if ufe.Provider != "bedrock" {
		t.Fatalf("media rejection %+v, want provider bedrock", ufe)
	}
	if ufe.Error() != mediaMessage {
		t.Fatalf("media rejection message drifted: %q", ufe.Error())
	}
}

// TestVertexCapabilityGate_TypedRefusals pins the matrix gates on the typed
// carrier: streaming/tool refusals carry provider=vertex, the precise
// capability axis and the model, while the messages stay byte-identical to
// the pinned contract; supported combinations return nil.
func TestVertexCapabilityGate_TypedRefusals(t *testing.T) {
	const streamMessage = `vertex: model "m" does not support streaming in the capability matrix; request rejected, not downgraded`
	const toolsMessage = `vertex: model "m" does not support tool calling in the capability matrix; request rejected, not downgraded`

	err := vertexCapabilityGate("m", VertexCapabilities{}, true, false)
	ce, ok := Refusal(err)
	if !ok {
		t.Fatalf("stream refusal not typed (err %v)", err)
	}
	if ce.Provider != "vertex" || ce.Capability != CapabilityStreaming || ce.Model != "m" {
		t.Fatalf("stream refusal %+v, want provider vertex capability streaming model m", ce)
	}
	if ce.Error() != streamMessage {
		t.Fatalf("stream refusal message drifted: %q", ce.Error())
	}

	err = vertexCapabilityGate("m", VertexCapabilities{}, false, true)
	ce, ok = Refusal(err)
	if !ok {
		t.Fatalf("tools refusal not typed (err %v)", err)
	}
	if ce.Provider != "vertex" || ce.Capability != CapabilityTools || ce.Model != "m" {
		t.Fatalf("tools refusal %+v, want provider vertex capability tools model m", ce)
	}
	if ce.Error() != toolsMessage {
		t.Fatalf("tools refusal message drifted: %q", ce.Error())
	}

	if err := vertexCapabilityGate("m", VertexCapabilities{Streaming: true, Tools: true}, true, true); err != nil {
		t.Fatalf("supported combination refused: %v", err)
	}
	if err := vertexCapabilityGate("m", VertexCapabilities{}, false, false); err != nil {
		t.Fatalf("feature-less request refused: %v", err)
	}
}
