package provider

import (
	"encoding/json"
	"fmt"
)

// rejectUnmappedResponseFormat enforces the N07-P01-T03 negative criterion on
// chat routes whose target API has no structured-output equivalent: an
// unmapped response_format must fail the request loudly (I51 — reject with
// the exact reason) instead of being silently dropped. A silent drop would
// break the client's JSON guarantee while reporting success: the model
// answers free-form text and the client believes the schema held.
//
// {"type":"text"} and an absent field are the no-guarantee default and pass
// as a no-op. Adapters that CAN honor structured outputs (e.g. vertex maps
// json_object to responseMimeType) do their own mapping and must not call
// this helper. Translation-layer rejections surface to the client through
// the standard upstream error mapping (pkg/gateway mapUpstreamError) — the
// established vertex strict-tools precedent.
func rejectUnmappedResponseFormat(adapter string, raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var rf struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &rf); err != nil {
		return fmt.Errorf("%s: decode response_format: %w (I51: rejecting instead of silently ignoring it)", adapter, err)
	}
	switch rf.Type {
	case "", "text":
		// Plain text is the default output shape of both target APIs.
		return nil
	case "json_object", "json_schema":
		return fmt.Errorf("%s: response_format %q has no equivalent on this route; rejecting instead of silently ignoring the JSON guarantee (I51)", adapter, rf.Type)
	default:
		return fmt.Errorf("%s: unsupported response_format type %q; rejecting instead of silently ignoring it (I51)", adapter, rf.Type)
	}
}
