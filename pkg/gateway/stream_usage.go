package cli

import "encoding/json"

// defaultStreamUsageSet mirrors config.defaultStreamUsageProviders for
// manually assembled test gateways; production builds it from
// Gateway.StreamUsageProviders.
//
// RM-03: OpenAI-compatible upstreams omit usage from streamed chunks unless
// the request opts in via stream_options.include_usage. Without it every
// streaming request records TokensIn/TokensOut = 0, EstimatedCostUSD = 0 and
// bypasses task/session token budgets. ensureStreamUsage flips that flag on
// the upstream hop; the trailing usage-only chunk it produces is stripped
// from the client bytes by the stream handler (SuppressUsageOnlyChunk).
func streamUsageEnabled(providers []string) map[string]bool {
	if len(providers) == 0 {
		return nil
	}
	m := make(map[string]bool, len(providers))
	for _, p := range providers {
		m[p] = true
	}
	return m
}

// ensureStreamUsage makes an OpenAI-compatible streaming body request usage
// in the final chunk. clientRequested reports whether the client itself
// asked for it (then the usage chunk must reach the client).
//
// Behaviour:
//   - provider not in enabled (empty provider name counts as
//     "openai-compat") → body unchanged, true (nothing was injected, so
//     there is nothing to suppress either);
//   - unreadable JSON → body unchanged, true (fail-open to passthrough);
//   - no stream_options → {"stream_options":{"include_usage":true}} added,
//     false;
//   - stream_options.include_usage already true → body unchanged, true;
//   - stream_options present without include_usage (or false) → flag set to
//     true, all other stream_options keys preserved, false.
//
// The body is re-marshalled via map[string]json.RawMessage so numbers and
// nested objects (tools, response_format, …) survive byte-accurate.
func ensureStreamUsage(body []byte, providerName string, enabled map[string]bool) (out []byte, clientRequested bool) {
	if providerName == "" {
		providerName = "openai-compat"
	}
	if !enabled[providerName] {
		return body, true
	}

	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil || root == nil {
		return body, true
	}

	soRaw, has := root["stream_options"]
	if !has {
		return addStreamUsageOption(root, body)
	}
	return setStreamUsageOption(root, soRaw, body)
}

// addStreamUsageOption handles a body without stream_options: it adds
// {"include_usage":true} and re-marshals the root. A marshal error is
// unreachable for RawMessage roots; keep the fail-open anyway.
func addStreamUsageOption(root map[string]json.RawMessage, body []byte) (out []byte, clientRequested bool) {
	root["stream_options"] = json.RawMessage(`{"include_usage":true}`)
	out, err := json.Marshal(root)
	if err != nil {
		return body, true
	}
	return out, false
}

// setStreamUsageOption handles a body whose stream_options lacks
// include_usage (or sets it to false): it sets the flag to true, preserves
// every other stream_options key and re-marshals both levels. Unreadable
// stream_options and marshal errors fail open to the original body.
func setStreamUsageOption(root map[string]json.RawMessage, soRaw json.RawMessage, body []byte) (out []byte, clientRequested bool) {
	var so map[string]json.RawMessage
	if err := json.Unmarshal(soRaw, &so); err != nil || so == nil {
		return body, true
	}
	if string(so["include_usage"]) == "true" {
		return body, true
	}

	so["include_usage"] = json.RawMessage("true")
	soBytes, err := json.Marshal(so)
	if err != nil {
		return body, true
	}
	root["stream_options"] = json.RawMessage(soBytes)
	out, err = json.Marshal(root)
	if err != nil {
		return body, true
	}
	return out, false
}
