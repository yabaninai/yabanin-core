package consumer

// message crosses exactly one boundary — handleMessage — where the effective
// profile (strictest of the process-local declaration and the wire-declared
// content_profile) is computed once and a sanitized COPY of the message is
// produced for handler processing, diagnostics, retry and DLQ. The received
// message and its Values map are never mutated: normal delivery and PEL
// reclaim share the same contract, and the out-of-band diagnostic writer
// (logging.ReplaceAttr) enforces the same process-local declaration.

import (
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/logging"
)

// resolveMessageContentProfile computes the effective profile for one
// message: the strictest of the process-local declaration and the
// wire-declared content_profile. The wire key's PRESENCE decides (checked
// before any typed extraction), so a malformed present value fails closed
// to metadata-only instead of degrading to legacy.
func resolveMessageContentProfile(fields map[string]interface{}, local config.LogContentProfile) config.LogContentProfile {
	wire, present := fields["content_profile"]
	return config.EffectiveLogContentProfile(local, wire, present)
}

// sanitizeStreamMessageForContentProfile applies secret scrubbing before
// durable writes under every profile. Metadata-only additionally returns a
// copy whose Values map is owned by
// the consumer:
//   - payload / upstream_payload / upstream_response are deleted;
//   - prompt_hash is re-bound from the body's still-present representation
//     BEFORE stripping: a valid supplied digest is kept byte-for-byte, a
//     malformed one is recomputed from the body, and a malformed one
//     without a body is dropped (no digest is invented);
//   - a non-empty error value is replaced by the fixed safe notice.
func sanitizeStreamMessageForContentProfile(msg redis.XMessage, local config.LogContentProfile) (redis.XMessage, config.LogContentProfile) {
	profile := resolveMessageContentProfile(msg.Values, local)
	values := make(map[string]interface{}, len(msg.Values))
	for k, v := range msg.Values {
		if text, ok := v.(string); ok {
			v = ScrubSecrets(text)
		}
		values[k] = v
	}
	if profile != config.LogContentProfileMetadataOnly {
		sanitized := msg
		sanitized.Values = values
		return sanitized, profile
	}
	body, _ := values["payload"].(string)
	supplied, _ := values["prompt_hash"].(string)
	if digest := eventpublisher.ResolvePromptHash(supplied, body); digest != "" {
		values["prompt_hash"] = digest
	} else {
		delete(values, "prompt_hash")
	}
	delete(values, "payload")
	delete(values, "upstream_payload")
	delete(values, "upstream_response")
	if v, ok := values["error"]; ok {
		if s, isStr := v.(string); !isStr || s != "" {
			values["error"] = eventpublisher.ContentProfileRedactedError
		}
	}

	sanitized := msg
	sanitized.Values = values
	return sanitized, profile
}

// safeDiagnostic renders one error text as a diagnostic value under the
// message's effective profile: legacy keeps the text, metadata-only
// replaces it with the fixed notice carrying no underlying error text.
func safeDiagnostic(profile config.LogContentProfile, text string) string {
	rendered := logging.ContentProfileDiagnosticValue(profile, text)
	s, _ := rendered.(string)
	return ScrubSecrets(s)
}

// strictDLQAllowlistKeys are the only fields a metadata-only DLQ envelope
// may carry. Identity/attribution/telemetry survive for replay; every
// content capture, free-form diagnostic and unknown future key is dropped
// at the envelope boundary — the original map is never serialized.
var strictDLQAllowlistKeys = []string{
	"event_type", "source", "ts", "request_id", "session_id", "org_id",
	"model_requested", "model_used", "upstream_url", "status_code",
	"duration_ms", "tokens_in", "tokens_out", "method", "error",
	"cache_hit_type", "cache_similarity", "counterfactual_cost_usd",
	"estimated_cost_usd", "resale_cost_usd", "tier_used",
	"classifier_class", "classifier_confidence", "classifier_source",
	"cache_read_tokens", "cache_creation_tokens", "endpoint",
	"usage_source", "cost_status", "evalgate_sampled",
	"evalgate_should_upgrade", "ab_group", "team_id", "routing_decision",
	"agent_id", "task_id", "reservations", "termination", "labels",
	"inference_region", "region_evidence", "model_origin_country",
	"log_storage_region", "provider_entity_jurisdiction",
	"attestation_hash", "attestation_signature", "attestation_key_id",
	"first_token_ms", "attempt_count", "retry_count", "used_org_key",
	"policy", "content_profile", "prompt_hash",
}

// strictDLQValues rebuilds the DLQ envelope Values from the bounded
// allowlist. The error field may only be empty or the fixed safe text —
// the sanitized boundary already normalized it, this is defense in depth.
func strictDLQValues(values map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(strictDLQAllowlistKeys))
	for _, key := range strictDLQAllowlistKeys {
		v, ok := values[key]
		if !ok {
			continue
		}
		if key == "error" {
			if s, isStr := v.(string); !isStr || s != "" {
				v = eventpublisher.ContentProfileRedactedError
			}
		}
		out[key] = v
	}
	return out
}
