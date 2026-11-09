// Package events defines the request-completion event payload consumed by
// loggerd. PB1 adds jurisdictional-lineage attestation fields.
package events

// Lineage stream field names. These are the canonical keys used in:
//   - pkg/eventpublisher/redis_publisher.go XAdd.Values
//   - pkg/events/payload.go JSON tags
//   - services/loggerd/consumer/stream.go field extraction
//
// Keep them in lock-step — a typo here would silently drop a field.
const (
	FieldInferenceRegion            = "inference_region"
	FieldRegionEvidence             = "region_evidence"
	FieldModelOriginCountry         = "model_origin_country"
	FieldLogStorageRegion           = "log_storage_region"
	FieldProviderEntityJurisdiction = "provider_entity_jurisdiction"
	FieldAttestationHash            = "attestation_hash"
	FieldAttestationSignature       = "attestation_signature"
	FieldAttestationKeyID           = "attestation_key_id"
)

// LineageFieldsCount is the number of lineage fields carried per event.
// Used by tests to assert no field is silently dropped.
const LineageFieldsCount = 8
