package ocsf

// ExportSchemaVersion is the version of the normalized export schema
// (schema/export-v1.json), stamped on every envelope and every record.
//
// Versioning contract (W02 versioning artifact):
//
//   - a missing or zero schema_version is a protocol violation — an
//     unversioned payload must not be guessed into the current schema
//     (same fail-closed discipline as secevents.SchemaVersion);
//   - version <= ExportSchemaVersion validates; evolution within a
//     version is strictly additive optional fields, and readers must
//     ignore unknown fields (forward compatibility is a packet
//     acceptance criterion);
//   - version > ExportSchemaVersion is rejected fail-closed
//     (ErrUnsupportedSchemaVersion from validate.go): an unknown schema
//     must never be silently zero-decoded into a valid-looking export.
//
// The export schema version is independent of the secevents schema
// version (records pin both — metadata.secevents_schema_version): the
// two contracts evolve on their own additive tracks.
const ExportSchemaVersion = 1

// ExportSchemaName is the file name of the embedded schema matching
// ExportSchemaVersion (schema/ directory, go:embed'd by validate.go).
const ExportSchemaName = "export-v1"
