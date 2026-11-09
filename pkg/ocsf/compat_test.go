package ocsf

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// W05-C02 compatibility battery: the forward-compatibility acceptance
// of the packet («неизвестные поля сохраняют forward compatibility»),
// the fail-closed future-version gate, the golden-corpus regression,
// and the idempotent-revalidation pin (batch-A review finding F3 —
// «повтор валидации идемпотентен», DISPATCH §8 routed here).
//
// The core-export-not-closed leg of the card («core-экспорт не
// закрыт — повторный прогон W01-C03-батарей») is command evidence:
// the request_export and loggerd batteries are re-run read-only (see
// the delivery record); pkg/ocsf adds no fence edits.

// compactGolden returns the compact canonical bytes of one golden case
// (the on-disk fixture is the indented form of exactly these bytes).
func compactGolden(t *testing.T, name string) []byte {
	t.Helper()
	ev := goldenEvent(name)
	for _, tc := range goldenCases {
		if tc.name == name {
			tc.mut(&ev)
			break
		}
	}
	rec, err := MapEvent(ev)
	if err != nil {
		t.Fatalf("MapEvent(%s): %v", name, err)
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal(%s): %v", name, err)
	}
	return data
}

// withAdditiveField decodes record bytes into a generic map, injects a
// future-producer additive extension, and re-encodes — the exact wire
// shape a newer writer emits against this reader.
func withAdditiveField(t *testing.T, data []byte) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal record: %v", err)
	}
	m["future_tenant_extension"] = map[string]any{
		"quota_scope": "eu-west",
		"labels":      []any{"beta", "soc"},
		"nested":      map[string]any{"depth": json.Number("2")},
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal additive record: %v", err)
	}
	return out
}

// TestCompatAdditiveFieldForwardCompat: a record (and envelope)
// carrying unknown fields from a future producer validates against the
// v1 reader, survives a generic decode/encode roundtrip unchanged, and
// still parses for the old struct reader (the W02-C03 rollback
// contract: «читатель старой версии продолжает парсить v1-записи» —
// the additive test IS the old-reader test, cross-cited there).
func TestCompatAdditiveFieldForwardCompat(t *testing.T) {
	base := compactGolden(t, "deny-full.json")
	additive := withAdditiveField(t, base)

	// New-client/old-validator: the additive record validates.
	if err := ValidateRecordJSON(additive); err != nil {
		t.Fatalf("additive record rejected by v1 validator: %v", err)
	}

	// Preserved on roundtrip: generic decode → encode → decode keeps
	// the additive subtree value-equal (retention, not just tolerance).
	var first, second map[string]any
	if err := json.Unmarshal(additive, &first); err != nil {
		t.Fatalf("decode additive: %v", err)
	}
	reencoded, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if err := json.Unmarshal(reencoded, &second); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if !reflect.DeepEqual(first["future_tenant_extension"], second["future_tenant_extension"]) {
		t.Fatalf("additive field not preserved on roundtrip: %v vs %v",
			first["future_tenant_extension"], second["future_tenant_extension"])
	}

	// Old struct reader: unknown field ignored, known fields intact.
	var withExt, withoutExt NormalizedRecord
	if err := json.Unmarshal(additive, &withExt); err != nil {
		t.Fatalf("old struct reader failed on additive record: %v", err)
	}
	if err := json.Unmarshal(base, &withoutExt); err != nil {
		t.Fatalf("old struct reader failed on base record: %v", err)
	}
	if !reflect.DeepEqual(withExt, withoutExt) {
		t.Fatalf("additive field leaked into the struct record form")
	}

	// Envelope level: additive fields inside records AND at the
	// envelope root both pass the v1 envelope validator.
	env, err := NewEnvelope("org-1", envelopeRecords(t), testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	body, err := EncodeEnvelope(env)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	var envMap map[string]any
	if err := json.Unmarshal(body, &envMap); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	envMap["future_delivery_hint"] = map[string]any{"retry_class": "batched"}
	records, ok := envMap["records"].([]any)
	if !ok || len(records) == 0 {
		t.Fatalf("envelope body carries no records")
	}
	rec0, ok := records[0].(map[string]any)
	if !ok {
		t.Fatalf("record[0] is not an object")
	}
	rec0["future_record_field"] = "carried"
	extended, err := json.Marshal(envMap)
	if err != nil {
		t.Fatalf("re-encode envelope: %v", err)
	}
	if err := ValidateEnvelopeJSON(extended); err != nil {
		t.Fatalf("envelope with additive fields rejected: %v", err)
	}
}

// TestCompatEnvelopeIdentityStableAcrossAdditiveFields pins the
// NewEnvelope tolerant-reader discipline: the envelope identity is
// derived from the DECODED record structs, so additive fields inside
// record JSON do not shift envelope_id (same records ⇒ same identity,
// across schema additions).
func TestCompatEnvelopeIdentityStableAcrossAdditiveFields(t *testing.T) {
	records := envelopeRecords(t)
	plain, err := json.Marshal(records)
	if err != nil {
		t.Fatalf("marshal records: %v", err)
	}
	var generic []map[string]any
	if err := json.Unmarshal(plain, &generic); err != nil {
		t.Fatalf("decode records: %v", err)
	}
	generic[0]["future_tenant_extension"] = map[string]any{"scope": "eu"}
	extended, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("re-encode records: %v", err)
	}
	var decoded []NormalizedRecord
	if err := json.Unmarshal(extended, &decoded); err != nil {
		t.Fatalf("struct-decode extended records: %v", err)
	}

	plainEnv, err := NewEnvelope("org-1", records, testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope(plain): %v", err)
	}
	extendedEnv, err := NewEnvelope("org-1", decoded, testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope(extended): %v", err)
	}
	if plainEnv.EnvelopeID != extendedEnv.EnvelopeID {
		t.Fatalf("envelope_id shifted across additive fields: %q vs %q",
			plainEnv.EnvelopeID, extendedEnv.EnvelopeID)
	}
}

// TestCompatFutureSchemaVersionRejected: the version gate is
// fail-closed in BOTH directions — a schema_version from the future is
// an explicit unsupported error, never a silent zero-decode; the
// zero/negative band (batch-B F1 fix) stays closed alongside.
func TestCompatFutureSchemaVersionRejected(t *testing.T) {
	base := compactGolden(t, "mask.json")

	setVersion := func(v any, remove bool) []byte {
		var m map[string]any
		if err := json.Unmarshal(base, &m); err != nil {
			t.Fatalf("decode base: %v", err)
		}
		if remove {
			delete(m, "schema_version")
		} else {
			m["schema_version"] = v
		}
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		return out
	}

	future := []struct {
		name string
		data []byte
	}{
		{"version 2", setVersion(json.Number("2"), false)},
		{"version 99", setVersion(json.Number("99"), false)},
	}
	for _, tc := range future {
		if err := ValidateRecordJSON(tc.data); !errors.Is(err, ErrUnsupportedSchemaVersion) {
			t.Fatalf("%s: record verdict = %v, want ErrUnsupportedSchemaVersion", tc.name, err)
		}
		var envMap map[string]any
		if err := json.Unmarshal(tc.data, &envMap); err != nil {
			t.Fatalf("%s: decode: %v", tc.name, err)
		}
		envMap["envelope_id"] = "env-future"
		envMap["issued_at"] = json.Number("1")
		envMap["records"] = []any{}
		envBody, err := json.Marshal(envMap)
		if err != nil {
			t.Fatalf("%s: encode envelope: %v", tc.name, err)
		}
		if err := ValidateEnvelopeJSON(envBody); !errors.Is(err, ErrUnsupportedSchemaVersion) {
			t.Fatalf("%s: envelope verdict = %v, want ErrUnsupportedSchemaVersion", tc.name, err)
		}
	}

	lowBand := []struct {
		name string
		data []byte
	}{
		{"version 0", setVersion(json.Number("0"), false)},
		{"version -3", setVersion(json.Number("-3"), false)},
		{"version missing", setVersion(nil, true)},
	}
	for _, tc := range lowBand {
		if err := ValidateRecordJSON(tc.data); !errors.Is(err, ErrNoSchemaVersion) {
			t.Fatalf("%s: verdict = %v, want ErrNoSchemaVersion (F1 band)", tc.name, err)
		}
	}
}

// TestCompatGoldenCorpusRegression: the W01-C03 golden corpus stays
// green — every fixture re-derives byte-identically from its source
// event and validates against the embedded schema.
func TestCompatGoldenCorpusRegression(t *testing.T) {
	dir := filepath.Join("testdata", "golden")
	for _, tc := range goldenCases {
		t.Run(tc.name, func(t *testing.T) {
			got := compactGolden(t, tc.name)
			// #nosec G304 -- path is built from this package's fixed
			// golden case table, same as mapper_golden_test.go.
			want, err := os.ReadFile(filepath.Join(dir, tc.name))
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			indented, err := marshalGolden(decodeRecord(t, got))
			if err != nil {
				t.Fatalf("indent: %v", err)
			}
			if !bytes.Equal(indented, want) {
				t.Fatalf("canonical record drifted from golden %s\n--- golden ---\n%s\n--- got ---\n%s",
					tc.name, want, indented)
			}
			if err := ValidateRecordJSON(got); err != nil {
				t.Fatalf("golden %s no longer validates: %v", tc.name, err)
			}
		})
	}
}

// decodeRecord is the battery's struct decode helper.
func decodeRecord(t *testing.T, data []byte) NormalizedRecord {
	t.Helper()
	var rec NormalizedRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("decode record: %v", err)
	}
	return rec
}

// TestCompatRevalidateIdempotent closes batch-A review finding F3
// (DISPATCH §8 «повтор валидации идемпотентен»): validating the same
// bytes twice always yields the SAME verdict — both the nil/non-nil
// class and the exact error — so a double-delivered or re-read payload
// can never flip a consumer decision.
func TestCompatRevalidateIdempotent(t *testing.T) {
	invalidRecord := func() []byte {
		data := compactGolden(t, "allow.json")
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("decode: %v", err)
		}
		m["severity_id"] = json.Number("9") // outside the enum
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		return out
	}()

	env, err := NewEnvelope("org-1", envelopeRecords(t), testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	envBody, err := EncodeEnvelope(env)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	var brokenEnv map[string]any
	if err := json.Unmarshal(envBody, &brokenEnv); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	delete(brokenEnv, "records") // required key removed
	brokenEnvBody, err := json.Marshal(brokenEnv)
	if err != nil {
		t.Fatalf("re-encode broken envelope: %v", err)
	}

	recordCorpus := map[string][]byte{
		"golden deny":      compactGolden(t, "deny-full.json"),
		"golden unmapped":  compactGolden(t, "unknown-type.json"),
		"additive field":   withAdditiveField(t, compactGolden(t, "mask.json")),
		"future version":   withVersion(t, compactGolden(t, "flag.json"), json.Number("2")),
		"invalid enum":     invalidRecord,
		"trailing garbage": append(append([]byte{}, compactGolden(t, "allow.json")...), []byte("{}")...),
		"empty evidence ok": func() []byte {
			ev := fixture("policy.flag")
			ev.Evidence = nil
			rec, err := MapEvent(ev)
			if err != nil {
				t.Fatalf("MapEvent: %v", err)
			}
			data, err := json.Marshal(rec)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			return data
		}(),
	}
	for name, data := range recordCorpus {
		first := ValidateRecordJSON(data)
		second := ValidateRecordJSON(data)
		if (first == nil) != (second == nil) {
			t.Fatalf("%s: revalidation flipped verdict: %v vs %v", name, first, second)
		}
		if first != nil && first.Error() != second.Error() {
			t.Fatalf("%s: revalidation changed error: %q vs %q", name, first, second)
		}
	}

	envelopeCorpus := map[string][]byte{
		"valid envelope":      envBody,
		"broken envelope":     brokenEnvBody,
		"record not envelope": compactGolden(t, "deny-full.json"),
		"additive envelope":   additiveEnvelopeBody(t, envBody),
		"future-version env":  withVersion(t, envBody, json.Number("7")),
	}

	for name, data := range envelopeCorpus {
		first := ValidateEnvelopeJSON(data)
		second := ValidateEnvelopeJSON(data)
		if (first == nil) != (second == nil) {
			t.Fatalf("envelope %s: revalidation flipped verdict: %v vs %v", name, first, second)
		}
		if first != nil && first.Error() != second.Error() {
			t.Fatalf("envelope %s: revalidation changed error: %q vs %q", name, first, second)
		}
	}

	// Same-bytes double encode: canonical encoding is a pure function.
	again, err := EncodeEnvelope(env)
	if err != nil {
		t.Fatalf("EncodeEnvelope (second): %v", err)
	}
	if !bytes.Equal(envBody, again) {
		t.Fatalf("double EncodeEnvelope not byte-identical")
	}
}

// additiveEnvelopeBody injects an unknown envelope-root field into an
// envelope body (future-producer wire shape at the envelope level).
func additiveEnvelopeBody(t *testing.T, body []byte) []byte {
	t.Helper()
	var envMap map[string]any
	if err := json.Unmarshal(body, &envMap); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	envMap["future_delivery_hint"] = "batched"
	out, err := json.Marshal(envMap)
	if err != nil {
		t.Fatalf("re-encode envelope: %v", err)
	}
	return out
}

// withVersion rewrites schema_version in record bytes (test-local
// mutation helper for the F3 corpus).
func withVersion(t *testing.T, data []byte, v any) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	m["schema_version"] = v
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	return out
}

// TestCompatReplayIDReDerivationEnforced is the routed-R2 battery
// (batch-B review finding 2 → registry a47ba332, implemented by batch
// C): VerifyEnvelope re-derives every ASSIGNED replay_id from the
// verifier's org and the record's own dedup anchor. The empty slot
// stays valid (W03-era back-compat); a filled slot that does not
// re-derive — minted under another org, or an arbitrary value — is
// caught even though the HMAC over the body is valid (a corrupted or
// colluding producer must not smuggle replay identities into a
// verified envelope).
func TestCompatReplayIDReDerivationEnforced(t *testing.T) {
	// Legit pipeline: AssignReplayIDs → NewEnvelope → Sign → Verify.
	records := envelopeRecords(t)
	if err := AssignReplayIDs(records); err != nil {
		t.Fatalf("AssignReplayIDs: %v", err)
	}
	env, err := NewEnvelope("org-1", records, testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	body, header, err := SignEnvelope(testSecret, env, testSignTime)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	if err := VerifyEnvelope(testSecret, header, body, "org-1", testTolerance, testVerifyTime()); err != nil {
		t.Fatalf("legit assigned-replay envelope rejected: %v", err)
	}

	// Back-compat: empty replay slots (W03-era records) still verify.
	legacy, err := NewEnvelope("org-1", envelopeRecords(t), testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope(legacy): %v", err)
	}
	legacyBody, legacyHeader, err := SignEnvelope(testSecret, legacy, testSignTime)
	if err != nil {
		t.Fatalf("SignEnvelope(legacy): %v", err)
	}
	if err := VerifyEnvelope(testSecret, legacyHeader, legacyBody, "org-1", testTolerance, testVerifyTime()); err != nil {
		t.Fatalf("legacy empty-slot envelope rejected: %v", err)
	}

	// Smuggled: a replay id correctly derived — but under ANOTHER org —
	// riding a validly signed org-1 envelope. Construction succeeds
	// (NewEnvelope does not gate replay derivation); verification must
	// catch it (ErrReplayIDMismatch), proving the re-derivation check
	// is a VERIFIER-side org guarantee, not a producer courtesy.
	for _, tc := range []struct {
		name string
		mint func(t *testing.T, rec NormalizedRecord) string
	}{
		{"foreign-org derivation", func(t *testing.T, rec NormalizedRecord) string {
			t.Helper()
			id, err := ReplayID("org-2", rec.FindingInfo.UID)
			if err != nil {
				t.Fatalf("ReplayID(org-2): %v", err)
			}
			return id
		}},
		{"arbitrary value", func(t *testing.T, rec NormalizedRecord) string {
			t.Helper()
			return "replay-" + strings.Repeat("ab", 32)
		}},
	} {
		smuggled := envelopeRecords(t)
		smuggled[0].ReplayID = tc.mint(t, smuggled[0])
		smuggledEnv, err := NewEnvelope("org-1", smuggled, testSignTime)
		if err != nil {
			t.Fatalf("%s: NewEnvelope: %v", tc.name, err)
		}
		smuggledBody, smuggledHeader, err := SignEnvelope(testSecret, smuggledEnv, testSignTime)
		if err != nil {
			t.Fatalf("%s: SignEnvelope: %v", tc.name, err)
		}
		err = VerifyEnvelope(testSecret, smuggledHeader, smuggledBody, "org-1", testTolerance, testVerifyTime())
		if !errors.Is(err, ErrReplayIDMismatch) {
			t.Fatalf("%s: verdict = %v, want ErrReplayIDMismatch (valid HMAC must not smuggle a foreign replay id)", tc.name, err)
		}
	}
}
