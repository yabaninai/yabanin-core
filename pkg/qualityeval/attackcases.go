// Attack corpus authoring over the example set interchange contract (see
// pkg/evalgate and the bundle engine in this package).
//
// This file is the operator/authoring side of the Enterprise-beta text
// attack detectors packet (N14-P03): it defines the verifiable attack
// classes for gateway-visible text — prompt injection, secret-leak
// attempts and tool abuse — as labeled, self-checking corpora and encodes
// them through the same reviewed artifacts every other dataset uses:
// datasets.Prepare (import batches only; authoring structurally cannot
// bypass history permissions because no history reference is ever taken)
// and BuildSetBundle/WriteSetBundle (digest-bound, versioned interchange).
// No new interchange format is introduced here.
//
// Validation is fail-closed: malformed, damaged or self-contradictory
// corpora (a positive case with no expected class, a benign control with
// expected classes, duplicate ids, unknown classes or surfaces, oversized
// text, binary or control-byte text) reject the whole corpus with
// ErrInvalidAttackCorpus and produce no artifact. Case text is inert data:
// nothing is ever executed, fetched or dereferenced by building, exporting
// or re-importing a corpus.
package qualityeval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/reireirei/yabanin/pkg/agenteval/datasets"
	"github.com/reireirei/yabanin/pkg/evalgate"
)

// ErrInvalidAttackCorpus reports a malformed, self-contradictory or
// oversized attack corpus. Deep preparation or bundle failures keep their
// own sentinel classes (ErrInvalidPrepare, ErrInvalidSetBundle) so callers
// can distinguish the failing layer.
var ErrInvalidAttackCorpus = errors.New("invalid attack corpus")

// AttackClass is one verifiable agent-attack class in gateway-visible text
// (N14-P03-T02). The set is deliberately closed: corpora with unknown
// classes reject so coverage measurement cannot drift into wishful labels.
type AttackClass string

// The verifiable attack classes.
const (
	// AttackClassPromptInjection covers instruction-override and role/
	// policy-hijacking attempts (including injections smuggled through tool
	// results and tool arguments).
	AttackClassPromptInjection AttackClass = "prompt_injection"
	// AttackClassSecretLeak covers attempts to make the agent disclose
	// secrets, credentials, keys or environment contents, or to egress
	// credential-shaped content through replies or tool calls.
	AttackClassSecretLeak AttackClass = "secret_leak"
	// AttackClassToolAbuse covers attempts to weaponise agent tools in
	// gateway-visible text: destructive commands, exfiltration channels,
	// guardrail/service tampering via tool invocations.
	AttackClassToolAbuse AttackClass = "tool_abuse"
)

// AttackSurface names the gateway-visible stage a case text belongs to
// (owner decision I66: textual requests and responses, tool arguments and
// results; binary media extraction is out of beta scope).
type AttackSurface string

// The gateway-visible text surfaces.
const (
	// SurfaceRequest is client-visible request text.
	SurfaceRequest AttackSurface = "request"
	// SurfaceResponse is model response text.
	SurfaceResponse AttackSurface = "response"
	// SurfaceToolArguments is tool invocation input.
	SurfaceToolArguments AttackSurface = "tool_arguments"
	// SurfaceToolResult is tool output text.
	SurfaceToolResult AttackSurface = "tool_result"
)

// Attack case bounds. The case cap mirrors the revision sample cap; the
// per-case text cap keeps authoring and downstream detector runs bounded
// (16 KiB per case). The bundle total remains bounded by the 8 MiB
// interchange limit in WriteSetBundle.
const (
	maxAttackCases        = 10000
	maxAttackCaseIDLength = 256
	maxAttackCaseTextByte = 16 << 10
)

// attackCaseSchemaVersion is the corpus payload schema inside each sample
// payload; readers reject other versions fail-closed.
const attackCaseSchemaVersion = 1

// attackCaseKind is the fixed payload type marker.
const attackCaseKind = "yabanin.attack-case"

// AttackCase is one labeled corpus case. Classes empty means a benign
// control: the case must not be reported as any attack class, and the
// harness counts detections on it as false positives. Every case carries
// at least one surface; classes must be non-empty exactly when the case is
// an attack case.
type AttackCase struct {
	ID       string
	Text     string
	Surfaces []AttackSurface
	Classes  []AttackClass
}

// attackCasePayload is the wire shape of one sample payload inside the
// revision document. Field order is fixed by the struct so identical
// corpora encode byte-identically.
type attackCasePayload struct {
	SchemaVersion int             `json:"schema_version"`
	Kind          string          `json:"kind"`
	Text          string          `json:"text"`
	Surfaces      []AttackSurface `json:"surfaces"`
	Classes       []AttackClass   `json:"classes"`
}

// ValidateAttackCases enforces the full authoring contract and rejects the
// whole corpus on the first violation. A corpus must contain at least one
// benign control and at least one positive per used class, so every class
// in the corpus is measurable in both directions (coverage and false
// positives).
func ValidateAttackCases(cases []AttackCase) error {
	if len(cases) == 0 {
		return fmt.Errorf("%w: corpus is empty", ErrInvalidAttackCorpus)
	}
	if len(cases) > maxAttackCases {
		return fmt.Errorf("%w: %d cases exceeds the %d-case limit", ErrInvalidAttackCorpus, len(cases), maxAttackCases)
	}
	seenIDs := make(map[string]struct{}, len(cases))
	benign := 0
	classes := map[AttackClass]int{}
	for _, c := range cases {
		if strings.TrimSpace(c.ID) == "" {
			return fmt.Errorf("%w: case id is required", ErrInvalidAttackCorpus)
		}
		if len(c.ID) > maxAttackCaseIDLength {
			return fmt.Errorf("%w: case id %q exceeds %d characters", ErrInvalidAttackCorpus, c.ID, maxAttackCaseIDLength)
		}
		if _, dup := seenIDs[c.ID]; dup {
			return fmt.Errorf("%w: duplicate case id %q", ErrInvalidAttackCorpus, c.ID)
		}
		seenIDs[c.ID] = struct{}{}
		if strings.TrimSpace(c.Text) == "" {
			return fmt.Errorf("%w: case %q text is blank", ErrInvalidAttackCorpus, c.ID)
		}
		if len(c.Text) > maxAttackCaseTextByte {
			return fmt.Errorf("%w: case %q text exceeds %d bytes", ErrInvalidAttackCorpus, c.ID, maxAttackCaseTextByte)
		}
		if err := validateAttackCaseText(c.ID, c.Text); err != nil {
			return err
		}
		if err := validateAttackSurfaces(c.ID, c.Surfaces); err != nil {
			return err
		}
		seen := map[AttackClass]struct{}{}
		for _, class := range c.Classes {
			if !isKnownAttackClass(class) {
				return fmt.Errorf("%w: case %q has unknown class %q", ErrInvalidAttackCorpus, c.ID, class)
			}
			if _, dup := seen[class]; dup {
				return fmt.Errorf("%w: case %q repeats class %q", ErrInvalidAttackCorpus, c.ID, class)
			}
			seen[class] = struct{}{}
			classes[class]++
		}
		// Conflicting labeling fails closed: a positive must declare what it
		// verifies, a benign control must declare nothing.
		if len(c.Classes) == 0 {
			benign++
		}
	}
	if benign == 0 {
		return fmt.Errorf("%w: corpus has no benign control case (coverage would be unverifiable)", ErrInvalidAttackCorpus)
	}
	return nil
}

// validateAttackCaseText rejects non-textual or damaged case text
// fail-closed (N14-P03-T05 negative contract, PRODUCT-CONTRACT §13: PDF
// extraction, image OCR and audio transcription for protective scanning
// are out of beta scope, and unverified binary input is never reported as
// analyzed). A corpus case is gateway-visible TEXT; a payload that is not
// valid UTF-8, carries control characters beyond tab/newline/carriage
// return, or contains the U+FFFD replacement character — the marker
// encoding/json silently leaves when decoding damaged bytes, so the strict
// re-import path would otherwise launder binary input into text — cannot
// enter a corpus, and therefore can never be scanned or counted as an
// analyzed case by the coverage/FP harness. Legitimate attack texts
// (quotes, CJK, emoji, RU/EN phrasing, tabs and newlines) are unaffected.
func validateAttackCaseText(caseID, text string) error {
	if !utf8.ValidString(text) {
		return fmt.Errorf("%w: case %q text is not valid UTF-8 (binary payload)", ErrInvalidAttackCorpus, caseID)
	}
	for _, r := range text {
		if r == utf8.RuneError {
			// Unreachable for invalid UTF-8 (rejected above), so this is the
			// explicit U+FFFD character only.
			return fmt.Errorf("%w: case %q text contains the U+FFFD replacement character (damaged or binary input)", ErrInvalidAttackCorpus, caseID)
		}
		if r != '\t' && r != '\n' && r != '\r' && unicode.IsControl(r) {
			return fmt.Errorf("%w: case %q text contains control character %#U", ErrInvalidAttackCorpus, caseID, r)
		}
	}
	return nil
}

// validateAttackSurfaces checks surface presence, membership and duplicity.
func validateAttackSurfaces(caseID string, surfaces []AttackSurface) error {
	if len(surfaces) == 0 {
		return fmt.Errorf("%w: case %q needs at least one surface", ErrInvalidAttackCorpus, caseID)
	}
	seen := make(map[AttackSurface]struct{}, len(surfaces))
	for _, s := range surfaces {
		if !isKnownAttackSurface(s) {
			return fmt.Errorf("%w: case %q has unknown surface %q", ErrInvalidAttackCorpus, caseID, s)
		}
		if _, dup := seen[s]; dup {
			return fmt.Errorf("%w: case %q repeats surface %q", ErrInvalidAttackCorpus, caseID, s)
		}
		seen[s] = struct{}{}
	}
	return nil
}

// isKnownAttackClass reports whether class is part of the closed v1 set.
func isKnownAttackClass(class AttackClass) bool {
	switch class {
	case AttackClassPromptInjection, AttackClassSecretLeak, AttackClassToolAbuse:
		return true
	}
	return false
}

// isKnownAttackSurface reports whether surface is part of the closed v1 set.
func isKnownAttackSurface(surface AttackSurface) bool {
	switch surface {
	case SurfaceRequest, SurfaceResponse, SurfaceToolArguments, SurfaceToolResult:
		return true
	}
	return false
}

// BuildAttackCorpus validates the corpus and produces the digest-bound
// example set bundle through the real preparation path: every case becomes
// one imported sample, provenance attributes one import source, and no
// history reference exists anywhere in the request (the reader parameter is
// structurally unused because there is nothing to resolve). The result is
// deterministic: identical inputs yield byte-identical exports.
func BuildAttackCorpus(cases []AttackCase, datasetID, creator string, createdAt time.Time) (evalgate.ExampleSet, error) {
	if err := ValidateAttackCases(cases); err != nil {
		return evalgate.ExampleSet{}, err
	}
	samples := make([]datasets.Sample, 0, len(cases))
	for _, c := range cases {
		payload, err := json.Marshal(attackCasePayload{
			SchemaVersion: attackCaseSchemaVersion,
			Kind:          attackCaseKind,
			Text:          c.Text,
			Surfaces:      attackSurfacesCopy(c.Surfaces),
			Classes:       attackClassesCopy(c.Classes),
		})
		if err != nil {
			return evalgate.ExampleSet{}, fmt.Errorf("%w: encode case %q: %v", ErrInvalidAttackCorpus, c.ID, err)
		}
		samples = append(samples, datasets.Sample{ID: c.ID, Payload: payload})
	}
	prepared, err := datasets.Prepare(context.Background(), nil, datasets.PrepareRequest{
		DatasetID: datasetID,
		Creator:   creator,
		CreatedAt: createdAt,
		Imports:   []datasets.ImportBatch{{Samples: samples}},
	})
	if err != nil {
		return evalgate.ExampleSet{}, fmt.Errorf("attack corpus: prepare: %w", err)
	}
	set, err := BuildSetBundle(prepared)
	if err != nil {
		return evalgate.ExampleSet{}, fmt.Errorf("attack corpus: bundle: %w", err)
	}
	return set, nil
}

// ParseAttackCorpus decodes a validated bundle revision back into attack
// cases. Payload decoding is strict (unknown fields, wrong schema version,
// unknown classes or surfaces, missing fields reject) and the whole corpus
// is re-validated afterwards, so a hand-edited revision cannot smuggle in a
// corpus that fails the authoring contract. Case order equals revision
// sample order.
func ParseAttackCorpus(rev datasets.Revision) ([]AttackCase, error) {
	if rev.DatasetID == "" || len(rev.Samples) == 0 {
		return nil, fmt.Errorf("%w: revision carries no corpus samples", ErrInvalidAttackCorpus)
	}
	cases := make([]AttackCase, 0, len(rev.Samples))
	for _, sample := range rev.Samples {
		var payload attackCasePayload
		dec := json.NewDecoder(bytes.NewReader(sample.Payload))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&payload); err != nil {
			return nil, fmt.Errorf("%w: case %q payload: %v", ErrInvalidAttackCorpus, sample.ID, err)
		}
		if err := dec.Decode(new(any)); err == nil {
			return nil, fmt.Errorf("%w: case %q payload has trailing data", ErrInvalidAttackCorpus, sample.ID)
		}
		if payload.SchemaVersion != attackCaseSchemaVersion {
			return nil, fmt.Errorf("%w: case %q payload schema version %d", ErrInvalidAttackCorpus, sample.ID, payload.SchemaVersion)
		}
		if payload.Kind != attackCaseKind {
			return nil, fmt.Errorf("%w: case %q payload kind %q", ErrInvalidAttackCorpus, sample.ID, payload.Kind)
		}
		if strings.TrimSpace(payload.Text) == "" {
			return nil, fmt.Errorf("%w: case %q payload text is blank", ErrInvalidAttackCorpus, sample.ID)
		}
		if len(payload.Text) > maxAttackCaseTextByte {
			return nil, fmt.Errorf("%w: case %q payload text exceeds %d bytes", ErrInvalidAttackCorpus, sample.ID, maxAttackCaseTextByte)
		}
		cases = append(cases, AttackCase{
			ID:       sample.ID,
			Text:     payload.Text,
			Surfaces: attackSurfacesCopy(payload.Surfaces),
			Classes:  attackClassesCopy(payload.Classes),
		})
	}
	if err := ValidateAttackCases(cases); err != nil {
		return nil, err
	}
	return cases, nil
}

// attackClassesCopy normalizes nil to the empty slice so benign controls
// encode as [] (present field, empty list) and round-trips keep deep
// equality.
func attackClassesCopy(in []AttackClass) []AttackClass {
	out := make([]AttackClass, 0, len(in))
	return append(out, in...)
}

// attackSurfacesCopy is attackClassesCopy for surfaces.
func attackSurfacesCopy(in []AttackSurface) []AttackSurface {
	out := make([]AttackSurface, 0, len(in))
	return append(out, in...)
}
