package guardhooks

// FIX-01 (CA-01, audit 2026-10-23): a custom guard pack detector reported a
// finding in redact mode, the hit was counted (secret:redact), but the secret
// stayed in the output — Hook.Apply delegated mutation to h.Redact, which
// re-applies only the built-in regexes and drops custom findings.
//
// These tests pin the repaired contract: redact mode mutates by the validated
// evaluator spans (merged overlaps, rune-boundary safe, deterministic order,
// JSON structure preserved) and fails closed when a safe mutation is not
// possible. The audit repro is TestFIX01CustomPackSecretIsRedacted.

import (
	"encoding/json"
	"regexp"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

// auditPackDetector mirrors the real pack loader's regexVersionedDetector
// shape (confidence 1 findings at regex byte offsets) without touching
// lifecycle.go, which is owned by FIX-02.
type auditPackDetector struct {
	id       RuleVersion
	category Category
	pattern  *regexp.Regexp
}

func (d auditPackDetector) Identity() RuleVersion { return d.id }

func (d auditPackDetector) Detect(in Invocation) ([]Finding, error) {
	text, err := in.Content()
	if err != nil {
		return nil, err
	}
	out := make([]Finding, 0, 4)
	for _, span := range d.pattern.FindAllStringIndex(text, -1) {
		out = append(out, Finding{
			Category: d.category, Start: span[0], End: span[1],
			Confidence: 1, Detector: d.id.PackID + ":" + d.id.RuleID,
		})
	}
	return out, nil
}

func auditPackEvaluator(t *testing.T, detectors ...VersionedDetector) *Evaluator {
	t.Helper()
	evaluator, err := NewExtendedEvaluator(detectors...)
	require.NoError(t, err)
	return evaluator
}

func auditPackDetectorFor(t *testing.T, rule string, category Category, pattern string) auditPackDetector {
	t.Helper()
	compiled, err := regexp.Compile(pattern)
	require.NoError(t, err)
	return auditPackDetector{
		id:       RuleVersion{PackID: "audit.pack", PackVersion: "1", RuleID: rule, RuleVersion: "1"},
		category: category,
		pattern:  compiled,
	}
}

func requireHit(t *testing.T, hits []Hit, category Category, outcome Outcome) {
	t.Helper()
	for _, hit := range hits {
		if hit.Category == category && hit.Outcome == outcome {
			return
		}
	}
	t.Fatalf("expected hit %s:%s in %v", category, outcome, hits)
}

// TestFIX01CustomPackSecretIsRedacted is the audit repro: a pack with regex
// PACK_SECRET_[A-Z]+ (category secret) under NewWithEvaluator(ModeRedact, …)
// must remove the match, not only report the hit.
func TestFIX01CustomPackSecretIsRedacted(t *testing.T) {
	detector := auditPackDetectorFor(t, "pack_secret", CatSecret, `PACK_SECRET_[A-Z]+`)
	hook := NewWithEvaluator(ModeRedact, auditPackEvaluator(t, detector))

	out, hits, err := hook.Apply("message PACK_SECRET_VALUE")
	require.NoError(t, err)
	requireHit(t, hits, CatSecret, OutcomeRedact)
	require.NotNil(t, out)
	require.NotContains(t, string(out), "PACK_SECRET_VALUE", "secret must not survive redact mode")
	require.Contains(t, string(out), "[REDACTED_SECRET]")
	require.Equal(t, "message [REDACTED_SECRET]", string(out))
}

// Clean input must stay untouched: no findings means no mutation and no hit.
func TestFIX01CleanInputUnchanged(t *testing.T) {
	detector := auditPackDetectorFor(t, "pack_secret", CatSecret, `PACK_SECRET_[A-Z]+`)
	hook := NewWithEvaluator(ModeRedact, auditPackEvaluator(t, detector))

	out, hits, err := hook.Apply("a perfectly clean message")
	require.NoError(t, err)
	require.Empty(t, hits)
	require.Nil(t, out)

	// A detector that matches nothing behaves the same way.
	nothing := auditPackDetectorFor(t, "pack_other", CatSecret, `NOTHING_MATCHES_THIS_XYZ`)
	out, hits, err = NewWithEvaluator(ModeRedact, auditPackEvaluator(t, nothing)).Apply("a perfectly clean message")
	require.NoError(t, err)
	require.Empty(t, hits)
	require.Nil(t, out)
}

// Sub-threshold findings keep the existing hit accounting: no hit, no
// mutation, no error (custom categories outside the catalog behave the same).
func TestFIX01SubThresholdAndUnknownCategoriesKeepHitAccounting(t *testing.T) {
	lowConf := testVersionedDetector{
		id:       RuleVersion{PackID: "audit.pack", PackVersion: "1", RuleID: "low", RuleVersion: "1"},
		findings: []Finding{{Category: CatSecret, Start: 0, End: 4, Confidence: 0.5, Detector: "low"}},
	}
	hook := NewWithEvaluator(ModeRedact, auditPackEvaluator(t, lowConf))
	out, hits, err := hook.Apply("leak leak")
	require.NoError(t, err)
	require.Empty(t, hits)
	require.Nil(t, out)

	unknown := auditPackDetectorFor(t, "vendor_rule", Category("vendor_custom"), `PACK_SECRET_[A-Z]+`)
	hook = NewWithEvaluator(ModeRedact, auditPackEvaluator(t, unknown))
	out, hits, err = hook.Apply("message PACK_SECRET_VALUE")
	require.NoError(t, err)
	require.Empty(t, hits)
	require.Nil(t, out)
}

// Overlapping findings — same or different category — must collapse into one
// deterministic union replacement with no detectable fragments left behind.
func TestFIX01OverlappingSpansMergeDeterministically(t *testing.T) {
	outer := auditPackDetectorFor(t, "pack_secret", CatSecret, `PACK_SECRET_[A-Z]+`)
	inner := auditPackDetectorFor(t, "pack_inner", CatSecret, `SECRET_VALUE`)
	hook := NewWithEvaluator(ModeRedact, auditPackEvaluator(t, outer, inner))

	out, hits, err := hook.Apply("x PACK_SECRET_VALUE y")
	require.NoError(t, err)
	requireHit(t, hits, CatSecret, OutcomeRedact)
	require.Equal(t, "x [REDACTED_SECRET] y", string(out))

	// Different-category overlap: the earliest-starting span's token wins and
	// the union is replaced once; the result is stable across repeated runs.
	panOverlap := auditPackDetectorFor(t, "pack_pan", CatPAN, `SECRET_VAL`)
	hook = NewWithEvaluator(ModeRedact, auditPackEvaluator(t, outer, panOverlap))
	first, _, err := hook.Apply("x PACK_SECRET_VALUE y")
	require.NoError(t, err)
	require.Equal(t, "x [REDACTED_SECRET] y", string(first))
	for i := 0; i < 50; i++ {
		again, _, err := hook.Apply("x PACK_SECRET_VALUE y")
		require.NoError(t, err)
		require.Equal(t, string(first), string(again), "redaction must be deterministic")
	}
}

// Correct byte offsets around multi-byte runes redact cleanly and keep the
// output valid UTF-8.
func TestFIX01UnicodeContextRedactsOnRuneBoundaries(t *testing.T) {
	detector := auditPackDetectorFor(t, "pack_secret", CatSecret, `PACK_SECRET_[A-Z]+`)
	hook := NewWithEvaluator(ModeRedact, auditPackEvaluator(t, detector))

	const text = "🔒🔒 leak PACK_SECRET_VALUE end"
	out, hits, err := hook.Apply(text)
	require.NoError(t, err)
	requireHit(t, hits, CatSecret, OutcomeRedact)
	require.Equal(t, "🔒🔒 leak [REDACTED_SECRET] end", string(out))
	require.True(t, utf8.ValidString(string(out)))
}

// A span that would split a multi-byte rune cannot be replaced safely: the
// hook must fail closed (deny) instead of emitting corrupted bytes.
func TestFIX01RuneSplittingSpanFailsClosed(t *testing.T) {
	hostile := func(start, end int) *Evaluator {
		return auditPackEvaluator(t, testVersionedDetector{
			id:       RuleVersion{PackID: "audit.pack", PackVersion: "1", RuleID: "hostile", RuleVersion: "1"},
			findings: []Finding{{Category: CatSecret, Start: start, End: end, Confidence: 1, Detector: "hostile"}},
		})
	}

	// Start boundary inside the 4-byte leading emoji.
	startSplit := NewWithEvaluator(ModeRedact, hostile(2, len("🔒PACK_SECRET_VALUE")))
	out, hits, err := startSplit.Apply("🔒PACK_SECRET_VALUE")
	require.ErrorIs(t, err, ErrDenied)
	require.Nil(t, out)
	requireHit(t, hits, CatDetectorFailure, OutcomeDeny)

	// End boundary inside the trailing emoji.
	endSplit := NewWithEvaluator(ModeRedact, hostile(0, len("PACK_SECRET_VALUE")+2))
	out, hits, err = endSplit.Apply("PACK_SECRET_VALUE🔒")
	require.ErrorIs(t, err, ErrDenied)
	require.Nil(t, out)
	requireHit(t, hits, CatDetectorFailure, OutcomeDeny)

	// Zero-width spans are not safely replaceable either.
	zero := NewWithEvaluator(ModeRedact, hostile(4, 4))
	out, hits, err = zero.Apply("🔒PACK_SECRET_VALUE")
	require.ErrorIs(t, err, ErrDenied)
	require.Nil(t, out)
	requireHit(t, hits, CatDetectorFailure, OutcomeDeny)
}

// Out-of-range and inverted spans stay rejected by the evaluator pipeline and
// surface as a deny, never as a silent pass-through of a reported secret.
func TestFIX01InvalidSpansFailClosed(t *testing.T) {
	hostile := func(start, end int) *Evaluator {
		return auditPackEvaluator(t, testVersionedDetector{
			id:       RuleVersion{PackID: "audit.pack", PackVersion: "1", RuleID: "hostile", RuleVersion: "1"},
			findings: []Finding{{Category: CatSecret, Start: start, End: end, Confidence: 1, Detector: "hostile"}},
		})
	}
	for name, span := range map[string][2]int{
		"negative start": {-1, 5},
		"end past text":  {0, 9999},
		"inverted":       {9, 3},
	} {
		t.Run(name, func(t *testing.T) {
			hook := NewWithEvaluator(ModeRedact, hostile(span[0], span[1]))
			out, hits, err := hook.Apply("PACK_SECRET_VALUE")
			require.ErrorIs(t, err, ErrDenied)
			require.Nil(t, out)
			requireHit(t, hits, CatDetectorFailure, OutcomeDeny)
		})
	}
}

// Redacting a secret embedded in a JSON document must keep the document
// valid, byte-identical outside the secret span.
func TestFIX01JSONEmbeddedSecretStaysValidJSON(t *testing.T) {
	detector := auditPackDetectorFor(t, "pack_secret", CatSecret, `PACK_SECRET_[A-Z]+`)
	hook := NewWithEvaluator(ModeRedact, auditPackEvaluator(t, detector))

	const body = `{"model":"gpt","messages":[{"role":"user","content":"leak PACK_SECRET_VALUE now"}]}`
	const want = `{"model":"gpt","messages":[{"role":"user","content":"leak [REDACTED_SECRET] now"}]}`

	out, hits, err := hook.Apply(body)
	require.NoError(t, err)
	requireHit(t, hits, CatSecret, OutcomeRedact)
	require.True(t, json.Valid(out))
	require.JSONEq(t, want, string(out))
}

// Tool-argument shape is preserved: the credential-key mutator keeps the key
// and the custom pack secret is removed, all inside one valid JSON object.
func TestFIX01ToolArgumentShapePreserved(t *testing.T) {
	detector := auditPackDetectorFor(t, "pack_secret", CatSecret, `PACK_SECRET_[A-Z]+`)
	hook := NewWithEvaluator(ModeRedact, auditPackEvaluator(t, detector))

	const body = `{"api_key":"sk-aaaaaaaaaaaaaaaa","note":"use PACK_SECRET_VALUE"}`
	const want = `{"api_key":"[REDACTED_CREDENTIAL]","note":"use [REDACTED_SECRET]"}`

	out, hits, err := hook.Apply(body)
	require.NoError(t, err)
	requireHit(t, hits, CatSecret, OutcomeRedact)
	require.True(t, json.Valid(out))
	require.JSONEq(t, want, string(out))
	require.Contains(t, string(out), `"api_key":"[REDACTED_CREDENTIAL]"`, "credential key must be preserved")
}

// A detector span whose replacement would corrupt a previously valid JSON
// document must fail closed instead of emitting broken bytes.
func TestFIX01JSONCorruptingSpanFailsClosed(t *testing.T) {
	// The span removes the closing quote of the first string value, which
	// would leave the document with an unterminated string.
	hostile := testVersionedDetector{
		id:       RuleVersion{PackID: "audit.pack", PackVersion: "1", RuleID: "corrupt", RuleVersion: "1"},
		findings: []Finding{{Category: CatSecret, Start: 6, End: 10, Confidence: 1, Detector: "corrupt"}},
	}
	hook := NewWithEvaluator(ModeRedact, auditPackEvaluator(t, hostile))

	const body = `{"a":"x\\","b":"PACKX"}`
	require.True(t, json.Valid([]byte(body)))

	out, hits, err := hook.Apply(body)
	require.ErrorIs(t, err, ErrDenied)
	require.Nil(t, out)
	requireHit(t, hits, CatDetectorFailure, OutcomeDeny)
}

// Built-in-only hooks keep their behavior through the new span path, and
// credential-keyed values still keep their key (MC-2) when no custom pack is
// loaded.
func TestFIX01BuiltinRedactBehaviorUnchanged(t *testing.T) {
	hook := New(ModeRedact)
	out, hits, err := hook.Apply("token sk-aaaaaaaaaaaaaaaa end")
	require.NoError(t, err)
	requireHit(t, hits, CatSecret, OutcomeRedact)
	require.Equal(t, "token [REDACTED_SECRET] end", string(out))

	out, hits, err = hook.Apply(`{"token":"supersecretvalue"}`)
	require.NoError(t, err)
	requireHit(t, hits, CatCredential, OutcomeRedact)
	require.JSONEq(t, `{"token":"[REDACTED_CREDENTIAL]"}`, string(out))

	// A custom pack whose finding overlaps a built-in match still composes
	// with the built-in chain in one pass.
	custom := auditPackDetectorFor(t, "pack_secret", CatSecret, `token sk-aaaaaaaaaaaaaaaa`)
	composed := NewWithEvaluator(ModeRedact, auditPackEvaluator(t, custom))
	out, hits, err = composed.Apply("token sk-aaaaaaaaaaaaaaaa end")
	require.NoError(t, err)
	requireHit(t, hits, CatSecret, OutcomeRedact)
	// The custom span covers "token sk-…", so both the label word and the key
	// disappear in one merged union replacement.
	require.Equal(t, "[REDACTED_SECRET] end", string(out))
	require.NotContains(t, string(out), "sk-", "overlapping custom span must remove the secret")
}

// Deny mode is unaffected by the span machinery: detection denies, no
// mutation is produced.
func TestFIX01DenyModeUnchanged(t *testing.T) {
	detector := auditPackDetectorFor(t, "pack_secret", CatSecret, `PACK_SECRET_[A-Z]+`)
	hook := NewWithEvaluator(ModeDeny, auditPackEvaluator(t, detector))
	out, hits, err := hook.Apply("message PACK_SECRET_VALUE")
	require.ErrorIs(t, err, ErrDenied)
	require.Nil(t, out)
	requireHit(t, hits, CatSecret, OutcomeDeny)
	require.NotContains(t, hits, Hit{Category: CatSecret, Outcome: OutcomeRedact})
}

// Direct helper edges: touching spans merge into one union, and an
// INN-namespace finding whose checksum fails stays unredacted (same rule as
// hit accounting), while an out-of-range INN-namespace span still fails closed.
func TestFIX01SpanHelperEdges(t *testing.T) {
	// Touching intervals [0,5) + [5,10) collapse to one union with the
	// earliest-starting span's token.
	merged := mergeRedactionSpans([]redactionSpan{
		{start: 5, end: 10, repl: "[B]"},
		{start: 0, end: 5, repl: "[A]"},
	})
	require.Equal(t, []redactionSpan{{start: 0, end: 10, repl: "[A]"}}, merged)
	require.Nil(t, mergeRedactionSpans(nil))

	// A checksum-invalid ru:inn10 finding at valid offsets is not a hit and
	// must not be redacted (keeps guard recall parity with hit accounting).
	detector := testVersionedDetector{
		id: RuleVersion{PackID: "audit.pack", PackVersion: "1", RuleID: "inn", RuleVersion: "1"},
		findings: []Finding{
			{Category: CatINNSNILS, Start: 0, End: 10, Confidence: 1, Detector: "ru:inn10"},
			{Category: CatSecret, Start: 11, End: 22, Confidence: 1, Detector: "pack"},
		},
	}
	hook := NewWithEvaluator(ModeRedact, auditPackEvaluator(t, detector))
	out, _, err := hook.Apply("1234567890 PACK_SECRET")
	require.NoError(t, err)
	require.Equal(t, "1234567890 [REDACTED_SECRET]", string(out))

	// An out-of-range ru:inn10 finding skips the checksum short-circuit and is
	// rejected by the span validator (fail closed), not silently dropped.
	outOfRange := testVersionedDetector{
		id:       RuleVersion{PackID: "audit.pack", PackVersion: "1", RuleID: "inn-bad", RuleVersion: "1"},
		findings: []Finding{{Category: CatINNSNILS, Start: 0, End: 99, Confidence: 1, Detector: "ru:inn10"}},
	}
	out, hits, err := NewWithEvaluator(ModeRedact, auditPackEvaluator(t, outOfRange)).Apply("1234567890")
	require.ErrorIs(t, err, ErrDenied)
	require.Nil(t, out)
	requireHit(t, hits, CatDetectorFailure, OutcomeDeny)
}
