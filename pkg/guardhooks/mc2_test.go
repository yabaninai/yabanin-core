package guardhooks

// MC-2 (owner decision 2026-10-24, wave-10 gate: "Credential-категория
// custom-pack (MC-2): fail-closed deny — никогда не оставлять секрет с
// пометкой redacted").
//
// CatCredential is excluded from span redaction (see redactionSpans):
// credential values are mutated only by the key-preserving built-in mutator
// (credentialKeyRe). A custom guard pack may declare category "credential"
// for any regex, so a finding outside the built-in key-value shape used to
// survive redact mode while a credential:redact hit was reported (the
// RV-FIX01 finding-1 shape, one category over).
//
// Contract pinned here:
//   - custom credential finding inside the built-in key-value shape ⇒ still
//     redacts via the built-in mutator (no behavior change);
//   - custom credential finding outside the shape (bare token, span wider
//     than the pair, zero-width) ⇒ Apply fails closed: ErrDenied, no output,
//     credential:deny hit, content-free error;
//   - mixed findings ⇒ the whole request is denied, nothing is forwarded;
//   - built-in credential findings are unchanged in every mode;
//   - log mode keeps classifying the finding (credential:log); off stays a
//     no-op.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// mc2BareSecret is the non-key-value secret material of the repro pack.
const mc2BareSecret = "PACK_BEARER_abc123"

// mc2BarePackDetector mirrors a real custom pack: category "credential",
// confidence 1, regex byte offsets — the exact shape LoadDetectorPack builds
// (regexVersionedDetector) without re-hashing lifecycle fixtures.
func mc2BarePackDetector(t *testing.T) auditPackDetector {
	t.Helper()
	return auditPackDetectorFor(t, "pack_bearer", CatCredential, `PACK_BEARER_[A-Za-z0-9]+`)
}

// TestMC2CustomCredentialNonShapeDeniesInRedactMode is the failing-before
// repro: redact mode used to report credential:redact and forward the bare
// token because the built-in key-value mutator never matches it. The owner
// decision (2026-10-24) makes this a fail-closed deny.
func TestMC2CustomCredentialNonShapeDeniesInRedactMode(t *testing.T) {
	hook := NewWithEvaluator(ModeRedact, auditPackEvaluator(t, mc2BarePackDetector(t)))

	out, hits, err := hook.Apply("call " + mc2BareSecret + " now")
	require.ErrorIs(t, err, ErrDenied)
	require.Nil(t, out, "denied request must not produce output text")
	requireHit(t, hits, CatCredential, OutcomeDeny)
	// Content-free error: never echo the reported secret (or any text) back.
	require.NotContains(t, err.Error(), mc2BareSecret)
}

// A custom credential finding whose span sits fully inside a built-in
// key-value match is honored by the built-in mutator: it still redacts, no
// deny. Covers both the exact-pair span and the value-inside-pair span.
func TestMC2CustomCredentialInsideBuiltInShapeStillRedacts(t *testing.T) {
	t.Run("exact pair span", func(t *testing.T) {
		// The pack rule is narrower than the built-in dictionary but its
		// match region is exactly the built-in key-value match.
		detector := auditPackDetectorFor(t, "pack_pair", CatCredential, `"token"\s*:\s*"[^"]*"`)
		hook := NewWithEvaluator(ModeRedact, auditPackEvaluator(t, detector))

		const body = `{"token":"sk-aaaaaaaaaaaaaaaa","note":"keep"}`
		out, hits, err := hook.Apply(body)
		require.NoError(t, err)
		requireHit(t, hits, CatCredential, OutcomeRedact)
		require.JSONEq(t, `{"token":"[REDACTED_CREDENTIAL]","note":"keep"}`, string(out))
		require.NotContains(t, string(out), "sk-aaaaaaaaaaaaaaaa")
	})

	t.Run("value inside pair span", func(t *testing.T) {
		// The pack rule matches only the value body; the finding span is
		// strictly contained in the built-in pair match, which removes it.
		detector := auditPackDetectorFor(t, "pack_value", CatCredential, `sk-[A-Za-z0-9]+`)
		hook := NewWithEvaluator(ModeRedact, auditPackEvaluator(t, detector))

		const body = `{"api_key":"sk-aaaaaaaaaaaaaaaa"}`
		out, hits, err := hook.Apply(body)
		require.NoError(t, err)
		requireHit(t, hits, CatCredential, OutcomeRedact)
		require.JSONEq(t, `{"api_key":"[REDACTED_CREDENTIAL]"}`, string(out))
		require.NotContains(t, string(out), "sk-aaaaaaaaaaaaaaaa")
	})
}

// A credential finding the built-in mutator cannot fully address — wider than
// the pair or zero-width — fails closed like any other unredactable claim.
func TestMC2CustomCredentialPartialAndZeroWidthSpansFailClosed(t *testing.T) {
	t.Run("span wider than the pair", func(t *testing.T) {
		// The finding reaches past the pair's closing brace, so no built-in
		// match covers it; forwarding would ship bytes the hit claims to
		// have redacted.
		hostile := testVersionedDetector{
			id:       RuleVersion{PackID: "audit.pack", PackVersion: "1", RuleID: "wide", RuleVersion: "1"},
			findings: []Finding{{Category: CatCredential, Start: 0, End: len(`{"token":"sk-aaaaaaaaaaaaaaaa"}`), Confidence: 1, Detector: "wide"}},
		}
		hook := NewWithEvaluator(ModeRedact, auditPackEvaluator(t, hostile))

		const body = `{"token":"sk-aaaaaaaaaaaaaaaa"}`
		out, hits, err := hook.Apply(body)
		require.ErrorIs(t, err, ErrDenied)
		require.Nil(t, out)
		requireHit(t, hits, CatCredential, OutcomeDeny)
	})

	t.Run("zero-width span", func(t *testing.T) {
		hostile := testVersionedDetector{
			id:       RuleVersion{PackID: "audit.pack", PackVersion: "1", RuleID: "zero", RuleVersion: "1"},
			findings: []Finding{{Category: CatCredential, Start: 2, End: 2, Confidence: 1, Detector: "zero"}},
		}
		hook := NewWithEvaluator(ModeRedact, auditPackEvaluator(t, hostile))

		out, hits, err := hook.Apply(`{"token":"x"}`)
		require.ErrorIs(t, err, ErrDenied)
		require.Nil(t, out)
		requireHit(t, hits, CatCredential, OutcomeDeny)
	})
}

// Mixed findings must deny the WHOLE request: no partial redaction output is
// produced, and the hits explain every reason (each category at outcome deny).
func TestMC2MixedFindingsDenyWholeRequest(t *testing.T) {
	pack := auditPackEvaluator(t, mc2BarePackDetector(t))
	hook := NewWithEvaluator(ModeRedact, pack)

	const body = `bearer ` + mc2BareSecret + ` and key sk-verysecretvalue123`
	out, hits, err := hook.Apply(body)
	require.ErrorIs(t, err, ErrDenied)
	require.Nil(t, out, "a denied request must never return redacted or raw text")
	requireHit(t, hits, CatCredential, OutcomeDeny)
	requireHit(t, hits, CatSecret, OutcomeDeny)
	require.NotContains(t, err.Error(), mc2BareSecret)
	require.NotContains(t, err.Error(), "sk-verysecretvalue123")
}

// Log mode keeps classifying the custom credential finding (credential:log)
// and stays a no-op on the text — classification notes it, enforcement does
// not silently widen.
func TestMC2LogModeClassifiesCredentialFinding(t *testing.T) {
	hook := NewWithEvaluator(ModeLog, auditPackEvaluator(t, mc2BarePackDetector(t)))

	out, hits, err := hook.Apply("call " + mc2BareSecret + " now")
	require.NoError(t, err)
	require.Nil(t, out, "log mode never mutates")
	requireHit(t, hits, CatCredential, OutcomeLog)
}

// Deny mode is unchanged: a custom credential finding denies through the
// pre-existing mode switch.
func TestMC2DenyModeCredentialFindingDenied(t *testing.T) {
	hook := NewWithEvaluator(ModeDeny, auditPackEvaluator(t, mc2BarePackDetector(t)))

	out, hits, err := hook.Apply("call " + mc2BareSecret + " now")
	require.ErrorIs(t, err, ErrDenied)
	require.Nil(t, out)
	requireHit(t, hits, CatCredential, OutcomeDeny)
}

// Off mode stays a full no-op: no evaluation, no hits, no error.
func TestMC2OffModeStaysNoop(t *testing.T) {
	hook := NewWithEvaluator(ModeOff, auditPackEvaluator(t, mc2BarePackDetector(t)))

	out, hits, err := hook.Apply("call " + mc2BareSecret + " now")
	require.NoError(t, err)
	require.Nil(t, out)
	require.Empty(t, hits)
}

// Built-in-only hooks keep their behavior in every mode: the built-in
// credential rule is always an exact key-value match, so nothing denies.
func TestMC2BuiltInCredentialFindingsUnchanged(t *testing.T) {
	const body = `{"api_key":"aaaaaaaaaaaaaaaa"}`

	out, hits, err := New(ModeRedact).Apply(body)
	require.NoError(t, err)
	requireHit(t, hits, CatCredential, OutcomeRedact)
	require.JSONEq(t, `{"api_key":"[REDACTED_CREDENTIAL]"}`, string(out))

	out, hits, err = New(ModeDeny).Apply(body)
	require.ErrorIs(t, err, ErrDenied)
	require.Nil(t, out)
	requireHit(t, hits, CatCredential, OutcomeDeny)

	out, hits, err = New(ModeLog).Apply(body)
	require.NoError(t, err)
	require.Nil(t, out)
	requireHit(t, hits, CatCredential, OutcomeLog)
}

// End-to-end through the real pack loader: a detector.json declaring
// category "credential" with a non-key-value pattern loads fine and then
// denies in redact mode instead of forwarding the reported token.
func TestMC2RealPackCredentialCategoryFailsClosed(t *testing.T) {
	root := t.TempDir()
	specs := []map[string]string{{
		"rule_id": "bare-bearer", "rule_version": "1",
		"category": string(CatCredential), "pattern": `PACK_BEARER_[A-Za-z0-9]+`,
	}}
	payload, err := json.Marshal(map[string]any{"detectors": specs})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, "detector.json"), payload, 0o600))
	sum := sha256.Sum256(payload)
	manifest, err := json.Marshal(PackManifest{
		SchemaVersion: GuardPackManifestVersion, PackID: "mc2.pack", PackVersion: "1",
		RuntimeAPI: RuntimeVersion, Files: []PackFile{{Path: "detector.json", SHA256: hex.EncodeToString(sum[:])}},
	})
	require.NoError(t, err)

	_, detectors, err := LoadDetectorPack(root, manifest)
	require.NoError(t, err)
	evaluator, err := NewExtendedEvaluator(detectors...)
	require.NoError(t, err)

	out, hits, err := NewWithEvaluator(ModeRedact, evaluator).Apply("call " + mc2BareSecret + " now")
	require.ErrorIs(t, err, ErrDenied)
	require.Nil(t, out)
	requireHit(t, hits, CatCredential, OutcomeDeny)
	require.NotContains(t, err.Error(), mc2BareSecret)
}

// Unit edges of the shape-coverage helper: containment inside one built-in
// match is safe; wider, zero-width, and no-match spans are not.
func TestMC2CredentialShapeCoversHelper(t *testing.T) {
	// Built-in matches of the fixture text, exactly as the mutator sees them.
	const text = `{"token":"aaaaaaaaaaaaaaaa"}`
	matches := credentialKeyRe.FindAllStringIndex(text, -1)
	require.Len(t, matches, 1)

	pairStart := int(matches[0][0])
	pairEnd := int(matches[0][1])

	require.True(t, credentialShapeCovers(matches, pairStart, pairEnd))
	require.True(t, credentialShapeCovers(matches, pairStart+2, pairEnd-2), "strictly inside the pair is covered")
	require.False(t, credentialShapeCovers(matches, 0, len(text)), "wider than the pair is not covered")
	require.False(t, credentialShapeCovers(matches, pairEnd, pairEnd+1), "reaching past the pair is not covered")
	require.False(t, credentialShapeCovers(matches, pairStart, pairStart), "zero-width is never covered")
	require.False(t, credentialShapeCovers(nil, 0, 1), "no matches cover nothing")
}
