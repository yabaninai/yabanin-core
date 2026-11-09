// Entitlement corpus verification battery (E01-P05 card W03-C02, batch B;
// design source: artifacts/enterprise-beta/E01-P05/offline-verification-design.md
// §6 — the executable proof matrix for the entitlement plane).
//
// The corpus (testdata/entitlement_corpus/) drives every state: each file is
// an UNSIGNED state definition, issued and signed at runtime with a
// runtime-generated Ed25519 keypair — no private key material lives in the
// tree, and VerifyPaidModuleEntitlement takes the public key as a parameter
// (the parameterized offline surfaces; the activation plane's embedded
// VendorPublicKey is deliberately not exercised here).
//
// States pinned at the fixed anchor 2026-11-08T00:00:00Z: valid (maintenance
// running), maintenance-ended (I24: verification has NO clock input — the
// run right survives MaintenanceEnd), updates-unentitled with an active
// trial (the trial is observational and never restores update rights),
// critical-only (the I25 exception: CriticalFixEntitledAt true while
// UpdatesEntitledAt false, failing closed for ended-support lines, flag-off
// lines and unknown lines), and the activation-plane grace member (the 7d
// GracePeriod of license.go:35 is activation-plane ONLY — pinned through
// StateFromClaims over corpus-shaped claims, because the grace law is a
// duration relative to the real clock, while Verify() itself additionally
// requires the embedded vendor key no test may hold).
//
// Negative arms: deployment mismatch (I23 — an independent production
// contour never verifies), tampered corpus bytes (signature fails closed),
// and version skew (a v1 legacy document is rejected by the v2 verifier —
// fail closed, never half-accepted; the issue API refuses to produce v1, so
// the vector is signed manually over the raw file bytes).
package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// corpusAnchor is the corpus reference instant (see the corpus README).
var corpusAnchor = time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)

// corpusDeployment matches the corpus files' licensed contour (I23).
const corpusDeployment = "corpus-deployment"

func loadCorpusFile(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "entitlement_corpus", name)) // #nosec G304 -- corpus fixture under testdata, name is a test constant
	require.NoError(t, err)
	return raw
}

func loadCorpusEntitlement(t *testing.T, name string) PaidModuleEntitlement {
	t.Helper()
	var ent PaidModuleEntitlement
	require.NoError(t, json.Unmarshal(loadCorpusFile(t, name), &ent))
	return ent
}

// issueCorpus signs an unsigned corpus state with a fresh runtime keypair.
func issueCorpus(t *testing.T, ent PaidModuleEntitlement) (token string, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	token, err = fixturePaidModuleEntitlement(priv, ent, corpusAnchor)
	require.NoError(t, err, "corpus states must be issuable (issue-time validation is part of the pin)")
	return token, pub
}

// TestEntitlementCorpus_AllStatesVerifyOffline walks the signed corpus and
// pins each state's offline predicates at the anchor. I24 is the headline:
// maintenance_ended and critical_only STILL VERIFY (no clock input in the
// decision), while the maintenance gates separate the update/support term
// from the perpetual run right.
func TestEntitlementCorpus_AllStatesVerifyOffline(t *testing.T) {
	cases := []struct {
		file string
		want struct {
			updatesEntitled bool
			maintenanceEnd  bool
			hasModule       map[string]bool
			critical        map[string]bool
			trialActive     bool
		}
	}{
		{file: "valid.json", want: struct {
			updatesEntitled bool
			maintenanceEnd  bool
			hasModule       map[string]bool
			critical        map[string]bool
			trialActive     bool
		}{
			updatesEntitled: true, maintenanceEnd: false,
			hasModule: map[string]bool{"internal-loop": true, "media-persistence": true, "protection-pack": false},
			// No ReleaseLines in the document: the I25 predicate fails
			// closed for ANY line on this entitlement.
			critical:    map[string]bool{"2026.1": false},
			trialActive: false,
		}},
		{file: "maintenance_ended.json", want: struct {
			updatesEntitled bool
			maintenanceEnd  bool
			hasModule       map[string]bool
			critical        map[string]bool
			trialActive     bool
		}{
			updatesEntitled: false, maintenanceEnd: true,
			hasModule: map[string]bool{"internal-loop": true},
			critical:  map[string]bool{"2026.1": false},
		}},
		{file: "updates_unentitled_trial.json", want: struct {
			updatesEntitled bool
			maintenanceEnd  bool
			hasModule       map[string]bool
			critical        map[string]bool
			trialActive     bool
		}{
			updatesEntitled: false, maintenanceEnd: true,
			hasModule:   map[string]bool{"history-export": true},
			critical:    map[string]bool{"2026.1": false},
			trialActive: true,
		}},
		{file: "critical_only.json", want: struct {
			updatesEntitled bool
			maintenanceEnd  bool
			hasModule       map[string]bool
			critical        map[string]bool
			trialActive     bool
		}{
			updatesEntitled: false, maintenanceEnd: true,
			hasModule: map[string]bool{"protection-pack": true},
			// I25 exception: the supported flagged line stays entitled to
			// critical fixes after MaintenanceEnd; ended-support line
			// (2026.0), flag-off line (2027.0) and unknown line all fail
			// closed.
			critical: map[string]bool{
				"2026.1": true,
				"2026.0": false,
				"2027.0": false,
				"9999.9": false,
			},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			token, pub := issueCorpus(t, loadCorpusEntitlement(t, tc.file))
			ent, err := VerifyPaidModuleEntitlement(token, pub, corpusDeployment)
			require.NoError(t, err,
				"I24: verification has no clock input — maintenance-ended states must still verify")
			assert.Equal(t, corpusDeployment, ent.DeploymentID)
			assert.Nil(t, ent.Signature, "a verified document never carries transport metadata")

			assert.Equal(t, tc.want.updatesEntitled, ent.UpdatesEntitledAt(corpusAnchor),
				"the renewal-gated update/support right (I24)")
			assert.Equal(t, tc.want.maintenanceEnd, ent.MaintenanceEndedAt(corpusAnchor))
			for module, want := range tc.want.hasModule {
				assert.Equal(t, want, ent.HasModule(module),
					"HasModule(%q): the perpetual run right follows the signed list exactly", module)
			}
			for line, want := range tc.want.critical {
				assert.Equal(t, want, ent.CriticalFixEntitledAt(line, corpusAnchor),
					"CriticalFixEntitledAt(%q): the I25 exception fails closed outside its window", line)
			}
			assert.Equal(t, tc.want.trialActive, ent.TrialActiveAt(corpusAnchor),
				"the trial is observational state only")
		})
	}
}

// TestEntitlementCorpus_TrialEndNeverRestoresRights pins the trial
// isolation law across the trial boundary: after TrialEnd the observational
// state flips to inactive, and NONE of the rights predicates moves — the
// trial neither bounds nor extends the perpetual run right, the update term
// or the I25 exception.
func TestEntitlementCorpus_TrialEndNeverRestoresRights(t *testing.T) {
	token, pub := issueCorpus(t, loadCorpusEntitlement(t, "updates_unentitled_trial.json"))
	ent, err := VerifyPaidModuleEntitlement(token, pub, corpusDeployment)
	require.NoError(t, err)

	before := corpusAnchor.Add(-time.Hour)         // trial active (before 2026-11-15)
	after := corpusAnchor.Add(30 * 24 * time.Hour) // trial over
	assert.True(t, ent.TrialActiveAt(before))
	assert.False(t, ent.TrialActiveAt(after))

	for _, at := range []time.Time{before, after} {
		assert.True(t, ent.HasModule("history-export"), "run right at %s", at)
		assert.False(t, ent.UpdatesEntitledAt(at), "updates stay unentitled at %s", at)
		assert.False(t, ent.CriticalFixEntitledAt("2026.1", at), "critical line absent at %s", at)
	}
}

// TestEntitlementCorpus_GraceActivationState pins the 7-day grace law of the
// ACTIVATION plane over the corpus grace member. The law is a duration
// (license.go:35), so the assertions derive the window from the real clock:
// the corpus claims are shifted to sit 3 days past expiry (grace),
// exactly at the grace end (the StateFromClaims dead-zone instant —
// disclosed here, totalized by the W04-C01 expiry machine), and 1ns past it
// (hard-expired). Verify() itself needs the embedded vendor key, which no
// test may hold; StateFromClaims is the exact post-parse derivation Verify's
// callers use.
func TestEntitlementCorpus_GraceActivationState(t *testing.T) {
	var c Claims
	require.NoError(t, json.Unmarshal(loadCorpusFile(t, "grace_activation.json"), &c))
	require.Equal(t, "corpus-org", c.OrgID)

	// The corpus member sits 3 days past its expires_at at the anchor
	// (2026-11-05 vs 2026-11-08): rebuild that offset against the real now.
	expiredAgo := corpusAnchor.Sub(c.ExpiresAt) // 72h
	inGrace := c
	inGrace.ExpiresAt = time.Now().Add(-expiredAgo)
	st := StateFromClaims(inGrace)
	assert.True(t, st.Active, "inside grace the activation stays active (degraded mode)")
	assert.True(t, st.Expired, "past ExpiresAt within 7d is the grace state")
	assert.False(t, st.HardExpired)
	assert.Equal(t, "corpus-org", st.OrgID)

	// The grace-end instant itself is unobservable through StateFromClaims
	// against the real clock: any elapsed time between constructing the
	// claims and deriving the state has already pushed strictly past
	// ExpiresAt+GracePeriod (strict-After semantics). The dead zone
	// (Active=false, Expired=false, HardExpired=false) exists only AT the
	// exact instant and is totalized by the injectable-clock expiry machine
	// (W04-C01 expiry.go: PhaseGrace covers the boundary instant).
	atGraceEnd := c
	atGraceEnd.ExpiresAt = time.Now().Add(-GracePeriod)
	st = StateFromClaims(atGraceEnd)
	assert.False(t, st.Active, "Active is strict Before — grace end is already inactive")
	assert.False(t, st.Expired)
	assert.True(t, st.HardExpired, "one clock tick past grace end hard-expires (the exact instant is the W04-C01 pin)")

	pastGrace := c
	pastGrace.ExpiresAt = time.Now().Add(-GracePeriod - time.Nanosecond)
	st = StateFromClaims(pastGrace)
	assert.False(t, st.Active)
	assert.False(t, st.Expired)
	assert.True(t, st.HardExpired, "1ns past grace end hard-expires")
}

// TestEntitlementCorpus_DeploymentMismatchFailsClosed pins I23: the
// entitlement names exactly one production contour; an independent contour
// presents a different DeploymentID and never verifies — and a rejected
// document never exposes its grants (zero value returned).
func TestEntitlementCorpus_DeploymentMismatchFailsClosed(t *testing.T) {
	token, pub := issueCorpus(t, loadCorpusEntitlement(t, "valid.json"))
	ent, err := VerifyPaidModuleEntitlement(token, pub, "independent-production-contour")
	require.Error(t, err, "an independent production contour is not covered by this license")
	assert.Contains(t, err.Error(), "licensed for deployment")
	assert.Equal(t, PaidModuleEntitlement{}, ent, "a rejected document never exposes its grants")
}

// TestEntitlementCorpus_VersionSkewFailsClosed pins the version gate: a v1
// legacy document (hard expiry, no maintenance split) is rejected by the v2
// verifier with the explicit unsupported-version error — fail closed, never
// half-accepted. The issue API refuses to produce v1 (pinned first), so the
// vector is signed manually over the RAW file bytes.
func TestEntitlementCorpus_VersionSkewFailsClosed(t *testing.T) {
	v1 := loadCorpusFile(t, "version_skew_v1.json")
	var legacy PaidModuleEntitlement
	require.NoError(t, json.Unmarshal(v1, &legacy))
	require.Equal(t, "1", legacy.Version)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = fixturePaidModuleEntitlement(priv, legacy, corpusAnchor)
	require.Error(t, err, "the issue API never produces a v1 document")
	assert.Contains(t, err.Error(), "unsupported version")

	token := base64.RawURLEncoding.EncodeToString(v1) + "." +
		base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, v1))
	pub := priv.Public().(ed25519.PublicKey)
	ent, err := VerifyPaidModuleEntitlement(token, pub, corpusDeployment)
	require.Error(t, err, "a v2 verifier must fail closed on a v1 document")
	assert.Contains(t, err.Error(), "unsupported version")
	assert.Equal(t, PaidModuleEntitlement{}, ent)
}

// TestEntitlementCorpus_TamperedCorpusFailsSignature pins integrity: a
// single flipped byte inside the signed payload (customer id) breaks the
// signature — offline verification is content-addressed by Ed25519, and the
// grants of a tampered document are never exposed.
func TestEntitlementCorpus_TamperedCorpusFailsSignature(t *testing.T) {
	token, pub := issueCorpus(t, loadCorpusEntitlement(t, "valid.json"))
	payloadB64, sigB64, ok := strings.Cut(token, ".")
	require.True(t, ok)
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(payload, &doc))
	doc["c"] = "corpus-customer-attacker"
	tampered, err := json.Marshal(doc)
	require.NoError(t, err)

	tamperedToken := base64.RawURLEncoding.EncodeToString(tampered) + "." + sigB64
	ent, err := VerifyPaidModuleEntitlement(tamperedToken, pub, corpusDeployment)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid entitlement signature")
	assert.Equal(t, PaidModuleEntitlement{}, ent)
}
