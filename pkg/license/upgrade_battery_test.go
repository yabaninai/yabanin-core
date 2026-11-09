// Upgrade/downgrade pairwise battery (E01-P05 card W05-C02, batch C).
//
// Card variants, all pinned below:
//
//   - every pair old→new: the matrix walks each OLD state (the signed corpus
//     members plus runtime states) against each transition KIND, asserting
//     for every pair either a verified, successor-legal next document or the
//     exact refusal class (version / stale / renewal-gated / inexact delta);
//   - downgrade: NEW claims against an OLD verifier fail closed — the
//     standing v2 verifier refuses a manually signed v3 successor and the
//     v1 legacy vector alike, the issue API refuses to produce either, and
//     NextEntitlement refuses to derive a v2 successor from a v1
//     predecessor (never half-accepted);
//   - stale token: after an accepted transition the consumer holds the
//     successor; re-presenting the OLD token (or any earlier step of the
//     chain, or the held document itself) is refused;
//   - maintenance-ended upgrade refused: every ended-term old state × every
//     kind is refused with the renewal-gated error, and the near-term-end
//     old pins the exact-instant boundary (strictly before the term end is
//     the last expressible transition instant).
//
// Determinism: one runtime vendor keypair stands in for the vendor across
// the whole battery (old and new tokens verify against the SAME public key —
// the not-re-issued secret law at battery scale); all instants are fixed
// offsets from the corpus anchor; no wall clock, no environment reads.
package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// batteryInstant is the single transition instant of the matrix
// (2026-12-08): strictly inside valid's term (2027-11-01) and the runtime
// states' anchor+180d terms, strictly past every ended-term corpus state
// (2026-10-09).
var batteryInstant = at(30)

// batteryKind is one transition kind of the matrix; apply may adapt per old
// state (e.g. mixed drops the line only where one exists).
type batteryKind struct {
	name    string
	mkTr    func(old PaidModuleEntitlement) EntitlementTransition
	want    string   // "" = accepted, else the refusal-class substring
	present []string // modules that must be granted after acceptance
	absent  []string // modules that must be gone after acceptance
}

// batteryOld is one OLD state of the matrix: an unsigned document (corpus
// file or runtime-built) plus the standing-key signing wrapper.
type batteryOld struct {
	name string
	ent  PaidModuleEntitlement
}

// batteryVendor signs with ONE standing keypair for the whole battery.
func batteryVendor(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

// signBatteryToken issues ent with the standing key at its own issuance
// instant and returns the VERIFIED document (the form a consumer holds).
func signBatteryToken(t *testing.T, priv ed25519.PrivateKey, ent PaidModuleEntitlement) PaidModuleEntitlement {
	t.Helper()
	token, err := fixturePaidModuleEntitlement(priv, ent, ent.IssuedAt)
	require.NoError(t, err, "%s: the old state must be issuable", ent.Nonce)
	verified, err := VerifyPaidModuleEntitlement(token, priv.Public().(ed25519.PublicKey), corpusDeployment)
	require.NoError(t, err, "%s: the old state must verify", ent.Nonce)
	return verified
}

func batteryOlds(t *testing.T) []batteryOld {
	t.Helper()
	return []batteryOld{
		{name: "valid", ent: loadCorpusEntitlement(t, "valid.json")},
		{name: "maintenance-ended", ent: loadCorpusEntitlement(t, "maintenance_ended.json")},
		{name: "updates-unentitled-trial", ent: loadCorpusEntitlement(t, "updates_unentitled_trial.json")},
		{name: "critical-only", ent: loadCorpusEntitlement(t, "critical_only.json")},
		{name: "v1-legacy", ent: loadCorpusEntitlement(t, "version_skew_v1.json")},
		{name: "with-lines", ent: PaidModuleEntitlement{
			Version: ModuleEntitlementVersion, CustomerID: "cust-battery-lines", DeploymentID: corpusDeployment,
			Modules:  []string{"internal-loop"},
			IssuedAt: corpusAnchor, MaintenanceEnd: corpusAnchor.Add(180 * 24 * time.Hour),
			ReleaseLines: []ReleaseLine{{Line: "2026.1", SupportEnd: at(365), CriticalFixes: true}},
			Nonce:        "battery-lines-1",
		}},
		{name: "trial-live", ent: PaidModuleEntitlement{
			Version: ModuleEntitlementVersion, CustomerID: "cust-battery-trial", DeploymentID: corpusDeployment,
			Modules:  []string{"internal-loop"},
			IssuedAt: corpusAnchor, MaintenanceEnd: corpusAnchor.Add(180 * 24 * time.Hour),
			TrialEnd: at(60), Nonce: "battery-trial-1",
		}},
		{name: "near-term-end", ent: PaidModuleEntitlement{
			Version: ModuleEntitlementVersion, CustomerID: "cust-battery-near", DeploymentID: corpusDeployment,
			Modules:  []string{"internal-loop"},
			IssuedAt: corpusAnchor, MaintenanceEnd: at(31),
			Nonce: "battery-near-1",
		}},
	}
}

func batteryKinds() []batteryKind {
	return []batteryKind{
		{
			name: "add-module",
			mkTr: func(PaidModuleEntitlement) EntitlementTransition {
				return EntitlementTransition{AddModules: []string{"protection-pack"}}
			},
			present: []string{"protection-pack"},
		},
		{
			name: "remove-module",
			mkTr: func(old PaidModuleEntitlement) EntitlementTransition {
				return EntitlementTransition{RemoveModules: []string{"media-persistence"}}
			},
			// "media-persistence" exists only on the valid corpus state;
			// every other old is refused as inexact.
			want:    "not granted",
			present: []string{"internal-loop"},
			absent:  []string{"media-persistence"},
		},
		{
			name: "line-add",
			mkTr: func(PaidModuleEntitlement) EntitlementTransition {
				return EntitlementTransition{AddReleaseLines: []ReleaseLine{{Line: "2027.0", SupportEnd: at(500), CriticalFixes: true}}}
			},
		},
		{
			name: "line-drop",
			mkTr: func(PaidModuleEntitlement) EntitlementTransition {
				return EntitlementTransition{DropReleaseLines: []string{"2026.1"}}
			},
			want: "not present", // only with-lines/critical-only carry the line
		},
		{
			name: "mixed",
			mkTr: func(old PaidModuleEntitlement) EntitlementTransition {
				tr := EntitlementTransition{
					AddModules:      []string{"protection-pack"},
					AddReleaseLines: []ReleaseLine{{Line: "2027.0", SupportEnd: at(500), CriticalFixes: true}},
				}
				if old.HasModule("media-persistence") {
					tr.RemoveModules = []string{"media-persistence"}
				}
				for _, rl := range old.ReleaseLines {
					if rl.Line == "2026.1" {
						tr.DropReleaseLines = []string{"2026.1"}
					}
				}
				return tr
			},
			present: []string{"protection-pack"},
		},
	}
}

// TestUpgradeBattery_EveryPairOldToNew walks the full old×kind matrix. For
// every pair the battery asserts ONE outcome: an accepted transition (the
// next document signs with the SAME standing key, verifies offline, and is a
// legal successor) or the exact refusal class.
func TestUpgradeBattery_EveryPairOldToNew(t *testing.T) {
	pub, priv := batteryVendor(t)
	for _, old := range batteryOlds(t) {
		// Only v2 olds can be issued and held by a consumer; the v1
		// legacy vector enters the matrix as the decoded document (its
		// pair outcome is the version refusal, pinned first below).
		held := old.ent
		if old.ent.Version == ModuleEntitlementVersion {
			held = signBatteryToken(t, priv, old.ent)
		}
		for _, kind := range batteryKinds() {
			pair := old.name + " → " + kind.name
			next, err := NextEntitlement(held, kind.mkTr(held), batteryInstant, "battery-next")
			switch {
			case old.name == "v1-legacy":
				require.ErrorContains(t, err, "not a v2 document", "%s", pair)
			case old.ent.MaintenanceEnd.Before(batteryInstant) || old.ent.MaintenanceEnd.Equal(batteryInstant):
				require.ErrorContains(t, err, "renewal required", "%s", pair)
				assert.Contains(t, err.Error(), "renewal required",
					"%s: the ended-term refusal names the renewal gate (distinguishable class)", pair)
			case kind.want != "" && batteryKindApplies(kind, held):
				require.ErrorContains(t, err, kind.want, "%s", pair)
			default:
				require.NoError(t, err, "%s", pair)
				token, issErr := fixturePaidModuleEntitlement(priv, next, batteryInstant)
				require.NoError(t, issErr, "%s: the pair result must be issuable", pair)
				verified, verErr := VerifyPaidModuleEntitlement(token, pub, corpusDeployment)
				require.NoError(t, verErr, "%s: the pair result must verify against the same standing key", pair)
				require.NoError(t, IsEntitlementSuccessor(held, verified), "%s", pair)
				for _, m := range kind.present {
					assert.True(t, verified.HasModule(m), "%s: expected module %q present", pair, m)
				}
				for _, m := range kind.absent {
					assert.False(t, verified.HasModule(m), "%s: expected module %q removed", pair, m)
				}
				if old.name == "trial-live" {
					assert.Equal(t, at(60), verified.TrialEnd, "%s: the live trial carries over", pair)
				}
			}
		}
	}
}

// batteryKindApplies reports whether the kind's negative expectation is
// really about THIS old state (remove-module only collides on olds without
// the module; line-drop only on olds without the line). Positive olds take
// the accepted path for those kinds.
func batteryKindApplies(kind batteryKind, old PaidModuleEntitlement) bool {
	switch kind.name {
	case "remove-module":
		return !old.HasModule("media-persistence")
	case "line-drop":
		for _, rl := range old.ReleaseLines {
			if rl.Line == "2026.1" {
				return false
			}
		}
		return true
	default:
		return true
	}
}

// TestUpgradeBattery_ChainWalkAndStaleRepeat walks a four-step chain from
// the valid corpus state and pins the stale law at every step: the consumer
// holds the newest verified document and refuses EVERY earlier
// re-presentation, of any length of the chain.
func TestUpgradeBattery_ChainWalkAndStaleRepeat(t *testing.T) {
	pub, priv := batteryVendor(t)
	steps := []struct {
		nonce string
		tr    EntitlementTransition
	}{
		{"chain-1", EntitlementTransition{AddModules: []string{"protection-pack"}}},
		{"chain-2", EntitlementTransition{AddReleaseLines: []ReleaseLine{{Line: "2027.0", SupportEnd: at(500), CriticalFixes: true}}}},
		{"chain-3", EntitlementTransition{RemoveModules: []string{"media-persistence"}}},
		{"chain-4", EntitlementTransition{DropReleaseLines: []string{"2027.0"}}},
	}

	held := signBatteryToken(t, priv, loadCorpusEntitlement(t, "valid.json"))
	history := []PaidModuleEntitlement{held}
	for i, s := range steps {
		now := batteryInstant.Add(time.Duration(i) * 24 * time.Hour)
		next, err := NextEntitlement(held, s.tr, now, s.nonce)
		require.NoError(t, err, "step %d", i+1)
		token, err := fixturePaidModuleEntitlement(priv, next, now)
		require.NoError(t, err, "step %d", i+1)
		verified, err := VerifyPaidModuleEntitlement(token, pub, corpusDeployment)
		require.NoError(t, err, "step %d", i+1)
		require.NoError(t, IsEntitlementSuccessor(held, verified), "step %d", i+1)

		// The stale law: every EARLIER presentation is refused against the
		// document now held — including the immediately previous step and
		// the original old token ("repeat of the old — rejected").
		for j, stale := range history {
			require.ErrorContains(t, IsEntitlementSuccessor(verified, stale),
				"stale presentation", "step %d: re-presenting history entry %d is refused", i+1, j)
		}
		require.ErrorContains(t, IsEntitlementSuccessor(verified, verified), "stale presentation",
			"step %d: the held document is not its own successor", i+1)

		held = verified
		history = append(history, verified)
	}
	assert.True(t, held.HasModule("internal-loop"), "the chain kept the perpetual-run module")
	assert.True(t, held.HasModule("protection-pack"), "the chain kept the added module")
	assert.False(t, held.HasModule("media-persistence"), "the chain removed the module at step 3")
	assert.Empty(t, held.ReleaseLines, "the chain dropped the last line at step 4")
}

// TestUpgradeBattery_DowngradeFailsClosed pins the downgrade direction: NEW
// claims against the OLD (standing v2) verifier fail closed — no silent
// partial acceptance, on either side of the version history.
func TestUpgradeBattery_DowngradeFailsClosed(t *testing.T) {
	pub, priv := batteryVendor(t)

	// D1: the v1 legacy vector (raw corpus bytes), manually signed with the
	// standing key — a VALID signature must still fail the version gate.
	v1Raw := loadCorpusFile(t, "version_skew_v1.json")
	v1Token := base64.RawURLEncoding.EncodeToString(v1Raw) + "." +
		base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, v1Raw))
	v1Ent, err := VerifyPaidModuleEntitlement(v1Token, pub, corpusDeployment)
	require.ErrorContains(t, err, "unsupported version", "a v1 document fails the v2 verifier closed")
	assert.Equal(t, PaidModuleEntitlement{}, v1Ent, "a rejected downgrade never exposes its grants")

	// D3: future v3 claims, manually signed — the standing v2 verifier is
	// OLD relative to the claims and refuses them (never half-accepts).
	v3 := map[string]any{
		"v": "3", "c": "cust-future", "d": corpusDeployment,
		"m": []string{"internal-loop"}, "i": batteryInstant,
		"me": batteryInstant.Add(24 * time.Hour), "n": "v3-future",
	}
	v3Raw, err := json.Marshal(v3)
	require.NoError(t, err)
	v3Token := base64.RawURLEncoding.EncodeToString(v3Raw) + "." +
		base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, v3Raw))
	v3Ent, err := VerifyPaidModuleEntitlement(v3Token, pub, corpusDeployment)
	require.ErrorContains(t, err, "unsupported version", "newer claims against the old verifier fail closed")
	assert.Equal(t, PaidModuleEntitlement{}, v3Ent)

	// D2: no v2 successor can be DERIVED from a v1 predecessor either
	// (upgrade.go refuses foreign-version predecessors before any delta).
	_, err = NextEntitlement(loadCorpusEntitlement(t, "version_skew_v1.json"),
		EntitlementTransition{AddModules: []string{"protection-pack"}}, batteryInstant, "x")
	require.ErrorContains(t, err, "not a v2 document")
}

// TestUpgradeBattery_MaintenanceEndedUpgradeRefused re-pins the renewal
// gate across the ended-term corpus states and the exact boundary instants
// of a live near-end term.
func TestUpgradeBattery_MaintenanceEndedUpgradeRefused(t *testing.T) {
	_, priv := batteryVendor(t)
	tr := EntitlementTransition{AddModules: []string{"protection-pack"}}

	for _, name := range []string{"maintenance_ended.json", "updates_unentitled_trial.json", "critical_only.json"} {
		held := signBatteryToken(t, priv, loadCorpusEntitlement(t, name))
		_, err := NextEntitlement(held, tr, batteryInstant, "renew")
		require.ErrorContains(t, err, "renewal required", "%s", name)
		assert.NotContains(t, err.Error(), "stale", "%s: the refusal class is renewal, not staleness", name)
		// I24 stays true meanwhile: the ended document itself keeps its
		// perpetual run right and its I25 critical windows.
		assert.NotEmpty(t, held.Modules, "%s: the run right is intact without any upgrade", name)
	}

	// Near-end term: strictly before the end is expressible, the exact end
	// instant is not, and past it is renewal territory.
	near := signBatteryToken(t, priv, PaidModuleEntitlement{
		Version: ModuleEntitlementVersion, CustomerID: "cust-battery-near", DeploymentID: corpusDeployment,
		Modules:  []string{"internal-loop"},
		IssuedAt: corpusAnchor, MaintenanceEnd: at(31),
		Nonce: "battery-near-1",
	})
	_, err := NextEntitlement(near, tr, at(31), "last")
	require.ErrorContains(t, err, "renewal required", "the exact term-end instant is the first refused instant")
	_, err = NextEntitlement(near, tr, at(32), "later")
	require.ErrorContains(t, err, "renewal required")
	last, err := NextEntitlement(near, tr, at(31).Add(-time.Nanosecond), "last-expressible")
	require.NoError(t, err, "one nanosecond before the end the transition is still expressible")
	token, err := fixturePaidModuleEntitlement(priv, last, at(31).Add(-time.Nanosecond))
	require.NoError(t, err)
	_, err = VerifyPaidModuleEntitlement(token, priv.Public().(ed25519.PublicKey), corpusDeployment)
	require.NoError(t, err)
}
